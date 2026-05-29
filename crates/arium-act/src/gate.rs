//! Auth + admin-role gate, shared by every `act-*` extension.
//!
//! Extensions get a uniform `-u` / `-p` / `--database-url` /
//! `--bootstrap` surface for free by flattening [`AuthArgs`] into their
//! clap `Cli` and calling [`run`] before they hit any DB-touching code:
//!
//! ```ignore
//! #[derive(clap::Parser)]
//! struct Cli {
//!     #[command(flatten)]
//!     auth: arium_act::gate::AuthArgs,
//!     #[command(subcommand)]
//!     cmd: Cmd,
//! }
//!
//! let cli = Cli::parse();
//! let pool = arium_act::gate::build_pool(&cli.auth.resolve_database_url()?).await?;
//! let actor = arium_act::gate::run(
//!     &cli.auth, &pool, cli.cmd.allows_bootstrap(), cli.cmd.label(),
//! ).await?;
//! ```
//!
//! [`run`] handles the canonical audit emission ([`audit::login_failed`],
//! [`audit::gate_denied`], [`audit::session_started`]) so consumers don't
//! reimplement that. Per-verb audit (`USER_API_TOKEN_CREATED`, etc.)
//! stays in the extension — that's the part only the extension knows the
//! semantics of.

use std::io::IsTerminal;

use arium::auth::VerifyOutcome;
use arium::auth::role::ADMIN as ADMIN_ROLE_ID;
use arium::pool::Pool;

use crate::audit;

/// Global auth-related flags. Flatten this into your extension's root
/// clap struct with `#[command(flatten)]`. `env =` attributes mean
/// `ACT_USER` / `ACT_PASSWORD` / `DATABASE_URL` work as fallbacks for
/// each flag automatically.
#[derive(clap::Args, Debug, Clone)]
pub struct AuthArgs {
    /// Username or email of the operator running this command.
    #[arg(
        short = 'u',
        long = "user",
        value_name = "USERNAME_OR_EMAIL",
        env = "ACT_USER",
        global = true
    )]
    pub user: Option<String>,

    /// Password for the operator. Prompted interactively on a TTY if
    /// neither this flag nor `ACT_PASSWORD` is set.
    #[arg(
        short = 'p',
        long = "password",
        value_name = "PASSWORD",
        env = "ACT_PASSWORD",
        hide_env_values = true,
        global = true
    )]
    pub password: Option<String>,

    /// Connection string for the arium database. Falls back to
    /// `DATABASE_URL`, then to a local sqlite default on sqlite builds.
    #[arg(
        long = "database-url",
        value_name = "URL",
        env = "DATABASE_URL",
        global = true
    )]
    pub database_url: Option<String>,

    /// Convenience shorthand for `--database-url sqlite://<PATH>?mode=rwc`.
    /// Sqlite-only; mutually exclusive with `--database-url`.
    #[cfg(feature = "gate-sqlite")]
    #[arg(
        long = "db",
        value_name = "PATH",
        global = true,
        conflicts_with = "database_url"
    )]
    pub db: Option<String>,

    /// Skip the auth gate. Only honored on the per-extension verbs that
    /// opt into it (e.g. `migrate`, `users create`) AND only when no
    /// admin yet exists on the install. Refuses itself once an admin
    /// has been provisioned.
    #[arg(long, global = true)]
    pub bootstrap: bool,
}

impl AuthArgs {
    /// Pick the database URL, applying the documented fallback chain:
    /// `--database-url` → `--db <path>` (sqlite only) → `DATABASE_URL`
    /// env (via clap's `env = ...`) → local sqlite default.
    pub fn resolve_database_url(&self) -> anyhow::Result<String> {
        if let Some(u) = &self.database_url
            && !u.is_empty()
        {
            return Ok(u.clone());
        }
        #[cfg(feature = "gate-sqlite")]
        if let Some(path) = self.db.as_deref().filter(|p| !p.is_empty()) {
            return Ok(format!("sqlite://{path}?mode=rwc"));
        }
        #[cfg(feature = "gate-sqlite")]
        {
            Ok("sqlite://./auth.db?mode=rwc".to_string())
        }
        #[cfg(not(feature = "gate-sqlite"))]
        {
            anyhow::bail!("no database URL (use --database-url or DATABASE_URL)")
        }
    }
}

/// Outcome of a successful gate. Extensions use this as the actor id for
/// per-verb audit records.
#[derive(Debug, Clone, Copy)]
pub enum Actor {
    /// A real user authenticated successfully and proved the `admin` role.
    User(i64),
    /// `--bootstrap` was honored — no actor yet exists. Per-verb audit
    /// callers should treat this as `actor_id = None` (the FK on
    /// `audit_events.actor_id` would reject any synthetic id).
    Bootstrap,
}

impl Actor {
    /// Actor id usable as an audit `actor_id`. `Bootstrap` returns `0`,
    /// which the extension's audit helper should translate to `None`
    /// before calling `arium::auth::audit::record_or_log` (the value of
    /// `0` would FK-fail).
    pub fn user_id(self) -> i64 {
        match self {
            Actor::User(id) => id,
            Actor::Bootstrap => 0,
        }
    }

    pub fn is_bootstrap(self) -> bool {
        matches!(self, Actor::Bootstrap)
    }
}

/// Authenticate, check the admin role, emit audit, and return the
/// resolved [`Actor`].
///
/// - `allows_bootstrap` — pass `true` if the verb the user requested
///   tolerates running without auth on a fresh install (today: `migrate`
///   and `users create`). On other verbs `--bootstrap` is rejected.
/// - `subcommand` — short label baked into the audit record's
///   `details.subcommand` field, so the trail can be filtered by which
///   verb was invoked.
pub async fn run(
    args: &AuthArgs,
    pool: &Pool,
    allows_bootstrap: bool,
    subcommand: &str,
) -> anyhow::Result<Actor> {
    if args.bootstrap {
        if !allows_bootstrap {
            anyhow::bail!(
                "--bootstrap is only honored on `migrate` and `users create`; \
                 authenticate with -u/-p for this verb instead"
            );
        }
        if has_any_admin(pool).await.unwrap_or(false) {
            anyhow::bail!(
                "--bootstrap refused; an admin already exists. \
                 Authenticate with -u/-p instead."
            );
        }
        return Ok(Actor::Bootstrap);
    }

    let identifier = args
        .user
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "-u/--user is required (or set ACT_USER) — run `act extensions` \
             to list installed commands without auth"
            )
        })?;

    let password = resolve_password(args)?;

    match arium::auth::verify_password_by_identifier(pool, identifier, &password).await? {
        VerifyOutcome::Verified(uid) => {
            let role_ids = arium::auth::get_user_role_ids(pool, uid).await?;
            if !role_ids.contains(&ADMIN_ROLE_ID) {
                audit::gate_denied(pool, uid, subcommand).await;
                anyhow::bail!("admin role required");
            }
            audit::session_started(pool, uid, subcommand).await;
            Ok(Actor::User(uid))
        }
        VerifyOutcome::Unverified => {
            audit::login_failed(pool, identifier, subcommand).await;
            anyhow::bail!("account email not verified")
        }
        VerifyOutcome::Invalid => {
            audit::login_failed(pool, identifier, subcommand).await;
            anyhow::bail!("authentication failed")
        }
    }
}

fn resolve_password(args: &AuthArgs) -> anyhow::Result<String> {
    if let Some(p) = &args.password
        && !p.is_empty()
    {
        return Ok(p.clone());
    }
    if !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "no password supplied — pass -p/--password, set ACT_PASSWORD, \
             or run on a TTY for an interactive prompt"
        );
    }
    Ok(rpassword::prompt_password("Password: ")?)
}

/// Build an [`arium::pool::Pool`] from a connection URL using the
/// backend selected at compile time (`gate-sqlite` / `gate-postgres`).
#[cfg(feature = "gate-sqlite")]
pub async fn build_pool(url: &str) -> anyhow::Result<Pool> {
    use std::str::FromStr;

    let opts = sqlx::sqlite::SqliteConnectOptions::from_str(url)?;
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(4)
        .connect_with(opts)
        .await?;
    Ok(pool)
}

#[cfg(feature = "gate-postgres")]
pub async fn build_pool(url: &str) -> anyhow::Result<Pool> {
    use std::str::FromStr;

    let opts = sqlx::postgres::PgConnectOptions::from_str(url)?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect_with(opts)
        .await?;
    Ok(pool)
}

/// Returns true if any user holds the canonical `admin` role
/// (`arium::auth::role::ADMIN`). Used to refuse `--bootstrap` once the
/// install is past initial setup.
///
/// Uses only public arium APIs (no SQL): pages `list_users_for_admin`
/// in 200-row chunks and probes each user's role list. For a brand-new
/// install this stops at the first user; for an established install
/// with at least one admin it stops at the first admin. The worst case
/// (a large install with NO admins at all) iterates everyone — but in
/// that case `--bootstrap` would have legitimately succeeded anyway.
pub async fn has_any_admin(pool: &Pool) -> anyhow::Result<bool> {
    let chunk: i64 = 200;
    let mut offset: i64 = 0;
    loop {
        let users = arium::auth::list_users_for_admin(pool, chunk, offset).await?;
        if users.is_empty() {
            return Ok(false);
        }
        for u in &users {
            let roles = arium::auth::get_user_role_ids(pool, u.id).await?;
            if roles.contains(&ADMIN_ROLE_ID) {
                return Ok(true);
            }
        }
        if (users.len() as i64) < chunk {
            return Ok(false);
        }
        offset = offset.saturating_add(chunk);
    }
}
