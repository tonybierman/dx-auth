//! `act-db` — operator-grade DB administration for arium.
//!
//! Plugs into the `act` host via the `arium-act` gate SDK: every verb
//! authenticates with `-u`/`-p` against the same arium database it
//! mutates, requires the canonical `admin` role, and writes one
//! `audit_events` row per successful action. Reads never audit;
//! denials are always recorded (by the gate itself).
//!
//! ```text
//! act-db migrate
//! act-db users create alice@example.com --new-password ... --verified
//! act-db users reset-password 42 --new-password ...
//! act-db roles grant 42 admin
//! act-db tokens create 42 "ci-deploy"        # cleartext printed once
//! act-db audit query --event-type user.login.failed --limit 200
//! act-db audit prune 90
//! ```
//!
//! Database selection follows arium's normal precedence:
//! `--database-url` > `DATABASE_URL` > `--db <PATH>` (the SQLite
//! shorthand that expands to `sqlite://<PATH>?mode=rwc`). Pass
//! `--bootstrap` to skip the admin check — accepted only by `migrate`
//! and `users create`, the verbs that have to run before there can be
//! an admin to authenticate against.
//!
//! Every operation routes through arium's existing public APIs
//! (`arium::auth::*`, `arium::auth::tokens::*`, `arium::auth::audit::*`).
//! `act-db` itself contains no second source of truth about the schema —
//! if a behavior changes in arium, `act-db` inherits it.

mod audit;
mod cmd;
mod output;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

use arium_act::gate;
use output::Format;

#[derive(Parser)]
#[command(name = "act-db", version, about = "DB operations for arium.")]
struct Cli {
    #[command(flatten)]
    auth: gate::AuthArgs,

    /// Render list/show output as JSON instead of human-readable.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Run arium's core migrations (and the membership migrator if
    /// `--features membership` was enabled at build time).
    Migrate,

    /// Manage users.
    Users {
        #[command(subcommand)]
        op: UsersOp,
    },

    /// Manage roles.
    Roles {
        #[command(subcommand)]
        op: RolesOp,
    },

    /// Manage API tokens.
    Tokens {
        #[command(subcommand)]
        op: TokensOp,
    },

    /// Query / prune the audit log.
    Audit {
        #[command(subcommand)]
        op: AuditOp,
    },
}

impl Cmd {
    /// True for verbs that may run against an empty DB (no admin yet),
    /// i.e. via `--bootstrap`. The gate refuses `--bootstrap` for
    /// everything else.
    fn allows_bootstrap(&self) -> bool {
        matches!(
            self,
            Cmd::Migrate
                | Cmd::Users {
                    op: UsersOp::Create { .. }
                }
        )
    }

    fn label(&self) -> &'static str {
        match self {
            Cmd::Migrate => "db.migrate",
            Cmd::Users { .. } => "db.users",
            Cmd::Roles { .. } => "db.roles",
            Cmd::Tokens { .. } => "db.tokens",
            Cmd::Audit { .. } => "db.audit",
        }
    }
}

#[derive(Subcommand)]
pub enum UsersOp {
    /// List users (paginated).
    List {
        #[arg(long, default_value_t = 50)]
        limit: i64,
        #[arg(long, default_value_t = 0)]
        offset: i64,
    },
    /// Show one user by id.
    Show { user_id: i64 },
    /// Create a new password user. Prompts for the new user's password
    /// if `--new-password` is omitted.
    Create {
        email: String,
        /// Password for the NEW user (distinct from -p / --password,
        /// which is the operator's auth password).
        #[arg(long = "new-password")]
        new_password: Option<String>,
        /// Mark the new user's email as verified immediately.
        #[arg(long)]
        verified: bool,
    },
    /// Soft-delete a user.
    Delete { user_id: i64 },
    /// Mark a user's email as verified.
    Verify { user_id: i64 },
    /// Reset a user's password (chains request_password_reset + consume_password_reset).
    ResetPassword {
        user_id: i64,
        /// Replacement password for the target user (distinct from
        /// -p / --password, which is the operator's auth password).
        #[arg(long = "new-password")]
        new_password: Option<String>,
    },
    /// List a user's role ids and names.
    Roles { user_id: i64 },
    /// Turn MFA off for a user (recovery).
    DisableMfa { user_id: i64 },
}

#[derive(Subcommand)]
pub enum RolesOp {
    /// List all roles.
    List,
    /// Create a role.
    Create {
        name: String,
        #[arg(long)]
        description: Option<String>,
        #[arg(long = "permission", value_name = "PERM")]
        permissions: Vec<String>,
    },
    /// Delete a role.
    Delete { role_id: i64 },
    /// List a role's permissions.
    Permissions { role_id: i64 },
    /// Grant a role to a user (role can be id or name).
    Grant { user_id: i64, role: String },
    /// Revoke a role from a user (role can be id or name).
    Revoke { user_id: i64, role: String },
}

#[derive(Subcommand)]
pub enum TokensOp {
    /// List a user's active tokens.
    List { user_id: i64 },
    /// Mint a new API token for a user. The cleartext is printed once.
    Create { user_id: i64, name: String },
    /// Revoke a token by its id.
    Revoke { user_id: i64, token_id: i64 },
}

#[derive(Subcommand)]
pub enum AuditOp {
    /// Query the audit log.
    Query {
        #[arg(long)]
        event_type: Option<String>,
        #[arg(long)]
        actor_id: Option<i64>,
        #[arg(long)]
        target_id: Option<i64>,
        #[arg(long, default_value_t = 50)]
        limit: i64,
        #[arg(long, default_value_t = 0)]
        offset: i64,
    },
    /// Prune events older than the given retention window.
    Prune { retention_days: u64 },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: tokio runtime: {e}");
            return ExitCode::from(1);
        }
    };

    match rt.block_on(run(cli)) {
        Ok(()) => ExitCode::from(0),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let fmt = if cli.json {
        Format::Json
    } else {
        Format::Human
    };
    let url = cli.auth.resolve_database_url()?;
    let pool = gate::build_pool(&url).await?;

    let actor = gate::run(
        &cli.auth,
        &pool,
        cli.cmd.allows_bootstrap(),
        cli.cmd.label(),
    )
    .await?;
    let actor_id = actor.user_id();

    match cli.cmd {
        Cmd::Migrate => cmd::migrate::run(&pool, actor_id).await,
        Cmd::Users { op } => cmd::users::run(&pool, actor_id, op, fmt).await,
        Cmd::Roles { op } => cmd::roles::run(&pool, actor_id, op, fmt).await,
        Cmd::Tokens { op } => cmd::tokens::run(&pool, actor_id, op, fmt).await,
        Cmd::Audit { op } => cmd::audit::run(&pool, actor_id, op, fmt).await,
    }
}
