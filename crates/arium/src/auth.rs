//! Server-side authentication primitives: the `User` model that the session
//! layer loads, the password and MFA flows, the audit-log emitter, and the
//! helpers every server fn uses to identify the caller.
//!
//! The session/user plumbing is adapted from the `axum-session-auth` examples
//! and tweaked to fit the axum server-fn request lifecycle the adapters share.

use crate::pool::Pool;
use crate::pool::SessionPool;
use async_trait::async_trait;
use axum_session_auth::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Per-request session handle that lets server fns identify the caller,
/// sign them in, sign them out, etc.
pub type Session = axum_session_auth::AuthSession<User, i64, SessionPool, Pool>;
/// Tower layer that attaches a [`Session`] to each request.
pub type AuthLayer = axum_session_auth::AuthSessionLayer<User, i64, SessionPool, Pool>;

/// Authenticated user as seen from the session layer. Stripped down to the
/// fields the UI needs; the full row stays in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Database row id (matches `users.id`).
    pub id: i32,
    /// `true` for the built-in Guest user.
    pub anonymous: bool,
    /// Unique, stable `@handle`: the provider login for OAuth accounts, the
    /// email local-part for password accounts (collision-suffixed at signup).
    /// Apps key on `id`, never on this — see [`unique_username`].
    pub username: String,
    /// User-editable display name, seeded from the OAuth provider's name at
    /// signup. Prefer this over `username` for UI; fall back to `username`.
    pub display_name: Option<String>,
    /// Email on file, if any.
    pub email: Option<String>,
    /// Avatar URL from the OAuth provider, when available.
    pub avatar_url: Option<String>,
    /// Public profile URL on the OAuth provider, when available.
    pub html_url: Option<String>,
    /// Effective permission tokens — direct plus role-inherited, deduped.
    pub permissions: HashSet<String>,
}

/// Row shape used internally to load permission tokens for a user.
#[derive(sqlx::FromRow, Clone)]
pub struct SqlPermissionTokens {
    /// The permission token string (e.g. `"admin"`, `"audit.read"`).
    pub token: String,
}

#[async_trait]
impl Authentication<User, i64, Pool> for User {
    async fn load_user(userid: i64, pool: Option<&Pool>) -> Result<User, anyhow::Error> {
        let db = pool.ok_or_else(|| anyhow::anyhow!("load_user called without a database pool"))?;

        #[derive(sqlx::FromRow, Clone)]
        struct SqlUser {
            id: i32,
            anonymous: bool,
            username: String,
            display_name: Option<String>,
            email: Option<String>,
            avatar_url: Option<String>,
            html_url: Option<String>,
        }

        let sqluser = sqlx::query_as::<_, SqlUser>(
            "SELECT id, anonymous, username, display_name, email, avatar_url, html_url \
             FROM users WHERE id = $1",
        )
        .bind(userid)
        .fetch_one(db)
        .await?;

        // Merge tokens from direct user_permissions rows AND tokens inherited
        // from any role the user has been assigned. The UNION dedupes.
        let sql_user_perms = sqlx::query_as::<_, SqlPermissionTokens>(
            "SELECT token FROM user_permissions WHERE user_id = $1 \
             UNION \
             SELECT rp.token FROM role_permissions rp \
             JOIN user_roles ur ON ur.role_id = rp.role_id \
             WHERE ur.user_id = $1",
        )
        .bind(userid)
        .fetch_all(db)
        .await?;

        Ok(User {
            id: sqluser.id,
            anonymous: sqluser.anonymous,
            username: sqluser.username,
            display_name: sqluser.display_name,
            email: sqluser.email,
            avatar_url: sqluser.avatar_url,
            html_url: sqluser.html_url,
            permissions: sql_user_perms.into_iter().map(|x| x.token).collect(),
        })
    }

    fn is_authenticated(&self) -> bool {
        !self.anonymous
    }

    fn is_active(&self) -> bool {
        !self.anonymous
    }

    fn is_anonymous(&self) -> bool {
        self.anonymous
    }
}

#[async_trait]
impl HasPermission<Pool> for User {
    async fn has(&self, perm: &str, _pool: &Option<&Pool>) -> bool {
        self.permissions.contains(perm)
    }
}

/// Canonical role ids — match the seed in migration 0005.
pub mod role {
    /// Full administrative access.
    pub const ADMIN: i64 = 1;
    /// Standard signed-in user.
    pub const MEMBER: i64 = 2;
    /// Anonymous / not signed in.
    pub const GUEST: i64 = 3;
}

/// Bootstrap-admin hook called after every successful new-user insert
/// (password + OAuth). Grants the `admin` role to a user whose email
/// matches `DX_AUTH_BOOTSTRAP_ADMIN_EMAIL` (or the alias
/// `BOOTSTRAP_ADMIN_EMAIL`) — handy for the first time you stand up an
/// app and need someone to be able to reach `/admin/users`.
pub async fn maybe_bootstrap_admin(
    db: &Pool,
    user_id: i64,
    email: Option<&str>,
) -> anyhow::Result<()> {
    let Some(email) = email else { return Ok(()) };
    let target = bootstrap_admin_email();
    if let Some(t) = target
        && t.eq_ignore_ascii_case(email)
    {
        grant_role(db, user_id, role::ADMIN).await?;
    }
    Ok(())
}

/// First-user-wins hook called after every successful new-user insert.
/// Grants the `admin` role when nobody currently holds it — convention
/// shared by Sentry, GitLab, and friends so a fresh install always has
/// at least one admin without any operator action.
///
/// Soft-deleted users have their `user_roles` rows wiped (see
/// `soft_delete_user`), so this also self-recovers if the last admin
/// gets deleted: the next new signup is promoted.
///
/// Concurrency: two simultaneous first-time signups could both pass the
/// "no admin yet" check and both get promoted. That's harmless — the
/// race window is tiny and applies only to the very first signups on a
/// brand-new install.
pub async fn maybe_grant_first_admin(db: &Pool, user_id: i64) -> anyhow::Result<()> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_roles WHERE role_id = $1")
        .bind(role::ADMIN)
        .fetch_one(db)
        .await?;
    if count == 0 {
        grant_role(db, user_id, role::ADMIN).await?;
        eprintln!(
            "[startup] bootstrap-admin: promoted user {user_id} to admin (first signup, \
             no existing admins)"
        );
    }
    Ok(())
}

/// Startup-time admin sync. If `DX_AUTH_BOOTSTRAP_ADMIN_EMAIL` is set
/// and the named account already exists in the `users` table, ensure
/// they hold the `admin` role. Complements [`maybe_bootstrap_admin`],
/// which only fires during signup — this runs every boot, so it covers:
///
/// - operator sets the env var after the user already signed up
/// - operator signed up via OAuth with a different address than the env var
/// - the admin was accidentally revoked and needs restoring on next deploy
///
/// No-op when the env var is unset, empty, or the email doesn't match
/// any (non-soft-deleted) account.
pub async fn sync_bootstrap_admin(db: &Pool) -> anyhow::Result<()> {
    let Some(email) = bootstrap_admin_email() else {
        return Ok(());
    };

    let user: Option<(i64,)> = sqlx::query_as(
        "SELECT id FROM users \
         WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL \
         LIMIT 1",
    )
    .bind(email.trim())
    .fetch_optional(db)
    .await?;

    let Some((user_id,)) = user else {
        eprintln!(
            "[startup] bootstrap-admin: no account for {email} yet — they'll be promoted on signup"
        );
        return Ok(());
    };

    let already: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM user_roles WHERE user_id = $1 AND role_id = $2")
            .bind(user_id)
            .bind(role::ADMIN)
            .fetch_one(db)
            .await?;

    if already == 0 {
        grant_role(db, user_id, role::ADMIN).await?;
        eprintln!("[startup] bootstrap-admin: granted admin role to {email} (user id {user_id})");
    }
    Ok(())
}

fn bootstrap_admin_email() -> Option<String> {
    std::env::var("DX_AUTH_BOOTSTRAP_ADMIN_EMAIL")
        .or_else(|_| std::env::var("BOOTSTRAP_ADMIN_EMAIL"))
        .ok()
        .filter(|s| !s.is_empty())
}

/// Grant the baseline role every newly-created (non-anonymous) account gets.
/// Called from `create_password_user` and `oauth::upsert_oauth_user` on the
/// new-user branch. Apps that want a different starter role can call
/// `grant_role` after the user is created (or directly INSERT to
/// `user_roles`).
pub async fn assign_default_role(db: &Pool, user_id: i64) -> anyhow::Result<()> {
    grant_role(db, user_id, role::MEMBER).await
}

/// Grant a role to a user. No-op if already assigned.
pub async fn grant_role(db: &Pool, user_id: i64, role_id: i64) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) \
         ON CONFLICT (user_id, role_id) DO NOTHING",
    )
    .bind(user_id)
    .bind(role_id)
    .execute(db)
    .await?;
    Ok(())
}

/// Revoke a role from a user. No-op if they didn't have it.
pub async fn revoke_role(db: &Pool, user_id: i64, role_id: i64) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2")
        .bind(user_id)
        .bind(role_id)
        .execute(db)
        .await?;
    Ok(())
}

/// Replace a user's full set of roles with the supplied list (single
/// transaction so observers never see a half-applied state).
pub async fn set_user_roles(db: &Pool, user_id: i64, role_ids: &[i64]) -> anyhow::Result<()> {
    let mut tx = db.begin().await?;
    sqlx::query("DELETE FROM user_roles WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    for &rid in role_ids {
        sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)")
            .bind(user_id)
            .bind(rid)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// One row in the `roles` table.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, PartialEq)]
pub struct RoleRow {
    /// Database row id.
    pub id: i64,
    /// Unique role name (e.g. `"admin"`, `"editor"`).
    pub name: String,
    /// Optional human-readable description.
    pub description: Option<String>,
    /// `true` for roles seeded by arium; these can't be renamed or deleted.
    pub is_system: bool,
}

/// All roles in the system, ordered by id (system roles first).
pub async fn list_roles(db: &Pool) -> anyhow::Result<Vec<RoleRow>> {
    let rows = sqlx::query_as::<_, RoleRow>(
        "SELECT id, name, description, is_system FROM roles ORDER BY id",
    )
    .fetch_all(db)
    .await?;
    Ok(rows)
}

/// Create a new (non-system) role with the supplied permission tokens.
/// Single transaction. Returns the new role id.
pub async fn create_role(
    db: &Pool,
    name: &str,
    description: Option<&str>,
    permissions: &[String],
) -> anyhow::Result<i64> {
    let name = name.trim();
    if name.is_empty() {
        anyhow::bail!("Role name is required.");
    }

    let mut tx = db.begin().await?;
    let inserted: Result<(i64,), sqlx::Error> = sqlx::query_as(
        "INSERT INTO roles (name, description, is_system) VALUES ($1, $2, false) RETURNING id",
    )
    .bind(name)
    .bind(description)
    .fetch_one(&mut *tx)
    .await;

    let (role_id,) = match inserted {
        Ok(row) => row,
        Err(sqlx::Error::Database(dberr)) if dberr.is_unique_violation() => {
            anyhow::bail!("A role with that name already exists.");
        }
        Err(e) => return Err(e.into()),
    };

    for token in dedup_tokens(permissions) {
        sqlx::query("INSERT INTO role_permissions (role_id, token) VALUES ($1, $2)")
            .bind(role_id)
            .bind(token)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(role_id)
}

/// Replace a non-system role's metadata + permission token set.
/// System roles (`is_system = true`) are read-only — calls against them
/// fail with a user-facing error.
pub async fn update_role(
    db: &Pool,
    role_id: i64,
    name: &str,
    description: Option<&str>,
    permissions: &[String],
) -> anyhow::Result<()> {
    let name = name.trim();
    if name.is_empty() {
        anyhow::bail!("Role name is required.");
    }

    let mut tx = db.begin().await?;
    let row: Option<(bool,)> = sqlx::query_as("SELECT is_system FROM roles WHERE id = $1")
        .bind(role_id)
        .fetch_optional(&mut *tx)
        .await?;
    match row {
        None => anyhow::bail!("Role not found."),
        Some((true,)) => anyhow::bail!("System roles are read-only."),
        _ => {}
    }

    match sqlx::query("UPDATE roles SET name = $1, description = $2 WHERE id = $3")
        .bind(name)
        .bind(description)
        .bind(role_id)
        .execute(&mut *tx)
        .await
    {
        Ok(_) => {}
        Err(sqlx::Error::Database(dberr)) if dberr.is_unique_violation() => {
            anyhow::bail!("A role with that name already exists.");
        }
        Err(e) => return Err(e.into()),
    }

    sqlx::query("DELETE FROM role_permissions WHERE role_id = $1")
        .bind(role_id)
        .execute(&mut *tx)
        .await?;
    for token in dedup_tokens(permissions) {
        sqlx::query("INSERT INTO role_permissions (role_id, token) VALUES ($1, $2)")
            .bind(role_id)
            .bind(token)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Delete a non-system role. Clears `user_roles` rows referencing it so
/// behavior is identical across sqlite and postgres regardless of FK
/// cascade settings.
pub async fn delete_role(db: &Pool, role_id: i64) -> anyhow::Result<()> {
    let mut tx = db.begin().await?;
    let row: Option<(bool,)> = sqlx::query_as("SELECT is_system FROM roles WHERE id = $1")
        .bind(role_id)
        .fetch_optional(&mut *tx)
        .await?;
    match row {
        None => anyhow::bail!("Role not found."),
        Some((true,)) => anyhow::bail!("System roles are read-only."),
        _ => {}
    }

    sqlx::query("DELETE FROM user_roles WHERE role_id = $1")
        .bind(role_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM role_permissions WHERE role_id = $1")
        .bind(role_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM roles WHERE id = $1")
        .bind(role_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

fn dedup_tokens(tokens: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(tokens.len());
    for t in tokens {
        let trimmed = t.trim();
        if trimmed.is_empty() {
            continue;
        }
        if seen.insert(trimmed.to_string()) {
            out.push(trimmed.to_string());
        }
    }
    out
}

/// Role ids attached to the given user.
pub async fn get_user_role_ids(db: &Pool, user_id: i64) -> anyhow::Result<Vec<i64>> {
    let rows: Vec<(i64,)> =
        sqlx::query_as("SELECT role_id FROM user_roles WHERE user_id = $1 ORDER BY role_id")
            .bind(user_id)
            .fetch_all(db)
            .await?;
    Ok(rows.into_iter().map(|(r,)| r).collect())
}

/// Soft-delete: NULL out PII, set `deleted_at`, revoke all roles, and
/// disconnect from oauth providers. The row stays so foreign keys
/// (app-owned tables that point at users.id) don't break.
pub async fn soft_delete_user(db: &Pool, user_id: i64) -> anyhow::Result<()> {
    let mut tx = db.begin().await?;
    sqlx::query(
        "UPDATE users SET \
            display_name = NULL, \
            email = NULL, \
            avatar_url = NULL, \
            html_url = NULL, \
            password_hash = NULL, \
            mfa_secret = NULL, \
            mfa_enabled_at = NULL, \
            email_verified_at = NULL, \
            deleted_at = $1 \
         WHERE id = $2 AND deleted_at IS NULL",
    )
    .bind(unix_now())
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM user_roles WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM oauth_accounts WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM user_permissions WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Change a user's self-chosen display name. Pass `None` to clear it.
pub async fn update_display_name(
    db: &Pool,
    user_id: i64,
    new_name: Option<&str>,
) -> anyhow::Result<()> {
    sqlx::query("UPDATE users SET display_name = $1 WHERE id = $2")
        .bind(new_name)
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(())
}

// ---- Admin / paginated user listing ----

/// Row shape returned by [`list_users_for_admin`] — fields the admin UI
/// needs without joining role data in.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AdminUserRow {
    /// Database row id.
    pub id: i64,
    /// Unique `@handle`.
    pub username: String,
    /// Display name (seeded from the OAuth provider, user-editable), if any.
    pub display_name: Option<String>,
    /// Email on file, if any.
    pub email: Option<String>,
    /// Unix seconds when the email was verified, or `None` if not yet.
    pub email_verified_at: Option<i64>,
    /// Unix seconds when MFA enrollment was confirmed, or `None` if MFA is off.
    pub mfa_enabled_at: Option<i64>,
    /// `true` for the Guest row.
    pub anonymous: bool,
    /// Unix seconds when the account was soft-deleted, or `None` if active.
    pub deleted_at: Option<i64>,
    /// Avatar URL from the OAuth provider, when available.
    pub avatar_url: Option<String>,
    /// Public profile URL on the OAuth provider, when available.
    pub html_url: Option<String>,
}

/// Paginated list of users for the admin UI. Returns the `users` row plus
/// the columns the admin list cares about; role assignments are loaded
/// separately so we don't fan out the join.
pub async fn list_users_for_admin(
    db: &Pool,
    limit: i64,
    offset: i64,
) -> anyhow::Result<Vec<AdminUserRow>> {
    let rows = sqlx::query_as::<_, AdminUserRow>(
        "SELECT id, username, display_name, email, email_verified_at, \
                mfa_enabled_at, anonymous, deleted_at, avatar_url, html_url \
         FROM users \
         ORDER BY id \
         LIMIT $1 OFFSET $2",
    )
    .bind(limit.clamp(1, 500))
    .bind(offset.max(0))
    .fetch_all(db)
    .await?;
    Ok(rows)
}

/// Single-user detail for the admin UI.
pub async fn get_user_for_admin(db: &Pool, user_id: i64) -> anyhow::Result<Option<AdminUserRow>> {
    let row = sqlx::query_as::<_, AdminUserRow>(
        "SELECT id, username, display_name, email, email_verified_at, \
                mfa_enabled_at, anonymous, deleted_at, avatar_url, html_url \
         FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(db)
    .await?;
    Ok(row)
}

/// Tokens a single user resolves to (direct + role-derived). The same
/// query `load_user` uses, just public for the admin detail view.
pub async fn list_permissions_for_user(db: &Pool, user_id: i64) -> anyhow::Result<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT token FROM user_permissions WHERE user_id = $1 \
         UNION \
         SELECT rp.token FROM role_permissions rp \
         JOIN user_roles ur ON ur.role_id = rp.role_id \
         WHERE ur.user_id = $1 \
         ORDER BY 1",
    )
    .bind(user_id)
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|(t,)| t).collect())
}

/// Permission tokens attached to a role.
pub async fn list_permissions_for_role(db: &Pool, role_id: i64) -> anyhow::Result<Vec<String>> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT token FROM role_permissions WHERE role_id = $1 ORDER BY token")
            .bind(role_id)
            .fetch_all(db)
            .await?;
    Ok(rows.into_iter().map(|(t,)| t).collect())
}

// ---- Account self-service helpers (called by the account server fns) ----

/// Look up the current password hash for the given user (None for OAuth-only
/// accounts). Used by `change_password` to verify the old password before
/// writing the new one.
pub async fn get_password_hash(db: &Pool, user_id: i64) -> anyhow::Result<Option<String>> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT password_hash FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(db)
            .await?;
    Ok(row.and_then(|(h,)| h))
}

/// Replace a user's password hash. Caller must have verified the old
/// password first (or be acting via the password-reset flow).
pub async fn replace_password_hash(
    db: &Pool,
    user_id: i64,
    new_password: &str,
) -> anyhow::Result<()> {
    if new_password.len() < 8 {
        anyhow::bail!("Password must be at least 8 characters.");
    }
    let hash = hash_password(new_password)?;
    sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
        .bind(hash)
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(())
}

/// Verify a candidate plaintext password against a stored hash.
pub fn verify_password_against_hash(stored_hash: &str, candidate: &str) -> bool {
    use argon2::Argon2;
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    let Ok(parsed) = PasswordHash::new(stored_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(candidate.as_bytes(), &parsed)
        .is_ok()
}

/// OAuth provider names this user has linked accounts for (e.g. "github").
pub async fn linked_oauth_providers(db: &Pool, user_id: i64) -> anyhow::Result<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT DISTINCT provider FROM oauth_accounts WHERE user_id = $1 ORDER BY provider",
    )
    .bind(user_id)
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|(p,)| p).collect())
}

/// Allocate a unique, case-insensitive `@username` handle from a desired base,
/// appending a numeric suffix when the bare handle is already taken
/// (`alice`, `alice2`, `alice3`, …). Empty/blank input falls back to `user`.
///
/// `username` is the user's public handle: unique and assigned once at account
/// creation. Apps key on `users.id`, never on this. There is a tiny
/// check-then-insert race (two concurrent signups picking the same handle); the
/// `ux_users_username_lower` unique index is the hard backstop, and the same
/// benign-race tolerance the first-admin grant relies on applies here.
pub async fn unique_username(db: &Pool, desired: &str) -> anyhow::Result<String> {
    let base = {
        let trimmed = desired.trim();
        if trimmed.is_empty() {
            "user".to_string()
        } else {
            trimmed.to_string()
        }
    };

    let mut candidate = base.clone();
    let mut n: u32 = 1;
    loop {
        let taken: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM users WHERE LOWER(username) = LOWER($1))",
        )
        .bind(&candidate)
        .fetch_one(db)
        .await?;
        if !taken {
            return Ok(candidate);
        }
        n = n.saturating_add(1);
        if n > 10_000 {
            anyhow::bail!("could not allocate a unique username for {base:?}");
        }
        candidate = format!("{base}{n}");
    }
}

/// Create a new email/password account.
///
/// Returns the new user's id on success. The error is a user-facing message
/// (server fn can surface it verbatim) — we deliberately avoid distinguishing
/// "no such user" from "wrong password" anywhere to prevent enumeration.
pub async fn create_password_user(db: &Pool, email: &str, password: &str) -> anyhow::Result<i64> {
    use argon2::Argon2;
    use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng};

    let email = email.trim();
    if email.is_empty() || !email.contains('@') {
        anyhow::bail!("Please enter a valid email address.");
    }
    if password.len() < 8 {
        anyhow::bail!("Password must be at least 8 characters.");
    }

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hashing failed: {e}"))?
        .to_string();

    let desired = email.split('@').next().unwrap_or(email);
    let username = unique_username(db, desired).await?;

    let inserted: Result<(i64,), sqlx::Error> = sqlx::query_as(
        "INSERT INTO users (anonymous, username, email, password_hash) \
         VALUES (false, $1, $2, $3) RETURNING id",
    )
    .bind(username)
    .bind(email)
    .bind(&hash)
    .fetch_one(db)
    .await;

    let (user_id,) = match inserted {
        Ok(row) => row,
        Err(sqlx::Error::Database(dberr)) if dberr.is_unique_violation() => {
            anyhow::bail!("An account with that email already exists.");
        }
        Err(e) => return Err(e.into()),
    };

    assign_default_role(db, user_id).await?;
    maybe_bootstrap_admin(db, user_id, Some(email)).await?;
    maybe_grant_first_admin(db, user_id).await?;
    Ok(user_id)
}

/// Issue a one-hour password reset token for the account with the given email.
///
/// Returns `Some(token)` when the account exists and has a password set.
/// Returns `None` when no such account exists — the server fn deliberately
/// surfaces the same "we sent it if the address was valid" response in both
/// cases to avoid revealing which emails are registered.
pub async fn request_password_reset(db: &Pool, email: &str) -> anyhow::Result<Option<String>> {
    use argon2::password_hash::rand_core::{OsRng, RngCore};

    let user: Option<(i64,)> = sqlx::query_as(
        "SELECT id FROM users \
         WHERE LOWER(email) = LOWER($1) AND password_hash IS NOT NULL \
         LIMIT 1",
    )
    .bind(email.trim())
    .fetch_optional(db)
    .await?;

    let Some((user_id,)) = user else {
        return Ok(None);
    };

    // 16 random bytes = 128 bits of entropy, plenty for short-lived
    // single-use tokens. Hex-encoded that's 32 chars, which keeps the
    // resulting reset/verify URL under 76 chars so the plain-text email body
    // stays in 7bit transfer encoding (clean URLs in raw `.eml` views).
    let mut bytes = [0u8; 16];
    let mut rng = OsRng;
    rng.fill_bytes(&mut bytes);
    let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();

    let expires_at = unix_now().saturating_add(3600);

    sqlx::query(
        "INSERT INTO password_reset_tokens (token, user_id, expires_at) VALUES ($1, $2, $3)",
    )
    .bind(&token)
    .bind(user_id)
    .bind(expires_at)
    .execute(db)
    .await?;

    Ok(Some(token))
}

/// Consume a reset token: validate, hash the new password, set it, and delete
/// all outstanding tokens for the same user (so a leaked older token can't be
/// re-used after a successful reset).
pub async fn consume_password_reset(
    db: &Pool,
    token: &str,
    new_password: &str,
) -> anyhow::Result<i64> {
    if new_password.len() < 8 {
        anyhow::bail!("Password must be at least 8 characters.");
    }

    let row: Option<(i64,)> = sqlx::query_as(
        "SELECT user_id FROM password_reset_tokens WHERE token = $1 AND expires_at > $2 LIMIT 1",
    )
    .bind(token)
    .bind(unix_now())
    .fetch_optional(db)
    .await?;

    let Some((user_id,)) = row else {
        anyhow::bail!("This reset link has expired or already been used.");
    };

    let hash = hash_password(new_password)?;

    let mut tx = db.begin().await?;
    sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
        .bind(&hash)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM password_reset_tokens WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    Ok(user_id)
}

fn hash_password(plaintext: &str) -> anyhow::Result<String> {
    use argon2::Argon2;
    use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng};
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(plaintext.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hashing failed: {e}"))?
        .to_string())
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Result of a password verification attempt.
///
/// The UI distinguishes `Unverified` so it can offer "Resend verification
/// email"; `Invalid` collapses the "no such account" and "wrong password"
/// cases into one to avoid user enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Password matched. Carries the user id.
    Verified(i64),
    /// Password matched, but the account's email is not yet verified.
    Unverified,
    /// No matching account or bad password — kept indistinguishable on
    /// purpose so attackers can't enumerate accounts.
    Invalid,
}

/// A precomputed throwaway Argon2 hash, used to equalize the cost of the "no
/// such account" and "corrupt stored hash" paths in [`verify_password_user`].
/// Without it, those paths skip the (deliberately expensive) Argon2 verify and
/// return ~25x faster than a wrong-password attempt against a real account — a
/// timing side-channel that lets an attacker enumerate which emails have
/// accounts, defeating the indistinguishability that [`VerifyOutcome::Invalid`]
/// promises.
///
/// Hardcoded rather than generated at runtime so there's no fallible hashing
/// (and no `unwrap`/`expect`) in this path; it's a hash of a fixed throwaway
/// string — no secret. Its params (`m=19456,t=2,p=1`) are `Argon2::default()`,
/// matching what `hash_password` produces, so verifying against it costs the
/// same as verifying a genuine user's hash. If the default params are ever
/// bumped, regenerate this so the costs stay aligned.
const DUMMY_PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$OSdEu4xJYj4c5XviuP4CTQ$8LSH0M1A859epUylwUTwZJUp5O8rAtv0wURpMnvMbE4";

/// Run an Argon2 verify against [`DUMMY_PASSWORD_HASH`] and discard the
/// result. Called on the early-return branches of [`verify_password_user`]
/// purely to burn the same CPU a real verify would, so response time doesn't
/// leak whether the account exists.
fn burn_password_verify(password: &str) {
    use argon2::Argon2;
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    if let Ok(parsed) = PasswordHash::new(DUMMY_PASSWORD_HASH) {
        let _ = Argon2::default().verify_password(password.as_bytes(), &parsed);
    }
}

/// Verify an email/password pair and the account's email-verified status.
pub async fn verify_password_user(
    db: &Pool,
    email: &str,
    password: &str,
) -> anyhow::Result<VerifyOutcome> {
    use argon2::Argon2;
    use argon2::password_hash::{PasswordHash, PasswordVerifier};

    let row: Option<(i64, String, Option<i64>)> = sqlx::query_as(
        "SELECT id, password_hash, email_verified_at FROM users \
         WHERE LOWER(email) = LOWER($1) AND password_hash IS NOT NULL \
         LIMIT 1",
    )
    .bind(email.trim())
    .fetch_optional(db)
    .await?;

    let Some((user_id, stored_hash, verified_at)) = row else {
        // No matching account: do a dummy verify so this costs the same as a
        // wrong-password attempt against a real account (see DUMMY_PASSWORD_HASH).
        burn_password_verify(password);
        return Ok(VerifyOutcome::Invalid);
    };

    let Ok(parsed) = PasswordHash::new(&stored_hash) else {
        // Stored hash is unparseable — same timing treatment as above.
        burn_password_verify(password);
        return Ok(VerifyOutcome::Invalid);
    };

    if Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_err()
    {
        return Ok(VerifyOutcome::Invalid);
    }

    if verified_at.is_none() {
        return Ok(VerifyOutcome::Unverified);
    }

    Ok(VerifyOutcome::Verified(user_id))
}

/// Issue a 24-hour email verification token for the given user.
pub async fn issue_verification_token(db: &Pool, user_id: i64) -> anyhow::Result<String> {
    use argon2::password_hash::rand_core::{OsRng, RngCore};

    // 16 random bytes = 128 bits of entropy, plenty for short-lived
    // single-use tokens. Hex-encoded that's 32 chars, which keeps the
    // resulting reset/verify URL under 76 chars so the plain-text email body
    // stays in 7bit transfer encoding (clean URLs in raw `.eml` views).
    let mut bytes = [0u8; 16];
    let mut rng = OsRng;
    rng.fill_bytes(&mut bytes);
    let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();

    let expires_at = unix_now().saturating_add(24 * 3600);

    sqlx::query(
        "INSERT INTO email_verification_tokens (token, user_id, expires_at) VALUES ($1, $2, $3)",
    )
    .bind(&token)
    .bind(user_id)
    .bind(expires_at)
    .execute(db)
    .await?;

    Ok(token)
}

/// Consume an email verification token: mark the user verified, delete all
/// outstanding tokens for them, and return the user id. Returns `None` when
/// the token is unknown or expired.
pub async fn consume_verification_token(db: &Pool, token: &str) -> anyhow::Result<Option<i64>> {
    let row: Option<(i64,)> = sqlx::query_as(
        "SELECT user_id FROM email_verification_tokens WHERE token = $1 AND expires_at > $2 LIMIT 1",
    )
    .bind(token)
    .bind(unix_now())
    .fetch_optional(db)
    .await?;

    let Some((user_id,)) = row else {
        return Ok(None);
    };

    let mut tx = db.begin().await?;
    sqlx::query("UPDATE users SET email_verified_at = $1 WHERE id = $2")
        .bind(unix_now())
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM email_verification_tokens WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    Ok(Some(user_id))
}

/// Mark a user's email as verified without going through the token flow.
/// Used by the env-var bypass at signup; also handy for tests and
/// admin-driven approvals.
pub async fn mark_email_verified(db: &Pool, user_id: i64) -> anyhow::Result<()> {
    sqlx::query("UPDATE users SET email_verified_at = $1 WHERE id = $2")
        .bind(unix_now())
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(())
}

// =============== TOTP MFA ==================

#[cfg(feature = "mfa")]
const MFA_ISSUER: &str = "dx-auth example";
#[cfg(feature = "mfa")]
const RECOVERY_CODE_COUNT: usize = 10;

/// Result of `setup_mfa_secret`: secret bytes (so the user can manually
/// type them if their scanner is broken), a data-URL-ready PNG QR code,
/// and the freshly-minted plaintext recovery codes (shown ONCE — only the
/// hashes hit the DB).
#[cfg(feature = "mfa")]
pub struct MfaSetupInfo {
    /// TOTP secret, base32-encoded.
    pub secret_base32: String,
    /// QR code PNG (base64) encoding the `otpauth://` URI.
    pub qr_png_base64: String,
    /// Freshly-minted plaintext recovery codes; shown to the user once.
    pub recovery_codes: Vec<String>,
}

/// High-level status of MFA on a single account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(feature = "mfa")]
pub enum MfaStatus {
    /// No secret stored.
    Disabled,
    /// Secret stored but the user hasn't confirmed enrollment yet.
    Pending,
    /// Secret stored AND `mfa_enabled_at` set.
    Enabled,
}

/// Start MFA enrollment: generate a fresh secret + 10 recovery codes,
/// persist the pending secret on the user (mfa_enabled_at stays NULL until
/// they confirm a TOTP), and store Argon2 hashes of the recovery codes.
/// Re-running on a still-pending or enabled account wipes the old data.
#[cfg(feature = "mfa")]
pub async fn setup_mfa_secret(
    db: &Pool,
    user_id: i64,
    account_label: &str,
) -> anyhow::Result<MfaSetupInfo> {
    use argon2::Argon2;
    use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng};
    use totp_rs::{Algorithm, Secret, TOTP};

    let secret = Secret::generate_secret();
    let secret_base32 = match &secret {
        Secret::Encoded(s) => s.clone(),
        Secret::Raw(_) => secret.to_encoded().to_string(),
    };

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret.to_bytes()?,
        Some(MFA_ISSUER.to_string()),
        account_label.to_string(),
    )?;
    let qr_png_base64 = totp
        .get_qr_base64()
        .map_err(|e| anyhow::anyhow!("QR generation failed: {e}"))?;

    let mut rng = OsRng;
    let mut recovery_codes = Vec::with_capacity(RECOVERY_CODE_COUNT);
    let mut recovery_hashes = Vec::with_capacity(RECOVERY_CODE_COUNT);
    for _ in 0..RECOVERY_CODE_COUNT {
        let code = generate_recovery_code(&mut rng);
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(code.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("hashing recovery code failed: {e}"))?
            .to_string();
        recovery_codes.push(code);
        recovery_hashes.push(hash);
    }

    let mut tx = db.begin().await?;
    sqlx::query("UPDATE users SET mfa_secret = $1, mfa_enabled_at = NULL WHERE id = $2")
        .bind(&secret_base32)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM mfa_recovery_codes WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    for hash in &recovery_hashes {
        sqlx::query("INSERT INTO mfa_recovery_codes (user_id, code_hash) VALUES ($1, $2)")
            .bind(user_id)
            .bind(hash)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;

    Ok(MfaSetupInfo {
        secret_base32,
        qr_png_base64,
        recovery_codes,
    })
}

/// Confirm enrollment by validating a current TOTP from the pending secret.
/// Returns `true` when the code matched and `mfa_enabled_at` is now set.
#[cfg(feature = "mfa")]
pub async fn enable_mfa(db: &Pool, user_id: i64, totp_code: &str) -> anyhow::Result<bool> {
    let Some(secret) = load_mfa_secret(db, user_id).await? else {
        return Ok(false);
    };
    if !check_totp(&secret, totp_code) {
        return Ok(false);
    }
    sqlx::query("UPDATE users SET mfa_enabled_at = $1 WHERE id = $2")
        .bind(unix_now())
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(true)
}

/// Login-time second-factor check. Accepts a 6-digit TOTP code or one of
/// the user's unused recovery codes (marked used on success).
#[cfg(feature = "mfa")]
pub async fn verify_mfa_challenge(db: &Pool, user_id: i64, code: &str) -> anyhow::Result<bool> {
    let code = code.trim();

    if let Some(secret) = load_mfa_secret(db, user_id).await?
        && check_totp(&secret, code)
    {
        return Ok(true);
    }

    consume_recovery_code(db, user_id, code).await
}

/// Fully turn off MFA: clear the secret, the enabled timestamp, and any
/// recovery codes.
#[cfg(feature = "mfa")]
pub async fn disable_mfa(db: &Pool, user_id: i64) -> anyhow::Result<()> {
    let mut tx = db.begin().await?;
    sqlx::query("UPDATE users SET mfa_secret = NULL, mfa_enabled_at = NULL WHERE id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM mfa_recovery_codes WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Returns true iff the user has fully completed enrollment.
#[cfg(feature = "mfa")]
pub async fn user_has_mfa(db: &Pool, user_id: i64) -> anyhow::Result<bool> {
    let row: Option<(Option<i64>,)> =
        sqlx::query_as("SELECT mfa_enabled_at FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(db)
            .await?;
    Ok(row.and_then(|(t,)| t).is_some())
}

/// Used by the /account/mfa page to decide which actions to render.
#[cfg(feature = "mfa")]
pub async fn mfa_status(db: &Pool, user_id: i64) -> anyhow::Result<MfaStatus> {
    let row: Option<(Option<String>, Option<i64>)> =
        sqlx::query_as("SELECT mfa_secret, mfa_enabled_at FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(db)
            .await?;
    Ok(match row {
        Some((Some(_), Some(_))) => MfaStatus::Enabled,
        Some((Some(_), None)) => MfaStatus::Pending,
        _ => MfaStatus::Disabled,
    })
}

#[cfg(feature = "mfa")]
async fn load_mfa_secret(db: &Pool, user_id: i64) -> anyhow::Result<Option<String>> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT mfa_secret FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(db)
            .await?;
    Ok(row.and_then(|(s,)| s))
}

#[cfg(feature = "mfa")]
fn check_totp(secret_base32: &str, code: &str) -> bool {
    use totp_rs::{Algorithm, Secret, TOTP};
    let Ok(bytes) = Secret::Encoded(secret_base32.to_string()).to_bytes() else {
        return false;
    };
    let Ok(totp) = TOTP::new(Algorithm::SHA1, 6, 1, 30, bytes, None, "".to_string()) else {
        return false;
    };
    totp.check_current(code).unwrap_or(false)
}

#[cfg(feature = "mfa")]
async fn consume_recovery_code(db: &Pool, user_id: i64, candidate: &str) -> anyhow::Result<bool> {
    use argon2::Argon2;
    use argon2::password_hash::{PasswordHash, PasswordVerifier};

    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT code_hash FROM mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL",
    )
    .bind(user_id)
    .fetch_all(db)
    .await?;

    for (hash,) in rows {
        if let Ok(parsed) = PasswordHash::new(&hash)
            && Argon2::default()
                .verify_password(candidate.as_bytes(), &parsed)
                .is_ok()
        {
            sqlx::query(
                "UPDATE mfa_recovery_codes SET used_at = $1 \
                     WHERE user_id = $2 AND code_hash = $3",
            )
            .bind(unix_now())
            .bind(user_id)
            .bind(&hash)
            .execute(db)
            .await?;
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(feature = "mfa")]
fn generate_recovery_code<R: argon2::password_hash::rand_core::RngCore>(rng: &mut R) -> String {
    // Crockford-style alphabet (no ambiguous chars). 10 chars × ~5 bits ≈ 50
    // bits per code — plenty for one-time backups.
    const ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    let mut bytes = [0u8; 10];
    rng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|b| {
            // checked_rem with a non-zero const divisor; `unwrap_or` and
            // `.get()` cover the "can't happen" arms so we don't have to
            // unwrap/panic on a path the math actually guarantees.
            let i = (*b as usize).checked_rem(ALPHABET.len()).unwrap_or(0);
            ALPHABET.get(i).copied().unwrap_or(b'A') as char
        })
        .collect()
}

/// Look up a still-unverified password account by email. Used by the
/// "resend verification email" endpoint.
pub async fn find_unverified_user_id(db: &Pool, email: &str) -> anyhow::Result<Option<i64>> {
    let row: Option<(i64,)> = sqlx::query_as(
        "SELECT id FROM users \
         WHERE LOWER(email) = LOWER($1) \
           AND password_hash IS NOT NULL \
           AND email_verified_at IS NULL \
         LIMIT 1",
    )
    .bind(email.trim())
    .fetch_optional(db)
    .await?;
    Ok(row.map(|(id,)| id))
}

// ============================================================
// Audit log
// ============================================================

/// Library helpers for writing and reading the audit log. The set of
/// emitted event types is open: callers pass arbitrary strings (we
/// recommend a `domain.action.qualifier` scheme — see the constants below).
pub mod audit {
    use super::*;
    use crate::wire::{AuditEventView, AuditQuery};

    // -- Canonical event-type constants used by the library's own server fns. --
    // Apps are free to emit their own taxonomies in addition.

    /// Password sign-in succeeded.
    pub const USER_LOGIN_SUCCESS: &str = "user.login.success";
    /// Password sign-in rejected (wrong password, unverified email, etc.).
    pub const USER_LOGIN_FAILED: &str = "user.login.failed";
    /// User signed out (explicit logout).
    pub const USER_LOGOUT: &str = "user.logout";
    /// Account created via the signup flow.
    pub const USER_SIGNUP: &str = "user.signup";
    /// Email verification link clicked successfully.
    pub const USER_EMAIL_VERIFIED: &str = "user.email_verified";
    /// Password-reset email was sent.
    pub const USER_PWD_RESET_REQUESTED: &str = "user.password_reset.requested";
    /// Password-reset token was consumed and the password was changed.
    pub const USER_PWD_RESET_CONSUMED: &str = "user.password_reset.consumed";
    /// MFA enrollment was confirmed.
    pub const USER_MFA_ENABLED: &str = "user.mfa.enabled";
    /// MFA was turned off on the account.
    pub const USER_MFA_DISABLED: &str = "user.mfa.disabled";

    /// A new API token was minted.
    pub const USER_API_TOKEN_CREATED: &str = "user.api_token.created";
    /// An API token was revoked.
    pub const USER_API_TOKEN_REVOKED: &str = "user.api_token.revoked";

    /// User changed their own password from the account settings page.
    pub const ACCOUNT_PASSWORD_CHANGED: &str = "account.password_changed";
    /// User changed their own display name.
    pub const ACCOUNT_DISPLAY_NAME_CHANGED: &str = "account.display_name_changed";
    /// User soft-deleted their own account.
    pub const ACCOUNT_SELF_DELETED: &str = "account.self_deleted";

    /// An admin changed the role assignments on another user.
    pub const ADMIN_ROLES_CHANGED: &str = "admin.user.roles_changed";
    /// An admin soft-deleted another user.
    pub const ADMIN_USER_DELETED: &str = "admin.user.soft_deleted";
    /// An admin created a new role.
    pub const ADMIN_ROLE_CREATED: &str = "admin.role.created";
    /// An admin updated a role's metadata or permission set.
    pub const ADMIN_ROLE_UPDATED: &str = "admin.role.updated";
    /// An admin deleted a role.
    pub const ADMIN_ROLE_DELETED: &str = "admin.role.deleted";

    /// A per-resource authorization check denied access (no relationship, or a
    /// role below the required minimum). See [`crate::authz::require_resource`].
    pub const RESOURCE_ACCESS_DENIED: &str = "resource.access.denied";
    /// A per-resource authorization check granted access. Opt-in: emitting this
    /// on every read can flood the log, so adapters record only DENIED by default.
    pub const RESOURCE_ACCESS_GRANTED: &str = "resource.access.granted";

    /// Input to [`record`]. All fields are optional — pass `None` for
    /// whatever you don't have. `details` should be a small JSON document
    /// (or `None`).
    pub struct RecordInput<'a> {
        /// Dotted event type (use the constants above when one applies).
        pub event_type: &'a str,
        /// User id that triggered the event, if any.
        pub actor_id: Option<i64>,
        /// User id the event acted on, when distinct from the actor.
        pub target_id: Option<i64>,
        /// Client IP, when captured.
        pub ip: Option<&'a str>,
        /// Client User-Agent, when captured.
        pub user_agent: Option<&'a str>,
        /// Free-form JSON payload describing the event.
        pub details: Option<&'a str>,
    }

    /// Insert one row. Logging failures are not fatal — the caller is
    /// responsible for deciding whether to bubble or swallow the error.
    pub async fn record(db: &Pool, input: RecordInput<'_>) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO audit_events \
             (occurred_at, event_type, actor_id, target_id, ip, user_agent, details) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(unix_now())
        .bind(input.event_type)
        .bind(input.actor_id)
        .bind(input.target_id)
        .bind(input.ip)
        .bind(input.user_agent)
        .bind(input.details)
        .execute(db)
        .await?;
        Ok(())
    }

    /// Convenience wrapper that logs+swallows errors. Use this from server
    /// fns so an audit-write hiccup never fails a user's sign-in.
    pub async fn record_or_log(db: &Pool, input: RecordInput<'_>) {
        if let Err(err) = record(db, input).await {
            eprintln!("[audit] WARN: failed to record event: {err}");
        }
    }

    /// Read rows back, applying optional filters. Results are sorted
    /// newest-first. `limit` is clamped to `[1, 500]`.
    pub async fn query(db: &Pool, q: &AuditQuery) -> anyhow::Result<Vec<AuditEventView>> {
        let limit = q.limit.clamp(1, 500);
        let offset = q.offset.max(0);

        // Event type can be exact or "prefix." (trailing dot signals
        // prefix match via LIKE).
        let (type_clause, type_pattern, type_is_filtered) = if q.event_type.is_empty() {
            ("".to_string(), String::new(), false)
        } else if q.event_type.ends_with('.') {
            (
                " AND e.event_type LIKE $1".to_string(),
                format!("{}%", q.event_type),
                true,
            )
        } else {
            (
                " AND e.event_type = $1".to_string(),
                q.event_type.clone(),
                true,
            )
        };

        // Build the parameter list incrementally so positional placeholders
        // line up across sqlite/postgres ($N works on both).
        let mut idx: i32 = if type_is_filtered { 2 } else { 1 };
        let mut clauses = String::new();

        let actor_idx = q.actor_id.map(|_| {
            let i = idx;
            idx = idx.saturating_add(1);
            clauses.push_str(&format!(" AND e.actor_id = ${i}"));
            i
        });
        let target_idx = q.target_id.map(|_| {
            let i = idx;
            idx = idx.saturating_add(1);
            clauses.push_str(&format!(" AND e.target_id = ${i}"));
            i
        });
        let since_idx = q.since.map(|_| {
            let i = idx;
            idx = idx.saturating_add(1);
            clauses.push_str(&format!(" AND e.occurred_at >= ${i}"));
            i
        });
        let until_idx = q.until.map(|_| {
            let i = idx;
            idx = idx.saturating_add(1);
            clauses.push_str(&format!(" AND e.occurred_at <= ${i}"));
            i
        });
        let limit_idx = idx;
        let offset_idx = idx.saturating_add(1);

        let sql = format!(
            "SELECT e.id, e.occurred_at, e.event_type, \
                    e.actor_id, ua.email AS actor_email, \
                    e.target_id, ut.email AS target_email, \
                    e.ip, e.user_agent, e.details \
             FROM audit_events e \
             LEFT JOIN users ua ON ua.id = e.actor_id \
             LEFT JOIN users ut ON ut.id = e.target_id \
             WHERE 1 = 1{type_clause}{clauses} \
             ORDER BY e.occurred_at DESC, e.id DESC \
             LIMIT ${limit_idx} OFFSET ${offset_idx}",
        );

        let mut qb = sqlx::query_as::<_, AuditRow>(&sql);
        if type_is_filtered {
            qb = qb.bind(type_pattern);
        }
        if let (Some(_), Some(v)) = (actor_idx, q.actor_id) {
            qb = qb.bind(v);
        }
        if let (Some(_), Some(v)) = (target_idx, q.target_id) {
            qb = qb.bind(v);
        }
        if let (Some(_), Some(v)) = (since_idx, q.since) {
            qb = qb.bind(v);
        }
        if let (Some(_), Some(v)) = (until_idx, q.until) {
            qb = qb.bind(v);
        }
        qb = qb.bind(limit).bind(offset);

        let rows = qb.fetch_all(db).await?;
        Ok(rows
            .into_iter()
            .map(|r| AuditEventView {
                id: r.id,
                occurred_at: r.occurred_at,
                occurred_at_iso: format_unix(r.occurred_at),
                event_type: r.event_type,
                actor_id: r.actor_id,
                actor_email: r.actor_email,
                target_id: r.target_id,
                target_email: r.target_email,
                ip: r.ip,
                user_agent: r.user_agent,
                details: r.details,
            })
            .collect())
    }

    fn format_unix(secs: i64) -> String {
        use chrono::TimeZone;
        chrono::Utc
            .timestamp_opt(secs, 0)
            .single()
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| secs.to_string())
    }

    /// Delete rows older than `retention_days`. Returns the number of rows
    /// deleted. A retention of 0 disables pruning (the call is a no-op).
    pub async fn prune(db: &Pool, retention_days: u64) -> anyhow::Result<u64> {
        if retention_days == 0 {
            return Ok(0);
        }
        let seconds = (retention_days as i64).saturating_mul(86_400);
        let cutoff = unix_now().saturating_sub(seconds);
        let res = sqlx::query("DELETE FROM audit_events WHERE occurred_at < $1")
            .bind(cutoff)
            .execute(db)
            .await?;
        Ok(res.rows_affected())
    }

    #[derive(sqlx::FromRow)]
    struct AuditRow {
        id: i64,
        occurred_at: i64,
        event_type: String,
        actor_id: Option<i64>,
        actor_email: Option<String>,
        target_id: Option<i64>,
        target_email: Option<String>,
        ip: Option<String>,
        user_agent: Option<String>,
        details: Option<String>,
    }
}

// ============================================================
// API tokens
// ============================================================

/// Personal API tokens that bypass the session-cookie auth path — used by
/// programmatic clients (CLI tools, MCP servers, …) that hold a long-lived
/// secret per user. Cleartext is shown to the user once at creation; only
/// the SHA-256 hex hash plus a short `prefix` for visual disambiguation are
/// persisted.
#[cfg(feature = "tokens")]
pub mod tokens {
    use super::*;
    use crate::wire::ApiTokenView;

    /// `dxsk_` + 32 random hex chars (16 bytes of entropy).
    const TOKEN_BYTES: usize = 16;
    const PREFIX_LEN: usize = 9; // "dxsk_" (5) + 4 hex chars
    const TOKEN_PREFIX: &str = "dxsk_";
    const MAX_NAME_LEN: usize = 64;

    /// Generate a fresh API token. Returns `(plaintext, prefix, sha256_hex)`.
    /// Pure / no IO so callers (and tests) can verify the contract directly.
    pub fn generate_api_token() -> (String, String, String) {
        use argon2::password_hash::rand_core::{OsRng, RngCore};
        use sha2::{Digest, Sha256};

        let mut bytes = [0u8; TOKEN_BYTES];
        let mut rng = OsRng;
        rng.fill_bytes(&mut bytes);
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();

        let plaintext = format!("{TOKEN_PREFIX}{hex}");
        let prefix = plaintext.chars().take(PREFIX_LEN).collect::<String>();

        let mut hasher = Sha256::new();
        hasher.update(plaintext.as_bytes());
        let hash_hex: String = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();

        (plaintext, prefix, hash_hex)
    }

    /// Hash a candidate token the same way [`generate_api_token`] does.
    /// Consumers validating an incoming `Authorization: Bearer dxsk_…`
    /// hash the bearer string with this and look up
    /// `api_keys.token_hash WHERE revoked_at IS NULL`.
    pub fn hash_api_token(plaintext: &str) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(plaintext.as_bytes());
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Create a new token for `user_id`. Returns the cleartext (shown once)
    /// plus the persisted row's view.
    pub async fn create_for_user(
        db: &Pool,
        user_id: i64,
        name: &str,
    ) -> anyhow::Result<(String, ApiTokenView)> {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err(anyhow::anyhow!("Token name is required."));
        }
        if trimmed.chars().count() > MAX_NAME_LEN {
            return Err(anyhow::anyhow!(
                "Token name is too long (max {MAX_NAME_LEN} characters)."
            ));
        }

        let (plaintext, prefix, token_hash) = generate_api_token();
        let now = unix_now();

        let (id,): (i64,) = sqlx::query_as(
            "INSERT INTO api_keys (user_id, name, token_hash, prefix, created_at) \
             VALUES ($1, $2, $3, $4, $5) \
             RETURNING id",
        )
        .bind(user_id)
        .bind(trimmed)
        .bind(&token_hash)
        .bind(&prefix)
        .bind(now)
        .fetch_one(db)
        .await?;

        let view = ApiTokenView {
            id,
            name: trimmed.to_string(),
            prefix,
            created_at_iso: format_unix_date(now),
            last_used_at_iso: None,
        };
        Ok((plaintext, view))
    }

    /// Active (non-revoked) tokens owned by `user_id`, newest first.
    pub async fn list_for_user(db: &Pool, user_id: i64) -> anyhow::Result<Vec<ApiTokenView>> {
        let rows: Vec<(i64, String, String, i64, Option<i64>)> = sqlx::query_as(
            "SELECT id, name, prefix, created_at, last_used_at \
             FROM api_keys \
             WHERE user_id = $1 AND revoked_at IS NULL \
             ORDER BY created_at DESC, id DESC",
        )
        .bind(user_id)
        .fetch_all(db)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, name, prefix, created_at, last_used_at)| ApiTokenView {
                    id,
                    name,
                    prefix,
                    created_at_iso: format_unix_date(created_at),
                    last_used_at_iso: last_used_at.map(format_unix_date),
                },
            )
            .collect())
    }

    /// Format a unix-seconds timestamp as `YYYY-MM-DD UTC`. Deliberately
    /// duplicates the audit module's helper so `tokens` stays independent of
    /// `audit`.
    fn format_unix_date(secs: i64) -> String {
        use chrono::TimeZone;
        chrono::Utc
            .timestamp_opt(secs, 0)
            .single()
            .map(|dt| dt.format("%Y-%m-%d").to_string())
            .unwrap_or_else(|| secs.to_string())
    }

    /// Soft-revoke. Returns `true` if a row was actually updated (i.e. the
    /// token existed, was owned by `user_id`, and wasn't already revoked).
    /// Returns `false` otherwise — callers should treat this as
    /// `not-found-for-you` without distinguishing the two cases (no info
    /// leak between users).
    pub async fn revoke_for_user(db: &Pool, user_id: i64, token_id: i64) -> anyhow::Result<bool> {
        let res = sqlx::query(
            "UPDATE api_keys SET revoked_at = $1 \
             WHERE id = $2 AND user_id = $3 AND revoked_at IS NULL",
        )
        .bind(unix_now())
        .bind(token_id)
        .bind(user_id)
        .execute(db)
        .await?;
        Ok(res.rows_affected() > 0)
    }
}
