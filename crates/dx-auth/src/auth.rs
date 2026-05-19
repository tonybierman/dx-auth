//! The code here is pulled from the `axum-session-auth` crate examples, requiring little to no
//! modification to work with dioxus fullstack.

use async_trait::async_trait;
use axum_session_auth::*;
use crate::pool::SessionPool;
use serde::{Deserialize, Serialize};
use crate::pool::Pool;
use std::collections::HashSet;

pub type Session = axum_session_auth::AuthSession<User, i64, SessionPool, Pool>;
pub type AuthLayer =
    axum_session_auth::AuthSessionLayer<User, i64, SessionPool, Pool>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: i32,
    pub anonymous: bool,
    pub username: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub avatar_url: Option<String>,
    pub html_url: Option<String>,
    pub permissions: HashSet<String>,
}

#[derive(sqlx::FromRow, Clone)]
pub struct SqlPermissionTokens {
    pub token: String,
}

#[async_trait]
impl Authentication<User, i64, Pool> for User {
    async fn load_user(userid: i64, pool: Option<&Pool>) -> Result<User, anyhow::Error> {
        let db = pool.unwrap();

        #[derive(sqlx::FromRow, Clone)]
        struct SqlUser {
            id: i32,
            anonymous: bool,
            username: String,
            name: Option<String>,
            email: Option<String>,
            avatar_url: Option<String>,
            html_url: Option<String>,
        }

        let sqluser = sqlx::query_as::<_, SqlUser>(
            "SELECT id, anonymous, username, name, email, avatar_url, html_url \
             FROM users WHERE id = $1",
        )
        .bind(userid)
        .fetch_one(db)
        .await
        .unwrap();

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
        .await
        .unwrap();

        Ok(User {
            id: sqluser.id,
            anonymous: sqluser.anonymous,
            username: sqluser.username,
            name: sqluser.name,
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

#[cfg(feature = "oauth-github")]
#[derive(Clone)]
pub struct OAuthClients {
    pub db: Pool,
    pub http: reqwest::Client,
    pub github_client_id: String,
    pub github_client_secret: String,
    pub github_redirect_url: String,
}

#[cfg(feature = "oauth-github")]
impl OAuthClients {
    /// Build `OAuthClients` from env vars.
    ///
    /// Returns `Ok(Some(_))` when GitHub credentials are configured (both
    /// `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` set and non-empty), or
    /// `Ok(None)` when they're absent — the caller should then skip
    /// registering the OAuth routes and the UI should hide the provider
    /// button. Errors are reserved for genuine misconfiguration (e.g. failure
    /// to build the HTTP client).
    pub fn from_env(db: Pool) -> anyhow::Result<Option<Self>> {
        let id = std::env::var("GITHUB_CLIENT_ID").ok().filter(|s| !s.is_empty());
        let secret = std::env::var("GITHUB_CLIENT_SECRET")
            .ok()
            .filter(|s| !s.is_empty());

        let (github_client_id, github_client_secret) = match (id, secret) {
            (Some(i), Some(s)) => (i, s),
            (None, None) => return Ok(None),
            _ => {
                eprintln!(
                    "[startup] WARN: partial GitHub OAuth config — both \
                     GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET are required. \
                     Disabling GitHub sign-in."
                );
                return Ok(None);
            }
        };

        let github_redirect_url = std::env::var("GITHUB_REDIRECT_URL")
            .unwrap_or_else(|_| "http://localhost:8080/auth/github/callback".to_string());

        // Disable automatic redirect following per oauth2 crate guidance (SSRF mitigation).
        let http = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        Ok(Some(Self {
            db,
            http,
            github_client_id,
            github_client_secret,
            github_redirect_url,
        }))
    }
}

/// The subset of GitHub's `/user` response we persist locally.
#[cfg(feature = "oauth-github")]
pub struct GithubProfile<'a> {
    pub id: u64,
    pub login: &'a str,
    pub name: Option<&'a str>,
    pub email: Option<&'a str>,
    pub avatar_url: Option<&'a str>,
    pub html_url: Option<&'a str>,
}

/// Find-or-create-or-link a local user row for the given GitHub identity.
///
/// Three branches, tried in order:
///
/// 1. **Repeat OAuth login** — `oauth_accounts` already has a row for this
///    GitHub id. Refresh the cached GitHub profile fields and return the
///    existing local user id.
/// 2. **First GitHub login, but a local account already exists with the same
///    email** — link by inserting only an `oauth_accounts` row pointing at
///    that user; refresh display fields (name/avatar/html_url) but preserve
///    `username`, `email`, and `password_hash` so the account's password
///    sign-in keeps working unchanged.
/// 3. **Brand-new user** — insert a new `users` row, link via
///    `oauth_accounts`, and seed default permissions.
///
/// GitHub's `/user` only returns `email` when the user has made it public,
/// so the link branch is best-effort. Linking is safe because the email on
/// `GithubProfile` came from an authenticated GitHub session — i.e. the
/// caller already controls that mailbox.
#[cfg(feature = "oauth-github")]
pub async fn upsert_github_user(
    db: &Pool,
    profile: GithubProfile<'_>,
) -> anyhow::Result<i64> {
    let github_id_str = profile.id.to_string();

    // 1) Already linked → refresh + return.
    let existing: Option<(i64,)> = sqlx::query_as(
        "SELECT user_id FROM oauth_accounts WHERE provider = 'github' AND provider_user_id = $1",
    )
    .bind(&github_id_str)
    .fetch_optional(db)
    .await?;

    if let Some((user_id,)) = existing {
        sqlx::query(
            "UPDATE users SET username = $1, name = $2, email = $3, avatar_url = $4, html_url = $5 \
             WHERE id = $6",
        )
        .bind(profile.login)
        .bind(profile.name)
        .bind(profile.email)
        .bind(profile.avatar_url)
        .bind(profile.html_url)
        .bind(user_id)
        .execute(db)
        .await?;
        return Ok(user_id);
    }

    // 2) Email matches an existing local account → link rather than duplicate.
    if let Some(email) = profile.email {
        let matched: Option<(i64,)> = sqlx::query_as(
            "SELECT id FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1",
        )
        .bind(email)
        .fetch_optional(db)
        .await?;

        if let Some((user_id,)) = matched {
            sqlx::query(
                "INSERT INTO oauth_accounts (provider, provider_user_id, user_id) \
                 VALUES ('github', $1, $2)",
            )
            .bind(&github_id_str)
            .bind(user_id)
            .execute(db)
            .await?;

            sqlx::query(
                "UPDATE users SET name = $1, avatar_url = $2, html_url = $3 WHERE id = $4",
            )
            .bind(profile.name)
            .bind(profile.avatar_url)
            .bind(profile.html_url)
            .bind(user_id)
            .execute(db)
            .await?;

            return Ok(user_id);
        }
    }

    // 3) Brand-new user. GitHub already verifies the address, so we mark
    //    `email_verified_at` now to skip the verification email flow.
    let (user_id,): (i64,) = sqlx::query_as(
        "INSERT INTO users (anonymous, username, name, email, avatar_url, html_url, email_verified_at) \
         VALUES (false, $1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(profile.login)
    .bind(profile.name)
    .bind(profile.email)
    .bind(profile.avatar_url)
    .bind(profile.html_url)
    .bind(unix_now())
    .fetch_one(db)
    .await?;

    sqlx::query(
        "INSERT INTO oauth_accounts (provider, provider_user_id, user_id) VALUES ('github', $1, $2)",
    )
    .bind(&github_id_str)
    .bind(user_id)
    .execute(db)
    .await?;

    assign_default_role(db, user_id).await?;
    maybe_bootstrap_admin(db, user_id, profile.email).await?;

    Ok(user_id)
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
    let target = std::env::var("DX_AUTH_BOOTSTRAP_ADMIN_EMAIL")
        .or_else(|_| std::env::var("BOOTSTRAP_ADMIN_EMAIL"))
        .ok()
        .filter(|s| !s.is_empty());
    if let Some(t) = target {
        if t.eq_ignore_ascii_case(email) {
            grant_role(db, user_id, role::ADMIN).await?;
        }
    }
    Ok(())
}

/// Grant the baseline role every newly-created (non-anonymous) account gets.
/// Called from `create_password_user` and `upsert_github_user` on the
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
pub async fn set_user_roles(
    db: &Pool,
    user_id: i64,
    role_ids: &[i64],
) -> anyhow::Result<()> {
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

#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, PartialEq)]
pub struct RoleRow {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
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
            name = NULL, \
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

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AdminUserRow {
    pub id: i64,
    pub username: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub email_verified_at: Option<i64>,
    pub mfa_enabled_at: Option<i64>,
    pub anonymous: bool,
    pub deleted_at: Option<i64>,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
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
                mfa_enabled_at, anonymous, deleted_at, name, avatar_url, html_url \
         FROM users \
         ORDER BY id \
         LIMIT $1 OFFSET $2",
    )
    .bind(limit.max(1).min(500))
    .bind(offset.max(0))
    .fetch_all(db)
    .await?;
    Ok(rows)
}

/// Single-user detail for the admin UI.
pub async fn get_user_for_admin(
    db: &Pool,
    user_id: i64,
) -> anyhow::Result<Option<AdminUserRow>> {
    let row = sqlx::query_as::<_, AdminUserRow>(
        "SELECT id, username, display_name, email, email_verified_at, \
                mfa_enabled_at, anonymous, deleted_at, name, avatar_url, html_url \
         FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(db)
    .await?;
    Ok(row)
}

/// Tokens a single user resolves to (direct + role-derived). The same
/// query `load_user` uses, just public for the admin detail view.
pub async fn list_permissions_for_user(
    db: &Pool,
    user_id: i64,
) -> anyhow::Result<Vec<String>> {
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
pub async fn list_permissions_for_role(
    db: &Pool,
    role_id: i64,
) -> anyhow::Result<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT token FROM role_permissions WHERE role_id = $1 ORDER BY token",
    )
    .bind(role_id)
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|(t,)| t).collect())
}

// ---- Account self-service helpers (called by Phase 11c server fns) ----

/// Look up the current password hash for the given user (None for OAuth-only
/// accounts). Used by `change_password` to verify the old password before
/// writing the new one.
pub async fn get_password_hash(
    db: &Pool,
    user_id: i64,
) -> anyhow::Result<Option<String>> {
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
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    use argon2::Argon2;
    let Ok(parsed) = PasswordHash::new(stored_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(candidate.as_bytes(), &parsed)
        .is_ok()
}

/// OAuth provider names this user has linked accounts for (e.g. "github").
pub async fn linked_oauth_providers(
    db: &Pool,
    user_id: i64,
) -> anyhow::Result<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT DISTINCT provider FROM oauth_accounts WHERE user_id = $1 ORDER BY provider",
    )
    .bind(user_id)
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|(p,)| p).collect())
}

/// Create a new email/password account.
///
/// Returns the new user's id on success. The error is a user-facing message
/// (server fn can surface it verbatim) — we deliberately avoid distinguishing
/// "no such user" from "wrong password" anywhere to prevent enumeration.
pub async fn create_password_user(
    db: &Pool,
    email: &str,
    password: &str,
) -> anyhow::Result<i64> {
    use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
    use argon2::Argon2;

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

    let username = email.split('@').next().unwrap_or(email);

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
    Ok(user_id)
}

/// Issue a one-hour password reset token for the account with the given email.
///
/// Returns `Some(token)` when the account exists and has a password set.
/// Returns `None` when no such account exists — the server fn deliberately
/// surfaces the same "we sent it if the address was valid" response in both
/// cases to avoid revealing which emails are registered.
pub async fn request_password_reset(
    db: &Pool,
    email: &str,
) -> anyhow::Result<Option<String>> {
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

    let expires_at = unix_now() + 3600;

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
    use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
    use argon2::Argon2;
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
    Verified(i64),
    Unverified,
    Invalid,
}

/// Verify an email/password pair and the account's email-verified status.
pub async fn verify_password_user(
    db: &Pool,
    email: &str,
    password: &str,
) -> anyhow::Result<VerifyOutcome> {
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    use argon2::Argon2;

    let row: Option<(i64, String, Option<i64>)> = sqlx::query_as(
        "SELECT id, password_hash, email_verified_at FROM users \
         WHERE LOWER(email) = LOWER($1) AND password_hash IS NOT NULL \
         LIMIT 1",
    )
    .bind(email.trim())
    .fetch_optional(db)
    .await?;

    let Some((user_id, stored_hash, verified_at)) = row else {
        return Ok(VerifyOutcome::Invalid);
    };

    let Ok(parsed) = PasswordHash::new(&stored_hash) else {
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
pub async fn issue_verification_token(
    db: &Pool,
    user_id: i64,
) -> anyhow::Result<String> {
    use argon2::password_hash::rand_core::{OsRng, RngCore};

    // 16 random bytes = 128 bits of entropy, plenty for short-lived
    // single-use tokens. Hex-encoded that's 32 chars, which keeps the
    // resulting reset/verify URL under 76 chars so the plain-text email body
    // stays in 7bit transfer encoding (clean URLs in raw `.eml` views).
    let mut bytes = [0u8; 16];
    let mut rng = OsRng;
    rng.fill_bytes(&mut bytes);
    let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();

    let expires_at = unix_now() + 24 * 3600;

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
pub async fn consume_verification_token(
    db: &Pool,
    token: &str,
) -> anyhow::Result<Option<i64>> {
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
    pub secret_base32: String,
    pub qr_png_base64: String,
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
    use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
    use argon2::Argon2;
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
pub async fn enable_mfa(
    db: &Pool,
    user_id: i64,
    totp_code: &str,
) -> anyhow::Result<bool> {
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
pub async fn verify_mfa_challenge(
    db: &Pool,
    user_id: i64,
    code: &str,
) -> anyhow::Result<bool> {
    let code = code.trim();

    if let Some(secret) = load_mfa_secret(db, user_id).await? {
        if check_totp(&secret, code) {
            return Ok(true);
        }
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
async fn consume_recovery_code(
    db: &Pool,
    user_id: i64,
    candidate: &str,
) -> anyhow::Result<bool> {
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    use argon2::Argon2;

    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT code_hash FROM mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL",
    )
    .bind(user_id)
    .fetch_all(db)
    .await?;

    for (hash,) in rows {
        if let Ok(parsed) = PasswordHash::new(&hash) {
            if Argon2::default()
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
        .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
        .collect()
}

/// Look up a still-unverified password account by email. Used by the
/// "resend verification email" endpoint.
pub async fn find_unverified_user_id(
    db: &Pool,
    email: &str,
) -> anyhow::Result<Option<i64>> {
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
// Audit log (Phase 12)
// ============================================================

/// Library helpers for writing and reading the audit log. The set of
/// emitted event types is open: callers pass arbitrary strings (we
/// recommend a `domain.action.qualifier` scheme — see the constants below).
pub mod audit {
    use super::*;
    use crate::wire::{AuditEventView, AuditQuery};

    // -- Canonical event-type constants used by the library's own server fns. --
    // Apps are free to emit their own taxonomies in addition.

    pub const USER_LOGIN_SUCCESS: &str = "user.login.success";
    pub const USER_LOGIN_FAILED:  &str = "user.login.failed";
    pub const USER_LOGOUT:        &str = "user.logout";
    pub const USER_SIGNUP:        &str = "user.signup";
    pub const USER_EMAIL_VERIFIED: &str = "user.email_verified";
    pub const USER_PWD_RESET_REQUESTED: &str = "user.password_reset.requested";
    pub const USER_PWD_RESET_CONSUMED:  &str = "user.password_reset.consumed";
    pub const USER_MFA_ENABLED:   &str = "user.mfa.enabled";
    pub const USER_MFA_DISABLED:  &str = "user.mfa.disabled";

    pub const ACCOUNT_PASSWORD_CHANGED:    &str = "account.password_changed";
    pub const ACCOUNT_DISPLAY_NAME_CHANGED: &str = "account.display_name_changed";
    pub const ACCOUNT_SELF_DELETED:        &str = "account.self_deleted";

    pub const ADMIN_ROLES_CHANGED: &str = "admin.user.roles_changed";
    pub const ADMIN_USER_DELETED:  &str = "admin.user.soft_deleted";

    /// All fields are optional — pass `None` for whatever you don't have.
    /// `details` should be a small JSON document (or `None`).
    pub struct RecordInput<'a> {
        pub event_type: &'a str,
        pub actor_id: Option<i64>,
        pub target_id: Option<i64>,
        pub ip: Option<&'a str>,
        pub user_agent: Option<&'a str>,
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
        let (type_clause, type_pattern, type_is_filtered) =
            if q.event_type.is_empty() {
                ("".to_string(), String::new(), false)
            } else if q.event_type.ends_with('.') {
                (" AND e.event_type LIKE $1".to_string(),
                 format!("{}%", q.event_type),
                 true)
            } else {
                (" AND e.event_type = $1".to_string(),
                 q.event_type.clone(),
                 true)
            };

        // Build the parameter list incrementally so positional placeholders
        // line up across sqlite/postgres ($N works on both).
        let mut idx = if type_is_filtered { 2 } else { 1 };
        let mut clauses = String::new();

        let actor_idx = q.actor_id.map(|_| {
            let i = idx;
            idx += 1;
            clauses.push_str(&format!(" AND e.actor_id = ${i}"));
            i
        });
        let target_idx = q.target_id.map(|_| {
            let i = idx;
            idx += 1;
            clauses.push_str(&format!(" AND e.target_id = ${i}"));
            i
        });
        let since_idx = q.since.map(|_| {
            let i = idx;
            idx += 1;
            clauses.push_str(&format!(" AND e.occurred_at >= ${i}"));
            i
        });
        let until_idx = q.until.map(|_| {
            let i = idx;
            idx += 1;
            clauses.push_str(&format!(" AND e.occurred_at <= ${i}"));
            i
        });
        let limit_idx = idx;
        let offset_idx = idx + 1;

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
        let cutoff = unix_now() - (retention_days as i64) * 86_400;
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
