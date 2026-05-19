//! The code here is pulled from the `axum-session-auth` crate examples, requiring little to no
//! modification to work with dioxus fullstack.

use async_trait::async_trait;
use axum_session_auth::*;
use axum_session_sqlx::SessionSqlitePool;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;
use std::collections::HashSet;

pub(crate) type Session = axum_session_auth::AuthSession<User, i64, SessionSqlitePool, SqlitePool>;
pub(crate) type AuthLayer =
    axum_session_auth::AuthSessionLayer<User, i64, SessionSqlitePool, SqlitePool>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct User {
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
pub(crate) struct SqlPermissionTokens {
    pub token: String,
}

#[async_trait]
impl Authentication<User, i64, SqlitePool> for User {
    async fn load_user(userid: i64, pool: Option<&SqlitePool>) -> Result<User, anyhow::Error> {
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

        let sql_user_perms = sqlx::query_as::<_, SqlPermissionTokens>(
            "SELECT token FROM user_permissions WHERE user_id = $1;",
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
impl HasPermission<SqlitePool> for User {
    async fn has(&self, perm: &str, _pool: &Option<&SqlitePool>) -> bool {
        self.permissions.contains(perm)
    }
}

#[derive(Clone)]
pub(crate) struct OAuthClients {
    pub db: SqlitePool,
    pub http: reqwest::Client,
    pub github_client_id: String,
    pub github_client_secret: String,
    pub github_redirect_url: String,
}

impl OAuthClients {
    /// Build `OAuthClients` from env vars.
    ///
    /// Returns `Ok(Some(_))` when GitHub credentials are configured (both
    /// `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` set and non-empty), or
    /// `Ok(None)` when they're absent — the caller should then skip
    /// registering the OAuth routes and the UI should hide the provider
    /// button. Errors are reserved for genuine misconfiguration (e.g. failure
    /// to build the HTTP client).
    pub fn from_env(db: SqlitePool) -> anyhow::Result<Option<Self>> {
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
pub(crate) struct GithubProfile<'a> {
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
pub(crate) async fn upsert_github_user(
    db: &SqlitePool,
    profile: GithubProfile<'_>,
) -> anyhow::Result<i64> {
    let github_id_str = profile.id.to_string();

    // 1) Already linked → refresh + return.
    let existing: Option<(i64,)> = sqlx::query_as(
        "SELECT user_id FROM oauth_accounts WHERE provider = 'github' AND provider_user_id = ?",
    )
    .bind(&github_id_str)
    .fetch_optional(db)
    .await?;

    if let Some((user_id,)) = existing {
        sqlx::query(
            "UPDATE users SET username = ?, name = ?, email = ?, avatar_url = ?, html_url = ? \
             WHERE id = ?",
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
            "SELECT id FROM users WHERE LOWER(email) = LOWER(?) LIMIT 1",
        )
        .bind(email)
        .fetch_optional(db)
        .await?;

        if let Some((user_id,)) = matched {
            sqlx::query(
                "INSERT INTO oauth_accounts (provider, provider_user_id, user_id) \
                 VALUES ('github', ?, ?)",
            )
            .bind(&github_id_str)
            .bind(user_id)
            .execute(db)
            .await?;

            sqlx::query(
                "UPDATE users SET name = ?, avatar_url = ?, html_url = ? WHERE id = ?",
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

    // 3) Brand-new user.
    let (user_id,): (i64,) = sqlx::query_as(
        "INSERT INTO users (anonymous, username, name, email, avatar_url, html_url) \
         VALUES (false, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(profile.login)
    .bind(profile.name)
    .bind(profile.email)
    .bind(profile.avatar_url)
    .bind(profile.html_url)
    .fetch_one(db)
    .await?;

    sqlx::query(
        "INSERT INTO oauth_accounts (provider, provider_user_id, user_id) VALUES ('github', ?, ?)",
    )
    .bind(&github_id_str)
    .bind(user_id)
    .execute(db)
    .await?;

    seed_default_permissions(db, user_id).await?;

    Ok(user_id)
}

/// Grant the baseline permissions every newly-created account starts with.
/// Phase 3's `create_password_user` should also call this.
pub(crate) async fn seed_default_permissions(
    db: &SqlitePool,
    user_id: i64,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT OR IGNORE INTO user_permissions (user_id, token) VALUES (?, 'Category::View')",
    )
    .bind(user_id)
    .execute(db)
    .await?;
    Ok(())
}

/// Create a new email/password account.
///
/// Returns the new user's id on success. The error is a user-facing message
/// (server fn can surface it verbatim) — we deliberately avoid distinguishing
/// "no such user" from "wrong password" anywhere to prevent enumeration.
pub(crate) async fn create_password_user(
    db: &SqlitePool,
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
         VALUES (false, ?, ?, ?) RETURNING id",
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

    seed_default_permissions(db, user_id).await?;
    Ok(user_id)
}

/// Issue a one-hour password reset token for the account with the given email.
///
/// Returns `Some(token)` when the account exists and has a password set.
/// Returns `None` when no such account exists — the server fn deliberately
/// surfaces the same "we sent it if the address was valid" response in both
/// cases to avoid revealing which emails are registered.
pub(crate) async fn request_password_reset(
    db: &SqlitePool,
    email: &str,
) -> anyhow::Result<Option<String>> {
    use argon2::password_hash::rand_core::{OsRng, RngCore};

    let user: Option<(i64,)> = sqlx::query_as(
        "SELECT id FROM users \
         WHERE LOWER(email) = LOWER(?) AND password_hash IS NOT NULL \
         LIMIT 1",
    )
    .bind(email.trim())
    .fetch_optional(db)
    .await?;

    let Some((user_id,)) = user else {
        return Ok(None);
    };

    let mut bytes = [0u8; 32];
    let mut rng = OsRng;
    rng.fill_bytes(&mut bytes);
    let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();

    let expires_at = unix_now() + 3600;

    sqlx::query(
        "INSERT INTO password_reset_tokens (token, user_id, expires_at) VALUES (?, ?, ?)",
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
pub(crate) async fn consume_password_reset(
    db: &SqlitePool,
    token: &str,
    new_password: &str,
) -> anyhow::Result<()> {
    if new_password.len() < 8 {
        anyhow::bail!("Password must be at least 8 characters.");
    }

    let row: Option<(i64,)> = sqlx::query_as(
        "SELECT user_id FROM password_reset_tokens WHERE token = ? AND expires_at > ? LIMIT 1",
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
    sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
        .bind(&hash)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM password_reset_tokens WHERE user_id = ?")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    Ok(())
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

/// Verify an email/password pair.
///
/// `Ok(Some(id))` on success, `Ok(None)` on any failure (no such user, wrong
/// password, malformed stored hash). Errors that bubble up are reserved for
/// genuinely unexpected database issues.
pub(crate) async fn verify_password_user(
    db: &SqlitePool,
    email: &str,
    password: &str,
) -> anyhow::Result<Option<i64>> {
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    use argon2::Argon2;

    let row: Option<(i64, String)> = sqlx::query_as(
        "SELECT id, password_hash FROM users \
         WHERE LOWER(email) = LOWER(?) AND password_hash IS NOT NULL \
         LIMIT 1",
    )
    .bind(email.trim())
    .fetch_optional(db)
    .await?;

    let Some((user_id, stored_hash)) = row else {
        return Ok(None);
    };

    let Ok(parsed) = PasswordHash::new(&stored_hash) else {
        return Ok(None);
    };

    if Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
    {
        Ok(Some(user_id))
    } else {
        Ok(None)
    }
}
