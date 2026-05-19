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
    pub fn from_env(db: SqlitePool) -> anyhow::Result<Self> {
        let github_client_id = std::env::var("GITHUB_CLIENT_ID")
            .map_err(|_| anyhow::anyhow!("GITHUB_CLIENT_ID must be set"))?;
        let github_client_secret = std::env::var("GITHUB_CLIENT_SECRET")
            .map_err(|_| anyhow::anyhow!("GITHUB_CLIENT_SECRET must be set"))?;
        let github_redirect_url = std::env::var("GITHUB_REDIRECT_URL")
            .unwrap_or_else(|_| "http://localhost:8080/auth/github/callback".to_string());

        // Disable automatic redirect following per oauth2 crate guidance (SSRF mitigation).
        let http = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        Ok(Self {
            db,
            http,
            github_client_id,
            github_client_secret,
            github_redirect_url,
        })
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

/// Find-or-create a local user row linked to the given GitHub identity, returning the local id.
/// On a repeat login the existing row's profile fields are refreshed so the local copy stays
/// in sync with GitHub.
pub(crate) async fn upsert_github_user(
    db: &SqlitePool,
    profile: GithubProfile<'_>,
) -> anyhow::Result<i64> {
    let github_id_str = profile.id.to_string();

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
