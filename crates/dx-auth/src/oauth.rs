//! Pluggable third-party OAuth providers.
//!
//! Apps register providers on [`AuthConfigBuilder`](crate::AuthConfigBuilder)
//! via [`OAuthRegistry::with_provider`]. [`crate::install`] then mounts the
//! generic `/auth/{provider}/login` + `/auth/{provider}/callback` routes for
//! every registered provider.
//!
//! ## Adding a new provider
//!
//! 1. Add a feature flag in `Cargo.toml` (e.g. `oauth-google = ["_oauth-core"]`).
//! 2. Implement [`OAuthProvider`] for a struct that holds your client id /
//!    secret / redirect URL, and write a `fetch_profile` that normalises the
//!    provider's user-info response into a [`NormalizedProfile`].
//! 3. Register it on the builder:
//!    `AuthConfig::builder(...).oauth_provider(GoogleProvider::from_env()?.unwrap())`.

#![cfg(all(feature = "server", feature = "_oauth-core"))]

use async_trait::async_trait;
use std::sync::Arc;

use crate::pool::Pool;

pub mod github;

/// Normalised subset of a provider's user-info response. Every provider's
/// `fetch_profile` returns this so [`upsert_oauth_user`] doesn't need to know
/// about GitHub vs. Google vs. Microsoft response shapes.
#[derive(Debug, Clone)]
pub struct NormalizedProfile {
    /// The provider's stable user id, stringified. Goes into
    /// `oauth_accounts.provider_user_id`.
    pub provider_user_id: String,
    /// Username-ish handle for the local `users.username` column. Providers
    /// without a public handle should fall back to the local-part of the
    /// email or the user id.
    pub login: String,
    /// Display name reported by the provider, when available.
    pub name: Option<String>,
    /// Primary email address reported by the provider, when available.
    pub email: Option<String>,
    /// Avatar URL reported by the provider, when available.
    pub avatar_url: Option<String>,
    /// Public profile URL on the provider's site (e.g. `https://github.com/octocat`).
    /// `None` for providers that don't expose one.
    pub html_url: Option<String>,
}

/// One pluggable identity provider.
#[async_trait]
pub trait OAuthProvider: Send + Sync + 'static {
    /// Stable lowercase machine name. Used in URLs (`/auth/{name}/login`) and
    /// stored verbatim in `oauth_accounts.provider`. Must be unique within a
    /// registry.
    fn name(&self) -> &str;

    /// Human-readable name shown on the sign-in button (e.g. "GitHub").
    fn display_name(&self) -> &str;

    /// Optional inline SVG markup for the provider button icon. Returning
    /// `Some(...)` lets the library ship a default icon; consumers can still
    /// override it in their own UI by ignoring the value.
    fn icon_svg(&self) -> Option<&str> {
        None
    }

    /// Provider OAuth client id.
    fn client_id(&self) -> &str;
    /// Provider OAuth client secret.
    fn client_secret(&self) -> &str;
    /// Redirect URL registered with the provider — must match exactly,
    /// including scheme and trailing slash.
    fn redirect_url(&self) -> &str;
    /// Authorize endpoint URL.
    fn auth_url(&self) -> &str;
    /// Token endpoint URL.
    fn token_url(&self) -> &str;

    /// OAuth scopes to request during the authorize step.
    fn scopes(&self) -> &[&str];

    /// Hit the provider's user-info endpoint with the obtained access token
    /// and return a [`NormalizedProfile`]. Implementations should set
    /// `User-Agent` (some providers reject requests without one).
    async fn fetch_profile(
        &self,
        http: &reqwest::Client,
        access_token: &str,
    ) -> anyhow::Result<NormalizedProfile>;
}

/// Holds every registered OAuth provider plus the shared HTTP client + DB
/// handle. Cloned into axum state for the generic OAuth handlers.
#[derive(Clone)]
pub struct OAuthRegistry {
    /// Database pool shared with the rest of the app; OAuth callback uses it
    /// to look up / create the local `users` row.
    pub db: Pool,
    /// Shared HTTP client; redirects are disabled (SSRF mitigation per the
    /// `oauth2` crate guidance).
    pub http: reqwest::Client,
    providers: Arc<Vec<Arc<dyn OAuthProvider>>>,
}

impl OAuthRegistry {
    /// Build an empty registry with a default HTTP client configured to NOT
    /// follow redirects (SSRF mitigation per the `oauth2` crate guidance).
    pub fn new(db: Pool) -> anyhow::Result<Self> {
        let http = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            db,
            http,
            providers: Arc::new(Vec::new()),
        })
    }

    /// Add a provider. Panics in debug if a provider with the same `name()`
    /// is already registered.
    pub fn with_provider<P: OAuthProvider>(mut self, p: P) -> Self {
        let mut v = (*self.providers).clone();
        debug_assert!(
            v.iter().all(|existing| existing.name() != p.name()),
            "OAuthRegistry: duplicate provider name {:?}",
            p.name()
        );
        v.push(Arc::new(p));
        self.providers = Arc::new(v);
        self
    }

    /// Look up a registered provider by its lowercase machine name.
    pub fn get(&self, name: &str) -> Option<Arc<dyn OAuthProvider>> {
        self.providers.iter().find(|p| p.name() == name).cloned()
    }

    /// All registered providers in registration order.
    pub fn list(&self) -> &[Arc<dyn OAuthProvider>] {
        &self.providers
    }

    /// `true` when no providers are registered (the OAuth routes are skipped).
    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }
}

/// Find-or-create-or-link a local user row for the given third-party identity.
///
/// Three branches, tried in order, all keyed on the runtime `provider` name:
///
/// 1. **Repeat OAuth login** — `oauth_accounts` already has a row for this
///    `(provider, provider_user_id)`. Refresh cached profile fields and return
///    the existing local user id.
/// 2. **First login with this provider, but a local account already exists
///    with the same email** — link by inserting an `oauth_accounts` row
///    pointing at that user; refresh display fields (name/avatar/html_url)
///    but preserve `username`, `email`, and `password_hash` so the account's
///    password sign-in keeps working unchanged.
/// 3. **Brand-new user** — insert a new `users` row, link via
///    `oauth_accounts`, and seed default permissions.
pub async fn upsert_oauth_user(
    db: &Pool,
    provider: &str,
    profile: NormalizedProfile,
) -> anyhow::Result<i64> {
    // 1) Already linked → refresh + return.
    let existing: Option<(i64,)> = sqlx::query_as(
        "SELECT user_id FROM oauth_accounts WHERE provider = $1 AND provider_user_id = $2",
    )
    .bind(provider)
    .bind(&profile.provider_user_id)
    .fetch_optional(db)
    .await?;

    if let Some((user_id,)) = existing {
        sqlx::query(
            "UPDATE users SET username = $1, name = $2, email = $3, avatar_url = $4, html_url = $5 \
             WHERE id = $6",
        )
        .bind(&profile.login)
        .bind(profile.name.as_deref())
        .bind(profile.email.as_deref())
        .bind(profile.avatar_url.as_deref())
        .bind(profile.html_url.as_deref())
        .bind(user_id)
        .execute(db)
        .await?;
        return Ok(user_id);
    }

    // 2) Email matches an existing local account → link rather than duplicate.
    if let Some(email) = profile.email.as_deref() {
        let matched: Option<(i64,)> =
            sqlx::query_as("SELECT id FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1")
                .bind(email)
                .fetch_optional(db)
                .await?;

        if let Some((user_id,)) = matched {
            sqlx::query(
                "INSERT INTO oauth_accounts (provider, provider_user_id, user_id) \
                 VALUES ($1, $2, $3)",
            )
            .bind(provider)
            .bind(&profile.provider_user_id)
            .bind(user_id)
            .execute(db)
            .await?;

            sqlx::query("UPDATE users SET name = $1, avatar_url = $2, html_url = $3 WHERE id = $4")
                .bind(profile.name.as_deref())
                .bind(profile.avatar_url.as_deref())
                .bind(profile.html_url.as_deref())
                .bind(user_id)
                .execute(db)
                .await?;

            return Ok(user_id);
        }
    }

    // 3) Brand-new user. The provider already verified the address (or didn't
    //    return one), so we mark `email_verified_at` now to skip the
    //    verification email flow.
    let (user_id,): (i64,) = sqlx::query_as(
        "INSERT INTO users (anonymous, username, name, email, avatar_url, html_url, email_verified_at) \
         VALUES (false, $1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(&profile.login)
    .bind(profile.name.as_deref())
    .bind(profile.email.as_deref())
    .bind(profile.avatar_url.as_deref())
    .bind(profile.html_url.as_deref())
    .bind(unix_now())
    .fetch_one(db)
    .await?;

    sqlx::query(
        "INSERT INTO oauth_accounts (provider, provider_user_id, user_id) VALUES ($1, $2, $3)",
    )
    .bind(provider)
    .bind(&profile.provider_user_id)
    .bind(user_id)
    .execute(db)
    .await?;

    crate::auth::assign_default_role(db, user_id).await?;
    crate::auth::maybe_bootstrap_admin(db, user_id, profile.email.as_deref()).await?;
    crate::auth::maybe_grant_first_admin(db, user_id).await?;

    Ok(user_id)
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// ============================================================
// Generic OAuth axum handlers (mounted by `install`)
// ============================================================

type BasicClient = oauth2::basic::BasicClient<
    oauth2::EndpointSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointSet,
>;

fn basic_client(p: &dyn OAuthProvider) -> anyhow::Result<BasicClient> {
    use oauth2::basic::BasicClient as Bc;
    use oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};

    Ok(Bc::new(ClientId::new(p.client_id().to_string()))
        .set_client_secret(ClientSecret::new(p.client_secret().to_string()))
        .set_auth_uri(AuthUrl::new(p.auth_url().to_string())?)
        .set_token_uri(TokenUrl::new(p.token_url().to_string())?)
        .set_redirect_uri(RedirectUrl::new(p.redirect_url().to_string())?))
}

fn http_err<E: std::fmt::Display>(
    status: axum::http::StatusCode,
    e: E,
) -> (axum::http::StatusCode, String) {
    (status, e.to_string())
}

fn oauth_state_key(provider: &str) -> String {
    format!("oauth_state:{provider}")
}

#[derive(serde::Deserialize)]
pub(crate) struct CallbackParams {
    code: String,
    state: String,
}

pub(crate) async fn oauth_login(
    axum::extract::State(reg): axum::extract::State<OAuthRegistry>,
    axum::extract::Path(provider): axum::extract::Path<String>,
    session: crate::server::SessionStore,
) -> Result<axum::response::Redirect, (axum::http::StatusCode, String)> {
    use oauth2::{CsrfToken, Scope};

    let provider_arc = reg.get(&provider).ok_or_else(|| {
        http_err(
            axum::http::StatusCode::NOT_FOUND,
            format!("unknown oauth provider: {provider}"),
        )
    })?;

    let client = basic_client(&*provider_arc)
        .map_err(|e| http_err(axum::http::StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let mut request = client.authorize_url(CsrfToken::new_random);
    for scope in provider_arc.scopes() {
        request = request.add_scope(Scope::new((*scope).to_string()));
    }
    let (auth_url, csrf_state) = request.url();

    session.set(&oauth_state_key(&provider), csrf_state.secret().to_string());

    Ok(axum::response::Redirect::to(auth_url.as_ref()))
}

pub(crate) async fn oauth_callback(
    axum::extract::State(reg): axum::extract::State<OAuthRegistry>,
    axum::extract::Path(provider): axum::extract::Path<String>,
    session: crate::server::SessionStore,
    auth_session: crate::auth::Session,
    audit: crate::server::AuditCtx,
    axum::extract::Query(params): axum::extract::Query<CallbackParams>,
) -> Result<axum::response::Redirect, (axum::http::StatusCode, String)> {
    use oauth2::{AuthorizationCode, TokenResponse};

    let provider_arc = reg.get(&provider).ok_or_else(|| {
        http_err(
            axum::http::StatusCode::NOT_FOUND,
            format!("unknown oauth provider: {provider}"),
        )
    })?;

    let state_key = oauth_state_key(&provider);
    let expected_state: Option<String> = session.get(&state_key);
    session.remove(&state_key);

    let expected = expected_state.ok_or_else(|| {
        http_err(
            axum::http::StatusCode::BAD_REQUEST,
            "missing oauth state in session",
        )
    })?;

    if expected != params.state {
        return Err(http_err(
            axum::http::StatusCode::BAD_REQUEST,
            "oauth state mismatch",
        ));
    }

    let client = basic_client(&*provider_arc)
        .map_err(|e| http_err(axum::http::StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let token = client
        .exchange_code(AuthorizationCode::new(params.code))
        .request_async(&reg.http)
        .await
        .map_err(|e| {
            http_err(
                axum::http::StatusCode::BAD_GATEWAY,
                format!("token exchange failed: {e}"),
            )
        })?;

    let profile = provider_arc
        .fetch_profile(&reg.http, token.access_token().secret())
        .await
        .map_err(|e| {
            http_err(
                axum::http::StatusCode::BAD_GATEWAY,
                format!("user-info fetch failed: {e}"),
            )
        })?;

    let user_id = upsert_oauth_user(&reg.db, provider_arc.name(), profile)
        .await
        .map_err(|e| http_err(axum::http::StatusCode::INTERNAL_SERVER_ERROR, e))?;

    auth_session.login_user(user_id);
    audit
        .record(
            &reg.db,
            crate::auth::audit::USER_LOGIN_SUCCESS,
            Some(user_id),
            Some(user_id),
            Some(&format!(
                "{{\"method\":\"oauth\",\"provider\":\"{}\"}}",
                provider_arc.name()
            )),
        )
        .await;

    Ok(axum::response::Redirect::to("/"))
}
