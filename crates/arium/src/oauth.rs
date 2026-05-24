//! Pluggable third-party OAuth providers.
//!
//! Apps register providers on [`AuthConfigBuilder`](crate::AuthConfigBuilder)
//! via [`OAuthRegistry::with_provider`]. [`crate::install`] then mounts the
//! generic `/auth/{provider}/login` + `/auth/{provider}/callback` routes for
//! every registered provider.
//!
//! ## Adding a new provider
//!
//! Most providers are **OpenID Connect** compliant — for those, don't write a
//! bespoke impl. Construct an `oidc::OidcProvider` (or use a preset such as
//! `google` / `microsoft`) with the issuer URL and discovery, PKCE, and
//! `id_token` validation are handled for you. The OIDC presets are **async**
//! (`from_env().await`) because discovery does network I/O at construction.
//!
//! For a non-OIDC provider (like GitHub):
//!
//! 1. Add a feature flag in `Cargo.toml` (e.g. `oauth-foo = ["_oauth-core"]`).
//! 2. Implement [`OAuthProvider`] for a struct that holds your client id /
//!    secret / redirect URL, and write a `fetch_profile` that normalises the
//!    provider's user-info response into a [`NormalizedProfile`]. The default
//!    [`begin`](OAuthProvider::begin) / [`finish`](OAuthProvider::finish) cover
//!    the standard OAuth2 code flow; opt into PKCE via
//!    [`use_pkce`](OAuthProvider::use_pkce).
//! 3. Register it on the builder:
//!    `AuthConfig::builder(...).oauth_provider(FooProvider::from_env()?.unwrap())`.

#![cfg(feature = "_oauth-core")]

use async_trait::async_trait;
use std::sync::Arc;

use crate::pool::Pool;

pub mod github;
#[cfg(feature = "oauth-google")]
pub mod google;
#[cfg(feature = "oauth-microsoft")]
pub mod microsoft;
#[cfg(feature = "oauth-oidc")]
pub mod oidc;

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

/// Per-attempt OAuth secrets persisted in the session between the `login`
/// redirect and the `callback`. Always carries the CSRF `state`; OIDC providers
/// additionally store the PKCE verifier and the `nonce` bound into the
/// `id_token`. Stored under [`oauth_state_key`] and consumed once at callback.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OAuthAttempt {
    /// Opaque CSRF token echoed back as the `state` query parameter.
    pub csrf_state: String,
    /// PKCE (RFC 7636) code verifier, when the provider uses PKCE.
    pub pkce_verifier: Option<String>,
    /// OIDC nonce bound into the `id_token`, when the provider is OIDC.
    pub nonce: Option<String>,
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
    /// and return a [`NormalizedProfile`]. The shared HTTP client already sends
    /// a default `User-Agent` (see [`OAuthRegistry::new`]).
    async fn fetch_profile(
        &self,
        http: &reqwest::Client,
        access_token: &str,
    ) -> anyhow::Result<NormalizedProfile>;

    /// Whether the default [`begin`](OAuthProvider::begin) /
    /// [`finish`](OAuthProvider::finish) flow should use PKCE (RFC 7636).
    /// `false` by default; plain-OAuth2 providers can opt in when the provider
    /// supports it. OIDC providers use PKCE unconditionally via their own
    /// `begin`/`finish` overrides, independent of this flag.
    fn use_pkce(&self) -> bool {
        false
    }

    /// Start a login: build the authorize redirect URL plus the per-attempt
    /// secrets ([`OAuthAttempt`]) to persist in the session. The default impl
    /// runs the standard OAuth2 authorize-code request (random CSRF state, plus
    /// a PKCE challenge when [`use_pkce`](OAuthProvider::use_pkce) is `true`).
    /// OIDC providers override this to add a nonce.
    fn begin(&self) -> anyhow::Result<(String, OAuthAttempt)> {
        use oauth2::{CsrfToken, PkceCodeChallenge, Scope};

        let client = basic_client(self)?;
        let mut request = client.authorize_url(CsrfToken::new_random);
        for scope in self.scopes() {
            request = request.add_scope(Scope::new((*scope).to_string()));
        }

        let pkce_verifier = if self.use_pkce() {
            let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
            request = request.set_pkce_challenge(challenge);
            Some(verifier.secret().to_string())
        } else {
            None
        };

        let (auth_url, csrf_state) = request.url();
        Ok((
            auth_url.to_string(),
            OAuthAttempt {
                csrf_state: csrf_state.secret().to_string(),
                pkce_verifier,
                nonce: None,
            },
        ))
    }

    /// Finish a login: exchange `code` for tokens (replaying the PKCE verifier
    /// from `attempt` when present) and return a [`NormalizedProfile`]. The
    /// default impl does the OAuth2 code exchange then calls
    /// [`fetch_profile`](OAuthProvider::fetch_profile). OIDC providers override
    /// this to validate the `id_token` against the stored nonce + the provider
    /// JWKS.
    async fn finish(
        &self,
        http: &reqwest::Client,
        code: &str,
        attempt: &OAuthAttempt,
    ) -> anyhow::Result<NormalizedProfile> {
        use oauth2::{AuthorizationCode, PkceCodeVerifier, TokenResponse};

        let client = basic_client(self)?;
        let mut request = client.exchange_code(AuthorizationCode::new(code.to_string()));
        if let Some(verifier) = attempt.pkce_verifier.as_ref() {
            request = request.set_pkce_verifier(PkceCodeVerifier::new(verifier.clone()));
        }
        let token = request.request_async(http).await?;
        self.fetch_profile(http, token.access_token().secret())
            .await
    }
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
    /// follow redirects (SSRF mitigation per the `oauth2` crate guidance) and
    /// to send a default `arium/<version>` `User-Agent` on every provider
    /// request (some providers, e.g. GitHub, reject requests without one).
    pub fn new(db: Pool) -> anyhow::Result<Self> {
        let http = reqwest::ClientBuilder::new()
            .user_agent(concat!("arium/", env!("CARGO_PKG_VERSION")))
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
        // Refresh provider-owned fields only. `username` is the user's stable
        // handle (assigned once — a rename on the provider must not silently
        // change it), and `display_name` is user-editable (refreshing it would
        // clobber a name the user chose in account settings).
        sqlx::query("UPDATE users SET email = $1, avatar_url = $2, html_url = $3 WHERE id = $4")
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

            // Refresh provider-owned display fields. Seed `display_name` from
            // the provider only when the linked account doesn't already have
            // one (COALESCE keeps a name the user chose); preserve `username`,
            // `email`, and `password_hash` so password sign-in keeps working.
            sqlx::query(
                "UPDATE users SET display_name = COALESCE(display_name, $1), \
                 avatar_url = $2, html_url = $3 WHERE id = $4",
            )
            .bind(profile.name.as_deref())
            .bind(profile.avatar_url.as_deref())
            .bind(profile.html_url.as_deref())
            .bind(user_id)
            .execute(db)
            .await?;

            return Ok(user_id);
        }
    }

    // 3) Brand-new user. Allocate a unique handle from the provider login
    //    (collision-suffixed) and seed the editable `display_name` from the
    //    provider's reported name. The provider already verified the address
    //    (or didn't return one), so we mark `email_verified_at` now to skip
    //    the verification email flow.
    let username = crate::auth::unique_username(db, &profile.login).await?;
    let (user_id,): (i64,) = sqlx::query_as(
        "INSERT INTO users (anonymous, username, display_name, email, avatar_url, html_url, email_verified_at) \
         VALUES (false, $1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(&username)
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

fn basic_client<P: OAuthProvider + ?Sized>(p: &P) -> anyhow::Result<BasicClient> {
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
    session: crate::extract::SessionStore,
) -> Result<axum::response::Redirect, (axum::http::StatusCode, String)> {
    let provider_arc = reg.get(&provider).ok_or_else(|| {
        http_err(
            axum::http::StatusCode::NOT_FOUND,
            format!("unknown oauth provider: {provider}"),
        )
    })?;

    let (auth_url, attempt) = provider_arc
        .begin()
        .map_err(|e| http_err(axum::http::StatusCode::INTERNAL_SERVER_ERROR, e))?;

    // Persist the per-attempt secrets (CSRF state + any PKCE verifier / nonce)
    // for the callback to validate against.
    session.set(&oauth_state_key(&provider), attempt);

    Ok(axum::response::Redirect::to(&auth_url))
}

pub(crate) async fn oauth_callback(
    axum::extract::State(reg): axum::extract::State<OAuthRegistry>,
    axum::extract::Path(provider): axum::extract::Path<String>,
    session: crate::extract::SessionStore,
    auth_session: crate::auth::Session,
    audit: crate::extract::AuditCtx,
    axum::extract::Query(params): axum::extract::Query<CallbackParams>,
) -> Result<axum::response::Redirect, (axum::http::StatusCode, String)> {
    let provider_arc = reg.get(&provider).ok_or_else(|| {
        http_err(
            axum::http::StatusCode::NOT_FOUND,
            format!("unknown oauth provider: {provider}"),
        )
    })?;

    let state_key = oauth_state_key(&provider);
    let attempt: Option<OAuthAttempt> = session.get(&state_key);
    session.remove(&state_key);

    let attempt = attempt.ok_or_else(|| {
        http_err(
            axum::http::StatusCode::BAD_REQUEST,
            "missing oauth state in session",
        )
    })?;

    if attempt.csrf_state != params.state {
        return Err(http_err(
            axum::http::StatusCode::BAD_REQUEST,
            "oauth state mismatch",
        ));
    }

    // The provider owns token exchange + profile extraction: the default impl
    // does an OAuth2 code exchange + user-info fetch; OIDC providers validate
    // the `id_token`. Both surface upstream/parse failures as 502.
    let profile = provider_arc
        .finish(&reg.http, &params.code, &attempt)
        .await
        .map_err(|e| {
            http_err(
                axum::http::StatusCode::BAD_GATEWAY,
                format!("oauth token exchange / profile fetch failed: {e}"),
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
