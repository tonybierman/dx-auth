//! Generic OpenID Connect (OIDC) provider.
//!
//! [`OidcProvider`] implements the OAuth provider trait for any spec-compliant
//! OIDC issuer. It runs discovery (`.well-known/openid-configuration` + JWKS)
//! once at construction, then drives the authorization-code flow with PKCE and
//! validates the returned `id_token` signature, `aud`, `exp`, and `nonce`
//! against the issuer's published keys. Standard claims (`sub`, `email`,
//! `name`, `preferred_username`, `picture`, `profile`) are normalised into a
//! `NormalizedProfile`; when the `id_token` omits the email it falls back to the
//! userinfo endpoint.
//!
//! Most third-party logins (Google, Microsoft/Entra, GitLab, Okta, Auth0,
//! Keycloak, ...) are OIDC compliant, so they need no bespoke code — construct
//! an `OidcProvider` with the issuer URL, or use a preset such as the `google`
//! / `microsoft` modules.
//!
//! Construction is **async** because discovery does network I/O:
//! `OidcProvider::discover(cfg).await` or `OidcProvider::from_env().await`.

#![cfg(feature = "oauth-oidc")]

use anyhow::{Context, anyhow};
use async_trait::async_trait;

use openidconnect::core::{
    CoreClient, CoreIdTokenClaims, CoreProviderMetadata, CoreResponseType, CoreUserInfoClaims,
};
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
};

use super::{NormalizedProfile, OAuthAttempt, OAuthProvider};

/// Scopes requested when none are configured. `openid` is mandatory for OIDC;
/// `email` + `profile` populate the normalised profile.
fn default_scopes() -> Vec<String> {
    vec![
        "openid".to_string(),
        "email".to_string(),
        "profile".to_string(),
    ]
}

/// Configuration for [`OidcProvider::discover`].
pub struct OidcConfig {
    /// Stable lowercase machine name (route segment + `oauth_accounts.provider`).
    pub name: String,
    /// Human-readable label for the sign-in button.
    pub display_name: String,
    /// Optional inline SVG icon for the button.
    pub icon_svg: Option<String>,
    /// OIDC issuer URL (discovery appends `/.well-known/openid-configuration`).
    pub issuer_url: String,
    /// This app's OAuth client id.
    pub client_id: String,
    /// This app's OAuth client secret.
    pub client_secret: String,
    /// Redirect URL registered with the provider.
    pub redirect_url: String,
    /// Requested scopes; `openid` is prepended automatically when absent.
    pub scopes: Vec<String>,
}

/// A configured OIDC provider: the discovered issuer metadata (including its
/// JWKS) plus this app's client credentials and button presentation.
#[derive(Clone)]
pub struct OidcProvider {
    name: String,
    display_name: String,
    icon_svg: Option<String>,
    client_id: String,
    client_secret: String,
    redirect_url: String,
    scopes: Vec<String>,
    metadata: CoreProviderMetadata,
}

impl OidcProvider {
    /// Run OIDC discovery against `config.issuer_url` and build a provider.
    /// Performs network I/O (discovery document + JWKS fetch).
    pub async fn discover(config: OidcConfig) -> anyhow::Result<Self> {
        let issuer = IssuerUrl::new(config.issuer_url.clone())
            .with_context(|| format!("invalid OIDC issuer URL: {}", config.issuer_url))?;

        let http = oidc_http_client()?;
        let metadata = CoreProviderMetadata::discover_async(issuer, &http)
            .await
            .with_context(|| format!("OIDC discovery failed for {}", config.issuer_url))?;

        let mut scopes = if config.scopes.is_empty() {
            default_scopes()
        } else {
            config.scopes
        };
        if !scopes.iter().any(|s| s == "openid") {
            scopes.insert(0, "openid".to_string());
        }

        Ok(Self {
            name: config.name,
            display_name: config.display_name,
            icon_svg: config.icon_svg,
            client_id: config.client_id,
            client_secret: config.client_secret,
            redirect_url: config.redirect_url,
            scopes,
            metadata,
        })
    }

    /// Build a generic OIDC provider from the standard env-var set.
    ///
    /// Reads `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_ISSUER_URL`, plus the
    /// optional `OIDC_REDIRECT_URL`, `OIDC_SCOPES` (space-separated),
    /// `OIDC_NAME`, and `OIDC_DISPLAY_NAME`. Returns `Ok(None)` when the
    /// client id / secret / issuer are not all set (the caller then skips
    /// registering the provider and the LoginPanel hides its button).
    pub async fn from_env() -> anyhow::Result<Option<Self>> {
        let Some((client_id, client_secret)) =
            read_client_env("OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "OIDC")
        else {
            return Ok(None);
        };

        let Some(issuer_url) = env_nonempty("OIDC_ISSUER_URL") else {
            eprintln!(
                "[startup] WARN: OIDC_CLIENT_ID set but OIDC_ISSUER_URL missing — \
                 disabling generic OIDC sign-in."
            );
            return Ok(None);
        };

        let redirect_url = env_nonempty("OIDC_REDIRECT_URL")
            .unwrap_or_else(|| "http://localhost:8080/auth/oidc/callback".to_string());
        let scopes = env_nonempty("OIDC_SCOPES")
            .map(|s| s.split_whitespace().map(str::to_owned).collect())
            .unwrap_or_else(default_scopes);
        let name = env_nonempty("OIDC_NAME").unwrap_or_else(|| "oidc".to_string());
        let display_name = env_nonempty("OIDC_DISPLAY_NAME").unwrap_or_else(|| "SSO".to_string());

        Ok(Some(
            Self::discover(OidcConfig {
                name,
                display_name,
                icon_svg: None,
                issuer_url,
                client_id,
                client_secret,
                redirect_url,
                scopes,
            })
            .await?,
        ))
    }

    /// Rebuild the `openidconnect` client from the stored metadata. No network
    /// I/O — the JWKS was fetched during [`discover`](Self::discover).
    fn build_client(
        &self,
    ) -> anyhow::Result<
        openidconnect::core::CoreClient<
            openidconnect::EndpointSet,
            openidconnect::EndpointNotSet,
            openidconnect::EndpointNotSet,
            openidconnect::EndpointNotSet,
            openidconnect::EndpointMaybeSet,
            openidconnect::EndpointMaybeSet,
        >,
    > {
        let redirect = RedirectUrl::new(self.redirect_url.clone())
            .with_context(|| format!("invalid OIDC redirect URL: {}", self.redirect_url))?;
        Ok(CoreClient::from_provider_metadata(
            self.metadata.clone(),
            ClientId::new(self.client_id.clone()),
            Some(ClientSecret::new(self.client_secret.clone())),
        )
        .set_redirect_uri(redirect))
    }
}

#[async_trait]
impl OAuthProvider for OidcProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn display_name(&self) -> &str {
        &self.display_name
    }

    fn icon_svg(&self) -> Option<&str> {
        self.icon_svg.as_deref()
    }

    fn client_id(&self) -> &str {
        &self.client_id
    }

    fn client_secret(&self) -> &str {
        &self.client_secret
    }

    fn redirect_url(&self) -> &str {
        &self.redirect_url
    }

    // Reported for completeness; the OIDC flow drives the discovered endpoints
    // through `begin`/`finish` rather than these strings.
    fn auth_url(&self) -> &str {
        self.metadata.authorization_endpoint().as_str()
    }

    fn token_url(&self) -> &str {
        self.metadata
            .token_endpoint()
            .map(|e| e.as_str())
            .unwrap_or("")
    }

    fn scopes(&self) -> &[&str] {
        // The OIDC flow uses `self.scopes` (owned) directly in `begin`; this is
        // only here to satisfy the trait. Returning an empty slice is correct —
        // it is never consumed for OIDC providers.
        &[]
    }

    fn use_pkce(&self) -> bool {
        true
    }

    fn begin(&self) -> anyhow::Result<(String, OAuthAttempt)> {
        let client = self.build_client()?;
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let mut request = client.authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        );
        for scope in &self.scopes {
            request = request.add_scope(Scope::new(scope.clone()));
        }
        let (url, csrf_state, nonce) = request.set_pkce_challenge(pkce_challenge).url();

        Ok((
            url.to_string(),
            OAuthAttempt {
                csrf_state: csrf_state.secret().to_string(),
                pkce_verifier: Some(pkce_verifier.secret().to_string()),
                nonce: Some(nonce.secret().to_string()),
            },
        ))
    }

    async fn finish(
        &self,
        http: &reqwest::Client,
        code: &str,
        attempt: &OAuthAttempt,
    ) -> anyhow::Result<NormalizedProfile> {
        let client = self.build_client()?;

        let mut exchange = client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .map_err(|e| anyhow!("OIDC client is missing a token endpoint: {e}"))?;
        if let Some(verifier) = attempt.pkce_verifier.as_ref() {
            exchange = exchange.set_pkce_verifier(PkceCodeVerifier::new(verifier.clone()));
        }
        let token = exchange
            .request_async(http)
            .await
            .context("OIDC token exchange failed")?;

        let nonce = attempt
            .nonce
            .as_ref()
            .map(|n| Nonce::new(n.clone()))
            .ok_or_else(|| anyhow!("missing OIDC nonce in session"))?;

        let id_token = token
            .extra_fields()
            .id_token()
            .ok_or_else(|| anyhow!("provider did not return an id_token"))?;
        let claims = id_token
            .claims(&client.id_token_verifier(), &nonce)
            .context("id_token verification failed")?;

        let mut profile = id_token_profile(claims);

        // Standard OIDC: email/name live in the id_token when `email`/`profile`
        // scopes are granted. If the issuer left them out, best-effort fill the
        // gaps from the userinfo endpoint (ignored if it errors / is absent).
        if profile.email.is_none()
            && let Ok(extra) = self
                .fetch_profile(http, token.access_token().secret())
                .await
        {
            profile.email = profile.email.or(extra.email);
            profile.name = profile.name.or(extra.name);
            profile.avatar_url = profile.avatar_url.or(extra.avatar_url);
            profile.html_url = profile.html_url.or(extra.html_url);
        }

        Ok(profile)
    }

    async fn fetch_profile(
        &self,
        http: &reqwest::Client,
        access_token: &str,
    ) -> anyhow::Result<NormalizedProfile> {
        use openidconnect::AccessToken;

        let client = self.build_client()?;
        let claims: CoreUserInfoClaims = client
            .user_info(AccessToken::new(access_token.to_string()), None)
            .map_err(|e| anyhow!("OIDC provider has no userinfo endpoint: {e}"))?
            .request_async(http)
            .await
            .context("OIDC userinfo request failed")?;

        Ok(userinfo_profile(&claims))
    }
}

/// Map a verified `id_token`'s standard claims into a [`NormalizedProfile`].
fn id_token_profile(claims: &CoreIdTokenClaims) -> NormalizedProfile {
    profile_from_parts(
        claims.subject().as_str(),
        claims.preferred_username().map(|u| u.as_str()),
        claims.name().and_then(|n| n.get(None)).map(|n| n.as_str()),
        claims.email().map(|e| e.as_str()),
        claims
            .picture()
            .and_then(|p| p.get(None))
            .map(|p| p.as_str()),
        claims
            .profile()
            .and_then(|p| p.get(None))
            .map(|p| p.as_str()),
    )
}

/// Map a userinfo response's standard claims into a [`NormalizedProfile`].
fn userinfo_profile(claims: &CoreUserInfoClaims) -> NormalizedProfile {
    profile_from_parts(
        claims.subject().as_str(),
        claims.preferred_username().map(|u| u.as_str()),
        claims.name().and_then(|n| n.get(None)).map(|n| n.as_str()),
        claims.email().map(|e| e.as_str()),
        claims
            .picture()
            .and_then(|p| p.get(None))
            .map(|p| p.as_str()),
        claims
            .profile()
            .and_then(|p| p.get(None))
            .map(|p| p.as_str()),
    )
}

/// Shared normalisation: `sub` is the stable id; the local `login` handle
/// prefers `preferred_username`, then the email local-part, then `sub`.
fn profile_from_parts(
    sub: &str,
    preferred_username: Option<&str>,
    name: Option<&str>,
    email: Option<&str>,
    picture: Option<&str>,
    profile_url: Option<&str>,
) -> NormalizedProfile {
    let login = preferred_username
        .filter(|s| !s.is_empty())
        .or_else(|| email.and_then(email_local_part))
        .unwrap_or(sub)
        .to_owned();

    NormalizedProfile {
        provider_user_id: sub.to_owned(),
        login,
        name: name.map(str::to_owned),
        email: email.map(str::to_owned),
        avatar_url: picture.map(str::to_owned),
        html_url: profile_url.map(str::to_owned),
    }
}

/// Local-part of an email address (`alice@example.com` -> `alice`), or `None`
/// when empty / malformed.
fn email_local_part(email: &str) -> Option<&str> {
    email.split('@').next().filter(|s| !s.is_empty())
}

/// HTTP client for discovery: no redirects (SSRF mitigation) + the shared
/// `arium/<version>` User-Agent.
fn oidc_http_client() -> anyhow::Result<reqwest::Client> {
    reqwest::ClientBuilder::new()
        .user_agent(concat!("arium/", env!("CARGO_PKG_VERSION")))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("failed to build OIDC discovery HTTP client")
}

/// Read a non-empty environment variable.
pub(super) fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

/// Read a client-id / client-secret env pair. Returns `None` when neither is
/// set (provider intentionally disabled) and warns + returns `None` on partial
/// config. Shared by the OIDC presets.
pub(super) fn read_client_env(
    id_var: &str,
    secret_var: &str,
    label: &str,
) -> Option<(String, String)> {
    match (env_nonempty(id_var), env_nonempty(secret_var)) {
        (Some(id), Some(secret)) => Some((id, secret)),
        (None, None) => None,
        _ => {
            eprintln!(
                "[startup] WARN: partial {label} OAuth config — both {id_var} and \
                 {secret_var} are required. Disabling {label} sign-in."
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{email_local_part, profile_from_parts};

    #[test]
    fn login_prefers_preferred_username() {
        let p = profile_from_parts(
            "sub-1",
            Some("alice"),
            Some("Alice A"),
            Some("alice@example.com"),
            Some("https://cdn/avatar.png"),
            Some("https://example.com/alice"),
        );
        assert_eq!(p.provider_user_id, "sub-1");
        assert_eq!(p.login, "alice");
        assert_eq!(p.name.as_deref(), Some("Alice A"));
        assert_eq!(p.email.as_deref(), Some("alice@example.com"));
        assert_eq!(p.avatar_url.as_deref(), Some("https://cdn/avatar.png"));
        assert_eq!(p.html_url.as_deref(), Some("https://example.com/alice"));
    }

    #[test]
    fn login_falls_back_to_email_local_part() {
        let p = profile_from_parts("sub-2", None, None, Some("bob@example.com"), None, None);
        assert_eq!(p.login, "bob");
        assert!(p.html_url.is_none());
    }

    #[test]
    fn empty_preferred_username_is_ignored() {
        let p = profile_from_parts(
            "sub-3",
            Some(""),
            None,
            Some("carol@example.com"),
            None,
            None,
        );
        assert_eq!(p.login, "carol");
    }

    #[test]
    fn login_falls_back_to_sub_without_username_or_email() {
        let p = profile_from_parts("sub-4", None, None, None, None, None);
        assert_eq!(p.login, "sub-4");
        assert!(p.email.is_none());
    }

    #[test]
    fn email_local_part_handles_plain_and_degenerate() {
        assert_eq!(email_local_part("dave@x.com"), Some("dave"));
        assert_eq!(email_local_part(""), None);
        assert_eq!(email_local_part("@x.com"), None);
    }
}
