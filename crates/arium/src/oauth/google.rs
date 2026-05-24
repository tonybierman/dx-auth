//! Google sign-in, as a thin preset over the generic [`OidcProvider`].
//!
//! Google is OpenID Connect compliant, so this is just the generic OIDC engine
//! pointed at the `https://accounts.google.com` issuer with the standard
//! `openid email profile` scopes and a Google button icon.

#![cfg(feature = "oauth-google")]

use super::oidc::{OidcConfig, OidcProvider};

/// Inline 4-colour Google "G" mark for the LoginPanel button.
const GOOGLE_ICON_SVG: &str = r##"<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.27-4.74 3.27-8.1z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84A11 11 0 0 0 12 23z"/><path fill="#FBBC05" d="M5.84 14.1a6.6 6.6 0 0 1 0-4.2V7.06H2.18a11 11 0 0 0 0 9.88l3.66-2.84z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84C6.71 7.31 9.14 5.38 12 5.38z"/></svg>"##;

/// Google sign-in preset. Construct an [`OidcProvider`] for the Google issuer.
pub struct GoogleProvider;

impl GoogleProvider {
    /// Build a Google provider from explicit credentials. Runs OIDC discovery
    /// (network I/O), so this is `async`. Returns the generic [`OidcProvider`]
    /// (Google needs no bespoke type).
    #[allow(clippy::new_ret_no_self)]
    pub async fn new(
        client_id: String,
        client_secret: String,
        redirect_url: String,
    ) -> anyhow::Result<OidcProvider> {
        OidcProvider::discover(OidcConfig {
            name: "google".to_string(),
            display_name: "Google".to_string(),
            icon_svg: Some(GOOGLE_ICON_SVG.to_string()),
            issuer_url: "https://accounts.google.com".to_string(),
            client_id,
            client_secret,
            redirect_url,
            scopes: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
        })
        .await
    }

    /// Build a Google provider from the standard env-var triple
    /// (`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, optional
    /// `GOOGLE_REDIRECT_URL`). Returns `Ok(None)` when the id/secret aren't both
    /// set — the caller then skips registering it and the button is hidden.
    pub async fn from_env() -> anyhow::Result<Option<OidcProvider>> {
        let Some((client_id, client_secret)) =
            super::oidc::read_client_env("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "Google")
        else {
            return Ok(None);
        };

        let redirect_url = super::oidc::env_nonempty("GOOGLE_REDIRECT_URL")
            .unwrap_or_else(|| "http://localhost:8080/auth/google/callback".to_string());

        Ok(Some(
            Self::new(client_id, client_secret, redirect_url).await?,
        ))
    }
}
