//! Microsoft / Entra ID sign-in, as a thin preset over the generic
//! [`OidcProvider`].
//!
//! Microsoft identity platform is OpenID Connect compliant. The issuer is
//! tenant-scoped: `https://login.microsoftonline.com/{tenant}/v2.0`, where
//! `{tenant}` is `common` (any work/school or personal account), `organizations`,
//! `consumers`, or a specific tenant id.

#![cfg(feature = "oauth-microsoft")]

use super::oidc::{OidcConfig, OidcProvider};

/// Inline 4-square Microsoft logo for the LoginPanel button.
const MICROSOFT_ICON_SVG: &str = r##"<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill="#F25022" d="M2 2h9.5v9.5H2z"/><path fill="#7FBA00" d="M12.5 2H22v9.5h-9.5z"/><path fill="#00A4EF" d="M2 12.5h9.5V22H2z"/><path fill="#FFB900" d="M12.5 12.5H22V22h-9.5z"/></svg>"##;

/// Microsoft sign-in preset. Construct an [`OidcProvider`] for a Microsoft
/// identity-platform tenant.
pub struct MicrosoftProvider;

impl MicrosoftProvider {
    /// Build a Microsoft provider from explicit credentials + tenant. Runs OIDC
    /// discovery (network I/O), so this is `async`. Returns the generic
    /// [`OidcProvider`] (Microsoft needs no bespoke type).
    #[allow(clippy::new_ret_no_self)]
    pub async fn new(
        client_id: String,
        client_secret: String,
        redirect_url: String,
        tenant: String,
    ) -> anyhow::Result<OidcProvider> {
        OidcProvider::discover(OidcConfig {
            name: "microsoft".to_string(),
            display_name: "Microsoft".to_string(),
            icon_svg: Some(MICROSOFT_ICON_SVG.to_string()),
            issuer_url: format!("https://login.microsoftonline.com/{tenant}/v2.0"),
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

    /// Build a Microsoft provider from env vars: `MICROSOFT_CLIENT_ID`,
    /// `MICROSOFT_CLIENT_SECRET`, optional `MICROSOFT_REDIRECT_URL`, and optional
    /// `MICROSOFT_TENANT` (defaults to `common`). Returns `Ok(None)` when the
    /// id/secret aren't both set.
    pub async fn from_env() -> anyhow::Result<Option<OidcProvider>> {
        let Some((client_id, client_secret)) = super::oidc::read_client_env(
            "MICROSOFT_CLIENT_ID",
            "MICROSOFT_CLIENT_SECRET",
            "Microsoft",
        ) else {
            return Ok(None);
        };

        let tenant =
            super::oidc::env_nonempty("MICROSOFT_TENANT").unwrap_or_else(|| "common".to_string());
        let redirect_url = super::oidc::env_nonempty("MICROSOFT_REDIRECT_URL")
            .unwrap_or_else(|| "http://localhost:8080/auth/microsoft/callback".to_string());

        Ok(Some(
            Self::new(client_id, client_secret, redirect_url, tenant).await?,
        ))
    }
}
