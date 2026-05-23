//! GitHub OAuth provider implementation.

#![cfg(feature = "oauth-github")]

use async_trait::async_trait;

use super::{NormalizedProfile, OAuthProvider};

/// Inline SVG of the GitHub mark, used as the LoginPanel button icon.
const GITHUB_ICON_SVG: &str = r#"<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" xmlns="http://www.w3.org/2000/svg"><path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.4 3-.405 1.02.005 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/></svg>"#;

/// Credentials and URLs for the GitHub OAuth App.
#[derive(Clone)]
pub struct GithubProvider {
    client_id: String,
    client_secret: String,
    redirect_url: String,
    scopes: Vec<&'static str>,
}

impl GithubProvider {
    /// Manual constructor — most apps want [`Self::from_env`] instead.
    pub fn new(client_id: String, client_secret: String, redirect_url: String) -> Self {
        Self {
            client_id,
            client_secret,
            redirect_url,
            scopes: vec!["read:user", "user:email"],
        }
    }

    /// Build a [`GithubProvider`] from the standard env-var triple.
    ///
    /// Returns `Ok(Some(_))` when both `GITHUB_CLIENT_ID` and
    /// `GITHUB_CLIENT_SECRET` are set, or `Ok(None)` when they're absent —
    /// the caller should skip registering the provider, and the LoginPanel
    /// will then hide the GitHub button. Partial config (one set, one
    /// missing) returns `None` with a warning logged.
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        let id = std::env::var("GITHUB_CLIENT_ID")
            .ok()
            .filter(|s| !s.is_empty());
        let secret = std::env::var("GITHUB_CLIENT_SECRET")
            .ok()
            .filter(|s| !s.is_empty());

        let (client_id, client_secret) = match (id, secret) {
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

        let redirect_url = std::env::var("GITHUB_REDIRECT_URL")
            .unwrap_or_else(|_| "http://localhost:8080/auth/github/callback".to_string());

        Ok(Some(Self::new(client_id, client_secret, redirect_url)))
    }
}

#[derive(serde::Deserialize)]
struct GithubUserInfo {
    id: u64,
    login: String,
    name: Option<String>,
    email: Option<String>,
    avatar_url: Option<String>,
    html_url: Option<String>,
}

#[async_trait]
impl OAuthProvider for GithubProvider {
    fn name(&self) -> &str {
        "github"
    }

    fn display_name(&self) -> &str {
        "GitHub"
    }

    fn icon_svg(&self) -> Option<&str> {
        Some(GITHUB_ICON_SVG)
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

    fn auth_url(&self) -> &str {
        "https://github.com/login/oauth/authorize"
    }

    fn token_url(&self) -> &str {
        "https://github.com/login/oauth/access_token"
    }

    fn scopes(&self) -> &[&str] {
        &self.scopes
    }

    async fn fetch_profile(
        &self,
        http: &reqwest::Client,
        access_token: &str,
    ) -> anyhow::Result<NormalizedProfile> {
        let info: GithubUserInfo = http
            .get("https://api.github.com/user")
            .header("User-Agent", "dx-auth")
            .header("Accept", "application/vnd.github+json")
            .bearer_auth(access_token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        Ok(NormalizedProfile {
            provider_user_id: info.id.to_string(),
            login: info.login,
            name: info.name,
            email: info.email,
            avatar_url: info.avatar_url,
            html_url: info.html_url,
        })
    }
}
