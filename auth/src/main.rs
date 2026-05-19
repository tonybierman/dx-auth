//! This example showcases how to use the `axum-session-auth` crate with Dioxus fullstack.
//! We add the `auth::Session` extractor to our server functions to get access to the current user session.
//!
//! To initialize the axum router, we use `dioxus::serve` to spawn a custom axum server that creates
//! our database, session store, and authentication layer.
//!
//! The `.serve_dioxus_application` method is used to mount our Dioxus app as a fallback service to
//! handle HTML rendering and static assets.
//!
//! We easily share the "permissions" between the server and client by using a `HashSet<String>`
//! which is serialized to/from JSON automatically by the server function system.

use std::collections::HashSet;

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

mod components;
use components::avatar::{Avatar, AvatarFallback, AvatarImage};
use components::button::{Button, ButtonVariant};
use components::card::{Card, CardContent, CardDescription, CardHeader, CardTitle};
use components::input::Input;
use components::label::Label;
use components::login_panel::{LoginPanel, LoginProvider, LoginSubmit};

#[cfg(feature = "server")]
mod auth;

const THEME_CSS: Asset = asset!("/assets/dx-components-theme.css");
const APP_CSS: Asset = asset!("/assets/app.css");

const GITHUB_ICON_SVG: &str = r#"<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" xmlns="http://www.w3.org/2000/svg"><path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.4 3-.405 1.02.005 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/></svg>"#;

/// Profile fields safe to expose to the client.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct UserProfile {
    pub is_authenticated: bool,
    pub username: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub avatar_url: Option<String>,
    pub html_url: Option<String>,
}

fn main() {
    // On the client, we simply launch the app as normal, taking over the main thread
    #[cfg(not(feature = "server"))]
    dioxus::launch(app);

    // On the server, we can use `dioxus::serve` to create a server that serves our app.
    //
    // The `serve` function takes a closure that returns a `Future` which resolves to an `axum::Router`.
    //
    // We return a `Router` such that dioxus sets up logging, hot-reloading, devtools, and wires up the
    // IP and PORT environment variables to our server.
    #[cfg(feature = "server")]
    dioxus::serve(|| async {
        use crate::auth::*;
        use axum_session::{SessionConfig, SessionLayer, SessionStore};
        use axum_session_auth::AuthConfig;
        use axum_session_sqlx::SessionSqlitePool;
        use sqlx::sqlite::SqlitePoolOptions;

        // File-backed SQLite so accounts persist across restarts. Lives next to the
        // binary's cwd — typically `auth/` during `dx serve`.
        let db = SqlitePoolOptions::new()
            .max_connections(20)
            .connect_with("sqlite://./auth.db?mode=rwc".parse()?)
            .await?;

        // Apply embedded migrations (compiled from auth/migrations/*.sql).
        sqlx::migrate!().run(&db).await?;

        // Build third-party OAuth state (GitHub) from env vars.
        let oauth_clients = OAuthClients::from_env(db.clone())?;

        let oauth_router = axum::Router::new()
            .route("/auth/github/login", axum::routing::get(github_login))
            .route("/auth/github/callback", axum::routing::get(github_callback))
            .with_state(oauth_clients);

        // Create an axum router that dioxus will attach the app to
        Ok(dioxus::server::router(app)
            .merge(oauth_router)
            .layer(
                AuthLayer::new(Some(db.clone()))
                    .with_config(AuthConfig::<i64>::default().with_anonymous_user_id(Some(1))),
            )
            .layer(SessionLayer::new(
                SessionStore::<SessionSqlitePool>::new(
                    Some(db.into()),
                    SessionConfig::default()
                        .with_table_name("test_table")
                        // Don't bind the session to client IP+UA. On localhost the browser may
                        // hit 127.0.0.1 on one request and ::1 on another, invalidating lookups.
                        .with_ip_and_user_agent(false),
                )
                .await?,
            )))
    });
}

fn app() -> Element {
    let mut profile = use_resource(get_current_user_profile);
    let mut permissions = use_action(get_permissions);
    let mut logout = use_action(logout);

    let providers = vec![LoginProvider {
        name: "GitHub",
        href: "/auth/github/login",
        icon_svg: Some(GITHUB_ICON_SVG),
    }];

    let current: UserProfile = profile()
        .and_then(|r| r.ok())
        .unwrap_or_default();
    let logged_in = current.is_authenticated;

    // Placeholder until Phase 3 wires `login_with_password` / `register_with_password`.
    let on_login_submit = move |_submission: LoginSubmit| {};

    rsx! {
        document::Stylesheet { href: THEME_CSS }
        document::Stylesheet { href: APP_CSS }

        // Pre-mount the catalog widgets that only appear inside LoginPanel so their
        // css_module assets are registered during the initial render. Without this,
        // a logged-in user signing out triggers a client-side mount whose
        // OnceLock + queue_effect link-insertion path can race against the paint
        // and leave the form unstyled until refresh.
        div { style: "display: none", aria_hidden: "true",
            Input {}
            Label { html_for: "__preload" }
        }

        main { class: "app-shell",
            if logged_in {
                ProfileCard { profile: current }

                div { class: "app-actions",
                    Button {
                        variant: ButtonVariant::Ghost,
                        onclick: move |_| async move {
                            logout.call().await;
                            profile.restart();
                        },
                        "Sign out"
                    }
                    Button {
                        variant: ButtonVariant::Outline,
                        onclick: move |_| async move {
                            permissions.call().await;
                        },
                        "Fetch permissions"
                    }
                }

                if let Some(Ok(perms)) = permissions.value().as_ref() {
                    pre { class: "app-debug", "Permissions: {perms:?}" }
                }
            } else {
                LoginPanel {
                    providers: providers.clone(),
                    title: "Welcome back",
                    description: "Sign in to your workspace.",
                    forgot_href: "#",
                    on_submit: on_login_submit,
                }
            }
        }
    }
}

#[component]
fn ProfileCard(profile: UserProfile) -> Element {
    let display_name = profile.name.clone().unwrap_or_else(|| profile.username.clone());
    let handle = profile.username.clone();
    let avatar_url = profile.avatar_url.clone();
    let email = profile.email.clone();
    let html_url = profile.html_url.clone();

    rsx! {
        Card { class: "profile-card",
            CardHeader {
                div { class: "profile-card-identity",
                    Avatar {
                        if let Some(url) = avatar_url.as_ref() {
                            AvatarImage { src: "{url}", alt: "{display_name}" }
                        }
                        AvatarFallback { "{initials(&display_name)}" }
                    }
                    div { class: "profile-card-text",
                        CardTitle { "{display_name}" }
                        CardDescription { "@{handle}" }
                    }
                }
            }
            CardContent {
                ul { class: "profile-card-meta",
                    if let Some(addr) = email {
                        li { "Email: {addr}" }
                    }
                    if let Some(url) = html_url {
                        li {
                            "Profile: "
                            a { href: "{url}", target: "_blank", "{url}" }
                        }
                    }
                }
            }
        }
    }
}

fn initials(name: &str) -> String {
    name.split_whitespace()
        .filter_map(|w| w.chars().next())
        .take(2)
        .collect::<String>()
        .to_uppercase()
}

/// Log out the current session.
#[post("/api/user/logout", auth: auth::Session)]
pub async fn logout() -> Result<()> {
    auth.logout_user();
    Ok(())
}

/// Returns the current user's public profile (including any third-party
/// data we cached from the OAuth provider's user-info response).
#[get("/api/user/profile", auth: auth::Session)]
pub async fn get_current_user_profile() -> Result<UserProfile> {
    let user = auth.current_user.unwrap();
    Ok(UserProfile {
        is_authenticated: !user.anonymous,
        username: user.username,
        name: user.name,
        email: user.email,
        avatar_url: user.avatar_url,
        html_url: user.html_url,
    })
}

/// Get the current user's permissions, guarding the endpoint with the `Auth` validator.
/// If this returns false, we use the `or_unauthorized` extension to return a 401 error.
#[get("/api/user/permissions", auth: auth::Session)]
pub async fn get_permissions() -> Result<HashSet<String>> {
    use crate::auth::User;
    use axum_session_auth::{Auth, Rights};

    let user = auth.current_user.unwrap();

    Auth::<User, i64, sqlx::SqlitePool>::build([axum::http::Method::GET], false)
        .requires(Rights::any([
            Rights::permission("Category::View"),
            Rights::permission("Admin::View"),
        ]))
        .validate(&user, &axum::http::Method::GET, None)
        .await
        .or_unauthorized("You do not have permission to view categories")?;

    Ok(user.permissions)
}

#[cfg(feature = "server")]
use crate::auth::OAuthClients;

#[cfg(feature = "server")]
#[derive(serde::Deserialize)]
struct GithubCallbackParams {
    code: String,
    state: String,
}

#[cfg(feature = "server")]
#[derive(serde::Deserialize)]
struct GithubUserInfo {
    id: u64,
    login: String,
    name: Option<String>,
    email: Option<String>,
    avatar_url: Option<String>,
    html_url: Option<String>,
}

#[cfg(feature = "server")]
fn github_basic_client(
    clients: &OAuthClients,
) -> anyhow::Result<
    oauth2::basic::BasicClient<
        oauth2::EndpointSet,
        oauth2::EndpointNotSet,
        oauth2::EndpointNotSet,
        oauth2::EndpointNotSet,
        oauth2::EndpointSet,
    >,
> {
    use oauth2::basic::BasicClient;
    use oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};

    Ok(
        BasicClient::new(ClientId::new(clients.github_client_id.clone()))
            .set_client_secret(ClientSecret::new(clients.github_client_secret.clone()))
            .set_auth_uri(AuthUrl::new(
                "https://github.com/login/oauth/authorize".to_string(),
            )?)
            .set_token_uri(TokenUrl::new(
                "https://github.com/login/oauth/access_token".to_string(),
            )?)
            .set_redirect_uri(RedirectUrl::new(clients.github_redirect_url.clone())?),
    )
}

#[cfg(feature = "server")]
fn http_err<E: std::fmt::Display>(status: axum::http::StatusCode, e: E) -> (axum::http::StatusCode, String) {
    (status, e.to_string())
}

#[cfg(feature = "server")]
async fn github_login(
    axum::extract::State(clients): axum::extract::State<OAuthClients>,
    session: axum_session::Session<axum_session_sqlx::SessionSqlitePool>,
) -> Result<axum::response::Redirect, (axum::http::StatusCode, String)> {
    use oauth2::{CsrfToken, Scope};

    let client = github_basic_client(&clients)
        .map_err(|e| http_err(axum::http::StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let (auth_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("read:user".to_string()))
        .add_scope(Scope::new("user:email".to_string()))
        .url();

    session.set("gh_oauth_state", csrf_state.secret().to_string());

    Ok(axum::response::Redirect::to(auth_url.as_ref()))
}

#[cfg(feature = "server")]
async fn github_callback(
    axum::extract::State(clients): axum::extract::State<OAuthClients>,
    session: axum_session::Session<axum_session_sqlx::SessionSqlitePool>,
    auth_session: auth::Session,
    axum::extract::Query(params): axum::extract::Query<GithubCallbackParams>,
) -> Result<axum::response::Redirect, (axum::http::StatusCode, String)> {
    use oauth2::{AuthorizationCode, TokenResponse};

    let expected_state: Option<String> = session.get("gh_oauth_state");
    session.remove("gh_oauth_state");

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

    let client = github_basic_client(&clients)
        .map_err(|e| http_err(axum::http::StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let token = client
        .exchange_code(AuthorizationCode::new(params.code))
        .request_async(&clients.http)
        .await
        .map_err(|e| http_err(axum::http::StatusCode::BAD_GATEWAY, format!("token exchange failed: {e}")))?;

    let info: GithubUserInfo = clients
        .http
        .get("https://api.github.com/user")
        .header("User-Agent", "dx-auth-example")
        .header("Accept", "application/vnd.github+json")
        .bearer_auth(token.access_token().secret())
        .send()
        .await
        .map_err(|e| http_err(axum::http::StatusCode::BAD_GATEWAY, format!("github api request failed: {e}")))?
        .error_for_status()
        .map_err(|e| http_err(axum::http::StatusCode::BAD_GATEWAY, format!("github api status: {e}")))?
        .json()
        .await
        .map_err(|e| http_err(axum::http::StatusCode::BAD_GATEWAY, format!("github api parse: {e}")))?;

    let profile = auth::GithubProfile {
        id: info.id,
        login: &info.login,
        name: info.name.as_deref(),
        email: info.email.as_deref(),
        avatar_url: info.avatar_url.as_deref(),
        html_url: info.html_url.as_deref(),
    };

    let user_id = auth::upsert_github_user(&clients.db, profile)
        .await
        .map_err(|e| http_err(axum::http::StatusCode::INTERNAL_SERVER_ERROR, e))?;

    auth_session.login_user(user_id);

    Ok(axum::response::Redirect::to("/"))
}
