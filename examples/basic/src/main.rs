//! Example consumer of the `arium` library.
//!
//! All auth primitives — password / OAuth / MFA / email / sessions / rate
//! limiting — live in the library. This binary only owns app-specific bits:
//! the Home / ProfileCard / Forgot / Reset / Verify / MFA UI pages and the
//! `get_permissions` server fn (which uses app-specific permission tokens).

use std::collections::HashSet;

use dioxus::prelude::*;

use arium_dioxus::server::*;
use arium_dioxus::ui::components::avatar::{Avatar, AvatarFallback, AvatarImage};
use arium_dioxus::ui::components::button::{Button, ButtonVariant};
use arium_dioxus::ui::components::card::{
    Card, CardContent, CardDescription, CardHeader, CardTitle,
};
use arium_dioxus::ui::components::input::Input;
use arium_dioxus::ui::components::label::Label;
use arium_dioxus::ui::components::tabs::{TabContent, TabList, TabTrigger, Tabs};
use arium_dioxus::ui::{
    ApiTokens, ForgotPassword, LoginPanel, LoginSubmit, MfaChallenge, MfaSetup,
    OAuthProvidersProvider, PermissionGate, PermissionsProvider, Policy, RequirePermission,
    ResetPassword, SubmitKind, VerifyEmail, use_oauth_providers, use_permissions,
};
use arium_dioxus::{LoginOutcome, UserProfile, friendly_server_error};

const APP_CSS: Asset = asset!("/assets/app.css");

/// Permission tokens guarding each tab inside `/admin`. Defined as
/// constants so neither `admin_policy` nor the per-tab visibility checks
/// inside `AdminPage` hard-code the strings independently.
const TOKEN_ADMIN_USERS: &str = "admin:users:read";
const TOKEN_ADMIN_AUDIT: &str = "admin:audit:read";
const TOKEN_ADMIN_ROLES: &str = "admin:roles:read";

/// Admission policy for `/admin`. Anyone with at least one admin-tab
/// token is admitted; individual tabs further filter by their specific
/// token. Adding a new admin tab is a one-place edit: add a const above,
/// reference it here and in `AdminPage`.
fn admin_policy() -> Policy {
    Policy::any_of([TOKEN_ADMIN_USERS, TOKEN_ADMIN_AUDIT, TOKEN_ADMIN_ROLES])
}

fn main() {
    #[cfg(not(feature = "server"))]
    dioxus::launch(app);

    #[cfg(feature = "server")]
    dioxus::serve(|| async {
        use sqlx::sqlite::SqlitePoolOptions;

        let pool = SqlitePoolOptions::new()
            .max_connections(20)
            .connect_with("sqlite://./auth.db?mode=rwc".parse()?)
            .await?;
        // arium owns the schema for `users`, `oauth_accounts`, `roles`,
        // `audit_events`, `api_keys`, ... — they're embedded in the arium
        // crate. App-specific migrations (none yet) would run after this.
        arium_dioxus::migrator().run(&pool).await?;

        let mailer = arium_dioxus::Mailer::from_env()?;
        println!("[startup] mailer backend: {}", mailer.describe());

        let builder = arium_dioxus::AuthConfig::builder(pool, mailer);
        let builder = match arium_dioxus::oauth::github::GithubProvider::from_env()? {
            Some(gh) => {
                println!("[startup] GitHub OAuth: enabled");
                builder.oauth_provider(gh)?
            }
            None => {
                println!(
                    "[startup] GitHub OAuth: disabled (set GITHUB_CLIENT_ID + \
                     GITHUB_CLIENT_SECRET to enable)"
                );
                builder
            }
        };

        let cfg = builder.build()?;

        arium_dioxus::install(dioxus::server::router(app), cfg).await
    });
}

#[derive(Routable, Clone, PartialEq)]
enum Route {
    #[route("/")]
    Home,
    #[route("/auth/forgot")]
    ForgotPassword,
    #[route("/auth/reset?:token")]
    ResetPassword { token: String },
    #[route("/auth/verify?:token")]
    VerifyEmail { token: String },
    #[route("/account/mfa")]
    MfaSetup,
    #[route("/account/settings")]
    AccountSettingsPage,
    #[route("/admin")]
    AdminPage,
}

fn app() -> Element {
    rsx! {
        // Catalog theme tokens straight from the library — the canonical way
        // for a consumer to pull these in (no vendored copy).
        document::Stylesheet { href: arium_dioxus::DEFAULT_THEME_CSS }
        document::Stylesheet { href: APP_CSS }

        // Pre-mount the catalog widgets that only appear inside LoginPanel /
        // MfaSetup so their css_module assets are registered during the
        // initial render. Without this, a logged-in user signing out
        // triggers a client-side mount whose OnceLock + queue_effect link-
        // insertion path can race against the paint and leave the form
        // unstyled until refresh.
        div { style: "display: none", aria_hidden: "true",
            Input {}
            Label { html_for: "__preload" }
        }

        PermissionsProvider {
            OAuthProvidersProvider {
                Router::<Route> {}
            }
        }
    }
}

#[component]
fn Home() -> Element {
    let perms = use_permissions();
    let mut logout = use_action(logout);

    // Provider list comes from a single use_resource at the app root via
    // OAuthProvidersProvider — using use_resource here too would re-fire
    // (and briefly return empty) every time the LoginPanel branch
    // unmounts and re-mounts during the login/logout transition, leaving
    // the GitHub button missing right after sign-out.
    let providers = use_oauth_providers();

    let current: UserProfile = perms.profile().unwrap_or_default();
    let logged_in = current.is_authenticated;

    let mut auth_error = use_signal(String::new);
    let mut pending_email = use_signal::<Option<String>>(|| None);
    let mut pending_mfa = use_signal(|| false);

    let on_login_submit = move |submission: LoginSubmit| {
        auth_error.set(String::new());
        let LoginSubmit {
            kind,
            email,
            password,
            remember,
        } = submission;
        let email_for_pending = email.clone();
        spawn(async move {
            let result = match kind {
                SubmitKind::SignIn => login_with_password(email, password, remember).await,
                SubmitKind::SignUp => register_with_password(email, password).await,
            };
            match result {
                Ok(LoginOutcome::LoggedIn) => perms.refresh(),
                Ok(LoginOutcome::EmailUnverified) => pending_email.set(Some(email_for_pending)),
                Ok(LoginOutcome::MfaRequired) => pending_mfa.set(true),
                Err(e) => auth_error.set(friendly_server_error(e)),
            }
        });
    };

    rsx! {
        main { class: "app-shell",
            if logged_in {
                {
                    let profile_for_tab = current.clone();
                    rsx! {
                        Tabs {
                            default_value: "account".to_string(),
                            TabList {
                                TabTrigger { index: 0_usize, value: "account".to_string(), "Account" }
                                TabTrigger { index: 1_usize, value: "mfa".to_string(),     "Two-factor auth" }
                                TabTrigger { index: 2_usize, value: "tokens".to_string(),  "API tokens" }
                                PermissionGate {
                                    policy: admin_policy(),
                                    // The TabTrigger primitive doesn't forward arbitrary
                                    // attributes onto its inner button, so wrap it and let
                                    // the click bubble into a navigation handler. The
                                    // primitive's own click toggles tab state, but Home
                                    // unmounts before that's visible.
                                    span {
                                        onclick: move |_| { navigator().push(Route::AdminPage); },
                                        TabTrigger { index: 3_usize, value: "admin".to_string(), "Admin" }
                                    }
                                }
                            }
                            TabContent { index: 0_usize, value: "account".to_string(),
                                ProfileCard { profile: profile_for_tab }
                                arium_dioxus::ui::AccountSettings {}
                            }
                            TabContent { index: 1_usize, value: "mfa".to_string(),
                                MfaSetup {}
                            }
                            TabContent { index: 2_usize, value: "tokens".to_string(),
                                ApiTokens {}
                            }
                        }
                        div { class: "app-actions-buttons",
                            Button {
                                variant: ButtonVariant::Outline,
                                onclick: move |_| async move {
                                    logout.call().await;
                                    perms.refresh();
                                },
                                "Sign out"
                            }
                        }
                    }
                }
            } else if pending_mfa() {
                MfaChallenge {
                    on_logged_in: move |_| {
                        pending_mfa.set(false);
                        perms.refresh();
                    },
                    on_cancel: move |_| {
                        pending_mfa.set(false);
                        auth_error.set(String::new());
                        spawn(async move {
                            let _ = cancel_mfa_challenge().await;
                        });
                    },
                }
            } else if let Some(email) = pending_email() {
                VerificationPending {
                    email,
                    on_back: move |_| {
                        pending_email.set(None);
                        auth_error.set(String::new());
                    },
                }
            } else {
                LoginPanel {
                    providers: providers.clone(),
                    title: "Welcome back",
                    description: "Sign in to your workspace.",
                    forgot_href: "/auth/forgot",
                    error: {
                        let e = auth_error();
                        if e.is_empty() { None } else { Some(e) }
                    },
                    on_submit: on_login_submit,
                }
            }
        }
    }
}

#[component]
fn ProfileCard(profile: UserProfile) -> Element {
    let display_name = profile
        .name
        .clone()
        .unwrap_or_else(|| profile.username.clone());
    let handle = profile.username.clone();
    let avatar_url = profile.avatar_url.clone();
    let email = profile.email.clone();
    let html_url = profile.html_url.clone();

    rsx! {
        div { class: "profile-card",
            div { class: "profile-card-identity",
                Avatar {
                    if let Some(url) = avatar_url.as_ref() {
                        AvatarImage { src: "{url}", alt: "{display_name}" }
                    }
                    AvatarFallback { "{initials(&display_name)}" }
                }
                div { class: "profile-card-text",
                    div { class: "profile-card-name", "{display_name}" }
                    div { class: "profile-card-handle", "@{handle}" }
                    if let Some(addr) = email {
                        div { class: "profile-card-email", "{addr}" }
                    }
                    if let Some(url) = html_url {
                        a {
                            class: "profile-card-link",
                            href: "{url}",
                            target: "_blank",
                            "{url}"
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

#[component]
fn VerificationPending(email: String, on_back: EventHandler<()>) -> Element {
    let mut resending = use_signal(|| false);
    let mut resent = use_signal(|| false);
    let email_for_resend = email.clone();

    rsx! {
        Card { class: "login-panel",
            CardHeader {
                CardTitle { "Check your inbox" }
                CardDescription {
                    "We sent a verification link to "
                    strong { "{email}" }
                    ". Click it to finish signing in."
                }
            }
            CardContent {
                div { class: "auth-form",
                    if resent() {
                        p { class: "auth-success", "Sent another link." }
                    }
                    Button {
                        variant: ButtonVariant::Outline,
                        onclick: move |_| {
                            let email = email_for_resend.clone();
                            resending.set(true);
                            spawn(async move {
                                let _ = resend_verification_email(email).await;
                                resending.set(false);
                                resent.set(true);
                            });
                        },
                        if resending() { "Sending…" } else { "Resend verification email" }
                    }
                    p { class: "auth-aux",
                        a {
                            href: "#",
                            onclick: move |evt| {
                                evt.prevent_default();
                                on_back.call(());
                            },
                            "Back to sign in"
                        }
                    }
                }
            }
        }
    }
}

// `ForgotPassword`, `ResetPassword`, `VerifyEmail`, `MfaChallenge`, and
// `MfaSetup` are all drop-in components shipped by the library at
// `arium_dioxus::ui::*` (imported above). The Route enum entries above pick
// them up automatically.

// ---- App-specific server fn: which permissions the current user has. ----

/// Demo permission check using the seed `Category::View` token the library's
/// helpers grant new accounts. Real apps would seed via their own hook (a
/// future API improvement) rather than depending on the library's default.
#[get("/api/user/permissions", auth: arium_dioxus::auth::Session)]
pub async fn get_permissions() -> Result<HashSet<String>> {
    use arium_dioxus::auth::User;
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

#[component]
fn AccountSettingsPage() -> Element {
    rsx! {
        main { class: "app-shell",
            arium_dioxus::ui::AccountSettings {}
            p { class: "auth-aux", a { href: "/", "← Back to home" } }
        }
    }
}

/// Admin console: its own route, its own tabset. The whole page is gated
/// behind `any_of` so a user with either users:read OR audit:read can land
/// here; individual tab triggers are then pruned to the specific permission
/// each surface needs.
#[component]
fn AdminPage() -> Element {
    let perms = use_permissions();
    let can_users = perms.has(TOKEN_ADMIN_USERS);
    let can_audit = perms.has(TOKEN_ADMIN_AUDIT);
    let can_roles = perms.has(TOKEN_ADMIN_ROLES);

    let mut selected = use_signal::<Option<i64>>(|| None);
    // Role pane state: None = list, Some(None) = new, Some(Some(id)) = edit.
    let mut role_pane = use_signal::<Option<Option<i64>>>(|| None);

    let default_tab = if can_users {
        "users"
    } else if can_audit {
        "audit"
    } else {
        "roles"
    }
    .to_string();

    rsx! {
        RequirePermission {
            policy: admin_policy(),
            redirect_to: "/".to_string(),
            main { class: "app-shell",
                Tabs {
                    default_value: default_tab,
                    TabList {
                        if can_users {
                            TabTrigger { index: 0_usize, value: "users".to_string(), "Users" }
                        }
                        if can_audit {
                            TabTrigger { index: 1_usize, value: "audit".to_string(), "Audit log" }
                        }
                        if can_roles {
                            TabTrigger { index: 2_usize, value: "roles".to_string(), "Roles" }
                        }
                    }
                    if can_users {
                        TabContent { index: 0_usize, value: "users".to_string(),
                            if let Some(uid) = selected() {
                                arium_dioxus::ui::AdminUserDetail {
                                    user_id: uid,
                                    on_back: move |_| selected.set(None),
                                }
                            } else {
                                arium_dioxus::ui::AdminUserList {
                                    on_select: move |id: i64| selected.set(Some(id)),
                                }
                            }
                        }
                    }
                    if can_audit {
                        TabContent { index: 1_usize, value: "audit".to_string(),
                            arium_dioxus::ui::AuditLog {}
                        }
                    }
                    if can_roles {
                        TabContent { index: 2_usize, value: "roles".to_string(),
                            match role_pane() {
                                Some(rid_opt) => rsx! {
                                    arium_dioxus::ui::AdminRoleEditor {
                                        role_id: rid_opt,
                                        on_back: move |_| role_pane.set(None),
                                    }
                                },
                                None => rsx! {
                                    arium_dioxus::ui::AdminRoleList {
                                        on_select: move |id: i64| role_pane.set(Some(Some(id))),
                                        on_new: move |_| role_pane.set(Some(None)),
                                    }
                                },
                            }
                        }
                    }
                }
                p { class: "auth-aux", a { href: "/", "← Back to home" } }
            }
        }
    }
}
