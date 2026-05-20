//! Example consumer of the `dx-auth` library.
//!
//! All auth primitives — password / OAuth / MFA / email / sessions / rate
//! limiting — live in the library. This binary only owns app-specific bits:
//! the Home / ProfileCard / Forgot / Reset / Verify / MFA UI pages and the
//! `get_permissions` server fn (which uses app-specific permission tokens).

use std::collections::HashSet;

use dioxus::prelude::*;

use dx_auth::server::*;
use dx_auth::ui::components::avatar::{Avatar, AvatarFallback, AvatarImage};
use dx_auth::ui::components::button::{Button, ButtonVariant};
use dx_auth::ui::components::card::{Card, CardContent, CardDescription, CardHeader, CardTitle};
use dx_auth::ui::components::input::Input;
use dx_auth::ui::components::label::Label;
use dx_auth::ui::components::tabs::{TabContent, TabList, TabTrigger, Tabs};
use dx_auth::ui::{
    use_permissions, ForgotPassword, LoginPanel, LoginProvider, LoginSubmit, PermissionGate,
    PermissionsProvider, Policy, RequirePermission, ResetPassword, SubmitKind, VerifyEmail,
};
use dx_auth::{friendly_server_error, LoginOutcome, MfaSetupView, MfaStatusView, UserProfile};

const THEME_CSS: Asset = asset!("/assets/dx-components-theme.css");
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
        // The example's migrations dir contains both dx-auth's bundled SQL
        // (copied from crates/dx-auth/migrations/sqlite/) and any
        // app-specific ones (none yet).
        sqlx::migrate!().run(&pool).await?;

        let mailer = dx_auth::Mailer::from_env()?;
        println!("[startup] mailer backend: {}", mailer.describe());

        let builder = dx_auth::AuthConfig::builder(pool, mailer);
        let builder = match dx_auth::oauth::github::GithubProvider::from_env()? {
            Some(gh) => {
                println!("[startup] GitHub OAuth: enabled");
                builder.oauth_provider(gh)
            }
            None => {
                println!(
                    "[startup] GitHub OAuth: disabled (set GITHUB_CLIENT_ID + \
                     GITHUB_CLIENT_SECRET to enable)"
                );
                builder
            }
        };

        let cfg = builder.build();

        dx_auth::install(dioxus::server::router(app), cfg).await
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
        document::Stylesheet { href: THEME_CSS }
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
            Router::<Route> {}
        }
    }
}

#[component]
fn Home() -> Element {
    let perms = use_permissions();
    let mut logout = use_action(logout);

    let providers_resource = use_resource(available_providers);
    let providers: Vec<LoginProvider> = providers_resource()
        .and_then(|r| r.ok())
        .unwrap_or_default()
        .into_iter()
        .map(LoginProvider::from)
        .collect();

    let current: UserProfile = perms.profile().unwrap_or_default();
    let logged_in = current.is_authenticated;

    let mut auth_error = use_signal(String::new);
    let mut pending_email = use_signal::<Option<String>>(|| None);
    let mut pending_mfa = use_signal(|| false);

    let on_login_submit = move |submission: LoginSubmit| {
        auth_error.set(String::new());
        let LoginSubmit { kind, email, password, remember } = submission;
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
                                PermissionGate {
                                    policy: admin_policy(),
                                    // The TabTrigger primitive doesn't forward arbitrary
                                    // attributes onto its inner button, so wrap it and let
                                    // the click bubble into a navigation handler. The
                                    // primitive's own click toggles tab state, but Home
                                    // unmounts before that's visible.
                                    span {
                                        onclick: move |_| { navigator().push(Route::AdminPage); },
                                        TabTrigger { index: 2_usize, value: "admin".to_string(), "Admin" }
                                    }
                                }
                            }
                            TabContent { index: 0_usize, value: "account".to_string(),
                                ProfileCard { profile: profile_for_tab }
                                dx_auth::ui::AccountSettings {}
                            }
                            TabContent { index: 1_usize, value: "mfa".to_string(),
                                MfaSetup {}
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
                MfaChallengeView {
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
    let display_name = profile.name.clone().unwrap_or_else(|| profile.username.clone());
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

#[component]
fn MfaChallengeView(on_logged_in: EventHandler<()>, on_cancel: EventHandler<()>) -> Element {
    let mut code = use_signal(String::new);
    let mut use_recovery = use_signal(|| false);
    let mut error = use_signal(String::new);
    let mut submitting = use_signal(|| false);

    rsx! {
        Card { class: "login-panel",
            CardHeader {
                CardTitle { "Two-factor authentication" }
                CardDescription {
                    if use_recovery() {
                        "Enter one of your recovery codes."
                    } else {
                        "Enter the 6-digit code from your authenticator app."
                    }
                }
            }
            CardContent {
                form {
                    class: "auth-form",
                    onsubmit: move |evt| {
                        evt.prevent_default();
                        let code_val = code.read().trim().to_string();
                        if code_val.is_empty() { return; }
                        error.set(String::new());
                        submitting.set(true);
                        spawn(async move {
                            match verify_login_mfa(code_val).await {
                                Ok(LoginOutcome::LoggedIn) => on_logged_in.call(()),
                                Ok(_) => error.set("Unexpected response from server.".to_string()),
                                Err(e) => error.set(friendly_server_error(e)),
                            }
                            code.set(String::new());
                            submitting.set(false);
                        });
                    },
                    div { class: "auth-field",
                        Label {
                            html_for: "mfa-code",
                            class: "auth-label",
                            if use_recovery() { "Recovery code" } else { "Authenticator code" }
                        }
                        Input {
                            id: "mfa-code",
                            r#type: "text",
                            inputmode: if use_recovery() { "text" } else { "numeric" },
                            autocomplete: "one-time-code",
                            placeholder: if use_recovery() { "ABCD-EFGH-IJ" } else { "123 456" },
                            value: "{code}",
                            oninput: move |evt: FormEvent| code.set(evt.value()),
                        }
                    }
                    if !error().is_empty() {
                        div { class: "auth-error", role: "alert", "{error}" }
                    }
                    Button {
                        variant: ButtonVariant::Primary,
                        r#type: "submit",
                        class: "auth-submit",
                        if submitting() { "Verifying…" } else { "Verify" }
                    }
                    p { class: "auth-aux",
                        a {
                            href: "#",
                            onclick: move |evt| {
                                evt.prevent_default();
                                use_recovery.set(!use_recovery());
                                code.set(String::new());
                                error.set(String::new());
                            },
                            if use_recovery() { "Use authenticator code" } else { "Use a recovery code" }
                        }
                    }
                    p { class: "auth-aux",
                        a {
                            href: "#",
                            onclick: move |evt| {
                                evt.prevent_default();
                                on_cancel.call(());
                            },
                            "Cancel sign in"
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn MfaSetup() -> Element {
    let profile = use_resource(get_current_user_profile);
    let mut status = use_resource(get_mfa_status);
    let mut setup_info = use_signal::<Option<MfaSetupView>>(|| None);
    let mut confirm_code = use_signal(String::new);
    let mut error = use_signal(String::new);
    let mut info_message = use_signal(String::new);
    let mut busy = use_signal(|| false);

    let current = profile().and_then(|r| r.ok()).unwrap_or_default();

    if !current.is_authenticated {
        return rsx! {
            main { class: "app-shell",
                Card { class: "login-panel",
                    CardHeader { CardTitle { "Sign in required" } }
                    CardContent {
                        p { "You need to be signed in to manage two-factor auth." }
                        p { a { href: "/", "Back to sign in" } }
                    }
                }
            }
        };
    }

    let status_value: MfaStatusView = status().and_then(|r| r.ok()).unwrap_or_default();

    rsx! {
        main { class: "app-shell",
            Card { class: "login-panel",
                CardHeader {
                    CardTitle { "Two-factor authentication" }
                    CardDescription {
                        match status_value {
                            MfaStatusView::Enabled => "Two-factor authentication is on.",
                            MfaStatusView::Pending => "Finish enrollment by entering a code from your app.",
                            MfaStatusView::Disabled => "Protect your account with an authenticator app.",
                        }
                    }
                }
                CardContent {
                    if !info_message().is_empty() {
                        p { class: "auth-success", "{info_message}" }
                    }
                    if !error().is_empty() {
                        div { class: "auth-error", role: "alert", "{error}" }
                    }
                    match status_value {
                        MfaStatusView::Disabled => rsx! {
                            div { class: "auth-form",
                                if let Some(info) = setup_info() {
                                    MfaSetupArtifacts { info: info.clone() }
                                    MfaConfirmForm {
                                        code: confirm_code,
                                        busy,
                                        on_submit: move |code_val: String| {
                                            error.set(String::new());
                                            busy.set(true);
                                            spawn(async move {
                                                match confirm_mfa_setup(code_val).await {
                                                    Ok(()) => {
                                                        info_message.set("Two-factor auth enabled.".to_string());
                                                        setup_info.set(None);
                                                        confirm_code.set(String::new());
                                                        status.restart();
                                                    }
                                                    Err(e) => error.set(friendly_server_error(e)),
                                                }
                                                busy.set(false);
                                            });
                                        },
                                    }
                                } else {
                                    Button {
                                        variant: ButtonVariant::Primary,
                                        class: "auth-submit",
                                        onclick: move |_| {
                                            error.set(String::new());
                                            info_message.set(String::new());
                                            busy.set(true);
                                            spawn(async move {
                                                match begin_mfa_setup().await {
                                                    Ok(info) => {
                                                        setup_info.set(Some(info));
                                                        status.restart();
                                                    }
                                                    Err(e) => error.set(friendly_server_error(e)),
                                                }
                                                busy.set(false);
                                            });
                                        },
                                        if busy() { "Setting up…" } else { "Set up two-factor auth" }
                                    }
                                }
                            }
                        },
                        MfaStatusView::Pending => rsx! {
                            div { class: "auth-form",
                                if let Some(info) = setup_info() {
                                    MfaSetupArtifacts { info: info.clone() }
                                } else {
                                    p {
                                        "You started setting up two-factor auth but didn't finish. "
                                        "Restart enrollment to get a fresh QR code and recovery codes."
                                    }
                                    Button {
                                        variant: ButtonVariant::Outline,
                                        class: "auth-submit",
                                        onclick: move |_| {
                                            error.set(String::new());
                                            info_message.set(String::new());
                                            busy.set(true);
                                            spawn(async move {
                                                match begin_mfa_setup().await {
                                                    Ok(info) => setup_info.set(Some(info)),
                                                    Err(e) => error.set(friendly_server_error(e)),
                                                }
                                                busy.set(false);
                                            });
                                        },
                                        if busy() { "Restarting…" } else { "Restart enrollment" }
                                    }
                                }
                                MfaConfirmForm {
                                    code: confirm_code,
                                    busy,
                                    on_submit: move |code_val: String| {
                                        error.set(String::new());
                                        busy.set(true);
                                        spawn(async move {
                                            match confirm_mfa_setup(code_val).await {
                                                Ok(()) => {
                                                    info_message.set("Two-factor auth enabled.".to_string());
                                                    setup_info.set(None);
                                                    confirm_code.set(String::new());
                                                    status.restart();
                                                }
                                                Err(e) => error.set(friendly_server_error(e)),
                                            }
                                            busy.set(false);
                                        });
                                    },
                                }
                            }
                        },
                        MfaStatusView::Enabled => rsx! {
                            div { class: "auth-form",
                                p { "Your account requires a 6-digit code on every sign-in." }
                                Button {
                                    variant: ButtonVariant::Destructive,
                                    class: "auth-submit",
                                    onclick: move |_| {
                                        error.set(String::new());
                                        info_message.set(String::new());
                                        busy.set(true);
                                        spawn(async move {
                                            match disable_mfa_for_user().await {
                                                Ok(()) => {
                                                    info_message.set("Two-factor auth disabled.".to_string());
                                                    setup_info.set(None);
                                                    status.restart();
                                                }
                                                Err(e) => error.set(friendly_server_error(e)),
                                            }
                                            busy.set(false);
                                        });
                                    },
                                    if busy() { "Disabling…" } else { "Disable two-factor auth" }
                                }
                            }
                        },
                    }
                    p { class: "auth-aux", a { href: "/", "Back to account" } }
                }
            }
        }
    }
}

#[component]
fn MfaSetupArtifacts(info: MfaSetupView) -> Element {
    rsx! {
        div { class: "mfa-artifacts",
            p { "Scan this QR code in your authenticator app, then enter a code below to confirm." }
            img {
                class: "mfa-qr",
                alt: "MFA QR code",
                src: "data:image/png;base64,{info.qr_png_base64}",
            }
            p { class: "auth-aux",
                "Can't scan? Enter this key manually: "
                code { "{info.secret_base32}" }
            }
            div { class: "mfa-recovery",
                strong { "Recovery codes" }
                p {
                    "Save these somewhere safe — each can be used once if you lose access to your "
                    "authenticator. They won't be shown again."
                }
                ul { class: "mfa-recovery-list",
                    for c in info.recovery_codes.iter() {
                        li { key: "{c}", code { "{c}" } }
                    }
                }
            }
        }
    }
}

#[component]
fn MfaConfirmForm(
    code: Signal<String>,
    busy: Signal<bool>,
    on_submit: EventHandler<String>,
) -> Element {
    let mut code = code;
    rsx! {
        form {
            class: "auth-form",
            onsubmit: move |evt| {
                evt.prevent_default();
                let val = code.read().trim().to_string();
                if val.is_empty() { return; }
                on_submit.call(val);
            },
            div { class: "auth-field",
                Label {
                    html_for: "mfa-confirm",
                    class: "auth-label",
                    "Authenticator code"
                }
                Input {
                    id: "mfa-confirm",
                    r#type: "text",
                    inputmode: "numeric",
                    autocomplete: "one-time-code",
                    placeholder: "123 456",
                    value: "{code}",
                    oninput: move |evt: FormEvent| code.set(evt.value()),
                }
            }
            Button {
                variant: ButtonVariant::Primary,
                r#type: "submit",
                class: "auth-submit",
                if busy() { "Confirming…" } else { "Confirm" }
            }
        }
    }
}

// `ForgotPassword`, `ResetPassword`, and `VerifyEmail` are now drop-in
// components shipped by the library at `dx_auth::ui::*` (imported above).
// The Route enum entries above pick them up automatically.

// ---- App-specific server fn: which permissions the current user has. ----

/// Demo permission check using the seed `Category::View` token the library's
/// helpers grant new accounts. Real apps would seed via their own hook (a
/// future API improvement) rather than depending on the library's default.
#[get("/api/user/permissions", auth: dx_auth::auth::Session)]
pub async fn get_permissions() -> Result<HashSet<String>> {
    use axum_session_auth::{Auth, Rights};
    use dx_auth::auth::User;

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
            dx_auth::ui::AccountSettings {}
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
                                dx_auth::ui::AdminUserDetail {
                                    user_id: uid,
                                    on_back: move |_| selected.set(None),
                                }
                            } else {
                                dx_auth::ui::AdminUserList {
                                    on_select: move |id: i64| selected.set(Some(id)),
                                }
                            }
                        }
                    }
                    if can_audit {
                        TabContent { index: 1_usize, value: "audit".to_string(),
                            dx_auth::ui::AuditLog {}
                        }
                    }
                    if can_roles {
                        TabContent { index: 2_usize, value: "roles".to_string(),
                            match role_pane() {
                                Some(rid_opt) => rsx! {
                                    dx_auth::ui::AdminRoleEditor {
                                        role_id: rid_opt,
                                        on_back: move |_| role_pane.set(None),
                                    }
                                },
                                None => rsx! {
                                    dx_auth::ui::AdminRoleList {
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
