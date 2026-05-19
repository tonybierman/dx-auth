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
use dx_auth::ui::{LoginPanel, LoginProvider, LoginSubmit, SubmitKind};
use dx_auth::{
    friendly_server_error, LoginOutcome, MfaSetupView, MfaStatusView, ProviderId, UserProfile,
};

const THEME_CSS: Asset = asset!("/assets/dx-components-theme.css");
const APP_CSS: Asset = asset!("/assets/app.css");

const GITHUB_ICON_SVG: &str = r#"<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" xmlns="http://www.w3.org/2000/svg"><path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.4 3-.405 1.02.005 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/></svg>"#;

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

        let github = dx_auth::auth::OAuthClients::from_env(pool.clone())?;
        match &github {
            Some(_) => println!("[startup] GitHub OAuth: enabled"),
            None => println!(
                "[startup] GitHub OAuth: disabled (set GITHUB_CLIENT_ID + GITHUB_CLIENT_SECRET to enable)"
            ),
        }

        let mailer = dx_auth::Mailer::from_env()?;
        println!("[startup] mailer backend: {}", mailer.describe());

        let cfg = dx_auth::AuthConfig::builder(pool, mailer).github(github).build();

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
    #[route("/admin/users")]
    AdminUsersPage,
    #[route("/admin/users/:user_id")]
    AdminUserPage { user_id: i64 },
    #[route("/admin/audit")]
    AdminAuditPage,
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

        Router::<Route> {}
    }
}

#[component]
fn Home() -> Element {
    let mut profile = use_resource(get_current_user_profile);
    let mut permissions = use_action(get_permissions);
    let mut logout = use_action(logout);

    let providers_resource = use_resource(available_providers);
    let providers: Vec<LoginProvider> = providers_resource()
        .and_then(|r| r.ok())
        .unwrap_or_default()
        .into_iter()
        .map(provider_descriptor)
        .collect();

    let current: UserProfile = profile().and_then(|r| r.ok()).unwrap_or_default();
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
                Ok(LoginOutcome::LoggedIn) => profile.restart(),
                Ok(LoginOutcome::EmailUnverified) => pending_email.set(Some(email_for_pending)),
                Ok(LoginOutcome::MfaRequired) => pending_mfa.set(true),
                Err(e) => auth_error.set(friendly_server_error(e)),
            }
        });
    };

    rsx! {
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
                    a { class: "app-link", href: "/account/settings", "Account" }
                    a { class: "app-link", href: "/account/mfa", "Two-factor auth" }
                    a { class: "app-link", href: "/admin/users", "Admin" }
                    a { class: "app-link", href: "/admin/audit", "Audit log" }
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
            } else if pending_mfa() {
                MfaChallengeView {
                    on_logged_in: move |_| {
                        pending_mfa.set(false);
                        profile.restart();
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

fn provider_descriptor(id: ProviderId) -> LoginProvider {
    match id {
        ProviderId::Github => LoginProvider {
            name: "GitHub",
            href: "/auth/github/login",
            icon_svg: Some(GITHUB_ICON_SVG),
        },
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

#[component]
fn VerifyEmail(token: String) -> Element {
    let token_for_call = token.clone();
    let result = use_resource(move || {
        let token = token_for_call.clone();
        async move { verify_email(token).await }
    });

    let body = match result() {
        None => rsx! { p { class: "auth-success", "Verifying…" } },
        Some(Ok(true)) => rsx! {
            p { class: "auth-success", "Email verified — you can sign in now." }
            p { a { href: "/", "Continue to sign in" } }
        },
        Some(Ok(false)) | Some(Err(_)) => rsx! {
            p { class: "auth-error", "This verification link has expired or already been used." }
            p { a { href: "/", "Back to sign in" } }
        },
    };

    rsx! {
        main { class: "app-shell",
            Card { class: "login-panel",
                CardHeader { CardTitle { "Verify your email" } }
                CardContent { {body} }
            }
        }
    }
}

#[component]
fn ForgotPassword() -> Element {
    let mut email = use_signal(String::new);
    let mut sent = use_signal(|| false);
    let mut sending = use_signal(|| false);

    rsx! {
        main { class: "app-shell",
            Card { class: "login-panel",
                CardHeader {
                    CardTitle { "Reset your password" }
                    CardDescription { "We'll email you a link to choose a new one." }
                }
                CardContent {
                    if sent() {
                        p { class: "auth-success",
                            "If an account exists for that address, a reset link is on its way."
                        }
                        p { a { href: "/", "Back to sign in" } }
                    } else {
                        form {
                            class: "auth-form",
                            onsubmit: move |evt| {
                                evt.prevent_default();
                                let email_val = email.read().clone();
                                if email_val.trim().is_empty() { return; }
                                sending.set(true);
                                spawn(async move {
                                    let _ = request_password_reset_email(email_val).await;
                                    sending.set(false);
                                    sent.set(true);
                                });
                            },
                            div { class: "auth-field",
                                Label { html_for: "forgot-email", class: "auth-label", "Email" }
                                Input {
                                    id: "forgot-email",
                                    r#type: "email",
                                    autocomplete: "email",
                                    placeholder: "you@example.com",
                                    value: "{email}",
                                    oninput: move |evt: FormEvent| email.set(evt.value()),
                                }
                            }
                            Button {
                                variant: ButtonVariant::Primary,
                                r#type: "submit",
                                class: "auth-submit",
                                if sending() { "Sending…" } else { "Send reset link" }
                            }
                            p { class: "auth-aux",
                                a { href: "/", "Back to sign in" }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn ResetPassword(token: String) -> Element {
    let mut password = use_signal(String::new);
    let mut confirm = use_signal(String::new);
    let mut done = use_signal(|| false);
    let mut error = use_signal(String::new);
    let mut submitting = use_signal(|| false);

    let token_for_submit = token.clone();

    rsx! {
        main { class: "app-shell",
            Card { class: "login-panel",
                CardHeader {
                    CardTitle { "Set a new password" }
                    CardDescription { "Choose a password of at least 8 characters." }
                }
                CardContent {
                    if done() {
                        p { class: "auth-success", "Password updated." }
                        p { a { href: "/", "Sign in with your new password" } }
                    } else {
                        form {
                            class: "auth-form",
                            onsubmit: move |evt| {
                                evt.prevent_default();
                                error.set(String::new());

                                let new_pw = password.read().clone();
                                if new_pw != confirm.read().clone() {
                                    error.set("Passwords don't match.".to_string());
                                    return;
                                }

                                let token = token_for_submit.clone();
                                submitting.set(true);
                                spawn(async move {
                                    match reset_password(token, new_pw).await {
                                        Ok(()) => done.set(true),
                                        Err(e) => error.set(friendly_server_error(e)),
                                    }
                                    submitting.set(false);
                                });
                            },
                            div { class: "auth-field",
                                Label { html_for: "reset-password", class: "auth-label", "New password" }
                                Input {
                                    id: "reset-password",
                                    r#type: "password",
                                    autocomplete: "new-password",
                                    placeholder: "••••••••",
                                    value: "{password}",
                                    oninput: move |evt: FormEvent| password.set(evt.value()),
                                }
                            }
                            div { class: "auth-field",
                                Label { html_for: "reset-password-confirm", class: "auth-label", "Confirm password" }
                                Input {
                                    id: "reset-password-confirm",
                                    r#type: "password",
                                    autocomplete: "new-password",
                                    placeholder: "••••••••",
                                    value: "{confirm}",
                                    oninput: move |evt: FormEvent| confirm.set(evt.value()),
                                }
                            }
                            if !error().is_empty() {
                                div { class: "auth-error", role: "alert", "{error}" }
                            }
                            Button {
                                variant: ButtonVariant::Primary,
                                r#type: "submit",
                                class: "auth-submit",
                                if submitting() { "Updating…" } else { "Reset password" }
                            }
                            p { class: "auth-aux",
                                a { href: "/", "Back to sign in" }
                            }
                        }
                    }
                }
            }
        }
    }
}

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
            dx_auth::ui::AccountSettings { mfa_setup_href: "/account/mfa" }
            p { class: "auth-aux", a { href: "/", "← Back to home" } }
        }
    }
}

#[component]
fn AdminUsersPage() -> Element {
    let nav = navigator();
    rsx! {
        main { class: "app-shell",
            dx_auth::ui::AdminUserList {
                on_select: move |id: i64| {
                    nav.push(Route::AdminUserPage { user_id: id });
                },
            }
            p { class: "auth-aux", a { href: "/", "← Back to home" } }
        }
    }
}

#[component]
fn AdminUserPage(user_id: i64) -> Element {
    let nav = navigator();
    rsx! {
        main { class: "app-shell",
            dx_auth::ui::AdminUserDetail {
                user_id,
                on_back: move |_| {
                    nav.push(Route::AdminUsersPage);
                },
            }
        }
    }
}

#[component]
fn AdminAuditPage() -> Element {
    rsx! {
        main { class: "app-shell",
            dx_auth::ui::AuditLog {}
            p { class: "auth-aux", a { href: "/", "← Back to home" } }
        }
    }
}
