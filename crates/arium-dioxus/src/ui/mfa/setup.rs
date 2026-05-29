use dioxus::prelude::*;

use crate::friendly_server_error;
use crate::server::{
    begin_mfa_setup, confirm_mfa_setup, disable_mfa_for_user, get_current_user_profile,
    get_mfa_status,
};
use crate::ui::components::button::{Button, ButtonVariant};
use crate::ui::components::card::{Card, CardContent, CardDescription, CardHeader, CardTitle};
use crate::ui::components::input::Input;
use crate::ui::components::label::Label;
use crate::wire::{MfaSetupView, MfaStatusView};

const MFA_CSS: Asset = asset!("/src/ui/mfa/style.css", AssetOptions::css_module());

#[css_module("/src/ui/mfa/style.css")]
struct Styles;

/// Drop-in MFA enrollment + management screen, intended to be mounted at
/// e.g. `/account/mfa` (or rendered inside an account-settings tab).
///
/// Branches on [`crate::server::get_mfa_status`]:
///
/// - **Disabled** — offers a "Set up two-factor auth" button that calls
///   [`crate::server::begin_mfa_setup`], displays the QR + secret +
///   recovery codes, and accepts a confirmation TOTP via
///   [`crate::server::confirm_mfa_setup`].
/// - **Pending** — the user started enrollment but didn't finish; lets
///   them restart or complete it.
/// - **Enabled** — shows a "Disable two-factor auth" destructive button
///   that calls [`crate::server::disable_mfa_for_user`].
///
/// Renders a sign-in-required card if the visitor isn't authenticated.
#[component]
pub fn MfaSetup(
    #[props(default = "Two-factor authentication")] title: &'static str,
    #[props(default = "/")] back_href: &'static str,
    /// When `true`, omit the full-viewport `.dx-auth-screen`/`.dx-auth-card`
    /// centering shell so the card renders inline (e.g. inside a tab or a
    /// console pane). Defaults to `false` for standalone-route use.
    #[props(default = false)]
    embedded: bool,
) -> Element {
    let profile = use_resource(get_current_user_profile);
    let mut status = use_resource(get_mfa_status);
    let mut setup_info = use_signal::<Option<MfaSetupView>>(|| None);
    let mut confirm_code = use_signal(String::new);
    let mut error = use_signal(String::new);
    let mut info_message = use_signal(String::new);
    let mut busy = use_signal(|| false);

    // Empty classes collapse the centering shell to plain block wrappers.
    let screen_class = if embedded {
        String::new()
    } else {
        Styles::dx_auth_screen.to_string()
    };
    let card_class = if embedded {
        String::new()
    } else {
        Styles::dx_auth_card.to_string()
    };
    // Inline override beats `.dx-card` by specificity, so an embedded card
    // sits flat in its pane (no border/background/shadow) instead of as a
    // boxed panel — matching the inline `AccountSettings` look.
    let card_style = if embedded {
        "border: none; box-shadow: none; background: none;"
    } else {
        ""
    };

    let current = profile().and_then(|r| r.ok()).unwrap_or_default();

    if !current.is_authenticated {
        return rsx! {
            document::Stylesheet { href: MFA_CSS }
            div { class: screen_class,
                div { class: card_class,
                    Card {
                        CardHeader { CardTitle { "Sign in required" } }
                        CardContent {
                            p { "You need to be signed in to manage two-factor auth." }
                            p { class: Styles::dx_auth_aux,
                                a { href: "{back_href}", "Back to sign in" }
                            }
                        }
                    }
                }
            }
        };
    }

    let status_value: MfaStatusView = status().and_then(|r| r.ok()).unwrap_or_default();

    rsx! {
        document::Stylesheet { href: MFA_CSS }
        div { class: screen_class,
            div { class: card_class,
                Card {
                    style: card_style,
                    CardHeader {
                        CardTitle { "{title}" }
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
                            p { class: Styles::dx_auth_success, "{info_message}" }
                        }
                        if !error().is_empty() {
                            div { class: Styles::dx_auth_error, role: "alert", "{error}" }
                        }
                        match status_value {
                            MfaStatusView::Disabled => rsx! {
                                div { class: Styles::dx_auth_form,
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
                                            class: Styles::dx_auth_submit,
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
                                div { class: Styles::dx_auth_form,
                                    if let Some(info) = setup_info() {
                                        MfaSetupArtifacts { info: info.clone() }
                                    } else {
                                        p {
                                            "You started setting up two-factor auth but didn't finish. "
                                            "Restart enrollment to get a fresh QR code and recovery codes."
                                        }
                                        Button {
                                            variant: ButtonVariant::Outline,
                                            class: Styles::dx_auth_submit,
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
                                div { class: Styles::dx_auth_form,
                                    p { "Your account requires a 6-digit code on every sign-in." }
                                    Button {
                                        variant: ButtonVariant::Destructive,
                                        class: Styles::dx_auth_submit,
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
                        p { class: Styles::dx_auth_aux, a { href: "{back_href}", "Back to account" } }
                    }
                }
            }
        }
    }
}

#[component]
fn MfaSetupArtifacts(info: MfaSetupView) -> Element {
    rsx! {
        div { class: Styles::dx_mfa_artifacts,
            p { "Scan this QR code in your authenticator app, then enter a code below to confirm." }
            img {
                class: Styles::dx_mfa_qr,
                alt: "MFA QR code",
                src: "data:image/png;base64,{info.qr_png_base64}",
            }
            p { class: Styles::dx_auth_aux,
                "Can't scan? Enter this key manually: "
                code { "{info.secret_base32}" }
            }
            div { class: Styles::dx_mfa_recovery,
                strong { "Recovery codes" }
                p {
                    "Save these somewhere safe — each can be used once if you lose access to your "
                    "authenticator. They won't be shown again."
                }
                ul { class: Styles::dx_mfa_recovery_list,
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
            class: Styles::dx_auth_form,
            onsubmit: move |evt| {
                evt.prevent_default();
                let val = code.read().trim().to_string();
                if val.is_empty() { return; }
                on_submit.call(val);
            },
            div { class: Styles::dx_auth_field,
                Label {
                    html_for: "dx-mfa-confirm",
                    class: Styles::dx_auth_label,
                    "Authenticator code"
                }
                Input {
                    id: "dx-mfa-confirm",
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
                class: Styles::dx_auth_submit,
                if busy() { "Confirming…" } else { "Confirm" }
            }
        }
    }
}
