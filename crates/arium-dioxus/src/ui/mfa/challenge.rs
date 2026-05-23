use dioxus::prelude::*;

use crate::friendly_server_error;
use crate::server::verify_login_mfa;
use crate::ui::components::button::{Button, ButtonVariant};
use crate::ui::components::card::{Card, CardContent, CardDescription, CardHeader, CardTitle};
use crate::ui::components::input::Input;
use crate::ui::components::label::Label;
use crate::wire::LoginOutcome;

const MFA_CSS: Asset = asset!("/src/ui/mfa/style.css", AssetOptions::css_module());

#[css_module("/src/ui/mfa/style.css")]
struct Styles;

/// Drop-in two-factor authentication challenge shown after
/// [`crate::server::login_with_password`] returns
/// [`LoginOutcome::MfaRequired`](crate::wire::LoginOutcome::MfaRequired).
///
/// Accepts either a 6-digit TOTP code from the user's authenticator app
/// or one of their single-use recovery codes (the link below the input
/// toggles between modes). On success, fires `on_logged_in`; `on_cancel`
/// is fired when the user backs out — the consumer is responsible for
/// calling [`crate::server::cancel_mfa_challenge`] in its handler if it
/// wants to clear the half-authenticated session.
#[component]
pub fn MfaChallenge(
    on_logged_in: EventHandler<()>,
    on_cancel: EventHandler<()>,
    #[props(default = "Two-factor authentication")] title: &'static str,
) -> Element {
    let mut code = use_signal(String::new);
    let mut use_recovery = use_signal(|| false);
    let mut error = use_signal(String::new);
    let mut submitting = use_signal(|| false);

    rsx! {
        document::Stylesheet { href: MFA_CSS }
        div { class: Styles::dx_auth_screen,
            div { class: Styles::dx_auth_card,
                Card {
                    CardHeader {
                        CardTitle { "{title}" }
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
                            class: Styles::dx_auth_form,
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
                            div { class: Styles::dx_auth_field,
                                Label {
                                    html_for: "dx-mfa-code",
                                    class: Styles::dx_auth_label,
                                    if use_recovery() { "Recovery code" } else { "Authenticator code" }
                                }
                                Input {
                                    id: "dx-mfa-code",
                                    r#type: "text",
                                    inputmode: if use_recovery() { "text" } else { "numeric" },
                                    autocomplete: "one-time-code",
                                    placeholder: if use_recovery() { "ABCD-EFGH-IJ" } else { "123 456" },
                                    value: "{code}",
                                    oninput: move |evt: FormEvent| code.set(evt.value()),
                                }
                            }
                            if !error().is_empty() {
                                div { class: Styles::dx_auth_error, role: "alert", "{error}" }
                            }
                            Button {
                                variant: ButtonVariant::Primary,
                                r#type: "submit",
                                class: Styles::dx_auth_submit,
                                if submitting() { "Verifying…" } else { "Verify" }
                            }
                            p { class: Styles::dx_auth_aux,
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
                            p { class: Styles::dx_auth_aux,
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
    }
}
