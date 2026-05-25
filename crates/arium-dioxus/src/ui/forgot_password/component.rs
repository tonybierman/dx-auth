use dioxus::prelude::*;

use crate::server::request_password_reset_email;
use crate::ui::components::button::{Button, ButtonVariant};
use crate::ui::components::card::{Card, CardContent, CardDescription, CardHeader, CardTitle};
use crate::ui::components::input::Input;
use crate::ui::components::label::Label;

// Same file the `#[css_module]` below points at; declared as a separate `Asset` so we can
// render a `document::Stylesheet` and guarantee the link tag is in the page on every
// render (the css_module macro's OnceLock-based injection only fires on the first SSR
// request).
const FORGOT_PASSWORD_CSS: Asset = asset!(
    "/src/ui/forgot_password/style.css",
    AssetOptions::css_module()
);

#[css_module("/src/ui/forgot_password/style.css")]
struct Styles;

/// Drop-in "Forgot your password?" screen.
///
/// Renders a centered card with an email input. On submit, calls
/// [`crate::server::request_password_reset_email`] — which always returns
/// `Ok(())` regardless of whether the address exists (user-enumeration-safe),
/// so the UI just flips to a neutral "if an account exists, a link is on
/// its way" message.
///
/// Mount it at `/auth/forgot` (the default `forgot_href` baked into
/// [`super::LoginPanel`]).
#[component]
pub fn ForgotPassword(
    #[props(default = "Reset your password")] title: &'static str,
    #[props(default = "We'll email you a link to choose a new one.")] description: &'static str,
    #[props(default = "you@example.com")] email_placeholder: &'static str,
    #[props(default = "/login")] back_href: &'static str,
) -> Element {
    let mut email = use_signal(String::new);
    let mut sent = use_signal(|| false);
    let mut sending = use_signal(|| false);

    rsx! {
        document::Stylesheet { href: FORGOT_PASSWORD_CSS }
        div { class: Styles::dx_auth_screen,
            div { class: Styles::dx_auth_card,
                Card {
                    CardHeader {
                        CardTitle { "{title}" }
                        CardDescription { "{description}" }
                    }
                    CardContent {
                        if sent() {
                            p { class: Styles::dx_auth_success,
                                "If an account exists for that address, a reset link is on its way."
                            }
                            p { class: Styles::dx_auth_aux,
                                a { href: "{back_href}", "Back to sign in" }
                            }
                        } else {
                            form {
                                // POST so the no-JS / pre-hydration native submit doesn't
                                // leak the email into the URL; `onsubmit` handles the live path.
                                method: "post",
                                class: Styles::dx_auth_form,
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
                                div { class: Styles::dx_auth_field,
                                    Label { html_for: "dx-forgot-email", "Email" }
                                    Input {
                                        id: "dx-forgot-email",
                                        r#type: "email",
                                        autocomplete: "email",
                                        placeholder: "{email_placeholder}",
                                        value: "{email}",
                                        oninput: move |evt: FormEvent| email.set(evt.value()),
                                    }
                                }
                                Button {
                                    variant: ButtonVariant::Primary,
                                    r#type: "submit",
                                    class: Styles::dx_auth_submit,
                                    if sending() { "Sending…" } else { "Send reset link" }
                                }
                                p { class: Styles::dx_auth_aux,
                                    a { href: "{back_href}", "Back to sign in" }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
