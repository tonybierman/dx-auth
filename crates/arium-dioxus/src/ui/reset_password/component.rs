use dioxus::prelude::*;

use crate::friendly_server_error;
use crate::server::reset_password as reset_password_server;
use crate::ui::components::button::{Button, ButtonVariant};
use crate::ui::components::card::{Card, CardContent, CardDescription, CardHeader, CardTitle};
use crate::ui::components::input::Input;
use crate::ui::components::label::Label;

// Same file the `#[css_module]` below points at; declared as a separate `Asset` so we can
// render a `document::Stylesheet` and guarantee the link tag is in the page on every
// render (the css_module macro's OnceLock-based injection only fires on the first SSR
// request).
const RESET_PASSWORD_CSS: Asset = asset!(
    "/src/ui/reset_password/style.css",
    AssetOptions::css_module()
);

#[css_module("/src/ui/reset_password/style.css")]
struct Styles;

/// Drop-in "set a new password" screen, mounted at e.g. `/auth/reset?:token`.
///
/// Calls [`crate::server::reset_password`] with the token from the URL and the
/// new password. On success, flips to a confirmation with a link back to sign in.
#[component]
pub fn ResetPassword(
    token: String,
    #[props(default = "Set a new password")] title: &'static str,
    #[props(default = "Choose a password of at least 8 characters.")] description: &'static str,
    #[props(default = "/login")] back_href: &'static str,
) -> Element {
    let mut password = use_signal(String::new);
    let mut confirm = use_signal(String::new);
    let mut done = use_signal(|| false);
    let mut error = use_signal(String::new);
    let mut submitting = use_signal(|| false);

    let token_for_submit = token.clone();

    rsx! {
        document::Stylesheet { href: RESET_PASSWORD_CSS }
        div { class: Styles::dx_auth_screen,
            div { class: Styles::dx_auth_card,
                Card {
                    CardHeader {
                        CardTitle { "{title}" }
                        CardDescription { "{description}" }
                    }
                    CardContent {
                        if done() {
                            p { class: Styles::dx_auth_success, "Password updated." }
                            p { class: Styles::dx_auth_aux,
                                a { href: "{back_href}", "Sign in with your new password" }
                            }
                        } else {
                            form {
                                // POST so the no-JS / pre-hydration native submit doesn't leak
                                // the new password into the URL; `onsubmit` handles the live path.
                                method: "post",
                                class: Styles::dx_auth_form,
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
                                        match reset_password_server(token, new_pw).await {
                                            Ok(()) => done.set(true),
                                            Err(e) => error.set(friendly_server_error(e)),
                                        }
                                        submitting.set(false);
                                    });
                                },
                                div { class: Styles::dx_auth_field,
                                    Label { html_for: "dx-reset-password", "New password" }
                                    Input {
                                        id: "dx-reset-password",
                                        r#type: "password",
                                        autocomplete: "new-password",
                                        value: "{password}",
                                        oninput: move |evt: FormEvent| password.set(evt.value()),
                                    }
                                }
                                div { class: Styles::dx_auth_field,
                                    Label { html_for: "dx-reset-password-confirm", "Confirm password" }
                                    Input {
                                        id: "dx-reset-password-confirm",
                                        r#type: "password",
                                        autocomplete: "new-password",
                                        value: "{confirm}",
                                        oninput: move |evt: FormEvent| confirm.set(evt.value()),
                                    }
                                }
                                if !error().is_empty() {
                                    div { class: Styles::dx_auth_error, role: "alert", "{error}" }
                                }
                                Button {
                                    variant: ButtonVariant::Primary,
                                    r#type: "submit",
                                    class: Styles::dx_auth_submit,
                                    if submitting() { "Updating…" } else { "Reset password" }
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
