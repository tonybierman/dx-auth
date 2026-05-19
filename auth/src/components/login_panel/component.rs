use dioxus::prelude::*;

use crate::components::button::{Button, ButtonVariant};
use crate::components::card::{Card, CardDescription, CardHeader, CardTitle};
use crate::components::input::Input;
use crate::components::label::Label;

/// Same file the `#[css_module]` below points at; declared as a separate `Asset` so we can
/// render a `document::Stylesheet` and guarantee the link tag is in the page even when the
/// LoginPanel first mounts client-side (the css_module's OnceLock + queue_effect path
/// doesn't reliably insert the link during post-hydration mounts).
const LOGIN_PANEL_CSS: Asset = asset!(
    "/src/components/login_panel/style.css",
    AssetOptions::css_module()
);

#[css_module("/src/components/login_panel/style.css")]
struct Styles;

/// One third-party login provider entry.
///
/// `href` is the server-side route that starts the OAuth dance (e.g. `/auth/github/login`).
/// `icon_svg` is optional inline SVG markup; pass `None` for a text-only button.
#[derive(Clone, PartialEq)]
pub struct LoginProvider {
    pub name: &'static str,
    pub href: &'static str,
    pub icon_svg: Option<&'static str>,
}

/// Which mode the email/password form is in. Drives title, submit label, and whether the
/// password-confirm field appears.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum SubmitKind {
    #[default]
    SignIn,
    SignUp,
}

/// Payload delivered to `LoginPanel`'s `on_submit` when the email/password form is submitted.
#[derive(Clone, PartialEq, Debug, Default)]
pub struct LoginSubmit {
    pub kind: SubmitKind,
    pub email: String,
    pub password: String,
}

/// A reusable "Sign in" card with an email + password form (toggleable into sign-up mode)
/// and an optional list of third-party providers below it. Drop-in: caller supplies a submit
/// handler (or omits it), a provider list (possibly empty), an optional error to render, and
/// any wording overrides.
#[component]
pub fn LoginPanel(
    #[props(default)] providers: Vec<LoginProvider>,
    #[props(default = "Welcome back")] title: &'static str,
    #[props(default = "Sign in to your workspace.")] description: &'static str,
    #[props(default = "Sign in")] submit_label: &'static str,
    #[props(default = "Create your account")] signup_title: &'static str,
    #[props(default = "Start a new workspace.")] signup_description: &'static str,
    #[props(default = "Create account")] signup_submit_label: &'static str,
    #[props(default = "you@example.com")] email_placeholder: &'static str,
    #[props(default = "••••••••")] password_placeholder: &'static str,
    #[props(default)] forgot_href: Option<&'static str>,
    #[props(default = true)] show_email_password: bool,
    #[props(default)] error: Option<String>,
    on_submit: Option<EventHandler<LoginSubmit>>,
) -> Element {
    let mut email = use_signal(String::new);
    let mut password = use_signal(String::new);
    let mut password_confirm = use_signal(String::new);
    let mut mode = use_signal(|| SubmitKind::SignIn);
    let mut local_error = use_signal(String::new);

    let is_signup = mode() == SubmitKind::SignUp;
    let effective_title = if is_signup { signup_title } else { title };
    let effective_description = if is_signup { signup_description } else { description };
    let effective_submit_label = if is_signup { signup_submit_label } else { submit_label };
    let toggle_prompt = if is_signup {
        "Already have an account?"
    } else {
        "Don't have an account?"
    };
    let toggle_action_label = if is_signup { "Sign in" } else { "Sign up" };

    // Prefer the inline (client-side) error; fall back to the parent-supplied one.
    let displayed_error = {
        let local = local_error.read().clone();
        if !local.is_empty() {
            Some(local)
        } else {
            error.clone().filter(|e| !e.is_empty())
        }
    };

    rsx! {
        document::Stylesheet { href: LOGIN_PANEL_CSS }
        Card { class: Styles::login_panel,
            CardHeader {
                CardTitle { "{effective_title}" }
                CardDescription { "{effective_description}" }
            }

            if show_email_password {
                form {
                    class: Styles::login_form,
                    onsubmit: move |evt| {
                        evt.prevent_default();
                        let email_val = email.read().clone();
                        let password_val = password.read().clone();

                        if is_signup && password_val != password_confirm.read().clone() {
                            local_error.set("Passwords don't match.".to_string());
                            return;
                        }
                        local_error.set(String::new());

                        if let Some(handler) = on_submit.as_ref() {
                            handler.call(LoginSubmit {
                                kind: mode(),
                                email: email_val,
                                password: password_val,
                            });
                        }
                    },

                    div { class: Styles::login_field,
                        Label {
                            html_for: "login-email",
                            class: Styles::login_label,
                            "Email"
                        }
                        Input {
                            id: "login-email",
                            name: "email",
                            r#type: "email",
                            autocomplete: "email",
                            placeholder: "{email_placeholder}",
                            value: "{email}",
                            oninput: move |evt: FormEvent| email.set(evt.value()),
                        }
                    }

                    div { class: Styles::login_field,
                        div { class: Styles::login_label_row,
                            Label {
                                html_for: "login-password",
                                class: Styles::login_label,
                                "Password"
                            }
                            if !is_signup {
                                if let Some(href) = forgot_href {
                                    a {
                                        class: Styles::login_forgot,
                                        href: "{href}",
                                        "Forgot?"
                                    }
                                }
                            }
                        }
                        Input {
                            id: "login-password",
                            name: "password",
                            r#type: "password",
                            autocomplete: if is_signup { "new-password" } else { "current-password" },
                            placeholder: "{password_placeholder}",
                            value: "{password}",
                            oninput: move |evt: FormEvent| password.set(evt.value()),
                        }
                    }

                    if is_signup {
                        div { class: Styles::login_field,
                            Label {
                                html_for: "login-password-confirm",
                                class: Styles::login_label,
                                "Confirm password"
                            }
                            Input {
                                id: "login-password-confirm",
                                name: "password_confirm",
                                r#type: "password",
                                autocomplete: "new-password",
                                placeholder: "{password_placeholder}",
                                value: "{password_confirm}",
                                oninput: move |evt: FormEvent| password_confirm.set(evt.value()),
                            }
                        }
                    }

                    if let Some(msg) = displayed_error {
                        div {
                            class: Styles::login_error,
                            role: "alert",
                            "{msg}"
                        }
                    }

                    Button {
                        variant: ButtonVariant::Primary,
                        r#type: "submit",
                        class: Styles::login_submit,
                        "{effective_submit_label}"
                    }

                    div { class: Styles::login_toggle,
                        span { "{toggle_prompt} " }
                        button {
                            class: Styles::login_toggle_button,
                            r#type: "button",
                            onclick: move |_| {
                                let next = if is_signup { SubmitKind::SignIn } else { SubmitKind::SignUp };
                                mode.set(next);
                                local_error.set(String::new());
                                password_confirm.set(String::new());
                            },
                            "{toggle_action_label}"
                        }
                    }
                }
            }

            if !providers.is_empty() {
                div { class: Styles::login_providers,
                    for provider in providers.iter() {
                        ProviderLink {
                            key: "{provider.name}",
                            name: provider.name,
                            href: provider.href,
                            icon_svg: provider.icon_svg,
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn ProviderLink(
    name: &'static str,
    href: &'static str,
    icon_svg: Option<&'static str>,
) -> Element {
    rsx! {
        a {
            class: Styles::login_provider_button,
            href: "{href}",
            if let Some(svg) = icon_svg {
                span {
                    class: Styles::login_provider_icon,
                    dangerous_inner_html: "{svg}",
                }
            }
            "Continue with {name}"
        }
    }
}
