use dioxus::prelude::*;

use crate::ui::components::button::{Button, ButtonVariant};
use crate::ui::components::card::{Card, CardDescription, CardHeader, CardTitle};
use crate::ui::components::input::Input;
use crate::ui::components::label::Label;

/// Same file the `#[css_module]` below points at; declared as a separate `Asset` so we can
/// render a `document::Stylesheet` and guarantee the link tag is in the page even when the
/// LoginPanel first mounts client-side (the css_module's OnceLock + queue_effect path
/// doesn't reliably insert the link during post-hydration mounts).
const LOGIN_PANEL_CSS: Asset = asset!("/src/ui/login_panel/style.css", AssetOptions::css_module());

#[css_module("/src/ui/login_panel/style.css")]
struct Styles;

/// One third-party login provider entry.
///
/// `href` is the server-side route that starts the OAuth dance (e.g. `/auth/github/login`).
/// `icon_svg` is optional inline SVG markup; pass `None` for a text-only button.
///
/// Fields are owned `String`s so server-driven provider lists (returned by
/// [`crate::server::available_providers`]) can be mapped directly without
/// `String::leak`ing.
#[derive(Clone, PartialEq)]
pub struct LoginProvider {
    /// Button label (e.g. `"GitHub"`).
    pub name: String,
    /// Server-side route that starts the OAuth dance.
    pub href: String,
    /// Optional inline SVG markup for the button icon.
    pub icon_svg: Option<String>,
}

impl From<crate::wire::ProviderInfo> for LoginProvider {
    fn from(info: crate::wire::ProviderInfo) -> Self {
        Self {
            name: info.display_name,
            href: info.login_url,
            icon_svg: info.icon_svg,
        }
    }
}

/// Which mode the email/password form is in. Drives title, submit label, and whether the
/// password-confirm field appears.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum SubmitKind {
    /// Existing user signing in.
    #[default]
    SignIn,
    /// New user registering an account.
    SignUp,
}

/// Payload delivered to `LoginPanel`'s `on_submit` when the email/password form is submitted.
/// `remember` is only meaningful on `SignIn`; sign-up always issues a short session because
/// the user still has to verify their email before they're really in.
#[derive(Clone, PartialEq, Debug, Default)]
pub struct LoginSubmit {
    /// Sign-in vs. sign-up form mode at submit time.
    pub kind: SubmitKind,
    /// Email the user typed.
    pub email: String,
    /// Password the user typed.
    pub password: String,
    /// "Remember me" checkbox state. Only meaningful when `kind == SignIn`.
    pub remember: bool,
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
    #[props(default = "")] password_placeholder: &'static str,
    #[props(default)] forgot_href: Option<&'static str>,
    #[props(default = true)] show_email_password: bool,
    #[props(default)] error: Option<String>,
    on_submit: Option<EventHandler<LoginSubmit>>,
) -> Element {
    let mut email = use_signal(String::new);
    let mut password = use_signal(String::new);
    let mut password_confirm = use_signal(String::new);
    let mut mode = use_signal(|| SubmitKind::SignIn);
    let mut remember = use_signal(|| false);
    let mut local_error = use_signal(String::new);

    let is_signup = mode() == SubmitKind::SignUp;
    let effective_title = if is_signup { signup_title } else { title };
    let effective_description = if is_signup {
        signup_description
    } else {
        description
    };
    let effective_submit_label = if is_signup {
        signup_submit_label
    } else {
        submit_label
    };
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
                    // `onsubmit` intercepts via `prevent_default`, so this method only
                    // governs the no-JS / pre-hydration native submit: POST keeps typed
                    // credentials out of the URL (query string → access logs/history/Referer).
                    method: "post",
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
                                remember: remember() && !is_signup,
                            });
                        }

                        // Wipe password fields after dispatching so the form
                        // doesn't keep showing stale entries on retry (also
                        // means a refused login doesn't leave the password
                        // sitting in the DOM).
                        password.set(String::new());
                        password_confirm.set(String::new());
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
                        Label {
                            html_for: "login-password",
                            class: Styles::login_label,
                            "Password"
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

                    if !is_signup {
                        div { class: Styles::login_options,
                            label { class: Styles::login_remember,
                                input {
                                    r#type: "checkbox",
                                    checked: remember(),
                                    oninput: move |evt: FormEvent| {
                                        remember.set(evt.value() == "true" || evt.value() == "on");
                                    },
                                }
                                span { "Remember me on this device" }
                            }
                            if let Some(href) = forgot_href {
                                a {
                                    class: Styles::login_forgot,
                                    href: "{href}",
                                    "Forgot?"
                                }
                            }
                        }
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
                                password.set(String::new());
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
                            name: provider.name.clone(),
                            href: provider.href.clone(),
                            icon_svg: provider.icon_svg.clone(),
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn ProviderLink(name: String, href: String, icon_svg: Option<String>) -> Element {
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
