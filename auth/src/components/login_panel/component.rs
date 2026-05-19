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

/// Payload delivered to `LoginPanel`'s `on_submit` when the email/password form is submitted.
#[derive(Clone, PartialEq, Debug, Default)]
pub struct LoginSubmit {
    pub email: String,
    pub password: String,
}

/// A reusable "Sign in" card with an email + password form and an optional list of
/// third-party providers below it. Drop-in: caller supplies a submit handler (or omits it),
/// a provider list (possibly empty), and any wording overrides.
#[component]
pub fn LoginPanel(
    #[props(default)] providers: Vec<LoginProvider>,
    #[props(default = "Welcome back")] title: &'static str,
    #[props(default = "Sign in to your workspace.")] description: &'static str,
    #[props(default = "Sign in")] submit_label: &'static str,
    #[props(default = "you@example.com")] email_placeholder: &'static str,
    #[props(default = "••••••••")] password_placeholder: &'static str,
    #[props(default)] forgot_href: Option<&'static str>,
    #[props(default = true)] show_email_password: bool,
    on_submit: Option<EventHandler<LoginSubmit>>,
) -> Element {
    let mut email = use_signal(String::new);
    let mut password = use_signal(String::new);

    rsx! {
        document::Stylesheet { href: LOGIN_PANEL_CSS }
        Card { class: Styles::login_panel,
            CardHeader {
                CardTitle { "{title}" }
                CardDescription { "{description}" }
            }

            if show_email_password {
                form {
                    class: Styles::login_form,
                    onsubmit: move |evt| {
                        evt.prevent_default();
                        if let Some(handler) = on_submit.as_ref() {
                            handler.call(LoginSubmit {
                                email: email.read().clone(),
                                password: password.read().clone(),
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
                            if let Some(href) = forgot_href {
                                a {
                                    class: Styles::login_forgot,
                                    href: "{href}",
                                    "Forgot?"
                                }
                            }
                        }
                        Input {
                            id: "login-password",
                            name: "password",
                            r#type: "password",
                            autocomplete: "current-password",
                            placeholder: "{password_placeholder}",
                            value: "{password}",
                            oninput: move |evt: FormEvent| password.set(evt.value()),
                        }
                    }

                    Button {
                        variant: ButtonVariant::Primary,
                        r#type: "submit",
                        class: Styles::login_submit,
                        "{submit_label}"
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
