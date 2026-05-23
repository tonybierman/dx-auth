use dioxus::prelude::*;

use crate::server::verify_email as verify_email_server;
use crate::ui::components::card::{Card, CardContent, CardHeader, CardTitle};

// Same file the `#[css_module]` below points at; declared as a separate `Asset` so we can
// render a `document::Stylesheet` and guarantee the link tag is in the page on every
// render (the css_module macro's OnceLock-based injection only fires on the first SSR
// request).
const VERIFY_EMAIL_CSS: Asset =
    asset!("/src/ui/verify_email/style.css", AssetOptions::css_module());

#[css_module("/src/ui/verify_email/style.css")]
struct Styles;

/// Drop-in email-verification screen, mounted at e.g. `/auth/verify?:token`.
///
/// Fires [`crate::server::verify_email`] on mount via [`use_resource`] and
/// renders one of three states: pending, success, or expired-or-already-used.
/// Both terminal states link back to sign in.
#[component]
pub fn VerifyEmail(
    token: String,
    #[props(default = "Verify your email")] title: &'static str,
    #[props(default = "/login")] back_href: &'static str,
) -> Element {
    let token_for_call = token.clone();
    let result = use_resource(move || {
        let token = token_for_call.clone();
        async move { verify_email_server(token).await }
    });

    let body = match result() {
        None => rsx! {
            p { class: Styles::dx_auth_message, "Verifying…" }
        },
        Some(Ok(true)) => rsx! {
            p { class: Styles::dx_auth_message,
                "Email verified — you can sign in now."
            }
            p { class: Styles::dx_auth_aux,
                a { href: "{back_href}", "Continue to sign in" }
            }
        },
        Some(Ok(false)) | Some(Err(_)) => rsx! {
            p { class: Styles::dx_auth_message,
                "This verification link has expired or already been used."
            }
            p { class: Styles::dx_auth_aux,
                a { href: "{back_href}", "Back to sign in" }
            }
        },
    };

    rsx! {
        document::Stylesheet { href: VERIFY_EMAIL_CSS }
        div { class: Styles::dx_auth_screen,
            div { class: Styles::dx_auth_card,
                Card {
                    CardHeader {
                        CardTitle { "{title}" }
                    }
                    CardContent { {body} }
                }
            }
        }
    }
}
