use crate::server::verify_email as verify_email_server;
use crate::ui::components::card::{Card, CardContent, CardHeader, CardTitle};
use leptos::prelude::*;

/// Drop-in email-verification screen, mounted at e.g. `/auth/verify?token=…`.
/// Fires [`crate::server::verify_email`] on mount and renders one of three
/// states: pending, success, or expired-or-already-used.
#[component]
pub fn VerifyEmail(
    #[prop(into)] token: String,
    #[prop(default = "Verify your email")] title: &'static str,
    #[prop(default = "/login")] back_href: &'static str,
) -> impl IntoView {
    let result = Resource::new(
        move || token.clone(),
        |token| async move { verify_email_server(token).await },
    );

    view! {
        <div class="dx-auth-screen">
            <div class="dx-auth-card">
                <Card>
                    <CardHeader>
                        <CardTitle>{title}</CardTitle>
                    </CardHeader>
                    <CardContent>
                        {move || match result.get() {
                            None => {
                                view! { <p class="dx-auth-message">"Verifying…"</p> }.into_any()
                            }
                            Some(Ok(true)) => {
                                view! {
                                    <p class="dx-auth-message">
                                        "Email verified — you can sign in now."
                                    </p>
                                    <p class="dx-auth-aux">
                                        <a href=back_href>"Continue to sign in"</a>
                                    </p>
                                }
                                    .into_any()
                            }
                            _ => {
                                view! {
                                    <p class="dx-auth-message">
                                        "This verification link has expired or already been used."
                                    </p>
                                    <p class="dx-auth-aux">
                                        <a href=back_href>"Back to sign in"</a>
                                    </p>
                                }
                                    .into_any()
                            }
                        }}
                    </CardContent>
                </Card>
            </div>
        </div>
    }
}
