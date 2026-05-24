use crate::server::request_password_reset_email;
use crate::ui::components::button::{Button, ButtonVariant};
use crate::ui::components::card::{Card, CardContent, CardDescription, CardHeader, CardTitle};
use crate::ui::components::input::Input;
use crate::ui::components::label::Label;
use leptos::prelude::*;
use leptos::task::spawn_local;

/// Drop-in "Forgot your password?" screen. On submit, calls
/// [`crate::server::request_password_reset_email`] — which always returns
/// `Ok(())` regardless of whether the address exists — so the UI flips to a
/// neutral "if an account exists, a link is on its way" message.
#[component]
pub fn ForgotPassword(
    #[prop(default = "Reset your password")] title: &'static str,
    #[prop(default = "We'll email you a link to choose a new one.")] description: &'static str,
    #[prop(default = "you@example.com")] email_placeholder: &'static str,
    #[prop(default = "/login")] back_href: &'static str,
) -> impl IntoView {
    let email = RwSignal::new(String::new());
    let sent = RwSignal::new(false);
    let sending = RwSignal::new(false);

    let on_submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let email_val = email.get_untracked();
        if email_val.trim().is_empty() {
            return;
        }
        sending.set(true);
        spawn_local(async move {
            let _ = request_password_reset_email(email_val).await;
            sending.set(false);
            sent.set(true);
        });
    };

    view! {
        <div class="dx-auth-screen">
            <div class="dx-auth-card">
                <Card>
                    <CardHeader>
                        <CardTitle>{title}</CardTitle>
                        <CardDescription>{description}</CardDescription>
                    </CardHeader>
                    <CardContent>
                        {move || {
                            if sent.get() {
                                view! {
                                    <p class="dx-auth-success">
                                        "If an account exists for that address, a reset link is on its way."
                                    </p>
                                    <p class="dx-auth-aux">
                                        <a href=back_href>"Back to sign in"</a>
                                    </p>
                                }
                                    .into_any()
                            } else {
                                view! {
                                    <form class="dx-auth-form" on:submit=on_submit>
                                        <div class="dx-auth-field">
                                            <Label html_for="dx-forgot-email">"Email"</Label>
                                            <Input
                                                id="dx-forgot-email"
                                                input_type="email"
                                                autocomplete="email"
                                                placeholder=email_placeholder
                                                value=email
                                                on_input=Callback::new(move |v: String| {
                                                    email.set(v)
                                                })
                                            />
                                        </div>
                                        <Button
                                            variant=ButtonVariant::Primary
                                            button_type="submit"
                                            class="dx-auth-submit"
                                        >
                                            {move || {
                                                if sending.get() {
                                                    "Sending…"
                                                } else {
                                                    "Send reset link"
                                                }
                                            }}
                                        </Button>
                                        <p class="dx-auth-aux">
                                            <a href=back_href>"Back to sign in"</a>
                                        </p>
                                    </form>
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
