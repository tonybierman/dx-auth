use crate::friendly_server_error;
use crate::server::reset_password as reset_password_server;
use crate::ui::components::button::{Button, ButtonVariant};
use crate::ui::components::card::{Card, CardContent, CardDescription, CardHeader, CardTitle};
use crate::ui::components::input::Input;
use crate::ui::components::label::Label;
use leptos::prelude::*;
use leptos::task::spawn_local;

/// Drop-in "set a new password" screen, mounted at e.g. `/auth/reset?token=…`.
/// Calls [`crate::server::reset_password`] with the token from the URL and the
/// new password; on success flips to a confirmation.
#[component]
pub fn ResetPassword(
    #[prop(into)] token: String,
    #[prop(default = "Set a new password")] title: &'static str,
    #[prop(default = "Choose a password of at least 8 characters.")] description: &'static str,
    #[prop(default = "/login")] back_href: &'static str,
) -> impl IntoView {
    let password = RwSignal::new(String::new());
    let confirm = RwSignal::new(String::new());
    let done = RwSignal::new(false);
    let error = RwSignal::new(String::new());
    let submitting = RwSignal::new(false);

    let on_submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        error.set(String::new());
        let new_pw = password.get_untracked();
        if new_pw != confirm.get_untracked() {
            error.set("Passwords don't match.".to_string());
            return;
        }
        let token = token.clone();
        submitting.set(true);
        spawn_local(async move {
            match reset_password_server(token, new_pw).await {
                Ok(()) => done.set(true),
                Err(e) => error.set(friendly_server_error(e)),
            }
            submitting.set(false);
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
                            if done.get() {
                                view! {
                                    <p class="dx-auth-success">"Password updated."</p>
                                    <p class="dx-auth-aux">
                                        <a href=back_href>"Sign in with your new password"</a>
                                    </p>
                                }
                                    .into_any()
                            } else {
                                view! {
                                    <form class="dx-auth-form" on:submit=on_submit.clone()>
                                        <div class="dx-auth-field">
                                            <Label html_for="dx-reset-password">"New password"</Label>
                                            <Input
                                                id="dx-reset-password"
                                                input_type="password"
                                                autocomplete="new-password"
                                                placeholder="••••••••"
                                                value=password
                                                on_input=Callback::new(move |v: String| {
                                                    password.set(v)
                                                })
                                            />
                                        </div>
                                        <div class="dx-auth-field">
                                            <Label html_for="dx-reset-password-confirm">
                                                "Confirm password"
                                            </Label>
                                            <Input
                                                id="dx-reset-password-confirm"
                                                input_type="password"
                                                autocomplete="new-password"
                                                placeholder="••••••••"
                                                value=confirm
                                                on_input=Callback::new(move |v: String| {
                                                    confirm.set(v)
                                                })
                                            />
                                        </div>
                                        <Show when=move || !error.get().is_empty()>
                                            <div class="dx-auth-error" role="alert">
                                                {move || error.get()}
                                            </div>
                                        </Show>
                                        <Button
                                            variant=ButtonVariant::Primary
                                            button_type="submit"
                                            class="dx-auth-submit"
                                        >
                                            {move || {
                                                if submitting.get() {
                                                    "Updating…"
                                                } else {
                                                    "Reset password"
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
