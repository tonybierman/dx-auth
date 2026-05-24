use crate::friendly_server_error;
use crate::server::verify_login_mfa;
use crate::ui::components::button::{Button, ButtonVariant};
use crate::ui::components::card::{Card, CardContent, CardDescription, CardHeader, CardTitle};
use crate::ui::components::input::Input;
use crate::ui::components::label::Label;
use crate::wire::LoginOutcome;
use leptos::prelude::*;
use leptos::task::spawn_local;

/// Drop-in two-factor authentication challenge shown after
/// [`crate::server::login_with_password`] returns
/// [`LoginOutcome::MfaRequired`](crate::wire::LoginOutcome::MfaRequired).
///
/// Accepts a TOTP code or a single-use recovery code (toggle below the input).
/// On success fires `on_logged_in`; `on_cancel` fires when the user backs out.
#[component]
pub fn MfaChallenge(
    on_logged_in: Callback<()>,
    on_cancel: Callback<()>,
    #[prop(default = "Two-factor authentication")] title: &'static str,
) -> impl IntoView {
    let code = RwSignal::new(String::new());
    let use_recovery = RwSignal::new(false);
    let error = RwSignal::new(String::new());
    let submitting = RwSignal::new(false);

    let on_submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let code_val = code.get_untracked().trim().to_string();
        if code_val.is_empty() {
            return;
        }
        error.set(String::new());
        submitting.set(true);
        spawn_local(async move {
            match verify_login_mfa(code_val).await {
                Ok(LoginOutcome::LoggedIn) => on_logged_in.run(()),
                Ok(_) => error.set("Unexpected response from server.".to_string()),
                Err(e) => error.set(friendly_server_error(e)),
            }
            code.set(String::new());
            submitting.set(false);
        });
    };

    view! {
        <div class="dx-auth-screen">
            <div class="dx-auth-card">
                <Card>
                    <CardHeader>
                        <CardTitle>{title}</CardTitle>
                        <CardDescription>
                            {move || {
                                if use_recovery.get() {
                                    "Enter one of your recovery codes."
                                } else {
                                    "Enter the 6-digit code from your authenticator app."
                                }
                            }}
                        </CardDescription>
                    </CardHeader>
                    <CardContent>
                        <form class="dx-auth-form" on:submit=on_submit>
                            <div class="dx-auth-field">
                                <Label html_for="dx-mfa-code" class="dx-auth-label">
                                    {move || {
                                        if use_recovery.get() {
                                            "Recovery code"
                                        } else {
                                            "Authenticator code"
                                        }
                                    }}
                                </Label>
                                <Input
                                    id="dx-mfa-code"
                                    input_type="text"
                                    autocomplete="one-time-code"
                                    placeholder="123 456"
                                    value=code
                                    on_input=Callback::new(move |v: String| code.set(v))
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
                                {move || if submitting.get() { "Verifying…" } else { "Verify" }}
                            </Button>
                            <p class="dx-auth-aux">
                                <a
                                    href="#"
                                    on:click=move |ev| {
                                        ev.prevent_default();
                                        use_recovery.update(|r| *r = !*r);
                                        code.set(String::new());
                                        error.set(String::new());
                                    }
                                >
                                    {move || {
                                        if use_recovery.get() {
                                            "Use authenticator code"
                                        } else {
                                            "Use a recovery code"
                                        }
                                    }}
                                </a>
                            </p>
                            <p class="dx-auth-aux">
                                <a
                                    href="#"
                                    on:click=move |ev| {
                                        ev.prevent_default();
                                        on_cancel.run(());
                                    }
                                >
                                    "Cancel sign in"
                                </a>
                            </p>
                        </form>
                    </CardContent>
                </Card>
            </div>
        </div>
    }
}
