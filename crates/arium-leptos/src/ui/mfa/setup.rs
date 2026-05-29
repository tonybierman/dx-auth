use crate::friendly_server_error;
use crate::server::{
    begin_mfa_setup, confirm_mfa_setup, disable_mfa_for_user, get_current_user_profile,
    get_mfa_status,
};
use crate::ui::components::button::{Button, ButtonVariant};
use crate::ui::components::card::{Card, CardContent, CardDescription, CardHeader, CardTitle};
use crate::ui::components::input::Input;
use crate::ui::components::label::Label;
use crate::wire::{MfaSetupView, MfaStatusView};
use leptos::prelude::*;
use leptos::task::spawn_local;

/// Drop-in MFA enrollment + management screen (mount at e.g. `/account/mfa`).
/// Branches on [`crate::server::get_mfa_status`]: Disabled offers setup,
/// Pending lets the user finish/restart, Enabled offers disabling.
#[component]
pub fn MfaSetup(
    #[prop(default = "Two-factor authentication")] title: &'static str,
    #[prop(default = "/")] back_href: &'static str,
    /// When `true`, omit the full-viewport `.dx-auth-screen`/`.dx-auth-card`
    /// centering shell and flatten the card so it renders inline (e.g. inside a
    /// console pane). Defaults to `false` for standalone-route use. Mirrors the
    /// Dioxus `MfaSetup` `embedded` prop.
    #[prop(default = false)]
    embedded: bool,
) -> impl IntoView {
    // Empty classes collapse the centering shell to plain block wrappers; the
    // flatten modifier rides on the Card (Leptos's Card takes no `style`).
    let screen_class = if embedded { "" } else { "dx-auth-screen" };
    let card_class = if embedded { "" } else { "dx-auth-card" };
    let card_flat = if embedded { "dx-card-embedded" } else { "" };
    let profile = Resource::new(|| (), |_| async { get_current_user_profile().await });
    let status = Resource::new(|| (), |_| async { get_mfa_status().await });
    let setup_info = RwSignal::new(None::<MfaSetupView>);
    let confirm_code = RwSignal::new(String::new());
    let error = RwSignal::new(String::new());
    let info_message = RwSignal::new(String::new());
    let busy = RwSignal::new(false);

    let begin = Callback::new(move |_| {
        error.set(String::new());
        info_message.set(String::new());
        busy.set(true);
        spawn_local(async move {
            match begin_mfa_setup().await {
                Ok(info) => {
                    setup_info.set(Some(info));
                    status.refetch();
                }
                Err(e) => error.set(friendly_server_error(e)),
            }
            busy.set(false);
        });
    });

    let confirm = Callback::new(move |code_val: String| {
        error.set(String::new());
        busy.set(true);
        spawn_local(async move {
            match confirm_mfa_setup(code_val).await {
                Ok(()) => {
                    info_message.set("Two-factor auth enabled.".to_string());
                    setup_info.set(None);
                    confirm_code.set(String::new());
                    status.refetch();
                }
                Err(e) => error.set(friendly_server_error(e)),
            }
            busy.set(false);
        });
    });

    let disable = Callback::new(move |_| {
        error.set(String::new());
        info_message.set(String::new());
        busy.set(true);
        spawn_local(async move {
            match disable_mfa_for_user().await {
                Ok(()) => {
                    info_message.set("Two-factor auth disabled.".to_string());
                    setup_info.set(None);
                    status.refetch();
                }
                Err(e) => error.set(friendly_server_error(e)),
            }
            busy.set(false);
        });
    });

    view! {
        {move || {
            let authed = profile
                .get()
                .and_then(|r| r.ok())
                .map(|p| p.is_authenticated)
                .unwrap_or(false);
            if !authed {
                return view! {
                    <div class=screen_class>
                        <div class=card_class>
                            <Card class=card_flat>
                                <CardHeader>
                                    <CardTitle>"Sign in required"</CardTitle>
                                </CardHeader>
                                <CardContent>
                                    <p>"You need to be signed in to manage two-factor auth."</p>
                                    <p class="dx-auth-aux">
                                        <a href=back_href>"Back to sign in"</a>
                                    </p>
                                </CardContent>
                            </Card>
                        </div>
                    </div>
                }
                    .into_any();
            }
            let status_value = status.get().and_then(|r| r.ok()).unwrap_or_default();
            let info = setup_info.get();
            view! {
                <div class=screen_class>
                    <div class=card_class>
                        <Card class=card_flat>
                            <CardHeader>
                                <CardTitle>{title}</CardTitle>
                                <CardDescription>
                                    {match status_value {
                                        MfaStatusView::Enabled => "Two-factor authentication is on.",
                                        MfaStatusView::Pending => {
                                            "Finish enrollment by entering a code from your app."
                                        }
                                        MfaStatusView::Disabled => {
                                            "Protect your account with an authenticator app."
                                        }
                                    }}
                                </CardDescription>
                            </CardHeader>
                            <CardContent>
                                <Show when=move || !info_message.get().is_empty()>
                                    <p class="dx-auth-success">{move || info_message.get()}</p>
                                </Show>
                                <Show when=move || !error.get().is_empty()>
                                    <div class="dx-auth-error" role="alert">
                                        {move || error.get()}
                                    </div>
                                </Show>
                                {match status_value {
                                    MfaStatusView::Disabled => {
                                        match info.clone() {
                                            Some(info) => {
                                                view! {
                                                    <div class="dx-auth-form">
                                                        <MfaSetupArtifacts info=info />
                                                        <MfaConfirmForm
                                                            code=confirm_code
                                                            busy=busy
                                                            on_submit=confirm
                                                        />
                                                    </div>
                                                }
                                                    .into_any()
                                            }
                                            None => {
                                                view! {
                                                    <div class="dx-auth-form">
                                                        <Button
                                                            variant=ButtonVariant::Primary
                                                            class="dx-auth-submit"
                                                            on_click=begin
                                                        >
                                                            {move || {
                                                                if busy.get() {
                                                                    "Setting up…"
                                                                } else {
                                                                    "Set up two-factor auth"
                                                                }
                                                            }}
                                                        </Button>
                                                    </div>
                                                }
                                                    .into_any()
                                            }
                                        }
                                    }
                                    MfaStatusView::Pending => {
                                        view! {
                                            <div class="dx-auth-form">
                                                {match info.clone() {
                                                    Some(info) => {
                                                        view! { <MfaSetupArtifacts info=info /> }.into_any()
                                                    }
                                                    None => {
                                                        view! {
                                                            <p>
                                                                "You started setting up two-factor auth but didn't finish. Restart enrollment to get a fresh QR code and recovery codes."
                                                            </p>
                                                            <Button
                                                                variant=ButtonVariant::Outline
                                                                class="dx-auth-submit"
                                                                on_click=begin
                                                            >
                                                                {move || {
                                                                    if busy.get() {
                                                                        "Restarting…"
                                                                    } else {
                                                                        "Restart enrollment"
                                                                    }
                                                                }}
                                                            </Button>
                                                        }
                                                            .into_any()
                                                    }
                                                }}
                                                <MfaConfirmForm
                                                    code=confirm_code
                                                    busy=busy
                                                    on_submit=confirm
                                                />
                                            </div>
                                        }
                                            .into_any()
                                    }
                                    MfaStatusView::Enabled => {
                                        view! {
                                            <div class="dx-auth-form">
                                                <p>
                                                    "Your account requires a 6-digit code on every sign-in."
                                                </p>
                                                <Button
                                                    variant=ButtonVariant::Destructive
                                                    class="dx-auth-submit"
                                                    on_click=disable
                                                >
                                                    {move || {
                                                        if busy.get() {
                                                            "Disabling…"
                                                        } else {
                                                            "Disable two-factor auth"
                                                        }
                                                    }}
                                                </Button>
                                            </div>
                                        }
                                            .into_any()
                                    }
                                }}
                                <p class="dx-auth-aux">
                                    <a href=back_href>"Back to account"</a>
                                </p>
                            </CardContent>
                        </Card>
                    </div>
                </div>
            }
                .into_any()
        }}
    }
}

#[component]
fn MfaSetupArtifacts(info: MfaSetupView) -> impl IntoView {
    let qr = format!("data:image/png;base64,{}", info.qr_png_base64);
    view! {
        <div class="dx-mfa-artifacts">
            <p>
                "Scan this QR code in your authenticator app, then enter a code below to confirm."
            </p>
            <img class="dx-mfa-qr" alt="MFA QR code" src=qr />
            <p class="dx-auth-aux">
                "Can't scan? Enter this key manually: " <code>{info.secret_base32}</code>
            </p>
            <div class="dx-mfa-recovery">
                <strong>"Recovery codes"</strong>
                <p>
                    "Save these somewhere safe — each can be used once if you lose access to your authenticator. They won't be shown again."
                </p>
                <ul class="dx-mfa-recovery-list">
                    {info
                        .recovery_codes
                        .into_iter()
                        .map(|c| view! { <li><code>{c}</code></li> })
                        .collect_view()}
                </ul>
            </div>
        </div>
    }
}

#[component]
fn MfaConfirmForm(
    code: RwSignal<String>,
    #[prop(into)] busy: Signal<bool>,
    on_submit: Callback<String>,
) -> impl IntoView {
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let val = code.get_untracked().trim().to_string();
        if val.is_empty() {
            return;
        }
        on_submit.run(val);
    };
    view! {
        <form class="dx-auth-form" on:submit=submit>
            <div class="dx-auth-field">
                <Label html_for="dx-mfa-confirm" class="dx-auth-label">
                    "Authenticator code"
                </Label>
                <Input
                    id="dx-mfa-confirm"
                    input_type="text"
                    autocomplete="one-time-code"
                    placeholder="123 456"
                    value=code
                    on_input=Callback::new(move |v: String| code.set(v))
                />
            </div>
            <Button variant=ButtonVariant::Primary button_type="submit" class="dx-auth-submit">
                {move || if busy.get() { "Confirming…" } else { "Confirm" }}
            </Button>
        </form>
    }
}
