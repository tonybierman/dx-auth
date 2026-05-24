use crate::friendly_server_error;
use crate::server::{change_password, delete_my_account, get_account_view, update_display_name};
use crate::ui::components::button::{Button, ButtonVariant};
use crate::ui::components::card::{Card, CardContent, CardDescription, CardHeader, CardTitle};
use crate::ui::components::input::Input;
use crate::ui::components::label::Label;
use leptos::prelude::*;
use leptos::task::spawn_local;
use std::time::Duration;

/// Clear `signal` to an empty string after 3s (client-side only; `set_timeout`
/// is a no-op on the server).
fn clear_after(signal: RwSignal<String>) {
    set_timeout(move || signal.set(String::new()), Duration::from_secs(3));
}

/// Top-level account self-service panel: display name editor, password change,
/// linked accounts list, and the soft-delete section. MFA lives in its own tab.
#[component]
pub fn AccountSettings() -> impl IntoView {
    let view_res = Resource::new(|| (), |_| async { get_account_view().await });

    view! {
        <Card class="login-panel">
            <CardHeader>
                <CardTitle>"Account settings"</CardTitle>
                <CardDescription>"Manage your profile, password, and account."</CardDescription>
            </CardHeader>
            <CardContent>
                {move || match view_res.get() {
                    None => view! { <p>"Loading…"</p> }.into_any(),
                    Some(Err(e)) => {
                        let msg = friendly_server_error(e);
                        view! { <div class="auth-error">{msg}</div> }.into_any()
                    }
                    Some(Ok(v)) => {
                        let display = v.display_name.clone().unwrap_or_default();
                        let has_password = v.has_password;
                        let providers = v.linked_oauth_providers.clone();
                        view! {
                            <div class="auth-form">
                                <h3>"Profile"</h3>
                                <DisplayNameForm
                                    initial=display
                                    on_saved=Callback::new(move |_| view_res.refetch())
                                />
                                <Show when=move || has_password>
                                    <h3>"Change password"</h3>
                                    <ChangePasswordForm />
                                </Show>
                                <h3>"Linked accounts"</h3>
                                {if providers.is_empty() {
                                    view! { <p>"No third-party providers linked."</p> }.into_any()
                                } else {
                                    view! {
                                        <ul>
                                            {providers
                                                .clone()
                                                .into_iter()
                                                .map(|p| view! { <li>{p}</li> })
                                                .collect_view()}
                                        </ul>
                                    }
                                        .into_any()
                                }}
                                <h3>"Danger zone"</h3>
                                <DeleteAccountSection />
                            </div>
                        }
                            .into_any()
                    }
                }}
            </CardContent>
        </Card>
    }
}

#[component]
fn DisplayNameForm(initial: String, on_saved: Callback<()>) -> impl IntoView {
    let name = RwSignal::new(initial);
    let busy = RwSignal::new(false);
    let info_msg = RwSignal::new(String::new());
    let error = RwSignal::new(String::new());

    let on_submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let val = name.get_untracked();
        info_msg.set(String::new());
        error.set(String::new());
        busy.set(true);
        spawn_local(async move {
            match update_display_name(val).await {
                Ok(()) => {
                    info_msg.set("Saved.".to_string());
                    on_saved.run(());
                    clear_after(info_msg);
                }
                Err(e) => error.set(friendly_server_error(e)),
            }
            busy.set(false);
        });
    };

    view! {
        <form class="auth-form" on:submit=on_submit>
            <div class="auth-field">
                <Label html_for="dx-display-name" class="auth-label">
                    "Display name"
                </Label>
                <Input
                    id="dx-display-name"
                    value=name
                    on_input=Callback::new(move |v: String| name.set(v))
                />
            </div>
            <Show when=move || !info_msg.get().is_empty()>
                <p class="auth-success">{move || info_msg.get()}</p>
            </Show>
            <Show when=move || !error.get().is_empty()>
                <div class="auth-error">{move || error.get()}</div>
            </Show>
            <Button variant=ButtonVariant::Primary button_type="submit" class="auth-submit">
                {move || if busy.get() { "Saving…" } else { "Save name" }}
            </Button>
        </form>
    }
}

#[component]
fn ChangePasswordForm() -> impl IntoView {
    let current = RwSignal::new(String::new());
    let new_pw = RwSignal::new(String::new());
    let confirm = RwSignal::new(String::new());
    let error = RwSignal::new(String::new());
    let info_msg = RwSignal::new(String::new());
    let busy = RwSignal::new(false);

    let on_submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        error.set(String::new());
        info_msg.set(String::new());
        let cur = current.get_untracked();
        let new = new_pw.get_untracked();
        if new != confirm.get_untracked() {
            error.set("New passwords don't match.".to_string());
            return;
        }
        busy.set(true);
        spawn_local(async move {
            match change_password(cur, new).await {
                Ok(()) => {
                    info_msg.set("Password updated.".to_string());
                    current.set(String::new());
                    new_pw.set(String::new());
                    confirm.set(String::new());
                    clear_after(info_msg);
                }
                Err(e) => error.set(friendly_server_error(e)),
            }
            busy.set(false);
        });
    };

    view! {
        <form class="auth-form" on:submit=on_submit>
            <div class="auth-field">
                <Label html_for="dx-cp-current" class="auth-label">
                    "Current password"
                </Label>
                <Input
                    id="dx-cp-current"
                    input_type="password"
                    autocomplete="current-password"
                    value=current
                    on_input=Callback::new(move |v: String| current.set(v))
                />
            </div>
            <div class="auth-field">
                <Label html_for="dx-cp-new" class="auth-label">
                    "New password"
                </Label>
                <Input
                    id="dx-cp-new"
                    input_type="password"
                    autocomplete="new-password"
                    value=new_pw
                    on_input=Callback::new(move |v: String| new_pw.set(v))
                />
            </div>
            <div class="auth-field">
                <Label html_for="dx-cp-confirm" class="auth-label">
                    "Confirm new password"
                </Label>
                <Input
                    id="dx-cp-confirm"
                    input_type="password"
                    autocomplete="new-password"
                    value=confirm
                    on_input=Callback::new(move |v: String| confirm.set(v))
                />
            </div>
            <Show when=move || !error.get().is_empty()>
                <div class="auth-error">{move || error.get()}</div>
            </Show>
            <Show when=move || !info_msg.get().is_empty()>
                <p class="auth-success">{move || info_msg.get()}</p>
            </Show>
            <Button variant=ButtonVariant::Primary button_type="submit" class="auth-submit">
                {move || if busy.get() { "Updating…" } else { "Update password" }}
            </Button>
        </form>
    }
}

#[component]
fn DeleteAccountSection() -> impl IntoView {
    let confirm = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    let error = RwSignal::new(String::new());
    let done = RwSignal::new(false);
    let navigate = leptos_router::hooks::use_navigate();

    let on_click = Callback::new(move |_| {
        if confirm.get_untracked() != "DELETE" {
            error.set("Type DELETE to confirm.".to_string());
            return;
        }
        error.set(String::new());
        busy.set(true);
        let navigate = navigate.clone();
        spawn_local(async move {
            match delete_my_account().await {
                Ok(()) => {
                    done.set(true);
                    navigate("/", Default::default());
                }
                Err(e) => error.set(friendly_server_error(e)),
            }
            busy.set(false);
        });
    });

    view! {
        <div class="auth-form">
            <p>
                "Permanently delete your account. Your personal data will be anonymised and you'll be signed out immediately. The action can't be reversed."
            </p>
            <p>"Type " <strong>"DELETE"</strong> " to confirm."</p>
            <Input value=confirm on_input=Callback::new(move |v: String| confirm.set(v)) />
            <Show when=move || !error.get().is_empty()>
                <div class="auth-error">{move || error.get()}</div>
            </Show>
            <Show when=move || done.get()>
                <p class="auth-success">"Account deleted. Reloading…"</p>
            </Show>
            <Button variant=ButtonVariant::Destructive class="auth-submit" on_click=on_click>
                {move || if busy.get() { "Deleting…" } else { "Permanently delete my account" }}
            </Button>
        </div>
    }
}
