use dioxus::prelude::*;

use crate::friendly_server_error;

async fn dismiss_after(duration: std::time::Duration) {
    #[cfg(target_arch = "wasm32")]
    gloo_timers::future::sleep(duration).await;
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = duration;
    }
}
use crate::server::{change_password, delete_my_account, get_account_view, update_display_name};
use crate::ui::components::button::{Button, ButtonVariant};
use crate::ui::components::card::{Card, CardContent, CardDescription, CardHeader, CardTitle};
use crate::ui::components::input::Input;
use crate::ui::components::label::Label;

/// Top-level account self-service panel: display name editor, password
/// change, linked accounts list, and the soft-delete section. MFA lives
/// in its own tab.
#[component]
pub fn AccountSettings() -> Element {
    let mut view = use_resource(|| async { get_account_view().await });

    let body = match view() {
        None => rsx! { p { "Loading…" } },
        Some(Err(e)) => {
            let msg = friendly_server_error(e);
            rsx! { div { class: "auth-error", "{msg}" } }
        }
        Some(Ok(v)) => {
            let display = v.display_name.clone().unwrap_or_default();
            let has_password = v.has_password;
            let providers = v.linked_oauth_providers.clone();
            rsx! {
                div { class: "auth-form",
                    h3 { "Profile" }
                    DisplayNameForm {
                        initial: display,
                        on_saved: move |_| view.restart(),
                    }

                    if has_password {
                        h3 { "Change password" }
                        ChangePasswordForm {}
                    }

                    h3 { "Linked accounts" }
                    if providers.is_empty() {
                        p { "No third-party providers linked." }
                    } else {
                        ul {
                            for p in providers.iter() {
                                li { key: "{p}", "{p}" }
                            }
                        }
                    }

                    h3 { "Danger zone" }
                    DeleteAccountSection {}
                }
            }
        }
    };

    rsx! {
        Card { class: "login-panel",
            CardHeader {
                CardTitle { "Account settings" }
                CardDescription { "Manage your profile, password, and account." }
            }
            CardContent { {body} }
        }
    }
}

#[component]
fn DisplayNameForm(initial: String, on_saved: EventHandler<()>) -> Element {
    let mut name = use_signal(|| initial);
    let mut busy = use_signal(|| false);
    let mut info_msg = use_signal(String::new);
    let mut error = use_signal(String::new);

    rsx! {
        form {
            class: "auth-form",
            onsubmit: move |evt| {
                evt.prevent_default();
                let val = name.read().clone();
                info_msg.set(String::new());
                error.set(String::new());
                busy.set(true);
                spawn(async move {
                    match update_display_name(val).await {
                        Ok(()) => {
                            info_msg.set("Saved.".to_string());
                            on_saved.call(());
                            spawn(async move {
                                dismiss_after(std::time::Duration::from_secs(3)).await;
                                info_msg.set(String::new());
                            });
                        }
                        Err(e) => error.set(friendly_server_error(e)),
                    }
                    busy.set(false);
                });
            },
            div { class: "auth-field",
                Label {
                    html_for: "dx-display-name",
                    class: "auth-label",
                    "Display name"
                }
                Input {
                    id: "dx-display-name",
                    value: "{name}",
                    oninput: move |evt: FormEvent| name.set(evt.value()),
                }
            }
            if !info_msg().is_empty() {
                p { class: "auth-success", "{info_msg}" }
            }
            if !error().is_empty() {
                div { class: "auth-error", "{error}" }
            }
            Button {
                variant: ButtonVariant::Primary,
                r#type: "submit",
                class: "auth-submit",
                if busy() { "Saving…" } else { "Save name" }
            }
        }
    }
}

#[component]
fn ChangePasswordForm() -> Element {
    let mut current = use_signal(String::new);
    let mut new_pw = use_signal(String::new);
    let mut confirm = use_signal(String::new);
    let mut error = use_signal(String::new);
    let mut info_msg = use_signal(String::new);
    let mut busy = use_signal(|| false);

    rsx! {
        form {
            class: "auth-form",
            onsubmit: move |evt| {
                evt.prevent_default();
                error.set(String::new());
                info_msg.set(String::new());
                let cur = current.read().clone();
                let new = new_pw.read().clone();
                if new != confirm.read().clone() {
                    error.set("New passwords don't match.".to_string());
                    return;
                }
                busy.set(true);
                spawn(async move {
                    match change_password(cur, new).await {
                        Ok(()) => {
                            info_msg.set("Password updated.".to_string());
                            current.set(String::new());
                            new_pw.set(String::new());
                            confirm.set(String::new());
                            spawn(async move {
                                dismiss_after(std::time::Duration::from_secs(3)).await;
                                info_msg.set(String::new());
                            });
                        }
                        Err(e) => error.set(friendly_server_error(e)),
                    }
                    busy.set(false);
                });
            },
            div { class: "auth-field",
                Label { html_for: "dx-cp-current", class: "auth-label", "Current password" }
                Input {
                    id: "dx-cp-current",
                    r#type: "password",
                    autocomplete: "current-password",
                    value: "{current}",
                    oninput: move |evt: FormEvent| current.set(evt.value()),
                }
            }
            div { class: "auth-field",
                Label { html_for: "dx-cp-new", class: "auth-label", "New password" }
                Input {
                    id: "dx-cp-new",
                    r#type: "password",
                    autocomplete: "new-password",
                    value: "{new_pw}",
                    oninput: move |evt: FormEvent| new_pw.set(evt.value()),
                }
            }
            div { class: "auth-field",
                Label { html_for: "dx-cp-confirm", class: "auth-label", "Confirm new password" }
                Input {
                    id: "dx-cp-confirm",
                    r#type: "password",
                    autocomplete: "new-password",
                    value: "{confirm}",
                    oninput: move |evt: FormEvent| confirm.set(evt.value()),
                }
            }
            if !error().is_empty() {
                div { class: "auth-error", "{error}" }
            }
            if !info_msg().is_empty() {
                p { class: "auth-success", "{info_msg}" }
            }
            Button {
                variant: ButtonVariant::Primary,
                r#type: "submit",
                class: "auth-submit",
                if busy() { "Updating…" } else { "Update password" }
            }
        }
    }
}

#[component]
fn DeleteAccountSection() -> Element {
    let mut confirm = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut error = use_signal(String::new);
    let mut done = use_signal(|| false);

    rsx! {
        div { class: "auth-form",
            p {
                "Permanently delete your account. Your personal data will be "
                "anonymised and you'll be signed out immediately. The action "
                "can't be reversed."
            }
            p {
                "Type "
                strong { "DELETE" }
                " to confirm."
            }
            Input {
                value: "{confirm}",
                oninput: move |evt: FormEvent| confirm.set(evt.value()),
            }
            if !error().is_empty() {
                div { class: "auth-error", "{error}" }
            }
            if done() {
                p { class: "auth-success", "Account deleted. Reloading…" }
            }
            Button {
                variant: ButtonVariant::Destructive,
                class: "auth-submit",
                onclick: move |_| {
                    if confirm.read().as_str() != "DELETE" {
                        error.set("Type DELETE to confirm.".to_string());
                        return;
                    }
                    error.set(String::new());
                    busy.set(true);
                    spawn(async move {
                        match delete_my_account().await {
                            Ok(()) => {
                                done.set(true);
                                let _ = document::eval("window.location.href = '/'");
                            }
                            Err(e) => error.set(friendly_server_error(e)),
                        }
                        busy.set(false);
                    });
                },
                if busy() { "Deleting…" } else { "Permanently delete my account" }
            }
        }
    }
}
