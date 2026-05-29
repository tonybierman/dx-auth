use dioxus::prelude::*;

use crate::friendly_server_error;
use crate::server::{
    create_api_token, get_current_user_profile, list_api_tokens, revoke_api_token,
};
use crate::ui::components::button::{Button, ButtonVariant};
use crate::ui::components::card::{Card, CardContent, CardDescription, CardHeader, CardTitle};
use crate::ui::components::input::Input;
use crate::ui::components::label::Label;
use crate::wire::{ApiTokenView, CreateApiTokenResponse};

const TOKENS_CSS: Asset = asset!("/src/ui/tokens/style.css", AssetOptions::css_module());

#[css_module("/src/ui/tokens/style.css")]
struct Styles;

/// Drop-in API-token management screen. Lists the current user's active
/// tokens, lets them create a new one (the cleartext secret is shown
/// **once** in a copy-and-confirm panel and never returned again), and
/// soft-revokes existing rows.
///
/// Renders a sign-in-required card when the visitor isn't authenticated.
#[component]
pub fn ApiTokens(
    #[props(default = "API tokens")] title: &'static str,
    #[props(default = "/")] back_href: &'static str,
    /// When `true`, omit the full-viewport `.dx-auth-screen`/`.dx-auth-card`
    /// centering shell so the card renders inline (e.g. inside a tab or a
    /// console pane). Defaults to `false` for standalone-route use.
    #[props(default = false)]
    embedded: bool,
) -> Element {
    let profile = use_resource(get_current_user_profile);
    let mut tokens = use_resource(list_api_tokens);
    let mut new_name = use_signal(String::new);
    let mut just_created = use_signal::<Option<CreateApiTokenResponse>>(|| None);
    let mut error = use_signal(String::new);
    let mut info_message = use_signal(String::new);
    let mut busy = use_signal(|| false);

    // Empty classes collapse the centering shell to plain block wrappers.
    let screen_class = if embedded {
        String::new()
    } else {
        Styles::dx_auth_screen.to_string()
    };
    let card_class = if embedded {
        String::new()
    } else {
        Styles::dx_auth_card.to_string()
    };
    // Inline override beats `.dx-card` by specificity, so an embedded card
    // sits flat in its pane (no border/background/shadow) instead of as a
    // boxed panel — matching the inline `AccountSettings` look.
    let card_style = if embedded {
        "border: none; box-shadow: none; background: none;"
    } else {
        ""
    };

    let current = profile().and_then(|r| r.ok()).unwrap_or_default();

    if !current.is_authenticated {
        return rsx! {
            document::Stylesheet { href: TOKENS_CSS }
            div { class: screen_class,
                div { class: card_class,
                    Card {
                        CardHeader { CardTitle { "Sign in required" } }
                        CardContent {
                            p { "You need to be signed in to manage API tokens." }
                            p { class: Styles::dx_auth_aux,
                                a { href: "{back_href}", "Back to sign in" }
                            }
                        }
                    }
                }
            }
        };
    }

    let token_list: Vec<ApiTokenView> = tokens().and_then(|r| r.ok()).unwrap_or_default();

    rsx! {
        document::Stylesheet { href: TOKENS_CSS }
        div { class: screen_class,
            div { class: card_class,
                Card {
                    style: card_style,
                    CardHeader {
                        CardTitle { "{title}" }
                        CardDescription {
                            "Personal tokens for CLI tools and programmatic clients. \
                             Treat each token like a password — anyone who has it can act as you."
                        }
                    }
                    CardContent {
                        if !info_message().is_empty() {
                            p { class: Styles::dx_auth_success, "{info_message}" }
                        }
                        if !error().is_empty() {
                            div { class: Styles::dx_auth_error, role: "alert", "{error}" }
                        }

                        if let Some(created) = just_created() {
                            SecretReveal {
                                created,
                                on_done: move |_| {
                                    just_created.set(None);
                                    new_name.set(String::new());
                                    tokens.restart();
                                },
                            }
                        } else {
                            CreateForm {
                                name: new_name,
                                busy,
                                on_submit: move |val: String| {
                                    error.set(String::new());
                                    info_message.set(String::new());
                                    busy.set(true);
                                    spawn(async move {
                                        match create_api_token(val).await {
                                            Ok(resp) => just_created.set(Some(resp)),
                                            Err(e) => error.set(friendly_server_error(e)),
                                        }
                                        busy.set(false);
                                    });
                                },
                            }

                            if token_list.is_empty() {
                                p { class: Styles::dx_token_empty,
                                    "No active tokens yet."
                                }
                            } else {
                                ul { class: Styles::dx_token_list,
                                    for token in token_list.iter().cloned() {
                                        TokenRow {
                                            key: "{token.id}",
                                            token,
                                            on_revoked: move |_| {
                                                info_message.set("Token revoked.".to_string());
                                                tokens.restart();
                                            },
                                            on_error: move |msg: String| error.set(msg),
                                        }
                                    }
                                }
                            }
                        }

                        p { class: Styles::dx_auth_aux,
                            a { href: "{back_href}", "Back to account" }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn CreateForm(
    name: Signal<String>,
    busy: Signal<bool>,
    on_submit: EventHandler<String>,
) -> Element {
    let mut name = name;
    rsx! {
        form {
            class: Styles::dx_auth_form,
            onsubmit: move |evt| {
                evt.prevent_default();
                let val = name.read().trim().to_string();
                if val.is_empty() { return; }
                on_submit.call(val);
            },
            div { class: Styles::dx_auth_field,
                Label {
                    html_for: "dx-token-name",
                    class: Styles::dx_auth_label,
                    "New token name"
                }
                Input {
                    id: "dx-token-name",
                    r#type: "text",
                    placeholder: "ci-deploy, laptop, …",
                    value: "{name}",
                    oninput: move |evt: FormEvent| name.set(evt.value()),
                }
            }
            Button {
                variant: ButtonVariant::Primary,
                r#type: "submit",
                class: Styles::dx_auth_submit,
                if busy() { "Creating…" } else { "Create token" }
            }
        }
    }
}

#[component]
fn SecretReveal(created: CreateApiTokenResponse, on_done: EventHandler<()>) -> Element {
    rsx! {
        div { class: Styles::dx_token_secret_box,
            strong { "Token created — copy it now." }
            p {
                "This is the only time the full secret is shown. Store it somewhere \
                 safe before continuing."
            }
            code { class: Styles::dx_token_secret_value, "{created.token}" }
            Button {
                variant: ButtonVariant::Primary,
                class: Styles::dx_auth_submit,
                onclick: move |_| on_done.call(()),
                "Done — I've saved it"
            }
        }
    }
}

#[component]
fn TokenRow(
    token: ApiTokenView,
    on_revoked: EventHandler<()>,
    on_error: EventHandler<String>,
) -> Element {
    let mut confirming = use_signal(|| false);
    let mut busy = use_signal(|| false);
    let token_id = token.id;
    let last_used = token
        .last_used_at_iso
        .clone()
        .unwrap_or_else(|| "Never used".to_string());

    rsx! {
        li { class: Styles::dx_token_row,
            div { class: Styles::dx_token_name, "{token.name}" }
            div { class: Styles::dx_token_revoke,
                if confirming() {
                    Button {
                        variant: ButtonVariant::Destructive,
                        onclick: move |_| {
                            busy.set(true);
                            spawn(async move {
                                match revoke_api_token(token_id).await {
                                    Ok(()) => on_revoked.call(()),
                                    Err(e) => on_error.call(friendly_server_error(e)),
                                }
                                busy.set(false);
                                confirming.set(false);
                            });
                        },
                        if busy() { "Revoking…" } else { "Confirm revoke" }
                    }
                } else {
                    Button {
                        variant: ButtonVariant::Outline,
                        onclick: move |_| confirming.set(true),
                        "Revoke"
                    }
                }
            }
            div { class: Styles::dx_token_prefix, "{token.prefix}…" }
            div { class: Styles::dx_token_meta,
                "Created {token.created_at_iso} · Last used {last_used}"
            }
        }
    }
}
