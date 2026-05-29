use crate::friendly_server_error;
use crate::server::{
    create_api_token, get_current_user_profile, list_api_tokens, revoke_api_token,
};
use crate::ui::components::button::{Button, ButtonVariant};
use crate::ui::components::card::{Card, CardContent, CardDescription, CardHeader, CardTitle};
use crate::ui::components::input::Input;
use crate::ui::components::label::Label;
use crate::wire::{ApiTokenView, CreateApiTokenResponse};
use leptos::prelude::*;
use leptos::task::spawn_local;

/// Drop-in API-token management screen. Lists active tokens, creates new ones
/// (the cleartext secret is shown **once**), and soft-revokes existing rows.
#[component]
pub fn ApiTokens(
    #[prop(default = "API tokens")] title: &'static str,
    #[prop(default = "/")] back_href: &'static str,
    /// When `true`, omit the full-viewport `.dx-auth-screen`/`.dx-auth-card`
    /// centering shell and flatten the card so it renders inline (e.g. inside a
    /// console pane). Defaults to `false` for standalone-route use. Mirrors the
    /// Dioxus `ApiTokens` `embedded` prop.
    #[prop(default = false)]
    embedded: bool,
) -> impl IntoView {
    // Empty classes collapse the centering shell to plain block wrappers; the
    // flatten modifier rides on the Card (Leptos's Card takes no `style`).
    let screen_class = if embedded { "" } else { "dx-auth-screen" };
    let card_class = if embedded { "" } else { "dx-auth-card" };
    let card_flat = if embedded { "dx-card-embedded" } else { "" };
    let profile = Resource::new(|| (), |_| async { get_current_user_profile().await });
    let tokens = Resource::new(|| (), |_| async { list_api_tokens().await });
    let new_name = RwSignal::new(String::new());
    let just_created = RwSignal::new(None::<CreateApiTokenResponse>);
    let error = RwSignal::new(String::new());
    let info_message = RwSignal::new(String::new());
    let busy = RwSignal::new(false);

    let create = Callback::new(move |val: String| {
        error.set(String::new());
        info_message.set(String::new());
        busy.set(true);
        spawn_local(async move {
            match create_api_token(val).await {
                Ok(resp) => just_created.set(Some(resp)),
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
                                    <p>"You need to be signed in to manage API tokens."</p>
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
            let token_list: Vec<ApiTokenView> = tokens.get().and_then(|r| r.ok()).unwrap_or_default();
            let created = just_created.get();
            view! {
                <div class=screen_class>
                    <div class=card_class>
                        <Card class=card_flat>
                            <CardHeader>
                                <CardTitle>{title}</CardTitle>
                                <CardDescription>
                                    "Personal tokens for CLI tools and programmatic clients. Treat each token like a password — anyone who has it can act as you."
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
                                {match created {
                                    Some(created) => {
                                        view! {
                                            <SecretReveal
                                                created=created
                                                on_done=Callback::new(move |_| {
                                                    just_created.set(None);
                                                    new_name.set(String::new());
                                                    tokens.refetch();
                                                })
                                            />
                                        }
                                            .into_any()
                                    }
                                    None => {
                                        view! {
                                            <CreateForm name=new_name busy=busy on_submit=create />
                                            {if token_list.is_empty() {
                                                view! {
                                                    <p class="dx-token-empty">"No active tokens yet."</p>
                                                }
                                                    .into_any()
                                            } else {
                                                view! {
                                                    <ul class="dx-token-list">
                                                        {token_list
                                                            .into_iter()
                                                            .map(|token| {
                                                                view! {
                                                                    <TokenRow
                                                                        token=token
                                                                        on_revoked=Callback::new(move |_| {
                                                                            info_message.set("Token revoked.".to_string());
                                                                            tokens.refetch();
                                                                        })
                                                                        on_error=Callback::new(move |msg: String| error.set(msg))
                                                                    />
                                                                }
                                                            })
                                                            .collect_view()}
                                                    </ul>
                                                }
                                                    .into_any()
                                            }}
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
fn CreateForm(
    name: RwSignal<String>,
    #[prop(into)] busy: Signal<bool>,
    on_submit: Callback<String>,
) -> impl IntoView {
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let val = name.get_untracked().trim().to_string();
        if val.is_empty() {
            return;
        }
        on_submit.run(val);
    };
    view! {
        <form class="dx-auth-form" on:submit=submit>
            <div class="dx-auth-field">
                <Label html_for="dx-token-name" class="dx-auth-label">
                    "New token name"
                </Label>
                <Input
                    id="dx-token-name"
                    input_type="text"
                    placeholder="ci-deploy, laptop, …"
                    value=name
                    on_input=Callback::new(move |v: String| name.set(v))
                />
            </div>
            <Button variant=ButtonVariant::Primary button_type="submit" class="dx-auth-submit">
                {move || if busy.get() { "Creating…" } else { "Create token" }}
            </Button>
        </form>
    }
}

#[component]
fn SecretReveal(created: CreateApiTokenResponse, on_done: Callback<()>) -> impl IntoView {
    view! {
        <div class="dx-token-secret-box">
            <strong>"Token created — copy it now."</strong>
            <p>
                "This is the only time the full secret is shown. Store it somewhere safe before continuing."
            </p>
            <code class="dx-token-secret-value">{created.token}</code>
            <Button
                variant=ButtonVariant::Primary
                class="dx-auth-submit"
                on_click=Callback::new(move |_| on_done.run(()))
            >
                "Done — I've saved it"
            </Button>
        </div>
    }
}

#[component]
fn TokenRow(
    token: ApiTokenView,
    on_revoked: Callback<()>,
    on_error: Callback<String>,
) -> impl IntoView {
    let confirming = RwSignal::new(false);
    let busy = RwSignal::new(false);
    let token_id = token.id;
    let last_used = token
        .last_used_at_iso
        .clone()
        .unwrap_or_else(|| "Never used".to_string());
    let meta = format!("Created {} · Last used {last_used}", token.created_at_iso);
    let prefix = format!("{}…", token.prefix);

    view! {
        <li class="dx-token-row">
            <div class="dx-token-name">{token.name}</div>
            <div class="dx-token-revoke">
                {move || {
                    if confirming.get() {
                        view! {
                            <Button
                                variant=ButtonVariant::Destructive
                                on_click=Callback::new(move |_| {
                                    busy.set(true);
                                    spawn_local(async move {
                                        match revoke_api_token(token_id).await {
                                            Ok(()) => on_revoked.run(()),
                                            Err(e) => on_error.run(friendly_server_error(e)),
                                        }
                                        busy.set(false);
                                        confirming.set(false);
                                    });
                                })
                            >
                                {move || if busy.get() { "Revoking…" } else { "Confirm revoke" }}
                            </Button>
                        }
                            .into_any()
                    } else {
                        view! {
                            <Button
                                variant=ButtonVariant::Outline
                                on_click=Callback::new(move |_| confirming.set(true))
                            >
                                "Revoke"
                            </Button>
                        }
                            .into_any()
                    }
                }}
            </div>
            <div class="dx-token-prefix">{prefix}</div>
            <div class="dx-token-meta">{meta}</div>
        </li>
    }
}
