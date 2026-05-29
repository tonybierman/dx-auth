use crate::friendly_server_error;
use crate::server::{admin_create_role, admin_delete_role, admin_list_roles, admin_update_role};
use crate::ui::components::button::{Button, ButtonVariant};
use crate::ui::components::card::{Card, CardContent, CardDescription, CardHeader, CardTitle};
use crate::ui::components::input::Input;
use crate::ui::components::label::Label;
use crate::ui::components::skeleton::Skeleton;
use crate::ui::components::virtual_list::VirtualList;
use crate::wire::AdminRoleDetail;
use leptos::prelude::*;
use leptos::task::spawn_local;

// Full grid is Name / Description / Tokens / Kind; phone portrait drops
// Tokens and Kind (see the portrait media query in style.css), so the
// portrait template is 2 tracks.
const ROLE_COLUMNS: &str = "--data-cols: minmax(0, 1.5fr) minmax(0, 2fr) minmax(0, 1fr) minmax(0, 0.75fr); \
     --data-cols-portrait: minmax(0, 1.5fr) minmax(0, 2fr);";

/// Role browser. Clicking a row fires `on_select(role_id)`; "New role" fires
/// `on_new(())`.
#[component]
pub fn AdminRoleList(on_select: Callback<i64>, on_new: Callback<()>) -> impl IntoView {
    let roles = Resource::new(|| (), |_| async { admin_list_roles().await });

    view! {
        <div class="admin-shell">
            <div class="admin-pager">
                <Button
                    variant=ButtonVariant::Primary
                    on_click=Callback::new(move |_| on_new.run(()))
                >
                    "+ New role"
                </Button>
            </div>
            {move || match roles.get() {
                None => {
                    view! {
                        <div class="admin-skeleton-row">
                            <Skeleton style="height: 2rem; border-radius: 0.5rem;" />
                            <Skeleton style="height: 2rem; border-radius: 0.5rem;" />
                            <Skeleton style="height: 2rem; border-radius: 0.5rem;" />
                        </div>
                    }
                        .into_any()
                }
                Some(Err(e)) => {
                    let msg = friendly_server_error(e);
                    view! { <div class="admin-error">{msg}</div> }.into_any()
                }
                Some(Ok(list)) => {
                    view! {
                        <div class="data-list" style=ROLE_COLUMNS>
                            <div class="data-header" role="row">
                                <div class="data-cell" data-label="Name">"Name"</div>
                                <div class="data-cell" data-label="Description">"Description"</div>
                                <div class="data-cell" data-label="Tokens">"Tokens"</div>
                                <div class="data-cell" data-label="Kind">"Kind"</div>
                            </div>
                            <VirtualList class="data-virtual">
                                {list
                                    .into_iter()
                                    .map(|role| view! { <AdminRoleRow role=role on_select=on_select /> })
                                    .collect_view()}
                            </VirtualList>
                        </div>
                    }
                        .into_any()
                }
            }}
        </div>
    }
}

#[component]
fn AdminRoleRow(role: AdminRoleDetail, on_select: Callback<i64>) -> impl IntoView {
    let id = role.id;
    let kind_label = if role.is_system { "system" } else { "custom" };
    let token_count = role.permissions.len();
    let description = role.description.clone().unwrap_or_default();

    view! {
        <div
            class="data-row"
            role="button"
            tabindex="0"
            on:click=move |_| on_select.run(id)
            on:keydown=move |ev: leptos::ev::KeyboardEvent| {
                let k = ev.key();
                if k == "Enter" || k == " " {
                    ev.prevent_default();
                    on_select.run(id);
                }
            }
        >
            <div class="data-cell" data-label="Name">
                <strong>{role.name}</strong>
                " "
                <small>{format!("#{id}")}</small>
            </div>
            <div class="data-cell" data-label="Description">
                {description}
            </div>
            <div class="data-cell" data-label="Tokens">
                {token_count}
            </div>
            <div class="data-cell" data-label="Kind">
                {kind_label}
            </div>
        </div>
    }
}

/// Editor for creating (`role_id = None`) or editing (`role_id = Some(id)`) a
/// role. System roles render read-only.
#[component]
pub fn AdminRoleEditor(role_id: Option<i64>, on_back: Callback<()>) -> impl IntoView {
    let roles = Resource::new(|| (), |_| async { admin_list_roles().await });

    let initialized = RwSignal::new(false);
    let name = RwSignal::new(String::new());
    let description = RwSignal::new(String::new());
    let tokens = RwSignal::new(Vec::<String>::new());
    let is_system = RwSignal::new(false);
    let not_found = RwSignal::new(false);
    let token_draft = RwSignal::new(String::new());
    let error = RwSignal::new(String::new());
    let busy = RwSignal::new(false);

    Effect::new(move |_| {
        if initialized.get_untracked() {
            return;
        }
        match role_id {
            None => initialized.set(true),
            Some(id) => {
                if let Some(result) = roles.get() {
                    match result {
                        Err(_) => initialized.set(true),
                        Ok(list) => {
                            if let Some(r) = list.iter().find(|r| r.id == id) {
                                name.set(r.name.clone());
                                description.set(r.description.clone().unwrap_or_default());
                                tokens.set(r.permissions.clone());
                                is_system.set(r.is_system);
                            } else {
                                not_found.set(true);
                            }
                            initialized.set(true);
                        }
                    }
                }
            }
        }
    });

    let title = if role_id.is_some() {
        "Edit role"
    } else {
        "New role"
    };
    let editing_id = role_id;

    let add_token = move || {
        let trimmed = token_draft.get_untracked().trim().to_string();
        if !trimmed.is_empty() && !tokens.get_untracked().contains(&trimmed) {
            tokens.update(|v| v.push(trimmed));
        }
        token_draft.set(String::new());
    };

    let save = Callback::new(move |_| {
        let name_val = name.get_untracked().trim().to_string();
        if name_val.is_empty() {
            error.set("Role name is required.".to_string());
            return;
        }
        let desc_raw = description.get_untracked().trim().to_string();
        let desc_opt = if desc_raw.is_empty() {
            None
        } else {
            Some(desc_raw)
        };
        let perms_val = tokens.get_untracked();
        error.set(String::new());
        busy.set(true);
        spawn_local(async move {
            let result = match editing_id {
                Some(rid) => admin_update_role(rid, name_val, desc_opt, perms_val).await,
                None => admin_create_role(name_val, desc_opt, perms_val)
                    .await
                    .map(|_| ()),
            };
            match result {
                Ok(()) => on_back.run(()),
                Err(e) => error.set(friendly_server_error(e)),
            }
            busy.set(false);
        });
    });

    let delete = Callback::new(move |_| {
        let Some(rid) = editing_id else {
            return;
        };
        error.set(String::new());
        busy.set(true);
        spawn_local(async move {
            match admin_delete_role(rid).await {
                Ok(()) => on_back.run(()),
                Err(e) => error.set(friendly_server_error(e)),
            }
            busy.set(false);
        });
    });

    view! {
        <div class="admin-shell">
            <Card>
                <CardHeader>
                    <CardTitle>{title}</CardTitle>
                    <CardDescription>
                        <button
                            class="admin-back"
                            type="button"
                            on:click=move |ev| {
                                ev.prevent_default();
                                on_back.run(());
                            }
                        >
                            "← Back to role list"
                        </button>
                    </CardDescription>
                </CardHeader>
                <CardContent>
                    {move || {
                        if !initialized.get() {
                            return view! {
                                <div class="admin-skeleton-row">
                                    <Skeleton style="height: 1.25rem; width: 12rem; border-radius: 0.375rem;" />
                                    <Skeleton style="height: 2.5rem; border-radius: 0.5rem;" />
                                    <Skeleton style="height: 2.5rem; border-radius: 0.5rem;" />
                                </div>
                            }
                                .into_any();
                        }
                        if not_found.get() {
                            return view! { <p class="admin-meta-row">"Role not found."</p> }
                                .into_any();
                        }
                        let readonly = is_system.get();
                        view! {
                            <Show when=move || readonly>
                                <div class="admin-info">
                                    "System roles are read-only. To customize grants, create a new role."
                                </div>
                            </Show>
                            <section class="admin-section">
                                <div class="role-field">
                                    <Label html_for="role-name" class="role-field-label">
                                        "Name"
                                    </Label>
                                    <Input
                                        id="role-name"
                                        placeholder="editor"
                                        value=name
                                        disabled=readonly
                                        on_input=Callback::new(move |v: String| name.set(v))
                                    />
                                </div>
                                <div class="role-field">
                                    <Label html_for="role-description" class="role-field-label">
                                        "Description"
                                    </Label>
                                    <Input
                                        id="role-description"
                                        placeholder="Optional"
                                        value=description
                                        disabled=readonly
                                        on_input=Callback::new(move |v: String| description.set(v))
                                    />
                                </div>
                            </section>
                            <section class="admin-section">
                                <h3 class="admin-section-heading">"Permission tokens"</h3>
                                <div class="token-chips">
                                    <Show when=move || tokens.get().is_empty()>
                                        <span class="admin-role-desc">
                                            "No tokens yet — add one below."
                                        </span>
                                    </Show>
                                    {move || {
                                        tokens
                                            .get()
                                            .into_iter()
                                            .map(|t| {
                                                let t_remove = t.clone();
                                                view! {
                                                    <span class="token-chip">
                                                        {t}
                                                        <Show when=move || !readonly>
                                                            <button
                                                                type="button"
                                                                class="token-chip-remove"
                                                                aria-label="Remove token"
                                                                on:click={
                                                                    let target = t_remove.clone();
                                                                    move |_| {
                                                                        let target = target.clone();
                                                                        tokens.update(|v| v.retain(|x| *x != target));
                                                                    }
                                                                }
                                                            >
                                                                "×"
                                                            </button>
                                                        </Show>
                                                    </span>
                                                }
                                            })
                                            .collect_view()
                                    }}
                                </div>
                                <Show when=move || !readonly>
                                    <div class="token-input-row">
                                        <Input
                                            id="role-token-input"
                                            placeholder="e.g. content:read"
                                            value=token_draft
                                            on_input=Callback::new(move |v: String| token_draft.set(v))
                                        />
                                        <Button
                                            variant=ButtonVariant::Outline
                                            on_click=Callback::new(move |_| add_token())
                                        >
                                            "Add"
                                        </Button>
                                    </div>
                                </Show>
                            </section>
                            <Show when=move || !error.get().is_empty()>
                                <div class="admin-error">{move || error.get()}</div>
                            </Show>
                            <section class="admin-section">
                                <div class="admin-meta-row">
                                    <Show when=move || !readonly>
                                        <Button
                                            variant=ButtonVariant::Primary
                                            on_click=save
                                        >
                                            {move || if busy.get() { "Saving…" } else { "Save" }}
                                        </Button>
                                    </Show>
                                    <Button
                                        variant=ButtonVariant::Outline
                                        on_click=Callback::new(move |_| on_back.run(()))
                                    >
                                        "Cancel"
                                    </Button>
                                </div>
                            </section>
                            <Show when=move || !readonly && editing_id.is_some()>
                                <section class="admin-section">
                                    <h3 class="admin-section-heading">"Danger zone"</h3>
                                    <Button variant=ButtonVariant::Destructive on_click=delete>
                                        {move || if busy.get() { "Working…" } else { "Delete role" }}
                                    </Button>
                                </section>
                            </Show>
                        }
                            .into_any()
                    }}
                </CardContent>
            </Card>
        </div>
    }
}
