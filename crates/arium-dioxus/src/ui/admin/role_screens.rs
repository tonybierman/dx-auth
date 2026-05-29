use dioxus::prelude::*;

use crate::friendly_server_error;
use crate::server::{admin_create_role, admin_delete_role, admin_list_roles, admin_update_role};
use crate::ui::components::button::{Button, ButtonVariant};
use crate::ui::components::card::{Card, CardContent, CardDescription, CardHeader, CardTitle};
use crate::ui::components::input::Input;
use crate::ui::components::label::Label;
use crate::ui::components::skeleton::Skeleton;
use crate::ui::components::virtual_list::VirtualList;
use crate::wire::AdminRoleDetail;

// Full grid is Name / Description / Tokens / Kind; phone portrait drops
// Tokens and Kind (see the portrait media query in style.css), so the
// portrait template is 2 tracks.
const ROLE_COLUMNS: &str = "--data-cols: minmax(0, 1.5fr) minmax(0, 2fr) minmax(0, 1fr) minmax(0, 0.75fr); \
     --data-cols-portrait: minmax(0, 1.5fr) minmax(0, 2fr);";

const ADMIN_CSS: Asset = asset!("/src/ui/admin/style.css", AssetOptions::css_module());

#[css_module("/src/ui/admin/style.css")]
struct Styles;

/// Role browser. Clicking a row fires `on_select(role_id)`; the "New
/// role" button fires `on_new(())`.
#[component]
pub fn AdminRoleList(on_select: EventHandler<i64>, on_new: EventHandler<()>) -> Element {
    let roles = use_resource(|| async { admin_list_roles().await });

    let body = match roles() {
        None => rsx! {
            div { class: Styles::admin_skeleton_row,
                Skeleton { style: "height: 2rem; border-radius: 0.5rem;" }
                Skeleton { style: "height: 2rem; border-radius: 0.5rem;" }
                Skeleton { style: "height: 2rem; border-radius: 0.5rem;" }
            }
        },
        Some(Err(e)) => {
            let msg = friendly_server_error(e);
            rsx! { div { class: Styles::admin_error, "{msg}" } }
        }
        Some(Ok(list)) => {
            let count = list.len();
            let rows_signal = use_signal(|| list.clone());
            rsx! {
                div { class: Styles::data_list, style: ROLE_COLUMNS,
                    div {
                        class: Styles::data_header,
                        role: "row",
                        div { class: Styles::data_cell, "data-label": "Name", "Name" }
                        div { class: Styles::data_cell, "data-label": "Description", "Description" }
                        div { class: Styles::data_cell, "data-label": "Tokens", "Tokens" }
                        div { class: Styles::data_cell, "data-label": "Kind", "Kind" }
                    }
                    VirtualList {
                        count,
                        estimate_size: |_idx| 56,
                        class: Styles::data_virtual,
                        render_item: move |idx: usize| {
                            let Some(role) = rows_signal.read().get(idx).cloned() else {
                                return rsx! { div {} };
                            };
                            rsx! { AdminRoleRow { role, on_select } }
                        },
                    }
                }
            }
        }
    };

    rsx! {
        document::Stylesheet { href: ADMIN_CSS }
        div { class: Styles::admin_shell,
            div { class: Styles::admin_pager,
                Button {
                    variant: ButtonVariant::Primary,
                    onclick: move |_| on_new.call(()),
                    "+ New role"
                }
            }
            {body}
        }
    }
}

#[component]
fn AdminRoleRow(role: AdminRoleDetail, on_select: EventHandler<i64>) -> Element {
    let id = role.id;
    let kind_label = if role.is_system { "system" } else { "custom" };
    let token_count = role.permissions.len();

    rsx! {
        div {
            class: Styles::data_row,
            role: "button",
            tabindex: "0",
            onclick: move |_| on_select.call(id),
            onkeydown: move |evt: KeyboardEvent| {
                let k = evt.key();
                if matches!(k, Key::Enter) || k.to_string() == " " {
                    evt.prevent_default();
                    on_select.call(id);
                }
            },
            div { class: Styles::data_cell, "data-label": "Name",
                strong { "{role.name}" }
                " "
                small { "#{id}" }
            }
            div { class: Styles::data_cell, "data-label": "Description",
                "{role.description.clone().unwrap_or_default()}"
            }
            div { class: Styles::data_cell, "data-label": "Tokens",
                "{token_count}"
            }
            div { class: Styles::data_cell, "data-label": "Kind", "{kind_label}" }
        }
    }
}

/// Editor for creating (`role_id = None`) or editing (`role_id = Some(id)`)
/// a role. System roles render read-only with a banner explaining why.
#[component]
pub fn AdminRoleEditor(role_id: Option<i64>, on_back: EventHandler<()>) -> Element {
    let roles = use_resource(|| async { admin_list_roles().await });

    let mut initialized = use_signal(|| false);
    let mut name = use_signal(String::new);
    let mut description = use_signal(String::new);
    let mut tokens = use_signal::<Vec<String>>(Vec::new);
    let mut is_system = use_signal(|| false);
    let mut not_found = use_signal(|| false);

    let mut token_draft = use_signal(String::new);
    let mut error = use_signal(String::new);
    let mut busy = use_signal(|| false);

    use_effect(move || {
        if initialized() {
            return;
        }
        match role_id {
            None => {
                initialized.set(true);
            }
            Some(id) => {
                if let Some(result) = roles() {
                    match result {
                        Err(_) => {
                            initialized.set(true);
                        }
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

    let body = if !initialized() {
        rsx! {
            div { class: Styles::admin_skeleton_row,
                Skeleton { style: "height: 1.25rem; width: 12rem; border-radius: 0.375rem;" }
                Skeleton { style: "height: 2.5rem; border-radius: 0.5rem;" }
                Skeleton { style: "height: 2.5rem; border-radius: 0.5rem;" }
            }
        }
    } else if not_found() {
        rsx! { p { class: Styles::admin_meta_row, "Role not found." } }
    } else {
        let readonly = is_system();
        rsx! {
            if readonly {
                div { class: Styles::admin_info,
                    "System roles are read-only. To customize grants, create a new role."
                }
            }

            section { class: Styles::admin_section,
                div { class: Styles::role_field,
                    Label { html_for: "role-name", class: Styles::role_field_label, "Name" }
                    Input {
                        id: "role-name",
                        r#type: "text",
                        placeholder: "editor",
                        value: "{name}",
                        disabled: readonly,
                        oninput: move |evt: FormEvent| name.set(evt.value()),
                    }
                }
                div { class: Styles::role_field,
                    Label { html_for: "role-description", class: Styles::role_field_label, "Description" }
                    Input {
                        id: "role-description",
                        r#type: "text",
                        placeholder: "Optional",
                        value: "{description}",
                        disabled: readonly,
                        oninput: move |evt: FormEvent| description.set(evt.value()),
                    }
                }
            }

            section { class: Styles::admin_section,
                h3 { class: Styles::admin_section_heading, "Permission tokens" }
                {
                    let current = tokens.read().clone();
                    rsx! {
                        div { class: Styles::token_chips,
                            if current.is_empty() {
                                span { class: Styles::admin_role_desc,
                                    "No tokens yet — add one below."
                                }
                            }
                            for t in current.iter() {
                                {
                                    let t = t.clone();
                                    let t_for_remove = t.clone();
                                    rsx! {
                                        span {
                                            key: "{t}",
                                            class: Styles::token_chip,
                                            "{t}"
                                            if !readonly {
                                                button {
                                                    r#type: "button",
                                                    class: Styles::token_chip_remove,
                                                    "aria-label": "Remove token",
                                                    onclick: move |_| {
                                                        let target = t_for_remove.clone();
                                                        tokens.write().retain(|x| *x != target);
                                                    },
                                                    "×"
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if !readonly {
                    div { class: Styles::token_input_row,
                        Input {
                            id: "role-token-input",
                            r#type: "text",
                            placeholder: "e.g. content:read",
                            value: "{token_draft}",
                            oninput: move |evt: FormEvent| token_draft.set(evt.value()),
                            onkeydown: move |evt: KeyboardEvent| {
                                if matches!(evt.key(), Key::Enter) {
                                    evt.prevent_default();
                                    let trimmed = token_draft.read().trim().to_string();
                                    if !trimmed.is_empty() && !tokens.read().contains(&trimmed) {
                                        tokens.write().push(trimmed);
                                    }
                                    token_draft.set(String::new());
                                }
                            },
                        }
                        Button {
                            variant: ButtonVariant::Outline,
                            onclick: move |_| {
                                let trimmed = token_draft.read().trim().to_string();
                                if !trimmed.is_empty() && !tokens.read().contains(&trimmed) {
                                    tokens.write().push(trimmed);
                                }
                                token_draft.set(String::new());
                            },
                            "Add"
                        }
                    }
                }
            }

            if !error().is_empty() {
                div { class: Styles::admin_error, "{error}" }
            }

            section { class: Styles::admin_section,
                div { class: Styles::admin_meta_row,
                    if !readonly {
                        Button {
                            variant: ButtonVariant::Primary,
                            onclick: move |_| {
                                let name_val = name.read().trim().to_string();
                                if name_val.is_empty() {
                                    error.set("Role name is required.".to_string());
                                    return;
                                }
                                let desc_raw = description.read().trim().to_string();
                                let desc_opt = if desc_raw.is_empty() { None } else { Some(desc_raw) };
                                let perms_val = tokens.read().clone();
                                error.set(String::new());
                                busy.set(true);
                                spawn(async move {
                                    let result = match editing_id {
                                        Some(rid) => {
                                            admin_update_role(rid, name_val, desc_opt, perms_val)
                                                .await
                                        }
                                        None => admin_create_role(name_val, desc_opt, perms_val)
                                            .await
                                            .map(|_| ()),
                                    };
                                    match result {
                                        Ok(()) => on_back.call(()),
                                        Err(e) => error.set(friendly_server_error(e)),
                                    }
                                    busy.set(false);
                                });
                            },
                            if busy() { "Saving…" } else { "Save" }
                        }
                    }
                    Button {
                        variant: ButtonVariant::Outline,
                        onclick: move |_| on_back.call(()),
                        "Cancel"
                    }
                }
            }

            if !readonly && editing_id.is_some() {
                section { class: Styles::admin_section,
                    h3 { class: Styles::admin_section_heading, "Danger zone" }
                    Button {
                        variant: ButtonVariant::Destructive,
                        onclick: move |_| {
                            let Some(rid) = editing_id else { return };
                            error.set(String::new());
                            busy.set(true);
                            spawn(async move {
                                match admin_delete_role(rid).await {
                                    Ok(()) => on_back.call(()),
                                    Err(e) => error.set(friendly_server_error(e)),
                                }
                                busy.set(false);
                            });
                        },
                        if busy() { "Working…" } else { "Delete role" }
                    }
                }
            }
        }
    };

    rsx! {
        document::Stylesheet { href: ADMIN_CSS }
        div { class: Styles::admin_shell,
            Card {
                CardHeader {
                    CardTitle { "{title}" }
                    CardDescription {
                        button {
                            class: Styles::admin_back,
                            r#type: "button",
                            onclick: move |evt| {
                                evt.prevent_default();
                                on_back.call(());
                            },
                            "← Back to role list"
                        }
                    }
                }
                CardContent { {body} }
            }
        }
    }
}
