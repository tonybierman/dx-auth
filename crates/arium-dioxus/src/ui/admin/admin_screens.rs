use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;

use crate::friendly_server_error;
use crate::server::{
    admin_get_user, admin_list_roles, admin_list_users, admin_set_user_roles,
    admin_soft_delete_user,
};
use crate::ui::components::badge::{Badge, BadgeVariant};
use crate::ui::components::button::{Button, ButtonVariant};
use crate::ui::components::card::{Card, CardContent, CardDescription, CardHeader, CardTitle};
use crate::ui::components::checkbox::Checkbox;
use crate::ui::components::pagination::{
    Pagination, PaginationContent, PaginationItem, PaginationNext, PaginationPrevious,
};
use crate::ui::components::skeleton::Skeleton;
use crate::ui::components::virtual_list::VirtualList;
use crate::wire::AdminUserSummary;

const USER_COLUMNS: &str =
    "--data-cols: minmax(10rem, 2fr) minmax(10rem, 2fr) minmax(8rem, 1.25fr) minmax(8rem, 1.25fr);";

/// Companion stylesheet for the admin tables / detail layout. Same trick
/// the LoginPanel uses: render `document::Stylesheet` so the link tag is
/// reliably in the page even on post-hydration client-side mounts.
const ADMIN_CSS: Asset = asset!("/src/ui/admin/style.css", AssetOptions::css_module());

#[css_module("/src/ui/admin/style.css")]
struct Styles;

/// Paginated user list. Renders 100 users at a time; clicking a row fires
/// `on_select(user_id)` so the parent can navigate to a detail page.
#[component]
pub fn AdminUserList(on_select: EventHandler<i64>) -> Element {
    let mut page = use_signal(|| 0i64);
    let users = use_resource(use_reactive!(|page| async move {
        admin_list_users(100, page().saturating_mul(100)).await
    }));
    let roles = use_resource(|| async { admin_list_roles().await });
    let role_names: std::collections::HashMap<i64, String> = roles()
        .and_then(|r| r.ok())
        .map(|list| list.into_iter().map(|r| (r.id, r.name)).collect())
        .unwrap_or_default();

    let body = match users() {
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
            let last_page = list.len() < 100;
            let count = list.len();
            let rows_signal = use_signal(|| list.clone());
            rsx! {
                div { class: Styles::data_list, style: USER_COLUMNS,
                    div {
                        class: Styles::data_header,
                        role: "row",
                        div { "User" }
                        div { "Email" }
                        div { "Roles" }
                        div { "Status" }
                    }
                    VirtualList {
                        count,
                        estimate_size: |_idx| 56,
                        class: Styles::data_virtual,
                        render_item: {
                            let role_names = role_names.clone();
                            move |idx: usize| {
                                // `VirtualList` only renders idx in `0..count`,
                                // but use `.get()` so a stale snapshot can't
                                // panic during an in-flight re-render.
                                let Some(user) = rows_signal.read().get(idx).cloned() else {
                                    return rsx! { div {} };
                                };
                                let role_names = role_names.clone();
                                rsx! { AdminUserRow { user, role_names, on_select } }
                            }
                        },
                    }
                }
                div { class: Styles::admin_pager,
                    Pagination {
                        PaginationContent {
                            PaginationItem {
                                PaginationPrevious {
                                    href: "#",
                                    onclick: move |evt: MouseEvent| {
                                        evt.prevent_default();
                                        if page() > 0 { page.set(page() - 1); }
                                    },
                                }
                            }
                            PaginationItem {
                                PaginationNext {
                                    href: "#",
                                    onclick: move |evt: MouseEvent| {
                                        evt.prevent_default();
                                        if !last_page { page.set(page() + 1); }
                                    },
                                }
                            }
                        }
                    }
                }
            }
        }
    };

    rsx! {
        document::Stylesheet { href: ADMIN_CSS }
        div { class: Styles::admin_shell,
            {body}
        }
    }
}

#[component]
fn AdminUserRow(
    user: AdminUserSummary,
    role_names: std::collections::HashMap<i64, String>,
    on_select: EventHandler<i64>,
) -> Element {
    let id = user.id;
    let display = user
        .display_name
        .clone()
        .unwrap_or_else(|| user.username.clone());
    let role_labels: Vec<String> = user
        .role_ids
        .iter()
        .map(|r| {
            role_names
                .get(r)
                .cloned()
                .unwrap_or_else(|| format!("role:{r}"))
        })
        .collect();
    let (status_label, status_variant) = if user.deleted {
        ("deleted", BadgeVariant::Destructive)
    } else if user.anonymous {
        ("anonymous", BadgeVariant::Outline)
    } else if !user.email_verified {
        ("unverified", BadgeVariant::Secondary)
    } else {
        ("active", BadgeVariant::Primary)
    };

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
            div { class: Styles::data_cell, "data-label": "User",
                strong { "{display}" }
                " "
                small { "#{id}" }
            }
            div { class: Styles::data_cell, "data-label": "Email",
                "{user.email.clone().unwrap_or_default()}"
            }
            div { class: Styles::data_cell, "data-label": "Roles",
                span { class: Styles::admin_row_roles,
                    for name in role_labels.iter() {
                        Badge { key: "{name}", variant: BadgeVariant::Secondary, "{name}" }
                    }
                }
            }
            div { class: Styles::data_cell, "data-label": "Status",
                span { class: Styles::admin_row_roles,
                    Badge { variant: status_variant, "{status_label}" }
                    if user.mfa_enabled {
                        Badge { variant: BadgeVariant::Outline, "2FA" }
                    }
                }
            }
        }
    }
}

/// Single-user detail: profile fields + role toggle + soft-delete.
#[component]
pub fn AdminUserDetail(user_id: i64, on_back: EventHandler<()>) -> Element {
    let mut detail = use_resource(use_reactive!(|user_id| async move {
        admin_get_user(user_id).await
    }));
    let roles = use_resource(|| async { admin_list_roles().await });
    let mut error = use_signal(String::new);
    let mut info_msg = use_signal(String::new);
    let mut busy = use_signal(|| false);

    let body = match detail() {
        None => rsx! {
            div { class: Styles::admin_skeleton_row,
                Skeleton { style: "height: 1.25rem; width: 12rem; border-radius: 0.375rem;" }
                Skeleton { style: "height: 1rem; width: 18rem; border-radius: 0.375rem;" }
                Skeleton { style: "height: 2.5rem; border-radius: 0.5rem;" }
                Skeleton { style: "height: 2.5rem; border-radius: 0.5rem;" }
            }
        },
        Some(Err(e)) => {
            let msg = friendly_server_error(e);
            rsx! { div { class: Styles::admin_error, "{msg}" } }
        }
        Some(Ok(None)) => rsx! {
            p { class: Styles::admin_meta_row, "User not found." }
        },
        Some(Ok(Some(d))) => {
            let display = d
                .summary
                .display_name
                .clone()
                .unwrap_or_else(|| d.summary.username.clone());
            let current_roles = d.summary.role_ids.clone();
            let summary_email = d.summary.email.clone();
            let summary_deleted = d.summary.deleted;
            let summary_username = d.summary.username.clone();
            rsx! {
                section { class: Styles::admin_section,
                    h3 { class: Styles::admin_section_heading, "{display}" }
                    div { class: Styles::admin_meta_row,
                        span { "@" "{summary_username}" }
                        if let Some(e) = summary_email.as_ref() {
                            span { strong { "Email: " } "{e}" }
                        }
                        if summary_deleted {
                            Badge { variant: BadgeVariant::Destructive, "deleted" }
                        }
                    }
                }

                section { class: Styles::admin_section,
                    h3 { class: Styles::admin_section_heading, "Roles" }
                    if let Some(Ok(role_list)) = roles().as_ref() {
                        ul { class: Styles::admin_roles,
                            for r in role_list.iter() {
                                {
                                    let r_id = r.id;
                                    let is_checked = current_roles.contains(&r_id);
                                    let starting = current_roles.clone();
                                    let r_name = r.name.clone();
                                    let r_desc = r.description.clone();
                                    let state = if is_checked {
                                        CheckboxState::Checked
                                    } else {
                                        CheckboxState::Unchecked
                                    };
                                    rsx! {
                                        li {
                                            key: "{r_id}",
                                            class: Styles::admin_role_row,
                                            Checkbox {
                                                checked: Some(state),
                                                on_checked_change: move |new_state: CheckboxState| {
                                                    let now_on = bool::from(new_state);
                                                    let mut next = starting.clone();
                                                    next.retain(|x| *x != r_id);
                                                    if now_on { next.push(r_id); }
                                                    busy.set(true);
                                                    error.set(String::new());
                                                    info_msg.set(String::new());
                                                    spawn(async move {
                                                        match admin_set_user_roles(user_id, next).await {
                                                            Ok(()) => info_msg.set("Roles updated.".to_string()),
                                                            Err(e) => error.set(friendly_server_error(e)),
                                                        }
                                                        busy.set(false);
                                                        detail.restart();
                                                    });
                                                },
                                            }
                                            div { class: Styles::admin_role_text,
                                                span { class: Styles::admin_role_name, "{r_name}" }
                                                if let Some(desc) = r_desc.as_ref() {
                                                    span { class: Styles::admin_role_desc, "{desc}" }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if !info_msg().is_empty() {
                        p { class: Styles::admin_info, "{info_msg}" }
                    }
                    if !error().is_empty() {
                        div { class: Styles::admin_error, "{error}" }
                    }
                }

                if !summary_deleted {
                    section { class: Styles::admin_section,
                        h3 { class: Styles::admin_section_heading, "Danger zone" }
                        Button {
                            variant: ButtonVariant::Destructive,
                            onclick: move |_| {
                                busy.set(true);
                                error.set(String::new());
                                info_msg.set(String::new());
                                spawn(async move {
                                    match admin_soft_delete_user(user_id).await {
                                        Ok(()) => info_msg.set("User soft-deleted.".to_string()),
                                        Err(e) => error.set(friendly_server_error(e)),
                                    }
                                    busy.set(false);
                                    detail.restart();
                                });
                            },
                            if busy() { "Working…" } else { "Soft-delete user" }
                        }
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
                    CardTitle { "User detail" }
                    CardDescription {
                        button {
                            class: Styles::admin_back,
                            r#type: "button",
                            onclick: move |evt| {
                                evt.prevent_default();
                                on_back.call(());
                            },
                            "← Back to user list"
                        }
                    }
                }
                CardContent { {body} }
            }
        }
    }
}
