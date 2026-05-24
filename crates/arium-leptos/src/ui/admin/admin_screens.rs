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
use leptos::prelude::*;
use leptos::task::spawn_local;
use std::collections::HashMap;

const USER_COLUMNS: &str =
    "--data-cols: minmax(10rem, 2fr) minmax(10rem, 2fr) minmax(8rem, 1.25fr) minmax(8rem, 1.25fr);";

/// Paginated user list. Renders 100 users at a time; clicking a row fires
/// `on_select(user_id)`.
#[component]
pub fn AdminUserList(on_select: Callback<i64>) -> impl IntoView {
    let page = RwSignal::new(0i64);
    let users = Resource::new(
        move || page.get(),
        |p| async move { admin_list_users(100, p.saturating_mul(100)).await },
    );
    let roles = Resource::new(|| (), |_| async { admin_list_roles().await });

    view! {
        <div class="admin-shell">
            {move || match users.get() {
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
                    let last_page = list.len() < 100;
                    let role_names: HashMap<i64, String> = roles
                        .get()
                        .and_then(|r| r.ok())
                        .map(|l| l.into_iter().map(|r| (r.id, r.name)).collect())
                        .unwrap_or_default();
                    view! {
                        <div class="data-list" style=USER_COLUMNS>
                            <div class="data-header" role="row">
                                <div>"User"</div>
                                <div>"Email"</div>
                                <div>"Roles"</div>
                                <div>"Status"</div>
                            </div>
                            <VirtualList class="data-virtual">
                                {list
                                    .into_iter()
                                    .map(|user| {
                                        view! {
                                            <AdminUserRow
                                                user=user
                                                role_names=role_names.clone()
                                                on_select=on_select
                                            />
                                        }
                                    })
                                    .collect_view()}
                            </VirtualList>
                        </div>
                        <div class="admin-pager">
                            <Pagination>
                                <PaginationContent>
                                    <PaginationItem>
                                        <PaginationPrevious on_click=Callback::new(move |_| {
                                            if page.get_untracked() > 0 {
                                                page.set(page.get_untracked() - 1);
                                            }
                                        }) />
                                    </PaginationItem>
                                    <PaginationItem>
                                        <PaginationNext on_click=Callback::new(move |_| {
                                            if !last_page {
                                                page.set(page.get_untracked() + 1);
                                            }
                                        }) />
                                    </PaginationItem>
                                </PaginationContent>
                            </Pagination>
                        </div>
                    }
                        .into_any()
                }
            }}
        </div>
    }
}

#[component]
fn AdminUserRow(
    user: AdminUserSummary,
    role_names: HashMap<i64, String>,
    on_select: Callback<i64>,
) -> impl IntoView {
    let id = user.id;
    let display = user
        .display_name
        .clone()
        .unwrap_or_else(|| user.username.clone());
    let role_labels: Vec<String> = user
        .role_ids
        .iter()
        .map(|r| role_names.get(r).cloned().unwrap_or_else(|| format!("role:{r}")))
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
    let email = user.email.clone().unwrap_or_default();
    let mfa = user.mfa_enabled;

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
            <div class="data-cell" data-label="User">
                <strong>{display}</strong>
                " "
                <small>{format!("#{id}")}</small>
            </div>
            <div class="data-cell" data-label="Email">
                {email}
            </div>
            <div class="data-cell" data-label="Roles">
                <span class="admin-row-roles">
                    {role_labels
                        .into_iter()
                        .map(|name| view! { <Badge variant=BadgeVariant::Secondary>{name}</Badge> })
                        .collect_view()}
                </span>
            </div>
            <div class="data-cell" data-label="Status">
                <span class="admin-row-roles">
                    <Badge variant=status_variant>{status_label}</Badge>
                    <Show when=move || mfa>
                        <Badge variant=BadgeVariant::Outline>"2FA"</Badge>
                    </Show>
                </span>
            </div>
        </div>
    }
}

/// Single-user detail: profile fields + role toggle + soft-delete.
#[component]
pub fn AdminUserDetail(user_id: i64, on_back: Callback<()>) -> impl IntoView {
    let detail = Resource::new(
        move || user_id,
        |id| async move { admin_get_user(id).await },
    );
    let roles = Resource::new(|| (), |_| async { admin_list_roles().await });
    let error = RwSignal::new(String::new());
    let info_msg = RwSignal::new(String::new());
    let busy = RwSignal::new(false);

    view! {
        <div class="admin-shell">
            <Card>
                <CardHeader>
                    <CardTitle>"User detail"</CardTitle>
                    <CardDescription>
                        <button
                            class="admin-back"
                            type="button"
                            on:click=move |ev| {
                                ev.prevent_default();
                                on_back.run(());
                            }
                        >
                            "← Back to user list"
                        </button>
                    </CardDescription>
                </CardHeader>
                <CardContent>
                    {move || match detail.get() {
                        None => {
                            view! {
                                <div class="admin-skeleton-row">
                                    <Skeleton style="height: 1.25rem; width: 12rem; border-radius: 0.375rem;" />
                                    <Skeleton style="height: 1rem; width: 18rem; border-radius: 0.375rem;" />
                                    <Skeleton style="height: 2.5rem; border-radius: 0.5rem;" />
                                </div>
                            }
                                .into_any()
                        }
                        Some(Err(e)) => {
                            let msg = friendly_server_error(e);
                            view! { <div class="admin-error">{msg}</div> }.into_any()
                        }
                        Some(Ok(None)) => {
                            view! { <p class="admin-meta-row">"User not found."</p> }.into_any()
                        }
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
                            let role_list = roles.get().and_then(|r| r.ok()).unwrap_or_default();
                            view! {
                                <section class="admin-section">
                                    <h3 class="admin-section-heading">{display}</h3>
                                    <div class="admin-meta-row">
                                        <span>{format!("@{summary_username}")}</span>
                                        {summary_email
                                            .map(|e| {
                                                view! {
                                                    <span>
                                                        <strong>"Email: "</strong>
                                                        {e}
                                                    </span>
                                                }
                                            })}
                                        <Show when=move || summary_deleted>
                                            <Badge variant=BadgeVariant::Destructive>"deleted"</Badge>
                                        </Show>
                                    </div>
                                </section>
                                <section class="admin-section">
                                    <h3 class="admin-section-heading">"Roles"</h3>
                                    <ul class="admin-roles">
                                        {role_list
                                            .into_iter()
                                            .map(|r| {
                                                let r_id = r.id;
                                                let is_checked = current_roles.contains(&r_id);
                                                let starting = current_roles.clone();
                                                let r_desc = r.description.clone();
                                                view! {
                                                    <li class="admin-role-row">
                                                        <Checkbox
                                                            checked=is_checked
                                                            on_checked_change=Callback::new(move |now_on: bool| {
                                                                let mut next = starting.clone();
                                                                next.retain(|x| *x != r_id);
                                                                if now_on {
                                                                    next.push(r_id);
                                                                }
                                                                busy.set(true);
                                                                error.set(String::new());
                                                                info_msg.set(String::new());
                                                                spawn_local(async move {
                                                                    match admin_set_user_roles(user_id, next).await {
                                                                        Ok(()) => info_msg.set("Roles updated.".to_string()),
                                                                        Err(e) => error.set(friendly_server_error(e)),
                                                                    }
                                                                    busy.set(false);
                                                                    detail.refetch();
                                                                });
                                                            })
                                                        />
                                                        <div class="admin-role-text">
                                                            <span class="admin-role-name">{r.name}</span>
                                                            {r_desc
                                                                .map(|desc| {
                                                                    view! { <span class="admin-role-desc">{desc}</span> }
                                                                })}
                                                        </div>
                                                    </li>
                                                }
                                            })
                                            .collect_view()}
                                    </ul>
                                    <Show when=move || !info_msg.get().is_empty()>
                                        <p class="admin-info">{move || info_msg.get()}</p>
                                    </Show>
                                    <Show when=move || !error.get().is_empty()>
                                        <div class="admin-error">{move || error.get()}</div>
                                    </Show>
                                </section>
                                <Show when=move || !summary_deleted>
                                    <section class="admin-section">
                                        <h3 class="admin-section-heading">"Danger zone"</h3>
                                        <Button
                                            variant=ButtonVariant::Destructive
                                            on_click=Callback::new(move |_| {
                                                busy.set(true);
                                                error.set(String::new());
                                                info_msg.set(String::new());
                                                spawn_local(async move {
                                                    match admin_soft_delete_user(user_id).await {
                                                        Ok(()) => info_msg.set("User soft-deleted.".to_string()),
                                                        Err(e) => error.set(friendly_server_error(e)),
                                                    }
                                                    busy.set(false);
                                                    detail.refetch();
                                                });
                                            })
                                        >
                                            {move || if busy.get() { "Working…" } else { "Soft-delete user" }}
                                        </Button>
                                    </section>
                                </Show>
                            }
                                .into_any()
                        }
                    }}
                </CardContent>
            </Card>
        </div>
    }
}
