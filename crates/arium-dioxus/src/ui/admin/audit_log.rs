use dioxus::prelude::*;

use crate::friendly_server_error;
use crate::server::admin_query_audit_events;
use crate::ui::components::button::{Button, ButtonVariant};
use crate::ui::components::card::{Card, CardContent, CardDescription, CardHeader, CardTitle};
use crate::ui::components::input::Input;
use crate::ui::components::label::Label;
use crate::ui::components::virtual_list::VirtualList;
use crate::wire::{AuditEventView, AuditQuery};

const ADMIN_CSS: Asset = asset!("/src/ui/admin/style.css", AssetOptions::css_module());

#[css_module("/src/ui/admin/style.css")]
struct Styles;

const AUDIT_COLUMNS: &str = "--data-cols: minmax(0, 1fr) minmax(0, 1.5fr) minmax(0, 1.25fr);";

/// Filterable, paginated audit-log table. Requires `admin:audit:read`
/// on the signed-in user; the server fn enforces this and the table
/// renders an error message if the caller isn't allowed.
#[component]
pub fn AuditLog() -> Element {
    let mut event_type = use_signal(String::new);
    let mut actor_id = use_signal(String::new);
    let mut page = use_signal(|| 0i64);
    let page_size: i64 = 100;

    // Submit-side snapshot of the filters. We only re-query when the
    // user clicks Apply (or clicks Next/Prev) — typing into the input
    // doesn't fire a new request.
    let mut applied = use_signal::<AuditQuery>(|| AuditQuery {
        event_type: String::new(),
        actor_id: None,
        target_id: None,
        since: None,
        until: None,
        limit: page_size,
        offset: 0,
    });

    let events =
        use_resource(move || async move { admin_query_audit_events(applied.read().clone()).await });

    let mut apply = move |_| {
        let actor = actor_id.read().parse::<i64>().ok();
        page.set(0);
        applied.set(AuditQuery {
            event_type: event_type.read().clone(),
            actor_id: actor,
            target_id: None,
            since: None,
            until: None,
            limit: page_size,
            offset: 0,
        });
    };

    let body = match events() {
        None => rsx! { p { "Loading…" } },
        Some(Err(e)) => {
            let msg = friendly_server_error(e);
            rsx! { div { class: "auth-error", "{msg}" } }
        }
        Some(Ok(rows)) => rsx! {
            EventTable { rows: rows.clone() }
            div { class: "dx-admin-pager",
                Button {
                    variant: ButtonVariant::Ghost,
                    onclick: move |_| {
                        if page() > 0 {
                            let new_page = page() - 1;
                            page.set(new_page);
                            applied.with_mut(|q| q.offset = new_page * page_size);
                        }
                    },
                    "← Prev"
                }
                span { " Page {page() + 1} " }
                Button {
                    variant: ButtonVariant::Ghost,
                    onclick: move |_| {
                        if rows.len() as i64 == page_size {
                            let new_page = page() + 1;
                            page.set(new_page);
                            applied.with_mut(|q| q.offset = new_page * page_size);
                        }
                    },
                    "Next →"
                }
            }
        },
    };

    rsx! {
        document::Stylesheet { href: ADMIN_CSS }
        Card { class: "login-panel",
            CardHeader {
                CardTitle { "Audit log" }
                CardDescription {
                    "Sign-in / sign-out, admin actions, account self-service. "
                    "Filter by event type, actor, or target."
                }
            }
            CardContent {
                form {
                    class: "auth-form dx-audit-filters",
                    onsubmit: move |evt| {
                        evt.prevent_default();
                        apply(());
                    },
                    div { class: "auth-field",
                        Label {
                            html_for: "dx-audit-event-type",
                            class: "auth-label",
                            "Event type (use \"prefix.\" to match many)"
                        }
                        Input {
                            id: "dx-audit-event-type",
                            value: "{event_type}",
                            placeholder: "e.g. user.login. or admin.user.roles_changed",
                            oninput: move |evt: FormEvent| event_type.set(evt.value()),
                        }
                    }
                    div { class: "auth-field",
                        Label { html_for: "dx-audit-actor", class: "auth-label", "Actor user id" }
                        Input {
                            id: "dx-audit-actor",
                            value: "{actor_id}",
                            placeholder: "(any)",
                            oninput: move |evt: FormEvent| actor_id.set(evt.value()),
                        }
                    }
                    Button {
                        variant: ButtonVariant::Primary,
                        r#type: "submit",
                        class: "auth-submit",
                        "Apply filters"
                    }
                }
                {body}
            }
        }
    }
}

#[component]
fn EventTable(rows: Vec<AuditEventView>) -> Element {
    if rows.is_empty() {
        return rsx! { p { "No matching events." } };
    }
    let count = rows.len();
    let rows_signal = use_signal(|| rows);
    rsx! {
        div { class: Styles::data_list, style: AUDIT_COLUMNS,
            div {
                class: Styles::data_header,
                role: "row",
                div { "When" }
                div { "Event" }
                div { "Actor" }
            }
            VirtualList {
                count,
                estimate_size: |_idx| 56,
                class: Styles::data_virtual,
                render_item: move |idx: usize| {
                    let Some(row) = rows_signal.read().get(idx).cloned() else {
                        return rsx! { div {} };
                    };
                    rsx! { EventRow { row } }
                },
            }
        }
    }
}

#[component]
fn EventRow(row: AuditEventView) -> Element {
    let actor = row
        .actor_username
        .clone()
        .unwrap_or_else(|| "—".to_string());
    rsx! {
        div {
            class: Styles::data_row,
            role: "row",
            "data-static": "true",
            div { class: Styles::data_cell, "data-label": "When", "{row.occurred_at_iso}" }
            div { class: Styles::data_cell, "data-label": "Event", "{row.event_type}" }
            div { class: Styles::data_cell, "data-label": "Actor", "{actor}" }
        }
    }
}
