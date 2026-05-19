use dioxus::prelude::*;

use crate::friendly_server_error;
use crate::server::admin_query_audit_events;
use crate::ui::components::button::{Button, ButtonVariant};
use crate::ui::components::card::{Card, CardContent, CardDescription, CardHeader, CardTitle};
use crate::ui::components::input::Input;
use crate::ui::components::label::Label;
use crate::wire::{AuditEventView, AuditQuery};

/// Filterable, paginated audit-log table. Requires `admin:audit:read`
/// on the signed-in user; the server fn enforces this and the table
/// renders an error message if the caller isn't allowed.
#[component]
pub fn AuditLog() -> Element {
    let mut event_type = use_signal(String::new);
    let mut actor_id = use_signal(String::new);
    let mut target_id = use_signal(String::new);
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

    let events = use_resource(move || async move {
        admin_query_audit_events(applied.read().clone()).await
    });

    let mut apply = move |_| {
        let actor = actor_id.read().parse::<i64>().ok();
        let target = target_id.read().parse::<i64>().ok();
        page.set(0);
        applied.set(AuditQuery {
            event_type: event_type.read().clone(),
            actor_id: actor,
            target_id: target,
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
                    div { class: "auth-field",
                        Label { html_for: "dx-audit-target", class: "auth-label", "Target user id" }
                        Input {
                            id: "dx-audit-target",
                            value: "{target_id}",
                            placeholder: "(any)",
                            oninput: move |evt: FormEvent| target_id.set(evt.value()),
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
    rsx! {
        table { class: "dx-admin-table dx-audit-table",
            thead {
                tr {
                    th { "When" }
                    th { "Event" }
                    th { "Actor" }
                    th { "Target" }
                    th { "IP" }
                    th { "Details" }
                }
            }
            tbody {
                for row in rows.iter() {
                    EventRow { key: "{row.id}", row: row.clone() }
                }
            }
        }
    }
}

#[component]
fn EventRow(row: AuditEventView) -> Element {
    let actor = pretty_user(row.actor_id, row.actor_email.as_deref());
    let target = pretty_user(row.target_id, row.target_email.as_deref());
    let ip = row.ip.clone().unwrap_or_else(|| "—".to_string());
    let details = row.details.clone().unwrap_or_default();
    rsx! {
        tr {
            td { "{row.occurred_at_iso}" }
            td { code { "{row.event_type}" } }
            td { "{actor}" }
            td { "{target}" }
            td { "{ip}" }
            td {
                if !details.is_empty() {
                    code { class: "dx-audit-details", "{details}" }
                } else {
                    "—"
                }
            }
        }
    }
}

fn pretty_user(id: Option<i64>, email: Option<&str>) -> String {
    match (id, email) {
        (Some(i), Some(e)) => format!("{e} (#{i})"),
        (Some(i), None) => format!("#{i}"),
        _ => "—".to_string(),
    }
}
