use crate::friendly_server_error;
use crate::server::admin_query_audit_events;
use crate::ui::components::button::{Button, ButtonVariant};
use crate::ui::components::card::{Card, CardContent, CardDescription, CardHeader, CardTitle};
use crate::ui::components::input::Input;
use crate::ui::components::label::Label;
use crate::ui::components::virtual_list::VirtualList;
use crate::wire::{AuditEventView, AuditQuery};
use leptos::prelude::*;

const AUDIT_COLUMNS: &str = "--data-cols: minmax(0, 1fr) minmax(0, 1.5fr) minmax(0, 1.25fr);";

/// Filterable, paginated audit-log table. Requires `admin:audit:read`; the
/// server fn enforces it and the table renders an error if the caller isn't
/// allowed.
#[component]
pub fn AuditLog() -> impl IntoView {
    let event_type = RwSignal::new(String::new());
    let actor_id = RwSignal::new(String::new());
    let page = RwSignal::new(0i64);
    let page_size: i64 = 100;

    // Submit-side snapshot of the filters; only re-queried on Apply / paging.
    let applied = RwSignal::new(AuditQuery {
        event_type: String::new(),
        actor_id: None,
        target_id: None,
        since: None,
        until: None,
        limit: page_size,
        offset: 0,
    });
    let refetch = RwSignal::new(0u32);

    let events = Resource::new(
        move || refetch.get(),
        move |_| async move { admin_query_audit_events(applied.get_untracked()).await },
    );

    let apply = move || {
        let actor = actor_id.get_untracked().trim().parse::<i64>().ok();
        page.set(0);
        applied.set(AuditQuery {
            event_type: event_type.get_untracked(),
            actor_id: actor,
            target_id: None,
            since: None,
            until: None,
            limit: page_size,
            offset: 0,
        });
        refetch.update(|n| *n = n.wrapping_add(1));
    };

    view! {
        <Card class="login-panel">
            <CardHeader>
                <CardTitle>"Audit log"</CardTitle>
                <CardDescription>
                    "Sign-in / sign-out, admin actions, account self-service. Filter by event type, actor, or target."
                </CardDescription>
            </CardHeader>
            <CardContent>
                <form
                    class="auth-form dx-audit-filters"
                    on:submit=move |ev| {
                        ev.prevent_default();
                        apply();
                    }
                >
                    <div class="auth-field">
                        <Label html_for="dx-audit-event-type" class="auth-label">
                            "Event type (use \"prefix.\" to match many)"
                        </Label>
                        <Input
                            id="dx-audit-event-type"
                            value=event_type
                            placeholder="e.g. user.login. or admin.user.roles_changed"
                            on_input=Callback::new(move |v: String| event_type.set(v))
                        />
                    </div>
                    <div class="auth-field">
                        <Label html_for="dx-audit-actor" class="auth-label">"Actor user id"</Label>
                        <Input
                            id="dx-audit-actor"
                            value=actor_id
                            placeholder="(any)"
                            on_input=Callback::new(move |v: String| actor_id.set(v))
                        />
                    </div>
                    <Button variant=ButtonVariant::Primary button_type="submit" class="auth-submit">
                        "Apply filters"
                    </Button>
                </form>
                {move || match events.get() {
                    None => view! { <p>"Loading…"</p> }.into_any(),
                    Some(Err(e)) => {
                        let msg = friendly_server_error(e);
                        view! { <div class="auth-error">{msg}</div> }.into_any()
                    }
                    Some(Ok(rows)) => {
                        let row_count = rows.len() as i64;
                        view! {
                            <EventTable rows=rows />
                            <div class="dx-admin-pager">
                                <Button
                                    variant=ButtonVariant::Ghost
                                    on_click=Callback::new(move |_| {
                                        if page.get_untracked() > 0 {
                                            let p = page.get_untracked().saturating_sub(1);
                                            page.set(p);
                                            applied.update(|q| q.offset = p.saturating_mul(page_size));
                                            refetch.update(|n| *n = n.wrapping_add(1));
                                        }
                                    })
                                >
                                    "← Prev"
                                </Button>
                                <span>{move || format!(" Page {} ", page.get().saturating_add(1))}</span>
                                <Button
                                    variant=ButtonVariant::Ghost
                                    on_click=Callback::new(move |_| {
                                        if row_count == page_size {
                                            let p = page.get_untracked().saturating_add(1);
                                            page.set(p);
                                            applied.update(|q| q.offset = p.saturating_mul(page_size));
                                            refetch.update(|n| *n = n.wrapping_add(1));
                                        }
                                    })
                                >
                                    "Next →"
                                </Button>
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
fn EventTable(rows: Vec<AuditEventView>) -> impl IntoView {
    if rows.is_empty() {
        return view! { <p>"No matching events."</p> }.into_any();
    }
    view! {
        <div class="data-list" style=AUDIT_COLUMNS>
            <div class="data-header" role="row">
                <div>"When"</div>
                <div>"Event"</div>
                <div>"Actor"</div>
            </div>
            <VirtualList class="data-virtual">
                {rows.into_iter().map(|row| view! { <EventRow row=row /> }).collect_view()}
            </VirtualList>
        </div>
    }
    .into_any()
}

#[component]
fn EventRow(row: AuditEventView) -> impl IntoView {
    let actor = row
        .actor_username
        .clone()
        .unwrap_or_else(|| "—".to_string());
    view! {
        <div class="data-row" role="row" data-static="true">
            <div class="data-cell" data-label="When">
                {row.occurred_at_iso}
            </div>
            <div class="data-cell" data-label="Event">
                {row.event_type}
            </div>
            <div class="data-cell" data-label="Actor">
                {actor}
            </div>
        </div>
    }
}
