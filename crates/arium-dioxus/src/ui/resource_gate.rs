//! Per-resource UI gate: render children only when the signed-in user holds at
//! least a given [`ResourceRole`] on a specific resource.
//!
//! Unlike [`PermissionGate`](super::permissions::PermissionGate) — which checks
//! the session's flat permission-token snapshot entirely client-side — this
//! fetches the caller's role for one specific resource from the server
//! ([`get_resource_role`](crate::server::get_resource_role)). It is a
//! **cosmetic** gate for showing/hiding UI; the real security boundary is
//! [`require_resource_dioxus`](crate::server::require_resource_dioxus) on the
//! mutation server fn behind whatever the gate reveals.

use dioxus::prelude::*;

use arium_wire::ResourceRole;

use crate::server::get_resource_role;

/// Fetch the current user's [`ResourceRole`] on `(kind, id)`. Re-fetches when
/// `kind` or `id` change. Once resolved, `Ok(None)` means "no relationship".
/// The error half is Dioxus's [`CapturedError`](dioxus::CapturedError), the
/// type a server-fn call surfaces on the client (pair with
/// [`friendly_server_error`](crate::friendly_server_error) to render it).
pub fn use_resource_role(
    kind: String,
    id: i64,
) -> Resource<Result<Option<ResourceRole>, dioxus::CapturedError>> {
    use_resource(move || {
        let kind = kind.clone();
        async move { get_resource_role(kind, id).await }
    })
}

/// Render `children` only when the signed-in user holds at least `min_role` on
/// resource `(kind, id)`. Renders `fallback` (or nothing) when the role is
/// insufficient, and nothing while the role is still loading.
#[component]
pub fn ResourceGate(
    kind: String,
    id: i64,
    min_role: ResourceRole,
    fallback: Option<Element>,
    children: Element,
) -> Element {
    let role = use_resource_role(kind, id);
    let allowed = matches!(&*role.read(), Some(Ok(Some(r))) if r.at_least(min_role));
    if allowed {
        rsx! { {children} }
    } else if let Some(f) = fallback {
        rsx! { {f} }
    } else {
        rsx! {}
    }
}
