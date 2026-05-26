//! Per-resource UI gate (Leptos): render children only when the signed-in user
//! holds at least a given [`ResourceRole`] on a specific resource.
//!
//! Unlike [`PermissionGate`](super::permissions::PermissionGate) — which checks
//! the session's flat permission-token snapshot entirely client-side — this
//! fetches the caller's role for one specific resource from the server
//! ([`get_resource_role`](crate::server::get_resource_role)). It is a
//! **cosmetic** gate for showing/hiding UI; the real security boundary is
//! [`require_resource_leptos`](crate::server::require_resource_leptos) on the
//! mutation server fn behind whatever the gate reveals.

use leptos::prelude::*;

use arium_wire::ResourceRole;

use crate::server::get_resource_role;

/// Fetch the current user's [`ResourceRole`] on `(kind, id)` as a client-only
/// [`LocalResource`] (the same shape `PermissionsProvider` uses, so it renders
/// a stable loading state through hydration). Once resolved, `Ok(None)` means
/// "no relationship".
pub fn use_resource_role(
    kind: String,
    id: i64,
) -> LocalResource<Result<Option<ResourceRole>, ServerFnError>> {
    LocalResource::new(move || {
        let kind = kind.clone();
        async move { get_resource_role(kind, id).await }
    })
}

/// Render `children` only when the signed-in user holds at least `min_role` on
/// resource `(kind, id)`. Renders `fallback` (or nothing) when the role is
/// insufficient, and nothing while the role is still loading.
#[component]
pub fn ResourceGate(
    #[prop(into)] kind: String,
    id: i64,
    min_role: ResourceRole,
    #[prop(optional)] fallback: ViewFn,
    children: ChildrenFn,
) -> impl IntoView {
    let role = use_resource_role(kind, id);
    let allowed = move || matches!(role.get(), Some(Ok(Some(r))) if r.at_least(min_role));
    view! { <Show when=allowed fallback=fallback.clone()>{children()}</Show> }
}
