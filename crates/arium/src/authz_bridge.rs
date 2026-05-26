//! The one place arium's two authorization axes compose.
//!
//! Per-resource roles ([`crate::authz`], from `arium-authz`) and global RBAC
//! (flat permission tokens, from [`crate::auth`]) are deliberately blind to
//! each other. This bridge lives in the engine crate because it reads *both* —
//! the resource role via [`require_resource`] and the global token set via
//! [`crate::auth::list_permissions_for_user`]. `arium-authz` itself stays free
//! of any authn dependency.

use crate::authz::{ResourceAuthority, ResourceAuthzError, ResourceRef, require_resource};
use crate::pool::Pool;
use crate::wire::ResourceRole;

/// Which axis authorized a [`require_resource_or_permission`] call.
///
/// Worth surfacing (e.g. in an audit row): a grant via [`Self::GlobalPermission`]
/// is an app-wide capability reaching *into* resource scope — a support agent
/// editing a board they don't belong to — and usually deserves louder logging
/// than the ordinary [`Self::Resource`] path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceGrant {
    /// The user met the per-resource bar (holds a role `>= min_role`).
    Resource,
    /// Their resource role was absent or insufficient, but they hold the global
    /// permission token — the app-wide escape hatch over resource scope.
    GlobalPermission,
}

/// Authorize on **either** axis: a sufficient per-resource role, **or** a global
/// permission token. The one place the two authorization stories compose.
///
/// arium's two axes are deliberately blind to each other ([`require_resource`]
/// never reads `User.permissions`; the global RBAC path never reads resource
/// state), which keeps each boundary simple but means *neither alone* answers
/// "can this user act?" when an app wants a global escape hatch — a super-admin
/// or support role that can touch resources they don't belong to. Rather than
/// have every call site re-derive "owner OR super-admin" (where the two drift),
/// express it once here.
///
/// Order and semantics: the resource check runs first; only on
/// [`ResourceAuthzError::Forbidden`] does it fall back to the global token set
/// ([`crate::auth::list_permissions_for_user`], which unions direct and
/// role-derived tokens). Default-deny is preserved — an absent role *and* a
/// missing token is [`ResourceAuthzError::Forbidden`] — and a storage failure on
/// **either** lookup surfaces as [`ResourceAuthzError::Lookup`], never a silent
/// deny. The return value names which axis let the caller through.
pub async fn require_resource_or_permission(
    authority: &dyn ResourceAuthority,
    db: &Pool,
    user_id: i64,
    resource: ResourceRef<'_>,
    min_role: ResourceRole,
    permission: &str,
) -> Result<ResourceGrant, ResourceAuthzError> {
    match require_resource(authority, db, user_id, resource, min_role).await {
        Ok(_) => Ok(ResourceGrant::Resource),
        Err(ResourceAuthzError::Forbidden) => {
            // Resource axis said no — consult the global axis. A failure reading
            // tokens is still a Lookup error, not a silent deny.
            let perms = crate::auth::list_permissions_for_user(db, user_id)
                .await
                .map_err(ResourceAuthzError::Lookup)?;
            if perms.iter().any(|p| p == permission) {
                Ok(ResourceGrant::GlobalPermission)
            } else {
                Err(ResourceAuthzError::Forbidden)
            }
        }
        Err(e @ ResourceAuthzError::Lookup(_)) => Err(e),
    }
}

/// [`require_resource`] plus the standard audit-on-denial, driven by an
/// **already-resolved** `user_id`. The reusable kernel behind the framework
/// adapters' session guards (e.g. dioxus's `require_resource_dioxus`).
///
/// The session adapters bundle three things: resolving the caller, the
/// enforcement check, and writing a `resource.access.denied` row on refusal.
/// Only the first is framework-specific. An app that resolves the caller
/// through its *own* request context (not arium's session extractor) can't
/// reuse a guard that insists on the session — so it would re-implement the
/// audit-on-denial wrapper. This is that wrapper, with the caller resolution
/// hoisted out to a plain `user_id`.
///
/// On [`ResourceAuthzError::Forbidden`] it records a `resource.access.denied`
/// audit row — `actor_id = user_id`, details `{"kind","id","min_role"}` (the
/// canonical lowercase role via [`ResourceRole::as_str`]), stamped with
/// whatever IP/User-Agent the supplied [`AuditCtx`](crate::extract::AuditCtx)
/// carries — and then returns `Forbidden` unchanged. A [`Lookup`](ResourceAuthzError::Lookup) error passes
/// through untouched: a storage failure is never recast as a deny, and never
/// audited as one. The error is returned raw so each caller maps it to its own
/// surface (a `403`/`ServerFnError`, a `404` for an existence-hiding SSE path,
/// …). On success returns `user_id`, for reuse as the acting id.
pub async fn require_resource_audited(
    authority: &dyn ResourceAuthority,
    db: &Pool,
    audit: &crate::extract::AuditCtx,
    user_id: i64,
    resource: ResourceRef<'_>,
    min_role: ResourceRole,
) -> Result<i64, ResourceAuthzError> {
    match require_resource(authority, db, user_id, resource, min_role).await {
        Ok(id) => Ok(id),
        Err(ResourceAuthzError::Forbidden) => {
            let details = serde_json::json!({
                "kind": resource.kind,
                "id": resource.id,
                "min_role": min_role.as_str(),
            })
            .to_string();
            audit
                .record(
                    db,
                    crate::auth::audit::RESOURCE_ACCESS_DENIED,
                    Some(user_id),
                    None,
                    Some(&details),
                )
                .await;
            Err(ResourceAuthzError::Forbidden)
        }
        Err(e @ ResourceAuthzError::Lookup(_)) => Err(e),
    }
}
