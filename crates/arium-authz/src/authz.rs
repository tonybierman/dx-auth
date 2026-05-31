//! Per-resource, relationship-based authorization — the second axis arium's
//! global RBAC (flat permission tokens) can't express.
//!
//! Global RBAC answers "what is this user across the whole app?" This module
//! answers "what is this user *with respect to this one resource?*" — the
//! defining need of collaborative apps (a board, a document, a project the
//! user owns, edits, or merely views).
//!
//! ## Two axes — which guard, when
//!
//! These are two axes of one authorization story, not two competing stories —
//! but they answer different questions, so keep them straight by vocabulary.
//! The global axis grants **permissions**: flat, app-wide capability *tokens*
//! (`"users:ban"`, `"admin-console"`), checked against the session's
//! `User.permissions` set. This module grants **roles**: an ordered *tier on
//! one resource* ([`ResourceRole`]). Both have a level people informally call
//! "admin" — they are not the same thing, and arium never lets them share a
//! name in code: an app-wide capability is a permission token
//! (`Rights::permission("...")`); a resource tier is [`ResourceRole::Manager`].
//! Say *Manager role* for "manages this one board", *permission* for "an app-wide
//! capability" — never bare "admin". (The tier was named `Admin` before this
//! collision was resolved; `"admin"` survives only as a legacy storage alias.)
//!
//! | Gating…                                              | Use                                       | Trust model                  |
//! |------------------------------------------------------|-------------------------------------------|------------------------------|
//! | An app-wide capability ("reach the admin console")   | global RBAC — `Rights::permission(tok)`   | session token snapshot       |
//! | A resource-scoped action ("edit *this* board")       | [`require_resource`]                      | fresh per-request DB lookup  |
//! | Either may authorize (global escape hatch over a resource) | `arium::require_resource_or_permission` | resource lookup, then tokens |
//! | Showing/hiding UI (never a security boundary)        | a UI gate (`ResourceGate`/`PermissionGate`) | cosmetic                   |
//!
//! The two axes are deliberately blind to each other: [`require_resource`]
//! never reads `User.permissions`, and the global path never reads resource
//! state. That keeps each boundary simple, but it means *neither answers "can
//! this user act?" alone* once an app wants a global escape hatch over resource
//! scope — so that composition lives in exactly one place,
//! `arium::require_resource_or_permission`, rather than being re-derived (and
//! left to drift) at each call site.
//!
//! ## The split: arium owns the boundary, the app owns the storage
//!
//! arium ships the *enforcement* — the [`ResourceRole`] lattice,
//! [`require_resource`], and a default-deny contract — but stores no
//! memberships itself. The app implements one method, [`ResourceAuthority::role_on`],
//! against whatever storage it owns (a `board_members` table, an ACL, a remote
//! service). arium never dictates that schema.
//!
//! ```rust,ignore
//! use arium::authz::{ResourceAuthority, ResourceRef};
//! use arium::ResourceRole;
//! use async_trait::async_trait;
//!
//! struct BoardAuthority;
//!
//! #[async_trait]
//! impl ResourceAuthority for BoardAuthority {
//!     async fn role_on(&self, db: &arium::pool::Pool, user_id: i64, r: ResourceRef<'_>)
//!         -> anyhow::Result<Option<ResourceRole>>
//!     {
//!         if r.kind != "board" { return Ok(None); }
//!         let role: Option<String> = sqlx::query_scalar(
//!             "SELECT role FROM board_members WHERE board_id = $1 AND user_id = $2",
//!         )
//!         .bind(r.id).bind(user_id)
//!         .fetch_optional(db).await?;
//!         Ok(role.map(|r| match r.as_str() {
//!             "owner" => ResourceRole::Owner,
//!             "manager" => ResourceRole::Manager,
//!             "editor" => ResourceRole::Editor,
//!             _ => ResourceRole::Viewer,
//!         }))
//!     }
//! }
//! ```
//!
//! Register the impl so server fns can reach it — either via the arium
//! builder (`AuthConfigBuilder::resource_authority`) or by layering it onto
//! the router yourself:
//!
//! ```rust,ignore
//! let authority: arium::authz::SharedResourceAuthority = std::sync::Arc::new(BoardAuthority);
//! let router = router.layer(axum::Extension(authority));
//! ```
//!
//! ## Beyond enforcement: lifecycle and enumeration
//!
//! This module answers "may this user act *now*?" For *changing* who has a role
//! (grant / revoke / transfer, with invariants like last-owner protection) and
//! for the reverse "which resources can this user see?" query, implement the
//! richer [`MembershipStore`](crate::membership::MembershipStore) (a supertrait
//! of [`ResourceAuthority`]) and call the composites in [`crate::membership`].
//! `arium::SqlMembershipStore` is a ready-made backing store for apps that
//! don't already own a memberships table.
//!
//! ## Resource hierarchy (a recipe, not a primitive)
//!
//! arium keeps [`ResourceRef`] flat: there is no built-in parent→child role
//! inheritance, because that would require arium to learn the app's schema.
//! When a child resource derives its access from a parent (a *card* inherits
//! the *board*'s membership), resolve the child to its parent first, then
//! authorize the parent:
//!
//! ```rust,ignore
//! let board_id = load_board_id_for_card(db, card_id).await?; // app's own join
//! require_resource(authority, db, user_id, ResourceRef::new("board", board_id), ResourceRole::Editor).await?;
//! ```
//!
//! ## User ids are `i64`
//!
//! This API takes `user_id: i64` throughout. If your user table's id is a
//! narrower integer (arium's own `users.id` is `i32`), cast at the call site
//! (`user.id`); ids only widen, so the conversion is lossless.

use crate::pool::Pool;
use crate::wire::ResourceRole;
use async_trait::async_trait;
use std::sync::Arc;

/// Identifies one resource instance for an authorization check. `kind` is an
/// opaque, app-chosen namespace (`"board"`, `"doc"`, ...) and `id` the row id
/// within it. Borrowed so a check on the request hot path needn't allocate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceRef<'a> {
    /// App-defined resource namespace, e.g. `"board"`.
    pub kind: &'a str,
    /// Row id of the resource within `kind`.
    pub id: i64,
}

impl<'a> ResourceRef<'a> {
    /// Construct a reference to resource `id` within namespace `kind`.
    pub fn new(kind: &'a str, id: i64) -> Self {
        Self { kind, id }
    }
}

/// App-implemented lookup of a user's role on a resource — the one method an
/// app writes to plug its own membership storage into arium's per-resource
/// enforcement. arium never stores resource memberships itself.
///
/// Return `Ok(None)` when the user has no relationship to the resource: that
/// is a hard deny, never an error. Reserve `Err` for genuine failures (the DB
/// is down, a row is malformed) — [`require_resource`] keeps the two distinct
/// so a lookup failure is never silently treated as "no access".
///
/// The trait is object-safe (stored as [`SharedResourceAuthority`]); keep it
/// that way — no generic methods, no `Self`-by-value receivers.
#[async_trait]
pub trait ResourceAuthority: Send + Sync {
    /// The role `user_id` holds on `resource`, or `None` for no relationship.
    async fn role_on(
        &self,
        db: &Pool,
        user_id: i64,
        resource: ResourceRef<'_>,
    ) -> anyhow::Result<Option<ResourceRole>>;
}

/// Cheaply-cloneable shared handle to the app's [`ResourceAuthority`]. Apps
/// register this as an `axum::Extension` (directly, or via arium's
/// `AuthConfigBuilder::resource_authority`); server fns reach it through the
/// `arium::extract::ResourceAuthorityExt` extractor.
pub type SharedResourceAuthority = Arc<dyn ResourceAuthority>;

/// Why a [`require_resource`] check did not pass.
#[derive(Debug)]
pub enum ResourceAuthzError {
    /// The user has no relationship to the resource, or holds a role below the
    /// required minimum. The expected "deny" outcome — map it to a 403 /
    /// user-facing "you don't have access" message.
    Forbidden,
    /// The authority's `role_on` returned an error (DB failure, etc.). Distinct
    /// from `Forbidden` so callers surface a 500 and never confuse an
    /// infrastructure failure with a deliberate deny.
    Lookup(anyhow::Error),
}

impl std::fmt::Display for ResourceAuthzError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResourceAuthzError::Forbidden => f.write_str("You don't have access to this resource."),
            ResourceAuthzError::Lookup(e) => write!(f, "authorization lookup failed: {e}"),
        }
    }
}

impl std::error::Error for ResourceAuthzError {}

/// Fresh, per-request authorization check for a single resource — **the**
/// security boundary for resource-scoped actions.
///
/// Calls `authority.role_on` (which hits the app's storage on *every* call —
/// no caching, and nothing to do with the session's flat permission-token
/// set), applies a structural default-deny when the user has no role, and
/// enforces the lattice: the held role must be `>= min_role`. Returns
/// `user_id` on success so call sites can reuse it as the acting id.
///
/// UI gates (`ResourceGate` in the adapters) are cosmetic; every
/// resource-scoped *mutation* server fn must call this.
///
/// It intentionally does **not** route through `axum_session_auth`'s
/// `Auth::build().requires(Rights::permission()).validate()` path: that
/// resolves the global RBAC permission set on the in-memory `User.permissions`
/// and never reads per-resource state. Composing the two axes (resource role
/// OR global permission) is `arium::require_resource_or_permission`.
pub async fn require_resource(
    authority: &dyn ResourceAuthority,
    db: &Pool,
    user_id: i64,
    resource: ResourceRef<'_>,
    min_role: ResourceRole,
) -> Result<i64, ResourceAuthzError> {
    match authority.role_on(db, user_id, resource).await {
        Ok(Some(role)) if role.at_least(min_role) => Ok(user_id),
        Ok(_) => Err(ResourceAuthzError::Forbidden),
        Err(e) => Err(ResourceAuthzError::Lookup(e)),
    }
}

// The global↔resource composition bridge (`require_resource_or_permission` +
// `ResourceGrant`) lives in the `arium` engine crate, not here: it reads the
// global RBAC permission set (`arium::auth::list_permissions_for_user`), which
// is the auth engine's concern. This crate stays free of any authn dependency.
