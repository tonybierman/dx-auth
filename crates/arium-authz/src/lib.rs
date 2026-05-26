//! Per-resource, relationship-based authorization — standalone.
//!
//! This is arium's *second authorization axis*, extracted so it can be used
//! independently of the arium auth engine. Global RBAC (flat permission tokens)
//! answers "what is this user across the whole app?"; this crate answers "what
//! is this user *with respect to this one resource?*" — the defining need of
//! collaborative apps (a board, a document, a project a user owns/edits/views).
//!
//! - `authz` — the enforcement boundary: the `ResourceRole` lattice,
//!   `ResourceAuthority` (the one trait an app implements over its own
//!   storage), and `require_resource` (fresh, per-request, default-deny).
//!   Always available.
//! - `membership` — the lifecycle layer: `MembershipStore` (a supertrait of
//!   `ResourceAuthority`) and the invariant-bearing composites
//!   `grant_membership` / `revoke_membership` / `transfer_ownership`.
//!   Behind the default-on `lifecycle` feature; turning it off drops the
//!   sqlx-transaction surface for pure-enforcement embedders.
//!
//! arium stores no resource memberships — the app owns that storage. The
//! global↔resource composition bridge (`require_resource_or_permission`) lives
//! in the `arium` engine crate, where both axes are present.

pub use arium_pool as pool;
pub use arium_wire as wire;

pub mod authz;
#[cfg(feature = "lifecycle")]
pub mod membership;

pub use authz::{
    ResourceAuthority, ResourceAuthzError, ResourceRef, SharedResourceAuthority, require_resource,
};
#[cfg(feature = "lifecycle")]
pub use membership::{
    Membership, MembershipError, MembershipStore, TxExec, grant_membership, revoke_membership,
    transfer_ownership,
};

/// The role lattice (`Viewer < Editor < Manager < Owner`), re-exported from
/// `arium-wire` at the crate root for ergonomics.
pub use arium_wire::ResourceRole;
