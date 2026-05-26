//! Membership lifecycle and enumeration — the management layer above
//! [`authz`](crate::authz)'s per-request enforcement.
//!
//! [`require_resource`](crate::authz::require_resource) answers "may this user
//! do this *now*?" but says nothing about *changing* who has a role, or listing
//! who does. That half — grant, revoke, transfer, "which resources can this
//! user see?" — is where apps reinvent subtly-wrong code (the classic bug: a
//! sole owner leaves and orphans the resource). This module owns the
//! **invariants** while the app still owns the **storage**.
//!
//! ## The contract
//!
//! An app implements [`MembershipStore`] — a supertrait of
//! [`ResourceAuthority`], so the same type powers both the enforcement gate
//! (`role_on`) and lifecycle. The app supplies storage-shaped *primitives*
//! (read a role, count holders, upsert, remove, enumerate); arium supplies the
//! *composites* that sequence them safely:
//!
//! - [`grant_membership`] — actor must hold ≥ `Admin` and cannot grant a role
//!   above their own.
//! - [`revoke_membership`] — refuses to remove the **sole `Owner`**
//!   ([`MembershipError::LastOwner`]); this is the orphan-resource guard.
//! - [`transfer_ownership`] — atomically promotes the new owner and demotes the
//!   old one, so there is never a window with two owners or none.
//!
//! ## Why a transaction handle ([`TxExec`])
//!
//! The composites must be atomic (count-then-delete, demote-then-promote), but
//! the app owns the table — so arium opens the transaction and threads it into
//! the write primitives as [`TxExec`]. The invariant check (e.g. the owner
//! count) therefore runs *inside the same transaction* as the write, leaving no
//! race. `TxExec` derefs to the backend connection, so an impl runs queries
//! with the familiar `.execute(&mut **tx)`. This is the one place the store
//! API is sqlx-specific; the read/enumeration half stays on `&Pool`.
//!
//! ## Bundled vs. app-owned storage
//!
//! [`SqlMembershipStore`](crate::SqlMembershipStore) is a ready-made
//! implementation over an arium-owned table for greenfield apps. An app with
//! its own table (e.g. dx_standup's `board_members`) implements
//! [`MembershipStore`] directly — same trait, no schema dictated.

use crate::authz::{ResourceAuthority, ResourceRef};
use crate::pool::{DbBackend, DbConnection, Pool};
use crate::wire::ResourceRole;
use async_trait::async_trait;

/// A live transaction handle arium opens and threads into [`MembershipStore`]
/// write primitives so a composite's steps commit or roll back together.
///
/// Derefs to the backend [`DbConnection`], so impls use it as an sqlx executor:
/// for a `tx: &mut TxExec<'_>` parameter, run queries with `&mut **tx`
/// (e.g. `sqlx::query(..).execute(&mut **tx).await?`).
pub struct TxExec<'a>(&'a mut sqlx::Transaction<'static, DbBackend>);

impl<'a> TxExec<'a> {
    /// Wrap a transaction arium has begun. Constructed by the composites in
    /// this module; apps receive it as a parameter rather than build it.
    pub(crate) fn new(tx: &'a mut sqlx::Transaction<'static, DbBackend>) -> Self {
        Self(tx)
    }
}

impl std::ops::Deref for TxExec<'_> {
    type Target = DbConnection;
    fn deref(&self) -> &DbConnection {
        self.0
    }
}

impl std::ops::DerefMut for TxExec<'_> {
    fn deref_mut(&mut self) -> &mut DbConnection {
        self.0
    }
}

/// One user's role on a resource, as returned by [`MembershipStore::list_members`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Membership {
    /// The member's user id.
    pub user_id: i64,
    /// The role they hold on the resource.
    pub role: ResourceRole,
}

/// Storage-shaped primitives for managing and enumerating resource memberships.
///
/// Supertrait of [`ResourceAuthority`]: the same impl answers both the
/// enforcement gate (`role_on`) and lifecycle. Implement the primitives against
/// your own table; call the module-level composites ([`grant_membership`],
/// [`revoke_membership`], [`transfer_ownership`]) for the invariant-bearing
/// operations rather than sequencing the writes yourself.
///
/// Object-safe (used behind `&dyn MembershipStore`): no generic methods, no
/// by-value `Self`. The `*_tx` primitives take `&mut TxExec` so a composite can
/// drive several through one transaction.
#[async_trait]
pub trait MembershipStore: ResourceAuthority {
    /// Every member of `resource` and the role each holds.
    async fn list_members(&self, db: &Pool, resource: ResourceRef<'_>)
        -> anyhow::Result<Vec<Membership>>;

    /// Ids of every resource of `kind` on which `user_id` holds at least
    /// `min_role` — the reverse of `role_on`, for "what can this user see?"
    /// list views.
    async fn list_resources_for_user(
        &self,
        db: &Pool,
        user_id: i64,
        kind: &str,
        min_role: ResourceRole,
    ) -> anyhow::Result<Vec<i64>>;

    /// Read a user's role within an open transaction (the consistent read the
    /// composites guard on). Mirror of [`ResourceAuthority::role_on`].
    async fn role_on_tx(
        &self,
        tx: &mut TxExec<'_>,
        resource: ResourceRef<'_>,
        user_id: i64,
    ) -> anyhow::Result<Option<ResourceRole>>;

    /// Count how many users hold exactly `role` on `resource`, within the
    /// transaction — the basis of the last-owner guard.
    async fn count_holders_of_role(
        &self,
        tx: &mut TxExec<'_>,
        resource: ResourceRef<'_>,
        role: ResourceRole,
    ) -> anyhow::Result<u64>;

    /// Insert or update `user_id`'s role on `resource`.
    async fn upsert_role(
        &self,
        tx: &mut TxExec<'_>,
        resource: ResourceRef<'_>,
        user_id: i64,
        role: ResourceRole,
    ) -> anyhow::Result<()>;

    /// Remove `user_id`'s membership of `resource` (no-op if absent).
    async fn remove_role(
        &self,
        tx: &mut TxExec<'_>,
        resource: ResourceRef<'_>,
        user_id: i64,
    ) -> anyhow::Result<()>;
}

/// Why a membership composite did not complete.
#[derive(Debug)]
pub enum MembershipError {
    /// Refused: removing/demoting this user would leave the resource with no
    /// `Owner`. Transfer ownership first.
    LastOwner,
    /// The actor is not an `Owner` of the resource (required for transfer).
    NotOwner,
    /// The target user has no membership of the resource.
    NotAMember,
    /// The actor may not perform this grant — below `Admin`, or attempting to
    /// grant a role above their own.
    Forbidden,
    /// A storage operation failed (begin/commit or a primitive). Distinct from
    /// the deny variants so callers surface a 500, never a 403.
    Lookup(anyhow::Error),
}

impl std::fmt::Display for MembershipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MembershipError::LastOwner => {
                f.write_str("Can't remove the last owner — transfer ownership first.")
            }
            MembershipError::NotOwner => f.write_str("Only an owner can do this."),
            MembershipError::NotAMember => f.write_str("That user isn't a member."),
            MembershipError::Forbidden => f.write_str("You can't grant that role."),
            MembershipError::Lookup(e) => write!(f, "membership operation failed: {e}"),
        }
    }
}

impl std::error::Error for MembershipError {}

fn lookup(e: impl Into<anyhow::Error>) -> MembershipError {
    MembershipError::Lookup(e.into())
}

/// Grant `target_id` the role `role` on `resource`, acting as `actor_id`.
///
/// The actor must hold at least [`ResourceRole::Admin`] on the resource and may
/// not grant a role above their own (an `Admin` can't mint an `Owner`).
/// Idempotent: re-granting updates the existing role.
pub async fn grant_membership(
    store: &dyn MembershipStore,
    db: &Pool,
    actor_id: i64,
    resource: ResourceRef<'_>,
    target_id: i64,
    role: ResourceRole,
) -> Result<(), MembershipError> {
    let mut raw = db.begin().await.map_err(lookup)?;
    let mut tx = TxExec::new(&mut raw);

    let actor = store
        .role_on_tx(&mut tx, resource, actor_id)
        .await
        .map_err(MembershipError::Lookup)?;
    match actor {
        Some(a) if a.at_least(ResourceRole::Admin) && a >= role => {}
        _ => return Err(MembershipError::Forbidden),
    }

    store
        .upsert_role(&mut tx, resource, target_id, role)
        .await
        .map_err(MembershipError::Lookup)?;

    raw.commit().await.map_err(lookup)?;
    Ok(())
}

/// Remove `user_id`'s membership of `resource`, refusing if they are the sole
/// [`ResourceRole::Owner`] ([`MembershipError::LastOwner`]).
///
/// This is the orphan-resource guard: the owner count is read inside the same
/// transaction as the delete, so the invariant can't be raced. Use it for both
/// self-departure ("leave") and admin removal.
pub async fn revoke_membership(
    store: &dyn MembershipStore,
    db: &Pool,
    resource: ResourceRef<'_>,
    user_id: i64,
) -> Result<(), MembershipError> {
    let mut raw = db.begin().await.map_err(lookup)?;
    let mut tx = TxExec::new(&mut raw);

    let current = store
        .role_on_tx(&mut tx, resource, user_id)
        .await
        .map_err(MembershipError::Lookup)?
        .ok_or(MembershipError::NotAMember)?;

    if current == ResourceRole::Owner {
        let owners = store
            .count_holders_of_role(&mut tx, resource, ResourceRole::Owner)
            .await
            .map_err(MembershipError::Lookup)?;
        if owners <= 1 {
            return Err(MembershipError::LastOwner); // raw rolls back on drop
        }
    }

    store
        .remove_role(&mut tx, resource, user_id)
        .await
        .map_err(MembershipError::Lookup)?;

    raw.commit().await.map_err(lookup)?;
    Ok(())
}

/// Transfer ownership of `resource` from `from_id` to `to_id`: the new owner is
/// promoted to [`ResourceRole::Owner`] and the previous owner demoted to
/// [`ResourceRole::Admin`], atomically. `from_id` must currently be an `Owner`
/// ([`MembershipError::NotOwner`] otherwise).
pub async fn transfer_ownership(
    store: &dyn MembershipStore,
    db: &Pool,
    resource: ResourceRef<'_>,
    from_id: i64,
    to_id: i64,
) -> Result<(), MembershipError> {
    let mut raw = db.begin().await.map_err(lookup)?;
    let mut tx = TxExec::new(&mut raw);

    let from_role = store
        .role_on_tx(&mut tx, resource, from_id)
        .await
        .map_err(MembershipError::Lookup)?;
    if from_role != Some(ResourceRole::Owner) {
        return Err(MembershipError::NotOwner);
    }

    store
        .upsert_role(&mut tx, resource, to_id, ResourceRole::Owner)
        .await
        .map_err(MembershipError::Lookup)?;
    store
        .upsert_role(&mut tx, resource, from_id, ResourceRole::Admin)
        .await
        .map_err(MembershipError::Lookup)?;

    raw.commit().await.map_err(lookup)?;
    Ok(())
}
