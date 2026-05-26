//! Membership lifecycle composites: the last-owner guard, atomic ownership
//! transfer, grant authority checks, and the reverse enumeration query — the
//! invariants arium owns on top of an app-owned membership table.

mod common;

use arium::membership::{
    grant_membership, revoke_membership, transfer_ownership, MembershipError, MembershipStore,
};
use arium::authz::{ResourceAuthority, ResourceRef};
use arium::{ResourceRole, SqlMembershipStore};
use common::test_authority::TableAuthority;

const BOARD: &str = "board";

/// Revoking the sole `Owner` is refused with `LastOwner` — the orphan guard.
#[tokio::test]
async fn revoking_the_last_owner_is_refused() {
    let pool = common::pool().await;
    TableAuthority::create_table(&pool).await;
    let owner = common::make_user(&pool, "owner@example.invalid", "password123").await;
    TableAuthority::grant(&pool, owner, BOARD, 1, "owner").await;

    let res = revoke_membership(&TableAuthority, &pool, ResourceRef::new(BOARD, 1), owner).await;
    assert!(
        matches!(res, Err(MembershipError::LastOwner)),
        "removing the only owner must be refused, not silently orphan the board",
    );

    // And the row is still there (the transaction rolled back).
    let members = TableAuthority
        .list_members(&pool, ResourceRef::new(BOARD, 1))
        .await
        .unwrap();
    assert_eq!(members.len(), 1, "the owner must remain after a refused revoke");
}

/// With two owners, revoking one is allowed (it isn't the *last* owner).
#[tokio::test]
async fn revoking_a_non_last_owner_is_allowed() {
    let pool = common::pool().await;
    TableAuthority::create_table(&pool).await;
    let a = common::make_user(&pool, "a@example.invalid", "password123").await;
    let b = common::make_user(&pool, "b@example.invalid", "password123").await;
    TableAuthority::grant(&pool, a, BOARD, 1, "owner").await;
    TableAuthority::grant(&pool, b, BOARD, 1, "owner").await;

    revoke_membership(&TableAuthority, &pool, ResourceRef::new(BOARD, 1), a)
        .await
        .expect("a second owner can be revoked");

    let remaining = TableAuthority
        .list_members(&pool, ResourceRef::new(BOARD, 1))
        .await
        .unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].user_id, b);
}

/// Revoking a user with no membership reports `NotAMember`, not success.
#[tokio::test]
async fn revoking_a_non_member_reports_not_a_member() {
    let pool = common::pool().await;
    TableAuthority::create_table(&pool).await;
    let ghost = common::make_user(&pool, "ghost@example.invalid", "password123").await;

    let res = revoke_membership(&TableAuthority, &pool, ResourceRef::new(BOARD, 1), ghost).await;
    assert!(matches!(res, Err(MembershipError::NotAMember)));
}

/// Transfer atomically promotes the new owner and demotes the old one to Admin.
#[tokio::test]
async fn transfer_promotes_and_demotes_atomically() {
    let pool = common::pool().await;
    TableAuthority::create_table(&pool).await;
    let old = common::make_user(&pool, "old@example.invalid", "password123").await;
    let new = common::make_user(&pool, "new@example.invalid", "password123").await;
    TableAuthority::grant(&pool, old, BOARD, 1, "owner").await;
    TableAuthority::grant(&pool, new, BOARD, 1, "editor").await;

    transfer_ownership(&TableAuthority, &pool, ResourceRef::new(BOARD, 1), old, new)
        .await
        .expect("owner can transfer");

    assert_eq!(
        TableAuthority
            .role_on(&pool, new, ResourceRef::new(BOARD, 1))
            .await
            .unwrap(),
        Some(ResourceRole::Owner),
        "the new owner is promoted",
    );
    assert_eq!(
        TableAuthority
            .role_on(&pool, old, ResourceRef::new(BOARD, 1))
            .await
            .unwrap(),
        Some(ResourceRole::Admin),
        "the previous owner is demoted to Admin, never left dangling as Owner",
    );

    // The transferred-to user, now sole Owner, then cannot be revoked.
    let res = revoke_membership(&TableAuthority, &pool, ResourceRef::new(BOARD, 1), new).await;
    assert!(matches!(res, Err(MembershipError::LastOwner)));
}

/// Only an Owner can transfer; a non-owner attempt is `NotOwner`.
#[tokio::test]
async fn only_an_owner_can_transfer() {
    let pool = common::pool().await;
    TableAuthority::create_table(&pool).await;
    let admin = common::make_user(&pool, "admin@example.invalid", "password123").await;
    let other = common::make_user(&pool, "other@example.invalid", "password123").await;
    TableAuthority::grant(&pool, admin, BOARD, 1, "admin").await;
    TableAuthority::grant(&pool, other, BOARD, 1, "editor").await;

    let res =
        transfer_ownership(&TableAuthority, &pool, ResourceRef::new(BOARD, 1), admin, other).await;
    assert!(matches!(res, Err(MembershipError::NotOwner)));
}

/// An Admin may grant up to their own role but not mint an Owner; a sub-Admin
/// may not grant at all.
#[tokio::test]
async fn grant_respects_actor_authority() {
    let pool = common::pool().await;
    TableAuthority::create_table(&pool).await;
    let admin = common::make_user(&pool, "admin@example.invalid", "password123").await;
    let editor = common::make_user(&pool, "editor@example.invalid", "password123").await;
    let target = common::make_user(&pool, "target@example.invalid", "password123").await;
    TableAuthority::grant(&pool, admin, BOARD, 1, "admin").await;
    TableAuthority::grant(&pool, editor, BOARD, 1, "editor").await;

    // Admin grants Editor — allowed (Editor <= Admin).
    grant_membership(
        &TableAuthority,
        &pool,
        admin,
        ResourceRef::new(BOARD, 1),
        target,
        ResourceRole::Editor,
    )
    .await
    .expect("admin can grant a role at or below their own");
    assert_eq!(
        TableAuthority
            .role_on(&pool, target, ResourceRef::new(BOARD, 1))
            .await
            .unwrap(),
        Some(ResourceRole::Editor),
    );

    // Admin tries to grant Owner — refused (above their own role).
    let res = grant_membership(
        &TableAuthority,
        &pool,
        admin,
        ResourceRef::new(BOARD, 1),
        target,
        ResourceRole::Owner,
    )
    .await;
    assert!(
        matches!(res, Err(MembershipError::Forbidden)),
        "an Admin must not be able to mint an Owner",
    );

    // An Editor can't grant at all.
    let res = grant_membership(
        &TableAuthority,
        &pool,
        editor,
        ResourceRef::new(BOARD, 1),
        target,
        ResourceRole::Viewer,
    )
    .await;
    assert!(matches!(res, Err(MembershipError::Forbidden)));
}

/// `list_resources_for_user` returns only resources where the user meets the
/// minimum role — the reverse query a list view needs.
#[tokio::test]
async fn list_resources_for_user_filters_by_min_role() {
    let pool = common::pool().await;
    TableAuthority::create_table(&pool).await;
    let u = common::make_user(&pool, "u@example.invalid", "password123").await;
    TableAuthority::grant(&pool, u, BOARD, 1, "owner").await;
    TableAuthority::grant(&pool, u, BOARD, 2, "viewer").await;
    TableAuthority::grant(&pool, u, BOARD, 3, "editor").await;

    let viewable = TableAuthority
        .list_resources_for_user(&pool, u, BOARD, ResourceRole::Viewer)
        .await
        .unwrap();
    assert_eq!(viewable, vec![1, 2, 3], "all three are at least Viewer");

    let editable = TableAuthority
        .list_resources_for_user(&pool, u, BOARD, ResourceRole::Editor)
        .await
        .unwrap();
    assert_eq!(editable, vec![1, 3], "only Owner(1) and Editor(3) meet Editor");
}

/// The bundled `SqlMembershipStore` over `arium_resource_members` exercises the
/// migration, the `ON CONFLICT` upsert, and every composite end-to-end.
#[tokio::test]
async fn sql_membership_store_roundtrip() {
    let pool = common::pool().await;
    let a = common::make_user(&pool, "a@example.invalid", "password123").await;
    let b = common::make_user(&pool, "b@example.invalid", "password123").await;

    // The app seeds the creator as the first Owner directly (no actor has Admin
    // yet to go through `grant_membership`).
    sqlx::query(
        "INSERT INTO arium_resource_members (kind, resource_id, user_id, role) \
         VALUES ('board', 7, $1, 'owner')",
    )
    .bind(a)
    .execute(&pool)
    .await
    .unwrap();

    // Owner grants b Editor.
    grant_membership(
        &SqlMembershipStore,
        &pool,
        a,
        ResourceRef::new(BOARD, 7),
        b,
        ResourceRole::Editor,
    )
    .await
    .expect("owner can grant editor");

    let members = SqlMembershipStore
        .list_members(&pool, ResourceRef::new(BOARD, 7))
        .await
        .unwrap();
    assert_eq!(members.len(), 2);

    // Transfer to b, then b (now sole owner) can't be revoked, but a (now Admin) can.
    transfer_ownership(&SqlMembershipStore, &pool, ResourceRef::new(BOARD, 7), a, b)
        .await
        .expect("owner transfers");
    assert_eq!(
        SqlMembershipStore
            .role_on(&pool, b, ResourceRef::new(BOARD, 7))
            .await
            .unwrap(),
        Some(ResourceRole::Owner),
    );
    assert!(matches!(
        revoke_membership(&SqlMembershipStore, &pool, ResourceRef::new(BOARD, 7), b).await,
        Err(MembershipError::LastOwner),
    ));
    revoke_membership(&SqlMembershipStore, &pool, ResourceRef::new(BOARD, 7), a)
        .await
        .expect("the demoted previous owner can leave");
}
