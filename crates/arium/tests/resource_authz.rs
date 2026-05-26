//! Per-resource authorization: the `require_resource` enforcement boundary,
//! the role lattice, default-deny, lookup-error propagation, and freshness
//! (no caching, no dependence on the session's flat permission set).

mod common;

use arium::ResourceRole;
use arium::authz::{ResourceAuthzError, ResourceRef, require_resource};
use common::test_authority::{FailingAuthority, TableAuthority};

const BOARD: &str = "board";

#[tokio::test]
async fn no_relationship_is_forbidden() {
    let pool = common::pool().await;
    TableAuthority::create_table(&pool).await;
    let uid = common::make_user(&pool, "a@example.invalid", "password123").await;

    let res = require_resource(
        &TableAuthority,
        &pool,
        uid,
        ResourceRef::new(BOARD, 1),
        ResourceRole::Viewer,
    )
    .await;
    assert!(
        matches!(res, Err(ResourceAuthzError::Forbidden)),
        "a user with no membership row must be denied even the lowest role",
    );
}

#[tokio::test]
async fn role_meets_or_exceeds_minimum_is_allowed() {
    let pool = common::pool().await;
    TableAuthority::create_table(&pool).await;
    let uid = common::make_user(&pool, "a@example.invalid", "password123").await;

    // Viewer satisfies a Viewer requirement (equality).
    TableAuthority::grant(&pool, uid, BOARD, 1, "viewer").await;
    assert_eq!(
        require_resource(&TableAuthority, &pool, uid, ResourceRef::new(BOARD, 1), ResourceRole::Viewer)
            .await
            .ok(),
        Some(uid),
        "require_resource returns the user id on success",
    );

    // Owner satisfies an Editor requirement (lattice above).
    TableAuthority::grant(&pool, uid, BOARD, 2, "owner").await;
    assert!(
        require_resource(&TableAuthority, &pool, uid, ResourceRef::new(BOARD, 2), ResourceRole::Editor)
            .await
            .is_ok(),
    );

    // Editor satisfies an Editor requirement (equality).
    TableAuthority::grant(&pool, uid, BOARD, 3, "editor").await;
    assert!(
        require_resource(&TableAuthority, &pool, uid, ResourceRef::new(BOARD, 3), ResourceRole::Editor)
            .await
            .is_ok(),
    );
}

#[tokio::test]
async fn role_below_minimum_is_forbidden() {
    let pool = common::pool().await;
    TableAuthority::create_table(&pool).await;
    let uid = common::make_user(&pool, "a@example.invalid", "password123").await;

    TableAuthority::grant(&pool, uid, BOARD, 1, "viewer").await;
    let res = require_resource(
        &TableAuthority,
        &pool,
        uid,
        ResourceRef::new(BOARD, 1),
        ResourceRole::Editor,
    )
    .await;
    assert!(
        matches!(res, Err(ResourceAuthzError::Forbidden)),
        "a Viewer must not satisfy an Editor requirement",
    );
}

#[tokio::test]
async fn lookup_error_propagates_distinct_from_deny() {
    let pool = common::pool().await;
    let uid = common::make_user(&pool, "a@example.invalid", "password123").await;

    let res = require_resource(
        &FailingAuthority,
        &pool,
        uid,
        ResourceRef::new(BOARD, 1),
        ResourceRole::Viewer,
    )
    .await;
    assert!(
        matches!(res, Err(ResourceAuthzError::Lookup(_))),
        "an errored role_on must surface as Lookup, never a silent Forbidden",
    );
}

#[tokio::test]
async fn check_is_fresh_no_caching() {
    let pool = common::pool().await;
    TableAuthority::create_table(&pool).await;
    let uid = common::make_user(&pool, "a@example.invalid", "password123").await;
    let r = ResourceRef::new(BOARD, 1);

    TableAuthority::grant(&pool, uid, BOARD, 1, "editor").await;
    assert!(
        require_resource(&TableAuthority, &pool, uid, r, ResourceRole::Editor)
            .await
            .is_ok(),
        "granted Editor should pass",
    );

    // Revoke and re-check: the very next call must reflect the new state,
    // proving the check hits storage every time rather than caching a snapshot.
    TableAuthority::revoke(&pool, uid, BOARD, 1).await;
    assert!(
        matches!(
            require_resource(&TableAuthority, &pool, uid, r, ResourceRole::Editor).await,
            Err(ResourceAuthzError::Forbidden)
        ),
        "revocation must take effect on the next request",
    );
}
