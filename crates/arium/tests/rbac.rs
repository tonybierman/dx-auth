//! Roles, role-derived permission tokens, and the soft-delete behaviour
//! that knocks a user out of every role at once.

mod common;

use arium::auth;

#[tokio::test]
async fn list_permissions_unions_direct_grants_and_role_grants() {
    let pool = common::pool().await;
    let uid = common::make_user(&pool, "alice@example.com", "hunter22!").await;
    // First user gets ADMIN via first-user-wins, plus MEMBER from
    // assign_default_role. Confirm we see admin tokens from the role.
    let perms = auth::list_permissions_for_user(&pool, uid).await.unwrap();
    assert!(
        perms.iter().any(|p| p == "admin:users:read"),
        "expected admin:users:read in {perms:?}",
    );

    // Direct grant (not via a role).
    sqlx::query("INSERT INTO user_permissions (user_id, token) VALUES ($1, $2)")
        .bind(uid)
        .bind("custom:tenant:42:write")
        .execute(&pool)
        .await
        .unwrap();
    let perms = auth::list_permissions_for_user(&pool, uid).await.unwrap();
    assert!(perms.iter().any(|p| p == "custom:tenant:42:write"));
    assert!(perms.iter().any(|p| p == "admin:users:read"));
}

#[tokio::test]
async fn list_permissions_dedupes_when_user_holds_two_roles_with_overlapping_tokens() {
    let pool = common::pool().await;
    let uid = common::make_user(&pool, "bob@example.com", "hunter22!").await;

    // Two distinct roles that share a permission.
    let r1 = auth::create_role(
        &pool,
        "reader-1",
        None,
        &["shared:token".to_string(), "extra:1".to_string()],
    )
    .await
    .unwrap();
    let r2 = auth::create_role(
        &pool,
        "reader-2",
        None,
        &["shared:token".to_string(), "extra:2".to_string()],
    )
    .await
    .unwrap();
    auth::set_user_roles(&pool, uid, &[r1, r2]).await.unwrap();

    let perms = auth::list_permissions_for_user(&pool, uid).await.unwrap();
    let shared_hits = perms
        .iter()
        .filter(|p| p.as_str() == "shared:token")
        .count();
    assert_eq!(
        shared_hits, 1,
        "duplicate tokens must be deduped: {perms:?}"
    );
    assert!(perms.contains(&"extra:1".to_string()));
    assert!(perms.contains(&"extra:2".to_string()));
}

#[tokio::test]
async fn set_user_roles_replaces_atomically() {
    let pool = common::pool().await;
    let uid = common::make_user(&pool, "carol@example.com", "hunter22!").await;

    let r1 = auth::create_role(&pool, "team-a", None, &["a:read".to_string()])
        .await
        .unwrap();
    let r2 = auth::create_role(&pool, "team-b", None, &["b:read".to_string()])
        .await
        .unwrap();

    auth::set_user_roles(&pool, uid, &[r1]).await.unwrap();
    assert_eq!(auth::get_user_role_ids(&pool, uid).await.unwrap(), vec![r1]);

    auth::set_user_roles(&pool, uid, &[r2]).await.unwrap();
    assert_eq!(auth::get_user_role_ids(&pool, uid).await.unwrap(), vec![r2]);

    // Empty list wipes all grants.
    auth::set_user_roles(&pool, uid, &[]).await.unwrap();
    assert!(
        auth::get_user_role_ids(&pool, uid)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn set_user_roles_rolls_back_on_invalid_role_id() {
    let pool = common::pool().await;
    let uid = common::make_user(&pool, "dan@example.com", "hunter22!").await;

    let r1 = auth::create_role(&pool, "team-c", None, &["c:read".to_string()])
        .await
        .unwrap();
    auth::set_user_roles(&pool, uid, &[r1]).await.unwrap();

    // 9999 doesn't exist — FK violation in the INSERT half of the
    // delete-then-insert. The whole replace is inside one tx, so the prior
    // state (just `r1`) must be preserved.
    let result = auth::set_user_roles(&pool, uid, &[r1, 9999]).await;
    assert!(result.is_err(), "FK violation must surface as an error");

    let role_ids = auth::get_user_role_ids(&pool, uid).await.unwrap();
    assert_eq!(
        role_ids,
        vec![r1],
        "failed set_user_roles must roll back to the original grants",
    );
}

#[tokio::test]
async fn create_role_rejects_duplicate_name() {
    let pool = common::pool().await;
    auth::create_role(&pool, "ops", None, &[]).await.unwrap();
    let err = auth::create_role(&pool, "ops", None, &[])
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("already exists"), "{err}");
}

#[tokio::test]
async fn create_role_dedups_and_trims_tokens() {
    let pool = common::pool().await;
    let role_id = auth::create_role(
        &pool,
        "support",
        None,
        &[
            "ticket:read".to_string(),
            "  ticket:read  ".to_string(), // dup w/ whitespace
            "".to_string(),                // empty → dropped
            "ticket:write".to_string(),
        ],
    )
    .await
    .unwrap();
    let perms = auth::list_permissions_for_role(&pool, role_id)
        .await
        .unwrap();
    assert_eq!(
        perms,
        vec!["ticket:read".to_string(), "ticket:write".to_string()]
    );
}

#[tokio::test]
async fn system_roles_are_read_only() {
    let pool = common::pool().await;
    // System role ids 1=admin, 2=member, 3=guest (seeded in migration 0005).
    let err = auth::update_role(&pool, 1, "admin-renamed", None, &[])
        .await
        .unwrap_err()
        .to_string();
    assert!(err.to_ascii_lowercase().contains("system"), "{err}");

    let err = auth::delete_role(&pool, 1).await.unwrap_err().to_string();
    assert!(err.to_ascii_lowercase().contains("system"), "{err}");
}

#[tokio::test]
async fn update_role_replaces_permission_set() {
    let pool = common::pool().await;
    let role_id = auth::create_role(
        &pool,
        "ops",
        Some("ops team"),
        &["ops:read".to_string(), "ops:write".to_string()],
    )
    .await
    .unwrap();
    auth::update_role(
        &pool,
        role_id,
        "ops",
        Some("ops team — updated"),
        &["ops:read".to_string()], // dropped ops:write
    )
    .await
    .unwrap();
    let perms = auth::list_permissions_for_role(&pool, role_id)
        .await
        .unwrap();
    assert_eq!(perms, vec!["ops:read".to_string()]);
}

#[tokio::test]
async fn delete_role_clears_user_role_assignments() {
    let pool = common::pool().await;
    let uid = common::make_user(&pool, "eve@example.com", "hunter22!").await;
    let role_id = auth::create_role(&pool, "deletable", None, &["x".to_string()])
        .await
        .unwrap();
    auth::grant_role(&pool, uid, role_id).await.unwrap();

    auth::delete_role(&pool, role_id).await.unwrap();

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_roles WHERE role_id = $1")
        .bind(role_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);

    let perms = auth::list_permissions_for_user(&pool, uid).await.unwrap();
    assert!(!perms.contains(&"x".to_string()));
}

#[tokio::test]
async fn grant_role_is_idempotent() {
    let pool = common::pool().await;
    let uid = common::make_user(&pool, "frank@example.com", "hunter22!").await;
    let r = auth::create_role(&pool, "doubler", None, &[])
        .await
        .unwrap();
    auth::grant_role(&pool, uid, r).await.unwrap();
    // Second grant must not error and must not create a duplicate row.
    auth::grant_role(&pool, uid, r).await.unwrap();

    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM user_roles WHERE user_id = $1 AND role_id = $2")
            .bind(uid)
            .bind(r)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn revoke_role_is_idempotent() {
    let pool = common::pool().await;
    let uid = common::make_user(&pool, "gina@example.com", "hunter22!").await;
    let r = auth::create_role(&pool, "revoker", None, &[])
        .await
        .unwrap();
    auth::revoke_role(&pool, uid, r).await.unwrap(); // never had it → fine
    auth::grant_role(&pool, uid, r).await.unwrap();
    auth::revoke_role(&pool, uid, r).await.unwrap();
    auth::revoke_role(&pool, uid, r).await.unwrap(); // already gone → fine
}

#[tokio::test]
async fn soft_delete_user_revokes_all_roles_and_links() {
    let pool = common::pool().await;
    let uid = common::make_user(&pool, "hank@example.com", "hunter22!").await;
    // Link an OAuth identity to make sure soft delete clears it.
    sqlx::query(
        "INSERT INTO oauth_accounts (provider, provider_user_id, user_id) \
         VALUES ('github', 'gh-link', $1)",
    )
    .bind(uid)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO user_permissions (user_id, token) VALUES ($1, 'custom')")
        .bind(uid)
        .execute(&pool)
        .await
        .unwrap();

    auth::soft_delete_user(&pool, uid).await.unwrap();

    assert!(
        auth::get_user_role_ids(&pool, uid)
            .await
            .unwrap()
            .is_empty()
    );
    let oauth_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM oauth_accounts WHERE user_id = $1")
            .bind(uid)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(oauth_count, 0);
    let perm_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM user_permissions WHERE user_id = $1")
            .bind(uid)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(perm_count, 0);

    // PII is null but the row still exists so app-owned FKs don't break.
    let row: (Option<String>, Option<String>, Option<i64>) =
        sqlx::query_as("SELECT email, password_hash, deleted_at FROM users WHERE id = $1")
            .bind(uid)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(row.0.is_none(), "email cleared");
    assert!(row.1.is_none(), "password_hash cleared");
    assert!(row.2.is_some(), "deleted_at stamped");
}

#[tokio::test]
async fn scoped_permission_round_trips_via_user_permissions() {
    // The library treats `scope` as an opaque prefix and stores the
    // composed token. We verify the round trip end to end.
    let pool = common::pool().await;
    let uid = common::make_user(&pool, "ivan@example.com", "hunter22!").await;

    sqlx::query("INSERT INTO user_permissions (user_id, token) VALUES ($1, $2)")
        .bind(uid)
        .bind("project:42:write")
        .execute(&pool)
        .await
        .unwrap();
    let perms = auth::list_permissions_for_user(&pool, uid).await.unwrap();
    assert!(perms.iter().any(|p| p == "project:42:write"));
}

#[tokio::test]
async fn update_display_name_clears_with_none() {
    let pool = common::pool().await;
    let uid = common::make_user(&pool, "joe@example.com", "hunter22!").await;

    auth::update_display_name(&pool, uid, Some("Joe Bloggs"))
        .await
        .unwrap();
    let row: Option<String> = sqlx::query_scalar("SELECT display_name FROM users WHERE id = $1")
        .bind(uid)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(row.as_deref(), Some("Joe Bloggs"));

    auth::update_display_name(&pool, uid, None).await.unwrap();
    let row: Option<String> = sqlx::query_scalar("SELECT display_name FROM users WHERE id = $1")
        .bind(uid)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(row.is_none());
}
