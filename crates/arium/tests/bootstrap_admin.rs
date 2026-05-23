//! Bootstrap-admin rules. Two hooks fire on every new non-anonymous user:
//!
//! 1. `maybe_bootstrap_admin` — promote to ADMIN if `DX_AUTH_BOOTSTRAP_ADMIN_EMAIL`
//!    matches their email.
//! 2. `maybe_grant_first_admin` — promote when no ADMIN exists yet
//!    (first-user-wins, regardless of email).
//!
//! Plus `sync_bootstrap_admin` runs at boot and reconciles the env var
//! against an existing account.
//!
//! These tests *mutate process env*, so they're marked `#[serial]` so they
//! never run alongside each other or anything else that reads env.

mod common;

use arium::auth;
use serial_test::serial;

const ENV: &str = "DX_AUTH_BOOTSTRAP_ADMIN_EMAIL";

#[tokio::test]
#[serial]
async fn first_signup_with_no_env_var_becomes_admin() {
    let _g = common::EnvGuard::unset(ENV);
    let pool = common::pool().await;

    let uid = common::make_user(&pool, "founder@example.com", "hunter22!").await;
    let roles = auth::get_user_role_ids(&pool, uid).await.unwrap();
    assert!(
        roles.contains(&auth::role::ADMIN),
        "first non-anonymous user must auto-promote: {roles:?}",
    );
}

#[tokio::test]
#[serial]
async fn second_signup_is_member_only() {
    let _g = common::EnvGuard::unset(ENV);
    let pool = common::pool().await;

    common::make_user(&pool, "founder@example.com", "hunter22!").await;
    let second = common::make_user(&pool, "regular@example.com", "hunter22!").await;

    let roles = auth::get_user_role_ids(&pool, second).await.unwrap();
    assert!(!roles.contains(&auth::role::ADMIN), "{roles:?}");
    assert!(roles.contains(&auth::role::MEMBER), "{roles:?}");
}

#[tokio::test]
#[serial]
async fn env_var_match_promotes_on_signup_even_when_not_first() {
    let _g = common::EnvGuard::set(ENV, "admin@example.com");
    let pool = common::pool().await;

    // Existing first user (gets admin via first-user-wins).
    common::make_user(&pool, "first@example.com", "hunter22!").await;
    // Second user matches the env — must also become admin.
    let target = common::make_user(&pool, "admin@example.com", "hunter22!").await;

    let roles = auth::get_user_role_ids(&pool, target).await.unwrap();
    assert!(roles.contains(&auth::role::ADMIN), "{roles:?}");
}

#[tokio::test]
#[serial]
async fn env_var_match_is_case_insensitive() {
    let _g = common::EnvGuard::set(ENV, "Admin@Example.COM");
    let pool = common::pool().await;
    common::make_user(&pool, "first@example.com", "hunter22!").await;
    let target = common::make_user(&pool, "admin@example.com", "hunter22!").await;
    assert!(
        auth::get_user_role_ids(&pool, target)
            .await
            .unwrap()
            .contains(&auth::role::ADMIN),
    );
}

#[tokio::test]
#[serial]
async fn sync_bootstrap_admin_promotes_a_preexisting_user_idempotently() {
    let _g = common::EnvGuard::set(ENV, "ops@example.com");
    let pool = common::pool().await;

    // Pre-existing user (signs up *before* the env var is set).
    let target = {
        let _g_unset = common::EnvGuard::unset(ENV);
        common::make_user(&pool, "ops@example.com", "hunter22!").await
    };
    // Strip the admin role they got from first-user-wins so we can see the
    // sync function actually do the promotion.
    auth::revoke_role(&pool, target, auth::role::ADMIN)
        .await
        .unwrap();
    assert!(
        !auth::get_user_role_ids(&pool, target)
            .await
            .unwrap()
            .contains(&auth::role::ADMIN),
    );

    auth::sync_bootstrap_admin(&pool).await.unwrap();
    assert!(
        auth::get_user_role_ids(&pool, target)
            .await
            .unwrap()
            .contains(&auth::role::ADMIN),
    );

    // Running it again is a no-op (idempotent — no duplicate row).
    auth::sync_bootstrap_admin(&pool).await.unwrap();
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM user_roles WHERE user_id = $1 AND role_id = $2")
            .bind(target)
            .bind(auth::role::ADMIN)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
#[serial]
async fn sync_bootstrap_admin_is_noop_when_email_unknown() {
    let _g = common::EnvGuard::set(ENV, "ghost@example.com");
    let pool = common::pool().await;
    // No user with that email. Must NOT error.
    auth::sync_bootstrap_admin(&pool).await.unwrap();
}

#[tokio::test]
#[serial]
async fn self_recovery_after_last_admin_is_soft_deleted() {
    let _g = common::EnvGuard::unset(ENV);
    let pool = common::pool().await;

    let first = common::make_user(&pool, "first@example.com", "hunter22!").await;
    assert!(
        auth::get_user_role_ids(&pool, first)
            .await
            .unwrap()
            .contains(&auth::role::ADMIN)
    );

    // Soft-delete clears `user_roles` so there's now zero admins.
    auth::soft_delete_user(&pool, first).await.unwrap();

    // Next signup must be promoted.
    let next = common::make_user(&pool, "next@example.com", "hunter22!").await;
    assert!(
        auth::get_user_role_ids(&pool, next)
            .await
            .unwrap()
            .contains(&auth::role::ADMIN),
        "self-recovery: with zero admins, next signup becomes admin",
    );
}

#[tokio::test]
#[serial]
async fn alias_env_var_is_honored() {
    // The library accepts `BOOTSTRAP_ADMIN_EMAIL` as a fallback.
    let _g_primary = common::EnvGuard::unset(ENV);
    let _g_alias = common::EnvGuard::set("BOOTSTRAP_ADMIN_EMAIL", "ops@example.com");
    let pool = common::pool().await;

    common::make_user(&pool, "first@example.com", "hunter22!").await;
    let target = common::make_user(&pool, "ops@example.com", "hunter22!").await;

    assert!(
        auth::get_user_role_ids(&pool, target)
            .await
            .unwrap()
            .contains(&auth::role::ADMIN),
    );
}
