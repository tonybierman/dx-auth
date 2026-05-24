//! `upsert_oauth_user` is the most subtle correctness surface in the crate:
//! one function decides between "log the same OAuth user back in",
//! "attach this OAuth identity to an existing local password account
//! because the emails match", and "create a brand-new user". Each branch
//! has security implications — e.g. branch 2 must never clobber the
//! existing password hash, branch 3 must mark the new user verified.

#![cfg(feature = "oauth-github")] // gates the OAuth trait + types

mod common;

use arium::auth;
use arium::oauth::{NormalizedProfile, upsert_oauth_user};

fn profile(provider_user_id: &str, login: &str, email: Option<&str>) -> NormalizedProfile {
    NormalizedProfile {
        provider_user_id: provider_user_id.to_string(),
        login: login.to_string(),
        name: Some(format!("{login} (display)")),
        email: email.map(str::to_string),
        avatar_url: Some(format!("https://example.invalid/{login}.png")),
        html_url: Some(format!("https://example.invalid/{login}")),
    }
}

// ============================================================
// Branch 1 — repeat login for an already-linked OAuth identity
// ============================================================

#[tokio::test]
async fn repeat_login_returns_same_user_and_refreshes_provider_fields_only() {
    let pool = common::pool().await;

    let first = profile("ext-1", "octocat", Some("octo@example.com"));
    let user_id = upsert_oauth_user(&pool, "github", first).await.unwrap();

    // Second login: same external id, but the provider returned a new login
    // (a rename), a new display name, and a new avatar.
    let updated = NormalizedProfile {
        name: Some("Octo Cat the Second".to_string()),
        avatar_url: Some("https://example.invalid/new.png".to_string()),
        ..profile("ext-1", "octocat-renamed", Some("octo@example.com"))
    };
    let again = upsert_oauth_user(&pool, "github", updated).await.unwrap();

    assert_eq!(again, user_id, "repeat login must return the same user id");

    let row: (String, Option<String>, Option<String>) =
        sqlx::query_as("SELECT username, display_name, avatar_url FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    // The handle is assigned once and stays stable across re-login: a rename
    // on the provider must NOT silently change the local @username.
    assert_eq!(row.0, "octocat", "username is stable across re-login");
    // display_name is user-editable, so re-login does NOT overwrite it — it
    // keeps the value seeded at first signup.
    assert_eq!(row.1.as_deref(), Some("octocat (display)"));
    // Provider-owned fields (avatar/email/html_url) ARE refreshed.
    assert_eq!(row.2.as_deref(), Some("https://example.invalid/new.png"));
}

// ============================================================
// Branch 2 — link OAuth identity to an existing password account
// ============================================================

#[tokio::test]
async fn email_match_links_to_existing_password_account_without_clobbering_hash() {
    let pool = common::pool().await;
    let existing_id = common::make_user(&pool, "alice@example.com", "hunter22!").await;
    let pre_hash = auth::get_password_hash(&pool, existing_id).await.unwrap();
    let pre_username: String = sqlx::query_scalar("SELECT username FROM users WHERE id = $1")
        .bind(existing_id)
        .fetch_one(&pool)
        .await
        .unwrap();

    let prof = profile("gh-42", "alice-on-gh", Some("alice@example.com"));
    let linked_id = upsert_oauth_user(&pool, "github", prof).await.unwrap();

    assert_eq!(linked_id, existing_id, "must link to the existing user");

    // The oauth_accounts row is in place.
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM oauth_accounts WHERE provider = 'github' \
         AND provider_user_id = 'gh-42' AND user_id = $1",
    )
    .bind(existing_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 1);

    // Password hash unchanged → user can still sign in with the password.
    let post_hash = auth::get_password_hash(&pool, existing_id).await.unwrap();
    assert_eq!(pre_hash, post_hash, "must preserve password hash on link");

    // Username preserved (the linking branch never touches the local handle).
    let post_username: String = sqlx::query_scalar("SELECT username FROM users WHERE id = $1")
        .bind(existing_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(pre_username, post_username);

    // The password account had no display_name, so linking seeds it from the
    // provider's reported name (COALESCE — it would NOT clobber an existing one).
    let display_name: Option<String> =
        sqlx::query_scalar("SELECT display_name FROM users WHERE id = $1")
            .bind(existing_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(display_name.as_deref(), Some("alice-on-gh (display)"));
}

#[tokio::test]
async fn email_match_is_case_insensitive() {
    let pool = common::pool().await;
    let existing_id = common::make_user(&pool, "Alice@Example.com", "hunter22!").await;

    let prof = profile("gh-43", "alice2", Some("alice@example.com"));
    let linked_id = upsert_oauth_user(&pool, "github", prof).await.unwrap();
    assert_eq!(linked_id, existing_id);
}

#[tokio::test]
async fn two_providers_link_to_same_local_user() {
    let pool = common::pool().await;
    let existing_id = common::make_user(&pool, "carol@example.com", "hunter22!").await;

    upsert_oauth_user(
        &pool,
        "github",
        profile("gh-1", "carol", Some("carol@example.com")),
    )
    .await
    .unwrap();
    upsert_oauth_user(
        &pool,
        "gitlab",
        profile("gl-1", "carol", Some("carol@example.com")),
    )
    .await
    .unwrap();

    let providers = auth::linked_oauth_providers(&pool, existing_id)
        .await
        .unwrap();
    // Sorted by the underlying query.
    assert_eq!(providers, vec!["github".to_string(), "gitlab".to_string()]);

    // And still exactly one underlying user.
    let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE anonymous = false")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(users, 1);
}

// ============================================================
// Branch 3 — brand-new user (no email match, or no email at all)
// ============================================================

#[tokio::test]
async fn brand_new_user_is_created_marked_verified_and_granted_member_role() {
    let pool = common::pool().await;
    let prof = profile("gh-100", "fresh", Some("fresh@example.com"));
    let user_id = upsert_oauth_user(&pool, "github", prof).await.unwrap();

    let row: (bool, Option<i64>, Option<String>) = sqlx::query_as(
        "SELECT anonymous, email_verified_at, password_hash FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!row.0, "OAuth users are not anonymous");
    assert!(row.1.is_some(), "OAuth signup auto-marks email_verified_at");
    assert!(row.2.is_none(), "OAuth-only user has no password hash");

    // First non-anonymous account → promoted to admin (first-user-wins).
    // But every OAuth user definitely gets the MEMBER baseline.
    let role_ids = auth::get_user_role_ids(&pool, user_id).await.unwrap();
    assert!(role_ids.contains(&auth::role::MEMBER));
}

#[tokio::test]
async fn provider_returning_no_email_creates_a_new_user_without_linking() {
    let pool = common::pool().await;
    // Pre-existing user whose email IS null — we must NOT accidentally
    // link an emailless OAuth identity to them via NULL = NULL.
    sqlx::query(
        "INSERT INTO users (anonymous, username, email_verified_at) \
         VALUES (false, 'no_email', strftime('%s','now'))",
    )
    .execute(&pool)
    .await
    .unwrap();

    let prof = profile("gh-no-email", "anon-gh", None);
    let new_id = upsert_oauth_user(&pool, "github", prof).await.unwrap();

    // We got a brand-new user, not the prior emailless one.
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE anonymous = false")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        count, 2,
        "an emailless OAuth profile must not link via NULL match"
    );

    // The new user has the oauth_accounts row attached.
    let attached_to: i64 = sqlx::query_scalar(
        "SELECT user_id FROM oauth_accounts \
         WHERE provider = 'github' AND provider_user_id = 'gh-no-email'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(attached_to, new_id);
}

#[tokio::test]
async fn brand_new_oauth_user_with_no_existing_admin_is_promoted_to_admin() {
    // The first-user-wins rule applies to OAuth signup too.
    let pool = common::pool().await;
    let prof = profile("gh-first", "founder", Some("founder@example.com"));
    let user_id = upsert_oauth_user(&pool, "github", prof).await.unwrap();

    let role_ids = auth::get_user_role_ids(&pool, user_id).await.unwrap();
    assert!(
        role_ids.contains(&auth::role::ADMIN),
        "first non-anonymous user (any signup method) must become admin: roles={role_ids:?}",
    );
}

#[tokio::test]
async fn oidc_shaped_profile_upserts_under_its_runtime_provider_name() {
    // An OIDC provider yields a profile keyed by `sub`, an email-derived login
    // (no public handle), and no html_url. The runtime provider name ("oidc",
    // "google", ...) is stored verbatim in oauth_accounts.provider.
    let pool = common::pool().await;
    let prof = NormalizedProfile {
        provider_user_id: "sub-abc-123".to_string(),
        login: "dana".to_string(), // e.g. derived from dana@corp.example
        name: Some("Dana Scully".to_string()),
        email: Some("dana@corp.example".to_string()),
        avatar_url: Some("https://cdn.example/dana.png".to_string()),
        html_url: None,
    };
    let user_id = upsert_oauth_user(&pool, "oidc", prof).await.unwrap();

    // Linked under the runtime provider name + sub.
    let oa: (String, String) =
        sqlx::query_as("SELECT provider, provider_user_id FROM oauth_accounts WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(oa, ("oidc".to_string(), "sub-abc-123".to_string()));

    // Verified (provider asserts the email), no html_url, handle seeded.
    let row: (String, Option<String>, Option<i64>) =
        sqlx::query_as("SELECT username, html_url, email_verified_at FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(row.0, "dana");
    assert!(row.1.is_none(), "OIDC profile carried no html_url");
    assert!(row.2.is_some(), "OAuth signup marks email verified");
}
