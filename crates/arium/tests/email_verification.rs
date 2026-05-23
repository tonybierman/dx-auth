//! Email-verification token lifecycle. The properties under test:
//!
//! - A fresh password account starts unverified; `verify_password_user`
//!   returns `Unverified` until the token is consumed.
//! - Consuming the token flips the user to verified AND wipes all
//!   outstanding verification tokens for that user.
//! - Expired and unknown tokens return `None`.
//! - `find_unverified_user_id` flips its answer at the same boundary.

mod common;

use arium::auth;
use arium::auth::VerifyOutcome;

/// Skip `make_user` (which marks verified) — these tests need the
/// unverified state.
async fn fresh_unverified_user(pool: &sqlx::SqlitePool, email: &str) -> i64 {
    auth::create_password_user(pool, email, "hunter22!")
        .await
        .expect("create_password_user")
}

#[tokio::test]
async fn fresh_password_account_starts_unverified() {
    let pool = common::pool().await;
    fresh_unverified_user(&pool, "alice@example.com").await;

    let outcome = auth::verify_password_user(&pool, "alice@example.com", "hunter22!")
        .await
        .unwrap();
    assert_eq!(outcome, VerifyOutcome::Unverified);
}

#[tokio::test]
async fn consume_token_marks_account_verified() {
    let pool = common::pool().await;
    let user_id = fresh_unverified_user(&pool, "bob@example.com").await;

    let token = auth::issue_verification_token(&pool, user_id)
        .await
        .unwrap();
    let returned = auth::consume_verification_token(&pool, &token)
        .await
        .unwrap();
    assert_eq!(returned, Some(user_id));

    let outcome = auth::verify_password_user(&pool, "bob@example.com", "hunter22!")
        .await
        .unwrap();
    assert_eq!(outcome, VerifyOutcome::Verified(user_id));
}

#[tokio::test]
async fn consume_invalidates_all_outstanding_tokens_for_same_user() {
    let pool = common::pool().await;
    let user_id = fresh_unverified_user(&pool, "carol@example.com").await;

    let t1 = auth::issue_verification_token(&pool, user_id)
        .await
        .unwrap();
    let t2 = auth::issue_verification_token(&pool, user_id)
        .await
        .unwrap();
    assert_ne!(t1, t2);

    auth::consume_verification_token(&pool, &t1).await.unwrap();

    // The other token issued in the same window is now dead.
    assert_eq!(
        auth::consume_verification_token(&pool, &t2).await.unwrap(),
        None
    );
}

#[tokio::test]
async fn unknown_token_returns_none_not_error() {
    let pool = common::pool().await;
    fresh_unverified_user(&pool, "dan@example.com").await;

    let result = auth::consume_verification_token(&pool, "deadbeef")
        .await
        .unwrap();
    assert_eq!(result, None);
}

#[tokio::test]
async fn expired_token_returns_none() {
    let pool = common::pool().await;
    let user_id = fresh_unverified_user(&pool, "eve@example.com").await;

    // Insert a hand-built token that's already past its expiry.
    let stale = "stale_verify_token";
    sqlx::query(
        "INSERT INTO email_verification_tokens (token, user_id, expires_at) \
         VALUES ($1, $2, $3)",
    )
    .bind(stale)
    .bind(user_id)
    .bind(common::now_secs() - 1)
    .execute(&pool)
    .await
    .unwrap();

    assert_eq!(
        auth::consume_verification_token(&pool, stale)
            .await
            .unwrap(),
        None
    );

    // User remains unverified.
    assert_eq!(
        auth::verify_password_user(&pool, "eve@example.com", "hunter22!")
            .await
            .unwrap(),
        VerifyOutcome::Unverified,
    );
}

#[tokio::test]
async fn find_unverified_user_id_flips_after_consume() {
    let pool = common::pool().await;
    let user_id = fresh_unverified_user(&pool, "frank@example.com").await;

    assert_eq!(
        auth::find_unverified_user_id(&pool, "frank@example.com")
            .await
            .unwrap(),
        Some(user_id),
    );

    let token = auth::issue_verification_token(&pool, user_id)
        .await
        .unwrap();
    auth::consume_verification_token(&pool, &token)
        .await
        .unwrap();

    assert_eq!(
        auth::find_unverified_user_id(&pool, "frank@example.com")
            .await
            .unwrap(),
        None,
    );
}

#[tokio::test]
async fn find_unverified_user_id_is_case_insensitive() {
    let pool = common::pool().await;
    let user_id = fresh_unverified_user(&pool, "gina@example.com").await;

    assert_eq!(
        auth::find_unverified_user_id(&pool, "GINA@EXAMPLE.COM")
            .await
            .unwrap(),
        Some(user_id),
    );
}

#[tokio::test]
async fn verification_token_is_32_lowercase_hex_chars() {
    let pool = common::pool().await;
    let user_id = fresh_unverified_user(&pool, "hank@example.com").await;
    let token = auth::issue_verification_token(&pool, user_id)
        .await
        .unwrap();
    assert_eq!(token.len(), 32);
    assert!(
        token
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "token {token:?} should be lowercase hex",
    );
}
