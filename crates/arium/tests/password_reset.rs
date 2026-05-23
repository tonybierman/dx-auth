//! Forgot-password reset token lifecycle. The properties we lock in are:
//!
//! - Tokens are one-shot.
//! - Issuing a reset for an unknown email returns `None` (the public server
//!   fn upgrades that to a generic `Ok` so the response can't enumerate).
//! - Consuming a token replaces the password AND invalidates every
//!   outstanding token for the same user (so a leaked older token from the
//!   user's inbox can't be reused after a successful reset).
//! - Expired tokens are rejected.

mod common;

use arium::auth;
use arium::auth::VerifyOutcome;

#[tokio::test]
async fn request_returns_some_for_known_email_and_persists_a_row() {
    let pool = common::pool().await;
    common::make_user(&pool, "alice@example.com", "hunter22!").await;

    let token = auth::request_password_reset(&pool, "alice@example.com")
        .await
        .unwrap()
        .expect("known email yields a token");

    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM password_reset_tokens WHERE token = $1")
            .bind(&token)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn request_returns_none_for_unknown_email() {
    let pool = common::pool().await;
    // No users at all.
    let token = auth::request_password_reset(&pool, "nobody@example.com")
        .await
        .unwrap();
    assert!(token.is_none(), "unknown email must not yield a token");
}

#[tokio::test]
async fn request_returns_none_for_oauth_only_account_with_no_password_hash() {
    let pool = common::pool().await;
    // Insert a user without a password_hash (OAuth-only shape).
    sqlx::query(
        "INSERT INTO users (anonymous, username, email, email_verified_at) \
         VALUES (false, 'gh', 'gh@example.com', strftime('%s','now'))",
    )
    .execute(&pool)
    .await
    .unwrap();

    let token = auth::request_password_reset(&pool, "gh@example.com")
        .await
        .unwrap();
    // The SQL filter `AND password_hash IS NOT NULL` means OAuth-only users
    // never receive a reset token — by design, since there's nothing to reset.
    assert!(token.is_none());
}

#[tokio::test]
async fn consume_swaps_the_password_and_invalidates_all_outstanding_tokens() {
    let pool = common::pool().await;
    let user_id = common::make_user(&pool, "bob@example.com", "hunter22!").await;

    let first = auth::request_password_reset(&pool, "bob@example.com")
        .await
        .unwrap()
        .unwrap();
    let second = auth::request_password_reset(&pool, "bob@example.com")
        .await
        .unwrap()
        .unwrap();
    assert_ne!(first, second);

    let consumed_uid = auth::consume_password_reset(&pool, &first, "new_password!")
        .await
        .unwrap();
    assert_eq!(consumed_uid, user_id);

    // Old password no longer works.
    assert_eq!(
        auth::verify_password_user(&pool, "bob@example.com", "hunter22!")
            .await
            .unwrap(),
        VerifyOutcome::Invalid,
    );
    // New one does.
    assert_eq!(
        auth::verify_password_user(&pool, "bob@example.com", "new_password!")
            .await
            .unwrap(),
        VerifyOutcome::Verified(user_id),
    );

    // The *other* token from the same issuance window is now dead.
    let err = auth::consume_password_reset(&pool, &second, "another_one!")
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("expired") || err.contains("already been used"),
        "{err}"
    );
}

#[tokio::test]
async fn consume_rejects_unknown_token() {
    let pool = common::pool().await;
    common::make_user(&pool, "carol@example.com", "hunter22!").await;

    let err = auth::consume_password_reset(&pool, "deadbeef", "new_password!")
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("expired") || err.contains("already been used"),
        "{err}"
    );
}

#[tokio::test]
async fn consume_rejects_expired_token() {
    let pool = common::pool().await;
    let user_id = common::make_user(&pool, "dan@example.com", "hunter22!").await;

    // Insert a token that's already past its expires_at.
    let stale = "stale_token_for_expiry_test";
    sqlx::query(
        "INSERT INTO password_reset_tokens (token, user_id, expires_at) \
         VALUES ($1, $2, $3)",
    )
    .bind(stale)
    .bind(user_id)
    .bind(common::now_secs() - 1) // already expired
    .execute(&pool)
    .await
    .unwrap();

    let err = auth::consume_password_reset(&pool, stale, "new_password!")
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("expired") || err.contains("already been used"),
        "{err}"
    );

    // And the original password still works — i.e. the failed consume
    // didn't accidentally clobber the hash.
    assert_eq!(
        auth::verify_password_user(&pool, "dan@example.com", "hunter22!")
            .await
            .unwrap(),
        VerifyOutcome::Verified(user_id),
    );
}

#[tokio::test]
async fn consume_rejects_short_password() {
    let pool = common::pool().await;
    common::make_user(&pool, "eve@example.com", "hunter22!").await;
    let token = auth::request_password_reset(&pool, "eve@example.com")
        .await
        .unwrap()
        .unwrap();

    let err = auth::consume_password_reset(&pool, &token, "short")
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("8 characters"), "{err}");

    // Token must NOT have been consumed by the failed attempt.
    let remaining: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM password_reset_tokens WHERE token = $1")
            .bind(&token)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, 1, "failed consume must not destroy the token");
}

#[tokio::test]
async fn consume_then_reuse_same_token_fails() {
    let pool = common::pool().await;
    common::make_user(&pool, "frank@example.com", "hunter22!").await;
    let token = auth::request_password_reset(&pool, "frank@example.com")
        .await
        .unwrap()
        .unwrap();

    auth::consume_password_reset(&pool, &token, "first_change!")
        .await
        .unwrap();
    let err = auth::consume_password_reset(&pool, &token, "second_change!")
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("expired") || err.contains("already been used"),
        "{err}"
    );
}

#[tokio::test]
async fn token_is_32_lowercase_hex_chars() {
    // Locks in the URL-shape contract documented in `auth.rs`: the email body
    // is plain-text 7bit-encoded, and the link must stay under 76 columns —
    // a 32-char hex token is what makes that math work.
    let pool = common::pool().await;
    common::make_user(&pool, "gina@example.com", "hunter22!").await;
    let token = auth::request_password_reset(&pool, "gina@example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(token.len(), 32);
    assert!(
        token
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "token {token:?} should be lowercase hex"
    );
}
