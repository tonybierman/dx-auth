//! TOTP MFA: enrollment, status transitions, login challenge, recovery
//! codes. We exercise the real `totp_rs` round-trip — the test computes a
//! current code from the secret the library just generated, instead of
//! faking the clock. This catches secret-encoding bugs (raw vs base32) that
//! a mock would gloss over.

#![cfg(feature = "mfa")]

mod common;

use arium::auth;
use arium::auth::MfaStatus;

#[tokio::test]
async fn status_progression_disabled_pending_enabled() {
    let pool = common::pool().await;
    let user_id = common::make_user(&pool, "alice@example.com", "hunter22!").await;

    assert_eq!(
        auth::mfa_status(&pool, user_id).await.unwrap(),
        MfaStatus::Disabled,
    );
    assert!(!auth::user_has_mfa(&pool, user_id).await.unwrap());

    let info = auth::setup_mfa_secret(&pool, user_id, "alice@example.com")
        .await
        .unwrap();
    assert_eq!(
        auth::mfa_status(&pool, user_id).await.unwrap(),
        MfaStatus::Pending,
        "after setup, before confirm: Pending",
    );
    assert!(!auth::user_has_mfa(&pool, user_id).await.unwrap());

    let code = common::current_totp(&info.secret_base32);
    let confirmed = auth::enable_mfa(&pool, user_id, &code).await.unwrap();
    assert!(confirmed, "valid TOTP must enable MFA");
    assert_eq!(
        auth::mfa_status(&pool, user_id).await.unwrap(),
        MfaStatus::Enabled,
    );
    assert!(auth::user_has_mfa(&pool, user_id).await.unwrap());
}

#[tokio::test]
async fn setup_returns_ten_distinct_plaintext_recovery_codes() {
    let pool = common::pool().await;
    let user_id = common::make_user(&pool, "bob@example.com", "hunter22!").await;

    let info = auth::setup_mfa_secret(&pool, user_id, "bob@example.com")
        .await
        .unwrap();

    assert_eq!(info.recovery_codes.len(), 10);
    let unique: std::collections::HashSet<_> = info.recovery_codes.iter().collect();
    assert_eq!(unique.len(), 10, "codes must be unique");

    // None of the stored rows leak plaintext: the DB has Argon2 hashes only.
    let stored: Vec<(String,)> =
        sqlx::query_as("SELECT code_hash FROM mfa_recovery_codes WHERE user_id = $1")
            .bind(user_id)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(stored.len(), 10);
    for (h,) in &stored {
        assert!(h.starts_with("$argon2"), "expected Argon2 hash, got {h}");
        assert!(
            !info.recovery_codes.iter().any(|c| c == h),
            "plaintext recovery code must not be stored verbatim",
        );
    }
}

#[tokio::test]
async fn confirm_with_wrong_code_keeps_status_pending() {
    let pool = common::pool().await;
    let user_id = common::make_user(&pool, "carol@example.com", "hunter22!").await;
    auth::setup_mfa_secret(&pool, user_id, "carol@example.com")
        .await
        .unwrap();

    let confirmed = auth::enable_mfa(&pool, user_id, "000000").await.unwrap();
    assert!(!confirmed);
    assert_eq!(
        auth::mfa_status(&pool, user_id).await.unwrap(),
        MfaStatus::Pending,
    );
    assert!(!auth::user_has_mfa(&pool, user_id).await.unwrap());
}

#[tokio::test]
async fn verify_challenge_accepts_valid_totp() {
    let pool = common::pool().await;
    let user_id = common::make_user(&pool, "dan@example.com", "hunter22!").await;
    let info = auth::setup_mfa_secret(&pool, user_id, "dan@example.com")
        .await
        .unwrap();
    auth::enable_mfa(&pool, user_id, &common::current_totp(&info.secret_base32))
        .await
        .unwrap();

    let code = common::current_totp(&info.secret_base32);
    assert!(
        auth::verify_mfa_challenge(&pool, user_id, &code)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn verify_challenge_rejects_garbage_code() {
    let pool = common::pool().await;
    let user_id = common::make_user(&pool, "eve@example.com", "hunter22!").await;
    let info = auth::setup_mfa_secret(&pool, user_id, "eve@example.com")
        .await
        .unwrap();
    auth::enable_mfa(&pool, user_id, &common::current_totp(&info.secret_base32))
        .await
        .unwrap();

    assert!(
        !auth::verify_mfa_challenge(&pool, user_id, "000000")
            .await
            .unwrap()
    );
    assert!(
        !auth::verify_mfa_challenge(&pool, user_id, "nope")
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn recovery_code_is_single_use() {
    let pool = common::pool().await;
    let user_id = common::make_user(&pool, "frank@example.com", "hunter22!").await;
    let info = auth::setup_mfa_secret(&pool, user_id, "frank@example.com")
        .await
        .unwrap();
    auth::enable_mfa(&pool, user_id, &common::current_totp(&info.secret_base32))
        .await
        .unwrap();

    let code = info.recovery_codes[0].clone();
    assert!(
        auth::verify_mfa_challenge(&pool, user_id, &code)
            .await
            .unwrap()
    );
    // Second attempt must fail.
    assert!(
        !auth::verify_mfa_challenge(&pool, user_id, &code)
            .await
            .unwrap()
    );

    // And the row is marked used_at != NULL.
    let used: Option<(Option<i64>,)> = sqlx::query_as(
        "SELECT used_at FROM mfa_recovery_codes WHERE user_id = $1 AND used_at IS NOT NULL LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert!(
        used.is_some(),
        "consumed recovery code must have used_at set"
    );
}

#[tokio::test]
async fn recovery_codes_remaining_after_one_use_is_nine() {
    let pool = common::pool().await;
    let user_id = common::make_user(&pool, "gina@example.com", "hunter22!").await;
    let info = auth::setup_mfa_secret(&pool, user_id, "gina@example.com")
        .await
        .unwrap();
    auth::enable_mfa(&pool, user_id, &common::current_totp(&info.secret_base32))
        .await
        .unwrap();

    auth::verify_mfa_challenge(&pool, user_id, &info.recovery_codes[0])
        .await
        .unwrap();

    let unused: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL",
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(unused, 9);
}

#[tokio::test]
async fn disable_mfa_wipes_secret_and_recovery_codes() {
    let pool = common::pool().await;
    let user_id = common::make_user(&pool, "hank@example.com", "hunter22!").await;
    let info = auth::setup_mfa_secret(&pool, user_id, "hank@example.com")
        .await
        .unwrap();
    auth::enable_mfa(&pool, user_id, &common::current_totp(&info.secret_base32))
        .await
        .unwrap();

    auth::disable_mfa(&pool, user_id).await.unwrap();

    assert_eq!(
        auth::mfa_status(&pool, user_id).await.unwrap(),
        MfaStatus::Disabled,
    );
    let leftover: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM mfa_recovery_codes WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(leftover, 0, "disable must drop every recovery code");

    let row: (Option<String>, Option<i64>) =
        sqlx::query_as("SELECT mfa_secret, mfa_enabled_at FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(row.0.is_none(), "mfa_secret must be NULL after disable");
    assert!(row.1.is_none(), "mfa_enabled_at must be NULL after disable");
}

#[tokio::test]
async fn resetup_on_enrolled_account_reverts_to_pending_and_rotates_codes() {
    let pool = common::pool().await;
    let user_id = common::make_user(&pool, "ivan@example.com", "hunter22!").await;
    let first = auth::setup_mfa_secret(&pool, user_id, "ivan@example.com")
        .await
        .unwrap();
    auth::enable_mfa(&pool, user_id, &common::current_totp(&first.secret_base32))
        .await
        .unwrap();

    let second = auth::setup_mfa_secret(&pool, user_id, "ivan@example.com")
        .await
        .unwrap();
    // New secret and fresh codes.
    assert_ne!(first.secret_base32, second.secret_base32);
    assert_ne!(first.recovery_codes, second.recovery_codes);

    // Re-setup demotes Enabled → Pending (per the setup function's
    // `mfa_enabled_at = NULL`).
    assert_eq!(
        auth::mfa_status(&pool, user_id).await.unwrap(),
        MfaStatus::Pending,
    );

    // The first run's codes are gone (the setup deletes them). Checking a
    // single old code is enough — Argon2 verifies are deliberately slow,
    // and the invariant is "setup wiped the set", not "every individual
    // string fails its own hash".
    assert!(
        !auth::verify_mfa_challenge(&pool, user_id, &first.recovery_codes[0])
            .await
            .unwrap()
    );
    let leftover_old: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM mfa_recovery_codes WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    // 10 new rows, 0 old rows — proves the wipe at the schema level.
    assert_eq!(leftover_old, 10);
}

#[tokio::test]
async fn verify_challenge_on_user_without_mfa_returns_false() {
    // Defensive: even if a caller tries to verify a challenge for a user
    // who never enrolled, we don't crash and we don't return true.
    let pool = common::pool().await;
    let user_id = common::make_user(&pool, "joe@example.com", "hunter22!").await;
    assert!(
        !auth::verify_mfa_challenge(&pool, user_id, "000000")
            .await
            .unwrap()
    );
}
