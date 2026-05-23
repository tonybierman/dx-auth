//! Email + password sign-up and sign-in, exercised through the *real*
//! `auth::create_password_user` / `auth::verify_password_user` pair against
//! a live sqlite pool. The intent is to lock in the invariants that protect
//! against user enumeration and weak-password admission.

mod common;

use arium::auth;
use arium::auth::VerifyOutcome;

#[tokio::test]
async fn signup_then_signin_succeeds_after_verification() {
    let pool = common::pool().await;
    let user_id = common::make_user(&pool, "alice@example.com", "hunter22!").await;

    let outcome = auth::verify_password_user(&pool, "alice@example.com", "hunter22!")
        .await
        .unwrap();
    assert_eq!(outcome, VerifyOutcome::Verified(user_id));
}

#[tokio::test]
async fn signup_without_verification_returns_unverified_on_login() {
    let pool = common::pool().await;
    auth::create_password_user(&pool, "bob@example.com", "hunter22!")
        .await
        .unwrap();

    // `create_password_user` does NOT mark verified; that's the mail flow's
    // job. So the immediate sign-in attempt is in the `Unverified` branch.
    let outcome = auth::verify_password_user(&pool, "bob@example.com", "hunter22!")
        .await
        .unwrap();
    assert_eq!(outcome, VerifyOutcome::Unverified);
}

#[tokio::test]
async fn wrong_password_and_unknown_email_are_indistinguishable() {
    let pool = common::pool().await;
    common::make_user(&pool, "carol@example.com", "hunter22!").await;

    let wrong = auth::verify_password_user(&pool, "carol@example.com", "WRONG")
        .await
        .unwrap();
    let unknown = auth::verify_password_user(&pool, "nobody@example.com", "anything")
        .await
        .unwrap();

    // Same enum variant — server fn surfaces the same string for both. If
    // these ever diverge a timing or response-body oracle would let an
    // attacker enumerate accounts.
    assert_eq!(wrong, VerifyOutcome::Invalid);
    assert_eq!(unknown, VerifyOutcome::Invalid);
}

#[tokio::test]
async fn email_lookup_is_case_insensitive_and_whitespace_tolerant() {
    let pool = common::pool().await;
    let user_id = common::make_user(&pool, "Dan@Example.Com", "hunter22!").await;

    // Case-folded input → same user.
    assert_eq!(
        auth::verify_password_user(&pool, "DAN@example.com", "hunter22!")
            .await
            .unwrap(),
        VerifyOutcome::Verified(user_id),
    );
    // Surrounding whitespace stripped.
    assert_eq!(
        auth::verify_password_user(&pool, "  dan@example.com  ", "hunter22!")
            .await
            .unwrap(),
        VerifyOutcome::Verified(user_id),
    );
}

#[tokio::test]
async fn duplicate_email_signup_is_rejected_with_user_facing_message() {
    let pool = common::pool().await;
    common::make_user(&pool, "eve@example.com", "hunter22!").await;

    let err = auth::create_password_user(&pool, "eve@example.com", "different1!")
        .await
        .unwrap_err()
        .to_string();
    // The user-facing wording is the *contract* — the UI surfaces it
    // verbatim. We only check for the structural part ("already exists")
    // so a copy edit doesn't break this test.
    assert!(
        err.contains("already exists"),
        "expected duplicate-email rejection, got: {err}"
    );
}

#[tokio::test]
async fn short_password_is_rejected_at_signup_boundary() {
    let pool = common::pool().await;
    let err = auth::create_password_user(&pool, "frank@example.com", "short")
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("8 characters"), "wording changed: {err}");
}

#[tokio::test]
async fn invalid_email_shape_is_rejected_at_signup_boundary() {
    let pool = common::pool().await;
    let err = auth::create_password_user(&pool, "notanemail", "hunter22!")
        .await
        .unwrap_err()
        .to_string();
    assert!(err.to_ascii_lowercase().contains("email"), "{err}");
}

#[tokio::test]
async fn password_hash_is_argon2_and_round_trips() {
    // Belt-and-braces: the function used internally for storing and the
    // helper used by `change_password` must agree on hash format.
    let pool = common::pool().await;
    let user_id = common::make_user(&pool, "gina@example.com", "hunter22!").await;

    let stored = auth::get_password_hash(&pool, user_id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        stored.starts_with("$argon2"),
        "expected an Argon2 PHC string, got prefix {:?}",
        &stored.chars().take(10).collect::<String>(),
    );
    assert!(auth::verify_password_against_hash(&stored, "hunter22!"));
    assert!(!auth::verify_password_against_hash(&stored, "wrong"));
}

#[tokio::test]
async fn change_password_replaces_hash_and_old_password_stops_working() {
    let pool = common::pool().await;
    let user_id = common::make_user(&pool, "hank@example.com", "hunter22!").await;

    auth::replace_password_hash(&pool, user_id, "new_password!")
        .await
        .unwrap();

    assert_eq!(
        auth::verify_password_user(&pool, "hank@example.com", "hunter22!")
            .await
            .unwrap(),
        VerifyOutcome::Invalid,
    );
    assert_eq!(
        auth::verify_password_user(&pool, "hank@example.com", "new_password!")
            .await
            .unwrap(),
        VerifyOutcome::Verified(user_id),
    );
}

#[tokio::test]
async fn replace_password_rejects_short_password() {
    let pool = common::pool().await;
    let user_id = common::make_user(&pool, "ivan@example.com", "hunter22!").await;

    let err = auth::replace_password_hash(&pool, user_id, "short")
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("8 characters"), "{err}");
}
