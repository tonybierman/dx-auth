//! API token CRUD: prefix/hash invariants, list scoping, soft-revoke.

#![cfg(feature = "tokens")]

mod common;

use arium::auth::tokens;

#[test]
fn generate_api_token_invariants() {
    let (plaintext, prefix, hash) = tokens::generate_api_token();

    assert!(
        plaintext.starts_with("dxsk_"),
        "plaintext must carry the dxsk_ scheme prefix: {plaintext}"
    );
    assert_eq!(
        plaintext.len(),
        5 + 32,
        "plaintext should be `dxsk_` + 32 hex chars",
    );
    assert!(
        plaintext[5..].chars().all(|c| c.is_ascii_hexdigit()),
        "plaintext body should be lowercase hex",
    );

    assert_eq!(prefix.len(), 9, "prefix is `dxsk_` + 4 hex chars");
    assert!(
        plaintext.starts_with(&prefix),
        "prefix must be a prefix of the cleartext: {prefix} vs {plaintext}",
    );

    assert_eq!(hash.len(), 64, "SHA-256 hex is 64 chars");
    assert_eq!(
        hash,
        tokens::hash_api_token(&plaintext),
        "the public hash_api_token() helper must match what generate_api_token() persisted",
    );
}

#[tokio::test]
async fn create_persists_prefix_and_hash_only() {
    let pool = common::pool().await;
    let user_id = common::make_user(&pool, "alice@example.com", "hunter22!").await;

    let (plaintext, view) = tokens::create_for_user(&pool, user_id, "laptop")
        .await
        .expect("create_for_user");

    assert_eq!(view.name, "laptop");
    assert!(plaintext.starts_with(&view.prefix));

    let (stored_hash, stored_prefix): (String, String) =
        sqlx::query_as("SELECT token_hash, prefix FROM api_keys WHERE id = $1")
            .bind(view.id)
            .fetch_one(&pool)
            .await
            .expect("fetch row");

    assert_eq!(stored_prefix, view.prefix);
    assert_eq!(
        stored_hash,
        tokens::hash_api_token(&plaintext),
        "DB stores SHA-256 hex of the plaintext",
    );
    assert!(
        !stored_hash.contains(&plaintext),
        "plaintext must never be persisted",
    );
}

#[tokio::test]
async fn create_rejects_empty_or_oversized_name() {
    let pool = common::pool().await;
    let user_id = common::make_user(&pool, "alice@example.com", "hunter22!").await;

    assert!(
        tokens::create_for_user(&pool, user_id, "   ")
            .await
            .is_err()
    );
    assert!(tokens::create_for_user(&pool, user_id, "").await.is_err());

    let too_long = "x".repeat(65);
    assert!(
        tokens::create_for_user(&pool, user_id, &too_long)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn list_returns_only_active_tokens_owned_by_caller() {
    let pool = common::pool().await;
    let alice = common::make_user(&pool, "alice@example.com", "hunter22!").await;
    let bob = common::make_user(&pool, "bob@example.com", "hunter22!").await;

    let (_, _) = tokens::create_for_user(&pool, alice, "a1").await.unwrap();
    let (_, _) = tokens::create_for_user(&pool, alice, "a2").await.unwrap();
    let (_, _) = tokens::create_for_user(&pool, bob, "b1").await.unwrap();

    let alice_list = tokens::list_for_user(&pool, alice).await.unwrap();
    let bob_list = tokens::list_for_user(&pool, bob).await.unwrap();

    assert_eq!(alice_list.len(), 2);
    assert_eq!(bob_list.len(), 1);
    assert!(alice_list.iter().all(|t| t.name.starts_with('a')));
    assert!(bob_list.iter().all(|t| t.name.starts_with('b')));
}

#[tokio::test]
async fn revoke_removes_token_from_list() {
    let pool = common::pool().await;
    let user_id = common::make_user(&pool, "alice@example.com", "hunter22!").await;

    let (_, view) = tokens::create_for_user(&pool, user_id, "to-revoke")
        .await
        .unwrap();

    let revoked = tokens::revoke_for_user(&pool, user_id, view.id)
        .await
        .unwrap();
    assert!(revoked, "first revoke succeeds");

    let listed = tokens::list_for_user(&pool, user_id).await.unwrap();
    assert!(
        listed.is_empty(),
        "revoked token must not appear in list_for_user: {listed:?}"
    );

    let again = tokens::revoke_for_user(&pool, user_id, view.id)
        .await
        .unwrap();
    assert!(!again, "second revoke is a no-op (already revoked)");
}

#[tokio::test]
async fn revoke_rejects_other_users_token() {
    let pool = common::pool().await;
    let alice = common::make_user(&pool, "alice@example.com", "hunter22!").await;
    let bob = common::make_user(&pool, "bob@example.com", "hunter22!").await;

    let (_, alice_token) = tokens::create_for_user(&pool, alice, "alice-token")
        .await
        .unwrap();

    let attempted = tokens::revoke_for_user(&pool, bob, alice_token.id)
        .await
        .unwrap();
    assert!(
        !attempted,
        "bob's revoke of alice's token must report no row updated (no info-leak)",
    );

    let alice_list = tokens::list_for_user(&pool, alice).await.unwrap();
    assert_eq!(
        alice_list.len(),
        1,
        "alice's token must still be active after bob's revoke attempt",
    );
}
