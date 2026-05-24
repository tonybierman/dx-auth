//! OIDC provider integration tests.
//!
//! Discovery + authorize-URL construction are exercised against a `wiremock`
//! server that serves a synthetic `.well-known/openid-configuration` + JWKS.
//! The pure claims→profile normalisation is unit-tested inside
//! `src/oauth/oidc.rs`; full `id_token` signature verification is covered there
//! at the type level (minting a signed token with a matching nonce in a
//! black-box flow test buys little over the unit + discovery coverage here).

#![cfg(feature = "oauth-oidc")]

use arium::oauth::OAuthProvider;
use arium::oauth::oidc::{OidcConfig, OidcProvider};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn mount_discovery(mock: &MockServer) -> String {
    let issuer = mock.uri();
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "userinfo_endpoint": format!("{issuer}/userinfo"),
            "jwks_uri": format!("{issuer}/jwks"),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        })))
        .mount(mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [] })))
        .mount(mock)
        .await;
    issuer
}

#[tokio::test]
async fn discover_parses_endpoints_and_builds_provider() {
    let mock = MockServer::start().await;
    let issuer = mount_discovery(&mock).await;

    let provider = OidcProvider::discover(OidcConfig {
        name: "acme".to_string(),
        display_name: "Acme SSO".to_string(),
        icon_svg: None,
        issuer_url: issuer.clone(),
        client_id: "cid".to_string(),
        client_secret: "csecret".to_string(),
        redirect_url: format!("{issuer}/auth/acme/callback"),
        scopes: vec![], // -> default openid email profile
    })
    .await
    .expect("discovery should succeed against the mock issuer");

    assert_eq!(provider.name(), "acme");
    assert_eq!(provider.display_name(), "Acme SSO");
}

#[tokio::test]
async fn begin_emits_pkce_challenge_and_nonce_at_discovered_endpoint() {
    let mock = MockServer::start().await;
    let issuer = mount_discovery(&mock).await;

    let provider = OidcProvider::discover(OidcConfig {
        name: "acme".to_string(),
        display_name: "Acme SSO".to_string(),
        icon_svg: None,
        issuer_url: issuer.clone(),
        client_id: "cid".to_string(),
        client_secret: "csecret".to_string(),
        redirect_url: format!("{issuer}/auth/acme/callback"),
        scopes: vec![],
    })
    .await
    .unwrap();

    let (url, attempt) = provider.begin().expect("begin builds the authorize URL");

    assert!(
        url.starts_with(&format!("{issuer}/authorize")),
        "authorize URL should point at the discovered endpoint: {url}"
    );
    assert!(
        url.contains("code_challenge="),
        "PKCE challenge expected: {url}"
    );
    assert!(
        url.contains("code_challenge_method=S256"),
        "S256 expected: {url}"
    );
    assert!(url.contains("scope=openid"), "openid scope expected: {url}");

    // OIDC always uses PKCE + a nonce; both must be persisted for the callback.
    assert!(attempt.pkce_verifier.is_some(), "verifier must be stored");
    assert!(attempt.nonce.is_some(), "nonce must be stored");
    assert!(!attempt.csrf_state.is_empty(), "csrf state must be stored");
}

#[tokio::test]
async fn discover_fails_for_unreachable_issuer() {
    // Nothing mounted at this issuer → discovery must error (fail-fast at
    // construction), not silently succeed.
    let mock = MockServer::start().await;
    let issuer = mock.uri();

    let result = OidcProvider::discover(OidcConfig {
        name: "acme".to_string(),
        display_name: "Acme SSO".to_string(),
        icon_svg: None,
        issuer_url: issuer.clone(),
        client_id: "cid".to_string(),
        client_secret: "csecret".to_string(),
        redirect_url: format!("{issuer}/auth/acme/callback"),
        scopes: vec![],
    })
    .await;

    assert!(
        result.is_err(),
        "discovery against an empty issuer must fail"
    );
}
