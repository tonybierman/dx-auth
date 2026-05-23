//! End-to-end OAuth callback against a `wiremock` token endpoint.
//!
//! The unit-level `oauth_link.rs` tests already cover the DB upsert
//! semantics. This file targets the *axum-layer* code path that the
//! upsert tests can't reach:
//!
//! - Authorize URL generation (scopes + CSRF state)
//! - State persistence across the login → callback round trip via the
//!   session cookie
//! - State mismatch and missing-state error branches
//! - Token-exchange success against a controlled `/token` endpoint
//! - Token-exchange failure (provider 5xx / malformed body → 502)
//! - Audit `user.login.success` emission on the happy path
//!
//! We do NOT mock the user-info endpoint over HTTP — the provider trait's
//! `fetch_profile` is a Rust function and the mock returns a profile
//! directly. That keeps the test focused on the OAuth wire shape that
//! lives in `oauth.rs::oauth_callback`.

#![cfg(feature = "oauth-github")]

mod common;

use async_trait::async_trait;
use axum::Router;
use dx_auth::oauth::{NormalizedProfile, OAuthProvider};
use dx_auth::{AuditConfig, AuthConfig, Mailer};
use reqwest::Client;
use reqwest::redirect::Policy;
use serde_json::json;
use sqlx::SqlitePool;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ============================================================
// Mock provider — parameterizable URLs so each test can swap the
// wiremock-backed token endpoint without rebuilding the registry shape.
// ============================================================

struct MockProvider {
    name: &'static str,
    auth_url: String,
    token_url: String,
    redirect_url: String,
    profile: NormalizedProfile,
}

#[async_trait]
impl OAuthProvider for MockProvider {
    fn name(&self) -> &str {
        self.name
    }
    fn display_name(&self) -> &str {
        "Test"
    }
    fn client_id(&self) -> &str {
        "test-client-id"
    }
    fn client_secret(&self) -> &str {
        "test-client-secret"
    }
    fn redirect_url(&self) -> &str {
        &self.redirect_url
    }
    fn auth_url(&self) -> &str {
        &self.auth_url
    }
    fn token_url(&self) -> &str {
        &self.token_url
    }
    fn scopes(&self) -> &[&str] {
        &["read:user", "user:email"]
    }
    async fn fetch_profile(
        &self,
        _http: &reqwest::Client,
        _access_token: &str,
    ) -> anyhow::Result<NormalizedProfile> {
        Ok(self.profile.clone())
    }
}

// ============================================================
// Test app bootstrap — stand up the dx-auth Router on 127.0.0.1:<rand>,
// return the pool, base URL, and a cookie-jar reqwest client.
// ============================================================

struct TestApp {
    pool: SqlitePool,
    base_url: String,
    client: Client,
    _serve: tokio::task::JoinHandle<()>,
}

async fn boot(mock_token_url: &str, profile: NormalizedProfile) -> TestApp {
    let pool = common::pool().await;
    let mailer = Mailer::from_env().expect("mailer build");

    let provider = MockProvider {
        name: "test",
        // We never follow this URL — the test calls /callback directly.
        auth_url: "https://example.invalid/authorize".to_string(),
        token_url: mock_token_url.to_string(),
        redirect_url: "http://127.0.0.1/auth/test/callback".to_string(),
        profile,
    };

    let cfg = AuthConfig::builder(pool.clone(), mailer)
        .oauth_provider(provider)
        .unwrap()
        // Disable rate limiting + audit prune — extra noise for these tests.
        .rate_limit(None)
        .audit(AuditConfig {
            capture_ip: false,
            capture_user_agent: false,
            retention_days: 0,
        })
        .build()
        .unwrap();

    let router: Router = dx_auth::install(Router::new(), cfg).await.expect("install");

    // Bind to an ephemeral port so parallel tests don't collide.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("local_addr");
    let base_url = format!("http://{addr}");

    let serve = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });

    let client = Client::builder()
        .cookie_store(true)
        .redirect(Policy::none())
        .build()
        .expect("client");

    TestApp {
        pool,
        base_url,
        client,
        _serve: serve,
    }
}

fn standard_profile() -> NormalizedProfile {
    NormalizedProfile {
        provider_user_id: "ext-1".to_string(),
        login: "testuser".to_string(),
        name: Some("Test User".to_string()),
        email: Some("test@example.invalid".to_string()),
        avatar_url: None,
        html_url: None,
    }
}

// ============================================================
// Tests
// ============================================================

#[tokio::test]
async fn login_redirects_to_authorize_url_with_state_and_scopes() {
    // No mock needed for the login leg — login doesn't call out.
    let app = boot("http://localhost:1/unused", standard_profile()).await;

    let resp = app
        .client
        .get(format!("{}/auth/test/login", app.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 303); // axum::response::Redirect::to is 303

    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    let parsed = url::Url::parse(loc).expect("location is a URL");
    assert_eq!(parsed.host_str(), Some("example.invalid"));
    assert_eq!(parsed.path(), "/authorize");

    let q: std::collections::HashMap<_, _> = parsed.query_pairs().collect();
    assert_eq!(q.get("response_type").map(|s| s.as_ref()), Some("code"));
    assert_eq!(
        q.get("client_id").map(|s| s.as_ref()),
        Some("test-client-id")
    );
    assert!(q.contains_key("state"), "state must be present");
    let scope = q.get("scope").map(|s| s.to_string()).unwrap_or_default();
    assert!(scope.contains("read:user"), "scope={scope:?}");
    assert!(scope.contains("user:email"), "scope={scope:?}");
}

#[tokio::test]
async fn callback_happy_path_creates_user_and_records_audit_event() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "test-access-token",
            "token_type": "bearer",
            "scope": "read:user",
        })))
        .expect(1)
        .mount(&mock)
        .await;

    let app = boot(&format!("{}/token", mock.uri()), standard_profile()).await;

    // Step 1: login leg, captures the session cookie + the state.
    let resp = app
        .client
        .get(format!("{}/auth/test/login", app.base_url))
        .send()
        .await
        .unwrap();
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    let parsed = url::Url::parse(loc).unwrap();
    let state = parsed
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.to_string())
        .unwrap();

    // Step 2: synthesize the provider callback. Cookie jar replays the
    // session cookie from step 1 automatically.
    let resp = app
        .client
        .get(format!(
            "{}/auth/test/callback?code=fake-code&state={state}",
            app.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        303,
        "callback success redirects to /"
    );
    assert_eq!(
        resp.headers().get("location").unwrap().to_str().unwrap(),
        "/"
    );

    // The upsert ran: user + oauth_accounts row exist.
    let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE anonymous = false")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(user_count, 1);

    let oa: (String, String) =
        sqlx::query_as("SELECT provider, provider_user_id FROM oauth_accounts LIMIT 1")
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(oa, ("test".to_string(), "ext-1".to_string()));

    // Audit event recorded with method=oauth in the details JSON.
    let row: (String, Option<String>) = sqlx::query_as(
        "SELECT event_type, details FROM audit_events \
         WHERE event_type = 'user.login.success' LIMIT 1",
    )
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(row.0, "user.login.success");
    let details = row.1.unwrap_or_default();
    assert!(details.contains("\"method\":\"oauth\""), "{details}");
    assert!(details.contains("\"provider\":\"test\""), "{details}");
}

#[tokio::test]
async fn callback_with_no_session_returns_400_missing_state() {
    // No prior /login call, so no `oauth_state:test` in the session.
    let app = boot("http://localhost:1/unused", standard_profile()).await;

    let resp = app
        .client
        .get(format!(
            "{}/auth/test/callback?code=fake&state=anything",
            app.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
    let body = resp.text().await.unwrap();
    assert!(body.contains("missing oauth state"), "body={body:?}");
}

#[tokio::test]
async fn callback_with_state_mismatch_returns_400() {
    let app = boot("http://localhost:1/unused", standard_profile()).await;

    // Establish a session via /login so the state cookie exists.
    app.client
        .get(format!("{}/auth/test/login", app.base_url))
        .send()
        .await
        .unwrap();

    // Hit /callback with a *wrong* state.
    let resp = app
        .client
        .get(format!(
            "{}/auth/test/callback?code=fake&state=not-the-real-state",
            app.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
    let body = resp.text().await.unwrap();
    assert!(body.contains("state mismatch"), "body={body:?}");
}

#[tokio::test]
async fn callback_state_is_consumed_after_one_attempt() {
    // The state must be single-use: even a *correct* state replay after a
    // failed attempt should now miss because the handler removes the state
    // from the session before checking it. Verifies the
    // `session.remove(&state_key)` line in `oauth_callback`.
    let app = boot("http://localhost:1/unused", standard_profile()).await;

    let resp = app
        .client
        .get(format!("{}/auth/test/login", app.base_url))
        .send()
        .await
        .unwrap();
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    let state = url::Url::parse(loc)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.to_string())
        .unwrap();

    // First attempt with a wrong state → 400, but session.remove fired.
    let _ = app
        .client
        .get(format!(
            "{}/auth/test/callback?code=x&state=wrong",
            app.base_url
        ))
        .send()
        .await
        .unwrap();

    // Now a second attempt with the *correct* state must fail too — the
    // state's already been pulled from the session.
    let resp = app
        .client
        .get(format!(
            "{}/auth/test/callback?code=x&state={state}",
            app.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
    let body = resp.text().await.unwrap();
    assert!(body.contains("missing oauth state"), "body={body:?}");
}

#[tokio::test]
async fn callback_when_token_endpoint_returns_500_returns_502() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(500).set_body_string("upstream boom"))
        .mount(&mock)
        .await;

    let app = boot(&format!("{}/token", mock.uri()), standard_profile()).await;

    // Establish state.
    let resp = app
        .client
        .get(format!("{}/auth/test/login", app.base_url))
        .send()
        .await
        .unwrap();
    let state = url::Url::parse(resp.headers().get("location").unwrap().to_str().unwrap())
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.to_string())
        .unwrap();

    let resp = app
        .client
        .get(format!(
            "{}/auth/test/callback?code=x&state={state}",
            app.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        502,
        "provider 5xx must surface as Bad Gateway",
    );
}

#[tokio::test]
async fn callback_with_malformed_token_body_returns_502() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("this is not json")
                .insert_header("content-type", "application/json"),
        )
        .mount(&mock)
        .await;

    let app = boot(&format!("{}/token", mock.uri()), standard_profile()).await;

    let resp = app
        .client
        .get(format!("{}/auth/test/login", app.base_url))
        .send()
        .await
        .unwrap();
    let state = url::Url::parse(resp.headers().get("location").unwrap().to_str().unwrap())
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.to_string())
        .unwrap();

    let resp = app
        .client
        .get(format!(
            "{}/auth/test/callback?code=x&state={state}",
            app.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 502);
}

#[tokio::test]
async fn callback_for_unknown_provider_returns_404() {
    let app = boot("http://localhost:1/unused", standard_profile()).await;
    let resp = app
        .client
        .get(format!(
            "{}/auth/nosuch/callback?code=x&state=y",
            app.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404);
}

#[tokio::test]
async fn login_for_unknown_provider_returns_404() {
    let app = boot("http://localhost:1/unused", standard_profile()).await;
    let resp = app
        .client
        .get(format!("{}/auth/nosuch/login", app.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404);
}

#[tokio::test]
async fn token_request_carries_client_credentials_and_code() {
    // Verify the wire shape of the outbound token request: client id +
    // secret as HTTP Basic, `code` + `grant_type=authorization_code` in
    // the form body. This is the bit the oauth2 crate owns, but a regression
    // in our wiring (e.g. swapping client id/secret) would slip past unit
    // tests of `upsert_oauth_user`.
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(wiremock::matchers::body_string_contains(
            "grant_type=authorization_code",
        ))
        .and(wiremock::matchers::body_string_contains("code=fake-code"))
        .and(wiremock::matchers::header(
            "authorization",
            // base64("test-client-id:test-client-secret")
            "Basic dGVzdC1jbGllbnQtaWQ6dGVzdC1jbGllbnQtc2VjcmV0",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "tok",
            "token_type": "bearer",
        })))
        .expect(1)
        .mount(&mock)
        .await;

    let app = boot(&format!("{}/token", mock.uri()), standard_profile()).await;
    let resp = app
        .client
        .get(format!("{}/auth/test/login", app.base_url))
        .send()
        .await
        .unwrap();
    let state = url::Url::parse(resp.headers().get("location").unwrap().to_str().unwrap())
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.to_string())
        .unwrap();
    let resp = app
        .client
        .get(format!(
            "{}/auth/test/callback?code=fake-code&state={state}",
            app.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 303);
    // Mock's `.expect(1)` is verified on drop.
    drop(app);
    drop(mock);
}
