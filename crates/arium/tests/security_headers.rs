//! Verifies [`arium::install`] stamps security response headers onto every
//! response: a behavior-safe static set always, and `Strict-Transport-Security`
//! / `Content-Security-Policy` only when opted into via the builder.

mod common;

use std::net::SocketAddr;

use arium::{AuditConfig, AuthConfig, Mailer, RECOMMENDED_HSTS};
use axum::Router;
use axum::routing::get;
use reqwest::Client;
use tokio::net::TcpListener;

/// Boot the arium router (plus one trivial probe route) on an ephemeral port.
/// `customize` lets a test layer extra builder settings (e.g. HSTS / CSP).
async fn boot(
    customize: impl FnOnce(arium::AuthConfigBuilder) -> arium::AuthConfigBuilder,
) -> String {
    let pool = common::pool().await;
    let mailer = Mailer::from_env().expect("mailer build");

    let builder = AuthConfig::builder(pool, mailer)
        // Trim noise unrelated to header behavior.
        .rate_limit(None)
        .audit(AuditConfig {
            capture_ip: false,
            capture_user_agent: false,
            retention_days: 0,
        });
    let cfg = customize(builder).build().unwrap();

    // A plain route so the response is ours, not a 404 — headers must land
    // regardless of which handler produced the response.
    let router: Router =
        arium::install(Router::new().route("/__ping", get(|| async { "ok" })), cfg)
            .await
            .expect("install");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });

    format!("http://{addr}")
}

/// Pull the `Set-Cookie` line for the *session* cookie specifically (the
/// response also sets axum_session's separate `store` cookie, which is always
/// `SameSite=None; Secure` and isn't what we're asserting on).
fn session_set_cookie(resp: &reqwest::Response) -> String {
    resp.headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .find(|c| c.starts_with("session="))
        .expect("a session= Set-Cookie header")
}

#[tokio::test]
async fn session_cookie_is_lax_httponly_and_insecure_by_default() {
    let base = boot(|b| b).await;
    let resp = Client::new()
        .get(format!("{base}/__ping"))
        .send()
        .await
        .expect("request");
    let cookie = session_set_cookie(&resp);

    // SameSite stays Lax (Strict would break the OAuth callback redirect).
    assert!(cookie.contains("SameSite=Lax"), "{cookie}");
    assert!(cookie.contains("HttpOnly"), "{cookie}");
    // Secure is opt-in, so it must be absent on a default (dev) build.
    assert!(
        !cookie.to_lowercase().contains("secure"),
        "session cookie should not be Secure by default: {cookie}"
    );
}

#[tokio::test]
async fn session_cookie_secure_when_opted_in() {
    let base = boot(|b| b.cookie_secure(true)).await;
    let resp = Client::new()
        .get(format!("{base}/__ping"))
        .send()
        .await
        .expect("request");
    let cookie = session_set_cookie(&resp);

    assert!(cookie.contains("Secure"), "{cookie}");
    // Still Lax + HttpOnly — enabling Secure changes nothing else.
    assert!(cookie.contains("SameSite=Lax"), "{cookie}");
    assert!(cookie.contains("HttpOnly"), "{cookie}");
}

#[tokio::test]
async fn static_security_headers_present_by_default() {
    let base = boot(|b| b).await;
    let resp = Client::new()
        .get(format!("{base}/__ping"))
        .send()
        .await
        .expect("request");
    let h = resp.headers();

    assert_eq!(h.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(
        h.get("referrer-policy").unwrap(),
        "strict-origin-when-cross-origin"
    );
    assert_eq!(h.get("x-frame-options").unwrap(), "SAMEORIGIN");
    assert_eq!(h.get("cross-origin-opener-policy").unwrap(), "same-origin");
    assert_eq!(h.get("x-permitted-cross-domain-policies").unwrap(), "none");
    assert_eq!(
        h.get("permissions-policy").unwrap(),
        "camera=(), microphone=(), geolocation=()"
    );

    // Opt-in headers must stay absent until configured.
    assert!(h.get("strict-transport-security").is_none());
    assert!(h.get("content-security-policy").is_none());
}

#[tokio::test]
async fn hsts_and_csp_emitted_when_opted_in() {
    let csp = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'";
    let base = boot(|b| b.hsts(RECOMMENDED_HSTS).content_security_policy(csp)).await;
    let resp = Client::new()
        .get(format!("{base}/__ping"))
        .send()
        .await
        .expect("request");
    let h = resp.headers();

    assert_eq!(
        h.get("strict-transport-security").unwrap(),
        RECOMMENDED_HSTS
    );
    assert_eq!(h.get("content-security-policy").unwrap(), csp);
    // Static set still present alongside the opt-ins.
    assert_eq!(h.get("x-content-type-options").unwrap(), "nosniff");
}
