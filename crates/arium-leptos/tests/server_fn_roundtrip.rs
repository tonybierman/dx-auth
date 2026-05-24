//! End-to-end server-fn round-trip over real HTTP.
//!
//! The feature-matrix / wasm CI jobs only `cargo check` the adapter — they
//! prove it *compiles*, not that the Leptos server-fn wire path still *works*.
//! This test closes that gap: it boots the real `install`-layered axum router
//! on an ephemeral port and drives the core auth flow end to end with a cookie
//! jar — register → login → authenticated read → logout → confirm the session
//! is gone. A Leptos/`server_fn` release that silently changed the request
//! encoding, the response shape, or the session-cookie handling would turn this
//! red even though `cargo check` stayed green.
//!
//! Mounts only the server-fn route (`/api/{*fn_name}` → `handle_server_fns`),
//! not the SSR/HTML routes — the auth contract lives entirely in the server fns.
//!
//! Native-only: the tokio/axum/sqlx/reqwest stack doesn't build for wasm, and a
//! `--target wasm32` test run (see tests/wasm_client.rs) must skip this file.
#![cfg(not(target_arch = "wasm32"))]

use std::sync::Once;

use arium_leptos::{LoginOutcome, UserProfile};
// Bring the server fns into scope so their `#[server]` inventory registrations
// link into this test binary and `handle_server_fns` can dispatch to them.
#[allow(unused_imports)]
use arium_leptos::server::*;

const EMAIL: &str = "roundtrip@example.test";
const PASSWORD: &str = "hunter22!longenough";

/// Boot the real router on `127.0.0.1:0` and return its base URL
/// (e.g. `http://127.0.0.1:54321`). The server task is detached; it lives for
/// the rest of the test process, which is fine for a single short test.
async fn spawn_app() -> String {
    use axum::Router;
    use axum::routing::post;
    use leptos_axum::handle_server_fns;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

    // Auto-verify + log in on register so the flow doesn't need a real mail
    // round-trip. Read by the server fn at call time (same process).
    enable_skip_email_verification();

    // A unique on-disk sqlite file (under the OS temp dir, gitignored anyway):
    // a file lets the session layer and the request handlers each grab their
    // own pooled connection without the single-connection `:memory:` contention.
    let db_path = std::env::temp_dir().join(format!(
        "arium-leptos-roundtrip-{}-{}.db",
        std::process::id(),
        unique()
    ));
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&db_path)
                .create_if_missing(true),
        )
        .await
        .expect("connect sqlite");
    arium_leptos::migrator()
        .run(&pool)
        .await
        .expect("run migrations");

    let mailer = arium_leptos::Mailer::from_env().expect("mailer");
    let cfg = arium_leptos::AuthConfig::builder(pool, mailer)
        .build()
        .expect("build config");

    let router = Router::new().route("/api/{*fn_name}", post(handle_server_fns));
    let app = arium_leptos::install(router, cfg)
        .await
        .expect("install arium");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    format!("http://{addr}")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn register_login_profile_logout_round_trip() {
    let base = spawn_app().await;

    // --- An anonymous caller (no cookies) reads as unauthenticated. ---
    let anon = client();
    let profile: UserProfile = post_json(&anon, &base, "user/profile", None).await;
    assert!(
        !profile.is_authenticated,
        "fresh caller must be anonymous, got {profile:?}"
    );

    // --- Register: creates + (skip-verification) logs in, returns LoggedIn. ---
    let registrar = client();
    let outcome: LoginOutcome = post_form(
        &registrar,
        &base,
        "user/register-password",
        &[("email", EMAIL), ("password", PASSWORD)],
    )
    .await;
    assert_eq!(outcome, LoginOutcome::LoggedIn, "register should log in");

    // --- Login on a *fresh* client to exercise the login path + Set-Cookie. ---
    let user = client();
    let (outcome, set_cookie) = post_form_with_headers::<LoginOutcome>(
        &user,
        &base,
        "user/login-password",
        &[
            ("email", EMAIL),
            ("password", PASSWORD),
            ("remember_me", "false"),
        ],
    )
    .await;
    assert_eq!(outcome, LoginOutcome::LoggedIn, "login should succeed");
    assert!(
        set_cookie,
        "a successful login must issue a session Set-Cookie"
    );

    // --- The authenticated read now reflects the logged-in identity. ---
    let profile: UserProfile = post_json(&user, &base, "user/profile", None).await;
    assert!(
        profile.is_authenticated,
        "should be authenticated post-login"
    );
    assert_eq!(
        profile.email.as_deref(),
        Some(EMAIL),
        "profile should carry the registered email"
    );

    // --- Logout, then confirm the session is gone on the same client. ---
    let _: () = post_json(&user, &base, "user/logout", None).await;
    let profile: UserProfile = post_json(&user, &base, "user/profile", None).await;
    assert!(
        !profile.is_authenticated,
        "must be anonymous again after logout, got {profile:?}"
    );
}

// ----- helpers -----

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .expect("build client")
}

/// POST a form-encoded body and deserialize the JSON response into `T`.
async fn post_form<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    base: &str,
    endpoint: &str,
    form: &[(&str, &str)],
) -> T {
    post_form_with_headers::<T>(client, base, endpoint, form)
        .await
        .0
}

/// Like [`post_form`] but also reports whether the response carried a
/// `Set-Cookie` header (used to assert the session cookie was issued).
async fn post_form_with_headers<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    base: &str,
    endpoint: &str,
    form: &[(&str, &str)],
) -> (T, bool) {
    let resp = client
        .post(format!("{base}/api/{endpoint}"))
        .form(form)
        .send()
        .await
        .unwrap_or_else(|e| panic!("POST {endpoint}: {e}"));
    let set_cookie = resp.headers().contains_key(reqwest::header::SET_COOKIE);
    let status = resp.status();
    let body = resp.text().await.expect("read body");
    assert!(status.is_success(), "POST {endpoint} -> {status}: {body}");
    let value = deserialize(&body, endpoint);
    (value, set_cookie)
}

/// POST with an optional JSON body (for no-arg server fns, pass `None`) and
/// deserialize the JSON response into `T`.
async fn post_json<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    base: &str,
    endpoint: &str,
    body: Option<serde_json::Value>,
) -> T {
    let mut req = client.post(format!("{base}/api/{endpoint}"));
    if let Some(b) = body {
        req = req.json(&b);
    }
    let resp = req
        .send()
        .await
        .unwrap_or_else(|e| panic!("POST {endpoint}: {e}"));
    let status = resp.status();
    let text = resp.text().await.expect("read body");
    assert!(status.is_success(), "POST {endpoint} -> {status}: {text}");
    deserialize(&text, endpoint)
}

/// Server fns whose return is `()` produce an empty body; everything else is
/// JSON. Handle both so a `()` endpoint (logout) and a struct endpoint
/// (profile) go through the same helper.
fn deserialize<T: serde::de::DeserializeOwned>(body: &str, endpoint: &str) -> T {
    if body.trim().is_empty() {
        // `serde_json::from_str("null")` yields `()` for the unit type.
        return serde_json::from_str("null")
            .unwrap_or_else(|e| panic!("decode empty body for {endpoint}: {e}"));
    }
    serde_json::from_str(body).unwrap_or_else(|e| panic!("decode {endpoint} body `{body}`: {e}"))
}

fn enable_skip_email_verification() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // SAFETY: set once, before any server fn runs; no other thread is
        // reading the process env at this point.
        unsafe {
            std::env::set_var("DX_AUTH_SKIP_EMAIL_VERIFICATION", "1");
        }
    });
}

/// Monotonic-ish unique suffix for the temp DB filename.
fn unique() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}
