//! Shared in-process HTTP harness for the arium-dioxus integration tests.
//!
//! Boots the real `install`-layered Dioxus server-fn router on an ephemeral
//! port and drives it with a `reqwest` cookie jar — the same approach the
//! round-trip test pioneered, lifted here so `server_fn_roundtrip.rs` and
//! `access_control.rs` share one copy instead of each inlining it.
//!
//! Native-only: the dioxus/server + tokio/sqlx/reqwest stack doesn't build for
//! wasm. Every test file that does `mod common;` is itself `cfg`-guarded with
//! `#![cfg(not(target_arch = "wasm32"))]`, so this module only ever compiles
//! into the native test binaries.
#![allow(dead_code)] // not every test binary uses every helper

use std::sync::Once;

use arium_dioxus::LoginOutcome;
use reqwest::StatusCode;

/// Boot the real router on `127.0.0.1:0` and return its base URL
/// (e.g. `http://127.0.0.1:54321`). The server task is detached; it lives for
/// the rest of the (single, short) test process.
pub async fn spawn_app() -> String {
    use axum::Router;
    use dioxus::server::{DioxusRouterExt, FullstackState};
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

    // Auto-verify + log in on register so flows need no real mail round-trip.
    // Read by the server fn at call time (same process).
    enable_skip_email_verification();

    // A unique on-disk sqlite file (under the OS temp dir, gitignored anyway):
    // a file lets the session layer and the request handlers each grab their
    // own pooled connection without the single-connection `:memory:` contention.
    let db_path = std::env::temp_dir().join(format!(
        "arium-dioxus-itest-{}-{}.db",
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
    arium_dioxus::migrator()
        .run(&pool)
        .await
        .expect("run migrations");

    // `AuthConfig::builder` takes a mailer only when the `mail` feature is on;
    // gate the construction so this harness boots under both feature sets (the
    // round-trip test runs under `mail` in CI and under `--no-default-features`
    // to exercise the no-mail register path).
    #[cfg(feature = "mail")]
    let builder = {
        let mailer = arium_dioxus::Mailer::from_env().expect("mailer");
        arium_dioxus::AuthConfig::builder(pool, mailer)
    };
    #[cfg(not(feature = "mail"))]
    let builder = arium_dioxus::AuthConfig::builder(pool);
    // Determinism: turn rate limiting off so a fast multi-endpoint sweep can't
    // drain the tower_governor burst and mask an auth gate behind a 429. The
    // `ratelimit` feature is on by default, so this is gated to match.
    #[cfg(feature = "ratelimit")]
    let builder = builder.rate_limit(None);
    let cfg = builder.build().expect("build config");

    // Register every collected server fn onto a headless state (no asset dir /
    // SSR render fallback), then layer the engine over it.
    let router = Router::<FullstackState>::new()
        .register_server_functions()
        .with_state(FullstackState::headless());
    let app = arium_dioxus::install(router, cfg)
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

/// A fresh cookie-jar client. Two `client()`s are two independent sessions.
pub fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .expect("build client")
}

// ----- raw requests (no success assertion — callers decide what's expected) --

/// POST a JSON body (Dioxus `#[post]` default encoding). Returns the status,
/// the body text, and whether a `Set-Cookie` came back.
pub async fn post_json_raw(
    client: &reqwest::Client,
    base: &str,
    path: &str,
    body: serde_json::Value,
) -> (StatusCode, String, bool) {
    let resp = client
        .post(format!("{base}{path}"))
        .json(&body)
        .send()
        .await
        .unwrap_or_else(|e| panic!("POST {path}: {e}"));
    let set_cookie = resp.headers().contains_key(reqwest::header::SET_COOKIE);
    let status = resp.status();
    let text = resp.text().await.expect("read body");
    (status, text, set_cookie)
}

/// GET (Dioxus `#[get]` default encoding — no body). Returns status + body text.
pub async fn get_raw(client: &reqwest::Client, base: &str, path: &str) -> (StatusCode, String) {
    let resp = client
        .get(format!("{base}{path}"))
        .send()
        .await
        .unwrap_or_else(|e| panic!("GET {path}: {e}"));
    let status = resp.status();
    let text = resp.text().await.expect("read body");
    (status, text)
}

// ----- typed wrappers (used by the round-trip test) --------------------------

/// POST JSON, assert 2xx, and deserialize the response into `T`. Also reports
/// whether a `Set-Cookie` came back.
pub async fn post_json<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    base: &str,
    path: &str,
    body: serde_json::Value,
) -> (T, bool) {
    let (status, text, set_cookie) = post_json_raw(client, base, path, body).await;
    assert!(status.is_success(), "POST {path} -> {status}: {text}");
    (deserialize(&text, path), set_cookie)
}

/// GET, assert 2xx, and deserialize the response into `T`.
pub async fn get_json<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    base: &str,
    path: &str,
) -> T {
    let (status, text) = get_raw(client, base, path).await;
    assert!(status.is_success(), "GET {path} -> {status}: {text}");
    deserialize(&text, path)
}

/// Server fns whose return is `()` produce an empty body; everything else is
/// JSON. Handle both so `()` (logout) and a struct (profile) share one helper.
pub fn deserialize<T: serde::de::DeserializeOwned>(body: &str, path: &str) -> T {
    if body.trim().is_empty() {
        return serde_json::from_str("null")
            .unwrap_or_else(|e| panic!("decode empty body for {path}: {e}"));
    }
    serde_json::from_str(body).unwrap_or_else(|e| panic!("decode {path} body `{body}`: {e}"))
}

// ----- auth-flow helpers (used by the access-control test) -------------------

/// Register a password user. With skip-email-verification on (see `spawn_app`),
/// this also logs the caller in and sets the session cookie on `client`.
pub async fn register(
    client: &reqwest::Client,
    base: &str,
    email: &str,
    password: &str,
) -> LoginOutcome {
    post_json(
        client,
        base,
        "/api/user/register-password",
        serde_json::json!({ "email": email, "password": password }),
    )
    .await
    .0
}

/// Log in a password user on `client`, returning the outcome and whether a
/// session `Set-Cookie` was issued.
pub async fn login(
    client: &reqwest::Client,
    base: &str,
    email: &str,
    password: &str,
) -> (LoginOutcome, bool) {
    post_json(
        client,
        base,
        "/api/user/login-password",
        serde_json::json!({ "email": email, "password": password, "remember_me": false }),
    )
    .await
}

/// arium grants the `admin` role to the FIRST account on a fresh DB
/// (`auth::maybe_grant_first_admin`, "first-user-wins"). Claim that slot with a
/// sacrificial admin on a throwaway client so any user registered afterward is
/// a genuine non-admin. Idempotent on a populated DB.
pub async fn claim_first_admin_slot(base: &str) {
    let throwaway = client();
    register(
        &throwaway,
        base,
        "admin-bootstrap@example.test",
        "Bootstrap-Admin-1!",
    )
    .await;
}

/// The auth-gate rejection markers `arium` emits (mirrors the shell probe's
/// `DENY_RE`). A match proves the gate itself rejected the call.
pub fn has_deny_marker(body: &str) -> bool {
    const MARKERS: &[&str] = &[
        "not signed in",
        "permission for this action",
        "don't have permission",
        "unauthorized",
        "forbidden",
        "not authenticated",
    ];
    let b = body.to_ascii_lowercase();
    MARKERS.iter().any(|m| b.contains(m))
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

/// Process-unique suffix for the temp DB filename. A bare wall-clock reading
/// isn't enough: two tests spawning in the same nanosecond under parallel
/// execution would collide on one DB file and run migrations concurrently
/// against it (observed as a spurious "duplicate column" migration error). The
/// monotonic counter guarantees uniqueness within the process; the clock keeps
/// names readable and time-ordered.
fn unique() -> u128 {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed) as u128;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    nanos.wrapping_mul(1_000_000).wrapping_add(seq)
}
