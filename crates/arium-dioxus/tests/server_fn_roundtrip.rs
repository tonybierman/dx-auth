//! End-to-end server-fn round-trip over real HTTP.
//!
//! The feature-matrix / wasm CI jobs only `cargo check` the adapter — they
//! prove it *compiles*, not that the Dioxus server-fn wire path still *works*.
//! This test closes that gap: it boots the real `install`-layered dioxus server
//! router on an ephemeral port and drives the core auth flow end to end with a
//! cookie jar — register → login → authenticated read → logout → confirm the
//! session is gone. A Dioxus/`server_fn` release that silently changed the
//! request encoding, the response shape, or the session-cookie handling would
//! turn this red even though `cargo check` stayed green.
//!
//! Built from the same `DioxusRouterExt::register_server_functions` the example
//! server uses under the hood — every `#[post]`/`#[get]` server fn is collected
//! from the inventory and routed — but onto a `FullstackState::headless()` so
//! the test needs no `public/` asset dir or SSR render config (the full
//! `dioxus::server::router(app)` insists on a built client). Unlike the Leptos
//! adapter, Dioxus `#[post]` fns take a JSON body and `#[get]` fns (the profile
//! read) take none — so the helpers below mirror that split.
//!
//! Native-only: the dioxus/server + tokio/sqlx/reqwest stack doesn't build for
//! wasm, and a `--target wasm32` test run (tests/wasm_client.rs) must skip this.
#![cfg(not(target_arch = "wasm32"))]

use std::sync::Once;

use arium_dioxus::{LoginOutcome, UserProfile};
// Bring the server fns into scope so their inventory registrations link into
// this test binary and `register_server_functions` can collect them.
#[allow(unused_imports)]
use arium_dioxus::server::*;

const EMAIL: &str = "roundtrip@example.test";
const PASSWORD: &str = "hunter22!longenough";

/// Boot the real router on `127.0.0.1:0` and return its base URL. The server
/// task is detached; it lives for the rest of the (single, short) test process.
async fn spawn_app() -> String {
    use axum::Router;
    use dioxus::server::{DioxusRouterExt, FullstackState};
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

    // Auto-verify + log in on register so the flow needs no real mail
    // round-trip. Read by the server fn at call time (same process).
    enable_skip_email_verification();

    // A unique on-disk sqlite file (under the OS temp dir, gitignored anyway):
    // a file lets the session layer and the request handlers each grab their
    // own pooled connection without the single-connection `:memory:` contention.
    let db_path = std::env::temp_dir().join(format!(
        "arium-dioxus-roundtrip-{}-{}.db",
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

    let mailer = arium_dioxus::Mailer::from_env().expect("mailer");
    let cfg = arium_dioxus::AuthConfig::builder(pool, mailer)
        .build()
        .expect("build config");

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn register_login_profile_logout_round_trip() {
    let base = spawn_app().await;

    // --- An anonymous caller (no cookies) reads as unauthenticated. ---
    let anon = client();
    let profile: UserProfile = get_json(&anon, &base, "/api/user/profile").await;
    assert!(
        !profile.is_authenticated,
        "fresh caller must be anonymous, got {profile:?}"
    );

    // --- Register: creates + (skip-verification) logs in, returns LoggedIn. ---
    let registrar = client();
    let outcome: LoginOutcome = post_json(
        &registrar,
        &base,
        "/api/user/register-password",
        serde_json::json!({ "email": EMAIL, "password": PASSWORD }),
    )
    .await
    .0;
    assert_eq!(outcome, LoginOutcome::LoggedIn, "register should log in");

    // --- Login on a *fresh* client to exercise the login path + Set-Cookie. ---
    let user = client();
    let (outcome, set_cookie) = post_json::<LoginOutcome>(
        &user,
        &base,
        "/api/user/login-password",
        serde_json::json!({ "email": EMAIL, "password": PASSWORD, "remember_me": false }),
    )
    .await;
    assert_eq!(outcome, LoginOutcome::LoggedIn, "login should succeed");
    assert!(
        set_cookie,
        "a successful login must issue a session Set-Cookie"
    );

    // --- The authenticated read now reflects the logged-in identity. ---
    let profile: UserProfile = get_json(&user, &base, "/api/user/profile").await;
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
    let _: () = post_json(&user, &base, "/api/user/logout", serde_json::json!({}))
        .await
        .0;
    let profile: UserProfile = get_json(&user, &base, "/api/user/profile").await;
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

/// POST a JSON body (Dioxus `#[post]` default encoding) and deserialize the
/// JSON response into `T`. Also reports whether a `Set-Cookie` came back.
async fn post_json<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    base: &str,
    path: &str,
    body: serde_json::Value,
) -> (T, bool) {
    let resp = client
        .post(format!("{base}{path}"))
        .json(&body)
        .send()
        .await
        .unwrap_or_else(|e| panic!("POST {path}: {e}"));
    let set_cookie = resp.headers().contains_key(reqwest::header::SET_COOKIE);
    let status = resp.status();
    let text = resp.text().await.expect("read body");
    assert!(status.is_success(), "POST {path} -> {status}: {text}");
    (deserialize(&text, path), set_cookie)
}

/// GET (Dioxus `#[get]` default encoding) and deserialize the JSON response.
async fn get_json<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    base: &str,
    path: &str,
) -> T {
    let resp = client
        .get(format!("{base}{path}"))
        .send()
        .await
        .unwrap_or_else(|e| panic!("GET {path}: {e}"));
    let status = resp.status();
    let text = resp.text().await.expect("read body");
    assert!(status.is_success(), "GET {path} -> {status}: {text}");
    deserialize(&text, path)
}

/// Server fns whose return is `()` produce an empty body; everything else is
/// JSON. Handle both so `()` (logout) and a struct (profile) share one helper.
fn deserialize<T: serde::de::DeserializeOwned>(body: &str, path: &str) -> T {
    if body.trim().is_empty() {
        return serde_json::from_str("null")
            .unwrap_or_else(|e| panic!("decode empty body for {path}: {e}"));
    }
    serde_json::from_str(body).unwrap_or_else(|e| panic!("decode {path} body `{body}`: {e}"))
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
