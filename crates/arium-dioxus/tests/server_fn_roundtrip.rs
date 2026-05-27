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
//! The harness (`spawn_app` + request helpers) lives in `common/mod.rs`, shared
//! with `access_control.rs`. `spawn_app` builds the router from the same
//! `DioxusRouterExt::register_server_functions` the example server uses under
//! the hood — every `#[post]`/`#[get]` server fn is collected from the
//! inventory and routed — onto a `FullstackState::headless()` so the test needs
//! no `public/` asset dir or SSR render config.
//!
//! Native-only: the dioxus/server + tokio/sqlx/reqwest stack doesn't build for
//! wasm, and a `--target wasm32` test run (tests/wasm_client.rs) must skip this.
#![cfg(not(target_arch = "wasm32"))]

mod common;

use arium_dioxus::{LoginOutcome, UserProfile};
// Bring the server fns into scope so their inventory registrations link into
// this test binary and `register_server_functions` can collect them.
#[allow(unused_imports)]
use arium_dioxus::server::*;

const EMAIL: &str = "roundtrip@example.test";
const PASSWORD: &str = "hunter22!longenough";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn register_login_profile_logout_round_trip() {
    let base = common::spawn_app().await;

    // --- An anonymous caller (no cookies) reads as unauthenticated. ---
    let anon = common::client();
    let profile: UserProfile = common::get_json(&anon, &base, "/api/user/profile").await;
    assert!(
        !profile.is_authenticated,
        "fresh caller must be anonymous, got {profile:?}"
    );

    // --- Register: creates + (skip-verification) logs in, returns LoggedIn. ---
    let registrar = common::client();
    let outcome = common::register(&registrar, &base, EMAIL, PASSWORD).await;
    assert_eq!(outcome, LoginOutcome::LoggedIn, "register should log in");

    // Register must *establish the session on the same client*, not merely
    // return `LoggedIn`. The no-mail register path once returned `LoggedIn`
    // without calling `complete_login`, so signup left the caller anonymous —
    // this asserts the cookie the registrar now carries actually authenticates.
    let profile: UserProfile = common::get_json(&registrar, &base, "/api/user/profile").await;
    assert!(
        profile.is_authenticated,
        "register must log the caller in (session established), got {profile:?}"
    );

    // --- Login on a *fresh* client to exercise the login path + Set-Cookie. ---
    let user = common::client();
    let (outcome, set_cookie) = common::login(&user, &base, EMAIL, PASSWORD).await;
    assert_eq!(outcome, LoginOutcome::LoggedIn, "login should succeed");
    assert!(
        set_cookie,
        "a successful login must issue a session Set-Cookie"
    );

    // --- The authenticated read now reflects the logged-in identity. ---
    let profile: UserProfile = common::get_json(&user, &base, "/api/user/profile").await;
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
    let _: () = common::post_json(&user, &base, "/api/user/logout", serde_json::json!({}))
        .await
        .0;
    let profile: UserProfile = common::get_json(&user, &base, "/api/user/profile").await;
    assert!(
        !profile.is_authenticated,
        "must be anonymous again after logout, got {profile:?}"
    );
}
