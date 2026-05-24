//! Wasm client-surface smoke test — runs in the wasm runtime (Node, via
//! wasm-bindgen-test-runner; no browser), under the `hydrate` build.
//!
//! The `wasm` CI job only `cargo check`s the hydrate build — it proves the
//! client compiles for wasm32, not that the client-side logic actually *runs*
//! there. A framework/serde release can compile fine yet break at runtime on
//! wasm (a serde feature that silently no-ops, a panic on the wasm allocator,
//! a `getrandom`-style target gap). This executes the two pieces of client
//! logic the adapter ships and that a consumer's hydrate bundle depends on:
//!
//!   1. serde round-tripping of the re-exported wire types (what every server
//!      fn response deserializes into on the client), and
//!   2. `friendly_server_error`, the client-only error-message mapper.
//!
//! Wasm-only: on native this file compiles to nothing (the round-trip test
//! covers the native side).
#![cfg(target_arch = "wasm32")]

use arium_leptos::{LoginOutcome, UserProfile};
use wasm_bindgen_test::wasm_bindgen_test;

// No `wasm_bindgen_test_configure!(run_in_browser)` — these are pure logic, so
// the default Node runner is enough (and keeps CI browser-free).

#[wasm_bindgen_test]
fn wire_types_round_trip_through_serde() {
    // The shape a server fn sends back to a hydrated client.
    let profile = UserProfile {
        is_authenticated: true,
        username: "ada".into(),
        display_name: Some("Ada Lovelace".into()),
        email: Some("ada@example.test".into()),
        avatar_url: None,
        html_url: None,
        permissions: vec!["Category::View".into()],
    };
    let json = serde_json::to_string(&profile).expect("serialize UserProfile");
    let back: UserProfile = serde_json::from_str(&json).expect("deserialize UserProfile");
    assert_eq!(back.username, "ada");
    assert_eq!(back.display_name.as_deref(), Some("Ada Lovelace"));
    assert!(back.is_authenticated);
    assert_eq!(back.permissions, vec!["Category::View".to_string()]);

    // The enum every login/register response decodes into.
    for outcome in [
        LoginOutcome::LoggedIn,
        LoginOutcome::EmailUnverified,
        LoginOutcome::MfaRequired,
    ] {
        let json = serde_json::to_string(&outcome).expect("serialize LoginOutcome");
        let back: LoginOutcome = serde_json::from_str(&json).expect("deserialize LoginOutcome");
        assert_eq!(back, outcome);
    }
}

#[wasm_bindgen_test]
fn friendly_server_error_maps_messages() {
    // Strips the server-fn wrapper down to the bare message.
    assert_eq!(
        arium_leptos::friendly_server_error("error running server function: Invalid password."),
        "Invalid password."
    );
    // Recognises the rate-limit response and substitutes a retry hint.
    let throttled = arium_leptos::friendly_server_error("server returned status 429");
    assert!(
        throttled.contains("Too many"),
        "429 should map to a retry hint, got {throttled:?}"
    );
}
