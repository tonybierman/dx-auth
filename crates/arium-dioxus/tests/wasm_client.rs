//! Wasm client-surface smoke test — runs in the wasm runtime (Node, via
//! wasm-bindgen-test-runner; no browser), under the browser/client build.
//!
//! The `wasm` CI job only `cargo check`s the client build — it proves the
//! client compiles for wasm32, not that the client-side logic actually *runs*
//! there. A framework/serde release can compile fine yet break at runtime on
//! wasm. This executes the serde round-trip of the re-exported wire types —
//! what every server-fn response deserializes into on the client — inside the
//! real wasm module the adapter links into a consumer's bundle.
//!
//! (The client-only `friendly_server_error` helper takes a `dioxus::CapturedError`;
//! constructing one here would pull the dioxus web stack into the Node test, so
//! it's left to the `wasm` job's `cargo check` instead.)
//!
//! Wasm-only: on native this file compiles to nothing (the round-trip test
//! covers the native side).
#![cfg(target_arch = "wasm32")]

use arium_dioxus::{LoginOutcome, UserProfile};
use wasm_bindgen_test::wasm_bindgen_test;

// No `wasm_bindgen_test_configure!(run_in_browser)` — pure logic runs on the
// default Node runner, keeping CI browser-free.

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
