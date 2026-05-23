//! Dioxus 0.7 adapter for the [`arium`](https://github.com/tonybierman/arium) auth engine.
//!
//! This crate exposes arium's authentication as Dioxus fullstack server
//! functions ([`server`]) plus ready-made UI components ([`ui`]). The
//! framework-agnostic engine lives in the `arium` crate; this adapter wires it
//! to Dioxus and, under the `server` feature, re-exports the engine's
//! server-side API (`AuthConfig`, `install`, `migrator`, `Mailer`, the OAuth
//! registry, the request extractors) so a fullstack app can reach everything
//! through this one crate.
//!
//! ```rust,ignore
//! use arium_dioxus::{
//!     AuthConfig, Mailer, install, migrator,
//!     oauth::{github::GithubProvider, OAuthRegistry},
//!     server::*,
//!     ui::LoginPanel,
//! };
//! ```

#![allow(clippy::needless_doctest_main)]

#[cfg(feature = "ui")]
pub mod ui;

pub mod server;

// Shared wire types — always available (client + server), sourced from the
// standalone `arium-wire` crate so the browser build doesn't pull the engine.
pub use arium_wire as wire;
#[cfg(feature = "tokens")]
pub use arium_wire::{ApiTokenView, CreateApiTokenResponse};
pub use arium_wire::{LoginOutcome, MfaSetupView, MfaStatusView, ProviderInfo, UserProfile};

// Server-side engine API, re-exported for fullstack consumers. Present only on
// the native/server build (the `arium` dep is target-gated off wasm).
#[cfg(all(feature = "server", feature = "mail"))]
pub use arium::Mailer;
#[cfg(all(feature = "server", feature = "ratelimit"))]
pub use arium::RateLimitConfig;
#[cfg(all(feature = "server", feature = "oauth-github"))]
pub use arium::oauth;
#[cfg(feature = "server")]
pub use arium::{
    AuditConfig, AuditCtx, AuthConfig, AuthConfigBuilder, SessionStore, auth, install, migrator,
};

/// Extract just the human-readable message from a server-fn error captured
/// on the client. The `CapturedError` Display wraps the original
/// `ServerFnError::ServerError` as `"error running server function: <msg>
/// (details: ...)"`; this strips that wrapper, and also recognises 429
/// responses from the rate-limit layer and substitutes a friendly retry
/// message.
///
/// Self-contained on purpose: it runs on the client (wasm) build, where the
/// `arium` engine crate is not a dependency.
pub fn friendly_server_error(e: dioxus::CapturedError) -> String {
    let raw = e.to_string();
    if raw.contains("429") || raw.contains("Too Many Requests") {
        return "Too many attempts. Wait a minute and try again.".to_string();
    }
    let rest = raw
        .strip_prefix("error running server function: ")
        .unwrap_or(&raw);
    let cleaned = rest
        .rsplit_once(" (details:")
        .map(|(m, _)| m)
        .unwrap_or(rest);
    cleaned.to_string()
}
