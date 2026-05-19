//! Reusable authentication primitives for Dioxus 0.7 fullstack apps.
//!
//! See the workspace README for the consumer-facing setup walkthrough and
//! the env-var surface; this rustdoc-level doc covers the public Rust API.
//!
//! Typical usage:
//!
//! ```rust,ignore
//! use dx_auth::{AuthConfig, Mailer, auth::OAuthClients, server::*, ui::LoginPanel};
//!
//! dioxus::serve(|| async {
//!     let pool = sqlx::sqlite::SqlitePoolOptions::new()
//!         .connect_with("sqlite://./app.db?mode=rwc".parse()?)
//!         .await?;
//!     sqlx::migrate!().run(&pool).await?;
//!
//!     let cfg = AuthConfig::builder(pool.clone(), Mailer::from_env()?)
//!         .github(OAuthClients::from_env(pool.clone())?)
//!         .build();
//!
//!     dx_auth::install(dioxus::server::router(app), cfg).await
//! });
//! ```

#![allow(clippy::needless_doctest_main)]

pub mod wire;

#[cfg(feature = "ui")]
pub mod ui;

pub mod server;

#[cfg(feature = "server")]
pub mod pool;

#[cfg(feature = "server")]
pub mod auth;

#[cfg(all(feature = "server", feature = "mail"))]
pub mod mail;

#[cfg(feature = "server")]
pub mod config;

#[cfg(feature = "server")]
mod install;

#[cfg(feature = "server")]
pub use config::{AuditConfig, AuthConfig, AuthConfigBuilder};

#[cfg(all(feature = "server", feature = "ratelimit"))]
pub use config::RateLimitConfig;

#[cfg(feature = "server")]
pub use install::install;

#[cfg(all(feature = "server", feature = "mail"))]
pub use mail::Mailer;

// Wire-types re-exported at the crate root for ergonomics.
pub use wire::{LoginOutcome, MfaSetupView, MfaStatusView, ProviderId, UserProfile};

/// Extract just the human-readable message from a server-fn error captured
/// on the client. The `CapturedError` Display wraps the original
/// `ServerFnError::ServerError` as `"error running server function: <msg>
/// (details: ...)"`; this strips that wrapper, and also recognises 429
/// responses from the rate-limit layer and substitutes a friendly retry
/// message.
pub fn friendly_server_error(e: dioxus::CapturedError) -> String {
    let raw = e.to_string();
    if raw.contains("429") || raw.contains("Too Many Requests") {
        return "Too many attempts. Wait a minute and try again.".to_string();
    }
    let rest = raw
        .strip_prefix("error running server function: ")
        .unwrap_or(&raw);
    let cleaned = rest.rsplit_once(" (details:").map(|(m, _)| m).unwrap_or(rest);
    cleaned.to_string()
}
