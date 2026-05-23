//! Reusable authentication primitives for Dioxus 0.7 fullstack apps.
//!
//! See the workspace README for the consumer-facing setup walkthrough and
//! the env-var surface; this rustdoc-level doc covers the public Rust API.
//!
//! Typical usage:
//!
//! ```rust,ignore
//! use dx_auth::{
//!     AuthConfig, Mailer,
//!     oauth::{github::GithubProvider, OAuthRegistry},
//!     server::*,
//!     ui::LoginPanel,
//! };
//!
//! dioxus::serve(|| async {
//!     let pool = sqlx::sqlite::SqlitePoolOptions::new()
//!         .connect_with("sqlite://./app.db?mode=rwc".parse()?)
//!         .await?;
//!     dx_auth::migrator().run(&pool).await?;
//!
//!     let mut oauth = OAuthRegistry::new(pool.clone())?;
//!     if let Some(gh) = GithubProvider::from_env()? {
//!         oauth = oauth.with_provider(gh);
//!     }
//!
//!     let cfg = AuthConfig::builder(pool.clone(), Mailer::from_env()?)
//!         .oauth(oauth)
//!         .build()?;
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

#[cfg(all(feature = "server", feature = "_oauth-core"))]
pub mod oauth;

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

/// Returns the embedded migrator that creates the `users`, `oauth_accounts`,
/// `roles`, `audit_events`, `api_keys`, and related tables dx-auth owns.
///
/// Run this once at startup before installing the router:
///
/// ```rust,ignore
/// dx_auth::migrator().run(&pool).await?;
/// ```
///
/// Returned with `ignore_missing = true` so consumers can keep their own
/// domain migrations in the same `_sqlx_migrations` table without the
/// "version X was previously applied but is missing in the resolved
/// migrations" cross-migrator error firing on every startup. The dialect
/// (sqlite vs postgres) is selected by the active backend feature.
#[cfg(all(feature = "server", feature = "sqlite", not(target_arch = "wasm32")))]
pub fn migrator() -> sqlx::migrate::Migrator {
    let mut m = sqlx::migrate!("./migrations/sqlite");
    m.set_ignore_missing(true);
    m
}

/// Returns the embedded migrator. See the sqlite-feature variant for the
/// full doc — same contract, postgres dialect.
#[cfg(all(feature = "server", feature = "postgres", not(target_arch = "wasm32")))]
pub fn migrator() -> sqlx::migrate::Migrator {
    let mut m = sqlx::migrate!("./migrations/postgres");
    m.set_ignore_missing(true);
    m
}

#[cfg(all(feature = "server", feature = "mail"))]
pub use mail::Mailer;

// Wire-types re-exported at the crate root for ergonomics.
#[cfg(feature = "tokens")]
pub use wire::{ApiTokenView, CreateApiTokenResponse};
pub use wire::{LoginOutcome, MfaSetupView, MfaStatusView, ProviderInfo, UserProfile};

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
    let cleaned = rest
        .rsplit_once(" (details:")
        .map(|(m, _)| m)
        .unwrap_or(rest);
    cleaned.to_string()
}
