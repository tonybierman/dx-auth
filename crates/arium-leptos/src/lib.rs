//! Leptos 0.8 adapter for the [`arium`](https://github.com/tonybierman/arium) auth engine.
//!
//! This crate exposes arium's authentication as Leptos fullstack server
//! functions (`server`) plus ready-made UI components (`ui`). The
//! framework-agnostic engine lives in the `arium` crate; this adapter wires it
//! to Leptos and, under the `ssr` feature, re-exports the engine's server-side
//! API (`AuthConfig`, `install`, `migrator`, `Mailer`, the OAuth registry, the
//! request extractors) so a fullstack app can reach everything through this one
//! crate.
//!
//! Unlike the Dioxus adapter, the server/client split is driven by the `ssr` /
//! `hydrate` cargo features (`#[cfg(feature = "ssr")]`), not by
//! `cfg(target_arch = "wasm32")` — Leptos compiles the crate once per side.
//!
//! ```rust,no_run
//! # #[allow(unused_imports)]
//! # async fn doc() -> anyhow::Result<()> {
//! # let pool: arium_leptos::pool::Pool = unimplemented!();
//! # let app = axum::Router::new();
//! // Server (`ssr` feature): layer the engine onto your Leptos axum router.
//! use arium_leptos::{AuthConfig, Mailer, install, migrator};
//!
//! migrator().run(&pool).await?;
//! let cfg = AuthConfig::builder(pool.clone(), Mailer::from_env()?).build()?;
//! let app = install(app, cfg).await?; // sessions, OAuth routes, audit, rate limiting
//!
//! // Client + server: wrap the router and drop in components.
//! use arium_leptos::ui::{LoginPanel, OAuthProvidersProvider, PermissionsProvider};
//! // <PermissionsProvider><OAuthProvidersProvider> <Router/> … <LoginPanel/> … </…></…>
//! # let _ = app;
//! # Ok(()) }
//! ```

#![allow(clippy::needless_doctest_main)]

#[cfg(feature = "ui")]
pub mod ui;

pub mod server;

/// The default dx-components catalog theme — the CSS custom properties
/// (`--primary-color-*`, `--secondary-color-*`, …) every catalog widget and
/// auth screen consumes via `var(...)`. [`ui::AuthStylesheets`] injects it
/// automatically (as one `<style>` block, theme tokens first); it's exposed
/// here for apps that want to inject it themselves.
///
/// To customize the palette, redefine the same custom-property names in your
/// own CSS. Since the theme ships in a body `<style>`, your override must come
/// *after* it in document order to win the cascade — a plain `<head>` link
/// loads first and loses. See the "Customizing the UI" section of
/// `CONFIG_LEPTOS.md` for the mechanics.
#[cfg(feature = "ui")]
pub const DEFAULT_THEME_CSS: &str = include_str!("../assets/dx-components-theme.css");

// Shared wire types — always available (client + server), sourced from the
// standalone `arium-wire` crate so the browser build doesn't pull the engine.
pub use arium_wire as wire;
#[cfg(feature = "tokens")]
pub use arium_wire::{ApiTokenView, CreateApiTokenResponse};
pub use arium_wire::{
    LoginOutcome, MfaSetupView, MfaStatusView, ProviderInfo, ResourceRole, UserProfile,
};

// Server-side engine API, re-exported for fullstack consumers. Present only on
// the `ssr` build (the `arium` dep is gated to the `ssr` feature).
#[cfg(all(feature = "ssr", feature = "mail"))]
pub use arium::Mailer;
#[cfg(all(feature = "ssr", feature = "ratelimit"))]
pub use arium::RateLimitConfig;
#[cfg(all(feature = "ssr", feature = "oauth-github"))]
pub use arium::oauth;
#[cfg(feature = "ssr")]
pub use arium::{
    AuditConfig, AuditCtx, AuthConfig, AuthConfigBuilder, AuthUser, AuthzCtx, Membership,
    MembershipError, MembershipStore, ResourceAuthority, ResourceAuthorityExt, ResourceAuthzError,
    ResourceGrant, ResourceRef, SessionStore, SharedResourceAuthority, TxExec, auth, authz,
    grant_membership, install, membership, migrator, pool, require_resource,
    require_resource_or_permission, revoke_membership, transfer_ownership,
};
// Bearer-token auth: the `ApiKeyUser` extension the `AuthUser`/`AuthzCtx`
// extractors honor (middleware applied by `install`).
#[cfg(all(feature = "ssr", feature = "tokens"))]
pub use arium::ApiKeyUser;
// Bundled per-resource membership store + migrator. Opt-in (off for apps that
// own their own membership table).
#[cfg(all(feature = "ssr", feature = "sql-membership"))]
pub use arium::{SqlMembershipStore, membership_migrator};

/// Extract just the human-readable message from a server-fn error surfaced on
/// the client. Leptos wraps server errors as
/// `"error running server function: <msg>"` (and the rate-limit layer returns a
/// raw 429); this strips that wrapper and substitutes a friendly retry message
/// for 429s.
///
/// Self-contained on purpose: it runs on the client (wasm) build, where the
/// `arium` engine crate is not a dependency. Pass the error directly (it is
/// `Display`), e.g. `friendly_server_error(&err)`.
pub fn friendly_server_error(e: impl std::fmt::Display) -> String {
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
