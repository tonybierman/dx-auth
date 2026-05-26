//! Dioxus 0.7 adapter for the [`arium`](https://github.com/tonybierman/arium) auth engine.
//!
//! This crate exposes arium's authentication as Dioxus fullstack server
//! functions (`server`) plus ready-made UI components (`ui`). The
//! framework-agnostic engine lives in the `arium` crate; this adapter wires it
//! to Dioxus and, under the `server` feature, re-exports the engine's
//! server-side API (`AuthConfig`, `install`, `migrator`, `Mailer`, the OAuth
//! registry, the request extractors) so a fullstack app can reach everything
//! through this one crate.
//!
//! ```rust,no_run
//! # #[allow(unused_imports)]
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

/// The default dx-components catalog theme — the single source of truth for the
/// CSS custom properties (`--primary-color-*`, `--secondary-color-*`,
/// `--focused-border-color`, …) that every catalog widget and auth screen under
/// [`ui`] consumes via `var(...)`. Link it once near your app root, e.g.
/// `document::Stylesheet { href: arium_dioxus::DEFAULT_THEME_CSS }`.
///
/// Consumers should link this asset rather than vendoring their own copy. To
/// customize the palette, redefine the same custom-property names in your own
/// stylesheet and link it *after* this default so the cascade resolves to your
/// values (override only the tokens you're changing) — or link yours instead of
/// this one to replace the palette wholesale. See the "Customizing the UI"
/// section of `CONFIG_DIOXUS.md` for the mechanics.
#[cfg(feature = "ui")]
pub use theme::DEFAULT_THEME_CSS;

#[cfg(feature = "ui")]
mod theme {
    use dioxus::prelude::*;
    /// See [`crate::DEFAULT_THEME_CSS`].
    pub const DEFAULT_THEME_CSS: Asset = asset!("/assets/dx-components-theme.css");
}

pub mod server;

// Shared wire types — always available (client + server), sourced from the
// standalone `arium-wire` crate so the browser build doesn't pull the engine.
pub use arium_wire as wire;
#[cfg(feature = "tokens")]
pub use arium_wire::{ApiTokenView, CreateApiTokenResponse};
pub use arium_wire::{
    LoginOutcome, MfaSetupView, MfaStatusView, ProviderInfo, ResourceRole, UserProfile,
};

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
    AuditConfig, AuditCtx, AuthConfig, AuthConfigBuilder, AuthUser, AuthzCtx, Membership,
    MembershipError, MembershipStore, ResourceAuthority, ResourceAuthorityExt, ResourceAuthzError,
    ResourceGrant, ResourceRef, SessionStore, SharedResourceAuthority, TxExec, auth, authz,
    grant_membership, install, membership, migrator, pool, require_resource,
    require_resource_audited, require_resource_or_permission, revoke_membership,
    transfer_ownership,
};
// Bearer-token auth: the `ApiKeyUser` extension the `AuthUser`/`AuthzCtx`
// extractors honor. The middleware that injects it is applied by `install`.
#[cfg(all(feature = "server", feature = "tokens"))]
pub use arium::ApiKeyUser;
// Bundled per-resource membership store + its migrator. Opt-in: apps that own
// their own membership table (like dx_standup's `board_members`) leave the
// `sql-membership` feature off and never link these.
#[cfg(all(feature = "server", feature = "sql-membership"))]
pub use arium::{SqlMembershipStore, membership_migrator};

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
