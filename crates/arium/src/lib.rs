//! Framework-agnostic authentication engine for axum + sqlx fullstack apps.
//!
//! `arium` owns the auth domain — password hashing, sessions, OAuth and
//! OpenID Connect (GitHub, Google, Microsoft, or any OIDC issuer), MFA/TOTP,
//! email verification + password reset, RBAC, API tokens, and an audit log —
//! plus the `install` helper that bolts the whole thing onto an
//! `axum::Router`. It has no UI-framework dependency; framework adapters such
//! as `arium-dioxus` wrap these primitives in their own server fns + UI.
//!
//! Typical server-side usage:
//!
//! ```rust,ignore
//! use arium::{
//!     AuthConfig, Mailer, install, migrator,
//!     oauth::{github::GithubProvider, OAuthRegistry},
//! };
//!
//! let pool = sqlx::sqlite::SqlitePoolOptions::new()
//!     .connect_with("sqlite://./app.db?mode=rwc".parse()?)
//!     .await?;
//! migrator().run(&pool).await?;
//!
//! let mut oauth = OAuthRegistry::new(pool.clone())?;
//! if let Some(gh) = GithubProvider::from_env()? {
//!     oauth = oauth.with_provider(gh);
//! }
//!
//! let cfg = AuthConfig::builder(pool.clone(), Mailer::from_env()?)
//!     .oauth(oauth)
//!     .build()?;
//!
//! // `router` is any `axum::Router` (e.g. your framework's server router).
//! let router = install(router, cfg).await?;
//! ```
//!
//! `oauth-github` is on by default. The opt-in `oauth-oidc`, `oauth-google`,
//! and `oauth-microsoft` features add a generic OpenID Connect provider plus
//! Google/Microsoft presets — each `from_env()`-constructed and registered the
//! same way as `GithubProvider` above.
//!
//! ## Per-resource authorization
//!
//! Beyond global RBAC (flat permission tokens), the [`authz`] module adds
//! relationship-based checks — "what role does this user hold on *this*
//! resource?" Implement [`authz::ResourceAuthority`] over your own membership
//! storage and guard resource-scoped mutations with
//! [`require_resource`](authz::require_resource); it does a fresh per-request
//! lookup and default-denies. arium ships no membership table — the app owns
//! that storage; arium owns the enforcement boundary and the [`ResourceRole`]
//! lattice.

#![allow(clippy::needless_doctest_main)]

/// Wire types shared with framework adapters and clients, re-exported from the
/// standalone `arium-wire` crate so `arium::wire::*` keeps resolving.
pub use arium_wire as wire;

pub mod auth;
pub mod authz;
pub mod config;
pub mod extract;
pub mod membership;
pub mod pool;
mod sql_membership;

mod install;

#[cfg(feature = "_oauth-core")]
pub mod oauth;

#[cfg(feature = "mail")]
pub mod mail;

pub use config::{AuditConfig, AuthConfig, AuthConfigBuilder, RECOMMENDED_HSTS};

#[cfg(feature = "ratelimit")]
pub use config::RateLimitConfig;

pub use authz::{
    require_resource, ResourceAuthority, ResourceAuthzError, ResourceRef, SharedResourceAuthority,
};
pub use membership::{
    grant_membership, revoke_membership, transfer_ownership, Membership, MembershipError,
    MembershipStore, TxExec,
};
pub use sql_membership::SqlMembershipStore;
pub use extract::{AuditCtx, AuthzCtx, ResourceAuthorityExt, SessionStore};
pub use install::install;

/// Returns the embedded migrator that creates the `users`, `oauth_accounts`,
/// `roles`, `audit_events`, `api_keys`, and related tables arium owns.
///
/// Run this once at startup before installing the router:
///
/// ```rust,ignore
/// arium::migrator().run(&pool).await?;
/// ```
///
/// Returned with `ignore_missing = true` so consumers can keep their own
/// domain migrations in the same `_sqlx_migrations` table without the
/// "version X was previously applied but is missing in the resolved
/// migrations" cross-migrator error firing on every startup. The dialect
/// (sqlite vs postgres) is selected by the active backend feature.
#[cfg(feature = "sqlite")]
pub fn migrator() -> sqlx::migrate::Migrator {
    let mut m = sqlx::migrate!("./migrations/sqlite");
    m.set_ignore_missing(true);
    m
}

/// Returns the embedded migrator. See the sqlite-feature variant for the
/// full doc — same contract, postgres dialect.
#[cfg(feature = "postgres")]
pub fn migrator() -> sqlx::migrate::Migrator {
    let mut m = sqlx::migrate!("./migrations/postgres");
    m.set_ignore_missing(true);
    m
}

#[cfg(feature = "mail")]
pub use mail::Mailer;

// Wire-types re-exported at the crate root for ergonomics.
#[cfg(feature = "tokens")]
pub use wire::{ApiTokenView, CreateApiTokenResponse};
pub use wire::{
    LoginOutcome, MfaSetupView, MfaStatusView, ProviderInfo, ResourceRole, UserProfile,
};
