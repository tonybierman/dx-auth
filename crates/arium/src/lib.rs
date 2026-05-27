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
//! ```rust,no_run
//! # async fn doc() -> anyhow::Result<()> {
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
//! # let router = axum::Router::new();
//! let router = install(router, cfg).await?;
//! # let _ = router;
//! # Ok(()) }
//! ```
//!
//! `oauth-github` is on by default. The opt-in `oauth-oidc`, `oauth-google`,
//! and `oauth-microsoft` features add a generic OpenID Connect provider plus
//! Google/Microsoft presets — each `from_env()`-constructed and registered the
//! same way as `GithubProvider` above.
//!
//! ## Per-resource authorization
//!
//! Beyond global RBAC (flat permission tokens), the `authz` module adds
//! relationship-based checks — "what role does this user hold on *this*
//! resource?" Implement `authz::ResourceAuthority` over your own membership
//! storage and guard resource-scoped mutations with `require_resource`; it
//! does a fresh per-request lookup and default-denies. arium ships no
//! membership table — the app owns that storage; arium owns the enforcement
//! boundary and the `ResourceRole` lattice.

#![allow(clippy::needless_doctest_main)]

/// Wire types shared with framework adapters and clients, re-exported from the
/// standalone `arium-wire` crate so `arium::wire::*` keeps resolving.
pub use arium_wire as wire;

pub mod auth;
mod authz_bridge;
pub mod config;
pub mod extract;
pub mod pool;
#[cfg(feature = "sql-membership")]
mod sql_membership;

/// Bearer-token authentication: the axum middleware that turns an
/// `Authorization: Bearer <token>` header into an [`api_key::ApiKeyUser`]
/// request extension, applied automatically by [`install`]. Gated on `tokens`
/// (it hashes the presented token with `auth::tokens`).
#[cfg(feature = "tokens")]
pub mod api_key;

mod install;

/// Per-resource authorization, re-exported from the standalone [`arium_authz`]
/// crate so `arium::authz::*` and `arium::membership::*` keep resolving for
/// existing code (and the framework adapters). The global↔resource bridge
/// (`require_resource_or_permission`) and the bundled `SqlMembershipStore`
/// stay in this crate — they touch the auth engine and its schema.
pub use arium_authz::{authz, membership};

#[cfg(feature = "_oauth-core")]
pub mod oauth;

#[cfg(feature = "mail")]
pub mod mail;

pub use config::{AuditConfig, AuthConfig, AuthConfigBuilder, RECOMMENDED_HSTS};

#[cfg(feature = "ratelimit")]
pub use config::RateLimitConfig;

// Per-resource authz primitives + lifecycle composites — flattened to the
// crate root, sourced from arium-authz.
pub use arium_authz::{
    Membership, MembershipError, MembershipStore, ResourceAuthority, ResourceAuthzError,
    ResourceRef, SharedResourceAuthority, TxExec, grant_membership, require_resource,
    revoke_membership, transfer_ownership,
};
// The global↔resource composition bridge lives here (it reads the auth
// engine's permission set).
#[cfg(feature = "tokens")]
pub use api_key::{ApiKeyUser, authenticate_token};
pub use authz_bridge::{ResourceGrant, require_resource_audited, require_resource_or_permission};
pub use extract::{AuditCtx, AuthUser, AuthzCtx, ResourceAuthorityExt, SessionStore};
pub use install::install;
#[cfg(feature = "sql-membership")]
pub use sql_membership::SqlMembershipStore;

/// Returns the embedded migrator that creates the `users`, `oauth_accounts`,
/// `roles`, `audit_events`, `api_keys`, and related tables arium owns.
///
/// Run this once at startup before installing the router:
///
/// ```rust,no_run
/// # async fn doc() -> anyhow::Result<()> {
/// # let pool: arium::pool::Pool = unimplemented!();
/// arium::migrator().run(&pool).await?;
/// # Ok(()) }
/// ```
///
/// This migrator does **not** create the `arium_resource_members` table; that
/// lives in [`membership_migrator`] (the `sql-membership` feature) so apps that
/// own their own membership table never get a dead table. Run both migrators
/// (core first — `arium_resource_members` has an FK to `users`) when using the
/// bundled [`SqlMembershipStore`](sql_membership::SqlMembershipStore).
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

/// Returns the migrator that creates the `arium_resource_members` table backing
/// the bundled [`SqlMembershipStore`](sql_membership::SqlMembershipStore).
///
/// Separate from [`migrator`] so this table is opt-in: only apps that actually
/// use the bundled store (the `sql-membership` feature) ever create it. Run it
/// *after* [`migrator`] — the table has an FK to `users`:
///
/// ```rust,no_run
/// # async fn doc() -> anyhow::Result<()> {
/// # let pool: arium::pool::Pool = unimplemented!();
/// arium::migrator().run(&pool).await?;
/// arium::membership_migrator().run(&pool).await?;
/// # Ok(()) }
/// ```
///
/// `ignore_missing = true` for the same cross-migrator coexistence reason as
/// [`migrator`] (it shares the `_sqlx_migrations` table).
#[cfg(all(feature = "sql-membership", feature = "sqlite"))]
pub fn membership_migrator() -> sqlx::migrate::Migrator {
    let mut m = sqlx::migrate!("./migrations-membership/sqlite");
    m.set_ignore_missing(true);
    m
}

/// Returns the membership migrator. See the sqlite-feature variant for the
/// full doc — same contract, postgres dialect.
#[cfg(all(feature = "sql-membership", feature = "postgres"))]
pub fn membership_migrator() -> sqlx::migrate::Migrator {
    let mut m = sqlx::migrate!("./migrations-membership/postgres");
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
