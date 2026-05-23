//! Compile-time-selected sqlx pool aliases.
//!
//! Enable exactly one of the `sqlite` or `postgres` features. Library code
//! consistently uses [`Pool`] / [`SessionPool`] rather than naming the
//! concrete sqlx pool type so the same query strings work across backends.

#[cfg(all(feature = "sqlite", feature = "postgres"))]
compile_error!("arium: enable exactly one of the `sqlite` or `postgres` features, not both.");

#[cfg(not(any(feature = "sqlite", feature = "postgres")))]
compile_error!("arium: enable one of the `sqlite` or `postgres` features.");

/// The sqlx connection pool arium runs every query against. Resolves to
/// `SqlitePool` or `PgPool` depending on which backend feature is active.
#[cfg(feature = "sqlite")]
pub type Pool = sqlx::SqlitePool;
/// The sqlx connection pool arium runs every query against. Resolves to
/// `SqlitePool` or `PgPool` depending on which backend feature is active.
#[cfg(feature = "postgres")]
pub type Pool = sqlx::PgPool;

/// The session-store pool adapter consumed by `axum_session`. Wraps the
/// matching backend variant of [`Pool`].
#[cfg(feature = "sqlite")]
pub type SessionPool = axum_session_sqlx::SessionSqlitePool;
/// The session-store pool adapter consumed by `axum_session`. Wraps the
/// matching backend variant of [`Pool`].
#[cfg(feature = "postgres")]
pub type SessionPool = axum_session_sqlx::SessionPgPool;
