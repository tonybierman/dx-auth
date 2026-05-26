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

/// The sqlx [`Database`](sqlx::Database) arium is compiled against — `Sqlite`
/// or `Postgres`. Used where a concrete backend type is unavoidable, e.g. the
/// transaction handle threaded through [`TxExec`](crate::membership::TxExec).
#[cfg(feature = "sqlite")]
pub type DbBackend = sqlx::Sqlite;
/// The sqlx [`Database`](sqlx::Database) arium is compiled against — `Sqlite`
/// or `Postgres`. Used where a concrete backend type is unavoidable, e.g. the
/// transaction handle threaded through [`TxExec`](crate::membership::TxExec).
#[cfg(feature = "postgres")]
pub type DbBackend = sqlx::Postgres;

/// The backend's connection type (`SqliteConnection` / `PgConnection`). A
/// `&mut DbConnection` is an sqlx [`Executor`](sqlx::Executor); [`TxExec`](crate::membership::TxExec)
/// derefs to it so store impls run queries with the familiar `&mut *tx`.
pub type DbConnection = <DbBackend as sqlx::Database>::Connection;

/// The session-store pool adapter consumed by `axum_session`. Wraps the
/// matching backend variant of [`Pool`].
#[cfg(feature = "sqlite")]
pub type SessionPool = axum_session_sqlx::SessionSqlitePool;
/// The session-store pool adapter consumed by `axum_session`. Wraps the
/// matching backend variant of [`Pool`].
#[cfg(feature = "postgres")]
pub type SessionPool = axum_session_sqlx::SessionPgPool;
