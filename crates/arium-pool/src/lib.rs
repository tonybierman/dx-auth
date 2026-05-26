//! Compile-time-selected sqlx pool aliases — the one place the backend
//! (`sqlite` vs `postgres`) is chosen.
//!
//! Enable exactly one of the `sqlite` or `postgres` features. Both the arium
//! auth engine and `arium-authz` depend on this crate, so they agree on a
//! single concrete `Pool` type and a single "exactly one backend" guard:
//! a feature-unification mistake fails here, loudly, rather than as a cryptic
//! `SqlitePool`-vs-`PgPool` mismatch deep in a transaction signature.

#[cfg(all(feature = "sqlite", feature = "postgres"))]
compile_error!("arium-pool: enable exactly one of the `sqlite` or `postgres` features, not both.");

#[cfg(not(any(feature = "sqlite", feature = "postgres")))]
compile_error!("arium-pool: enable one of the `sqlite` or `postgres` features.");

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
/// transaction handle threaded through `arium_authz::membership::TxExec`.
#[cfg(feature = "sqlite")]
pub type DbBackend = sqlx::Sqlite;
/// The sqlx [`Database`](sqlx::Database) arium is compiled against — `Sqlite`
/// or `Postgres`. Used where a concrete backend type is unavoidable, e.g. the
/// transaction handle threaded through `arium_authz::membership::TxExec`.
#[cfg(feature = "postgres")]
pub type DbBackend = sqlx::Postgres;

/// The backend's connection type (`SqliteConnection` / `PgConnection`). A
/// `&mut DbConnection` is an sqlx [`Executor`](sqlx::Executor); the membership
/// layer's `TxExec` derefs to it so store impls run queries with the familiar
/// `&mut *tx`.
pub type DbConnection = <DbBackend as sqlx::Database>::Connection;
