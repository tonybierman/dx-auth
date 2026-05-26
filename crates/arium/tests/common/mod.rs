//! Shared test scaffolding.
//!
//! Every integration test in this crate spins up a *fresh* sqlite-in-memory
//! pool via [`pool()`] and migrates it from the SQL files under
//! `crates/arium/migrations/sqlite/`. That gives us real SQL semantics
//! (unique indexes, FK cascades, transactional rollback) without needing a
//! container, while still being parallel-safe — each test owns its own
//! pool and never touches another test's data.

#![allow(dead_code)] // each test file uses a subset of the helpers

use std::path::PathBuf;

use sqlx::SqlitePool;
use sqlx::sqlite::SqlitePoolOptions;

/// Build a fresh in-memory sqlite pool with the arium schema applied.
///
/// One shared connection — sqlite's `:memory:` database is per-connection
/// and we want every query in a test to see the same DB.
pub async fn pool() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("connect sqlite memory");
    run_migrations(&pool).await;
    pool
}

async fn run_migrations(pool: &SqlitePool) {
    let dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("migrations")
        .join("sqlite");
    let mut entries = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "sql"))
        .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
        let sql = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        // Strip `--` line comments before splitting on `;`, since our
        // migrations include comments with semicolons inside them. The
        // migrations don't contain trigger bodies or other nested-semicolon
        // SQL, so a comment-stripped naive split is safe.
        let stripped: String = sql
            .lines()
            .map(|line| match line.find("--") {
                Some(idx) => &line[..idx],
                None => line,
            })
            .collect::<Vec<_>>()
            .join("\n");
        for stmt in stripped.split(';') {
            let trimmed = stmt.trim();
            if trimmed.is_empty() {
                continue;
            }
            sqlx::query(trimmed)
                .execute(pool)
                .await
                .unwrap_or_else(|e| panic!("migrate {} ({trimmed}): {e}", path.display()));
        }
    }
}

/// Insert a verified password user directly (skips the audit log noise).
/// Returns the user id.
pub async fn make_user(pool: &SqlitePool, email: &str, password: &str) -> i64 {
    let user_id = arium::auth::create_password_user(pool, email, password)
        .await
        .expect("create_password_user");
    // Mark verified so callers can `verify_password_user` without ceremony.
    sqlx::query("UPDATE users SET email_verified_at = $1 WHERE id = $2")
        .bind(now_secs())
        .bind(user_id)
        .execute(pool)
        .await
        .expect("verify user");
    user_id
}

/// Current unix epoch seconds.
pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Generate the current TOTP code for a given base32 secret. Uses the same
/// `totp_rs` params as `arium::auth::check_totp` so the codes line up.
pub fn current_totp(secret_base32: &str) -> String {
    use totp_rs::{Algorithm, Secret, TOTP};
    let bytes = Secret::Encoded(secret_base32.to_string())
        .to_bytes()
        .expect("decode secret");
    let totp =
        TOTP::new(Algorithm::SHA1, 6, 1, 30, bytes, None, "".to_string()).expect("totp construct");
    totp.generate_current().expect("totp generate")
}

/// RAII guard for setting an env var only for the lifetime of one test.
///
/// We need this for the bootstrap-admin tests, which mutate the process
/// env. Combined with `#[serial]` it stops cross-test contamination.
pub struct EnvGuard {
    key: &'static str,
    prev: Option<String>,
}

impl EnvGuard {
    pub fn set(key: &'static str, value: &str) -> Self {
        let prev = std::env::var(key).ok();
        // SAFETY: serial_test forces these tests onto a single thread, so the
        // env mutation can't race with other tests reading the var.
        unsafe {
            std::env::set_var(key, value);
        }
        Self { key, prev }
    }

    pub fn unset(key: &'static str) -> Self {
        let prev = std::env::var(key).ok();
        unsafe {
            std::env::remove_var(key);
        }
        Self { key, prev }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        unsafe {
            match &self.prev {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }
}

// ============================================================
// Test OAuth provider
// ============================================================

#[cfg(feature = "oauth-github")]
pub mod test_provider {
    use arium::oauth::{NormalizedProfile, OAuthProvider};
    use async_trait::async_trait;

    /// A stand-in `OAuthProvider` that never hits the network. Tests
    /// usually bypass the axum login flow and call
    /// `arium::oauth::upsert_oauth_user(...)` directly, so the only thing
    /// `TestProvider` is used for is registry-level wiring tests.
    pub struct TestProvider {
        pub name: &'static str,
        pub display_name: &'static str,
        pub profile: NormalizedProfile,
    }

    impl TestProvider {
        pub fn new(name: &'static str) -> Self {
            Self {
                name,
                display_name: "Test",
                profile: NormalizedProfile {
                    provider_user_id: "1".to_string(),
                    login: "testuser".to_string(),
                    name: Some("Test User".to_string()),
                    email: Some("test@example.invalid".to_string()),
                    avatar_url: None,
                    html_url: None,
                },
            }
        }
    }

    #[async_trait]
    impl OAuthProvider for TestProvider {
        fn name(&self) -> &str {
            self.name
        }
        fn display_name(&self) -> &str {
            self.display_name
        }
        fn client_id(&self) -> &str {
            "test-client-id"
        }
        fn client_secret(&self) -> &str {
            "test-client-secret"
        }
        fn redirect_url(&self) -> &str {
            "http://localhost:8080/auth/test/callback"
        }
        fn auth_url(&self) -> &str {
            "https://example.invalid/authorize"
        }
        fn token_url(&self) -> &str {
            "https://example.invalid/token"
        }
        fn scopes(&self) -> &[&str] {
            &["read:user"]
        }
        async fn fetch_profile(
            &self,
            _http: &reqwest::Client,
            _access_token: &str,
        ) -> anyhow::Result<NormalizedProfile> {
            Ok(self.profile.clone())
        }
    }
}

// ============================================================
// Test resource authority (per-resource authz)
// ============================================================

pub mod test_authority {
    use arium::ResourceRole;
    use arium::authz::{ResourceAuthority, ResourceRef};
    use arium::membership::{Membership, MembershipStore, TxExec};
    use arium::pool::Pool;
    use async_trait::async_trait;

    /// A [`ResourceAuthority`] backed by a `test_memberships(user_id, kind,
    /// resource_id, role)` table the test creates itself — demonstrating the
    /// "app owns the storage" contract arium's resource authz relies on.
    pub struct TableAuthority;

    impl TableAuthority {
        /// Create the membership table this authority reads. arium ships no
        /// such table; the app (here, the test) owns it.
        pub async fn create_table(pool: &Pool) {
            sqlx::query(
                "CREATE TABLE IF NOT EXISTS test_memberships (\
                    user_id     INTEGER NOT NULL,\
                    kind        TEXT NOT NULL,\
                    resource_id INTEGER NOT NULL,\
                    role        TEXT NOT NULL,\
                    PRIMARY KEY (user_id, kind, resource_id))",
            )
            .execute(pool)
            .await
            .expect("create test_memberships");
        }

        /// Grant `role` to `user_id` on `(kind, id)`.
        pub async fn grant(pool: &Pool, user_id: i64, kind: &str, id: i64, role: &str) {
            sqlx::query(
                "INSERT INTO test_memberships (user_id, kind, resource_id, role) \
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(user_id)
            .bind(kind)
            .bind(id)
            .bind(role)
            .execute(pool)
            .await
            .expect("grant membership");
        }

        /// Remove any membership `user_id` holds on `(kind, id)`.
        pub async fn revoke(pool: &Pool, user_id: i64, kind: &str, id: i64) {
            sqlx::query(
                "DELETE FROM test_memberships \
                 WHERE user_id = $1 AND kind = $2 AND resource_id = $3",
            )
            .bind(user_id)
            .bind(kind)
            .bind(id)
            .execute(pool)
            .await
            .expect("revoke membership");
        }
    }

    #[async_trait]
    impl ResourceAuthority for TableAuthority {
        async fn role_on(
            &self,
            db: &Pool,
            user_id: i64,
            r: ResourceRef<'_>,
        ) -> anyhow::Result<Option<ResourceRole>> {
            let role: Option<String> = sqlx::query_scalar(
                "SELECT role FROM test_memberships \
                 WHERE user_id = $1 AND kind = $2 AND resource_id = $3",
            )
            .bind(user_id)
            .bind(r.kind)
            .bind(r.id)
            .fetch_optional(db)
            .await?;
            Ok(role.map(|r| ResourceRole::from_str_lossy(&r)))
        }
    }

    #[async_trait]
    impl MembershipStore for TableAuthority {
        async fn list_members(
            &self,
            db: &Pool,
            r: ResourceRef<'_>,
        ) -> anyhow::Result<Vec<Membership>> {
            let rows: Vec<(i64, String)> = sqlx::query_as(
                "SELECT user_id, role FROM test_memberships \
                 WHERE kind = $1 AND resource_id = $2 ORDER BY user_id",
            )
            .bind(r.kind)
            .bind(r.id)
            .fetch_all(db)
            .await?;
            Ok(rows
                .into_iter()
                .map(|(user_id, role)| Membership {
                    user_id,
                    role: ResourceRole::from_str_lossy(&role),
                })
                .collect())
        }

        async fn list_resources_for_user(
            &self,
            db: &Pool,
            user_id: i64,
            kind: &str,
            min_role: ResourceRole,
        ) -> anyhow::Result<Vec<i64>> {
            let rows: Vec<(i64, String)> = sqlx::query_as(
                "SELECT resource_id, role FROM test_memberships \
                 WHERE user_id = $1 AND kind = $2 ORDER BY resource_id",
            )
            .bind(user_id)
            .bind(kind)
            .fetch_all(db)
            .await?;
            Ok(rows
                .into_iter()
                .filter(|(_, role)| ResourceRole::from_str_lossy(role).at_least(min_role))
                .map(|(id, _)| id)
                .collect())
        }

        async fn role_on_tx(
            &self,
            tx: &mut TxExec<'_>,
            r: ResourceRef<'_>,
            user_id: i64,
        ) -> anyhow::Result<Option<ResourceRole>> {
            let role: Option<String> = sqlx::query_scalar(
                "SELECT role FROM test_memberships \
                 WHERE user_id = $1 AND kind = $2 AND resource_id = $3",
            )
            .bind(user_id)
            .bind(r.kind)
            .bind(r.id)
            .fetch_optional(&mut **tx)
            .await?;
            Ok(role.map(|r| ResourceRole::from_str_lossy(&r)))
        }

        async fn count_holders_of_role(
            &self,
            tx: &mut TxExec<'_>,
            r: ResourceRef<'_>,
            role: ResourceRole,
        ) -> anyhow::Result<u64> {
            let n: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM test_memberships \
                 WHERE kind = $1 AND resource_id = $2 AND role = $3",
            )
            .bind(r.kind)
            .bind(r.id)
            .bind(role.as_str())
            .fetch_one(&mut **tx)
            .await?;
            Ok(n as u64)
        }

        async fn upsert_role(
            &self,
            tx: &mut TxExec<'_>,
            r: ResourceRef<'_>,
            user_id: i64,
            role: ResourceRole,
        ) -> anyhow::Result<()> {
            sqlx::query(
                "INSERT INTO test_memberships (user_id, kind, resource_id, role) \
                 VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (user_id, kind, resource_id) DO UPDATE SET role = excluded.role",
            )
            .bind(user_id)
            .bind(r.kind)
            .bind(r.id)
            .bind(role.as_str())
            .execute(&mut **tx)
            .await?;
            Ok(())
        }

        async fn remove_role(
            &self,
            tx: &mut TxExec<'_>,
            r: ResourceRef<'_>,
            user_id: i64,
        ) -> anyhow::Result<()> {
            sqlx::query(
                "DELETE FROM test_memberships \
                 WHERE user_id = $1 AND kind = $2 AND resource_id = $3",
            )
            .bind(user_id)
            .bind(r.kind)
            .bind(r.id)
            .execute(&mut **tx)
            .await?;
            Ok(())
        }
    }

    /// An authority whose `role_on` always errors — proves `require_resource`
    /// surfaces `Lookup` rather than silently denying on infrastructure failure.
    pub struct FailingAuthority;

    #[async_trait]
    impl ResourceAuthority for FailingAuthority {
        async fn role_on(
            &self,
            _db: &Pool,
            _user_id: i64,
            _r: ResourceRef<'_>,
        ) -> anyhow::Result<Option<ResourceRole>> {
            Err(anyhow::anyhow!("simulated storage failure"))
        }
    }
}
