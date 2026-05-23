//! Configuration object the consumer hands to [`crate::install`].
//!
//! Built explicitly via the [`AuthConfig::builder`] entry point — env-var
//! parsing only happens inside the optional convenience constructors that
//! consumers can opt into (e.g. `Mailer::from_env`, `GithubProvider::from_env`).

#![cfg(feature = "server")]

use chrono::Duration;

use crate::pool::Pool;

#[cfg(feature = "mail")]
use crate::mail::Mailer;

#[cfg(feature = "_oauth-core")]
use crate::oauth::{OAuthProvider, OAuthRegistry};

/// Rate-limit settings applied to the entire router. See [`crate::install`].
#[cfg(feature = "ratelimit")]
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Number of requests allowed without delay before throttling kicks in.
    pub burst: u32,
    /// Sustained refill rate (requests per second per IP).
    pub per_second: u64,
}

#[cfg(feature = "ratelimit")]
impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            burst: 30,
            per_second: 1,
        }
    }
}

/// Audit-log capture/retention settings. Wired into the audit emitter and
/// the background prune task started by [`crate::install`].
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Persist client IP address with every event.
    pub capture_ip: bool,
    /// Persist client `User-Agent` header with every event.
    pub capture_user_agent: bool,
    /// Delete events older than this. Set to `0` to keep events forever
    /// (the periodic prune task becomes a no-op).
    pub retention_days: u64,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            capture_ip: true,
            capture_user_agent: true,
            retention_days: 90,
        }
    }
}

/// Everything the library needs to wire itself into a Dioxus fullstack app.
#[derive(Clone)]
pub struct AuthConfig {
    pub(crate) pool: Pool,
    #[cfg(feature = "mail")]
    pub(crate) mailer: Mailer,
    #[cfg(feature = "_oauth-core")]
    pub(crate) oauth: OAuthRegistry,
    pub(crate) session_lifetime: Duration,
    pub(crate) session_max_lifetime: Duration,
    pub(crate) cookie_max_age: Duration,
    #[cfg(feature = "ratelimit")]
    pub(crate) rate_limit: Option<RateLimitConfig>,
    pub(crate) session_table_name: String,
    pub(crate) audit: AuditConfig,
}

impl AuthConfig {
    /// Start a new builder. With the `mail` feature `pool` AND `mailer` are
    /// required; without `mail` only `pool` is taken.
    #[cfg(feature = "mail")]
    pub fn builder(pool: Pool, mailer: Mailer) -> AuthConfigBuilder {
        AuthConfigBuilder {
            pool,
            mailer,
            #[cfg(feature = "_oauth-core")]
            oauth: None,
            session_lifetime: Duration::hours(2),
            session_max_lifetime: Duration::days(30),
            cookie_max_age: Duration::days(30),
            #[cfg(feature = "ratelimit")]
            rate_limit: Some(RateLimitConfig::default()),
            session_table_name: "dx_auth_sessions".to_string(),
            audit: AuditConfig::default(),
        }
    }

    /// Start a new builder without the `mail` feature compiled in.
    #[cfg(not(feature = "mail"))]
    pub fn builder(pool: Pool) -> AuthConfigBuilder {
        AuthConfigBuilder {
            pool,
            #[cfg(feature = "_oauth-core")]
            oauth: None,
            session_lifetime: Duration::hours(2),
            session_max_lifetime: Duration::days(30),
            cookie_max_age: Duration::days(30),
            #[cfg(feature = "ratelimit")]
            rate_limit: Some(RateLimitConfig::default()),
            session_table_name: "dx_auth_sessions".to_string(),
            audit: AuditConfig::default(),
        }
    }
}

/// Builder for [`AuthConfig`]. All methods consume + return `Self`.
pub struct AuthConfigBuilder {
    pool: Pool,
    #[cfg(feature = "mail")]
    mailer: Mailer,
    #[cfg(feature = "_oauth-core")]
    oauth: Option<OAuthRegistry>,
    session_lifetime: Duration,
    session_max_lifetime: Duration,
    cookie_max_age: Duration,
    #[cfg(feature = "ratelimit")]
    rate_limit: Option<RateLimitConfig>,
    session_table_name: String,
    audit: AuditConfig,
}

impl AuthConfigBuilder {
    /// Attach a fully-built OAuth registry (typically one constructed with
    /// `OAuthRegistry::new(pool.clone())?.with_provider(GithubProvider::from_env()?.unwrap())`).
    ///
    /// Replaces any previously-set registry. For one-off provider registration
    /// see [`Self::oauth_provider`].
    #[cfg(feature = "_oauth-core")]
    pub fn oauth(mut self, registry: OAuthRegistry) -> Self {
        self.oauth = Some(registry);
        self
    }

    /// Append a single provider, lazily initialising the registry on first
    /// call. Convenient when registering one provider at a time:
    ///
    /// ```rust,ignore
    /// let mut builder = AuthConfig::builder(pool, mailer);
    /// if let Some(gh) = GithubProvider::from_env()? {
    ///     builder = builder.oauth_provider(gh);
    /// }
    /// ```
    #[cfg(feature = "_oauth-core")]
    pub fn oauth_provider<P: OAuthProvider>(mut self, provider: P) -> Self {
        let reg = match self.oauth.take() {
            Some(r) => r,
            None => OAuthRegistry::new(self.pool.clone())
                .expect("default reqwest::Client builds with redirect policy only"),
        };
        self.oauth = Some(reg.with_provider(provider));
        self
    }

    /// Short-term session lifespan. Sessions created without "Remember me"
    /// expire after this duration of inactivity. Default: 2 hours.
    pub fn session_lifetime(mut self, d: Duration) -> Self {
        self.session_lifetime = d;
        self
    }

    /// Long-term session lifespan. Sessions created with "Remember me"
    /// stretch to this duration. Default: 30 days.
    pub fn session_max_lifetime(mut self, d: Duration) -> Self {
        self.session_max_lifetime = d;
        self
    }

    /// Cookie `Max-Age`. Should be `>=` the long-term lifespan or the cookie
    /// will be GC'd by the browser before the server-side row expires.
    /// Default: 30 days.
    pub fn cookie_max_age(mut self, d: Duration) -> Self {
        self.cookie_max_age = d;
        self
    }

    /// Replace the rate-limit settings. Pass `None` to disable rate limiting
    /// entirely (the layer is still attached, just permissive).
    #[cfg(feature = "ratelimit")]
    pub fn rate_limit(mut self, rl: Option<RateLimitConfig>) -> Self {
        self.rate_limit = rl;
        self
    }

    /// Override the SQL table name used by `axum_session` for session
    /// persistence. Default: `dx_auth_sessions`.
    pub fn session_table_name(mut self, name: impl Into<String>) -> Self {
        self.session_table_name = name.into();
        self
    }

    /// Replace the audit-log capture/retention settings.
    pub fn audit(mut self, audit: AuditConfig) -> Self {
        self.audit = audit;
        self
    }

    /// Consume the builder and produce the [`AuthConfig`] ready to hand to
    /// [`crate::install`].
    pub fn build(self) -> AuthConfig {
        #[cfg(feature = "_oauth-core")]
        let oauth = self.oauth.unwrap_or_else(|| {
            OAuthRegistry::new(self.pool.clone())
                .expect("default reqwest::Client builds with redirect policy only")
        });
        AuthConfig {
            pool: self.pool,
            #[cfg(feature = "mail")]
            mailer: self.mailer,
            #[cfg(feature = "_oauth-core")]
            oauth,
            session_lifetime: self.session_lifetime,
            session_max_lifetime: self.session_max_lifetime,
            cookie_max_age: self.cookie_max_age,
            #[cfg(feature = "ratelimit")]
            rate_limit: self.rate_limit,
            session_table_name: self.session_table_name,
            audit: self.audit,
        }
    }
}
