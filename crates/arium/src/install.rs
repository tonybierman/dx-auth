//! Single entry point that bolts arium onto an `axum::Router`.
//!
//! ```rust,ignore
//! let router = arium::install(my_axum_router, cfg).await?;
//! Ok(router)
//! ```

use crate::pool::SessionPool;
use axum::Router;
use axum_session::{SessionConfig, SessionLayer, SessionStore};
use axum_session_auth::AuthConfig as AxumAuthConfig;

use crate::auth::AuthLayer;
use crate::config::AuthConfig;

/// Attach all arium wiring to `router` and return the augmented Router.
///
/// What this does, in order:
///
/// 1. Mounts `/auth/{provider}/login` + `/auth/{provider}/callback` routes for
///    every provider registered on the config's OAuth registry. With no
///    providers (or when `_oauth-core` is off) this is a no-op.
/// 2. Layers a per-IP rate limiter (when configured) using a key extractor
///    that gracefully falls back to a fixed sentinel address if no IP source
///    is available (so the first request under `dx serve` doesn't 500).
/// 3. Adds `axum::Extension`s for the [`Pool`](crate::pool::Pool), the list
///    of `ProviderInfo` available_providers serves, and the `Mailer` (when
///    the `mail` feature is on).
/// 4. Adds the `axum_session_auth::AuthSessionLayer` with the anonymous Guest
///    user (`id = 1`).
/// 5. Adds the `axum_session::SessionLayer` with cookie / lifetime settings
///    from the config.
pub async fn install(router: Router, cfg: AuthConfig) -> anyhow::Result<Router> {
    let mut router = router;

    // 0) Reconcile bootstrap admin from env. Idempotent — grants the `admin`
    // role to whoever `DX_AUTH_BOOTSTRAP_ADMIN_EMAIL` points at if that user
    // already exists. Pairs with `maybe_bootstrap_admin` on the signup path
    // and `maybe_grant_first_admin` (first-user-wins).
    crate::auth::sync_bootstrap_admin(&cfg.pool).await?;

    // 1) OAuth provider routes. One pair per registered provider; the registry
    //    drives both the route table and the `available_providers` response.
    #[cfg(feature = "_oauth-core")]
    let provider_infos: Vec<crate::wire::ProviderInfo> = {
        let mut infos = Vec::new();
        if !cfg.oauth.is_empty() {
            let oauth_router = Router::new()
                .route(
                    "/auth/{provider}/login",
                    axum::routing::get(crate::oauth::oauth_login),
                )
                .route(
                    "/auth/{provider}/callback",
                    axum::routing::get(crate::oauth::oauth_callback),
                )
                .with_state(cfg.oauth.clone());
            router = router.merge(oauth_router);

            for p in cfg.oauth.list() {
                infos.push(crate::wire::ProviderInfo {
                    name: p.name().to_string(),
                    display_name: p.display_name().to_string(),
                    login_url: format!("/auth/{}/login", p.name()),
                    icon_svg: p.icon_svg().map(|s| s.to_string()),
                });
            }
        }
        infos
    };
    #[cfg(not(feature = "_oauth-core"))]
    let provider_infos: Vec<crate::wire::ProviderInfo> = Vec::new();

    // 2) Rate limit (compiled out without `ratelimit`).
    #[cfg(feature = "ratelimit")]
    if let Some(rl) = cfg.rate_limit.as_ref() {
        let governor_config = tower_governor::governor::GovernorConfigBuilder::default()
            .key_extractor(LenientIpKeyExtractor)
            .per_second(rl.per_second)
            .burst_size(rl.burst)
            .finish()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "invalid rate-limit config (per_second={}, burst={})",
                    rl.per_second,
                    rl.burst,
                )
            })?;
        let governor_config = std::sync::Arc::new(governor_config);
        let limiter = governor_config.limiter().clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                limiter.retain_recent();
            }
        });
        router = router.layer(tower_governor::GovernorLayer::new(governor_config));
    }

    // 3) Extensions visible to all server fns.
    router = router.layer(axum::Extension(cfg.pool.clone()));
    router = router.layer(axum::Extension(cfg.audit.clone()));
    router = router.layer(axum::Extension(std::sync::Arc::new(provider_infos)));
    #[cfg(feature = "mail")]
    {
        router = router.layer(axum::Extension(cfg.mailer.clone()));
    }

    // 3b) Background audit-log prune. No-ops when retention_days == 0.
    if cfg.audit.retention_days > 0 {
        let prune_pool = cfg.pool.clone();
        let retention = cfg.audit.retention_days;
        tokio::spawn(async move {
            // First sweep on the next minute, then hourly. Long-running
            // processes should still see at least one sweep early so a
            // freshly-restarted app doesn't carry a 6-month backlog.
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            loop {
                match crate::auth::audit::prune(&prune_pool, retention).await {
                    Ok(n) if n > 0 => {
                        eprintln!("[audit] pruned {n} event(s) older than {retention}d");
                    }
                    Ok(_) => {}
                    Err(err) => {
                        eprintln!("[audit] WARN: prune failed: {err}");
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            }
        });
    }

    // 4) Auth session layer (anonymous Guest user id 1).
    router = router.layer(
        AuthLayer::new(Some(cfg.pool.clone()))
            .with_config(AxumAuthConfig::<i64>::default().with_anonymous_user_id(Some(1))),
    );

    // 5) Session layer.
    let session_store = SessionStore::<SessionPool>::new(
        Some(cfg.pool.into()),
        SessionConfig::default()
            .with_table_name(cfg.session_table_name)
            // Don't bind sessions to client IP/UA — under `dx serve` the
            // browser may hit 127.0.0.1 on one request and ::1 on another.
            .with_ip_and_user_agent(false)
            .with_lifetime(cfg.session_lifetime)
            .with_max_lifetime(cfg.session_max_lifetime)
            .with_max_age(Some(cfg.cookie_max_age)),
    )
    .await?;
    router = router.layer(SessionLayer::new(session_store));

    Ok(router)
}

/// Like `tower_governor::key_extractor::SmartIpKeyExtractor` but falls back
/// to a fixed sentinel address when no IP source is available (e.g. local
/// `dx serve` without `ConnectInfo`). Without this fallback the very first
/// request 500s with "Unable To Extract Key!". In production behind a real
/// proxy the smart path will fire and per-IP limits kick in normally.
#[cfg(feature = "ratelimit")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LenientIpKeyExtractor;

#[cfg(feature = "ratelimit")]
impl tower_governor::key_extractor::KeyExtractor for LenientIpKeyExtractor {
    type Key = std::net::IpAddr;

    fn extract<T>(
        &self,
        req: &http::Request<T>,
    ) -> Result<Self::Key, tower_governor::GovernorError> {
        use tower_governor::key_extractor::SmartIpKeyExtractor;
        Ok(SmartIpKeyExtractor
            .extract(req)
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)))
    }
}
