//! Axum request extractors shared across arium's framework adapters.
//!
//! [`AuditCtx`] pulls audit-relevant request metadata (client IP, User-Agent)
//! out of the request according to the active [`AuditConfig`](crate::config::AuditConfig);
//! [`SessionStore`] is the per-request session handle for the active backend.
//! Both are plain axum primitives with no UI-framework dependency, so the
//! Dioxus and Leptos adapters reuse them as server-fn / handler extractors.

/// Per-request session store axum exposes for the active backend.
pub type SessionStore = axum_session::Session<crate::pool::SessionPool>;

/// Bundle of audit-relevant request info pulled out by the extractor below.
/// Handlers consume this and pass it through to [`AuditCtx::record`].
#[derive(Debug, Clone, Default)]
pub struct AuditCtx {
    /// Capture/retention settings inherited from [`crate::AuthConfig`].
    pub config: crate::config::AuditConfig,
    /// Client IP, when `config.capture_ip` is on and an address is available.
    pub ip: Option<String>,
    /// Client `User-Agent`, when `config.capture_user_agent` is on.
    pub user_agent: Option<String>,
}

impl AuditCtx {
    /// Writes one audit row, stamping it with the IP and User-Agent captured
    /// at extraction time. `actor_id` is who performed the action, `target_id`
    /// who it acted on (often the same), and `details` an optional JSON blob.
    /// Best-effort: a write failure is logged, not propagated — see
    /// [`record_or_log`](crate::auth::audit::record_or_log).
    pub async fn record(
        &self,
        db: &crate::pool::Pool,
        event_type: &str,
        actor_id: Option<i64>,
        target_id: Option<i64>,
        details: Option<&str>,
    ) {
        crate::auth::audit::record_or_log(
            db,
            crate::auth::audit::RecordInput {
                event_type,
                actor_id,
                target_id,
                ip: self.ip.as_deref(),
                user_agent: self.user_agent.as_deref(),
                details,
            },
        )
        .await
    }
}

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for AuditCtx {
    type Rejection = std::convert::Infallible;

    fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        let config = parts
            .extensions
            .get::<crate::config::AuditConfig>()
            .cloned()
            .unwrap_or_default();

        let ip = if config.capture_ip {
            parts
                .extensions
                .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                .map(|ci| ci.0.ip().to_string())
                .or_else(|| {
                    parts
                        .headers
                        .get("x-forwarded-for")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.split(',').next())
                        .map(|s| s.trim().to_string())
                })
                .or_else(|| {
                    parts
                        .headers
                        .get("x-real-ip")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string())
                })
        } else {
            None
        };

        let user_agent = if config.capture_user_agent {
            parts
                .headers
                .get(axum::http::header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        } else {
            None
        };

        std::future::ready(Ok(AuditCtx {
            config,
            ip,
            user_agent,
        }))
    }
}
