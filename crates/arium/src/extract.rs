//! Axum request extractors shared across arium's framework adapters.
//!
//! [`AuditCtx`] pulls audit-relevant request metadata (client IP, User-Agent)
//! out of the request according to the active [`AuditConfig`](crate::config::AuditConfig);
//! [`SessionStore`] is the per-request session handle for the active backend.
//! Both are plain axum primitives with no UI-framework dependency, so the
//! Dioxus and Leptos adapters reuse them as server-fn / handler extractors.

/// Per-request session store axum exposes for the active backend.
pub type SessionStore = axum_session::Session<crate::pool::SessionPool>;

/// Minimal JSON string escaping for audit `details` built in core (which has no
/// runtime `serde_json` dependency — that's dev-only here).
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

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

/// One-stop resource-authz context for server fns: it bundles the session
/// (resolved to the caller's user id), the db pool, the app's
/// [`ResourceAuthority`](crate::authz::ResourceAuthority), and an [`AuditCtx`],
/// so a handler authorizes a resource action in a single line:
///
/// ```rust,ignore
/// #[server]
/// async fn rename_board(board_id: i64, name: String) -> Result<(), ServerFnError> {
///     let ctx: AuthzCtx = extract().await?;
///     ctx.require("board", board_id, ResourceRole::Editor).await?; // 403 unless >= Editor
///     // ... authorized
/// }
/// ```
///
/// This is the documented general-case guard. Apps with a bespoke auth context
/// (e.g. one that also accepts API keys) can replicate [`AuthzCtx::require`]
/// against their own context type — it's a thin wrapper over
/// [`require_resource`](crate::authz::require_resource).
///
/// Rejects with `500` when the db pool or authority extension is missing — a
/// wiring bug, surfaced loudly rather than as a silent deny.
pub struct AuthzCtx {
    user_id: Option<i64>,
    db: crate::pool::Pool,
    authority: crate::authz::SharedResourceAuthority,
    audit: AuditCtx,
}

impl AuthzCtx {
    /// The authenticated caller's user id, or `None` for an anonymous request.
    pub fn user_id(&self) -> Option<i64> {
        self.user_id
    }

    /// Authorize a resource-scoped action: returns the caller's user id when
    /// they hold at least `min_role` on `(kind, id)`, else
    /// [`ResourceAuthzError::Forbidden`](crate::authz::ResourceAuthzError); a
    /// storage failure surfaces as `Lookup`. An authenticated-but-denied
    /// outcome writes a `resource.access.denied` audit row.
    pub async fn require(
        &self,
        kind: &str,
        id: i64,
        min_role: crate::wire::ResourceRole,
    ) -> Result<i64, crate::authz::ResourceAuthzError> {
        let uid = match self.user_id {
            Some(uid) => uid,
            None => return Err(crate::authz::ResourceAuthzError::Forbidden),
        };
        let res = crate::authz::require_resource(
            &*self.authority,
            &self.db,
            uid,
            crate::authz::ResourceRef::new(kind, id),
            min_role,
        )
        .await;
        if matches!(res, Err(crate::authz::ResourceAuthzError::Forbidden)) {
            // `min_role` is a fixed token and `id` an integer; only `kind` is
            // app-supplied, so it's the only field that needs escaping.
            let details = format!(
                r#"{{"kind":"{}","id":{},"min_role":"{}"}}"#,
                json_escape(kind),
                id,
                min_role.as_str(),
            );
            self.audit
                .record(
                    &self.db,
                    crate::auth::audit::RESOURCE_ACCESS_DENIED,
                    Some(uid),
                    None,
                    Some(&details),
                )
                .await;
        }
        res
    }
}

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for AuthzCtx {
    type Rejection = (axum::http::StatusCode, &'static str);

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        // Infallible.
        let audit = AuditCtx::from_request_parts(parts, state).await.unwrap();

        let db = parts
            .extensions
            .get::<crate::pool::Pool>()
            .cloned()
            .ok_or((
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "db pool not registered",
            ))?;
        let authority = parts
            .extensions
            .get::<crate::authz::SharedResourceAuthority>()
            .cloned()
            .ok_or((
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "resource authority not registered",
            ))?;

        // Resolve the caller. A missing/anonymous session is not an error here
        // — it becomes a `None` user id that `require` denies.
        let user_id = match <crate::auth::Session as axum::extract::FromRequestParts<S>>::from_request_parts(parts, state).await {
            Ok(session) => session
                .current_user
                .as_ref()
                .filter(|u| !u.anonymous)
                .map(|u| u.id as i64),
            Err(_) => None,
        };

        Ok(AuthzCtx {
            user_id,
            db,
            authority,
            audit,
        })
    }
}

/// Per-request handle to the app's
/// [`ResourceAuthority`](crate::authz::ResourceAuthority) implementation,
/// pulled from the `Arc<dyn ResourceAuthority>` extension the app registered
/// (via [`AuthConfigBuilder::resource_authority`](crate::AuthConfigBuilder::resource_authority)
/// or its own `Router::layer`). Server fns name it like any other extractor.
///
/// Rejects with `500` when no authority is registered: that's a wiring bug
/// (the app forgot to register one), not a per-request authorization outcome,
/// so it surfaces loudly rather than silently denying.
pub struct ResourceAuthorityExt(pub crate::authz::SharedResourceAuthority);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for ResourceAuthorityExt {
    type Rejection = (axum::http::StatusCode, &'static str);

    fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        let found = parts
            .extensions
            .get::<crate::authz::SharedResourceAuthority>()
            .cloned();
        std::future::ready(found.map(ResourceAuthorityExt).ok_or((
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "resource authority not registered",
        )))
    }
}
