//! Protect a remote MCP server as an arium OAuth 2.0 Resource Server.
//!
//! `arium-mcp` turns any MCP HTTP endpoint (e.g. an `rmcp` streamable-HTTP
//! service) into an OAuth 2.0 *Resource Server* guarded by arium's API tokens.
//! It is deliberately **rmcp-version-agnostic**: it operates purely at the
//! axum/tower boundary, so it composes with whatever `rmcp` (or other MCP
//! server) you mount behind it.
//!
//! What it provides:
//!
//! - A per-request bearer-auth layer that validates `Authorization: Bearer
//!   <token>` against arium's `api_keys` table (via `arium::authenticate_token`)
//!   and rejects unauthenticated callers with `401` plus a `WWW-Authenticate`
//!   header pointing at the metadata document (per the MCP authorization spec).
//! - The RFC 9728 Protected Resource Metadata document, served at
//!   `/.well-known/oauth-protected-resource`, so MCP clients can discover where
//!   to authenticate.
//! - Audit logging through arium's existing `audit_events` log: a
//!   `mcp.access.denied` row on every rejected request, and an opt-in
//!   `mcp.access.granted` row on accepted ones.
//!
//! ## Usage
//!
//! ```rust,no_run
//! # fn doc() {
//! use arium_mcp::{AriumMcpState, ResourceMetadata, protect};
//! use axum::Router;
//!
//! # let pool: arium::pool::Pool = unimplemented!();
//! # let mcp_service: Router = unimplemented!();
//! let base = "http://127.0.0.1:8080";
//!
//! let meta = ResourceMetadata::new(format!("{base}/mcp"))
//!     .authorization_server(base.to_string());
//!
//! let state = AriumMcpState::new(pool, meta.metadata_url(base))
//!     .audit_granted(true);
//!
//! // `mcp_service` is your MCP endpoint nested under `/mcp`, e.g.
//! // `Router::new().nest_service("/mcp", rmcp_streamable_http_service)`.
//! let app: Router = protect(mcp_service, state, meta);
//! # let _ = app;
//! # }
//! ```
//!
//! Serve `app` with `into_make_service_with_connect_info::<SocketAddr>()` so the
//! audit layer can capture the client IP.
//!
//! This is *resource-server* mode: tokens are minted out-of-band (arium's token
//! UI / `arium::auth::tokens::create_for_user`) and presented as bearer
//! credentials. `arium-mcp` does not implement an OAuth Authorization Server
//! (no `/authorize`, `/token`, dynamic client registration, or PKCE auth-code
//! flow).

use std::net::SocketAddr;

use arium::pool::Pool;
use axum::Router;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::header::{AUTHORIZATION, USER_AGENT, WWW_AUTHENTICATE};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use serde::Serialize;
use std::sync::Arc;

/// The well-known path (RFC 9728) where Protected Resource Metadata is served.
pub const WELL_KNOWN_PATH: &str = "/.well-known/oauth-protected-resource";

/// Audit event type recorded when a request is rejected (missing/invalid token).
pub const MCP_ACCESS_DENIED: &str = "mcp.access.denied";
/// Audit event type recorded when an authenticated request is allowed through
/// (only when [`AriumMcpState::audit_granted`] is enabled).
pub const MCP_ACCESS_GRANTED: &str = "mcp.access.granted";

/// OAuth 2.0 Protected Resource Metadata (RFC 9728).
///
/// Served as JSON at [`WELL_KNOWN_PATH`]; advertises this MCP endpoint as a
/// protected resource and points clients at the authorization server(s) that
/// can issue tokens for it.
#[derive(Debug, Clone, Serialize)]
pub struct ResourceMetadata {
    /// The resource identifier — the canonical URL of the protected MCP
    /// endpoint (e.g. `https://host/mcp`).
    pub resource: String,
    /// Authorization server issuer URLs that can mint tokens for this resource.
    pub authorization_servers: Vec<String>,
    /// How bearer tokens may be presented. Defaults to `["header"]`.
    pub bearer_methods_supported: Vec<String>,
    /// OAuth scopes understood by this resource. Empty by default.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub scopes_supported: Vec<String>,
    /// Optional human-facing documentation URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_documentation: Option<String>,
}

impl ResourceMetadata {
    /// Start a metadata document for the given resource URL (the MCP endpoint).
    /// `bearer_methods_supported` defaults to `["header"]`.
    pub fn new(resource: impl Into<String>) -> Self {
        Self {
            resource: resource.into(),
            authorization_servers: Vec::new(),
            bearer_methods_supported: vec!["header".to_string()],
            scopes_supported: Vec::new(),
            resource_documentation: None,
        }
    }

    /// Add an authorization server issuer URL (chainable).
    pub fn authorization_server(mut self, url: impl Into<String>) -> Self {
        self.authorization_servers.push(url.into());
        self
    }

    /// Declare a supported OAuth scope (chainable).
    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.scopes_supported.push(scope.into());
        self
    }

    /// Set the documentation URL (chainable).
    pub fn documentation(mut self, url: impl Into<String>) -> Self {
        self.resource_documentation = Some(url.into());
        self
    }

    /// Build the absolute URL of the metadata document for a given base, used
    /// in the `resource_metadata` field of the `WWW-Authenticate` challenge.
    pub fn metadata_url(&self, base_url: &str) -> String {
        format!("{}{WELL_KNOWN_PATH}", base_url.trim_end_matches('/'))
    }
}

/// State shared with the bearer-auth layer.
#[derive(Clone)]
pub struct AriumMcpState {
    pool: Pool,
    /// Absolute URL of the metadata document, advertised in `WWW-Authenticate`.
    resource_metadata_url: String,
    /// Whether to also audit *granted* access (off by default to avoid
    /// flooding the log on chatty endpoints — mirrors arium's own convention
    /// of recording DENIED by default and GRANTED opt-in).
    audit_granted: bool,
}

impl AriumMcpState {
    /// Build the layer state from an arium pool and the absolute metadata URL
    /// (typically `ResourceMetadata::metadata_url(base)`).
    pub fn new(pool: Pool, resource_metadata_url: impl Into<String>) -> Self {
        Self {
            pool,
            resource_metadata_url: resource_metadata_url.into(),
            audit_granted: false,
        }
    }

    /// Enable (or disable) recording a `mcp.access.granted` audit row on every
    /// accepted request. Off by default.
    pub fn audit_granted(mut self, enabled: bool) -> Self {
        self.audit_granted = enabled;
        self
    }
}

/// A `Router` serving only the RFC 9728 metadata document at
/// [`WELL_KNOWN_PATH`]. Mount this *outside* the auth layer so discovery works
/// without a token. [`protect`] wires this up for you.
pub fn metadata_router(meta: ResourceMetadata) -> Router {
    let meta = Arc::new(meta);
    Router::new().route(
        WELL_KNOWN_PATH,
        get(move || {
            let meta = meta.clone();
            async move { Json((*meta).clone()) }
        }),
    )
}

/// Compose a protected MCP app: apply the bearer-auth + audit layer to
/// `mcp_router` and merge in the public metadata endpoint.
///
/// `mcp_router` is your MCP endpoint already nested under its path, e.g.
/// `Router::new().nest_service("/mcp", rmcp_streamable_http_service)`. The
/// metadata route is merged separately so it stays reachable without a token.
pub fn protect(mcp_router: Router, state: AriumMcpState, meta: ResourceMetadata) -> Router {
    let guarded = mcp_router.layer(axum::middleware::from_fn_with_state(state, bearer_guard));
    metadata_router(meta).merge(guarded)
}

/// The bearer-auth + audit middleware. Validates the token, gates the request,
/// and records an audit row. On success the resolved `arium::ApiKeyUser` is
/// inserted into the request extensions (so downstream layers can read it).
async fn bearer_guard(State(state): State<AriumMcpState>, req: Request, next: Next) -> Response {
    let headers = req.headers();
    let user_agent = headers
        .get(USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    // `ConnectInfo` is best-effort: present only when the app is served with
    // `into_make_service_with_connect_info`. Read it leniently from extensions
    // so a missing source never 500s the request.
    let ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip().to_string());
    let path = req.uri().path().to_owned();
    let details = serde_json::json!({ "path": path }).to_string();

    let token = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let user = match token {
        Some(token) => arium::authenticate_token(&state.pool, token).await,
        None => None,
    };

    match user {
        Some(user) => {
            if state.audit_granted {
                arium::auth::audit::record_or_log(
                    &state.pool,
                    arium::auth::audit::RecordInput {
                        event_type: MCP_ACCESS_GRANTED,
                        actor_id: Some(user.user_id),
                        target_id: None,
                        ip: ip.as_deref(),
                        user_agent: user_agent.as_deref(),
                        details: Some(&details),
                    },
                )
                .await;
            }
            let mut req = req;
            req.extensions_mut().insert(user);
            next.run(req).await
        }
        None => {
            arium::auth::audit::record_or_log(
                &state.pool,
                arium::auth::audit::RecordInput {
                    event_type: MCP_ACCESS_DENIED,
                    actor_id: None,
                    target_id: None,
                    ip: ip.as_deref(),
                    user_agent: user_agent.as_deref(),
                    details: Some(&details),
                },
            )
            .await;
            unauthorized(&state.resource_metadata_url)
        }
    }
}

/// Build the `401 Unauthorized` response with the RFC 9728 `WWW-Authenticate`
/// challenge pointing at the Protected Resource Metadata document.
fn unauthorized(resource_metadata_url: &str) -> Response {
    let challenge = format!("Bearer resource_metadata=\"{resource_metadata_url}\"");
    let mut resp = (
        StatusCode::UNAUTHORIZED,
        "missing or invalid bearer token\n",
    )
        .into_response();
    if let Ok(value) = HeaderValue::from_str(&challenge) {
        resp.headers_mut().insert(WWW_AUTHENTICATE, value);
    }
    resp
}
