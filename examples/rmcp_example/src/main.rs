//! `rmcp_example` — a self-contained, arium-protected MCP server.
//!
//! Boots its own SQLite database, runs arium's migrations, seeds a demo user,
//! mints a `dxsk_` API token (printed at startup), and serves an rmcp
//! streamable-HTTP MCP endpoint at `/mcp` that is gated by arium's bearer-token
//! auth via the `arium-mcp` crate. Discovery metadata is served (unauthenticated)
//! at `/.well-known/oauth-protected-resource`.
//!
//! Unlike a stdio MCP server (a local subprocess that, at most, carries one
//! static key to a separate protected backend), here the remote MCP endpoint
//! *itself* is the arium-protected OAuth resource.

mod server;

use std::net::SocketAddr;
use std::str::FromStr;

use anyhow::Context;
use arium::pool::Pool;
use arium_mcp::{AriumMcpState, ResourceMetadata, protect};
use axum::Router;
use rmcp::transport::{
    StreamableHttpServerConfig,
    streamable_http_server::{session::local::LocalSessionManager, tower::StreamableHttpService},
};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use tracing_subscriber::EnvFilter;

use server::DemoMcp;

const DEMO_USERNAME: &str = "mcp-demo";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // Where to listen, and the externally-visible base URL (used to build the
    // resource identifier + metadata URL advertised to MCP clients).
    let addr_str =
        std::env::var("RMCP_EXAMPLE_ADDR").unwrap_or_else(|_| "127.0.0.1:8181".to_string());
    let addr: SocketAddr = addr_str
        .parse()
        .with_context(|| format!("invalid RMCP_EXAMPLE_ADDR: {addr_str}"))?;
    let base_url =
        std::env::var("RMCP_EXAMPLE_BASE_URL").unwrap_or_else(|_| format!("http://{addr}"));

    // SQLite pool — file under the workspace `target/` by default.
    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        format!(
            "sqlite://{}/../../target/rmcp_example.db",
            env!("CARGO_MANIFEST_DIR")
        )
    });
    let connect_opts = SqliteConnectOptions::from_str(&db_url)
        .with_context(|| format!("invalid DATABASE_URL: {db_url}"))?
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(connect_opts)
        .await
        .context("opening SQLite pool")?;

    // arium owns the schema (users, api_keys, audit_events, …).
    arium::migrator().run(&pool).await?;

    // Seed a demo user (idempotent) and mint a fresh token for this run.
    let user_id = ensure_demo_user(&pool).await?;
    let (token, view) = arium::auth::tokens::create_for_user(&pool, user_id, "rmcp-demo").await?;

    // rmcp streamable-HTTP service, mounted at /mcp.
    let mcp_service = StreamableHttpService::new(
        || Ok(DemoMcp::new()),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default(),
    );
    let mcp_router = Router::new().nest_service("/mcp", mcp_service);

    // arium resource-server protection: bearer validation + RFC 9728 metadata +
    // audit logging (granted opt-in enabled here so the demo shows both rows).
    let resource = format!("{}/mcp", base_url.trim_end_matches('/'));
    let meta = ResourceMetadata::new(resource.clone())
        .authorization_server(base_url.clone())
        .documentation("https://github.com/tonybierman/arium/tree/main/examples/rmcp_example");
    let state = AriumMcpState::new(pool.clone(), meta.metadata_url(&base_url)).audit_granted(true);
    let app = protect(mcp_router, state, meta);

    print_banner(&base_url, &resource, &token, &view.prefix);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    // `with_connect_info` so the audit layer can capture the client IP.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("serving")?;
    Ok(())
}

/// Find-or-create the demo user. Runs on every startup, so it must be idempotent
/// (the `username` column is unique-ish by convention here).
async fn ensure_demo_user(pool: &Pool) -> anyhow::Result<i64> {
    if let Some(id) = sqlx::query_scalar::<_, i64>("SELECT id FROM users WHERE username = $1")
        .bind(DEMO_USERNAME)
        .fetch_optional(pool)
        .await?
    {
        return Ok(id);
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let id = sqlx::query_scalar::<_, i64>(
        "INSERT INTO users (anonymous, username, display_name, email, email_verified_at) \
         VALUES (false, $1, $2, $3, $4) RETURNING id",
    )
    .bind(DEMO_USERNAME)
    .bind("MCP Demo User")
    .bind("mcp-demo@example.com")
    .bind(now)
    .fetch_one(pool)
    .await?;
    Ok(id)
}

fn print_banner(base_url: &str, resource: &str, token: &str, prefix: &str) {
    let meta_url = format!(
        "{}/.well-known/oauth-protected-resource",
        base_url.trim_end_matches('/')
    );
    println!(
        "\n\
========================================================================\n\
 arium-protected MCP server (rmcp_example) — resource-server demo\n\
========================================================================\n\
 MCP endpoint            : {resource}\n\
 Protected-resource meta : {meta_url}\n\
\n\
 Demo API token (minted via arium::auth::tokens::create_for_user, prefix {prefix};\n\
 stored hashed in api_keys, shown once):\n\
\n\
   {token}\n\
\n\
 Try it:\n\
   # discovery (no token):\n\
   curl -s {meta_url}\n\
\n\
   # rejected without a token (401 + WWW-Authenticate):\n\
   curl -i -X POST {resource}\n\
\n\
   # MCP initialize WITH the token:\n\
   curl -i -X POST {resource} \\\n\
     -H 'Authorization: Bearer {token}' \\\n\
     -H 'Content-Type: application/json' \\\n\
     -H 'Accept: application/json, text/event-stream' \\\n\
     -d '{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{{}},\"clientInfo\":{{\"name\":\"curl\",\"version\":\"0\"}}}}}}'\n\
\n\
 Or point MCP Inspector at {resource} with header `Authorization: Bearer <token>`.\n\
========================================================================\n"
    );
}
