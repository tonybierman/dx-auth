[![Crates.io](https://img.shields.io/crates/v/arium-mcp.svg)](https://crates.io/crates/arium-mcp)
[![Docs.rs](https://docs.rs/arium-mcp/badge.svg)](https://docs.rs/arium-mcp)
[![CI](https://github.com/tonybierman/arium/actions/workflows/ci.yml/badge.svg)](https://github.com/tonybierman/arium/actions)
[![License](https://img.shields.io/crates/l/arium-mcp.svg)](#license)

# arium-mcp

<!-- The section below is generated from src/lib.rs by cargo-rdme. Edit the `//!` doc comment, then run `cargo rdme`. -->
<!-- cargo-rdme start -->

Protect a remote MCP server as an arium OAuth 2.0 Resource Server.

`arium-mcp` turns any MCP HTTP endpoint (e.g. an `rmcp` streamable-HTTP
service) into an OAuth 2.0 *Resource Server* guarded by arium's API tokens.
It is deliberately **rmcp-version-agnostic**: it operates purely at the
axum/tower boundary, so it composes with whatever `rmcp` (or other MCP
server) you mount behind it.

What it provides:

- A per-request bearer-auth layer that validates `Authorization: Bearer
  <token>` against arium's `api_keys` table (via `arium::authenticate_token`)
  and rejects unauthenticated callers with `401` plus a `WWW-Authenticate`
  header pointing at the metadata document (per the MCP authorization spec).
- The RFC 9728 Protected Resource Metadata document, served at
  `/.well-known/oauth-protected-resource`, so MCP clients can discover where
  to authenticate.
- Audit logging through arium's existing `audit_events` log: a
  `mcp.access.denied` row on every rejected request, and an opt-in
  `mcp.access.granted` row on accepted ones.

### Usage

```rust
use arium_mcp::{AriumMcpState, ResourceMetadata, protect};
use axum::Router;

let base = "http://127.0.0.1:8080";

let meta = ResourceMetadata::new(format!("{base}/mcp"))
    .authorization_server(base.to_string());

let state = AriumMcpState::new(pool, meta.metadata_url(base))
    .audit_granted(true);

// `mcp_service` is your MCP endpoint nested under `/mcp`, e.g.
// `Router::new().nest_service("/mcp", rmcp_streamable_http_service)`.
let app: Router = protect(mcp_service, state, meta);
```

Serve `app` with `into_make_service_with_connect_info::<SocketAddr>()` so the
audit layer can capture the client IP.

This is *resource-server* mode: tokens are minted out-of-band (arium's token
UI / `arium::auth::tokens::create_for_user`) and presented as bearer
credentials. `arium-mcp` does not implement an OAuth Authorization Server
(no `/authorize`, `/token`, dynamic client registration, or PKCE auth-code
flow).

<!-- cargo-rdme end -->
