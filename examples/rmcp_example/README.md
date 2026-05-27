# rmcp_example — an arium-protected MCP server

A self-contained [rmcp](https://crates.io/crates/rmcp) **streamable-HTTP** MCP server
whose endpoint is guarded by [arium](../../crates/arium)'s bearer-token auth, via the
reusable [`arium-mcp`](../../crates/arium-mcp) crate. It is the proof of work for
treating a remote MCP server as an **OAuth 2.0 Resource Server**.

## What it demonstrates

- **Bearer auth at the MCP boundary.** Every request to `/mcp` must carry a valid arium
  API token (`Authorization: Bearer dxsk_…`). Unauthenticated calls get `401` with a
  `WWW-Authenticate: Bearer resource_metadata="…"` challenge.
- **Discovery.** RFC 9728 Protected Resource Metadata is served (without a token) at
  `/.well-known/oauth-protected-resource`.
- **Auditing.** Access is recorded in arium's `audit_events` log — `mcp.access.denied`
  on every rejected request, and `mcp.access.granted` on accepted ones (the demo opts
  into granted-auditing so you can see both).

## Why streamable-HTTP (not stdio)

A typical stdio MCP server is a local subprocess; if it talks to a protected backend at
all, it carries one static key, and auth happens on that backend rather than at the MCP
layer. There's no per-caller identity, 401 challenge, or discovery.

Here the **remote MCP endpoint itself** is the arium-protected OAuth resource:
per-request, per-caller bearer validation, a 401 challenge, and discovery metadata —
the things that only make sense for a network-exposed (streamable-HTTP) MCP server.

## Run it

```bash
cargo run -p rmcp_example
```

On startup it creates a SQLite DB (`target/rmcp_example.db` by default), runs arium's
migrations, seeds a demo user, mints a fresh `dxsk_` token, and **prints the token plus
copy-paste `curl` commands**. Environment overrides:

- `RMCP_EXAMPLE_ADDR` — listen address (default `127.0.0.1:8181`)
- `RMCP_EXAMPLE_BASE_URL` — externally-visible base URL (default `http://<addr>`)
- `DATABASE_URL` — SQLite URL (default a file under the workspace `target/`)

## Verify

```bash
# Discovery (no token needed):
curl -s http://127.0.0.1:8181/.well-known/oauth-protected-resource

# Rejected without a token → 401 + WWW-Authenticate:
curl -i -X POST http://127.0.0.1:8181/mcp

# MCP initialize WITH the token (use the one printed at startup):
curl -i -X POST http://127.0.0.1:8181/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}'
```

Or point [MCP Inspector](https://github.com/modelcontextprotocol/inspector)
(`npx @modelcontextprotocol/inspector`) at `http://127.0.0.1:8181/mcp` with an
`Authorization: Bearer <token>` header.

Inspect the audit trail:

```bash
sqlite3 target/rmcp_example.db \
  "SELECT occurred_at, event_type, actor_id, ip FROM audit_events WHERE event_type LIKE 'mcp.%' ORDER BY occurred_at DESC"
```

## Scope

This is **resource-server** mode: tokens are minted out-of-band (the demo prints one) and
presented as bearer credentials. It does **not** implement an OAuth Authorization Server
(no `/authorize`, `/token`, dynamic client registration, or PKCE auth-code flow), so MCP
clients that *require* the interactive OAuth dance won't auto-flow; clients that accept a
manually supplied bearer token will. The two demo tools (`ping`, `echo`) are deliberately
trivial — the point is that the endpoint is gated.
