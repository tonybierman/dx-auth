//! Bearer-token authentication middleware.
//!
//! A request carrying `Authorization: Bearer <token>` is matched against a
//! non-revoked row in the `api_keys` table (created by [`migrator`] and the
//! `tokens` feature). On a hit the caller is injected as an [`ApiKeyUser`]
//! request extension, which the [`AuthUser`](crate::extract::AuthUser) and
//! [`AuthzCtx`](crate::extract::AuthzCtx) extractors prefer over the session
//! cookie — so programmatic clients authenticate with a token instead of a
//! browser session, transparently to server fns.
//!
//! [`install`](crate::install) applies this middleware automatically when the
//! `tokens` feature is on; apps don't wire it up themselves. The token
//! lifecycle (mint / hash / list / revoke) lives in
//! [`auth::tokens`](crate::auth::tokens) — this module is only the request-time
//! lookup, hashing the presented token with the same
//! [`hash_api_token`](crate::auth::tokens::hash_api_token) so the lookup
//! matches whatever `auth::tokens::create_for_user` persisted.
//!
//! [`migrator`]: crate::migrator

use crate::auth::tokens::hash_api_token;
use crate::pool::Pool;
use axum::body::Body;
use axum::http::{Request, header::AUTHORIZATION};
use axum::middleware::Next;
use axum::response::Response;

/// Request extension set by the bearer-auth middleware when a valid token is
/// presented. The [`AuthUser`](crate::extract::AuthUser) /
/// [`AuthzCtx`](crate::extract::AuthzCtx) extractors resolve their acting user
/// from this (preferred) or from the session cookie as a fallback.
#[derive(Clone, Copy, Debug)]
pub struct ApiKeyUser {
    /// The user the token authenticates as.
    pub user_id: i64,
    /// The `api_keys` row id (for `last_used_at` bookkeeping / audit).
    pub key_id: i64,
}

/// Validate a presented bearer token against the `api_keys` table.
///
/// Hashes `token` with [`hash_api_token`](crate::auth::tokens::hash_api_token)
/// and looks up a non-revoked row; on a hit, returns the resolved
/// [`ApiKeyUser`] and bumps `last_used_at` in the background. Returns `None`
/// for a missing / blank / unknown / revoked token. Lookup errors are logged
/// and treated as `None` (fail-closed for auth purposes).
///
/// This is the shared validation path used both by the [`bearer_auth`]
/// middleware [`install`](crate::install) applies and by out-of-tree consumers
/// that gate their own endpoints on arium tokens (e.g. an MCP server protected
/// via `arium-mcp`). `token` is the raw bearer credential *without* the
/// `Bearer ` scheme prefix.
pub async fn authenticate_token(pool: &Pool, token: &str) -> Option<ApiKeyUser> {
    let token = token.trim();
    if token.is_empty() {
        return None;
    }

    let hash = hash_api_token(token);
    let row: Result<Option<(i64, i64)>, _> = sqlx::query_as(
        "SELECT id, user_id FROM api_keys WHERE token_hash = $1 AND revoked_at IS NULL",
    )
    .bind(&hash)
    .fetch_optional(pool)
    .await;

    match row {
        Ok(Some((key_id, user_id))) => {
            let p = pool.clone();
            tokio::spawn(async move {
                if let Err(e) = sqlx::query(
                    "UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE id = $1",
                )
                .bind(key_id)
                .execute(&p)
                .await
                {
                    eprintln!("[api_key] WARN: last_used_at update failed (key {key_id}): {e}");
                }
            });
            Some(ApiKeyUser { user_id, key_id })
        }
        Ok(None) => None,
        Err(e) => {
            eprintln!("[api_key] WARN: api_keys lookup failed: {e}");
            None
        }
    }
}

/// Axum middleware: if the request carries a `Authorization: Bearer …` header
/// matching a non-revoked `api_keys` row, inject [`ApiKeyUser`] into the
/// request extensions and bump `last_used_at` in the background.
///
/// Missing / malformed / revoked tokens are silently ignored — the session
/// layer may still authenticate via cookie, and server fns that require auth
/// produce the 401 themselves. Applied by [`install`](crate::install) with the
/// configured pool captured. The actual validation is delegated to
/// [`authenticate_token`].
pub(crate) async fn bearer_auth(pool: Pool, mut req: Request<Body>, next: Next) -> Response {
    if let Some(token) = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        && let Some(user) = authenticate_token(&pool, token).await
    {
        req.extensions_mut().insert(user);
    }
    next.run(req).await
}
