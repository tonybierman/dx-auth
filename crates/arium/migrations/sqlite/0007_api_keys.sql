-- API keys bound to a user account. Used by standup-mcp (and any other
-- programmatic client) to bypass the session-cookie auth path. Cleartext
-- tokens are NEVER stored; only the SHA-256 hex hash. The 8-char `prefix`
-- is the first chars of the cleartext (e.g. `dxsk_abcd`) so the UI can
-- show "dxsk_abcd…" in a key list without needing the secret back.
--
-- Revocation is soft: setting `revoked_at` removes the row from auth
-- consideration without losing the audit trail.

CREATE TABLE IF NOT EXISTS api_keys (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    prefix       TEXT NOT NULL,
    created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP,
    revoked_at   TIMESTAMP
);

CREATE INDEX IF NOT EXISTS api_keys_user ON api_keys(user_id);
