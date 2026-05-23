-- Postgres mirror of 0007_api_keys.
--
-- API keys bound to a user account. Cleartext tokens are NEVER stored;
-- only the SHA-256 hex hash. The 8-char `prefix` is the first chars of
-- the cleartext (e.g. `dxsk_abcd`) so the UI can show "dxsk_abcd…" in a
-- key list without needing the secret back. Revocation is soft: setting
-- `revoked_at` removes the row from auth consideration without losing
-- the audit trail.

CREATE TABLE IF NOT EXISTS api_keys (
    id           BIGSERIAL PRIMARY KEY,
    user_id      BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    prefix       TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS api_keys_user ON api_keys(user_id);
