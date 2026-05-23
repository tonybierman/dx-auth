-- TOTP secret (base32). Populated when a user starts MFA enrollment.
-- mfa_enabled_at flips from NULL to unix-seconds the moment they confirm
-- enrollment by submitting a valid 6-digit code from their authenticator app.
ALTER TABLE users ADD COLUMN mfa_secret TEXT;
ALTER TABLE users ADD COLUMN mfa_enabled_at BIGINT;

-- One-time backup codes the user can use in place of a TOTP. Stored Argon2-
-- hashed so the DB doesn't leak usable codes. `used_at` is set the first time
-- a code is consumed; rows aren't deleted so the audit trail (and the
-- "remaining codes" count) survives.
CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
    user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    used_at    BIGINT,
    PRIMARY KEY (user_id, code_hash)
);
