-- Unix seconds when the user verified their email address. NULL = unverified
-- and will block password sign-in until they click the link in their inbox.
ALTER TABLE users ADD COLUMN email_verified_at INTEGER;

-- Grandfather every account that existed before this migration so we don't
-- lock anyone out. (For OAuth-only accounts the email column may be NULL,
-- which is fine — the verification check only applies to password sign-ins.)
UPDATE users
   SET email_verified_at = strftime('%s', 'now')
 WHERE email_verified_at IS NULL;

CREATE TABLE IF NOT EXISTS email_verification_tokens (
    token       TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_email_verification_tokens_user_id
    ON email_verification_tokens(user_id);
