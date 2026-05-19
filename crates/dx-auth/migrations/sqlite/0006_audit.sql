-- Audit log: one row per security-relevant event (sign-in, sign-out,
-- admin actions, account self-service). Retention is handled by a
-- background task in install.rs that periodically deletes rows older
-- than AuthConfig::audit_retention_days.

CREATE TABLE IF NOT EXISTS audit_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at INTEGER NOT NULL,                          -- unix seconds
    event_type  VARCHAR(64) NOT NULL,                      -- e.g. user.login.success
    actor_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
    target_id   INTEGER REFERENCES users(id) ON DELETE SET NULL,
    ip          TEXT,
    user_agent  TEXT,
    details     TEXT                                       -- JSON blob, app-defined
);

CREATE INDEX IF NOT EXISTS ix_audit_events_occurred_at ON audit_events(occurred_at);
CREATE INDEX IF NOT EXISTS ix_audit_events_actor_id    ON audit_events(actor_id);
CREATE INDEX IF NOT EXISTS ix_audit_events_target_id   ON audit_events(target_id);
CREATE INDEX IF NOT EXISTS ix_audit_events_type        ON audit_events(event_type);

-- Grant the admin role read access on the audit log.
INSERT INTO role_permissions (role_id, token) VALUES
    (1, 'admin:audit:read')
ON CONFLICT (role_id, token) DO NOTHING;
