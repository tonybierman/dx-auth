-- Postgres mirror of 0006_audit.

CREATE TABLE IF NOT EXISTS audit_events (
    id          BIGSERIAL PRIMARY KEY,
    occurred_at BIGINT NOT NULL,
    event_type  VARCHAR(64) NOT NULL,
    actor_id    BIGINT REFERENCES users(id) ON DELETE SET NULL,
    target_id   BIGINT REFERENCES users(id) ON DELETE SET NULL,
    ip          TEXT,
    user_agent  TEXT,
    details     TEXT
);

CREATE INDEX IF NOT EXISTS ix_audit_events_occurred_at ON audit_events(occurred_at);
CREATE INDEX IF NOT EXISTS ix_audit_events_actor_id    ON audit_events(actor_id);
CREATE INDEX IF NOT EXISTS ix_audit_events_target_id   ON audit_events(target_id);
CREATE INDEX IF NOT EXISTS ix_audit_events_type        ON audit_events(event_type);

INSERT INTO role_permissions (role_id, token) VALUES
    (1, 'admin:audit:read')
ON CONFLICT (role_id, token) DO NOTHING;
