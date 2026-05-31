-- Postgres mirror of 0005_roles.

CREATE TABLE IF NOT EXISTS roles (
    id          BIGSERIAL PRIMARY KEY,
    name        VARCHAR(64) NOT NULL UNIQUE,
    description TEXT,
    is_system   BOOLEAN NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id BIGINT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    token   VARCHAR(256) NOT NULL,
    PRIMARY KEY (role_id, token)
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id BIGINT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

ALTER TABLE users ADD COLUMN deleted_at BIGINT;
ALTER TABLE users ADD COLUMN display_name TEXT;

INSERT INTO roles (id, name, description, is_system) VALUES
    (1, 'admin',  'Full administrative access',     true),
    (2, 'member', 'Standard signed-in user',        true),
    (3, 'guest',  'Anonymous / not signed in',      true)
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (role_id, token) VALUES
    (1, 'admin:users:read'),
    (1, 'admin:users:write'),
    (1, 'admin:users:delete'),
    (1, 'admin:roles:read'),
    (1, 'admin:roles:write')
ON CONFLICT (role_id, token) DO NOTHING;

INSERT INTO user_roles (user_id, role_id) VALUES (1, 3)
ON CONFLICT (user_id, role_id) DO NOTHING;

-- Same sequence-bump rationale as 0001_init.sql's users seed: roles ids 1..3
-- are explicit, so advance the BIGSERIAL sequence past them.
SELECT setval(pg_get_serial_sequence('roles', 'id'),
              GREATEST((SELECT COALESCE(MAX(id), 0) FROM roles), 1));

CREATE INDEX IF NOT EXISTS ix_users_deleted_at  ON users(deleted_at);
CREATE INDEX IF NOT EXISTS ix_user_roles_role_id ON user_roles(role_id);
