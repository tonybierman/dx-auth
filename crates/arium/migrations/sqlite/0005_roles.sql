-- Roles + role-derived permissions + per-user role assignments.
-- The library effectively replaces the old "insert each permission token
-- directly into user_permissions" pattern with role-based grants: every
-- new signed-in user gets the `member` role, and admins additionally hold
-- the `admin` role. `user_permissions` is preserved so apps can still
-- attach one-off tokens to a specific user when a role isn't a fit.

CREATE TABLE IF NOT EXISTS roles (
    id          INTEGER PRIMARY KEY,
    name        VARCHAR(64) NOT NULL UNIQUE,
    description TEXT,
    is_system   BOOLEAN NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    token   VARCHAR(256) NOT NULL,
    PRIMARY KEY (role_id, token)
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- Soft-delete marker for account self-deletion. Library-side checks reject
-- sign-in / load when this is non-null. PII columns get NULLed at delete time.
ALTER TABLE users ADD COLUMN deleted_at INTEGER;

-- Optional self-chosen display name (distinct from `name`, which is whatever
-- the OAuth provider returned).
ALTER TABLE users ADD COLUMN display_name TEXT;

-- Canonical roles.
INSERT INTO roles (id, name, description, is_system) VALUES
    (1, 'admin',  'Full administrative access',     true),
    (2, 'member', 'Standard signed-in user',        true),
    (3, 'guest',  'Anonymous / not signed in',      true)
ON CONFLICT (id) DO NOTHING;

-- Default permission grants per canonical role.
INSERT INTO role_permissions (role_id, token) VALUES
    (1, 'admin:users:read'),
    (1, 'admin:users:write'),
    (1, 'admin:users:delete'),
    (1, 'admin:roles:read'),
    (1, 'admin:roles:write')
ON CONFLICT (role_id, token) DO NOTHING;

-- Map the seeded Guest user (id 1) to the guest role so HasPermission lookups
-- against the anonymous fallback resolve cleanly.
INSERT INTO user_roles (user_id, role_id) VALUES (1, 3)
ON CONFLICT (user_id, role_id) DO NOTHING;

-- Helpful indexes for admin user listings.
CREATE INDEX IF NOT EXISTS ix_users_deleted_at ON users(deleted_at);
CREATE INDEX IF NOT EXISTS ix_user_roles_role_id ON user_roles(role_id);
