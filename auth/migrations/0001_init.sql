-- Final-shape schema; previously this was created inline in main.rs.
-- Future schema changes get their own migration file (0002_*, 0003_*, ...).

CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY,
    anonymous       BOOLEAN NOT NULL,
    username        VARCHAR(256) NOT NULL,
    name            TEXT,
    email           TEXT,
    avatar_url      TEXT,
    html_url        TEXT,
    password_hash   TEXT
);

CREATE TABLE IF NOT EXISTS user_permissions (
    user_id INTEGER NOT NULL,
    token   VARCHAR(256) NOT NULL,
    PRIMARY KEY (user_id, token)
);

CREATE TABLE IF NOT EXISTS oauth_accounts (
    provider          TEXT    NOT NULL,
    provider_user_id  TEXT    NOT NULL,
    user_id           INTEGER NOT NULL,
    PRIMARY KEY (provider, provider_user_id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Email is unique only among password-using accounts; OAuth-only users may share
-- (or lack) an email without colliding.
CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email_password
    ON users(email) WHERE password_hash IS NOT NULL;

-- Case-insensitive email lookup index for sign-in and GitHub account linking.
CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email_lower
    ON users(LOWER(email)) WHERE email IS NOT NULL;

-- Seed the anonymous Guest user that AuthConfig.with_anonymous_user_id(Some(1))
-- expects to exist.
INSERT OR IGNORE INTO users (id, anonymous, username) VALUES (1, true, 'Guest');
