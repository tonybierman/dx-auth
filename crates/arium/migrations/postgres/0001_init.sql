-- Postgres-flavored equivalent of the sqlite init migration.

CREATE TABLE IF NOT EXISTS users (
    id              BIGINT PRIMARY KEY,
    anonymous       BOOLEAN NOT NULL,
    username        VARCHAR(256) NOT NULL,
    name            TEXT,
    email           TEXT,
    avatar_url      TEXT,
    html_url        TEXT,
    password_hash   TEXT
);

CREATE TABLE IF NOT EXISTS user_permissions (
    user_id BIGINT NOT NULL,
    token   VARCHAR(256) NOT NULL,
    PRIMARY KEY (user_id, token)
);

CREATE TABLE IF NOT EXISTS oauth_accounts (
    provider          TEXT   NOT NULL,
    provider_user_id  TEXT   NOT NULL,
    user_id           BIGINT NOT NULL,
    PRIMARY KEY (provider, provider_user_id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email_password
    ON users(email) WHERE password_hash IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email_lower
    ON users(LOWER(email)) WHERE email IS NOT NULL;

-- Anonymous Guest user that AuthConfig.with_anonymous_user_id(Some(1)) expects.
INSERT INTO users (id, anonymous, username) VALUES (1, true, 'Guest')
    ON CONFLICT (id) DO NOTHING;
