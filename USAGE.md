## Getting started

In your app's `Cargo.toml`:

```toml
[dependencies]
dx-auth = { git = "https://github.com/<you>/dx-auth", default-features = false, features = ["server", "ui", "sqlite"] }
dioxus  = { version = "0.7.9", features = ["fullstack", "router"] }
sqlx    = { version = "0.8", features = ["runtime-tokio", "sqlite", "macros", "migrate"] }
```

Copy `crates/dx-auth/migrations/sqlite/*.sql` into your `migrations/`
directory (rename-prefix if you collide with your own files) — then in
your fullstack entry point:

```rust
use dx_auth::{AuthConfig, Mailer, auth::OAuthClients, server::*};

#[cfg(feature = "server")]
dioxus::serve(|| async {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .connect_with("sqlite://./app.db?mode=rwc".parse()?)
        .await?;
    sqlx::migrate!().run(&pool).await?;     // your migrations + the ones you copied

    let cfg = AuthConfig::builder(pool.clone(), Mailer::from_env()?)
        .github(OAuthClients::from_env(pool.clone())?)
        .build();

    dx_auth::install(dioxus::server::router(app), cfg).await
});
```

Then somewhere in your client-side UI:

```rust
use dx_auth::ui::{LoginPanel, LoginProvider};

LoginPanel {
    providers: vec![LoginProvider {
        name: "GitHub",
        href: "/auth/github/login",
        icon_svg: Some(GITHUB_ICON_SVG),
    }],
    title: "Welcome back",
    description: "Sign in to your workspace.",
    forgot_href: "/auth/forgot",
    on_submit: handler,
}
```

`examples/basic/` shows the complete shape, including the ProfileCard,
ForgotPassword / ResetPassword / VerifyEmail pages, and the MFA setup
flow.

## Features

`dx-auth` exposes the following Cargo features. The defaults give you
"everything on, SQLite backend, UI components included":

```toml
default = ["server", "ui", "sqlite", "oauth-github", "mfa", "mail", "ratelimit"]
```

| Feature        | What it gates                                                                 |
| -------------- | ----------------------------------------------------------------------------- |
| `server`       | Core server-side runtime (sqlx, axum, axum_session, argon2). Required for all server functionality. |
| `ui`           | The catalog UI components (`LoginPanel`, `Button`, `Card`, `Input`, etc.).    |
| `sqlite`       | Use `sqlx::SqlitePool` as the storage backend. **Mutually exclusive with `postgres`.** |
| `postgres`     | Use `sqlx::PgPool` as the storage backend. **Mutually exclusive with `sqlite`.**       |
| `oauth-github` | GitHub OAuth client + `/auth/github/login` + `/auth/github/callback`.         |
| `mfa`          | TOTP enrollment + verification, recovery codes, MFA challenge step in sign-in. |
| `mail`         | The `Mailer` (SMTP + dev `.eml` fallback) and the email-verification / password-reset endpoints. Without `mail`, sign-up auto-marks accounts verified. |
| `ratelimit`    | Per-IP rate limiter via `tower_governor`.                                     |

Examples:

```toml
# Postgres + everything
dx-auth = { version = "0.1", default-features = false, features = ["server", "ui", "postgres"] }

# OAuth-only (no password / email features), SQLite
dx-auth = { version = "0.1", default-features = false, features = ["server", "ui", "sqlite", "oauth-github", "ratelimit"] }

# Headless (no UI; you bring your own component library)
dx-auth = { version = "0.1", default-features = false, features = ["server", "sqlite", "oauth-github", "mfa", "mail", "ratelimit"] }
```

## Environment variables

All env vars are optional — features gracefully degrade when their config
isn't present.

### GitHub OAuth (`oauth-github` feature)

| Var                    | Default                                       | Notes |
| ---------------------- | --------------------------------------------- | --- |
| `GITHUB_CLIENT_ID`     | _(unset)_                                     | OAuth App Client ID from <https://github.com/settings/developers>. |
| `GITHUB_CLIENT_SECRET` | _(unset)_                                     | OAuth App Client Secret. |
| `GITHUB_REDIRECT_URL`  | `http://localhost:8080/auth/github/callback`  | Must exactly match the GitHub OAuth App's "Authorization callback URL". |

`OAuthClients::from_env(pool)` returns `Ok(None)` when either required
var is missing/empty, in which case the GitHub routes aren't
registered and `available_providers` returns an empty list.

### Email (`mail` feature)

When `SMTP_HOST` is set, lettre opens a STARTTLS submission connection.
When it's unset, the dev fallback writes RFC-822 `.eml` files into
`./emails/<timestamp>.eml` so password-reset and verification flows are
testable without a provider.

| Var               | Default                  | Notes |
| ----------------- | ------------------------ | --- |
| `SMTP_HOST`       | _(unset → file backend)_ | e.g. `smtp.sendgrid.net` or `localhost` against a local [Mailpit](https://mailpit.axllent.org/). |
| `SMTP_PORT`       | `587`                    |   |
| `SMTP_USER`       | _(unset → no auth)_      |   |
| `SMTP_PASSWORD`   | _(unset)_                |   |
| `FROM_EMAIL`      | `noreply@localhost`      | `From:` header. |
| `PUBLIC_BASE_URL` | `http://localhost:8080`  | Used to build absolute links inside email bodies. |

### Dev server

| Var    | Default     | Notes |
| ------ | ----------- | --- |
| `IP`   | `127.0.0.1` | Wired by `dx serve`. |
| `PORT` | `8080`      | Wired by `dx serve`. |

## Audit log

Every sign-in, sign-out, admin action, and account self-service write
goes through the audit emitter and lands in the `audit_events` table.
The admin UI [`dx_auth::ui::admin::AuditLog`] renders a filterable,
paginated table on top of it — drop it onto an `/admin/audit` route in
your app (the example does this).

### Configuration

Capture / retention is set via `AuthConfig::audit(AuditConfig { … })`:

```rust
use dx_auth::{AuditConfig, AuthConfig};

let cfg = AuthConfig::builder(pool.clone(), mailer)
    .audit(AuditConfig {
        capture_ip: true,           // store the requester's IP
        capture_user_agent: true,   // store the requester's UA
        retention_days: 90,         // background task prunes older rows
    })
    .build();
```

Defaults: IP + UA both captured, 90-day retention. Set `retention_days
= 0` to disable pruning entirely (the library writes; you handle
cleanup).

### Emitted events

| Event type                        | When |
| --------------------------------- | --- |
| `user.login.success`              | Password (with or without MFA) or OAuth sign-in completes. `details` carries `method` + `remember_me`. |
| `user.login.failed`               | Bad password, unverified email, or wrong MFA code. `details.reason` is `"invalid"`, `"unverified"`, or `"invalid_code"`. |
| `user.logout`                     | `/api/user/logout` called. |
| `user.signup`                     | Password account created. |
| `user.email_verified`             | Verification token consumed. |
| `user.password_reset.requested`   | Reset email sent (only fires when the address actually matches a user). |
| `user.password_reset.consumed`    | Reset link followed and a new password set. |
| `user.mfa.enabled`                | TOTP enrollment confirmed. |
| `user.mfa.disabled`               | TOTP turned off. |
| `account.display_name_changed`    | Self-service display name edit. |
| `account.password_changed`        | Self-service password rotation. |
| `account.self_deleted`            | User soft-deletes their own account. |
| `admin.user.roles_changed`        | Admin replaces a user's role assignments. `details` carries `before` / `after` role-id arrays. |
| `admin.user.soft_deleted`         | Admin soft-deletes a user. |

Apps can emit their own events too — call
`dx_auth::auth::audit::record(&pool, RecordInput { … }).await` with any
`event_type` string and an optional JSON `details` blob.

## What the library ships vs what your app owns

**Library owns:**

- `users` table + `user_permissions`, `oauth_accounts`,
  `password_reset_tokens`, `email_verification_tokens`,
  `mfa_recovery_codes`, `mfa_secret` / `mfa_enabled_at` columns.
- Sign-in / sign-up / OAuth / verification / reset / MFA server fns.
- `LoginPanel` UI component (drop in; takes a provider list + submit
  callback).

**Your app owns:**

- Page layout, theme, copy.
- Domain extensions to the user record (store side-data in your own
  table keyed by `users.id`).
- Permission tokens and what they mean.
- Profile page / MFA-setup page UI (the example has these — copy them
  as starting points).

## Repo layout

```
.
├── Cargo.toml                       (workspace root)
├── crates/dx-auth/
│   ├── Cargo.toml
│   ├── migrations/
│   │   ├── sqlite/                  (copy into your app's migrations/)
│   │   └── postgres/
│   └── src/
│       ├── lib.rs                   public surface
│       ├── auth.rs                  User + password / OAuth / MFA helpers
│       ├── mail.rs                  Mailer + templates
│       ├── server.rs                server fns + axum OAuth handlers
│       ├── pool.rs                  cfg-gated Pool / SessionPool aliases
│       ├── config.rs                AuthConfig + builder
│       ├── install.rs               dx_auth::install(router, cfg)
│       ├── wire.rs                  LoginOutcome, UserProfile, etc.
│       └── ui/
│           ├── login_panel/         the reusable login card
│           └── components/          catalog widgets (button, card, etc.)
└── examples/basic/                  end-to-end fullstack consumer
```

## Dev tips

- `cargo check --workspace` builds both crates.
- `cargo check -p dx-auth --no-default-features --features server,sqlite`
  builds the minimal library (no MFA, no OAuth, no mail, no rate limit).
- Example app: `cd examples/basic && dx serve`. See
  [examples/basic/README.md](examples/basic/README.md) for the env-var
  walkthrough specific to running the demo locally.
- `sqlite3 examples/basic/auth.db '.schema'` to inspect the live schema.
- Migrations are checksummed by sqlx; if you edit a `.sql` file after
  it's been applied, sqlx refuses to start until you wipe the DB or add
  a new migration file with the fix-up.
