# Configuring arium-leptos

Two kinds of configuration: **Cargo features** (compiled in at build time) and
**environment variables** (read at runtime). Every feature degrades gracefully
when its config is absent — the GitHub button hides itself when OAuth isn't
configured, the mailer falls back to writing `.eml` files, and so on.

See also [INSTALL_LEPTOS.md](INSTALL_LEPTOS.md) and [USAGE_LEPTOS.md](USAGE_LEPTOS.md).

## Cargo features

Defaults give you "everything on, server build, SQLite backend, UI included":

```toml
default = ["ssr", "ui", "sqlite", "oauth-github", "mfa", "mail", "ratelimit", "tokens"]
```

| Feature | Default | Gates |
| --- | --- | --- |
| `ssr` | yes | Server build. Pulls in the engine + axum integration and Leptos's SSR runtime. |
| `hydrate` | no | Client/wasm build. Enabled on the `lib` build by `cargo-leptos`, not in `default`. |
| `ui` | yes | Catalog widgets + drop-in screens (`LoginPanel`, `MfaSetup`, …). Needs the router. |
| `sqlite` | yes | `sqlx::SqlitePool` backend. **Mutually exclusive with `postgres`.** |
| `postgres` | no | `sqlx::PgPool` backend. **Mutually exclusive with `sqlite`.** |
| `oauth-github` | yes | GitHub provider + the generic OAuth routes. |
| `oauth-oidc` | no | Generic OpenID Connect provider (`OidcProvider`) — discovery + PKCE + `id_token` validation via the `openidconnect` crate. Use for any OIDC issuer / enterprise SSO. |
| `oauth-google` | no | Google sign-in preset (`GoogleProvider`) over the OIDC engine. Implies `oauth-oidc`. |
| `oauth-microsoft` | no | Microsoft / Entra ID preset (`MicrosoftProvider`) over the OIDC engine. Implies `oauth-oidc`. |
| `mfa` | yes | TOTP enrollment + verification, recovery codes (+ `MfaChallenge` / `MfaSetup` UI). |
| `mail` | yes | `Mailer` (SMTP + dev `.eml` fallback) and the email-verification / password-reset endpoints + UI. Without `mail`, signup auto-marks accounts verified. |
| `ratelimit` | yes | Per-IP rate limiting via `tower_governor`. |
| `tokens` | yes | Personal API tokens (`ApiTokens` UI + `create/list/revoke` server fns). |

> **The capability flags and the backend must be present on _both_ builds**
> (`ssr` and `hydrate`). They only pull in engine code on the `ssr` build, but
> the `hydrate` build needs them visible so the gated server-fn declarations
> compile into client stubs. In a `cargo-leptos` project this means listing them
> in `[dependencies]` (not behind `ssr`); `bin-features` selects `ssr`,
> `lib-features` selects `hydrate`. See [INSTALL_LEPTOS.md](INSTALL_LEPTOS.md).

For PostgreSQL, swap `sqlite` for `postgres` (mutually exclusive).

## Environment variables

All are optional. Defaults below are what the engine uses when the variable is
unset.

> **Default ports assume `:8080`.** The OAuth-redirect and email-link defaults
> were written for the Dioxus dev server (port 8080). A `cargo-leptos` app
> serves on its `site-addr` (the example uses `127.0.0.1:3000`), so set
> `GITHUB_REDIRECT_URL` and `PUBLIC_BASE_URL` explicitly to match your port.

### GitHub OAuth (`oauth-github`)

`GithubProvider::from_env()` returns `Ok(None)` when the client ID or secret is
unset — the routes aren't registered and the "Continue with GitHub" button
hides itself.

| Var | Default | Notes |
| --- | --- | --- |
| `GITHUB_CLIENT_ID` | _(unset)_ | OAuth App Client ID from <https://github.com/settings/developers>. |
| `GITHUB_CLIENT_SECRET` | _(unset)_ | OAuth App Client Secret. |
| `GITHUB_REDIRECT_URL` | `http://localhost:8080/auth/github/callback` | Must exactly match the GitHub OAuth App's "Authorization callback URL". Set this to your `site-addr`, e.g. `http://127.0.0.1:3000/auth/github/callback`. |

> The redirect-URL defaults below also assume `:8080` — override each to match
> your `site-addr` (e.g. `http://127.0.0.1:3000/auth/<provider>/callback`).

### Google OAuth (`oauth-google`)

`GoogleProvider::from_env().await` returns `Ok(None)` when the client ID or
secret is unset. Credentials come from a Google Cloud OAuth 2.0 Client (type
"Web application").

| Var | Default | Notes |
| --- | --- | --- |
| `GOOGLE_CLIENT_ID` | _(unset)_ | OAuth client ID from <https://console.cloud.google.com/apis/credentials>. |
| `GOOGLE_CLIENT_SECRET` | _(unset)_ | OAuth client secret. |
| `GOOGLE_REDIRECT_URL` | `http://localhost:8080/auth/google/callback` | Must match an "Authorized redirect URI" on the OAuth client. |

### Microsoft / Entra OAuth (`oauth-microsoft`)

`MicrosoftProvider::from_env().await` returns `Ok(None)` when the client ID or
secret is unset. Register an app at the Microsoft Entra admin center.

| Var | Default | Notes |
| --- | --- | --- |
| `MICROSOFT_CLIENT_ID` | _(unset)_ | Application (client) ID. |
| `MICROSOFT_CLIENT_SECRET` | _(unset)_ | Client secret value. |
| `MICROSOFT_REDIRECT_URL` | `http://localhost:8080/auth/microsoft/callback` | Must match a redirect URI registered on the app. |
| `MICROSOFT_TENANT` | `common` | Tenant: `common`, `organizations`, `consumers`, or a specific tenant id. |

### Generic OIDC (`oauth-oidc`)

For any other OpenID Connect issuer (GitLab, Okta, Auth0, Keycloak, …),
`OidcProvider::from_env().await` builds a provider by discovery against
`OIDC_ISSUER_URL`. Returns `Ok(None)` unless the client ID, secret, **and**
issuer are all set.

| Var | Default | Notes |
| --- | --- | --- |
| `OIDC_CLIENT_ID` | _(unset)_ | OAuth client ID. |
| `OIDC_CLIENT_SECRET` | _(unset)_ | OAuth client secret. |
| `OIDC_ISSUER_URL` | _(unset, required)_ | Issuer base URL; discovery fetches `<issuer>/.well-known/openid-configuration`. |
| `OIDC_REDIRECT_URL` | `http://localhost:8080/auth/oidc/callback` | Must match a redirect URI registered with the provider. |
| `OIDC_SCOPES` | `openid email profile` | Space-separated; `openid` is added automatically if omitted. |
| `OIDC_NAME` | `oidc` | Machine name → route segment (`/auth/<name>/...`) + `oauth_accounts.provider`. |
| `OIDC_DISPLAY_NAME` | `SSO` | Label on the sign-in button. |

> OIDC presets run discovery (a network call) when constructed, so
> `from_env()` is **async** — `await` it, and an unreachable issuer fails app
> startup.

### Email (`mail`)

When `SMTP_HOST` is set, [lettre](https://github.com/lettre/lettre) opens a
STARTTLS submission connection. When unset, the dev fallback writes RFC-822
`.eml` files into `./emails/<timestamp>.eml`.

| Var | Default | Notes |
| --- | --- | --- |
| `SMTP_HOST` | _(unset → file backend)_ | e.g. `smtp.sendgrid.net`, or `localhost` against [Mailpit](https://mailpit.axllent.org/). |
| `SMTP_PORT` | `587` | |
| `SMTP_USER` | _(unset → no auth)_ | |
| `SMTP_PASSWORD` | _(unset)_ | |
| `FROM_EMAIL` | `noreply@localhost` | `From:` header. |
| `PUBLIC_BASE_URL` | `http://localhost:8080` | Builds the absolute links in email bodies. Set this to your `site-addr`, e.g. `http://127.0.0.1:3000`. |

### Bootstrap / dev

| Var | Default | Notes |
| --- | --- | --- |
| `DX_AUTH_BOOTSTRAP_ADMIN_EMAIL` | _(unset)_ | If set, the matching signup is auto-granted the `admin` role (re-granted on every startup if the row exists). `BOOTSTRAP_ADMIN_EMAIL` is accepted as an alias. Independently, if no admin exists when a new user signs up, that signup is promoted — so a fresh install always has one admin. |
| `DX_AUTH_SKIP_EMAIL_VERIFICATION` | _(unset)_ | Accepts `1` / `true` / `yes` / `on`. When truthy, `register_with_password` marks accounts verified immediately and returns `LoginOutcome::LoggedIn`. |

### Dev server address

`cargo-leptos` reads the listen address from `[package.metadata.leptos]` in
`Cargo.toml`, not from environment variables:

```toml
[package.metadata.leptos]
site-addr = "127.0.0.1:3000"
reload-port = 3001
```

## Audit log

Sign-ins, sign-outs, admin actions, and account self-service writes all land in
the `audit_events` table. Tune capture and retention on the builder:

```rust
use arium_leptos::{AuditConfig, AuthConfig};

let cfg = AuthConfig::builder(pool.clone(), mailer)
    .audit(AuditConfig {
        capture_ip: true,
        capture_user_agent: true,
        retention_days: 90,   // a background task prunes older rows; 0 disables pruning
    })
    .build()?;
```

Defaults: IP + user-agent captured, 90-day retention. Drop the `AuditLog`
component onto an `/admin/audit` route for the viewer.
