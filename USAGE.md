# Using arium-dioxus

A walkthrough of integrating `arium-dioxus` into a Dioxus 0.7 fullstack app.
The companion to this document is `examples/basic/` — every pattern here
is exercised there end-to-end.

## Getting started

### 1. Cargo.toml

```toml
[dependencies]
dioxus = { version = "0.7.9", features = ["fullstack", "router"] }

# Capability features (ui, mail, oauth-github, mfa, ratelimit) need to
# be on for BOTH the wasm/client and server builds so the
# `#[cfg(feature = "...")]`-gated server-fn declarations are visible to
# the dioxus macro on both sides. The actual server-only crates inside
# arium-dioxus are already target-gated to non-wasm.
#
# IMPORTANT: `sqlite` (or `postgres`) is server-only — keep it OUT of
# the default feature list and gate it behind your own `server`
# feature. See "Common pitfalls" below.
arium-dioxus = { version = "0.1", default-features = false, features = [
  "ui",
  "mail",
  "oauth-github",
  "mfa",
  "ratelimit",
] }

# Direct deps the host needs
axum  = { version = "0.8", optional = true }
tokio = { version = "1",   features = ["full"], optional = true }
sqlx  = { version = "0.8", features = ["runtime-tokio", "sqlite", "macros", "migrate"], optional = true }

[features]
default = ["web"]
web     = ["dioxus/web"]
server  = [
  "dioxus/server",
  "dep:axum", "dep:tokio", "dep:sqlx",
  "arium-dioxus/server",
  "arium-dioxus/sqlite",    # <-- gated behind YOUR server feature
]
```

### 2. Server setup

`arium_dioxus::migrator()` ships the schema (`users`, `oauth_accounts`,
`roles`, `audit_events`, `api_keys`, …); compose it with your own
migrator if you have one. `arium_dioxus::install` layers session + auth onto
whatever `axum::Router` you hand it — merge any custom routes (SSE,
websockets, REST) into the router *before* calling `install` so they
inherit the session middleware.

```rust
fn main() {
    #[cfg(not(feature = "server"))]
    dioxus::launch(app);

    #[cfg(feature = "server")]
    dioxus::serve(|| async {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .connect_with("sqlite://./app.db?mode=rwc".parse()?)
            .await?;
        arium_dioxus::migrator().run(&pool).await?;
        // your own migrator runs here if you have one

        let mailer = arium_dioxus::Mailer::from_env()?;
        let mut builder = arium_dioxus::AuthConfig::builder(pool, mailer);
        if let Some(gh) = arium_dioxus::oauth::github::GithubProvider::from_env()? {
            builder = builder.oauth_provider(gh);
        }

        let router = dioxus::server::router(app)
            // .merge(my_sse_router)
            // .layer(axum::Extension(my_app_state))
            ;

        arium_dioxus::install(router, builder.build()).await
    });
}
```

### 3. Client wiring

Wrap the router in `PermissionsProvider` (always, even if you don't
gate anything — it also pins the catalog widget stylesheets so the
auth screens stay styled across mount cycles). Wrap that in
`OAuthProvidersProvider` so the provider list is fetched once at the
app root and survives login/logout transitions.

```rust
use arium_dioxus::ui::{OAuthProvidersProvider, PermissionsProvider};

#[component]
fn app() -> Element {
    rsx! {
        PermissionsProvider {
            OAuthProvidersProvider {
                Router::<Route> {}
            }
        }
    }
}
```

### 4. Smoke test

```bash
rm app.db && dx serve
```

Sign up with email + password. Without `SMTP_HOST` set, the
verification email is written to `./emails/<timestamp>.eml`; open it in
any mail client (or `cat`) to grab the link. For dev, you can skip the
round-trip entirely with `DX_AUTH_SKIP_EMAIL_VERIFICATION=1 dx serve`.

## Drop-in auth routes

`arium-dioxus` ships ready-made screen components for every email- or
session-driven flow. Wire them into your `Route` enum:

```rust
use arium_dioxus::ui::{
    ApiTokens, ForgotPassword, LoginPanel, MfaChallenge, MfaSetup, ResetPassword, VerifyEmail,
};

#[derive(Routable, Clone, PartialEq)]
pub enum Route {
    #[route("/")]                  Home,
    #[route("/auth/forgot")]       ForgotPassword,
    #[route("/auth/reset?:token")] ResetPassword { token: String },
    #[route("/auth/verify?:token")] VerifyEmail { token: String },
    #[route("/account/mfa")]       MfaSetup,
    #[route("/account/tokens")]    ApiTokens,
    // ... your domain routes
}
```

The default paths match `LoginPanel`'s baked-in `forgot_href` and the
URLs the `mail` backend writes into outgoing emails. If you mount them
somewhere else, override `LoginPanel { forgot_href: "..." }` and the
mailer's link templates to match.

Each screen calls its corresponding server fn under the hood:

| Component | Server fn | Notes |
| --- | --- | --- |
| `LoginPanel` | `login_with_password` / `register_with_password` | The login card. Anonymous-accessible. |
| `ForgotPassword` | `request_password_reset_email` | User-enumeration-safe; always shows the neutral "if an account exists…" message. |
| `ResetPassword { token }` | `reset_password` | Confirms passwords match client-side. |
| `VerifyEmail { token }` | `verify_email` | Fires on mount; renders pending / verified / expired states. |
| `MfaChallenge` | `verify_login_mfa` | Post-password 6-digit prompt with recovery-code toggle. |
| `MfaSetup` | `begin/confirm/disable_mfa_setup`, `get_mfa_status` | Enrollment + management screen for `/account/mfa`. |
| `ApiTokens` | `create_api_token`, `list_api_tokens`, `revoke_api_token` | Personal-token management. Cleartext shown once at creation; only prefix + SHA-256 hash are persisted. See "API tokens" below for the validation contract. |

All components accept overridable `title` / `description` / `back_href`
props for copy customization.

### Login handler

`login_with_password` returns one of three `LoginOutcome` variants — a
login screen has to dispatch on all three:

```rust
use arium_dioxus::ui::{LoginPanel, LoginSubmit, MfaChallenge, SubmitKind, use_oauth_providers, use_permissions};
use arium_dioxus::{LoginOutcome, friendly_server_error};
use arium_dioxus::server::{cancel_mfa_challenge, login_with_password, register_with_password};

#[component]
fn Home() -> Element {
    let perms = use_permissions();
    let providers = use_oauth_providers();
    let mut auth_error = use_signal(String::new);
    let mut pending_email = use_signal::<Option<String>>(|| None);
    let mut pending_mfa = use_signal(|| false);

    let on_submit = move |s: LoginSubmit| {
        let email_for_pending = s.email.clone();
        spawn(async move {
            let result = match s.kind {
                SubmitKind::SignIn => login_with_password(s.email, s.password, s.remember).await,
                SubmitKind::SignUp => register_with_password(s.email, s.password).await,
            };
            match result {
                Ok(LoginOutcome::LoggedIn)       => perms.refresh(),
                Ok(LoginOutcome::EmailUnverified) => pending_email.set(Some(email_for_pending)),
                Ok(LoginOutcome::MfaRequired)    => pending_mfa.set(true),
                Err(e) => auth_error.set(friendly_server_error(e)),
            }
        });
    };

    if perms.is_authenticated() {
        rsx! { /* your authenticated UI */ }
    } else if pending_mfa() {
        rsx! {
            MfaChallenge {
                on_logged_in: move |_| { pending_mfa.set(false); perms.refresh(); },
                on_cancel: move |_| {
                    pending_mfa.set(false);
                    spawn(async move { let _ = cancel_mfa_challenge().await; });
                },
            }
        }
    } else {
        rsx! { LoginPanel { providers: providers.clone(), on_submit, /* … */ } }
    }
}
```

The full version is in `examples/basic/src/main.rs`.

## OAuth providers

GitHub ships in the box (feature `oauth-github`). `GithubProvider::from_env()`
returns `Ok(None)` when `GITHUB_CLIENT_ID` or `GITHUB_CLIENT_SECRET` is
unset — the routes simply aren't registered and `available_providers`
returns an empty list, so the "Continue with GitHub" button hides
itself.

### Adding a new provider

Implement `arium_dioxus::oauth::OAuthProvider` (id/secret/URLs, scopes, and
a `fetch_profile` that hits the user-info endpoint and returns a
`NormalizedProfile`). Add a `oauth-<name>` Cargo feature that enables
the internal `_oauth-core` feature, drop a module under
`crates/arium/src/oauth/<name>.rs` mirroring `github.rs`, then
register it on the builder:

```rust
let builder = builder.oauth_provider(GoogleProvider::from_env()?.unwrap());
```

`install` mounts `/auth/<name>/login` + `/auth/<name>/callback` for
every registered provider automatically.

## API tokens

The `tokens` feature (default on) ships an `api_keys` table, the
`ApiTokens` drop-in, and three server fns (`create_api_token`,
`list_api_tokens`, `revoke_api_token`) so users can self-manage
personal tokens for CLI tools, MCP servers, and other programmatic
clients that can't carry a session cookie.

### What's persisted

- `name` — user-supplied label
- `prefix` — first 9 chars of the cleartext (`dxsk_abcd`), shown in the
  list UI for visual disambiguation
- `token_hash` — SHA-256 hex of the cleartext (64 chars)
- `created_at`, `last_used_at`, `revoked_at`

The cleartext secret is returned **once** in the response from
`create_api_token` and never recoverable from the server. Lost tokens
have to be revoked and replaced.

### Validating an incoming token

The library doesn't ship a Bearer-token axum extractor — consumers do
the lookup themselves, which keeps the auth path explicit. Hash the
incoming bearer string with [`arium_dioxus::auth::tokens::hash_api_token`]
and look it up:

```rust
use axum::{extract::Request, http::StatusCode, middleware::Next, response::Response};
use arium_dioxus::auth::tokens::hash_api_token;

pub async fn require_api_token(
    db: axum::Extension<sqlx::SqlitePool>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let hash = hash_api_token(header);

    let row: Option<(i64,)> = sqlx::query_as(
        "SELECT user_id FROM api_keys \
         WHERE token_hash = $1 AND revoked_at IS NULL",
    )
    .bind(&hash)
    .fetch_optional(&db.0)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let Some((user_id,)) = row else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    // Best-effort `last_used_at` bump — failures here don't fail the request.
    let _ = sqlx::query("UPDATE api_keys SET last_used_at = strftime('%s','now') WHERE token_hash = $1")
        .bind(&hash)
        .execute(&db.0)
        .await;

    req.extensions_mut().insert(user_id);
    Ok(next.run(req).await)
}
```

Bumping `last_used_at` is the consumer's responsibility — the library
only writes it via the consumer-supplied middleware above (or whatever
equivalent path you use). `arium_dioxus::ui::ApiTokens` reads it back so
users can spot stale tokens.

## Writing server fns that read the current user

`arium_dioxus::auth::Session` is an `axum_session_auth::AuthSession`
extractor. Use it as the auth attribute on your own server fns, then
read `auth.current_user`:

```rust
#[post("/api/cards/new", auth: arium_dioxus::auth::Session)]
pub async fn create_card(board_id: i64, /* … */) -> Result<Card, ServerFnError> {
    #[cfg(feature = "server")]
    {
        let user = auth.current_user.as_ref()
            .filter(|u| !u.anonymous)            // arium-dioxus has a Guest user (id=1)
            .ok_or_else(|| ServerFnError::new("not logged in"))?;
        let user_id = user.id as i64;            // see pitfall below
        // ... domain authz + DB work ...
    }
}
```

Plain axum handlers (SSE, REST) take the same type as a handler
parameter:

```rust
pub async fn events_handler(
    Path(board_id): Path<i64>,
    State(state): State<AppState>,
    auth: arium_dioxus::auth::Session,
) -> Result<Sse<...>, StatusCode> { /* … */ }
```

## Permissions & RBAC

`arium-dioxus` resolves the current user's permission tokens (direct grants
plus role-inherited ones) and ships them to the client on the
`UserProfile`. `PermissionsProvider` (set up in step 3 above) caches the
result for the lifetime of the tree; everything below reads from that.

### Route-level guards

`RequireAuth` for "must be signed in" — pick the shape that fits the
surrounding UX:

```rust
// Redirect on deny
RequireAuth { redirect_to: "/login".to_string(), DashboardBody {} }

// Inline fallback (avoids redirect flash; more robust under hydration)
RequireAuth { fallback: rsx! { Login {} }, DashboardBody {} }
```

`RequirePermission` for role-aware checks. While the profile is still
loading it renders nothing (no content flash); on failure it calls
`Navigator::replace(redirect_to)` so the denied page can't be
back-buttoned into:

```rust
RequirePermission {
    token: "admin:users:read".to_string(),
    redirect_to: "/".to_string(),
    AdminUsersBody {}
}
```

`RequirePermission` with no `token`/`any_of`/`all_of` builds an empty
policy that **fails closed** — reach for `RequireAuth` when you just
need "user must be signed in."

### Element-level pruning

`PermissionGate` renders its children only when the check passes.
Provide exactly one of `token`, `any_of`, `all_of`, or `policy`:

```rust
PermissionGate {
    token: "admin:users:read".to_string(),
    AdminUsersLink {}
}

PermissionGate {
    any_of: vec!["admin:users:read".into(), "admin:audit:read".into()],
    AdminTabs {}
}

PermissionGate {
    token: "admin:users:write".to_string(),
    fallback: rsx! { p { "Read-only." } },
    EditableUserRow {}
}
```

### Imperative checks

`use_permissions()` returns a `Copy` handle for event handlers and
imperative branches:

```rust
let perms = use_permissions();
if perms.has("admin:users:read") { /* … */ }
if perms.any_of(["a", "b"])      { /* … */ }
if perms.all_of(["a", "b"])      { /* … */ }
perms.is_authenticated();
perms.is_loading();
perms.profile();                 // Option<UserProfile>
perms.refresh();                 // re-fetch after a grant change
```

### Reusable policies

When the same check appears in more than one place — typically a nav
entry *and* a route guard — define it as a `Policy` so the call sites
can't drift apart:

```rust
fn admin_policy() -> Policy {
    Policy::any_of(["admin:users:read", "admin:audit:read"])
}

PermissionGate     { policy: admin_policy(), AdminTabTrigger {} }
RequirePermission  { policy: admin_policy(), redirect_to: "/", AdminBody {} }
if perms.check(&admin_policy()) { /* … */ }
```

Tier-building shape with `.with(...)` and `.scoped(...)`:

```rust
fn project_viewer() -> Policy { Policy::token("read") }
fn project_editor() -> Policy { project_viewer().with("write") }
fn project_owner()  -> Policy { project_editor().with("admin") }

PermissionGate {
    policy: project_editor().scoped(format!("project:{project_id}")),
    EditToolbar {}
}
```

`Policy` is deliberately not a full boolean DSL — there's no `or` /
`and` / `not` between policies. If a `policy` is set on a gate, the
inline `token` / `any_of` / `all_of` / `scope` props are ignored.

### Scoped tokens (inline form)

For one-off checks that vary by resource, pass `scope` inline; the
gate composes the final lookup as `"{scope}:{token}"`:

```rust
PermissionGate {
    token: "write".to_string(),
    scope: format!("project:{project_id}"),
    EditToolbar {}
}
// checks the token "project:{id}:write"
```

The library treats `scope` as an opaque prefix — what it means is up
to your app. Grant the matching tokens server-side via
`user_permissions` (or your own scoped-grant table).

## Cargo features

The defaults give you "everything on, SQLite backend, UI included":

```toml
default = ["server", "ui", "sqlite", "oauth-github", "mfa", "mail", "ratelimit"]
```

| Feature        | Gates |
| -------------- | ----- |
| `server`       | Core server runtime (sqlx, axum, axum_session, argon2). Required for any backend functionality. |
| `ui`           | Catalog widgets + drop-in screens (`LoginPanel`, `MfaSetup`, etc.). |
| `sqlite`       | `sqlx::SqlitePool` backend. **Mutually exclusive with `postgres`.** |
| `postgres`     | `sqlx::PgPool` backend. **Mutually exclusive with `sqlite`.** |
| `oauth-github` | GitHub provider impl. Implies internal `_oauth-core` (oauth2 + reqwest + the generic provider routes shared by every provider). |
| `mfa`          | TOTP enrollment + verification, recovery codes, MFA challenge step. Includes `MfaChallenge` / `MfaSetup` UI. |
| `mail`         | `Mailer` (SMTP + dev `.eml` fallback) and email-verification / password-reset endpoints + UI. Without `mail`, signup auto-marks accounts verified. |
| `ratelimit`    | Per-IP rate limiter via `tower_governor`. |
| `tokens`       | Personal API tokens (`ApiTokens` UI + `create/list/revoke` server fns + `hash_api_token` helper). Pulls in `sha2`. |

Examples:

```toml
# Postgres + everything
arium-dioxus = { version = "0.1", default-features = false, features = ["server", "ui", "postgres"] }

# OAuth-only (no password / email flows), SQLite
arium-dioxus = { version = "0.1", default-features = false, features = ["server", "ui", "sqlite", "oauth-github", "ratelimit"] }

# Headless (bring your own component library)
arium-dioxus = { version = "0.1", default-features = false, features = ["server", "sqlite", "oauth-github", "mfa", "mail", "ratelimit"] }
```

## Environment variables

All env vars are optional — features gracefully degrade when their
config isn't present.

### GitHub OAuth (`oauth-github` feature)

| Var | Default | Notes |
| --- | --- | --- |
| `GITHUB_CLIENT_ID` | _(unset)_ | OAuth App Client ID from <https://github.com/settings/developers>. |
| `GITHUB_CLIENT_SECRET` | _(unset)_ | OAuth App Client Secret. |
| `GITHUB_REDIRECT_URL` | `http://localhost:8080/auth/github/callback` | Must exactly match the GitHub OAuth App's "Authorization callback URL". |

### Email (`mail` feature)

When `SMTP_HOST` is set, lettre opens a STARTTLS submission connection.
When unset, the dev fallback writes RFC-822 `.eml` files into
`./emails/<timestamp>.eml`.

| Var | Default | Notes |
| --- | --- | --- |
| `SMTP_HOST` | _(unset → file backend)_ | e.g. `smtp.sendgrid.net`, or `localhost` against [Mailpit](https://mailpit.axllent.org/). |
| `SMTP_PORT` | `587` | |
| `SMTP_USER` | _(unset → no auth)_ | |
| `SMTP_PASSWORD` | _(unset)_ | |
| `FROM_EMAIL` | `noreply@localhost` | `From:` header. |
| `PUBLIC_BASE_URL` | `http://localhost:8080` | Used to build absolute links in email bodies. |

### Bootstrap / dev

| Var | Default | Notes |
| --- | --- | --- |
| `DX_AUTH_BOOTSTRAP_ADMIN_EMAIL` | _(unset)_ | If set, the matching signup is auto-granted the `admin` role (and re-granted on every startup if the row exists). `BOOTSTRAP_ADMIN_EMAIL` is accepted as an alias. Independently, if no admin exists when a new user signs up, that signup is promoted (Sentry/GitLab convention) so a fresh install always has one admin. |
| `DX_AUTH_SKIP_EMAIL_VERIFICATION` | _(unset)_ | Accepts `1` / `true` / `yes` / `on`. When truthy, `register_with_password` marks accounts verified immediately and returns `LoginOutcome::LoggedIn`. |

### Dev server

| Var | Default | Notes |
| --- | --- | --- |
| `IP` | `127.0.0.1` | Wired by `dx serve`. |
| `PORT` | `8080` | Wired by `dx serve`. |

## Audit log

Every sign-in, sign-out, admin action, and account self-service write
goes through the audit emitter and lands in the `audit_events` table.
The `arium_dioxus::ui::admin::AuditLog` component renders a filterable,
paginated table — drop it onto an `/admin/audit` route.

```rust
use arium_dioxus::{AuditConfig, AuthConfig};

let cfg = AuthConfig::builder(pool.clone(), mailer)
    .audit(AuditConfig {
        capture_ip: true,
        capture_user_agent: true,
        retention_days: 90,         // background task prunes older rows
    })
    .build();
```

Defaults: IP + UA both captured, 90-day retention. Set
`retention_days = 0` to disable pruning (the library writes; you
handle cleanup).

### Emitted events

| Event type | When |
| --- | --- |
| `user.login.success` | Password (with or without MFA) or OAuth sign-in completes. `details` carries `method` + `remember_me`. |
| `user.login.failed` | Bad password, unverified email, or wrong MFA code. `details.reason` is `"invalid"`, `"unverified"`, or `"invalid_code"`. |
| `user.logout` | `/api/user/logout` called. |
| `user.signup` | Password account created. |
| `user.email_verified` | Verification token consumed. |
| `user.password_reset.requested` | Reset email sent (only when the address matches a user). |
| `user.password_reset.consumed` | Reset link followed and a new password set. |
| `user.mfa.enabled` | TOTP enrollment confirmed. |
| `user.mfa.disabled` | TOTP turned off. |
| `user.api_token.created` | New API token issued. `details` carries `name` + `prefix`. |
| `user.api_token.revoked` | Token soft-revoked. `details` carries `token_id`. |
| `account.display_name_changed` | Self-service display name edit. |
| `account.password_changed` | Self-service password rotation. |
| `account.self_deleted` | User soft-deletes their own account. |
| `admin.user.roles_changed` | Admin replaces a user's role assignments. `details` carries `before` / `after` role-id arrays. |
| `admin.user.soft_deleted` | Admin soft-deletes a user. |

Apps can emit their own events too:

```rust
arium_dioxus::auth::audit::record(&pool, RecordInput { /* event_type, details, … */ }).await?;
```

## What the library ships vs what your app owns

**Library owns:**

- The schema: `users`, `user_permissions`, `oauth_accounts`,
  `password_reset_tokens`, `email_verification_tokens`,
  `mfa_recovery_codes`, `audit_events`, `roles`, `user_roles`, `api_keys`.
- Sign-in / sign-up / OAuth / verification / reset / MFA server fns.
- Drop-in screens: `LoginPanel`, `ForgotPassword`, `ResetPassword`,
  `VerifyEmail`, `MfaChallenge`, `MfaSetup`, `ApiTokens`,
  `AccountSettings`, `AdminUserList` / `AdminUserDetail` /
  `AdminRoleList` / `AdminRoleEditor` / `AuditLog`.
- Client RBAC primitives: `PermissionsProvider`, `use_permissions`,
  `PermissionGate`, `RequirePermission`, `RequireAuth`, `Policy`.

**Your app owns:**

- Page layout, theme, copy.
- Domain extensions to the user record (keep side-data in your own
  table keyed by `users.id`).
- Permission tokens and what they mean (the library evaluates them;
  your code grants them and writes the policies that use them).

## Common pitfalls

### `arium-dioxus/sqlite` (or `postgres`) belongs behind your `server` feature

`sqlite` / `postgres` pull `axum_session_sqlx` → `aes-gcm` →
`getrandom 0.2` into the build, and `getrandom 0.2` doesn't compile
for `wasm32-unknown-unknown` without its `js` feature. Keep
`arium-dioxus/sqlite` (or `postgres`) gated behind your own `server`
feature rather than in the default `arium-dioxus` feature list. The example
in `Cargo.toml` above shows this.

### `user.id` is `i32` but the session is `i64`

`arium_dioxus::auth::User` declares `id: i32`, but the session type is
`AuthSession<User, i64, _, _>` and the SQLite users column is
`INTEGER` (64-bit). Cast at the boundary:

```rust
let user_id = auth.current_user.as_ref()
    .filter(|u| !u.anonymous)
    .ok_or_else(|| ServerFnError::new("not logged in"))?
    .id as i64;
```

### First signup may get the `admin` role automatically

If `DX_AUTH_BOOTSTRAP_ADMIN_EMAIL` is set, the matching signup is
granted `admin`. Independently, if no admin currently exists when a
new user signs up, that signup is promoted. Harmless if you don't
expose an admin UI, but worth knowing when you see `admin:users:read`
on a freshly-signed-up test account.

### The `mail` feature changes signup semantics

With `mail` on, `register_with_password` returns
`LoginOutcome::EmailUnverified` and writes a verification email.
Without `mail`, it returns `LoginOutcome::LoggedIn` directly. A login
handler should cover all three outcomes (`LoggedIn` /
`EmailUnverified` / `MfaRequired`) so the same code works whichever
feature set you ship.

### `username` is derived from the email prefix and is NOT unique

`ensure_user` fills `users.username` from the email prefix on signup
(or the OAuth provider's login). Nothing enforces uniqueness on that
column — two `foo@x.com` / `foo@y.com` accounts both get `foo`. If
your domain has a "lookup by username" path, prefer email-based lookup
for any feature where selecting the wrong user matters.

## Dev tips

- `cargo check --workspace` builds the library + example.
- `cargo check -p arium-dioxus --no-default-features --features server,sqlite`
  builds the minimal library (no MFA, no OAuth, no mail, no rate limit).
- `cd examples/basic && dx serve` runs the demo.
- `sqlite3 examples/basic/auth.db '.schema'` inspects the live schema.
- Migrations are checksummed by sqlx; if you edit a `.sql` file after
  it's been applied, sqlx refuses to start until you wipe the DB or
  add a new migration file with the fix-up.
