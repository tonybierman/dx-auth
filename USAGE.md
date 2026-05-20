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
use dx_auth::{
    AuthConfig, Mailer,
    oauth::github::GithubProvider,
    server::*,
};

#[cfg(feature = "server")]
dioxus::serve(|| async {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .connect_with("sqlite://./app.db?mode=rwc".parse()?)
        .await?;
    sqlx::migrate!().run(&pool).await?;     // your migrations + the ones you copied

    let builder = AuthConfig::builder(pool.clone(), Mailer::from_env()?);
    let builder = match GithubProvider::from_env()? {
        Some(gh) => builder.oauth_provider(gh),
        None => builder,
    };

    dx_auth::install(dioxus::server::router(app), builder.build()).await
});
```

Then somewhere in your client-side UI — driven by what
`available_providers` returns from the server, which means buttons
appear / disappear based on which providers you registered above:

```rust
use dx_auth::ui::{LoginPanel, LoginProvider};
use dx_auth::server::available_providers;

let providers_resource = use_resource(available_providers);
let providers: Vec<LoginProvider> = providers_resource()
    .and_then(|r| r.ok())
    .unwrap_or_default()
    .into_iter()
    .map(LoginProvider::from)        // ProviderInfo → LoginProvider
    .collect();

LoginPanel {
    providers,
    title: "Welcome back",
    description: "Sign in to your workspace.",
    forgot_href: "/auth/forgot",
    on_submit: handler,
}
```

### Adding a new OAuth provider

Each provider is a struct that implements `dx_auth::oauth::OAuthProvider`.
The trait is small — id/secret/URLs, scopes, and a `fetch_profile` that
hits the provider's user-info endpoint and returns a
`NormalizedProfile`. Add a `oauth-<name>` Cargo feature that enables the
internal `_oauth-core` feature, drop a new module under
`crates/dx-auth/src/oauth/<name>.rs` mirroring `github.rs`, then
register it on the builder:

```rust
let builder = builder.oauth_provider(GoogleProvider::from_env()?.unwrap());
```

`install` mounts `/auth/<name>/login` + `/auth/<name>/callback` for every
registered provider automatically.

`examples/basic/` shows the complete shape, including the ProfileCard,
ForgotPassword / ResetPassword / VerifyEmail pages, and the MFA setup
flow.

## Gating UI by permission

`dx-auth` resolves the current user's permission tokens (direct grants
plus role-inherited ones) and ships them to the client on the
`UserProfile`. Rather than every component re-fetching, wrap your
router once in `PermissionsProvider`; downstream code uses the hook or
gate components against the shared resource.

```rust
use dx_auth::ui::{
    PermissionsProvider, PermissionGate, RequirePermission, use_permissions,
};

fn app() -> Element {
    rsx! {
        PermissionsProvider {
            Router::<Route> {}
        }
    }
}
```

### Element-level pruning

`PermissionGate` renders its children only when the check passes.
Provide exactly one of `token`, `any_of`, or `all_of`:

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

### Route-level guard

`RequirePermission` is the same check at route scope. While the
profile is still loading it renders nothing (no content flash); when
the check fails it calls `Navigator::replace(redirect_to)` so the
denied page can't be back-buttoned into:

```rust
#[component]
fn AdminUsersPage() -> Element {
    rsx! {
        RequirePermission {
            token: "admin:users:read".to_string(),
            redirect_to: "/".to_string(),
            AdminUsersBody {}
        }
    }
}
```

For routes that just need "user must be signed in" (no role / scope
check), use `RequireAuth`. Two shapes are supported — pick whichever
matches the surrounding UX.

Redirect on deny (matches `RequirePermission`):

```rust
#[component]
fn DashboardPage() -> Element {
    rsx! {
        RequireAuth { redirect_to: "/login".to_string(),
            DashboardBody {}
        }
    }
}
```

Inline fallback (render a `Login` panel in place of the gated page —
avoids the redirect flash and is more robust than a `use_effect`-based
navigation under hydration):

```rust
#[component]
fn DashboardPage() -> Element {
    rsx! {
        RequireAuth { fallback: rsx! { Login {} },
            DashboardBody {}
        }
    }
}
```

`RequirePermission` with no `token`/`any_of`/`all_of` props builds an
empty policy that fails closed — so it won't admit even authenticated
users. Reach for `RequireAuth` for the plain login gate;
`RequirePermission` for role-aware checks.

### Imperative checks via the hook

`use_permissions()` returns a `Copy` handle for event handlers and
imperative branches:

```rust
let perms = use_permissions();
if perms.has("admin:users:read")        { /* … */ }
if perms.any_of(["a", "b"])             { /* … */ }
if perms.all_of(["a", "b"])             { /* … */ }
perms.is_authenticated();
perms.is_loading();
perms.profile();           // Option<UserProfile> — full profile if loaded
perms.refresh();           // re-fetch after a grant change
```

### Reusable policies

When the same check appears in more than one place — typically the
navigation entry to a section *and* the section's route guard — define
it as a `Policy` so the call sites can't drift apart. A `Policy` is a
small value type: combine tokens with `any_of` / `all_of` / `with`,
optionally bind a scope, and pass to either gate component:

```rust
fn admin_policy() -> Policy {
    Policy::any_of(["admin:users:read", "admin:audit:read"])
}

// Nav entry — pruned when none of the admin tokens are held.
PermissionGate { policy: admin_policy(), AdminTabTrigger {} }

// Route guard — same check, redirects on miss.
RequirePermission { policy: admin_policy(), redirect_to: "/", AdminBody {} }

// Imperative branch.
if perms.check(&admin_policy()) { /* … */ }
```

Adding a new surface to the section is now a one-place edit: append the
new token to the policy. Both call sites pick it up.

Policies support a small tier-building shape with `.with(...)` and
`.scoped(...)`:

```rust
fn project_viewer() -> Policy { Policy::token("read") }
fn project_editor() -> Policy { project_viewer().with("write") }
fn project_owner()  -> Policy { project_editor().with("admin") }

PermissionGate {
    policy: project_editor().scoped(format!("project:{project_id}")),
    EditToolbar {}
}
```

`Policy` is deliberately not a full boolean DSL — there's no
`or`/`and`/`not` between policies. If your use case needs that today,
construct the union of tokens by hand and revisit when a third pattern
emerges.

If `policy` is set on a gate, the inline `token` / `any_of` / `all_of`
/ `scope` props are ignored.

### Scoped tokens (inline form)

For one-off checks that vary by resource (one record, one tenant, etc.),
pass `scope` inline; the gate composes the final lookup as
`"{scope}:{token}"`:

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

### Live invalidation

The profile resource is cached for the lifetime of the
`PermissionsProvider`. After any action that changes the current
user's grants, call `perms.refresh()` to re-fetch. Cross-tab /
server-push invalidation is left to the app.

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
| `oauth-github` | GitHub OAuth provider impl. Implies the internal `_oauth-core` feature, which pulls in the `oauth2` + `reqwest` deps and gates the generic `OAuthProvider` trait, `OAuthRegistry`, and the `/auth/{provider}/login`+`/callback` axum handlers shared by every provider. |
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

`GithubProvider::from_env()` returns `Ok(None)` when either required
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
- Client-side RBAC primitives — `PermissionsProvider`,
  `use_permissions`, `PermissionGate`, `RequirePermission`.

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
│       ├── auth.rs                  User + password / MFA helpers
│       ├── oauth.rs                 OAuthProvider trait + registry + generic axum handlers
│       ├── oauth/github.rs          GitHub provider impl (oauth-github feature)
│       ├── mail.rs                  Mailer + templates
│       ├── server.rs                Dioxus server fns
│       ├── pool.rs                  cfg-gated Pool / SessionPool aliases
│       ├── config.rs                AuthConfig + builder
│       ├── install.rs               dx_auth::install(router, cfg)
│       ├── wire.rs                  LoginOutcome, UserProfile, ProviderInfo, etc.
│       └── ui/
│           ├── login_panel/         the reusable login card
│           ├── permissions.rs       PermissionsProvider / Gate / Require / hook
│           ├── account/             AccountSettings panel
│           ├── admin/               AdminUserList / AdminUserDetail / AuditLog
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

## Drop-in auth routes

`LoginPanel` is one of four ready-made screen components. The other three
sit at the email-driven side flows linked from the login card. Wire them
into the consumer's `Route` enum:

```rust
use dx_auth::ui::{ForgotPassword, ResetPassword, VerifyEmail};

#[derive(Routable, Clone, PartialEq)]
pub enum Route {
    #[route("/login")]
    Login {},
    #[route("/auth/forgot")]
    ForgotPassword {},
    #[route("/auth/reset?:token")]
    ResetPassword { token: String },
    #[route("/auth/verify?:token")]
    VerifyEmail { token: String },
    // ... your domain routes
}
```

Paths above match `LoginPanel`'s default `forgot_href` and the URLs that
the `mail` backend bakes into outgoing verification / reset emails. If
you mount them somewhere else, override `LoginPanel { forgot_href: "..." }`
and configure the mailer's link templates to match.

Each component is anonymous-accessible (no `RequireAuth` wrapping) and
calls the corresponding server fn under the hood:

- `ForgotPassword` → `dx_auth::server::request_password_reset_email`.
  Always shows a neutral "if an account exists…" message — the server fn
  is user-enumeration-safe and returns `Ok(())` regardless.
- `ResetPassword { token }` → `dx_auth::server::reset_password`.
  Confirms passwords match client-side; surfaces friendly errors via
  `friendly_server_error`.
- `VerifyEmail { token }` → `dx_auth::server::verify_email`. Fires on
  mount, then renders one of three states (pending / verified /
  expired-or-used).

Each accepts overridable text props (`title`, `description`, `back_href`)
if you want to localize the copy.

## Common pitfalls

These came out of an early consumer migration. None are blocking, but
they're easier to plan around if you know about them.

### `user.id` is `i32` but the session is `i64`

`dx_auth::auth::User` declares `pub id: i32`, but the session type is
`AuthSession<User, i64, _, _>` and the SQLite users table column is
`INTEGER` (64-bit). Anywhere you read the ID for use with i64 columns or
domain models, cast at the boundary:

```rust
let user_id = auth.current_user.as_ref()
    .filter(|u| !u.anonymous)
    .ok_or_else(|| ServerFnError::new("not logged in"))?
    .id as i64;
```

### First signup gets the `admin` role automatically

The library's bootstrap path grants the `admin` role to the first user
that signs up (or to whoever matches `DX_AUTH_BOOTSTRAP_ADMIN_EMAIL` if
set). Harmless if you don't expose an admin UI, but worth knowing when
you see `admin:users:read` etc. on a freshly-signed-up account.

### The `mail` feature changes signup-success semantics

With `mail` on, `register_with_password` returns
`LoginOutcome::EmailUnverified` and writes a verification email. Without
`mail`, it returns `LoginOutcome::LoggedIn` directly. Your login UI's
`on_submit` should handle both branches so the same code path works
whichever feature set you ship — `examples/basic`'s `on_login_submit`
covers all three outcomes (`LoggedIn` / `EmailUnverified` / `MfaRequired`).

### `username` is derived from the email prefix and is NOT unique

`auth::ensure_user` fills `users.username` from the email prefix on
signup (or the OAuth provider's login). Nothing enforces uniqueness on
that column — two `foo@x.com` / `foo@y.com` accounts both get
`username = "foo"`. If your domain has a "lookup by username" path
(e.g. invite-by-username), prefer email-based lookup for any feature
where selecting the wrong user matters.
