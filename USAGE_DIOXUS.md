# Using arium-dioxus

A walkthrough of wiring [`arium-dioxus`](crates/arium-dioxus) into a Dioxus 0.7
fullstack app. Every pattern here is exercised end-to-end in
[`examples/dioxus-fullstack-example`](examples/dioxus-fullstack-example).

Already installed? If not, start with [INSTALL_DIOXUS.md](INSTALL_DIOXUS.md).
For features and environment variables, see [CONFIG_DIOXUS.md](CONFIG_DIOXUS.md).

## 1. Server setup

`arium_dioxus::migrator()` ships the schema (`users`, `oauth_accounts`,
`roles`, `audit_events`, `api_keys`, …). `arium_dioxus::install` layers
sessions and auth onto whatever `axum::Router` you hand it — merge any custom
routes (SSE, websockets, REST) into the router *before* calling `install` so
they inherit the session middleware.

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
            builder = builder.oauth_provider(gh)?;
        }
        // OIDC presets (feature `oauth-google` / `oauth-microsoft`) are async —
        // they run discovery when constructed:
        #[cfg(feature = "oauth-google")]
        if let Some(google) = arium_dioxus::oauth::google::GoogleProvider::from_env().await? {
            builder = builder.oauth_provider(google)?;
        }

        let router = dioxus::server::router(app)
            // .merge(my_sse_router)
            // .layer(axum::Extension(my_app_state))
            ;

        arium_dioxus::install(router, builder.build()?).await
    });
}
```

## 2. Client wiring

Wrap the router in `PermissionsProvider` (always — it also pins the catalog
widget stylesheets so the auth screens stay styled across mount cycles), then
in `OAuthProvidersProvider` so the provider list is fetched once at the app
root and survives login/logout transitions.

```rust
use arium_dioxus::ui::{OAuthProvidersProvider, PermissionsProvider};

#[component]
fn app() -> Element {
    rsx! {
        document::Stylesheet { href: arium_dioxus::DEFAULT_THEME_CSS }
        PermissionsProvider {
            OAuthProvidersProvider {
                Router::<Route> {}
            }
        }
    }
}
```

`DEFAULT_THEME_CSS` is the catalog theme (the CSS custom properties every
widget reads). Override the palette by loading your own stylesheet after it.

## 3. Drop-in screens

`arium-dioxus` ships ready-made screen components for every email- or
session-driven flow. Wire them into your `Route` enum:

```rust
use arium_dioxus::ui::{
    ApiTokens, ForgotPassword, MfaSetup, ResetPassword, VerifyEmail,
};

#[derive(Routable, Clone, PartialEq)]
pub enum Route {
    #[route("/")]                   Home,
    #[route("/auth/forgot")]        ForgotPassword,
    #[route("/auth/reset?:token")]  ResetPassword { token: String },
    #[route("/auth/verify?:token")] VerifyEmail { token: String },
    #[route("/account/mfa")]        MfaSetup,
    #[route("/account/tokens")]     ApiTokens,
    // ... your domain routes
}
```

The default paths match `LoginPanel`'s baked-in `forgot_href` and the URLs the
mailer writes into outgoing emails. If you mount them elsewhere, override
`LoginPanel { forgot_href: "..." }` and the mailer link templates to match.

| Component | Backed by | Notes |
| --- | --- | --- |
| `LoginPanel` | `login_with_password` / `register_with_password` | The login card. Anonymous-accessible. |
| `ForgotPassword` | `request_password_reset_email` | Always shows a neutral "if an account exists…" message (no user enumeration). |
| `ResetPassword { token }` | `reset_password` | Confirms passwords match client-side. |
| `VerifyEmail { token }` | `verify_email` | Fires on mount; renders pending / verified / expired states. |
| `MfaChallenge` | `verify_login_mfa` | Post-password 6-digit prompt with recovery-code toggle. |
| `MfaSetup` | `begin/confirm/disable_mfa_setup` | Enrollment + management for `/account/mfa`. |
| `ApiTokens` | `create/list/revoke_api_token` | Personal-token management. |
| `AccountSettings` | account server fns | Display name, password change, delete account. |
| `AdminUserList` / `AdminUserDetail` / `AdminRoleList` / `AdminRoleEditor` / `AuditLog` | admin server fns | The admin console surfaces. |

## 4. Login handling

`login_with_password` returns one of three `LoginOutcome` variants; a login
screen has to dispatch on all three. (Which ones you see depends on features —
e.g. without `mail`, signup returns `LoggedIn` directly.)

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
                Ok(LoginOutcome::LoggedIn)        => perms.refresh(),
                Ok(LoginOutcome::EmailUnverified) => pending_email.set(Some(email_for_pending)),
                Ok(LoginOutcome::MfaRequired)     => pending_mfa.set(true),
                Err(e) => auth_error.set(friendly_server_error(e)),
            }
        });
    };

    if perms.is_authenticated() {
        rsx! { /* your authenticated UI */ }
    } else if pending_mfa() {
        rsx! { MfaChallenge {
            on_logged_in: move |_| { pending_mfa.set(false); perms.refresh(); },
            on_cancel: move |_| {
                pending_mfa.set(false);
                spawn(async move { let _ = cancel_mfa_challenge().await; });
            },
        } }
    } else {
        rsx! { LoginPanel { providers: providers.clone(), on_submit, /* … */ } }
    }
}
```

## 5. Permissions & RBAC

`arium-dioxus` resolves the current user's permission tokens (direct grants
plus role-inherited ones) and ships them to the client on the `UserProfile`.
`PermissionsProvider` (from step 2) caches the result for the tree.

**Route guards** — `RequireAuth` for "must be signed in", `RequirePermission`
for token checks:

```rust
RequireAuth { fallback: rsx! { Login {} }, DashboardBody {} }

RequirePermission {
    token: "admin:users:read".to_string(),
    redirect_to: "/".to_string(),
    AdminUsersBody {}
}
```

`RequirePermission` with no `token` / `any_of` / `all_of` / `policy` **fails
closed** — use `RequireAuth` when you only need "signed in".

**Element gates** — `PermissionGate` renders its children only when the check
passes (provide exactly one of `token`, `any_of`, `all_of`, `policy`):

```rust
PermissionGate { token: "admin:users:read".to_string(), AdminUsersLink {} }
PermissionGate {
    token: "admin:users:write".to_string(),
    fallback: rsx! { p { "Read-only." } },
    EditableUserRow {}
}
```

**Imperative checks** — `use_permissions()` returns a `Copy` handle:

```rust
let perms = use_permissions();
perms.has("admin:users:read");
perms.any_of(["a", "b"]);
perms.is_authenticated();
perms.refresh();          // re-fetch after a grant change
perms.profile();          // Option<UserProfile>
```

**Reusable policies** — when the same check guards both a nav entry and a route,
define it once as a `Policy` so the call sites can't drift:

```rust
fn admin_policy() -> Policy {
    Policy::any_of(["admin:users:read", "admin:audit:read"])
}

PermissionGate    { policy: admin_policy(), AdminTabTrigger {} }
RequirePermission { policy: admin_policy(), redirect_to: "/", AdminBody {} }
```

`Policy` supports tier-building (`.with(...)`) and resource scoping
(`.scoped(...)`); it is deliberately not a full boolean DSL.

## 6. Reading the current user in your own server fns

`arium_dioxus::auth::Session` is the `axum_session_auth` extractor. Use it as
the auth attribute on your server fns:

```rust
#[post("/api/cards/new", auth: arium_dioxus::auth::Session)]
pub async fn create_card(/* … */) -> Result<Card, ServerFnError> {
    #[cfg(feature = "server")]
    {
        let user = auth.current_user.as_ref()
            .filter(|u| !u.anonymous)   // arium-dioxus has a Guest user (id=1)
            .ok_or_else(|| ServerFnError::new("not logged in"))?;
        let user_id = user.id as i64;   // `User::id` is i32; the session key is i64
        // ... domain authz + DB work ...
    }
}
```

## 7. API tokens

The `tokens` feature ships the `ApiTokens` screen and `create/list/revoke`
server fns so users can self-manage personal tokens for CLI tools and other
clients that can't carry a session cookie. The cleartext secret is shown
**once** at creation; only a prefix and a SHA-256 hash are stored.

The library does not ship a Bearer-token extractor — validate incoming tokens
yourself by hashing the header and looking it up, which keeps the auth path
explicit:

```rust
use arium_dioxus::auth::tokens::hash_api_token;

let hash = hash_api_token(bearer_string);
let row: Option<(i64,)> = sqlx::query_as(
    "SELECT user_id FROM api_keys WHERE token_hash = $1 AND revoked_at IS NULL",
).bind(&hash).fetch_optional(&pool).await?;
```

## What the library owns vs what you own

**Library:** the schema, the auth server fns, the drop-in screens, and the
client RBAC primitives.

**You:** page layout / theme / copy, any domain extensions to the user record
(keep side-data in your own table keyed by `users.id`), and what your
permission tokens mean (the library evaluates them; your code grants them).

The full version of every snippet above is in
[`examples/dioxus-fullstack-example/src/main.rs`](examples/dioxus-fullstack-example/src/main.rs).
