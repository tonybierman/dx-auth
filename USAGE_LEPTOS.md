# Using arium-leptos

A walkthrough of wiring [`arium-leptos`](crates/arium-leptos) into a Leptos 0.8
fullstack app. Every pattern here is exercised end-to-end in
[`examples/leptos-fullstack-example`](examples/leptos-fullstack-example).

Already installed? If not, start with [INSTALL_LEPTOS.md](INSTALL_LEPTOS.md).
For features and environment variables, see [CONFIG_LEPTOS.md](CONFIG_LEPTOS.md).

Unlike the Dioxus adapter, the server/client split is driven by the `ssr` /
`hydrate` cargo features (`#[cfg(feature = "ssr")]`), not by
`cfg(target_arch = "wasm32")` — Leptos compiles the crate once per side.

## 1. Server setup (`ssr`)

`arium_leptos::migrator()` ships the schema; `arium_leptos::install` layers
sessions, OAuth routes, the audit emitter, and the rate limiter over your
Leptos axum router. Build the router (server-fn handler + Leptos routes)
first, then `install` over the whole thing.

```rust
#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use axum::{Router, routing::post};
    use leptos::config::get_configuration;
    use leptos_axum::{LeptosRoutes, file_and_error_handler, generate_route_list, handle_server_fns};

    let pool = /* build your sqlx pool */;
    arium_leptos::migrator().run(&pool).await?;

    let mut builder = arium_leptos::AuthConfig::builder(pool.clone(), arium_leptos::Mailer::from_env()?);
    if let Some(gh) = arium_leptos::oauth::github::GithubProvider::from_env()? {
        builder = builder.oauth_provider(gh)?;
    }
    // OIDC presets (feature `oauth-google` / `oauth-microsoft`) are async —
    // they run discovery when constructed:
    #[cfg(feature = "oauth-google")]
    if let Some(google) = arium_leptos::oauth::google::GoogleProvider::from_env().await? {
        builder = builder.oauth_provider(google)?;
    }
    let cfg = builder.build()?;

    let conf = get_configuration(None)?;
    let leptos_options = conf.leptos_options;
    let routes = generate_route_list(App);

    let app = Router::new()
        .route("/api/{*fn_name}", post(handle_server_fns))
        .leptos_routes(&leptos_options, routes, {
            let opts = leptos_options.clone();
            move || shell(opts.clone())
        })
        .fallback(file_and_error_handler::<LeptosOptions, _>(shell))
        .with_state(leptos_options.clone());

    // Layers AuthSessionLayer + SessionLayer (+ OAuth routes, rate limiter,
    // Pool/Mailer/Providers extensions) over the whole router.
    let app = arium_leptos::install(app, cfg).await?;

    let listener = tokio::net::TcpListener::bind(&leptos_options.site_addr).await?;
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}
```

Server fns extract their request context (auth session, db pool, mailer) from
the axum extensions `install` layers on — no extra `provide_context` is needed.

## 2. Client wiring

Wrap the router in `PermissionsProvider` (always — it also pins the catalog
widget stylesheets), then in `OAuthProvidersProvider` so the provider list is
fetched once at the app root.

```rust
use arium_leptos::ui::{OAuthProvidersProvider, PermissionsProvider};

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();
    view! {
        <PermissionsProvider>
            <OAuthProvidersProvider>
                <Router>
                    <Routes fallback=|| view! { <p>"Not found."</p> }>
                        <Route path=path!("/")              view=Home />
                        <Route path=path!("/auth/forgot")   view=|| view! { <ForgotPassword /> } />
                        <Route path=path!("/auth/reset")    view=ResetRoute />
                        <Route path=path!("/auth/verify")   view=VerifyRoute />
                        <Route path=path!("/account/mfa")   view=|| view! { <MfaSetup /> } />
                        <Route path=path!("/admin")         view=AdminPage />
                    </Routes>
                </Router>
            </OAuthProvidersProvider>
        </PermissionsProvider>
    }
}
```

The catalog theme is exposed as `arium_leptos::DEFAULT_THEME_CSS`; inject it (or
your own override) in your SSR shell. `ResetPassword` / `VerifyEmail` take a
`token` prop — read it from the query string with `use_query_map` (see the
example's `ResetRoute` / `VerifyRoute`).

## 3. Drop-in screens

The same screen set as the Dioxus adapter, as Leptos components under
`arium_leptos::ui`:

| Component | Backed by | Notes |
| --- | --- | --- |
| `LoginPanel` | `login_with_password` / `register_with_password` | The login card. |
| `ForgotPassword` | `request_password_reset_email` | Neutral message — no user enumeration. |
| `ResetPassword` (prop `token`) | `reset_password` | |
| `VerifyEmail` (prop `token`) | `verify_email` | Renders on mount. |
| `MfaChallenge` | `verify_login_mfa` | Post-password 6-digit prompt. |
| `MfaSetup` | `begin/confirm/disable_mfa_setup` | Enrollment + management. |
| `ApiTokens` | `create/list/revoke_api_token` | Personal-token management. |
| `AccountSettings` | account server fns | Display name, password, delete. |
| `AdminUserList` / `AdminUserDetail` / `AdminRoleList` / `AdminRoleEditor` / `AuditLog` | admin server fns | Admin console surfaces. |

## 4. Login handling

`login_with_password` returns one of three `LoginOutcome` variants; dispatch on
all three:

```rust
use arium_leptos::server::{login_with_password, register_with_password, logout};
use arium_leptos::ui::{LoginPanel, LoginSubmit, MfaChallenge, SubmitKind, use_oauth_providers, use_permissions};
use arium_leptos::{LoginOutcome, friendly_server_error};
use leptos::task::spawn_local;

#[component]
fn Home() -> impl IntoView {
    let perms = use_permissions();
    let providers = use_oauth_providers();
    let auth_error = RwSignal::new(String::new());
    let pending_email = RwSignal::new(None::<String>);
    let pending_mfa = RwSignal::new(false);

    let on_login = Callback::new(move |sub: LoginSubmit| {
        let LoginSubmit { kind, email, password, remember } = sub;
        let email_pending = email.clone();
        spawn_local(async move {
            let result = match kind {
                SubmitKind::SignIn => login_with_password(email, password, remember).await,
                SubmitKind::SignUp => register_with_password(email, password).await,
            };
            match result {
                Ok(LoginOutcome::LoggedIn)        => perms.refresh(),
                Ok(LoginOutcome::EmailUnverified) => pending_email.set(Some(email_pending)),
                Ok(LoginOutcome::MfaRequired)     => pending_mfa.set(true),
                Err(e) => auth_error.set(friendly_server_error(e)),
            }
        });
    });

    view! {
        {move || {
            if perms.is_authenticated() {
                view! { /* your authenticated UI */ }.into_any()
            } else if pending_mfa.get() {
                view! {
                    <MfaChallenge
                        on_logged_in=Callback::new(move |_| { pending_mfa.set(false); perms.refresh(); })
                        on_cancel=Callback::new(move |_| {
                            pending_mfa.set(false);
                            spawn_local(async move { let _ = arium_leptos::server::cancel_mfa_challenge().await; });
                        })
                    />
                }.into_any()
            } else {
                view! { <LoginPanel providers=providers on_submit=on_login /> }.into_any()
            }
        }}
    }
}
```

`friendly_server_error` strips Leptos's `"error running server function: …"`
wrapper and substitutes a friendly retry message for rate-limit 429s.

## 5. Permissions & RBAC

`PermissionsProvider` (from step 2) caches the current user's resolved tokens.

**Route guard** — `RequirePermission` (and `RequireAuth` for plain
"signed in"):

```rust
view! {
    <RequirePermission policy=admin_policy() redirect_to="/">
        <AdminBody />
    </RequirePermission>
}
```

**Element gate** — `PermissionGate` renders its children only when the check
passes:

```rust
view! {
    <PermissionGate token="admin:users:read".to_string()>
        <TabTrigger value="users">"Users"</TabTrigger>
    </PermissionGate>
}
```

**Imperative checks** — `use_permissions()`:

```rust
let perms = use_permissions();
perms.has("admin:users:read");
perms.any_of(["a", "b"]);
perms.is_authenticated();
perms.refresh();
perms.profile();          // Option<UserProfile>
```

**Reusable policies** — define a check once so the nav entry and route guard
can't drift:

```rust
fn admin_policy() -> Policy {
    Policy::any_of(["admin:users:read", "admin:audit:read", "admin:roles:read"])
}

view! { <PermissionGate policy=admin_policy()> … </PermissionGate> }
```

`Policy` supports tier-building (`.with(...)`) and resource scoping
(`.scoped(...)`); it is deliberately not a full boolean DSL.

## 6. API tokens

The `tokens` feature ships the `ApiTokens` screen and `create/list/revoke`
server fns. The cleartext secret is shown **once** at creation; only a prefix
and a SHA-256 hash are stored. The library does not ship a Bearer-token
extractor — validate incoming tokens yourself by hashing the header and looking
up `api_keys.token_hash`, which keeps the auth path explicit.

## What the library owns vs what you own

**Library:** the schema, the auth server fns, the drop-in screens, and the
client RBAC primitives.

**You:** the SSR shell, page layout / theme / copy, any domain extensions to
the user record (your own table keyed by `users.id`), and what your permission
tokens mean.

The full version of every snippet above is in
[`examples/leptos-fullstack-example/src/app.rs`](examples/leptos-fullstack-example/src/app.rs)
(and `main.rs` for the server).
