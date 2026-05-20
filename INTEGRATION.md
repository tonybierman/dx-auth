# Integrating dx-auth into a Dioxus 0.7 fullstack app

This is a field report from migrating a homegrown auth stack (`dx_standup`,
a collaborative kanban / standup board) over to `dx-auth`. The library
already has a clean USAGE.md describing the happy path; this document
focuses on:

1. The integration steps that worked end-to-end (not just compile-clean).
2. The pitfalls that took real time to diagnose, with the underlying cause
   and the workaround.
3. Concrete suggestions for `dx-auth` itself so future integrations are
   shorter.

The target reader for sections 1-2 is someone wiring `dx-auth` into a
fullstack Dioxus app for the first time. Section 3 is feedback for the
library maintainer.

---

## 1. The integration recipe that works

The order matters — several of the gotchas in section 2 only surface
later in the build chain.

### 1.1 Cargo.toml

```toml
[dependencies]
dioxus = { version = "0.7.9", features = ["fullstack", "router"] }

# Capability features (ui, mail, oauth-github, mfa) need to be on for
# BOTH wasm and server builds so the `#[cfg(feature = "...")]`-gated
# server fn declarations are visible to the macro on both sides. The
# actual server-only crates inside dx-auth are target-gated to non-wasm.
#
# CRITICAL: `sqlite` (or `postgres`) is server-only — do NOT put it in
# the default feature list. It pulls axum_session_sqlx -> aes-gcm ->
# getrandom 0.2 into the wasm dep graph, which doesn't compile for
# wasm32-unknown-unknown without `getrandom/js`. See gotcha 2.1.
dx-auth = { path = "../dx-auth/crates/dx-auth", default-features = false, features = [
  "ui",
  "mail",
  "oauth-github",
  "mfa",
] }

# Direct deps the host already needs
axum              = { version = "0.8", features = ["json"], optional = true }
tokio             = { version = "1",   features = ["sync", "macros", "rt-multi-thread"], optional = true }
sqlx              = { version = "0.8", features = ["runtime-tokio", "sqlite", "macros", "migrate"], optional = true }
anyhow            = { version = "1", optional = true }

# Needed so server fns / axum handlers can name `dx_auth::auth::Session`
# as an extractor — that type is `axum_session_auth::AuthSession<...>`,
# and Rust needs the crate in scope to resolve the extractor's traits.
axum_session_auth = { version = "0.16.0", optional = true }

[features]
default = ["web"]
web     = ["dioxus/web", ...]
server  = [
  "dioxus/server",
  "dep:axum", "dep:tokio", "dep:sqlx", "dep:anyhow",
  "dep:axum_session_auth",
  "dx-auth/server",
  "dx-auth/sqlite",    # <-- gated behind YOUR server feature, not dx-auth's defaults
]
```

### 1.2 Copy the migrations

```
mkdir -p migrations
cp ../dx-auth/crates/dx-auth/migrations/sqlite/*.sql migrations/
```

`sqlx::migrate!()` picks them up from `./migrations/` at compile time.

### 1.3 Wire `install()` in your `serve` closure

```rust
dioxus::server::serve(|| async move {
    let pool = SqlitePoolOptions::new()
        .connect_with("sqlite://./app.db?mode=rwc".parse()?)
        .await?;
    sqlx::migrate!().run(&pool).await?;        // library + your own migrations

    // Build your own router(s) and merge them BEFORE install — dx_auth::install
    // layers session/auth onto whatever Router it's given, so any axum routes
    // you want to be auth-aware (SSE handlers, websockets, custom REST) must
    // already be merged in before this call.
    let merged = dioxus::server::router(App)
        .merge(my_sse_router)
        .layer(axum::Extension(my_app_state));

    let mailer = dx_auth::Mailer::from_env()?;
    let mut builder = dx_auth::AuthConfig::builder(pool, mailer);
    if let Some(gh) = dx_auth::oauth::github::GithubProvider::from_env()? {
        builder = builder.oauth_provider(gh);
    }
    dx_auth::install(merged, builder.build()).await
});
```

### 1.4 Wrap the router in `PermissionsProvider`

```rust
#[component]
fn App() -> Element {
    rsx! {
        document::Link { rel: "stylesheet", href: TAILWIND_CSS }
        document::Link { rel: "stylesheet", href: DX_COMPONENTS_CSS }

        // See gotcha 2.4 — without these, the LoginPanel renders unstyled
        // after the first SSR request.
        for href in DX_CATALOG_STYLESHEETS.iter() {
            document::Link { rel: "stylesheet", href: "{href}" }
        }

        dx_auth::ui::PermissionsProvider {
            Router::<Route> {}
        }
    }
}
```

### 1.5 Server fns: swap your auth extractor

For every server fn that used a cookie-based session, change the macro
attr from `cookies: TypedHeader<Cookie>` to `auth: dx_auth::auth::Session`,
then read `auth.current_user`:

```rust
#[post("/api/cards/new", auth: dx_auth::auth::Session)]
pub async fn create_card(board_id: i64, ...) -> Result<Card, ServerFnError> {
    #[cfg(feature = "server")]
    {
        let user = auth.current_user.as_ref()
            .filter(|u| !u.anonymous)         // dx-auth has a Guest user (id=1)
            .ok_or_else(|| ServerFnError::new("not logged in"))?;
        let user_id = user.id as i64;          // dx-auth User.id is i32

        // ... domain authz + DB work ...
    }
}
```

For plain axum handlers (e.g. an SSE route): the same `dx_auth::auth::Session`
type is an `AuthSession<User, i64, _, _>` extractor — name it as a handler
parameter:

```rust
pub async fn events_handler(
    Path(board_id): Path<i64>,
    State(state): State<AppState>,
    auth: dx_auth::auth::Session,
) -> Result<Sse<...>, StatusCode> { ... }
```

### 1.6 Auth-gating routes on the client

`dx-auth` provides `PermissionGate` and `RequirePermission` for *role-based*
checks. For the common "user must be logged in" gate, write a small wrapper
that reads `use_permissions().is_authenticated()` and renders the Login UI
inline (see gotcha 2.5):

```rust
#[component]
pub fn RequireAuth(children: Element) -> Element {
    let perms = use_permissions();
    if perms.is_authenticated() {
        rsx! { {children} }
    } else {
        rsx! { Login {} }
    }
}
```

### 1.7 Login page

A login screen is essentially a thin shell around `LoginPanel` with one
handler that dispatches `login_with_password` or `register_with_password`
and routes the four outcomes (`LoggedIn`, `EmailUnverified`, `MfaRequired`,
`Err`). The dx-auth example's `Home` component (in `examples/basic/src/main.rs`)
is the reference; copying its `on_submit` body is the shortest path.

### 1.8 Password-reset / email-verify routes

`LoginPanel`'s default `forgot_href` is `/auth/forgot`. The library does
not ship a router with those routes wired up — the consumer adds them.
If the `mail` feature is enabled, you need all three of these or signup
flows can't complete (the verification email links to `/auth/verify`).

Add three routes to your `Route` enum and three small components:

```rust
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

What each component does:

- **`ForgotPassword`** — email input, calls
  `dx_auth::server::request_password_reset_email(email)`. The library
  always returns `Ok(())` regardless of whether the address exists
  (user-enumeration-safe), so the UI just shows a neutral "if an account
  exists, a link is on its way" message after submit.
- **`ResetPassword { token }`** — new-password + confirm fields, calls
  `dx_auth::server::reset_password(token, new_pw)`. On success, link
  back to `/login`. On error, render the message from
  `dx_auth::friendly_server_error(e)`.
- **`VerifyEmail { token }`** — fires
  `dx_auth::server::verify_email(token)` from a `use_resource`. Render
  three states: pending / `Ok(true)` (success) / `Ok(false)` or `Err(_)`
  (expired-or-already-used). Both terminal states should link to
  `/login`.

The dx-auth example's `ForgotPassword`, `ResetPassword`, and
`VerifyEmail` components in `examples/basic/src/main.rs` are the
canonical reference. They use plain CSS class names from the example's
`app.css`; if you don't carry that file over, swap in
`dx_auth::ui::components::{button, card, input, label}::*` and your own
layout utility classes — the catalog widgets pick up the same
stylesheets you already pinned in App (1.4), so the visual treatment
stays consistent with `LoginPanel`.

These pages do NOT need to be wrapped in `RequireAuth` — they're
intentionally reachable while signed out.

If you ALSO enable the `mfa` feature, you'll want a fourth route
(`/account/mfa`) plus the `MfaSetup` / `MfaChallengeView` /
`VerificationPending` components from the example. Without them, the
sign-in flow handles `Ok(LoginOutcome::MfaRequired)` from
`login_with_password` only as an inline error string, which is fine for
accounts that haven't enrolled but blocks any account that has.

### 1.9 Smoke test

```
rm app.db                        # fresh start
dx serve
```

Sign up with an email + password. With `mail` enabled but `SMTP_HOST`
unset, a verification `.eml` is dumped to `./emails/<ts>.eml`. If you
don't want to wire up the verify route yet, fast-track it:

```
sqlite3 app.db "UPDATE users SET email_verified_at = strftime('%s','now') WHERE email = 'you@example.com';"
```

then sign in.

---

## 2. Pitfalls and workarounds

These are the things that took real time. None are blocking once you know
about them, but none are obvious from USAGE.md.

### 2.1 `sqlite` / `postgres` features pull server crates into the wasm build

**Symptom**

```
error: could not compile `getrandom` (lib) due to 1 previous error
   = note: the wasm*-unknown-unknown targets are not supported by default,
           you may need to enable the "js" feature.
```

**Cause**

`dx-auth`'s `sqlite` feature pulls in `axum_session_sqlx`, which depends on
`axum_session`, which uses `aes-gcm` for cookie signing, which uses
`rand_core`, which uses `getrandom 0.2`. None of these are target-gated to
non-wasm in dx-auth, so they end up in the wasm dep graph. `getrandom 0.2`
on `wasm32-unknown-unknown` needs the `js` feature to compile.

**Fix**

Don't put `sqlite` in your consumer's `dx-auth` feature list. Gate it
behind your own `server` feature (the dx-auth example does this too):

```toml
dx-auth = { ..., features = ["ui", "mail", "oauth-github", "mfa"] }

[features.server]
server = [..., "dx-auth/server", "dx-auth/sqlite"]
```

**Dx-auth could fix this** by target-gating `sqlx`, `axum_session`,
`axum_session_sqlx`, `axum_session_auth`, `argon2`, etc. to `cfg(not(target_arch = "wasm32"))`,
the same way `oauth2` / `reqwest` / `lettre` / `totp-rs` already are. The
capability features (`mfa`, `mail`, `oauth-github`) demonstrate the
pattern works — the backend feature just hasn't been migrated yet.

### 2.2 CSS-module asset filename collisions between library and consumer

**Symptom**

`LoginPanel` renders with class names like `dx-card-a80dec74`, but the
bundled CSS at `/assets/style-dxhcdc97e20afaee2cb.css` contains a
different class hash (`dx-card-9b2df649`) — so no rules match and the card
renders without a border.

**Cause**

When two crates have files at the same path-suffix (e.g. both `dx-auth`
and the consumer ship `card/style.css` under their `#[css_module(...)]`
declarations), the `asset!()` macro produces the same bundled output
filename. The second crate's content overwrites the first. The class
hashes inside the file are computed independently and do NOT collide,
so you end up with markup pointing at one hash and CSS defining the
other.

**Fix**

Rename your consumer-side `style.css` files to something unique per
widget — `card/card.css`, `input/input.css`, `button/button.css` — and
update the `#[css_module("/src/components/card/card.css")]` paths to
match. The bundled output filenames change to `card-dxh*.css` etc., and
the library's `style-dxh*.css` files are no longer overwritten.

**Dx-auth could fix this** by giving its own catalog stylesheets unique
filenames — e.g. `card/dx-card.css`, `input/dx-input.css` — so the
collision can't happen even if a consumer naively keeps a similar file
tree. Two-line file rename plus updating the `#[css_module(...)]` paths.

### 2.3 `dx-auth/sqlite` is required for axum_session_sqlx assets — but the macro re-feeds them via `sqlite`/`postgres` aliasing

This is mostly fine if you follow 2.1, but worth knowing: the host crate
also needs `sqlx/migrate` in its own dependency set (not just transitively
through dx-auth), because `sqlx::migrate!()` is invoked in the host's
`main.rs`.

### 2.4 catalog widget stylesheets vanish after the first SSR request

**Symptom**

Right after `dx serve` starts, the first browser load sees a styled
LoginPanel. Refresh once, and the catalog widget styles (card border,
button styling, input borders) are gone. Curl `/` and only 3-4
`<link rel="stylesheet">` tags appear in the head — the LoginPanel CSS is
present but the underlying catalog widget CSSes are missing.

**Cause**

The `#[css_module]` macro (from `manganis-macro 0.7.8`) injects its
`<link>` tag via a process-wide `OnceLock` in the `Deref::deref` impl of
the generated `__CssIdent` type. The link is created on first dereference
and never again for the lifetime of the process. In a long-running SSR
server, "first dereference" is request 1; request 2 onwards gets no link
because the OnceLock is already initialized.

`LoginPanel` works around this for *itself* by declaring an explicit
`Asset` constant for its own `style.css` and rendering
`document::Stylesheet { href: LOGIN_PANEL_CSS }` in its `rsx!` — so on
every render, a fresh link is emitted into the document head, no
OnceLock involved. The catalog widgets it relies on (`Card`, `Input`,
`Label`, `Button`, `Checkbox`) do NOT do this — they rely on the macro's
OnceLock path, which is broken under SSR.

**Workaround in the consumer**

Pin the catalog stylesheet URLs explicitly in `App`. The URLs are
deterministic from the dx-auth source tree's content hashes:

```rust
const DX_CATALOG_STYLESHEETS: &[&str] = &[
    "/assets/style-dxhcdc97e20afaee2cb.css", // dx-card-a80dec74
    "/assets/style-dxhd2b5a211eb3fb5b0.css", // dx-input-9d87df8a
    "/assets/style-dxh18addf1f9895a1.css",   // dx-button-b25df0a4
    "/assets/style-dxhb0ebf7906aa56cd1.css", // dx-label-620311f5
    "/assets/style-dxh20de733256a825b3.css", // dx-checkbox-5e59ddf6
];

#[component]
fn App() -> Element {
    rsx! {
        for href in DX_CATALOG_STYLESHEETS.iter() {
            document::Link { rel: "stylesheet", href: "{href}" }
        }
        ...
    }
}
```

To rediscover URLs after a dx-auth bump:

```bash
for f in target/dx/<your-app>/debug/web/public/assets/style-dxh*.css; do
  first=$(head -1 "$f" | grep -oE '^\.dx-[a-z_-]+-[a-f0-9]+' | head -1)
  echo "${first}  →  $(basename $f)"
done | sort -u
```

**Dx-auth could fix this** in the cleanest way by giving every catalog
widget the same explicit-Stylesheet treatment LoginPanel uses (the
"Same file the `#[css_module]` below points at; declared as a separate
`Asset`..." comment in `login_panel/component.rs`). Five widgets to
update, each gets ~5 lines added. After that, consumers don't need the
hardcoded URL list at all.

A complementary fix is at the manganis layer: replace the process-wide
`OnceLock` in the css_module macro with a per-render check (e.g. emit
`document::Stylesheet { href: ASSET }` directly in the macro expansion,
making every render reassert the link). The link's `href` is the same
string each time so the browser de-dupes it, but the SSR document
collector picks it up every request. Worth filing upstream.

### 2.5 `RequirePermission` doesn't gate on "logged in or not"

**Symptom**

You wrap a screen in `RequirePermission { redirect_to: "/login", … }`
with no `policy`/`token`/`any_of`/`all_of` — and authenticated users get
booted to the login page too, even though they're signed in.

**Cause**

`RequirePermission` builds a `Policy` from the inline props. With no
tokens, the policy is empty, and `Policy::evaluate()` deliberately
returns `false` for empty policies (per the doc comment: "unsatisfiable
policies do not silently admit everyone"). So `denied` is true for
every user.

The doc comment is right — RBAC gates should fail closed. But "this
route just needs an authenticated user" is a real use case that this
component doesn't serve, and the name doesn't make that obvious.

**Workaround**

Roll a tiny `RequireAuth` wrapper that reads `is_authenticated()` from
`use_permissions()` directly. Render the Login UI inline when not
authenticated rather than using `navigator().replace()` — the redirect
path inside a `use_effect` has been flaky under hydration here (it
reliably fires for some routes and not others; we never isolated why).
Inline rendering is more robust.

**Dx-auth could fix this** by shipping a first-class `RequireAuth`
component alongside `RequirePermission`. ~10 lines. Documenting it
in USAGE.md as "use this when you just need authentication; use
RequirePermission when you need a specific role" would clear up the
trap.

### 2.6 `LoginPanel` props are `&'static str`, not `String`

A small type-system papercut. `title`, `description`, `submit_label`,
etc. on `LoginPanel` are `&'static str`. Passing a dynamic `format!()`
result requires `String::leak()` or hoisting to a const. In practice
most consumers want fixed copy, so this works — but if you want to
localize the panel at runtime, you'll have to fork it.

### 2.7 `User.id` is `i32` in `dx_auth::auth::User`, but `i64` everywhere else

The `dx-auth` `User` struct has `pub id: i32`, but the session is
parameterized `AuthSession<User, i64, _, _>` and the SQLite column is
INTEGER (64-bit). Inside dx-auth, every site that touches the ID casts
`user.id as i64`. Consumers need to do the same:

```rust
let user_id = auth.current_user.unwrap().id as i64;
```

Easy enough once you know. Worth a note in USAGE.md.

### 2.8 `username` is derived from email-prefix and is NOT unique

dx-auth's `auth::ensure_user` populates `users.username` from the email
prefix on signup and from the OAuth provider's login otherwise. Nothing
enforces uniqueness on that column. Two accounts at `foo@x.com` and
`foo@y.com` both end up with `username = "foo"`, and a domain "invite by
username" query (`WHERE username = ?`) will silently pick the first row.

Workaround: invite by email, not username, for any feature where
selecting the wrong user matters. We left the "invite by username" code
in `dx_standup` as-is for now since the standup app is hobby-scale.

**Dx-auth could fix this** by adding a UNIQUE constraint on
`users.username` in migration 0001 (or a separate migration) and either
disambiguating with a numeric suffix on collision, or rejecting the
signup. A note in USAGE.md flagging the trade-off would suffice in the
meantime.

### 2.9 First signup gets the `admin` role automatically

`dx-auth`'s bootstrap-admin path grants the `admin` role to the first
user that signs up (or to whoever matches `DX_AUTH_BOOTSTRAP_ADMIN_EMAIL`).
Harmless if you don't expose any admin UI, but worth knowing. We had to
remember why a freshly-signed-up account had `admin:users:read` and
friends. A line in USAGE.md or the `auth::maybe_bootstrap_admin` doc
comment would help.

### 2.10 The `mail` feature changes signup outcome semantics

With `mail` enabled, `register_with_password` returns
`LoginOutcome::EmailUnverified` and writes a verification `.eml` (or sends
SMTP). Without `mail`, it returns `LoginOutcome::LoggedIn` directly.

Your login UI needs to handle both branches if you want the feature
matrix to be configurable. The dx-auth example handles all three outcomes
(`LoggedIn` / `EmailUnverified` / `MfaRequired`); copying that handler
is the easiest path.

---

## 3. Suggested improvements to dx-auth

In rough priority order:

1. **Target-gate the server backend deps** (sqlx, axum_session, axum_session_*,
   argon2) to `cfg(not(target_arch = "wasm32"))`. This removes the most
   confusing gotcha (2.1) — the wasm build wouldn't fail at all, and
   consumers wouldn't need to know about the `dx-auth/sqlite` placement
   trick.

2. **Give every catalog widget an explicit `document::Stylesheet` declaration**,
   following the `LoginPanel` pattern. Removes gotcha 2.4 entirely.
   Pattern is already proven inside dx-auth.

3. **Ship a `RequireAuth` component** (alongside `RequirePermission`) and
   document the difference. Removes gotcha 2.5.

4. **Rename catalog widget CSS files** so they can't collide with consumer
   files. E.g. `card/style.css` -> `card/dx-card.css`. Removes 2.2.

5. **File an upstream issue / PR against `manganis-macro`** for the
   process-wide `OnceLock` in the css_module path. Even with #2 above
   inside dx-auth, this still bites any other catalog that doesn't know
   to work around it. The fix is to emit `document::Stylesheet { href: ASSET }`
   into the rsx of any component that uses the css_module's classes —
   or equivalently to emit it directly from the macro expansion at every
   call site.

6. **Add a UNIQUE constraint on `users.username`** and handle the
   collision case explicitly (numeric suffix is the simplest). Removes
   the silent-wrong-user trap in 2.8.

7. **USAGE.md additions** — a single "common pitfalls" section near the
   bottom would cover 2.1, 2.5, 2.7, 2.8, 2.9, 2.10 without code changes.
   Each is a 2-3 sentence note.

8. **Ship the side-route components** (`ForgotPassword`, `ResetPassword`,
   `VerifyEmail`, plus the MFA variants) as drop-in `dx_auth::ui::*`
   exports, mirroring the LoginPanel pattern. Right now every consumer
   re-derives them from `examples/basic/src/main.rs`. They're pure
   wrappers around the existing server fns and would slot into the same
   `Route` enum with `forgot_href`-style defaults pointing at the
   library route paths. This is the single biggest one-time savings
   for the next integration.

8. **Consider whether `LoginPanel` should take `Into<String>` for its
   text props** rather than `&'static str`, for localized apps. Minor.

---

## 4. Reference: full file list touched in our migration

For anyone doing a similar swap-out, here's what we ended up editing
in the consumer (`dx_standup`):

Modified
- `Cargo.toml` — added dx-auth path dep with the right feature set,
  added `axum_session_auth`, added `sqlx/migrate`, dropped `axum-extra`.
- `src/main.rs` — replaced custom `provide_session()` with
  `PermissionsProvider`, merged routers before calling `dx_auth::install`,
  added the catalog-stylesheet pin list.
- `src/server/db.rs` — dropped custom `users` / `sessions` table DDL,
  switched to `sqlx::migrate!()` for dx-auth's migrations then runs
  domain DDL.
- `src/server/mod.rs` — dropped `login` / `register` / `logout` / `me`
  / `auth` modules; added `authz`.
- `src/server/realtime/sse.rs` — extractor swapped to
  `auth: dx_auth::auth::Session`; builds domain `User` at the boundary.
- 19 `src/server/*.rs` server fns — same swap as above, plus
  `user.id as i64` casts.
- `src/components/login.rs` — replaced with a thin `LoginPanel` wrapper.
- `src/router.rs` — added `/auth/forgot`, `/auth/reset?:token`,
  `/auth/verify?:token` routes (see 1.8).
- `src/components/board_list_screen.rs`, `board_screen.rs` — swapped
  `Protected` for `RequireAuth`.
- `src/components/{card,input,button}/style.css` — renamed to
  `{card,input,button}.css` and updated the `#[css_module]` paths to
  avoid asset-name collisions with dx-auth's catalog (gotcha 2.2).

Created
- `migrations/0001_init.sql` ... `0006_audit.sql` — copied from
  `dx-auth/crates/dx-auth/migrations/sqlite/`.
- `src/server/authz.rs` — domain `is_member` helper (was previously in
  `src/server/auth.rs`).
- `src/components/require_auth.rs` — the thin `RequireAuth` wrapper
  described in 1.6.
- `src/components/forgot_password.rs`, `reset_password.rs`,
  `verify_email.rs` — the three side routes for the email-driven flows
  (see 1.8). Each is ~50 lines of card + form wired to one server fn.

Deleted
- `src/auth/` (whole dir).
- `src/server/auth.rs`, `login.rs`, `register.rs`, `logout.rs`, `me.rs`.
- `src/components/protected.rs`.
- The old `dx_standup.db` (schema incompatible; fresh start).
