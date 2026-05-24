# Installing arium-dioxus

This covers adding [`arium-dioxus`](crates/arium-dioxus) to a Dioxus 0.7
fullstack app. For the runtime walkthrough see [USAGE_DIOXUS.md](USAGE_DIOXUS.md);
for features and environment variables see [CONFIG_DIOXUS.md](CONFIG_DIOXUS.md).

## Prerequisites

- A recent Rust toolchain (the workspace uses edition 2024).
- The [Dioxus CLI](https://dioxuslabs.com/learn/0.7/getting_started/) (`dx`):

  ```bash
  cargo install dioxus-cli
  ```

- The wasm target for the client build:

  ```bash
  rustup target add wasm32-unknown-unknown
  ```

## Add the dependency

`arium-dioxus` is compiled for two targets in one app: the wasm client and the
native server. The capability features (`ui`, `mail`, `oauth-github`, `mfa`,
`ratelimit`, `tokens`) must be on for **both** builds so the Dioxus macro can
see the `#[cfg(feature = "...")]`-gated server-fn declarations on each side. The
heavy server-only crates are already target-gated to non-wasm inside
`arium-dioxus`, so they stay inert on the client.

The one exception is the database backend: `sqlite` (or `postgres`) is
server-only and must be gated behind your own `server` feature — never put it
in the default feature list (see [Common pitfalls](#common-pitfalls)).

```toml
[dependencies]
dioxus = { version = "0.7.9", features = ["fullstack", "router"] }

arium-dioxus = { version = "0.1", default-features = false, features = [
  "ui",
  "mail",
  "oauth-github",
  # Opt-in OIDC logins (off by default — pull in the openidconnect crate):
  # "oauth-google",      # Google preset
  # "oauth-microsoft",   # Microsoft / Entra preset
  # "oauth-oidc",        # generic OIDC issuer (GitLab, Okta, Auth0, Keycloak, …)
  "mfa",
  "ratelimit",
  "tokens",
] }

# Server-only deps your host touches directly.
axum  = { version = "0.8", optional = true }
tokio = { version = "1",   features = ["full"], optional = true }
sqlx  = { version = "0.8", optional = true, features = [
  "runtime-tokio", "sqlite", "macros", "migrate",
] }

[features]
default = ["web"]
web     = ["dioxus/web"]
server  = [
  "dioxus/server",
  "dep:axum", "dep:tokio", "dep:sqlx",
  "arium-dioxus/server",
  "arium-dioxus/sqlite",    # <-- backend gated behind YOUR server feature
]
```

For PostgreSQL, swap the `sqlite` feature for `postgres` (in both the `sqlx`
features and `arium-dioxus/postgres`). The two backends are mutually exclusive.

## Build and run

```bash
dx serve
```

Then open <http://localhost:8080>. To skip the email round-trip in development:

```bash
DX_AUTH_SKIP_EMAIL_VERIFICATION=1 dx serve
```

To sanity-check the server build without the dev server:

```bash
cargo check --features server
```

## Common pitfalls

### Keep `arium-dioxus/sqlite` (or `postgres`) behind your `server` feature

The backend feature pulls `axum_session_sqlx` → `aes-gcm` → `getrandom 0.2`
into the build, and `getrandom 0.2` doesn't compile for
`wasm32-unknown-unknown` without its `js` feature. Gating the backend behind
your own `server` feature keeps it off the client build entirely. The
`Cargo.toml` above shows the correct shape.

### Capability features go on both sides

`ui`, `mail`, `oauth-github`, `mfa`, `ratelimit`, and `tokens` must be enabled
unconditionally (not behind `server`). The Dioxus `#[post]` / `#[get]` macros
generate the client-side fetch stub from the same gated declarations, so the
client build needs the features visible even though the implementation only
compiles on the server.

## Try the example

A complete, runnable app lives in
[`examples/dioxus-fullstack-example`](examples/dioxus-fullstack-example):

```bash
cd examples/dioxus-fullstack-example
DX_AUTH_SKIP_EMAIL_VERIFICATION=1 dx serve
```
