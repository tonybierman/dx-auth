# Installing arium-leptos

This covers adding [`arium-leptos`](crates/arium-leptos) to a Leptos 0.8
fullstack app. For the runtime walkthrough see [USAGE_LEPTOS.md](USAGE_LEPTOS.md);
for features and environment variables see [CONFIG_LEPTOS.md](CONFIG_LEPTOS.md).

## Prerequisites

- A recent Rust toolchain (the workspace uses edition 2024).
- [`cargo-leptos`](https://github.com/leptos-rs/cargo-leptos):

  ```bash
  cargo install cargo-leptos
  ```

- The wasm target for the client build:

  ```bash
  rustup target add wasm32-unknown-unknown
  ```

## Add the dependency

Like any Leptos fullstack app, the crate is compiled twice: once with `ssr`
for the server binary, once with `hydrate` for the wasm client. The server/
client split is driven by these cargo features (`#[cfg(feature = "ssr")]`),
not by `cfg(target_arch = "wasm32")`.

The capability features (`oauth-github`, `mfa`, `mail`, `ratelimit`, `tokens`)
and the backend (`sqlite` / `postgres`) must be present on **both** builds —
they only pull in engine code on the `ssr` build, where the `arium` engine is
actually a dependency.

```toml
[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
leptos = { version = "0.8", default-features = false }
leptos_router = { version = "0.8", default-features = false }
leptos_meta = { version = "0.8", default-features = false }
arium-leptos = { version = "0.1", default-features = false, features = [
  "ui",
  "mfa",
  "mail",
  "oauth-github",
  # Opt-in OIDC logins (off by default — pull in the openidconnect crate):
  # "oauth-google",      # Google preset
  # "oauth-microsoft",   # Microsoft / Entra preset
  # "oauth-oidc",        # generic OIDC issuer (GitLab, Okta, Auth0, Keycloak, …)
  "ratelimit",
  "tokens",
] }

# Server-only deps (axum host, runtime, db pool, Leptos axum integration).
axum = { version = "0.8", optional = true }
tokio = { version = "1", optional = true, features = ["rt-multi-thread", "macros", "net"] }
sqlx = { version = "0.8", optional = true, default-features = false, features = [
  "macros", "migrate", "sqlite", "runtime-tokio", "tls-native-tls",
] }
leptos_axum = { version = "0.8", optional = true }

# Client/wasm hydration entrypoint deps.
wasm-bindgen = { version = "0.2", optional = true }
console_error_panic_hook = { version = "0.1", optional = true }

[features]
default = ["ssr"]
ssr = [
  "dep:axum", "dep:tokio", "dep:sqlx", "dep:leptos_axum",
  "leptos/ssr", "leptos_meta/ssr", "leptos_router/ssr",
  "arium-leptos/ssr",
  "arium-leptos/sqlite",
]
hydrate = [
  "leptos/hydrate",
  "arium-leptos/hydrate",
  "dep:wasm-bindgen", "dep:console_error_panic_hook",
]

[package.metadata.leptos]
output-name = "your-app"
site-root = "target/site"
site-pkg-dir = "pkg"
site-addr = "127.0.0.1:3000"
reload-port = 3001
bin-features = ["ssr"]
bin-default-features = false
lib-features = ["hydrate"]
lib-default-features = false
```

For PostgreSQL, swap the `sqlite` feature for `postgres` (in both the `sqlx`
features and `arium-leptos/postgres`). The two backends are mutually exclusive.

## Build and run

```bash
cargo leptos watch
```

Then open <http://127.0.0.1:3000> (the `site-addr` from the metadata above). To
skip the email round-trip in development:

```bash
DX_AUTH_SKIP_EMAIL_VERIFICATION=1 cargo leptos watch
```

To check the server and client builds independently:

```bash
cargo check --features ssr
cargo check --features hydrate --target wasm32-unknown-unknown
```

## Try the example

A complete, runnable app lives in
[`examples/leptos-fullstack-example`](examples/leptos-fullstack-example):

```bash
cd examples/leptos-fullstack-example
DX_AUTH_SKIP_EMAIL_VERIFICATION=1 cargo leptos watch
```

Run only one instance at a time — the dev SQLite DB is a single file.
