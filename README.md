# arium

[![CI](https://github.com/tonybierman/arium/actions/workflows/ci.yml/badge.svg)](https://github.com/tonybierman/arium/actions)
[![Crates.io](https://img.shields.io/crates/v/arium.svg)](https://crates.io/crates/arium)
[![Docs.rs](https://docs.rs/arium/badge.svg)](https://docs.rs/arium)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Drop-in authentication and authorization for Rust fullstack apps built on
[axum](https://github.com/tokio-rs/axum) and [sqlx](https://github.com/launchbadge/sqlx),
with ready-made UI adapters for [Dioxus](https://dioxuslabs.com) and [Leptos](https://leptos.dev).

## Why this exists

Every multi-user app re-implements the same auth surface: password hashing, sessions,
OAuth, MFA, email verification, password reset, roles and permissions, and an
audit trail. arium implements that surface once as a framework-agnostic engine
you bolt onto an `axum::Router` with a single `install` call, then ships
framework adapters that wrap the engine in server functions and working
sign-in / account / admin screens. You get a complete auth flow without
rebuilding it, and you keep your own router, schema, and UI.

What's included:

- Email + password sign-in / sign-up with Argon2id hashing.
- OAuth / OpenID Connect sign-in — GitHub by default, plus opt-in Google,
  Microsoft/Entra, and any generic OIDC issuer (env-driven; each button hides
  itself when unconfigured), with account linking to email-matched local
  accounts.
- Forgot-password reset and email-verification flows over a pluggable mailer
  (SMTP via [lettre](https://github.com/lettre/lettre), or a dev fallback that
  writes `.eml` files locally).
- TOTP two-factor authentication with single-use recovery codes.
- Per-IP rate limiting and "remember me" long-lived sessions.
- Role-based access control: system `admin` / `user` roles plus user-defined
  roles, scoped permission tokens, route guards, and element-level gates.
- Per-resource, relationship-based authorization (the second axis): a role
  lattice (Viewer / Editor / Manager / Owner) with default-deny enforcement and
  a grant / revoke / transfer membership lifecycle — for collaborative apps
  where access is "what can this user do with *this* board / doc / project?"
- Personal API tokens for CLI / programmatic clients, with built-in
  `Authorization: Bearer` authentication.
- An append-only audit log of auth and admin events, with a built-in viewer.
- Drop-in UI screens (login, MFA, account settings, admin console) for both
  Dioxus and Leptos.

## Workspace layout

| Crate | What it is |
| --- | --- |
| [`arium`](crates/arium) | The framework-agnostic auth engine (axum + sqlx). Owns the schema, server logic, and the `install` helper. |
| [`arium-dioxus`](crates/arium-dioxus) | Dioxus 0.7 adapter — wraps the engine in server functions and UI components. |
| [`arium-leptos`](crates/arium-leptos) | Leptos 0.8 adapter — same surface, Leptos idioms. |
| [`arium-authz`](crates/arium-authz) | Per-resource (relationship-based) authorization — the role lattice, default-deny enforcement, and the membership lifecycle. Standalone; the engine re-exports it as `arium::authz` / `arium::membership`. |
| [`arium-pool`](crates/arium-pool) | Compile-time sqlx backend selection (`sqlite` / `postgres`) shared by the engine and `arium-authz`. Pulled in transitively. |
| [`arium-wire`](crates/arium-wire) | Shared types that cross the client/server boundary. Pulled in transitively; you rarely depend on it directly. |

Pick the adapter for your framework (`arium-dioxus` or `arium-leptos`) — it
re-exports everything you need from the engine. Use `arium` directly only if
you're wiring auth into a non-Dioxus, non-Leptos axum app.

## Installation

The install steps differ per framework (build tooling, feature flags,
client/server split):

- **Dioxus** → [INSTALL_DIOXUS.md](INSTALL_DIOXUS.md)
- **Leptos** → [INSTALL_LEPTOS.md](INSTALL_LEPTOS.md)

## Usage

At the core, you build an `AuthConfig` and `install` it onto your router. With
the engine directly:

```rust
use arium::{AuthConfig, Mailer, install, migrator};

let pool = sqlx::sqlite::SqlitePoolOptions::new()
    .connect_with("sqlite://./app.db?mode=rwc".parse()?)
    .await?;
migrator().run(&pool).await?;

let cfg = AuthConfig::builder(pool.clone(), Mailer::from_env()?).build()?;

// `router` is any axum::Router — e.g. your framework's server router.
let router = install(router, cfg).await?;
```

The adapters wrap this in server functions and ship the matching UI screens.
Full walkthroughs — server setup, client wiring, routes, login handling, and
RBAC guards:

- **Dioxus** → [USAGE_DIOXUS.md](USAGE_DIOXUS.md)
- **Leptos** → [USAGE_LEPTOS.md](USAGE_LEPTOS.md)

End-to-end runnable apps live in [`examples/`](examples).

## Configuration

Cargo features select the backend (`sqlite` / `postgres`) and which
capabilities are compiled in (`oauth-github`, `mfa`, `mail`, `ratelimit`,
`tokens`). Runtime behaviour — GitHub OAuth, SMTP, the bootstrap admin — is
driven entirely by environment variables; every feature degrades gracefully
when its config is absent. Full feature and env-var reference:

- **Dioxus** → [CONFIG_DIOXUS.md](CONFIG_DIOXUS.md)
- **Leptos** → [CONFIG_LEPTOS.md](CONFIG_LEPTOS.md)

Branding and theming the drop-in UI (shared across both adapters) →
[CUSTOMIZING.md](CUSTOMIZING.md).

## Security

Auth is the part of your app most worth getting right, so arium ships hardened
by default:

- **Password handling:** Argon2id hashing; sign-in runs a verify on every
  attempt — including unknown emails — so timing can't enumerate accounts.
- **Sessions & MFA:** single-use TOTP recovery codes (enforced at the DB
  layer), OAuth CSRF `state` verification, and secure response headers stamped
  on every response; `Secure` cookies, HSTS, and CSP are one builder call away
  for HTTPS deployments.
- **Abuse resistance:** per-IP rate limiting and an append-only audit log of
  auth and admin events.
- **Supply chain (CI-enforced):** `cargo audit`, `cargo deny`, `gitleaks`, and
  security-leaning `clippy` lints gate every PR, with nightly `trufflehog`,
  `cargo geiger`, and `cargo outdated` sweeps.

See [SECURITY.md](SECURITY.md) for the full threat model, the hardening
rationale behind each item, and how to report a vulnerability privately.

## Contributing

Issues and pull requests are welcome at
<https://github.com/tonybierman/arium>.

Before opening a PR, make sure CI will pass locally:

```bash
cargo fmt --all
cargo clippy --workspace --exclude dioxus-fullstack-example --all-targets -- -D warnings
cargo test --workspace --exclude dioxus-fullstack-example
```

Conventions:

- The crate READMEs are generated from the `//!` module docs with
  [`cargo-rdme`](https://github.com/orium/cargo-rdme). Edit the doc comment in
  `src/lib.rs`, then run `cargo rdme -w <crate>` — CI fails if they drift.
- Never edit an already-applied sqlx migration. sqlx checksums migration
  files; changing one breaks startup. Add a new migration instead.

## License

Licensed under either of:

- [Apache License, Version 2.0](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>
- [MIT License](LICENSE-MIT) or <https://opensource.org/licenses/MIT>

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
