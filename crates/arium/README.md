[![Crates.io](https://img.shields.io/crates/v/arium.svg)](https://crates.io/crates/arium)
[![Docs.rs](https://docs.rs/arium/badge.svg)](https://docs.rs/arium)
[![CI](https://github.com/tonybierman/arium/actions/workflows/ci.yml/badge.svg)](https://github.com/tonybierman/arium/actions)
[![License](https://img.shields.io/crates/l/arium.svg)](#license)

# arium

<!-- The section below is generated from src/lib.rs by cargo-rdme. Edit the `//!` doc comment, then run `cargo rdme`. -->
<!-- cargo-rdme start -->

Framework-agnostic authentication engine for axum + sqlx fullstack apps.

`arium` owns the auth domain — password hashing, sessions, OAuth and
OpenID Connect (GitHub, Google, Microsoft, or any OIDC issuer), MFA/TOTP,
email verification + password reset, RBAC, API tokens, and an audit log —
plus the `install` helper that bolts the whole thing onto an
`axum::Router`. It has no UI-framework dependency; framework adapters such
as `arium-dioxus` wrap these primitives in their own server fns + UI.

Typical server-side usage:

```rust
use arium::{
    AuthConfig, Mailer, install, migrator,
    oauth::{github::GithubProvider, OAuthRegistry},
};

let pool = sqlx::sqlite::SqlitePoolOptions::new()
    .connect_with("sqlite://./app.db?mode=rwc".parse()?)
    .await?;
migrator().run(&pool).await?;

let mut oauth = OAuthRegistry::new(pool.clone())?;
if let Some(gh) = GithubProvider::from_env()? {
    oauth = oauth.with_provider(gh);
}

let cfg = AuthConfig::builder(pool.clone(), Mailer::from_env()?)
    .oauth(oauth)
    .build()?;

// `router` is any `axum::Router` (e.g. your framework's server router).
let router = install(router, cfg).await?;
```

`oauth-github` is on by default. The opt-in `oauth-oidc`, `oauth-google`,
and `oauth-microsoft` features add a generic OpenID Connect provider plus
Google/Microsoft presets — each `from_env()`-constructed and registered the
same way as `GithubProvider` above.

### Per-resource authorization

Beyond global RBAC (flat permission tokens), the `authz` module adds
relationship-based checks — "what role does this user hold on *this*
resource?" Implement `authz::ResourceAuthority` over your own membership
storage and guard resource-scoped mutations with `require_resource`; it
does a fresh per-request lookup and default-denies. arium ships no
membership table — the app owns that storage; arium owns the enforcement
boundary and the `ResourceRole` lattice.

<!-- cargo-rdme end -->

## Installation

```toml
[dependencies]
arium = "0.1"
```

`arium` requires exactly one database backend. `sqlite` is on by default; for PostgreSQL, disable defaults and select `postgres`:

```toml
[dependencies]
arium = { version = "0.1", default-features = false, features = ["postgres", "oauth-github", "mfa", "mail", "ratelimit", "tokens"] }
```

| Feature        | Default | Enables                                        |
| -------------- | ------- | ---------------------------------------------- |
| `sqlite`       | yes     | SQLite backend (pick exactly one backend)      |
| `postgres`     | no      | PostgreSQL backend (pick exactly one backend)  |
| `oauth-github` | yes     | GitHub OAuth provider + routes                 |
| `oauth-oidc`   | no      | Generic OpenID Connect provider (any issuer)   |
| `oauth-google` | no      | Google OIDC preset (implies `oauth-oidc`)      |
| `oauth-microsoft` | no   | Microsoft OIDC preset (implies `oauth-oidc`)   |
| `mfa`          | yes     | TOTP MFA setup and challenge                   |
| `mail`         | yes     | Email verification & password reset (`Mailer`) |
| `ratelimit`    | yes     | Per-IP rate limiting on auth routes            |
| `tokens`       | yes     | API token issuance, validation, and `Bearer` auth |
| `sql-membership` | yes   | Bundled `SqlMembershipStore` + `membership_migrator()` for per-resource authz |

Without `mail`, `AuthConfig::builder` takes the pool alone. Full API reference on [docs.rs](https://docs.rs/arium).

## License

Licensed under either of:

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.
