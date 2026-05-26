[![Crates.io](https://img.shields.io/crates/v/arium-pool.svg)](https://crates.io/crates/arium-pool)
[![Docs.rs](https://docs.rs/arium-pool/badge.svg)](https://docs.rs/arium-pool)
[![CI](https://github.com/tonybierman/arium/actions/workflows/ci.yml/badge.svg)](https://github.com/tonybierman/arium/actions)
[![License](https://img.shields.io/crates/l/arium-pool.svg)](#license)

# arium-pool

<!-- The section below is generated from src/lib.rs by cargo-rdme. Edit the `//!` doc comment, then run `cargo rdme`. -->
<!-- cargo-rdme start -->

Compile-time-selected sqlx pool aliases — the one place the backend
(`sqlite` vs `postgres`) is chosen.

Enable exactly one of the `sqlite` or `postgres` features. Both the arium
auth engine and `arium-authz` depend on this crate, so they agree on a
single concrete `Pool` type and a single "exactly one backend" guard:
a feature-unification mistake fails here, loudly, rather than as a cryptic
`SqlitePool`-vs-`PgPool` mismatch deep in a transaction signature.

<!-- cargo-rdme end -->

## Installation

Enable exactly one backend feature — there is no default, so the backend is
chosen once at the top of the dependency tree and forwarded down:

```toml
[dependencies]
arium-pool = { version = "0.1", features = ["sqlite"] } # or "postgres"
```

Full API reference on [docs.rs](https://docs.rs/arium-pool). Key aliases: `Pool`, `DbBackend`, `DbConnection`.

## License

Licensed under either of:

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.
