[![Crates.io](https://img.shields.io/crates/v/arium-authz.svg)](https://crates.io/crates/arium-authz)
[![Docs.rs](https://docs.rs/arium-authz/badge.svg)](https://docs.rs/arium-authz)
[![CI](https://github.com/tonybierman/arium/actions/workflows/ci.yml/badge.svg)](https://github.com/tonybierman/arium/actions)
[![License](https://img.shields.io/crates/l/arium-authz.svg)](#license)

# arium-authz

<!-- The section below is generated from src/lib.rs by cargo-rdme. Edit the `//!` doc comment, then run `cargo rdme`. -->
<!-- cargo-rdme start -->

Per-resource, relationship-based authorization — standalone.

This is arium's *second authorization axis*, extracted so it can be used
independently of the arium auth engine. Global RBAC (flat permission tokens)
answers "what is this user across the whole app?"; this crate answers "what
is this user *with respect to this one resource?*" — the defining need of
collaborative apps (a board, a document, a project a user owns/edits/views).

- `authz` — the enforcement boundary: the `ResourceRole` lattice,
  `ResourceAuthority` (the one trait an app implements over its own
  storage), and `require_resource` (fresh, per-request, default-deny).
  Always available.
- `membership` — the lifecycle layer: `MembershipStore` (a supertrait of
  `ResourceAuthority`) and the invariant-bearing composites
  `grant_membership` / `revoke_membership` / `transfer_ownership`.
  Behind the default-on `lifecycle` feature; turning it off drops the
  sqlx-transaction surface for pure-enforcement embedders.

arium stores no resource memberships — the app owns that storage. The
global↔resource composition bridge (`require_resource_or_permission`) lives
in the `arium` engine crate, where both axes are present.

<!-- cargo-rdme end -->

## Installation

Pick exactly one backend (`sqlite` or `postgres`); it forwards down to
`arium-pool` so the whole tree agrees on one `Pool` type:

```toml
[dependencies]
arium-authz = { version = "0.1", features = ["sqlite"] }
```

Pure-enforcement embedders that don't want the membership lifecycle (and its
sqlx-transaction surface) can drop the default `lifecycle` feature:

```toml
[dependencies]
arium-authz = { version = "0.1", default-features = false }
```

Full API reference on [docs.rs](https://docs.rs/arium-authz). Key items: `ResourceRole`, `ResourceAuthority`, `require_resource`, `MembershipStore`, and the `grant_membership` / `revoke_membership` / `transfer_ownership` composites.

## License

Licensed under either of:

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.
