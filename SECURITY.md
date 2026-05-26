# Security Policy

## Reporting a vulnerability

If you believe you've found a security issue in `arium`, please report
it privately. Public issues on the tracker should be reserved for
non-security bug reports.

- **Preferred:** open a GitHub Security Advisory at
  <https://github.com/tonybierman/arium/security/advisories/new> — this
  keeps the report private until a fix lands.
- **Fallback:** email `tonybierman@gmail.com` with `[arium security]`
  in the subject.

This is a personal project with no SLA; expect best-effort response
times. Please include in your report:

- a clear description of the issue and its impact,
- a minimal reproduction (commit SHA + repro steps or PoC),
- whether you intend to disclose publicly and on what timeline.

Researchers will be credited in the changelog and the resolved advisory
unless they request otherwise.

## Supported versions

The crate is pre-1.0 and ships from `main`. Only the latest commit on
`main` receives fixes. There is no release-branch backport policy yet.

## Threat model

`arium` is a reusable authentication and authorization library. It is intended to defend against:

- credential stuffing and brute-force sign-in (per-IP rate limiting),
- offline password cracking after database exfiltration (Argon2id
  hashing),
- session theft over the wire (cookie flags + TLS expected at the
  reverse proxy),
- OAuth callback CSRF (`state` verification stored in the session and
  checked on callback — see `crates/arium/src/oauth.rs`),
- TOTP recovery-code reuse (single-use enforced at the DB layer:
  `mfa_recovery_codes.used_at`),
- SQL injection (queries built with SQLx parameter binding — no string
  interpolation),
- secret leakage into the repo (gitleaks + trufflehog scans, see
  below).

It is **not** intended to defend against:

- a compromised host or database operator,
- a malicious dependency injected before the advisory database flags
  it,
- application-level authorization bugs in code that *consumes* this
  crate (it provides building blocks; correct use is the consumer's
  responsibility),
- side-channel attacks on Argon2 outside the documented parameter
  envelope.

## Hardening practices in place

### Authentication design

- Passwords hashed with **Argon2id** via the `argon2` crate.
- Sessions backed by `axum_session` / `axum_session_auth`.
- **TOTP** enrolment generates recovery codes whose Argon2 hashes are
  stored in `mfa_recovery_codes`; consumption sets `used_at` so a code
  can never be replayed.
- **OAuth** flows store the CSRF `state` per provider in the session
  before redirecting and compare on callback.
- **Per-IP rate limiting** on the entire router via `tower_governor`.
- **Append-only `audit_events` table** records authentication and
  admin state changes.
- **Bootstrap admin** is gated by the `BOOTSTRAP_ADMIN_EMAIL` env var —
  the first signup matching that email is auto-promoted, after which
  the env var no longer grants privileges to anyone else.
- **Secure response headers by default.** `install` stamps a behaviour-safe
  static set on every response (including short-circuited ones like a
  rate-limit `429`): `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: strict-origin-when-cross-origin`,
  `X-Frame-Options: SAMEORIGIN`, `Cross-Origin-Opener-Policy: same-origin`,
  `X-Permitted-Cross-Domain-Policies: none`, and a restrictive
  `Permissions-Policy`. No configuration required. The environment-specific
  headers (HSTS, CSP) and the `Secure` cookie flag are opt-in — see
  [Deploying behind HTTPS](#deploying-behind-https) below.
- **Credential forms submit over POST.** The login, forgot-password, and
  reset-password forms carry `method="post"`, so even in a degraded path
  (JS disabled, pre-hydration, or a native scanner submit) typed
  credentials never land in the URL / access logs / `Referer`.
- **Constant-time login.** Sign-in runs an Argon2 verify on every attempt —
  including unknown emails — so response timing can't be used to enumerate
  which addresses have accounts.
- **API tokens** are shown in cleartext only once at creation; only a prefix
  and a SHA-256 hash are stored. The `Authorization: Bearer` middleware
  (applied by `install` under the `tokens` feature) matches the hash against
  non-revoked `api_keys` rows — a malformed or revoked token is silently
  ignored, never trusted.
- **Per-resource authorization (`arium-authz`).** Resource-scoped checks are
  fresh, per-request, and default-deny: `require_resource` (and the `AuthzCtx`
  guard) hits the app's membership storage on every call — no caching — and
  treats "no relationship" and a below-threshold role identically as a deny,
  keeping a storage lookup failure distinct from a deliberate deny so the
  former can never be silently read as "no access." Denials write a
  `resource.access.denied` audit row.

### Dependency hygiene (CI-enforced)

Two GitHub Actions workflows run security tooling:

**Per push / PR — `.github/workflows/ci.yml`**

Gating (a failure blocks the merge):

- `cargo clippy` — two passes. `--all-targets` with the default
  warning set, plus `--lib` with security-leaning lints layered on
  (`unwrap_used`, `expect_used`, `panic`, `indexing_slicing`,
  `arithmetic_side_effects`). The strict set is scoped to the lib
  target only — `unwrap()` is idiomatic in tests.
- `cargo deny check bans licenses sources` — deterministic policy
  enforcement against `Cargo.lock`. Advisories are deliberately
  excluded here (see the `audit` job below) so an upstream-controlled
  moving target doesn't block PRs.
- `cargo audit` — RustSec advisory database against `Cargo.lock`.
  One curated ignore lives in [`.cargo/audit.toml`](.cargo/audit.toml),
  each entry justified inline with a reachability argument and a
  pointer to the standup card tracking re-evaluation.
- `cargo machete` — unused dependency detection.
- `gitleaks detect --source . --redact` — secret scan of the full
  repo + history. Invoked via the official binary, not the
  marketplace action (the action's license check is flaky for
  personal accounts). Allowlist lives in [`.gitleaks.toml`](.gitleaks.toml).
- `cargo fmt --check` — formatting.
- `cargo test` and a `cargo check` matrix across realistic feature
  combinations.

**Nightly — `.github/workflows/nightly.yml`**

- `cargo audit` again, so newly-published advisories surface within
  24 hours even when no PR is open.
- `cargo outdated` — surfaces new compatible releases.
- `cargo geiger` — counts `unsafe` reachable in the dep tree.
- `trufflehog` — full-history secret scan with `--only-verified`.

### Policy files

- [`deny.toml`](deny.toml) — license allow-list with per-entry
  rationale; explicit `allow-git` per source (no wildcard org trust);
  `yanked = "deny"`; `allow-wildcard-paths = true` for internal
  workspace members only.
- [`.cargo/audit.toml`](.cargo/audit.toml) — RustSec ignores, each
  entry annotated with the reachability argument that justifies it
  and a pointer to the standup card tracking re-evaluation.
- [`.gitleaks.toml`](.gitleaks.toml) — extends the upstream default
  ruleset with an allowlist for one recognisable test-fixture hex
  literal used to exercise email-template width checks.
- [`.gitignore`](.gitignore) — excludes dev SQLite databases, the
  dev-fallback `emails/` directory, and `.env` files.

### Cryptography and randomness

- **Password hashing:** Argon2id (`argon2` crate, default parameters).
  Verification uses the `password-hash` ecosystem; do not reach into
  raw hash bytes.
- **OAuth:** `oauth2` 5.x over `reqwest` + `rustls-tls`.
- **TOTP:** `totp-rs` 5.x.
- **Random secrets:** seeded from the OS via `argon2::password_hash::
  rand_core::OsRng` and `getrandom` — never a thread-local PRNG.

## Deploying behind HTTPS

Three production hardening knobs are **off by default** — each one breaks
plain-HTTP `localhost` development, so you opt in when deploying behind TLS.
Set them on the `AuthConfig` builder before `install`:

```rust
let cfg = AuthConfig::builder(pool, mailer)
    // ...providers, audit, rate-limit, etc...
    .cookie_secure(true)                       // session cookie sent over HTTPS only
    .hsts(arium::RECOMMENDED_HSTS)             // Strict-Transport-Security
    .content_security_policy("default-src 'self'; ...") // tune for your build
    .build()?;
```

- **`cookie_secure(true)`** adds `Secure` to the session cookie. Leave it off
  locally — a `Secure` cookie is never sent over HTTP, so enabling it on a
  plain-HTTP dev build silently logs everyone out. The cookie stays
  `SameSite=Lax` (not `Strict`) on purpose: the OAuth provider's callback is a
  cross-site top-level redirect, and only `Lax` lets the session cookie — which
  carries the CSRF `state` and PKCE verifier — ride it. `Strict` breaks OAuth.
- **`hsts(...)`** enables `Strict-Transport-Security`. `arium::RECOMMENDED_HSTS`
  is a sensible two-year `includeSubDomains; preload` value. Only set it behind
  HTTPS: once a browser sees HSTS it refuses plain-HTTP for the domain until the
  directive expires, which can lock you out of a `localhost` dev build.
- **`content_security_policy(...)`** enables CSP. A Dioxus app hydrates from
  wasm plus an inline bootstrap script, so the policy must permit them — a wrong
  CSP silently breaks hydration. See the rustdoc on
  `AuthConfigBuilder::content_security_policy` for a working starter policy to
  tighten with nonces/hashes once you've confirmed your build still hydrates.

`RECOMMENDED_HSTS` is exported from the `arium` crate; reference it as
`arium::RECOMMENDED_HSTS` (or pass the equivalent string literal) — the
`arium-dioxus` / `arium-leptos` adapters re-export `AuthConfig` and
`AuthConfigBuilder` but not the constant.

## Known limitations

- TLS termination is expected at a reverse proxy in front of the app;
  the example does not terminate TLS itself.
- The development-mode email backend writes `.eml` files to disk for
  inspection — never enable it in production (the `MAIL_*` env vars
  drive the production SMTP backend instead).
- `RUSTSEC-2023-0071` (`rsa 0.9.10`, Marvin Attack) — reaches the
  build graph only through `sqlx-macros-core`'s compile-time backend
  support and is not reachable from a deployed SQLite-only or
  Postgres-only build. Triaged, ignored in `.cargo/audit.toml` with
  the reachability argument inline. No upstream fix exists yet;
  recheck monthly via the nightly `cargo audit` and drop the ignore
  the moment a fix ships.
