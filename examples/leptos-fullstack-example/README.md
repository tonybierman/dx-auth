# leptos-fullstack-example

End-to-end demo of [`arium-leptos`](../../crates/arium-leptos).

## Run

```bash
cd examples/leptos-fullstack-example
DX_AUTH_SKIP_EMAIL_VERIFICATION=1 cargo leptos watch
```

Open <http://127.0.0.1:3000>. Register an account — the **first** user
becomes admin. The dev SQLite DB is `target/auth-leptos.db` (`rm` it to
start fresh); run only one instance at a time.

- `DX_AUTH_SKIP_EMAIL_VERIFICATION=1` skips the email round-trip. Without
  it, verification/reset emails are written to `./emails/*.eml`.
- Set `GITHUB_CLIENT_ID` + `GITHUB_CLIENT_SECRET` to enable the GitHub
  button; set `SMTP_HOST` (+ creds) for real email.
- For Google sign-in (OIDC), build with `--features oauth-google` and set
  `GOOGLE_CLIENT_ID` + `GOOGLE_CLIENT_SECRET`.

Needs [`cargo-leptos`](https://github.com/leptos-rs/cargo-leptos)
(`cargo install cargo-leptos`) and the `wasm32-unknown-unknown` target.

## Run with Docker

A **runtime-only** image — no Rust/wasm toolchain inside. You build on the
host, and a slim Debian image just runs the SSR `server` binary plus the
client bundle from `target/site/`. SQLite keeps it single-container: no
database service to manage.

```bash
cd examples/leptos-fullstack-example
cp .env.example .env            # optional — edit port / OAuth / SMTP
mkdir -p data                   # so it's owned by you, not root (see below)
cargo leptos build --release
docker compose up -d --build
```

Open <http://localhost:8080>. The SQLite DB and the `.eml` mailer output land
in `./data/` (host-owned, gitignored) — `rm -rf data` to start fresh.

- Create `data/` yourself first: the container runs as `user:
  ${UID:-1000}:${GID:-1000}` so the DB/emails land host-owned, but if Docker
  has to create the bind-mount dir it makes it `root`-owned and the container
  can't write. On a default `1000:1000` login, `mkdir -p data` is all you
  need; on a different uid/gid, set `UID=` / `GID=` in `.env` (bash keeps
  `UID` readonly, so `export UID` won't work — `.env` is the clean path).
- Build context is the workspace root (the binary + bundle live in the shared
  `target/`); compose sets `context: ../..` for you. Runtime config comes from
  `LEPTOS_*` env in the Dockerfile (there's no `Cargo.toml` in the image).
- Override the published port, `PUBLIC_BASE_URL`, SMTP creds, GitHub OAuth,
  etc. via `.env` (see `.env.example`). For the full arium config surface —
  Microsoft, generic OIDC, rate limiting, … — see
  [CONFIG_LEPTOS.md](../../CONFIG_LEPTOS.md#environment-variables).
- After a code change, rebuild:
  `cargo leptos build --release && docker compose up -d --build`.
