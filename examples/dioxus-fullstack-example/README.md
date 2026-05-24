# dioxus-fullstack-example

End-to-end demo of [`arium-dioxus`](../../crates/arium-dioxus).

## Run

```bash
cd examples/dioxus-fullstack-example
DX_AUTH_SKIP_EMAIL_VERIFICATION=1 dx serve
```

Open <http://localhost:8080>. Register an account — the **first** user
becomes admin. The dev SQLite DB is `target/auth.db` (`rm` it to start
fresh).

- `DX_AUTH_SKIP_EMAIL_VERIFICATION=1` skips the email round-trip. Without
  it, verification/reset emails are written to `./emails/*.eml`.
- Set `GITHUB_CLIENT_ID` + `GITHUB_CLIENT_SECRET` to enable the GitHub
  button; set `SMTP_HOST` (+ creds) for real email. See
  [CONFIG_DIOXUS.md](../../CONFIG_DIOXUS.md#environment-variables) for the full list.
- For Google sign-in (OIDC), run `dx serve --features oauth-google` and set
  `GOOGLE_CLIENT_ID` + `GOOGLE_CLIENT_SECRET`.

Needs the [Dioxus CLI](https://dioxuslabs.com/learn/0.7/getting_started/)
(`dx`).

## Run with Docker

A **runtime-only** image — no Rust/wasm toolchain inside. You build the bundle
on the host, and a slim Debian image just runs the resulting `server` +
`public/`. SQLite keeps it single-container: no database service to manage.

```bash
cd examples/dioxus-fullstack-example
cp .env.example .env            # optional — edit port / OAuth / SMTP
mkdir -p data                   # so it's owned by you, not root (see below)
dx bundle --release --platform web --package dioxus-fullstack-example
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
- Build context is the workspace root (the bundle lives in the shared
  `target/`); compose sets `context: ../..` for you.
- Override the published port, `PUBLIC_BASE_URL`, SMTP creds, GitHub OAuth,
  etc. via `.env` (see `.env.example`). For the full arium config surface —
  Microsoft, generic OIDC, rate limiting, … — see
  [CONFIG_DIOXUS.md](../../CONFIG_DIOXUS.md#environment-variables).
- After a code change, re-bundle and rebuild:
  `dx bundle --release --platform web --package dioxus-fullstack-example && docker compose up -d --build`.
