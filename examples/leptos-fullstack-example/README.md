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

Needs [`cargo-leptos`](https://github.com/leptos-rs/cargo-leptos)
(`cargo install cargo-leptos`) and the `wasm32-unknown-unknown` target.
