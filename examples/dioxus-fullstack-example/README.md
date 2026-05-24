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
