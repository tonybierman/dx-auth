# dx-auth

A Dioxus 0.7 fullstack example wiring `axum-session-auth` to a real auth stack:

- Email + password sign-in / sign-up (Argon2id).
- "Continue with GitHub" OAuth (only when configured — see env vars below).
- Account linking — signing in with GitHub when an email-matched local account
  already exists attaches the OAuth identity to it instead of creating a
  duplicate.
- Persistent SQLite at `auth/auth.db`, schema applied via `sqlx::migrate!()`.
- Pluggable email backend (real SMTP, or local `.eml` files for dev).

## Running

```bash
cd auth
dx serve
```

Then open `http://localhost:8080`.

`auth/auth.db` is created on first run and reused across restarts. To start
fresh, just `rm auth/auth.db`.

## Environment variables

All env vars are **optional** — features gracefully degrade when their config
isn't present.

### GitHub OAuth

`GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` must **both** be set for the
"Continue with GitHub" button to appear. With either missing, the routes are
skipped and the button is hidden — the rest of the app continues working with
email/password only.

| Var | Default | Notes |
| --- | --- | --- |
| `GITHUB_CLIENT_ID` | _(unset)_ | OAuth App Client ID from <https://github.com/settings/developers>. |
| `GITHUB_CLIENT_SECRET` | _(unset)_ | OAuth App Client Secret. |
| `GITHUB_REDIRECT_URL` | `http://localhost:8080/auth/github/callback` | Must exactly match the "Authorization callback URL" registered in the GitHub OAuth App. |

To set up a GitHub OAuth App for local development:

1. <https://github.com/settings/developers> → **New OAuth App**.
2. Homepage URL: `http://localhost:8080`.
3. Authorization callback URL: `http://localhost:8080/auth/github/callback`.
4. Copy the Client ID; generate a Client Secret.

### Outbound email (Phase 5+)

When `SMTP_HOST` is set, lettre opens a STARTTLS submission connection.
When it's unset, the dev fallback writes RFC-822 `.eml` files into
`auth/emails/<timestamp>.eml` so password-reset and verification flows are
testable without a provider.

| Var | Default | Notes |
| --- | --- | --- |
| `SMTP_HOST` | _(unset → file backend)_ | e.g. `smtp.sendgrid.net`, or `localhost` against a local [Mailpit](https://mailpit.axllent.org/). |
| `SMTP_PORT` | `587` | |
| `SMTP_USER` | _(unset → no auth)_ | |
| `SMTP_PASSWORD` | _(unset)_ | |
| `FROM_EMAIL` | `noreply@localhost` | Address used in the `From:` header. |
| `PUBLIC_BASE_URL` | `http://localhost:8080` | Used to build absolute links inside email bodies (verification, password reset). |

### Server-rendering

| Var | Default | Notes |
| --- | --- | --- |
| `IP` | `127.0.0.1` | Wired by `dx serve` — bind address. |
| `PORT` | `8080` | Wired by `dx serve` — port. |

## Development tips

- `sqlite3 auth/auth.db '.schema'` shows the live schema.
- Migrations live in `auth/migrations/`. Modifying a migration after it has
  been applied requires deleting `auth/auth.db` (sqlx detects the checksum
  change and refuses to run otherwise).
- The dev email backend logs each delivery with a path like
  `[mail] wrote ./emails/1747700000000.eml` — open the file in any email
  client to inspect rendering.

## Project layout

```
auth/
├── Cargo.toml
├── migrations/                 # sqlx migrations, embedded at compile time
├── assets/
│   ├── dx-components-theme.css # catalog theme
│   └── app.css                 # app-level layout + dark-theme override
└── src/
    ├── main.rs                 # router, server fns, app() UI
    ├── auth.rs                 # User type, OAuth helpers, password helpers
    ├── mail.rs                 # Mailer + email templates
    └── components/
        ├── login_panel/        # reusable email/password + provider login card
        └── …                   # `dx components add`-installed catalog widgets
```
