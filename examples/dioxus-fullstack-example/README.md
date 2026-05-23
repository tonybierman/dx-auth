# examples/dioxus-fullstack-example

End-to-end demo of [`arium-dioxus`](../../). Every auth screen — sign in,
forgot/reset password, email verification, MFA challenge, MFA setup,
account settings, admin user list / role editor / audit log — comes
from the library as a drop-in `arium_dioxus::ui::*` component. This binary
only owns app-specific pieces:

- `Home` — the post-login landing page (tabs for Account, Two-factor,
  and Admin) plus the pre-login `LoginPanel` shell.
- `ProfileCard` — a small avatar + name + email card rendered above
  the account settings tab.
- `VerificationPending` — the "check your inbox" card shown after a
  signup needs verification.
- `AccountSettingsPage` — a thin route wrapper around
  `arium_dioxus::ui::AccountSettings`.
- `AdminPage` — a tabset that composes the library's
  `AdminUserList` / `AdminUserDetail` / `AuditLog` /
  `AdminRoleList` / `AdminRoleEditor` drop-ins, with per-tab
  permission gating and master-detail selection state.
- `get_permissions` server fn — demos the `axum_session_auth` rights
  check against the library's `User` and an app-specific permission
  token (`Category::View`).

## Run

```bash
cd examples/dioxus-fullstack-example
DX_AUTH_SKIP_EMAIL_VERIFICATION=1 dx serve
```

Then open `http://localhost:8080`. A SQLite file is created on first run at
`target/auth.db` in the workspace root; `rm target/auth.db` to start fresh
(you'll lose all accounts).

## Optional env vars

See [USAGE.md](../../USAGE.md#environment-variables) in the workspace
root for the full table. The most useful ones for kicking the tires
locally:

```bash
# Enable the "Continue with GitHub" button. Without these the panel
# renders email/password only.
export GITHUB_CLIENT_ID=...
export GITHUB_CLIENT_SECRET=...

# With no SMTP_HOST set, verification + password-reset emails get
# written to ./emails/<timestamp>.eml — open them in any email client
# (or `cat`) to grab the link.

dx serve
```

## What's in the example

- `src/main.rs` — `Home`, `ProfileCard`, `VerificationPending`,
  `AccountSettingsPage`, `AdminPage`, plus the `get_permissions`
  server fn.
- `assets/dx-components-theme.css` — the catalog's theme (dark
  variables; the example forces dark via `app.css`).
- `assets/app.css` — page layout + dark-theme override + a couple of
  example-only classes (`.app-shell`, `.profile-card`).
- Schema migrations are applied via `arium_dioxus::migrator().run(&pool)`
  at startup — the example owns no `.sql` files of its own.
