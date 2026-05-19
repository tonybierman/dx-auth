Out of scope for this change: persistent DB, refresh tokens, additional providers, account linking UI, email/password fallback.

To run

  cd /home/tony/src/dx-auth/auth
  GITHUB_CLIENT_ID=... GITHUB_CLIENT_SECRET=... dx serve

  Register a GitHub OAuth App at https://github.com/settings/developers with callback
  http://localhost:8080/auth/github/callback (override via GITHUB_REDIRECT_URL).

  For local development, use http://localhost:8080 as the Homepage URL.

  That matches the host/port the Dioxus fullstack dev server (and your GITHUB_REDIRECT_URL) is using.
  GitHub doesn't enforce the homepage value at OAuth-time — only the Authorization callback URL has to
  match exactly — so the homepage is mostly cosmetic. You can update it later when you have a real
  deployed URL.


GITHUB_CLIENT_ID=... GITHUB_CLIENT_SECRET=... dx serve