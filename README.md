# dx-auth

Reusable authentication library for [Dioxus 0.7](https://dioxuslabs.com)
fullstack apps. Provides:

- Email + password sign-in / sign-up with Argon2id hashing.
- "Continue with GitHub" OAuth (env-driven; the button hides itself when
  unconfigured).
- Account linking — signing in with GitHub when an email-matched local
  account already exists attaches the OAuth identity to it.
- Forgot-password reset and email-verification flows with a pluggable
  email backend (SMTP via lettre, or a dev fallback that writes `.eml`
  files locally).
- TOTP two-factor authentication with single-use recovery codes.
- Per-IP rate limiting on the entire router.
- "Remember me" long-lived sessions.
- A drop-in `LoginPanel` UI component built on the Dioxus components
  catalog.

See [USAGE.md](USAGE.md) for getting started, features, environment
variables, audit log, repo layout, and dev tips.
