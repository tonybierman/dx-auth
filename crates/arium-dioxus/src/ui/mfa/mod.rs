//! Drop-in TOTP MFA UI.
//!
//! Two components, both gated on `feature = "mfa"`:
//!
//! - [`MfaChallenge`] — the post-password 6-digit prompt shown when
//!   [`crate::server::login_with_password`] returns
//!   [`LoginOutcome::MfaRequired`](crate::wire::LoginOutcome::MfaRequired).
//!   Calls [`crate::server::verify_login_mfa`] and reports back via
//!   `on_logged_in` / `on_cancel`.
//!
//! - [`MfaSetup`] — the `/account/mfa` enrollment + management screen.
//!   Drives [`crate::server::get_mfa_status`],
//!   [`crate::server::begin_mfa_setup`],
//!   [`crate::server::confirm_mfa_setup`], and
//!   [`crate::server::disable_mfa_for_user`].

mod challenge;
mod setup;

pub use challenge::MfaChallenge;
pub use setup::MfaSetup;
