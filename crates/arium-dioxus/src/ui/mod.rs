//! UI components.
//!
//! The catalog components ([`components::button::Button`] etc.) are
//! re-exported in case consumers want to compose their own panels.
//!
//! Drop-in auth flows ship as standalone components that wrap the relevant
//! server fns: [`LoginPanel`] for sign-in/sign-up, [`ForgotPassword`] /
//! [`ResetPassword`] / [`VerifyEmail`] for the email-driven side routes,
//! and [`RequireAuth`] / [`RequirePermission`] for route-level guards.

/// Small catalog of styled UI primitives (Button, Input, Card, ...) used
/// internally by the auth panels and re-exported for app reuse.
pub mod components;
/// Combined sign-in + sign-up panel.
pub mod login_panel;

/// User-facing "Account settings" page.
pub mod account;
/// Administrator pages (user list, role editor, audit log).
pub mod admin;
/// Bundle of `<link rel="stylesheet">` tags for the auth CSS modules.
pub mod auth_stylesheets;
/// "Forgot your password?" form that requests a reset email.
#[cfg(feature = "mail")]
pub mod forgot_password;
/// MFA enrollment + TOTP challenge screens.
#[cfg(feature = "mfa")]
pub mod mfa;
/// Context provider that fetches the list of OAuth providers once.
pub mod oauth_providers;
/// Passkey (WebAuthn) enrollment + sign-in screens and the browser bridge.
#[cfg(feature = "webauthn")]
pub mod passkeys;
/// Permission set context provider and route-level permission guards.
pub mod permissions;
/// Route-level guard that bounces unauthenticated visitors.
pub mod require_auth;
/// Password-reset form consumed from the link in the reset email.
#[cfg(feature = "mail")]
pub mod reset_password;
/// API-token management UI (create / list / revoke).
#[cfg(feature = "tokens")]
pub mod tokens;
/// Verify-email landing page consumed from the link in the verification email.
pub mod verify_email;

pub use account::AccountSettings;
pub use admin::{AdminRoleEditor, AdminRoleList, AdminUserDetail, AdminUserList, AuditLog};
pub use auth_stylesheets::AuthStylesheets;
#[cfg(feature = "mail")]
pub use forgot_password::ForgotPassword;
pub use login_panel::{LoginPanel, LoginProvider, LoginSubmit, SubmitKind};
#[cfg(feature = "mfa")]
pub use mfa::{MfaChallenge, MfaSetup};
pub use oauth_providers::{OAuthProvidersProvider, use_oauth_providers};
pub use permissions::{
    PermissionGate, PermissionSet, PermissionsProvider, Policy, RequirePermission, UsePermissions,
    use_permissions,
};
pub use require_auth::RequireAuth;
#[cfg(feature = "mail")]
pub use reset_password::ResetPassword;
#[cfg(feature = "tokens")]
pub use tokens::ApiTokens;
pub use verify_email::VerifyEmail;
