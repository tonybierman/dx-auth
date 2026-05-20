//! UI components.
//!
//! The catalog components ([`components::button::Button`] etc.) are
//! re-exported in case consumers want to compose their own panels.
//!
//! Drop-in auth flows ship as standalone components that wrap the relevant
//! server fns: [`LoginPanel`] for sign-in/sign-up, [`ForgotPassword`] /
//! [`ResetPassword`] / [`VerifyEmail`] for the email-driven side routes,
//! and [`RequireAuth`] / [`RequirePermission`] for route-level guards.

pub mod components;
pub mod login_panel;

pub mod account;
pub mod admin;
#[cfg(feature = "mail")]
pub mod forgot_password;
pub mod permissions;
pub mod require_auth;
#[cfg(feature = "mail")]
pub mod reset_password;
pub mod verify_email;

pub use account::AccountSettings;
pub use admin::{AdminRoleEditor, AdminRoleList, AdminUserDetail, AdminUserList, AuditLog};
#[cfg(feature = "mail")]
pub use forgot_password::ForgotPassword;
pub use login_panel::{LoginPanel, LoginProvider, LoginSubmit, SubmitKind};
pub use permissions::{
    use_permissions, PermissionGate, PermissionSet, PermissionsProvider, Policy,
    RequirePermission, UsePermissions,
};
pub use require_auth::RequireAuth;
#[cfg(feature = "mail")]
pub use reset_password::ResetPassword;
pub use verify_email::VerifyEmail;
