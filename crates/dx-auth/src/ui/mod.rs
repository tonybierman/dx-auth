//! UI components — currently just the [`LoginPanel`].
//!
//! The catalog components ([`components::button::Button`] etc.) are
//! re-exported in case consumers want to compose their own panels.

pub mod components;
pub mod login_panel;

pub mod account;
pub mod admin;

pub use account::AccountSettings;
pub use admin::{AdminUserDetail, AdminUserList, AuditLog};
pub use login_panel::{LoginPanel, LoginProvider, LoginSubmit, SubmitKind};
