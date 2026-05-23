//! Admin UI components. Consumers mount these under routes they own
//! (typically `/admin/users`, `/admin/users/:id`, `/admin/roles`).
//!
//! Each component talks to the matching server fn in [`crate::server`]
//! and re-renders on success. All endpoints require the matching
//! `admin:*` permission token — drop the components on a page that's
//! only reachable to admins (the components themselves render an error
//! message if the server rejects).

mod admin_screens;
mod audit_log;
mod role_screens;
pub use admin_screens::{AdminUserDetail, AdminUserList};
pub use audit_log::AuditLog;
pub use role_screens::{AdminRoleEditor, AdminRoleList};
