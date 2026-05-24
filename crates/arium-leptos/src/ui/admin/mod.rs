//! Admin UI components. Consumers mount these under routes they own
//! (typically `/admin/users`, `/admin/users/:id`, `/admin/roles`). Each talks
//! to the matching `admin:*` server fn and re-renders on success.

mod admin_screens;
mod audit_log;
mod role_screens;
pub use admin_screens::{AdminUserDetail, AdminUserList};
pub use audit_log::AuditLog;
pub use role_screens::{AdminRoleEditor, AdminRoleList};
