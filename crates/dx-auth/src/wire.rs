//! Types that cross the client/server boundary. Kept feature-flag-free so
//! they compile on both targets without bringing in any server-only deps.

use serde::{Deserialize, Serialize};

/// Result of a sign-in or sign-up attempt.
///
/// `EmailUnverified` and `MfaRequired` are *not* errors: they're successful
/// auth states that need an additional step before the user is fully signed
/// in (open the verification email; submit a TOTP code).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoginOutcome {
    LoggedIn,
    EmailUnverified,
    MfaRequired,
}

/// Third-party identity providers the server knows how to handle. Each
/// entry returned by the `available_providers` server fn gets mapped to a
/// `LoginProvider` button on the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProviderId {
    Github,
}

/// Profile fields safe to expose to the client.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct UserProfile {
    pub is_authenticated: bool,
    pub username: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub avatar_url: Option<String>,
    pub html_url: Option<String>,
}

/// Setup payload returned to the client when starting MFA enrollment.
/// `recovery_codes` is the only time these appear in plaintext anywhere —
/// the server only persists Argon2 hashes.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MfaSetupView {
    pub secret_base32: String,
    pub qr_png_base64: String,
    pub recovery_codes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum MfaStatusView {
    #[default]
    Disabled,
    /// Secret stored but the user hasn't confirmed enrollment with a TOTP yet.
    Pending,
    Enabled,
}

// ---- Admin / role wire types ----

/// One row in the admin user-list response. Lightweight enough to render
/// hundreds at a time.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AdminUserSummary {
    pub id: i64,
    pub username: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub email_verified: bool,
    pub mfa_enabled: bool,
    pub anonymous: bool,
    pub deleted: bool,
    pub role_ids: Vec<i64>,
}

/// Full admin view of a single user, returned by the detail endpoint.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AdminUserDetail {
    pub summary: AdminUserSummary,
    /// Display name pulled from the OAuth provider (separate from
    /// `summary.display_name`, which is user-chosen).
    pub name: Option<String>,
    pub avatar_url: Option<String>,
    pub html_url: Option<String>,
    /// All permission tokens this user resolves to (direct + role-inherited).
    pub permissions: Vec<String>,
}

/// A role + its permission tokens, used by the admin role browser.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AdminRoleDetail {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub is_system: bool,
    pub permissions: Vec<String>,
}

// ---- Audit log wire types (Phase 12) ----

/// One row from the audit log. `details` is whatever JSON the emitter
/// chose to attach (e.g. `{"method":"password","remember_me":true}`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AuditEventView {
    pub id: i64,
    pub occurred_at: i64,
    /// Human-readable rendering of `occurred_at`, formatted server-side
    /// so the client doesn't need a date library.
    pub occurred_at_iso: String,
    pub event_type: String,
    pub actor_id: Option<i64>,
    pub actor_email: Option<String>,
    pub target_id: Option<i64>,
    pub target_email: Option<String>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub details: Option<String>,
}

/// Filter set the admin audit viewer sends to `admin_query_audit_events`.
/// All fields are optional; defaults return the most-recent events across
/// all users.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AuditQuery {
    /// Match `event_type` exactly or as a `prefix.` if it ends with `.`.
    /// Empty string means "all".
    pub event_type: String,
    pub actor_id: Option<i64>,
    pub target_id: Option<i64>,
    /// Inclusive lower bound (unix seconds). `None` = no lower bound.
    pub since: Option<i64>,
    /// Inclusive upper bound (unix seconds). `None` = no upper bound.
    pub until: Option<i64>,
    pub limit: i64,
    pub offset: i64,
}

/// The current user's full account view (used by the AccountSettings UI).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AccountView {
    pub username: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub email_verified: bool,
    pub mfa_enabled: bool,
    pub has_password: bool,
    pub linked_oauth_providers: Vec<String>,
}
