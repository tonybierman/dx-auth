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
    /// Credentials accepted and the session is fully authenticated.
    LoggedIn,
    /// Credentials accepted but the email address still needs to be verified.
    EmailUnverified,
    /// Credentials accepted; the user must submit a TOTP code to finish.
    MfaRequired,
}

/// One third-party identity provider the server has credentials for and is
/// willing to mount routes for. Returned by `available_providers` so the
/// client can render a button per entry without needing to know which
/// provider features were compiled in.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderInfo {
    /// Machine name (e.g. `"github"`). Matches the route segment in
    /// `login_url` and the `provider` column in `oauth_accounts`.
    pub name: String,
    /// Human-readable label for the sign-in button (e.g. `"GitHub"`).
    pub display_name: String,
    /// Full path the client should navigate to in order to start the
    /// OAuth dance (e.g. `"/auth/github/login"`).
    pub login_url: String,
    /// Optional inline SVG for the button icon. `None` when the provider
    /// implementation doesn't supply one.
    pub icon_svg: Option<String>,
}

/// Profile fields safe to expose to the client.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct UserProfile {
    /// `false` for the anonymous Guest user, `true` once a real account is
    /// attached to the session.
    pub is_authenticated: bool,
    /// Local username (email for password accounts, provider handle for OAuth).
    pub username: String,
    /// Optional human-readable display name.
    pub name: Option<String>,
    /// Email on file, if any.
    pub email: Option<String>,
    /// Avatar URL pulled from the OAuth provider, when available.
    pub avatar_url: Option<String>,
    /// Public profile URL on the OAuth provider, when available.
    pub html_url: Option<String>,
    /// All permission tokens this user resolves to (direct + role-inherited).
    /// Empty for anonymous users. UI uses this to gate admin-only views.
    pub permissions: Vec<String>,
}

impl UserProfile {
    /// Returns `true` if `token` is one of the permissions on this profile.
    pub fn has_permission(&self, token: &str) -> bool {
        self.permissions.iter().any(|p| p == token)
    }
}

/// Setup payload returned to the client when starting MFA enrollment.
/// `recovery_codes` is the only time these appear in plaintext anywhere —
/// the server only persists Argon2 hashes.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MfaSetupView {
    /// TOTP secret, base32-encoded — pair with the QR for authenticator apps
    /// that prefer manual entry.
    pub secret_base32: String,
    /// QR code PNG (base64) that encodes the `otpauth://` URI.
    pub qr_png_base64: String,
    /// One-time recovery codes. Shown to the user once and never recoverable
    /// from the server; only Argon2 hashes are persisted.
    pub recovery_codes: Vec<String>,
}

/// Whether the current user has MFA enabled, pending, or off entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum MfaStatusView {
    /// MFA is not configured.
    #[default]
    Disabled,
    /// Secret stored but the user hasn't confirmed enrollment with a TOTP yet.
    Pending,
    /// MFA is required at every sign-in.
    Enabled,
}

// ---- API token wire types ----

/// One row in the user's API-token list. The full secret is NEVER returned
/// after creation — only `prefix` (`"dxsk_abcd"`) so the UI can disambiguate
/// tokens by sight.
///
/// Date fields are pre-formatted on the server (mirrors
/// [`AuditEventView::occurred_at_iso`]) so the wasm client doesn't need a
/// date library.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiTokenView {
    /// Database row id; stable for the lifetime of the token.
    pub id: i64,
    /// User-supplied label (e.g. `"CI build"`).
    pub name: String,
    /// Public-facing prefix of the secret (e.g. `"dxsk_abcd"`). Safe to log.
    pub prefix: String,
    /// ISO 8601 timestamp the token was created.
    pub created_at_iso: String,
    /// ISO 8601 timestamp of the most recent successful use, or `None` if
    /// the token has never authenticated a request.
    pub last_used_at_iso: Option<String>,
}

/// Response from `create_api_token`. `token` is the cleartext secret —
/// shown to the user ONCE and never recoverable from the server.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateApiTokenResponse {
    /// Full cleartext token. Hand it to the caller; do not log or store.
    pub token: String,
    /// Metadata view for the newly-created token (id, prefix, timestamps).
    pub view: ApiTokenView,
}

// ---- Admin / role wire types ----

/// One row in the admin user-list response. Lightweight enough to render
/// hundreds at a time.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AdminUserSummary {
    /// Database row id.
    pub id: i64,
    /// Local username (email for password accounts, provider handle otherwise).
    pub username: String,
    /// User-chosen display name.
    pub display_name: Option<String>,
    /// Email on file, if any.
    pub email: Option<String>,
    /// `true` once `verify_email` has been completed for `email`.
    pub email_verified: bool,
    /// `true` if the user has a confirmed TOTP enrollment.
    pub mfa_enabled: bool,
    /// `true` for the built-in Guest row; users can't sign in to it.
    pub anonymous: bool,
    /// `true` if the account has been soft-deleted (login disabled).
    pub deleted: bool,
    /// Roles attached to this user. Resolve via [`AdminRoleDetail`] for names.
    pub role_ids: Vec<i64>,
}

/// Full admin view of a single user, returned by the detail endpoint.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AdminUserDetail {
    /// List-view fields (id, username, flags, role ids).
    pub summary: AdminUserSummary,
    /// Display name pulled from the OAuth provider (separate from
    /// `summary.display_name`, which is user-chosen).
    pub name: Option<String>,
    /// Avatar URL pulled from the OAuth provider, when available.
    pub avatar_url: Option<String>,
    /// Public profile URL on the OAuth provider, when available.
    pub html_url: Option<String>,
    /// All permission tokens this user resolves to (direct + role-inherited).
    pub permissions: Vec<String>,
}

/// A role + its permission tokens, used by the admin role browser.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AdminRoleDetail {
    /// Database row id.
    pub id: i64,
    /// Role name (e.g. `"admin"`, `"editor"`). Unique.
    pub name: String,
    /// Optional human-readable description.
    pub description: Option<String>,
    /// `true` for roles seeded by arium (e.g. `admin`); these can't be
    /// renamed or deleted from the admin UI.
    pub is_system: bool,
    /// Permission tokens granted by this role.
    pub permissions: Vec<String>,
}

// ---- Audit log wire types (Phase 12) ----

/// One row from the audit log. `details` is whatever JSON the emitter
/// chose to attach (e.g. `{"method":"password","remember_me":true}`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AuditEventView {
    /// Database row id.
    pub id: i64,
    /// Event time as unix seconds.
    pub occurred_at: i64,
    /// Human-readable rendering of `occurred_at`, formatted server-side
    /// so the client doesn't need a date library.
    pub occurred_at_iso: String,
    /// Dotted event type, e.g. `"login.success"` or `"admin.user.update"`.
    pub event_type: String,
    /// User id of the actor that triggered the event (`None` for system-driven
    /// events).
    pub actor_id: Option<i64>,
    /// Actor's email at the time of the event, denormalized for the viewer.
    pub actor_email: Option<String>,
    /// User id the event acted on, when distinct from the actor.
    pub target_id: Option<i64>,
    /// Target's email at the time of the event, denormalized for the viewer.
    pub target_email: Option<String>,
    /// Source IP recorded at the time, when available.
    pub ip: Option<String>,
    /// User-Agent header recorded at the time, when available.
    pub user_agent: Option<String>,
    /// Free-form JSON blob attached by the emitter (e.g.
    /// `{"method":"password","remember_me":true}`).
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
    /// Restrict to events where the actor is this user, when set.
    pub actor_id: Option<i64>,
    /// Restrict to events where the target is this user, when set.
    pub target_id: Option<i64>,
    /// Inclusive lower bound (unix seconds). `None` = no lower bound.
    pub since: Option<i64>,
    /// Inclusive upper bound (unix seconds). `None` = no upper bound.
    pub until: Option<i64>,
    /// Page size; the server clamps this to a sane maximum.
    pub limit: i64,
    /// Page offset (rows skipped before `limit` is applied).
    pub offset: i64,
}

/// The current user's full account view (used by the AccountSettings UI).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AccountView {
    /// Local username (email for password accounts, provider handle otherwise).
    pub username: String,
    /// User-chosen display name.
    pub display_name: Option<String>,
    /// Email on file, if any.
    pub email: Option<String>,
    /// `true` once the verification flow has completed for `email`.
    pub email_verified: bool,
    /// `true` if the user has a confirmed TOTP enrollment.
    pub mfa_enabled: bool,
    /// `true` if a password is set (OAuth-only accounts may have no password).
    pub has_password: bool,
    /// Provider names (`"github"`, ...) currently linked to this account.
    pub linked_oauth_providers: Vec<String>,
}
