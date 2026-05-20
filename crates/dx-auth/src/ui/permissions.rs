//! Reactive RBAC primitives for client-side UI gating.
//!
//! Apps wrap their router in [`PermissionsProvider`] once; descendants then
//! call [`use_permissions`] or drop in [`PermissionGate`] /
//! [`RequirePermission`] without each component refetching the profile.
//!
//! ## Scopes
//!
//! Resource-scoped permissions follow the convention `"<scope>:<token>"`.
//! Pass `scope` on the gate so call sites stay readable — the gate
//! composes the final token as `"{scope}:{token}"` before lookup. Apps
//! decide what a scope means (a record id, a tenant id, etc.); the
//! library only treats it as an opaque prefix.
//!
//! ## Live invalidation
//!
//! [`UsePermissions::refresh`] re-fetches the profile. Call it after any
//! action that mutates the current user's grants. Cross-tab / server-push
//! invalidation is left to the app.

use std::collections::HashSet;
use std::sync::Arc;

use dioxus::prelude::*;
use dioxus::CapturedError;

use crate::server::get_current_user_profile;
use crate::wire::UserProfile;

/// Snapshot of the current user's permission tokens.
#[derive(Clone, Default, PartialEq)]
pub struct PermissionSet {
    tokens: Arc<HashSet<String>>,
    is_authenticated: bool,
}

impl PermissionSet {
    pub fn has(&self, token: &str) -> bool {
        self.tokens.contains(token)
    }

    pub fn any_of<S: AsRef<str>>(&self, tokens: impl IntoIterator<Item = S>) -> bool {
        tokens.into_iter().any(|t| self.has(t.as_ref()))
    }

    pub fn all_of<S: AsRef<str>>(&self, tokens: impl IntoIterator<Item = S>) -> bool {
        tokens.into_iter().all(|t| self.has(t.as_ref()))
    }

    pub fn is_authenticated(&self) -> bool {
        self.is_authenticated
    }
}

impl From<&UserProfile> for PermissionSet {
    fn from(p: &UserProfile) -> Self {
        Self {
            tokens: Arc::new(p.permissions.iter().cloned().collect()),
            is_authenticated: p.is_authenticated,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Loading,
    Ready,
}

#[derive(Clone, Copy)]
struct PermissionsCtx {
    profile: Resource<Result<UserProfile, CapturedError>>,
    set: Memo<PermissionSet>,
    phase: Memo<Phase>,
}

/// Establishes a single shared profile resource for descendants. Place it
/// once near the top of your app (e.g. wrapping `Router::<Route> {}`).
///
/// Also pins the catalog widget stylesheets used by the drop-in auth UI
/// ([`super::LoginPanel`], [`super::ForgotPassword`], etc.) to the document
/// head, so they survive component re-mount cycles (sign in → navigate
/// away → log out → re-mount). The catalog widgets emit their own
/// `document::Stylesheet` declarations too, but a component-local
/// emission disappears from `<head>` when the component unmounts; pinning
/// from the root provider keeps the links in place for the whole session.
#[component]
pub fn PermissionsProvider(children: Element) -> Element {
    let profile = use_resource(|| async { get_current_user_profile().await });

    let set = use_memo(move || match &*profile.read() {
        Some(Ok(p)) => PermissionSet::from(p),
        _ => PermissionSet::default(),
    });

    let phase = use_memo(move || match &*profile.read() {
        None => Phase::Loading,
        Some(_) => Phase::Ready,
    });

    use_context_provider(|| PermissionsCtx { profile, set, phase });

    rsx! {
        super::AuthStylesheets {}
        {children}
    }
}

/// Handle returned by [`use_permissions`]. `Copy`, so it's cheap to capture
/// in event handlers.
#[derive(Clone, Copy)]
pub struct UsePermissions {
    ctx: PermissionsCtx,
}

impl UsePermissions {
    /// Cloneable snapshot of the current token set.
    pub fn set(&self) -> PermissionSet {
        self.ctx.set.read().clone()
    }

    pub fn has(&self, token: &str) -> bool {
        self.ctx.set.read().has(token)
    }

    pub fn any_of<S: AsRef<str>>(&self, tokens: impl IntoIterator<Item = S>) -> bool {
        self.ctx.set.read().any_of(tokens)
    }

    pub fn all_of<S: AsRef<str>>(&self, tokens: impl IntoIterator<Item = S>) -> bool {
        self.ctx.set.read().all_of(tokens)
    }

    pub fn is_loading(&self) -> bool {
        *self.ctx.phase.read() == Phase::Loading
    }

    pub fn is_authenticated(&self) -> bool {
        self.ctx.set.read().is_authenticated()
    }

    /// Evaluate a [`Policy`] against the current token snapshot.
    pub fn check(&self, policy: &Policy) -> bool {
        policy.evaluate(&self.ctx.set.read())
    }

    /// The underlying profile, if loaded successfully. Useful for rendering
    /// account UI without re-issuing `get_current_user_profile`.
    pub fn profile(&self) -> Option<UserProfile> {
        self.ctx
            .profile
            .read()
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .cloned()
    }

    /// Re-fetch the current user's profile. Call after any action that
    /// changes the current user's grants.
    pub fn refresh(&self) {
        let mut r = self.ctx.profile;
        r.restart();
    }
}

/// Read shared permission state. Panics if no [`PermissionsProvider`] is
/// in scope.
pub fn use_permissions() -> UsePermissions {
    let ctx = use_context::<PermissionsCtx>();
    UsePermissions { ctx }
}

fn scoped(scope: Option<&str>, token: &str) -> String {
    match scope {
        Some(s) if !s.is_empty() => format!("{s}:{token}"),
        _ => token.to_string(),
    }
}

/// Reusable permission check. Define once (typically as a function returning
/// a `Policy` or via `LazyLock`), pass to one or more
/// [`PermissionGate`] / [`RequirePermission`] / [`UsePermissions::check`]
/// call sites so updates land in one place.
///
/// Semantics: if both `any_of` and `all_of` are populated, **both** clauses
/// must pass (intersection). An empty policy (no tokens) evaluates to
/// `false` — unsatisfiable policies do not silently admit everyone.
///
/// ```ignore
/// // Tiered, scoped policies for a kanban-style app:
/// fn board_viewer() -> Policy { Policy::token("read") }
/// fn board_editor() -> Policy { board_viewer().with("write") }
/// fn board_owner()  -> Policy { board_editor().with("admin") }
///
/// PermissionGate {
///     policy: board_editor().scoped(format!("board:{id}")),
///     EditToolbar {}
/// }
/// ```
#[derive(Clone, Default, PartialEq)]
pub struct Policy {
    any_of: Vec<String>,
    all_of: Vec<String>,
    scope: Option<String>,
}

impl Policy {
    /// Single-token policy. Equivalent to `any_of([token])`.
    pub fn token(token: impl Into<String>) -> Self {
        Self {
            any_of: vec![token.into()],
            ..Default::default()
        }
    }

    /// Pass when the user holds at least one of `tokens`.
    pub fn any_of<I, S>(tokens: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            any_of: tokens.into_iter().map(Into::into).collect(),
            ..Default::default()
        }
    }

    /// Pass only when the user holds every token in `tokens`.
    pub fn all_of<I, S>(tokens: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            all_of: tokens.into_iter().map(Into::into).collect(),
            ..Default::default()
        }
    }

    /// Bind a scope prefix; every lookup becomes `"{scope}:{token}"`. The
    /// library treats `scope` as an opaque prefix.
    pub fn scoped(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// Extend `all_of` with one more token. Useful for tier-building:
    /// `EDITOR = VIEWER.with("write")`.
    pub fn with(mut self, token: impl Into<String>) -> Self {
        self.all_of.push(token.into());
        self
    }

    /// Extend `all_of` with multiple tokens.
    pub fn with_all<I, S>(mut self, tokens: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.all_of.extend(tokens.into_iter().map(Into::into));
        self
    }

    /// Evaluate this policy against the user's token snapshot.
    pub fn evaluate(&self, set: &PermissionSet) -> bool {
        if self.any_of.is_empty() && self.all_of.is_empty() {
            return false;
        }
        let scope = self.scope.as_deref();
        if !self.any_of.is_empty()
            && !self.any_of.iter().any(|t| set.has(&scoped(scope, t)))
        {
            return false;
        }
        if !self.all_of.is_empty()
            && !self.all_of.iter().all(|t| set.has(&scoped(scope, t)))
        {
            return false;
        }
        true
    }
}

/// Build a Policy from the gate's inline props. Mirrors the legacy
/// exclusive ordering: `token` > `any_of` > `all_of` (first non-empty wins).
fn policy_from_inline(
    token: Option<String>,
    any_of: Vec<String>,
    all_of: Vec<String>,
    scope: Option<String>,
) -> Policy {
    let mut p = if let Some(t) = token {
        Policy::token(t)
    } else if !any_of.is_empty() {
        Policy::any_of(any_of)
    } else if !all_of.is_empty() {
        Policy::all_of(all_of)
    } else {
        Policy::default()
    };
    if let Some(s) = scope {
        p = p.scoped(s);
    }
    p
}

/// Render `children` only when the current user satisfies the check.
///
/// Either pass a reusable [`Policy`] via `policy:`, or use the inline
/// `token` / `any_of` / `all_of` / `scope` props for one-off checks. If
/// `policy` is set, the inline props are ignored.
#[component]
pub fn PermissionGate(
    policy: Option<Policy>,
    token: Option<String>,
    #[props(default)] any_of: Vec<String>,
    #[props(default)] all_of: Vec<String>,
    scope: Option<String>,
    fallback: Option<Element>,
    children: Element,
) -> Element {
    let perms = use_permissions();
    let p = policy.unwrap_or_else(|| policy_from_inline(token, any_of, all_of, scope));
    let allowed = perms.check(&p);
    if allowed {
        rsx! { {children} }
    } else if let Some(f) = fallback {
        rsx! { {f} }
    } else {
        rsx! {}
    }
}

/// Route-level guard. Renders nothing while the profile is loading, the
/// children when allowed, and otherwise navigates to `redirect_to` via
/// `Navigator::replace` (so the user can't back into the protected page).
///
/// Accepts a [`Policy`] or the same inline props as [`PermissionGate`].
#[component]
pub fn RequirePermission(
    policy: Option<Policy>,
    token: Option<String>,
    #[props(default)] any_of: Vec<String>,
    #[props(default)] all_of: Vec<String>,
    scope: Option<String>,
    redirect_to: String,
    children: Element,
) -> Element {
    let perms = use_permissions();
    let p = policy.unwrap_or_else(|| policy_from_inline(token, any_of, all_of, scope));
    let loading = perms.is_loading();
    let allowed = !loading && perms.check(&p);
    let denied = !loading && !allowed;

    let target = redirect_to.clone();
    use_effect(move || {
        if denied {
            navigator().replace(target.clone());
        }
    });

    if allowed {
        rsx! { {children} }
    } else {
        rsx! {}
    }
}
