//! Reactive RBAC primitives for client-side UI gating.
//!
//! Apps wrap their router in [`PermissionsProvider`] once; descendants then
//! call [`use_permissions`] or drop in [`PermissionGate`] /
//! [`RequirePermission`] without each component refetching the profile.
//!
//! ## Scopes (deprecated)
//!
//! [`Policy::scoped`] composes a `"<scope>:<token>"` string and matches it
//! against the same client-side token snapshot — it is **never enforced on the
//! server**, so it gates UI without guarding anything behind it. It is
//! deprecated. For real per-resource authorization (e.g. a user's role on
//! board 42), use [`ResourceGate`](super::resource_gate::ResourceGate) for the
//! UI and `require_resource_leptos` on the mutation server fn — the actual
//! security boundary. See the engine's `arium::authz` module.
//!
//! ## Live invalidation
//!
//! [`UsePermissions::refresh`] re-fetches the profile. Call it after any
//! action that mutates the current user's grants.

use std::collections::HashSet;
use std::sync::Arc;

use leptos::prelude::*;
use leptos_router::NavigateOptions;
use leptos_router::hooks::use_navigate;

use crate::server::get_current_user_profile;
use crate::wire::UserProfile;

/// Snapshot of the current user's permission tokens.
#[derive(Clone, Default, PartialEq)]
pub struct PermissionSet {
    tokens: Arc<HashSet<String>>,
    is_authenticated: bool,
}

impl PermissionSet {
    /// `true` if `token` is one of the user's permissions.
    pub fn has(&self, token: &str) -> bool {
        self.tokens.contains(token)
    }

    /// `true` if the user has at least one of `tokens`.
    pub fn any_of<S: AsRef<str>>(&self, tokens: impl IntoIterator<Item = S>) -> bool {
        tokens.into_iter().any(|t| self.has(t.as_ref()))
    }

    /// `true` if the user has every token in `tokens`.
    pub fn all_of<S: AsRef<str>>(&self, tokens: impl IntoIterator<Item = S>) -> bool {
        tokens.into_iter().all(|t| self.has(t.as_ref()))
    }

    /// `true` if the underlying profile is authenticated (not the Guest row).
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
    profile: LocalResource<Result<UserProfile, ServerFnError>>,
    refetch: RwSignal<u32>,
    set: Memo<PermissionSet>,
    phase: Memo<Phase>,
}

/// Establishes a single shared profile resource for descendants. Place it once
/// near the top of your app (e.g. wrapping the `<Router>`). Also mounts
/// [`super::AuthStylesheets`] so the catalog/auth CSS is present for the whole
/// session.
#[component]
pub fn PermissionsProvider(children: ChildrenFn) -> impl IntoView {
    // A `LocalResource` (client-only) rather than a server-streamed `Resource`:
    // the profile is read imperatively all over the tree (`use_permissions`),
    // i.e. outside any `<Suspense>`, which would risk hydration mismatches with
    // a server resource. `LocalResource` renders the same "loading" shape on the
    // server and the initial client pass, then resolves after hydration. The
    // `refetch` trigger drives `refresh()`.
    let refetch = RwSignal::new(0u32);
    let profile = LocalResource::new(move || {
        refetch.track();
        async move { get_current_user_profile().await }
    });

    let set = Memo::new(move |_| match profile.get() {
        Some(Ok(p)) => PermissionSet::from(&p),
        _ => PermissionSet::default(),
    });

    let phase = Memo::new(move |_| match profile.get() {
        None => Phase::Loading,
        Some(_) => Phase::Ready,
    });

    provide_context(PermissionsCtx {
        profile,
        refetch,
        set,
        phase,
    });

    view! {
        <super::AuthStylesheets />
        {children()}
    }
}

/// Handle returned by [`use_permissions`]. `Copy`, so it's cheap to capture in
/// event handlers.
#[derive(Clone, Copy)]
pub struct UsePermissions {
    ctx: PermissionsCtx,
}

impl UsePermissions {
    /// Cloneable snapshot of the current token set.
    pub fn set(&self) -> PermissionSet {
        self.ctx.set.get()
    }

    /// `true` if the current user has `token`.
    pub fn has(&self, token: &str) -> bool {
        self.ctx.set.read().has(token)
    }

    /// `true` if the current user has at least one of `tokens`.
    pub fn any_of<S: AsRef<str>>(&self, tokens: impl IntoIterator<Item = S>) -> bool {
        self.ctx.set.read().any_of(tokens)
    }

    /// `true` if the current user has every token in `tokens`.
    pub fn all_of<S: AsRef<str>>(&self, tokens: impl IntoIterator<Item = S>) -> bool {
        self.ctx.set.read().all_of(tokens)
    }

    /// `true` while the underlying profile resource is still loading.
    pub fn is_loading(&self) -> bool {
        self.ctx.phase.get() == Phase::Loading
    }

    /// `true` if the underlying profile is authenticated.
    pub fn is_authenticated(&self) -> bool {
        self.ctx.set.read().is_authenticated()
    }

    /// Evaluate a [`Policy`] against the current token snapshot.
    pub fn check(&self, policy: &Policy) -> bool {
        policy.evaluate(&self.ctx.set.read())
    }

    /// The underlying profile, if loaded successfully.
    pub fn profile(&self) -> Option<UserProfile> {
        self.ctx.profile.get().and_then(|r| r.ok())
    }

    /// Re-fetch the current user's profile. Call after any action that changes
    /// the current user's grants.
    pub fn refresh(&self) {
        self.ctx.refetch.update(|n| *n = n.wrapping_add(1));
    }
}

/// Read shared permission state. Panics if no [`PermissionsProvider`] is in
/// scope.
pub fn use_permissions() -> UsePermissions {
    let ctx = expect_context::<PermissionsCtx>();
    UsePermissions { ctx }
}

fn scoped(scope: Option<&str>, token: &str) -> String {
    match scope {
        Some(s) if !s.is_empty() => format!("{s}:{token}"),
        _ => token.to_string(),
    }
}

/// Reusable permission check. Define once, pass to one or more
/// [`PermissionGate`] / [`RequirePermission`] / [`UsePermissions::check`] call
/// sites so updates land in one place.
///
/// Semantics: if both `any_of` and `all_of` are populated, **both** clauses
/// must pass. An empty policy evaluates to `false`.
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

    /// Bind a scope prefix; every lookup becomes `"{scope}:{token}"`.
    ///
    /// **Deprecated.** Matched only against the client-side token snapshot and
    /// never enforced on the server, so it gates UI without guarding anything.
    /// Use [`ResourceGate`](super::resource_gate::ResourceGate) +
    /// `require_resource_leptos` for real per-resource authorization.
    #[deprecated(
        note = "client-only string prefix, never enforced server-side; use ResourceGate + require_resource (see arium::authz)"
    )]
    pub fn scoped(self, scope: impl Into<String>) -> Self {
        self.with_scope(scope)
    }

    /// Internal scope setter — identical to the (deprecated) public `scoped`,
    /// but not deprecated so internal callers (the `scope` prop via
    /// `policy_from_inline`) don't trip the warning.
    fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// Extend `all_of` with one more token.
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
        if !self.any_of.is_empty() && !self.any_of.iter().any(|t| set.has(&scoped(scope, t))) {
            return false;
        }
        if !self.all_of.is_empty() && !self.all_of.iter().all(|t| set.has(&scoped(scope, t))) {
            return false;
        }
        true
    }
}

/// Build a Policy from the gate's inline props. Exclusive ordering:
/// `token` > `any_of` > `all_of` (first non-empty wins).
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
        p = p.with_scope(s);
    }
    p
}

/// Render `children` only when the current user satisfies the check. Either
/// pass a reusable [`Policy`] via `policy`, or use the inline
/// `token` / `any_of` / `all_of` / `scope` props. If `policy` is set, the
/// inline props are ignored.
#[component]
pub fn PermissionGate(
    #[prop(optional)] policy: Option<Policy>,
    #[prop(optional)] token: Option<String>,
    #[prop(optional)] any_of: Vec<String>,
    #[prop(optional)] all_of: Vec<String>,
    #[prop(optional)] scope: Option<String>,
    #[prop(optional)] fallback: ViewFn,
    children: ChildrenFn,
) -> impl IntoView {
    let perms = use_permissions();
    let p = policy.unwrap_or_else(|| policy_from_inline(token, any_of, all_of, scope));
    let allowed = move || perms.check(&p);
    view! { <Show when=allowed fallback=fallback.clone()>{children()}</Show> }
}

/// Route-level guard. Renders nothing while loading, the children when allowed,
/// and otherwise navigates to `redirect_to` (via a replace, so the user can't
/// back into the protected page). Accepts a [`Policy`] or the same inline props
/// as [`PermissionGate`].
#[component]
pub fn RequirePermission(
    #[prop(optional)] policy: Option<Policy>,
    #[prop(optional)] token: Option<String>,
    #[prop(optional)] any_of: Vec<String>,
    #[prop(optional)] all_of: Vec<String>,
    #[prop(optional)] scope: Option<String>,
    #[prop(into)] redirect_to: String,
    children: ChildrenFn,
) -> impl IntoView {
    let perms = use_permissions();
    let p = policy.unwrap_or_else(|| policy_from_inline(token, any_of, all_of, scope));
    let p_effect = p.clone();
    let target = redirect_to.clone();

    Effect::new(move |_| {
        if !perms.is_loading() && !perms.check(&p_effect) {
            use_navigate()(
                &target,
                NavigateOptions {
                    replace: true,
                    ..Default::default()
                },
            );
        }
    });

    let allowed = move || !perms.is_loading() && perms.check(&p);
    view! { <Show when=allowed fallback=|| ()>{children()}</Show> }
}
