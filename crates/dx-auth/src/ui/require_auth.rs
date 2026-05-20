use dioxus::prelude::*;

use crate::ui::permissions::use_permissions;

/// Route-level guard that admits any authenticated user.
///
/// Use this when you only need "the user is signed in." For role / scope
/// checks, use [`super::RequirePermission`].
///
/// The guard offers two shapes — pick whichever fits the surrounding
/// UX. Both are supported simultaneously; if `fallback` is supplied it
/// takes precedence over the redirect.
///
/// **Redirect** (matches `RequirePermission`): pass `redirect_to`. The
/// guard renders nothing while the profile is loading or denied, and
/// schedules `Navigator::replace(redirect_to)` once denial is confirmed.
///
/// ```rust,ignore
/// RequireAuth { redirect_to: "/login".to_string(),
///     Dashboard {}
/// }
/// ```
///
/// **Inline fallback**: pass `fallback` (e.g. an inline `Login` panel).
/// The guard renders `fallback` for every non-authed state — loading and
/// denied alike — so there's no flash-of-blank and no dependence on a
/// `use_effect` firing post-hydration (which has been observed to be
/// flaky on some routes — see INTEGRATION.md gotcha 2.5).
///
/// ```rust,ignore
/// RequireAuth { fallback: rsx! { Login {} },
///     Dashboard {}
/// }
/// ```
#[component]
pub fn RequireAuth(
    redirect_to: Option<String>,
    fallback: Option<Element>,
    children: Element,
) -> Element {
    let perms = use_permissions();
    let loading = perms.is_loading();
    let authed = !loading && perms.is_authenticated();
    let denied = !loading && !authed;

    // If no inline fallback is supplied, fall back to redirect-on-deny.
    if fallback.is_none()
        && let Some(target) = redirect_to.clone()
    {
        use_effect(move || {
            if denied {
                navigator().replace(target.clone());
            }
        });
    }

    if authed {
        rsx! { {children} }
    } else if let Some(f) = fallback {
        rsx! { {f} }
    } else {
        rsx! {}
    }
}
