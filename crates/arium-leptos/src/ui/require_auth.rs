use leptos::prelude::*;
use leptos_router::NavigateOptions;
use leptos_router::hooks::use_navigate;

use crate::ui::permissions::use_permissions;

/// Route-level guard that admits any authenticated user. For role / scope
/// checks, use [`super::RequirePermission`].
///
/// Pass `redirect_to` to bounce unauthenticated visitors (renders nothing
/// while loading/denied, then navigates), or `fallback` to render an inline
/// view (e.g. a `LoginPanel`) for every non-authed state. If `fallback` is
/// supplied it takes precedence over the redirect.
#[component]
pub fn RequireAuth(
    #[prop(optional, into)] redirect_to: Option<String>,
    #[prop(optional)] fallback: Option<ViewFn>,
    children: ChildrenFn,
) -> impl IntoView {
    let perms = use_permissions();

    // If no inline fallback is supplied, fall back to redirect-on-deny.
    if fallback.is_none()
        && let Some(target) = redirect_to.clone()
    {
        Effect::new(move |_| {
            if !perms.is_loading() && !perms.is_authenticated() {
                use_navigate()(
                    &target,
                    NavigateOptions {
                        replace: true,
                        ..Default::default()
                    },
                );
            }
        });
    }

    let authed = move || !perms.is_loading() && perms.is_authenticated();
    let fb = fallback.unwrap_or_default();
    view! { <Show when=authed fallback=fb.clone()>{children()}</Show> }
}
