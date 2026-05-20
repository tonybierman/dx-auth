//! Shared OAuth provider list, established once at the app root.
//!
//! [`LoginPanel`](super::LoginPanel) takes a `providers: Vec<LoginProvider>`
//! prop. Building that list with `use_resource(available_providers)` inside
//! a route component is fine for a one-screen app, but it has a sharp edge
//! whenever the login surface comes in and out of the tree:
//!
//! - In a single-route app where one component (e.g. `Home`) renders either
//!   a dashboard or a `LoginPanel` based on auth state, the `LoginPanel`
//!   unmounts and remounts on every login/logout cycle. The route
//!   component's `use_resource` stays cached across those transitions in
//!   theory, but the LoginPanel sees the resource's value before the next
//!   tick — often as the empty default, so the provider buttons don't
//!   render.
//! - In a multi-route app where `LoginPanel` lives behind a `/login` route,
//!   navigating away unmounts the resource entirely. Coming back fires a
//!   fresh fetch on every visit.
//!
//! Hoisting the resource to the app root via [`OAuthProvidersProvider`]
//! fixes both. The resource is established once at app mount, lives for
//! the entire session, and any number of components can read the cached
//! provider list with [`use_oauth_providers`].
//!
//! Drop the provider near the top of your app, alongside
//! [`PermissionsProvider`](super::PermissionsProvider):
//!
//! ```rust,ignore
//! rsx! {
//!     PermissionsProvider {
//!         OAuthProvidersProvider {
//!             Router::<Route> {}
//!         }
//!     }
//! }
//! ```
//!
//! Then anywhere downstream:
//!
//! ```rust,ignore
//! let providers = use_oauth_providers();
//! rsx! { LoginPanel { providers, /* … */ } }
//! ```

use dioxus::prelude::*;

use crate::server::available_providers;
use crate::ui::login_panel::LoginProvider;

#[derive(Clone, Copy)]
struct OAuthProvidersCtx {
    providers: Signal<Vec<LoginProvider>>,
}

/// Fetches the OAuth provider list once at the app root and shares it
/// with descendants via context. See the [module docs](self) for the full
/// pattern.
///
/// Implementation note: uses `use_hook(|| spawn(...))` to fire the fetch
/// exactly once on mount and write the result to a `Signal`. We avoided
/// `use_resource` + `use_memo` here because that composition had the
/// LoginPanel `if !providers.is_empty()` branch stay collapsed on the
/// client after hydration in some configurations — the Memo would
/// recompute when the resource resolved, but the subscriber re-render
/// didn't always fire reliably for descendants reading through context.
/// A bare `Signal` with a manual spawn is one less layer of indirection
/// and renders the provider buttons every time.
#[component]
pub fn OAuthProvidersProvider(children: Element) -> Element {
    let mut providers = use_signal(Vec::<LoginProvider>::new);

    use_hook(|| {
        spawn(async move {
            if let Ok(list) = available_providers().await {
                let mapped: Vec<LoginProvider> =
                    list.into_iter().map(LoginProvider::from).collect();
                providers.set(mapped);
            }
        });
    });

    use_context_provider(|| OAuthProvidersCtx { providers });
    rsx! { {children} }
}

/// Read the OAuth provider list shared by [`OAuthProvidersProvider`].
///
/// Returns an empty `Vec` if no provider wrapper is in scope, or if the
/// fetch hasn't resolved yet. Calling this hook outside a component
/// scope panics.
pub fn use_oauth_providers() -> Vec<LoginProvider> {
    try_consume_context::<OAuthProvidersCtx>()
        .map(|ctx| ctx.providers.read().clone())
        .unwrap_or_default()
}
