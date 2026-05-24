//! Shared OAuth provider list, fetched once at the app root and shared with
//! descendants via context. Hoisting the fetch here (rather than inside the
//! login route) means it survives the login surface mounting/unmounting across
//! sign-in / sign-out cycles. Drop it near the top of your app alongside
//! [`crate::ui::permissions::PermissionsProvider`], then read the list with
//! [`use_oauth_providers`].

use leptos::prelude::*;

use crate::server::available_providers;
use crate::ui::login_panel::LoginProvider;

#[derive(Clone, Copy)]
struct OAuthProvidersCtx {
    providers: RwSignal<Vec<LoginProvider>>,
}

/// Fetches the OAuth provider list once at the app root and shares it via
/// context.
#[component]
pub fn OAuthProvidersProvider(children: ChildrenFn) -> impl IntoView {
    let providers = RwSignal::new(Vec::<LoginProvider>::new());
    let res = Resource::new(|| (), |_| async move { available_providers().await });
    Effect::new(move |_| {
        if let Some(Ok(list)) = res.get() {
            providers.set(list.into_iter().map(LoginProvider::from).collect());
        }
    });
    provide_context(OAuthProvidersCtx { providers });
    view! { {children()} }
}

/// Read the OAuth provider list shared by [`OAuthProvidersProvider`] as a
/// reactive signal. Returns an empty list if no provider wrapper is in scope
/// or the fetch hasn't resolved yet.
pub fn use_oauth_providers() -> Signal<Vec<LoginProvider>> {
    match use_context::<OAuthProvidersCtx>() {
        Some(ctx) => ctx.providers.into(),
        None => Signal::derive(Vec::new),
    }
}
