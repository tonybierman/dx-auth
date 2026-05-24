//! Example consumer of `arium-leptos` — a Leptos fullstack app.
//!
//! The auth primitives (server fns, UI screens, RBAC guards) all live in the
//! library; this crate owns only the app shell, routes, and the example pages.

pub mod app;

use leptos::prelude::*;

/// The SSR HTML shell. Leptos renders `<App/>` into the body and injects the
/// hydration scripts that boot the wasm client.
pub fn shell(options: LeptosOptions) -> impl IntoView {
    use leptos_meta::MetaTags;
    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1" />
                <AutoReload options=options.clone() />
                <HydrationScripts options=options.clone() />
                <MetaTags />
            </head>
            <body>
                <app::App />
            </body>
        </html>
    }
}

/// Wasm entrypoint: hydrate the server-rendered `<App/>` on the client.
#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    console_error_panic_hook::set_once();
    leptos::mount::hydrate_body(app::App);
}
