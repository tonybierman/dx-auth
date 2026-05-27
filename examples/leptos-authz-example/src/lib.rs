//! Leptos parallel of `dioxus-authz-example` — the smallest faithful demo of
//! arium's per-resource membership authorization. The membership pieces all
//! live in [`app`]; this file is just the SSR shell + the wasm hydrate
//! entrypoint.

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
