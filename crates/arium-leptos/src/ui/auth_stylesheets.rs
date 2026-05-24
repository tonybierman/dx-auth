//! Injects all catalog + auth-screen CSS (and the default theme) as a single
//! `<style>` block.
//!
//! The Dioxus adapter emitted a `document::Stylesheet` link per css-module and
//! fought a remount/`OnceLock` race to keep them in `<head>`. Leptos has no
//! css-module hashing and no such race: the CSS is `include_str!`-bundled into
//! the binary and emitted once here (mounted for the whole session by
//! [`crate::ui::permissions::PermissionsProvider`]). Inline `<style>` applies globally, on both
//! the SSR and hydrate render, and the markup is identical on both sides so it
//! hydrates cleanly.

use leptos::prelude::*;

/// Concatenate every stylesheet the library ships into one CSS string. The
/// theme tokens come first so an app's own later-loaded CSS can override them.
fn bundle() -> String {
    let mut s = String::new();
    s.push_str(crate::DEFAULT_THEME_CSS);

    // Catalog widgets.
    s.push_str(include_str!("components/card/dx-card.css"));
    s.push_str(include_str!("components/button/dx-button.css"));
    s.push_str(include_str!("components/input/dx-input.css"));
    s.push_str(include_str!("components/label/dx-label.css"));
    s.push_str(include_str!("components/checkbox/dx-checkbox.css"));
    s.push_str(include_str!("components/separator/dx-separator.css"));
    s.push_str(include_str!("components/tabs/dx-tabs.css"));
    s.push_str(include_str!("components/select/dx-select.css"));
    s.push_str(include_str!("components/alert_dialog/dx-alert-dialog.css"));
    s.push_str(include_str!("components/pagination/dx-pagination.css"));
    s.push_str(include_str!("components/badge/dx-badge.css"));
    s.push_str(include_str!("components/avatar/dx-avatar.css"));
    s.push_str(include_str!("components/skeleton/dx-skeleton.css"));

    // Auth screens.
    s.push_str(include_str!("login_panel/style.css"));
    s.push_str(include_str!("verify_email/style.css"));
    s.push_str(include_str!("admin/style.css"));

    #[cfg(feature = "mail")]
    {
        s.push_str(include_str!("forgot_password/style.css"));
        s.push_str(include_str!("reset_password/style.css"));
    }
    #[cfg(feature = "mfa")]
    {
        s.push_str(include_str!("mfa/style.css"));
    }
    #[cfg(feature = "tokens")]
    {
        s.push_str(include_str!("tokens/style.css"));
    }

    s
}

/// Emits a single `<style>` block with the full catalog + auth CSS. Rendered by
/// [`crate::ui::permissions::PermissionsProvider`], so consumers don't normally call it directly
/// — but it's `pub` for apps that embed the auth UI without the RBAC plumbing.
#[component]
pub fn AuthStylesheets() -> impl IntoView {
    view! { <style inner_html=bundle()></style> }
}
