//! Pin the auth UI catalog stylesheets to the document head.
//!
//! Every catalog widget under `crate::ui::components::*` already emits its
//! own `document::Stylesheet` declaration when it renders — which is fine
//! while the widget is mounted, but the link tag is removed from `<head>`
//! the moment the widget unmounts. That bites consumers who sign in,
//! navigate away from the login screen, and then log out: the catalog
//! widgets re-mount but the `#[css_module]` macro's process-wide `OnceLock`
//! has already fired this WASM process, and Dioxus's re-emit of the
//! `document::Stylesheet` declaration has been observed to silently no-op
//! on remount, leaving the login screen unstyled.
//!
//! `AuthStylesheets` declares the same `Asset`s a second time and emits
//! them from a component that's mounted by [`super::PermissionsProvider`]
//! for the whole session, so the link tags stay put. The `asset!()` macro
//! is content-addressed, so re-declaring the same path + options here
//! resolves to the same bundled URL the widgets themselves use — no
//! duplicate files in the bundle, just an idempotent second link tag in
//! `<head>` that the browser dedupes.

use dioxus::prelude::*;

const CARD_CSS: Asset = asset!(
    "/src/ui/components/card/dx-card.css",
    AssetOptions::css_module()
);
const BUTTON_CSS: Asset = asset!(
    "/src/ui/components/button/dx-button.css",
    AssetOptions::css_module()
);
const INPUT_CSS: Asset = asset!(
    "/src/ui/components/input/dx-input.css",
    AssetOptions::css_module()
);
const LABEL_CSS: Asset = asset!(
    "/src/ui/components/label/dx-label.css",
    AssetOptions::css_module()
);
const CHECKBOX_CSS: Asset = asset!(
    "/src/ui/components/checkbox/dx-checkbox.css",
    AssetOptions::css_module()
);
const SEPARATOR_CSS: Asset = asset!(
    "/src/ui/components/separator/dx-separator.css",
    AssetOptions::css_module()
);
const TABS_CSS: Asset = asset!(
    "/src/ui/components/tabs/dx-tabs.css",
    AssetOptions::css_module()
);
const SELECT_CSS: Asset = asset!(
    "/src/ui/components/select/dx-select.css",
    AssetOptions::css_module()
);
const ALERT_DIALOG_CSS: Asset = asset!(
    "/src/ui/components/alert_dialog/dx-alert-dialog.css",
    AssetOptions::css_module()
);
const PAGINATION_CSS: Asset = asset!(
    "/src/ui/components/pagination/dx-pagination.css",
    AssetOptions::css_module()
);
const BADGE_CSS: Asset = asset!(
    "/src/ui/components/badge/dx-badge.css",
    AssetOptions::css_module()
);
const AVATAR_CSS: Asset = asset!(
    "/src/ui/components/avatar/dx-avatar.css",
    AssetOptions::css_module()
);
const SKELETON_CSS: Asset = asset!(
    "/src/ui/components/skeleton/dx-skeleton.css",
    AssetOptions::css_module()
);
const VIRTUAL_LIST_CSS: Asset = asset!(
    "/src/ui/components/virtual_list/style.css",
    AssetOptions::css_module()
);
const LOGIN_PANEL_CSS: Asset = asset!(
    "/src/ui/login_panel/style.css",
    AssetOptions::css_module()
);
#[cfg(feature = "mail")]
const FORGOT_PASSWORD_CSS: Asset = asset!(
    "/src/ui/forgot_password/style.css",
    AssetOptions::css_module()
);
#[cfg(feature = "mail")]
const RESET_PASSWORD_CSS: Asset = asset!(
    "/src/ui/reset_password/style.css",
    AssetOptions::css_module()
);
const VERIFY_EMAIL_CSS: Asset = asset!(
    "/src/ui/verify_email/style.css",
    AssetOptions::css_module()
);

/// Emits `document::Stylesheet` link tags for every catalog widget and
/// drop-in auth route the library ships. Rendered by
/// [`super::PermissionsProvider`] so consumers don't need to call this
/// directly — but it's `pub` in case an app wants to mount the link tags
/// without using `PermissionsProvider` (e.g. a marketing landing page
/// that embeds `LoginPanel` without any of the RBAC plumbing).
#[component]
pub fn AuthStylesheets() -> Element {
    rsx! {
        document::Stylesheet { href: CARD_CSS }
        document::Stylesheet { href: BUTTON_CSS }
        document::Stylesheet { href: INPUT_CSS }
        document::Stylesheet { href: LABEL_CSS }
        document::Stylesheet { href: CHECKBOX_CSS }
        document::Stylesheet { href: SEPARATOR_CSS }
        document::Stylesheet { href: TABS_CSS }
        document::Stylesheet { href: SELECT_CSS }
        document::Stylesheet { href: ALERT_DIALOG_CSS }
        document::Stylesheet { href: PAGINATION_CSS }
        document::Stylesheet { href: BADGE_CSS }
        document::Stylesheet { href: AVATAR_CSS }
        document::Stylesheet { href: SKELETON_CSS }
        document::Stylesheet { href: VIRTUAL_LIST_CSS }
        document::Stylesheet { href: LOGIN_PANEL_CSS }
        document::Stylesheet { href: VERIFY_EMAIL_CSS }
        {
            #[cfg(feature = "mail")]
            rsx! {
                document::Stylesheet { href: FORGOT_PASSWORD_CSS }
                document::Stylesheet { href: RESET_PASSWORD_CSS }
            }
        }
    }
}
