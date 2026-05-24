//! Inline SVG icons (a small subset of [lucide](https://lucide.dev)) so the
//! catalog widgets don't pull an icon-font or component dependency. Each takes
//! an optional `size` (CSS length) and `class`; `stroke="currentColor"` (the
//! default) lets the surrounding `color` drive the glyph color, matching the
//! catalog CSS.

use leptos::prelude::*;

/// Shared `<svg>` shell for the stroke-based lucide icons.
#[component]
fn Svg(
    #[prop(default = "1rem")] size: &'static str,
    #[prop(optional, into)] class: String,
    #[prop(default = "currentColor")] stroke: &'static str,
    children: Children,
) -> impl IntoView {
    view! {
        <svg
            xmlns="http://www.w3.org/2000/svg"
            width=size
            height=size
            viewBox="0 0 24 24"
            fill="none"
            stroke=stroke
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
            class=class
            aria-hidden="true"
        >
            {children()}
        </svg>
    }
}

#[component]
pub fn IconCheck(
    #[prop(default = "1rem")] size: &'static str,
    #[prop(default = "currentColor")] stroke: &'static str,
) -> impl IntoView {
    view! { <Svg size=size stroke=stroke><path d="M20 6 9 17l-5-5" /></Svg> }
}

#[component]
pub fn IconChevronDown(
    #[prop(default = "1rem")] size: &'static str,
    #[prop(optional, into)] class: String,
    #[prop(default = "currentColor")] stroke: &'static str,
) -> impl IntoView {
    view! { <Svg size=size class=class stroke=stroke><path d="m6 9 6 6 6-6" /></Svg> }
}

#[component]
pub fn IconChevronLeft(#[prop(default = "1rem")] size: &'static str) -> impl IntoView {
    view! { <Svg size=size><path d="m15 18-6-6 6-6" /></Svg> }
}

#[component]
pub fn IconChevronRight(#[prop(default = "1rem")] size: &'static str) -> impl IntoView {
    view! { <Svg size=size><path d="m9 18 6-6-6-6" /></Svg> }
}

#[component]
pub fn IconEllipsis(#[prop(default = "1rem")] size: &'static str) -> impl IntoView {
    view! {
        <Svg size=size>
            <circle cx="12" cy="12" r="1" />
            <circle cx="19" cy="12" r="1" />
            <circle cx="5" cy="12" r="1" />
        </Svg>
    }
}

/// Small "verified" badge-check glyph — pairs with a [`super::badge::Badge`].
#[component]
pub fn IconBadgeCheck(#[prop(default = "12px")] size: &'static str) -> impl IntoView {
    view! {
        <Svg size=size stroke="var(--secondary-color-4)">
            <path d="M3.85 8.62a4 4 0 0 1 4.78-4.77 4 4 0 0 1 6.74 0 4 4 0 0 1 4.78 4.78 4 4 0 0 1 0 6.74 4 4 0 0 1-4.77 4.78 4 4 0 0 1-6.75 0 4 4 0 0 1-4.78-4.77 4 4 0 0 1 0-6.76Z" />
            <path d="m9 12 2 2 4-4" />
        </Svg>
    }
}
