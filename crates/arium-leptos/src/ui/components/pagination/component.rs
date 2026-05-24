use crate::ui::components::icons::{IconChevronLeft, IconChevronRight, IconEllipsis};
use leptos::ev::MouseEvent;
use leptos::prelude::*;

/// Sizing preset for a [`PaginationLink`].
#[derive(Copy, Clone, PartialEq, Default)]
#[non_exhaustive]
pub enum PaginationLinkSize {
    /// Square, no label.
    #[default]
    Icon,
    /// Standard, with a label.
    Default,
}

impl PaginationLinkSize {
    /// CSS `data-size` value for this size.
    pub fn class(&self) -> &'static str {
        match self {
            PaginationLinkSize::Icon => "icon",
            PaginationLinkSize::Default => "default",
        }
    }
}

/// Whether a [`PaginationLink`] is the previous- or next-page chevron.
#[derive(Copy, Clone, PartialEq)]
#[non_exhaustive]
pub enum PaginationLinkKind {
    /// Previous-page chevron.
    Previous,
    /// Next-page chevron.
    Next,
}

impl PaginationLinkKind {
    /// CSS `data-kind` value for this kind.
    pub fn attr(&self) -> &'static str {
        match self {
            PaginationLinkKind::Previous => "previous",
            PaginationLinkKind::Next => "next",
        }
    }
}

/// Outer `<nav>` wrapper for a page navigator.
#[component]
pub fn Pagination(#[prop(optional, into)] class: String, children: Children) -> impl IntoView {
    view! {
        <nav
            class=format!("dx-pagination {class}")
            data-slot="pagination"
            role="navigation"
            aria-label="pagination"
        >
            {children()}
        </nav>
    }
}

/// `<ul>` row of [`PaginationItem`]s inside a [`Pagination`].
#[component]
pub fn PaginationContent(children: Children) -> impl IntoView {
    view! {
        <ul class="dx-pagination-content" data-slot="pagination-content">
            {children()}
        </ul>
    }
}

/// `<li>` wrapper around a [`PaginationLink`] or [`PaginationEllipsis`].
#[component]
pub fn PaginationItem(children: Children) -> impl IntoView {
    view! { <li data-slot="pagination-item">{children()}</li> }
}

/// Clickable page-number / previous-/next- control inside a [`Pagination`].
#[component]
pub fn PaginationLink(
    #[prop(optional, into)] is_active: Signal<bool>,
    #[prop(optional)] size: PaginationLinkSize,
    #[prop(optional)] data_kind: Option<PaginationLinkKind>,
    #[prop(optional, into)] disabled: Signal<bool>,
    #[prop(optional, into)] aria_label: String,
    #[prop(optional)] on_click: Option<Callback<MouseEvent>>,
    children: Children,
) -> impl IntoView {
    let kind = data_kind.map(|k| k.attr());
    view! {
        <a
            class="dx-pagination-link"
            data-slot="pagination-link"
            data-active=move || is_active.get().to_string()
            data-size=size.class()
            data-kind=kind
            data-disabled=move || disabled.get().to_string()
            aria-current=move || if is_active.get() { "page" } else { "" }
            aria-label=aria_label
            on:click=move |ev| {
                if !disabled.get_untracked()
                    && let Some(cb) = on_click
                {
                    cb.run(ev);
                }
            }
        >
            {children()}
        </a>
    }
}

/// "Previous" chevron-link convenience over [`PaginationLink`].
#[component]
pub fn PaginationPrevious(
    #[prop(optional, into)] disabled: Signal<bool>,
    on_click: Callback<MouseEvent>,
) -> impl IntoView {
    view! {
        <PaginationLink
            size=PaginationLinkSize::Default
            aria_label="Go to previous page"
            data_kind=PaginationLinkKind::Previous
            disabled=disabled
            on_click=on_click
        >
            <IconChevronLeft size="1rem" />
            <span class="dx-pagination-label">"Previous"</span>
        </PaginationLink>
    }
}

/// "Next" chevron-link convenience over [`PaginationLink`].
#[component]
pub fn PaginationNext(
    #[prop(optional, into)] disabled: Signal<bool>,
    on_click: Callback<MouseEvent>,
) -> impl IntoView {
    view! {
        <PaginationLink
            size=PaginationLinkSize::Default
            aria_label="Go to next page"
            data_kind=PaginationLinkKind::Next
            disabled=disabled
            on_click=on_click
        >
            <span class="dx-pagination-label">"Next"</span>
            <IconChevronRight size="1rem" />
        </PaginationLink>
    }
}

/// `...` placeholder inserted between gaps in a long page list.
#[component]
pub fn PaginationEllipsis() -> impl IntoView {
    view! {
        <span class="dx-pagination-ellipsis" data-slot="pagination-ellipsis" aria-hidden="true">
            <IconEllipsis size="1rem" />
            <span class="dx-sr-only">"More pages"</span>
        </span>
    }
}
