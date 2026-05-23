use dioxus::prelude::*;
use dioxus_icons::lucide::{ChevronLeft, ChevronRight, Ellipsis};

// See comment in card/component.rs: explicit Stylesheet emission so SSR always
// reasserts the link tag.
const PAGINATION_CSS: Asset = asset!(
    "/src/ui/components/pagination/dx-pagination.css",
    AssetOptions::css_module()
);

#[css_module("/src/ui/components/pagination/dx-pagination.css")]
struct Styles;

/// Sizing preset for a [`PaginationLink`]. `Icon` produces a square button
/// suitable for chevron-only previous/next controls; `Default` is wider for
/// numbered pages.
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

/// Outer `<nav>` wrapper for a page navigator. Compose with
/// [`PaginationContent`] holding [`PaginationItem`] children.
#[component]
pub fn Pagination(
    #[props(extends = GlobalAttributes)] attributes: Vec<Attribute>,
    children: Element,
) -> Element {
    rsx! {
        document::Stylesheet { href: PAGINATION_CSS }
        nav {
            class: Styles::dx_pagination,
            "data-slot": "pagination",
            role: "navigation",
            aria_label: "pagination",
            ..attributes,
            {children}
        }
    }
}

/// `<ul>` row of [`PaginationItem`]s inside a [`Pagination`].
#[component]
pub fn PaginationContent(
    #[props(extends = GlobalAttributes)] attributes: Vec<Attribute>,
    children: Element,
) -> Element {
    rsx! {
        document::Stylesheet { href: PAGINATION_CSS }
        ul {
            class: Styles::dx_pagination_content,
            "data-slot": "pagination-content",
            ..attributes,
            {children}
        }
    }
}

/// `<li>` wrapper around a [`PaginationLink`] or [`PaginationEllipsis`].
#[component]
pub fn PaginationItem(
    #[props(extends = GlobalAttributes)] attributes: Vec<Attribute>,
    children: Element,
) -> Element {
    rsx! {
        li {
            "data-slot": "pagination-item",
            ..attributes,
            {children}
        }
    }
}

/// Props for [`PaginationLink`].
#[derive(Props, Clone, PartialEq)]
pub struct PaginationLinkProps {
    /// `true` if this link represents the current page.
    #[props(default)]
    pub is_active: bool,
    /// Sizing preset.
    #[props(default)]
    pub size: PaginationLinkSize,
    /// Tag the link as the previous- or next-page control.
    #[props(default)]
    pub data_kind: Option<PaginationLinkKind>,
    /// Click handler.
    onclick: Option<EventHandler<MouseEvent>>,
    /// Mouse-down handler.
    onmousedown: Option<EventHandler<MouseEvent>>,
    /// Mouse-up handler.
    onmouseup: Option<EventHandler<MouseEvent>>,
    /// Extra HTML attributes merged onto the `<a>`.
    #[props(extends = GlobalAttributes)]
    #[props(extends = a)]
    pub attributes: Vec<Attribute>,
    /// Link label (typically a page number).
    pub children: Element,
}

/// Clickable page-number / previous-/next- control inside a [`Pagination`].
#[component]
pub fn PaginationLink(props: PaginationLinkProps) -> Element {
    let aria_current = if props.is_active { Some("page") } else { None };
    let data_kind = props.data_kind.map(|kind| kind.attr());
    rsx! {
        document::Stylesheet { href: PAGINATION_CSS }
        a {
            class: Styles::dx_pagination_link,
            "data-slot": "pagination-link",
            "data-active": props.is_active,
            "data-size": props.size.class(),
            "data-kind": data_kind,
            aria_current: aria_current,
            onclick: move |event| {
                if let Some(f) = &props.onclick {
                    f.call(event);
                }
            },
            onmousedown: move |event| {
                if let Some(f) = &props.onmousedown {
                    f.call(event);
                }
            },
            onmouseup: move |event| {
                if let Some(f) = &props.onmouseup {
                    f.call(event);
                }
            },
            ..props.attributes,
            {props.children}
        }
    }
}

/// "Previous" chevron-link convenience over [`PaginationLink`].
#[component]
pub fn PaginationPrevious(
    onclick: Option<EventHandler<MouseEvent>>,
    onmousedown: Option<EventHandler<MouseEvent>>,
    onmouseup: Option<EventHandler<MouseEvent>>,
    #[props(extends = GlobalAttributes)]
    #[props(extends = a)]
    attributes: Vec<Attribute>,
) -> Element {
    rsx! {
        PaginationLink {
            size: PaginationLinkSize::Default,
            aria_label: "Go to previous page",
            data_kind: Some(PaginationLinkKind::Previous),
            onclick,
            onmousedown,
            onmouseup,
            attributes,
            ChevronLeft { size: "1rem" }
            span { class: Styles::dx_pagination_label, "Previous" }
        }
    }
}

/// "Next" chevron-link convenience over [`PaginationLink`].
#[component]
pub fn PaginationNext(
    onclick: Option<EventHandler<MouseEvent>>,
    onmousedown: Option<EventHandler<MouseEvent>>,
    onmouseup: Option<EventHandler<MouseEvent>>,
    #[props(extends = GlobalAttributes)]
    #[props(extends = a)]
    attributes: Vec<Attribute>,
) -> Element {
    rsx! {
        PaginationLink {
            size: PaginationLinkSize::Default,
            aria_label: "Go to next page",
            data_kind: Some(PaginationLinkKind::Next),
            onclick,
            onmousedown,
            onmouseup,
            attributes,
            span { class: Styles::dx_pagination_label, "Next" }
            ChevronRight { size: "1rem" }
        }
    }
}

/// `...` placeholder inserted between gaps in a long page list.
#[component]
pub fn PaginationEllipsis(
    #[props(extends = GlobalAttributes)] attributes: Vec<Attribute>,
) -> Element {
    rsx! {
        document::Stylesheet { href: PAGINATION_CSS }
        span {
            class: Styles::dx_pagination_ellipsis,
            "data-slot": "pagination-ellipsis",
            aria_hidden: "true",
            ..attributes,
            Ellipsis { size: "1rem" }
            span { class: Styles::dx_sr_only, "More pages" }
        }
    }
}
