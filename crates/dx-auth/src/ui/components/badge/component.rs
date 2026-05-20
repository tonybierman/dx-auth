use dioxus::prelude::*;
use dioxus_icons::lucide::BadgeCheck;

// See comment in card/component.rs: explicit Stylesheet emission so SSR always
// reasserts the link tag.
const BADGE_CSS: Asset = asset!(
    "/src/ui/components/badge/dx-badge.css",
    AssetOptions::css_module()
);

#[css_module("/src/ui/components/badge/dx-badge.css")]
struct Styles;

#[derive(Copy, Clone, PartialEq, Default)]
#[non_exhaustive]
pub enum BadgeVariant {
    #[default]
    Primary,
    Secondary,
    Destructive,
    Outline,
}

impl BadgeVariant {
    pub fn class(&self) -> &'static str {
        match self {
            BadgeVariant::Primary => "primary",
            BadgeVariant::Secondary => "secondary",
            BadgeVariant::Destructive => "destructive",
            BadgeVariant::Outline => "outline",
        }
    }
}

/// The props for the [`Badge`] component.
#[derive(Props, Clone, PartialEq)]
pub struct BadgeProps {
    #[props(default)]
    pub variant: BadgeVariant,

    /// Additional attributes to extend the badge element
    #[props(extends = GlobalAttributes)]
    pub attributes: Vec<Attribute>,

    /// The children of the badge element
    pub children: Element,
}

#[component]
pub fn Badge(props: BadgeProps) -> Element {
    rsx! {
        BadgeElement {
            "padding": true,
            variant: props.variant,
            attributes: props.attributes,
            {props.children}
        }
    }
}

#[component]
fn BadgeElement(props: BadgeProps) -> Element {
    rsx! {
        document::Stylesheet { href: BADGE_CSS }
        span {
            class: Styles::dx_badge,
            "data-style": props.variant.class(),
            ..props.attributes,
            {props.children}
        }
    }
}

#[component]
pub fn VerifiedIcon() -> Element {
    rsx! {
        BadgeCheck {
            size: "12px",
            stroke: "var(--secondary-color-4)",
        }
    }
}
