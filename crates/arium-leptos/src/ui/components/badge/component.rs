use crate::ui::components::icons::IconBadgeCheck;
use leptos::prelude::*;

/// Visual style of a [`Badge`].
#[derive(Copy, Clone, PartialEq, Default)]
#[non_exhaustive]
pub enum BadgeVariant {
    /// Solid primary brand color.
    #[default]
    Primary,
    /// Muted secondary fill.
    Secondary,
    /// Red, for destructive labels.
    Destructive,
    /// Transparent fill with a border.
    Outline,
}

impl BadgeVariant {
    /// CSS `data-style` value used to select this variant in the stylesheet.
    pub fn class(&self) -> &'static str {
        match self {
            BadgeVariant::Primary => "primary",
            BadgeVariant::Secondary => "secondary",
            BadgeVariant::Destructive => "destructive",
            BadgeVariant::Outline => "outline",
        }
    }
}

/// Inline pill displaying a short label (e.g. role, status).
#[component]
pub fn Badge(
    #[prop(optional)] variant: BadgeVariant,
    #[prop(optional, into)] class: String,
    children: Children,
) -> impl IntoView {
    view! {
        <span class=format!("dx-badge {class}") data-style=variant.class()>
            {children()}
        </span>
    }
}

/// Small green checkmark icon — pair with a [`Badge`] to mark "verified".
#[component]
pub fn VerifiedIcon() -> impl IntoView {
    view! { <IconBadgeCheck size="12px" /> }
}
