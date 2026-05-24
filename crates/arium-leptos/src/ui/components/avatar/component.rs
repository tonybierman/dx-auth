use leptos::prelude::*;

/// Dimensions preset for [`Avatar`].
#[derive(Clone, Copy, PartialEq, Default)]
pub enum AvatarImageSize {
    /// 2rem.
    #[default]
    Small,
    /// 3rem.
    Medium,
    /// 4rem.
    Large,
}

impl AvatarImageSize {
    fn class(self) -> &'static str {
        match self {
            AvatarImageSize::Small => "dx-avatar-sm",
            AvatarImageSize::Medium => "dx-avatar-md",
            AvatarImageSize::Large => "dx-avatar-lg",
        }
    }
}

/// Corner style for [`Avatar`].
#[derive(Clone, Copy, PartialEq, Default)]
pub enum AvatarShape {
    /// Fully-circular.
    #[default]
    Circle,
    /// Square with rounded corners.
    Rounded,
}

impl AvatarShape {
    fn class(self) -> &'static str {
        match self {
            AvatarShape::Circle => "dx-avatar-circle",
            AvatarShape::Rounded => "dx-avatar-rounded",
        }
    }
}

/// Round image avatar with a fallback shown while the image loads or if it
/// fails. Compose with [`AvatarImage`] (overlaid) + [`AvatarFallback`] inside.
#[component]
pub fn Avatar(
    #[prop(optional)] size: AvatarImageSize,
    #[prop(optional)] shape: AvatarShape,
    children: Children,
) -> impl IntoView {
    view! {
        <span class=format!("dx-avatar {} {}", size.class(), shape.class())>
            {children()}
        </span>
    }
}

/// The `<img>` child of [`Avatar`]. Overlays the [`AvatarFallback`]; hides
/// itself on a load error so the fallback shows through.
#[component]
pub fn AvatarImage(
    #[prop(into)] src: String,
    #[prop(optional, into)] alt: String,
) -> impl IntoView {
    let (failed, set_failed) = signal(false);
    view! {
        <img
            class="dx-avatar-image"
            src=src
            alt=alt
            draggable="false"
            style="position:absolute;top:0;left:0;width:100%;height:100%;object-fit:cover"
            style:display=move || if failed.get() { "none" } else { "block" }
            on:error=move |_| set_failed.set(true)
        />
    }
}

/// Placeholder content (e.g. initials) shown underneath [`AvatarImage`].
#[component]
pub fn AvatarFallback(children: Children) -> impl IntoView {
    view! { <span class="dx-avatar-fallback">{children()}</span> }
}
