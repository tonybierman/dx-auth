use dioxus::prelude::*;
use dioxus_primitives::avatar::{self, AvatarState};
use dioxus_primitives::dioxus_attributes::attributes;
use dioxus_primitives::merge_attributes;

// See comment in card/component.rs: explicit Stylesheet emission so SSR always
// reasserts the link tag.
const AVATAR_CSS: Asset = asset!(
    "/src/ui/components/avatar/dx-avatar.css",
    AssetOptions::css_module()
);

#[css_module("/src/ui/components/avatar/dx-avatar.css")]
struct Styles;

/// Dimensions preset for [`Avatar`].
#[derive(Clone, Copy, PartialEq, Default)]
pub enum AvatarImageSize {
    /// 24px-ish.
    #[default]
    Small,
    /// 32px-ish.
    Medium,
    /// 48px-ish.
    Large,
}

impl AvatarImageSize {
    fn to_class(self) -> &'static str {
        match self {
            AvatarImageSize::Small => Styles::dx_avatar_sm.inner,
            AvatarImageSize::Medium => Styles::dx_avatar_md.inner,
            AvatarImageSize::Large => Styles::dx_avatar_lg.inner,
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
    fn to_class(self) -> &'static str {
        match self {
            AvatarShape::Circle => Styles::dx_avatar_circle.inner,
            AvatarShape::Rounded => Styles::dx_avatar_rounded.inner,
        }
    }
}

/// The props for the [`Avatar`] root component.
#[derive(Props, Clone, PartialEq)]
pub struct AvatarProps {
    /// Callback when image loads successfully.
    #[props(default)]
    pub on_load: Option<EventHandler<()>>,

    /// Callback when image fails to load.
    #[props(default)]
    pub on_error: Option<EventHandler<()>>,

    /// Callback when the avatar state changes.
    #[props(default)]
    pub on_state_change: Option<EventHandler<AvatarState>>,

    /// Sizing preset.
    #[props(default)]
    pub size: AvatarImageSize,

    /// Corner-radius preset.
    #[props(default)]
    pub shape: AvatarShape,

    /// Additional attributes for the avatar element.
    #[props(extends = GlobalAttributes)]
    pub attributes: Vec<Attribute>,

    /// The fallback content shown while the image is loading or if it fails to load.
    pub children: Element,
}

/// Round image avatar with a [`AvatarFallback`] shown while the image loads
/// or if it fails. Compose with [`AvatarImage`] inside.
#[component]
pub fn Avatar(props: AvatarProps) -> Element {
    let class = format!(
        "{} {} {}",
        Styles::dx_avatar,
        props.size.to_class(),
        props.shape.to_class()
    );
    let base = attributes!(span { class });
    let merged = merge_attributes(vec![base, props.attributes]);

    rsx! {
        document::Stylesheet { href: AVATAR_CSS }
        avatar::Avatar {
            on_load: props.on_load,
            on_error: props.on_error,
            on_state_change: props.on_state_change,
            attributes: merged,
            {props.children}
        }
    }
}

/// Props for [`AvatarImage`].
#[derive(Props, Clone, PartialEq)]
pub struct AvatarImageProps {
    /// Optional DOM id (reactive).
    #[props(default)]
    pub id: ReadSignal<Option<String>>,

    /// Image URL.
    pub src: String,

    /// Alt text for screen readers.
    #[props(default)]
    pub alt: String,

    /// Extra HTML attributes merged onto the `<img>`.
    #[props(extends = GlobalAttributes)]
    pub attributes: Vec<Attribute>,
}

/// The `<img>` child of [`Avatar`]. Hidden until it loads successfully; the
/// [`AvatarFallback`] takes over on error.
#[component]
pub fn AvatarImage(props: AvatarImageProps) -> Element {
    let base = attributes!(img {
        class: Styles::dx_avatar_image,
        draggable: "false",
    });
    let merged = merge_attributes(vec![base, props.attributes]);

    rsx! {
        document::Stylesheet { href: AVATAR_CSS }
        avatar::AvatarImage {
            id: props.id,
            src: props.src,
            alt: props.alt,
            attributes: merged,
        }
    }
}

/// Props for [`AvatarFallback`].
#[derive(Props, Clone, PartialEq)]
pub struct AvatarFallbackProps {
    /// Extra HTML attributes merged onto the fallback element.
    #[props(extends = GlobalAttributes)]
    pub attributes: Vec<Attribute>,

    /// Fallback content (e.g. initials, an icon).
    pub children: Element,
}

/// Placeholder content shown until [`AvatarImage`] succeeds.
#[component]
pub fn AvatarFallback(props: AvatarFallbackProps) -> Element {
    let base = attributes!(span {
        class: Styles::dx_avatar_fallback,
    });
    let merged = merge_attributes(vec![base, props.attributes]);

    rsx! {
        document::Stylesheet { href: AVATAR_CSS }
        avatar::AvatarFallback {
            attributes: merged,
            {props.children}
        }
    }
}

/// The props for the [`ImageAvatar`] convenience component.
#[derive(Props, Clone, PartialEq)]
pub struct ImageAvatarProps {
    /// The image source URL.
    pub src: String,

    /// The image alt text.
    #[props(default)]
    pub alt: String,

    /// Callback when image loads successfully.
    #[props(default)]
    pub on_load: Option<EventHandler<()>>,

    /// Callback when image fails to load.
    #[props(default)]
    pub on_error: Option<EventHandler<()>>,

    /// Callback when the avatar state changes.
    #[props(default)]
    pub on_state_change: Option<EventHandler<AvatarState>>,

    /// Sizing preset.
    #[props(default)]
    pub size: AvatarImageSize,

    /// Corner-radius preset.
    #[props(default)]
    pub shape: AvatarShape,

    /// Additional attributes for the avatar element.
    #[props(extends = GlobalAttributes)]
    pub attributes: Vec<Attribute>,

    /// The fallback content shown while the image is loading or if it fails to load.
    pub children: Element,
}

/// One-shot avatar that wires [`Avatar`] + [`AvatarImage`] + [`AvatarFallback`]
/// together. Use when you have a URL and a fallback string and don't need
/// to compose the parts yourself.
#[component]
pub fn ImageAvatar(props: ImageAvatarProps) -> Element {
    rsx! {
        Avatar {
            on_load: props.on_load,
            on_error: props.on_error,
            on_state_change: props.on_state_change,
            size: props.size,
            shape: props.shape,
            attributes: props.attributes,
            AvatarImage {
                src: props.src,
                alt: props.alt,
            }
            AvatarFallback {
                {props.children}
            }
        }
    }
}
