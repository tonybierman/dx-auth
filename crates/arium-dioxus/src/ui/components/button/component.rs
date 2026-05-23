use dioxus::prelude::*;
use dioxus_primitives::dioxus_attributes::attributes;
use dioxus_primitives::merge_attributes;

// See comment in card/component.rs: explicit Stylesheet emission so SSR always
// reasserts the link tag.
const BUTTON_CSS: Asset = asset!(
    "/src/ui/components/button/dx-button.css",
    AssetOptions::css_module()
);

#[css_module("/src/ui/components/button/dx-button.css")]
struct Styles;

/// Visual style of a [`Button`]. Maps to the `data-style="..."` attribute.
#[derive(Copy, Clone, PartialEq, Default)]
#[non_exhaustive]
pub enum ButtonVariant {
    /// Solid primary brand color.
    #[default]
    Primary,
    /// Muted secondary fill.
    Secondary,
    /// Red, for destructive actions.
    Destructive,
    /// Transparent fill with a border.
    Outline,
    /// No background until hover.
    Ghost,
    /// Renders like a text link.
    Link,
}

impl ButtonVariant {
    /// CSS `data-style` value used to select this variant in the stylesheet.
    pub fn class(&self) -> &'static str {
        match self {
            ButtonVariant::Primary => "primary",
            ButtonVariant::Secondary => "secondary",
            ButtonVariant::Destructive => "destructive",
            ButtonVariant::Outline => "outline",
            ButtonVariant::Ghost => "ghost",
            ButtonVariant::Link => "link",
        }
    }
}

/// Sizing preset for a [`Button`]. Maps to `data-size="..."`. Icon-prefixed
/// sizes produce a square button suitable for a single glyph.
#[derive(Copy, Clone, PartialEq, Default)]
#[non_exhaustive]
pub enum ButtonSize {
    /// Extra-small.
    Xs,
    /// Small.
    Sm,
    /// Standard.
    #[default]
    Default,
    /// Large.
    Lg,
    /// Square, standard height.
    Icon,
    /// Square, extra-small.
    IconXs,
    /// Square, small.
    IconSm,
    /// Square, large.
    IconLg,
}

impl ButtonSize {
    /// CSS `data-size` value used to select this size in the stylesheet.
    pub fn class(&self) -> &'static str {
        match self {
            ButtonSize::Xs => "xs",
            ButtonSize::Sm => "sm",
            ButtonSize::Default => "default",
            ButtonSize::Lg => "lg",
            ButtonSize::Icon => "icon",
            ButtonSize::IconXs => "icon-xs",
            ButtonSize::IconSm => "icon-sm",
            ButtonSize::IconLg => "icon-lg",
        }
    }
}

/// Themed `<button>`. Pass `variant` / `size` to pick a preset; any extra
/// HTML attributes (`id`, `disabled`, `aria-*`, ...) are merged through.
#[component]
pub fn Button(
    #[props(default)] variant: ButtonVariant,
    #[props(default)] size: ButtonSize,
    #[props(extends=GlobalAttributes)]
    #[props(extends=button)]
    attributes: Vec<Attribute>,
    onclick: Option<EventHandler<MouseEvent>>,
    onmousedown: Option<EventHandler<MouseEvent>>,
    onmouseup: Option<EventHandler<MouseEvent>>,
    onkeydown: Option<EventHandler<KeyboardEvent>>,
    children: Element,
) -> Element {
    let base = attributes!(button {
        class: Styles::dx_button,
        "data-style": variant.class(),
        "data-size": size.class(),
    });
    let merged = merge_attributes(vec![base, attributes]);

    rsx! {
        document::Stylesheet { href: BUTTON_CSS }
        button {
            onclick: move |event| {
                if let Some(f) = &onclick {
                    f.call(event);
                }
            },
            onmousedown: move |event| {
                if let Some(f) = &onmousedown {
                    f.call(event);
                }
            },
            onmouseup: move |event| {
                if let Some(f) = &onmouseup {
                    f.call(event);
                }
            },
            onkeydown: move |event| {
                if let Some(f) = &onkeydown {
                    f.call(event);
                }
            },
            ..merged,
            {children}
        }
    }
}
