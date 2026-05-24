use leptos::ev::MouseEvent;
use leptos::prelude::*;

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

/// Sizing preset for a [`Button`]. Maps to `data-size="..."`.
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

/// Themed `<button>`. Pass `variant` / `size` to pick a preset. `on_click`
/// receives the raw `MouseEvent`; `disabled` is reactive.
#[component]
pub fn Button(
    #[prop(optional)] variant: ButtonVariant,
    #[prop(optional)] size: ButtonSize,
    /// HTML `type` attribute — `"button"` (default), `"submit"`, or `"reset"`.
    #[prop(default = "button")]
    button_type: &'static str,
    #[prop(optional, into)] disabled: Signal<bool>,
    /// Extra class names appended after `dx-button`.
    #[prop(optional, into)]
    class: String,
    #[prop(optional)] on_click: Option<Callback<MouseEvent>>,
    children: Children,
) -> impl IntoView {
    let class = format!("dx-button {class}");
    view! {
        <button
            type=button_type
            class=class
            data-style=variant.class()
            data-size=size.class()
            disabled=move || disabled.get()
            on:click=move |ev| {
                if let Some(cb) = on_click {
                    cb.run(ev);
                }
            }
        >
            {children()}
        </button>
    }
}
