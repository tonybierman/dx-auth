use dioxus::prelude::*;
use dioxus_icons::lucide::Check;
use dioxus_primitives::checkbox::{self, CheckboxProps};

// See comment in card/component.rs: explicit Stylesheet emission so SSR always
// reasserts the link tag.
const CHECKBOX_CSS: Asset = asset!(
    "/src/ui/components/checkbox/dx-checkbox.css",
    AssetOptions::css_module()
);

#[css_module("/src/ui/components/checkbox/dx-checkbox.css")]
struct Styles;

/// Themed checkbox primitive.
#[component]
pub fn Checkbox(props: CheckboxProps) -> Element {
    rsx! {
        document::Stylesheet { href: CHECKBOX_CSS }
        checkbox::Checkbox {
            class: Styles::dx_checkbox,
            checked: props.checked,
            default_checked: props.default_checked,
            required: props.required,
            disabled: props.disabled,
            name: props.name,
            value: props.value,
            on_checked_change: props.on_checked_change,
            attributes: props.attributes,
            checkbox::CheckboxIndicator { class: Styles::dx_checkbox_indicator,
                Check { size: "1rem" }
            }
        }
    }
}
