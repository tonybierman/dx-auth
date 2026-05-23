use dioxus::prelude::*;
use dioxus_primitives::label::{self, LabelProps};

// See comment in card/component.rs: explicit Stylesheet emission so SSR always
// reasserts the link tag.
const LABEL_CSS: Asset = asset!(
    "/src/ui/components/label/dx-label.css",
    AssetOptions::css_module()
);

#[css_module("/src/ui/components/label/dx-label.css")]
struct Styles;

/// Themed `<label>` — pass `html_for: "input-id"` to wire it to a primitive.
#[component]
pub fn Label(props: LabelProps) -> Element {
    rsx! {
        document::Stylesheet { href: LABEL_CSS }
        label::Label {
            class: Styles::dx_label,
            html_for: props.html_for,
            attributes: props.attributes,
            {props.children}
        }
    }
}
