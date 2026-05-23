use dioxus::prelude::*;
use dioxus_primitives::{dioxus_attributes::attributes, merge_attributes};

// See comment in card/component.rs: explicit Stylesheet emission so SSR always
// reasserts the link tag.
const SKELETON_CSS: Asset = asset!(
    "/src/ui/components/skeleton/dx-skeleton.css",
    AssetOptions::css_module()
);

#[css_module("/src/ui/components/skeleton/dx-skeleton.css")]
struct Styles;

/// Pulsing placeholder shown while async content is loading.
#[component]
pub fn Skeleton(#[props(extends=GlobalAttributes)] attributes: Vec<Attribute>) -> Element {
    let base = attributes!(div {
        class: Styles::dx_skeleton,
    });
    let merged = merge_attributes(vec![base, attributes]);

    rsx! {
        document::Stylesheet { href: SKELETON_CSS }
        div { ..merged }
    }
}
