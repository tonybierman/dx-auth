use dioxus::prelude::*;

// Same file the `#[css_module]` below points at; declared as a separate `Asset` so we can
// render a `document::Stylesheet` from every component in the module. The css_module
// macro's own link-injection path uses a process-wide `OnceLock` that only fires once per
// process — fine for fully client-rendered apps, but on an SSR server only the first
// request gets the `<link>` tag. Emitting the Stylesheet from rsx! makes every render
// reassert the link; the browser de-dupes by href so the multiple emissions are harmless.
const CARD_CSS: Asset = asset!(
    "/src/ui/components/card/dx-card.css",
    AssetOptions::css_module()
);

#[css_module("/src/ui/components/card/dx-card.css")]
struct Styles;

#[component]
pub fn Card(
    #[props(extends=GlobalAttributes)] attributes: Vec<Attribute>,
    children: Element,
) -> Element {
    rsx! {
        document::Stylesheet { href: CARD_CSS }
        div {
            class: Styles::dx_card,
            "data-slot": "card",
            ..attributes,
            {children}
        }
    }
}

#[component]
pub fn CardHeader(
    #[props(extends=GlobalAttributes)] attributes: Vec<Attribute>,
    children: Element,
) -> Element {
    rsx! {
        document::Stylesheet { href: CARD_CSS }
        div {
            class: Styles::dx_card_header,
            "data-slot": "card-header",
            ..attributes,
            {children}
        }
    }
}

#[component]
pub fn CardTitle(
    #[props(extends=GlobalAttributes)] attributes: Vec<Attribute>,
    children: Element,
) -> Element {
    rsx! {
        document::Stylesheet { href: CARD_CSS }
        div {
            class: Styles::dx_card_title,
            "data-slot": "card-title",
            ..attributes,
            {children}
        }
    }
}

#[component]
pub fn CardDescription(
    #[props(extends=GlobalAttributes)] attributes: Vec<Attribute>,
    children: Element,
) -> Element {
    rsx! {
        document::Stylesheet { href: CARD_CSS }
        div {
            class: Styles::dx_card_description,
            "data-slot": "card-description",
            ..attributes,
            {children}
        }
    }
}

#[component]
pub fn CardAction(
    #[props(extends=GlobalAttributes)] attributes: Vec<Attribute>,
    children: Element,
) -> Element {
    rsx! {
        document::Stylesheet { href: CARD_CSS }
        div {
            class: Styles::dx_card_action,
            "data-slot": "card-action",
            ..attributes,
            {children}
        }
    }
}

#[component]
pub fn CardContent(
    #[props(extends=GlobalAttributes)] attributes: Vec<Attribute>,
    children: Element,
) -> Element {
    rsx! {
        document::Stylesheet { href: CARD_CSS }
        div {
            class: Styles::dx_card_content,
            "data-slot": "card-content",
            ..attributes,
            {children}
        }
    }
}

#[component]
pub fn CardFooter(
    #[props(extends=GlobalAttributes)] attributes: Vec<Attribute>,
    children: Element,
) -> Element {
    rsx! {
        document::Stylesheet { href: CARD_CSS }
        div {
            class: Styles::dx_card_footer,
            "data-slot": "card-footer",
            ..attributes,
            {children}
        }
    }
}
