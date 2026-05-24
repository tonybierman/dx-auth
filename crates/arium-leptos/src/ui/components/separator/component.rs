use leptos::prelude::*;

/// Horizontal or vertical hairline. Set `horizontal=false` for a vertical rule;
/// set `decorative=true` to keep it out of the accessibility tree.
#[component]
pub fn Separator(
    #[prop(default = true)] horizontal: bool,
    #[prop(default = false)] decorative: bool,
    #[prop(optional, into)] class: String,
) -> impl IntoView {
    let orientation = if horizontal { "horizontal" } else { "vertical" };
    let role = if decorative { "none" } else { "separator" };
    view! {
        <div
            class=format!("dx-separator {class}")
            role=role
            data-orientation=orientation
            aria-orientation=orientation
        ></div>
    }
}
