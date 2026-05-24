use leptos::prelude::*;

/// Scrollable list container. The Dioxus catalog windowed this with a
/// `render_item` callback; in Leptos the screens render their rows directly
/// with `<For>` inside this scroll container (admin lists are capped at 500
/// rows, so full rendering is fine). The `dx-virtual-list-container` class is
/// preserved for styling parity.
#[component]
pub fn VirtualList(
    #[prop(optional, into)] class: String,
    #[prop(default = "28rem")] max_height: &'static str,
    children: Children,
) -> impl IntoView {
    view! {
        <div
            class=format!("dx-virtual-list-container {class}")
            style=format!("overflow-y:auto;max-height:{max_height}")
        >
            {children()}
        </div>
    }
}
