use leptos::prelude::*;

/// Pulsing placeholder shown while async content is loading.
#[component]
pub fn Skeleton(
    #[prop(optional, into)] class: String,
    #[prop(optional, into)] style: String,
) -> impl IntoView {
    view! { <div class=format!("dx-skeleton {class}") style=style></div> }
}
