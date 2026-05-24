use leptos::prelude::*;

/// Themed `<label>` — pass `html_for` to wire it to an input's `id`.
#[component]
pub fn Label(
    #[prop(optional, into)] html_for: String,
    #[prop(optional, into)] class: String,
    children: Children,
) -> impl IntoView {
    view! {
        <label r#for=html_for class=format!("dx-label {class}")>
            {children()}
        </label>
    }
}
