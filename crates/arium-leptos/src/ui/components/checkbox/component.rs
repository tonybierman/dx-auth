use crate::ui::components::icons::IconCheck;
use leptos::prelude::*;

/// Themed checkbox. Controlled: bind `checked` to a signal and handle
/// `on_checked_change` (which receives the new boolean state).
#[component]
pub fn Checkbox(
    #[prop(optional, into)] checked: Signal<bool>,
    #[prop(optional)] on_checked_change: Option<Callback<bool>>,
    #[prop(optional, into)] disabled: Signal<bool>,
    #[prop(optional, into)] class: String,
) -> impl IntoView {
    view! {
        <button
            type="button"
            role="checkbox"
            class=format!("dx-checkbox {class}")
            data-state=move || if checked.get() { "checked" } else { "unchecked" }
            aria-checked=move || checked.get().to_string()
            disabled=move || disabled.get()
            on:click=move |_| {
                if let Some(cb) = on_checked_change {
                    cb.run(!checked.get_untracked());
                }
            }
        >
            <span class="dx-checkbox-indicator">
                <Show when=move || checked.get()>
                    <IconCheck size="1rem" />
                </Show>
            </span>
        </button>
    }
}
