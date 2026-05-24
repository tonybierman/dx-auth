use crate::ui::components::icons::{IconCheck, IconChevronDown};
use leptos::prelude::*;

/// Shared state for a [`Select`] group, read by [`SelectOption`] via context.
#[derive(Clone, Copy)]
struct SelectCtx {
    value: RwSignal<String>,
    open: RwSignal<bool>,
    on_change: Option<Callback<String>>,
}

/// Single-select dropdown (string-valued). Compose with [`SelectOption`]
/// children. Uncontrolled: `default_value` sets the initial selection.
#[component]
pub fn Select(
    #[prop(optional, into)] default_value: String,
    #[prop(optional)] on_value_change: Option<Callback<String>>,
    #[prop(optional, into)] placeholder: String,
    #[prop(optional, into)] class: String,
    children: Children,
) -> impl IntoView {
    let value = RwSignal::new(default_value);
    let open = RwSignal::new(false);
    provide_context(SelectCtx {
        value,
        open,
        on_change: on_value_change,
    });
    view! {
        <div class=format!("dx-select {class}")>
            <button
                type="button"
                class="dx-select-trigger"
                data-state=move || if open.get() { "open" } else { "closed" }
                data-placeholder=move || value.get().is_empty().to_string()
                on:click=move |_| open.update(|o| *o = !*o)
            >
                <span>
                    {move || {
                        let v = value.get();
                        if v.is_empty() { placeholder.clone() } else { v }
                    }}
                </span>
                <IconChevronDown class="dx-select-expand-icon" size="20px" />
            </button>
            <div
                class="dx-select-list"
                role="listbox"
                data-state=move || if open.get() { "open" } else { "closed" }
                style:display=move || if open.get() { "block" } else { "none" }
            >
                {children()}
            </div>
        </div>
    }
}

/// Heading row inside a grouped [`Select`].
#[component]
pub fn SelectGroupLabel(children: Children) -> impl IntoView {
    view! { <div class="dx-select-group-label">{children()}</div> }
}

/// One option inside a [`Select`].
#[component]
pub fn SelectOption(
    #[prop(into)] value: String,
    #[prop(optional, into)] class: String,
    children: Children,
) -> impl IntoView {
    let ctx = expect_context::<SelectCtx>();
    let sel = ctx.value;
    let v_state = value.clone();
    let selected = Memo::new(move |_| sel.get() == v_state);
    let v_click = value;
    view! {
        <div
            class=format!("dx-select-option {class}")
            role="option"
            data-state=move || if selected.get() { "checked" } else { "unchecked" }
            aria-selected=move || selected.get().to_string()
            on:click=move |_| {
                ctx.value.set(v_click.clone());
                ctx.open.set(false);
                if let Some(cb) = ctx.on_change {
                    cb.run(v_click.clone());
                }
            }
        >
            {children()}
            <span class="dx-select-item-indicator">
                <Show when=move || selected.get()>
                    <IconCheck size="1rem" stroke="var(--secondary-color-5)" />
                </Show>
            </span>
        </div>
    }
}
