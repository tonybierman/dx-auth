use leptos::prelude::*;

/// The variant of the tabs component.
#[derive(Clone, Copy, PartialEq, Default)]
pub enum TabsVariant {
    /// The default variant.
    #[default]
    Default,
    /// The ghost variant.
    Ghost,
}

impl TabsVariant {
    fn class(self) -> &'static str {
        match self {
            TabsVariant::Default => "default",
            TabsVariant::Ghost => "ghost",
        }
    }
}

/// Shared state for a [`Tabs`] group: the active tab value + an optional
/// change callback. Read by [`TabTrigger`] / [`TabContent`] via context.
#[derive(Clone, Copy)]
struct TabsCtx {
    active: RwSignal<String>,
    on_change: Option<Callback<String>>,
}

/// Tabbed container. Compose with one [`TabList`] of [`TabTrigger`]s and one
/// [`TabContent`] per tab (matched by `value`). Uncontrolled: `default_value`
/// picks the initially-active tab.
#[component]
pub fn Tabs(
    #[prop(optional, into)] default_value: String,
    #[prop(optional)] on_value_change: Option<Callback<String>>,
    #[prop(optional)] variant: TabsVariant,
    #[prop(optional, into)] class: String,
    children: Children,
) -> impl IntoView {
    let active = RwSignal::new(default_value);
    provide_context(TabsCtx {
        active,
        on_change: on_value_change,
    });
    view! {
        <div class=format!("dx-tabs {class}") data-variant=variant.class()>
            {children()}
        </div>
    }
}

/// Row of [`TabTrigger`]s rendered inside [`Tabs`].
#[component]
pub fn TabList(#[prop(optional, into)] class: String, children: Children) -> impl IntoView {
    view! {
        <div class=format!("dx-tabs-list {class}") role="tablist">
            {children()}
        </div>
    }
}

/// Clickable tab header — activates the [`TabContent`] with the same `value`.
#[component]
pub fn TabTrigger(
    #[prop(into)] value: String,
    #[prop(optional, into)] class: String,
    children: Children,
) -> impl IntoView {
    let ctx = expect_context::<TabsCtx>();
    let active = ctx.active;
    let v_state = value.clone();
    let is_active = Memo::new(move |_| active.get() == v_state);
    let v_click = value;
    view! {
        <button
            type="button"
            role="tab"
            class=format!("dx-tabs-trigger {class}")
            data-state=move || if is_active.get() { "active" } else { "inactive" }
            aria-selected=move || is_active.get().to_string()
            on:click=move |_| {
                active.set(v_click.clone());
                if let Some(cb) = ctx.on_change {
                    cb.run(v_click.clone());
                }
            }
        >
            {children()}
        </button>
    }
}

/// Body shown when its matching [`TabTrigger`] is active.
#[component]
pub fn TabContent(
    #[prop(into)] value: String,
    #[prop(optional, into)] class: String,
    children: Children,
) -> impl IntoView {
    let ctx = expect_context::<TabsCtx>();
    let active = ctx.active;
    let is_active = Memo::new(move |_| active.get() == value);
    view! {
        <div
            role="tabpanel"
            class=format!("dx-tabs-content dx-tabs-content-themed {class}")
            data-state=move || if is_active.get() { "active" } else { "inactive" }
            style:display=move || if is_active.get() { "block" } else { "none" }
        >
            {children()}
        </div>
    }
}
