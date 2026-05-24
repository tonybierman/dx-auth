use leptos::prelude::*;

/// Outer card surface. Compose with `Card*` subcomponents inside.
#[component]
pub fn Card(#[prop(optional, into)] class: String, children: Children) -> impl IntoView {
    view! {
        <div class=format!("dx-card {class}") data-slot="card">
            {children()}
        </div>
    }
}

/// Top section of a [`Card`] — typically holds title + description + action.
#[component]
pub fn CardHeader(#[prop(optional, into)] class: String, children: Children) -> impl IntoView {
    view! {
        <div class=format!("dx-card-header {class}") data-slot="card-header">
            {children()}
        </div>
    }
}

/// Heading text inside a [`CardHeader`].
#[component]
pub fn CardTitle(#[prop(optional, into)] class: String, children: Children) -> impl IntoView {
    view! {
        <div class=format!("dx-card-title {class}") data-slot="card-title">
            {children()}
        </div>
    }
}

/// Secondary text inside a [`CardHeader`].
#[component]
pub fn CardDescription(
    #[prop(optional, into)] class: String,
    children: Children,
) -> impl IntoView {
    view! {
        <div class=format!("dx-card-description {class}") data-slot="card-description">
            {children()}
        </div>
    }
}

/// Right-aligned action slot inside a [`CardHeader`].
#[component]
pub fn CardAction(#[prop(optional, into)] class: String, children: Children) -> impl IntoView {
    view! {
        <div class=format!("dx-card-action {class}") data-slot="card-action">
            {children()}
        </div>
    }
}

/// Main body of a [`Card`].
#[component]
pub fn CardContent(#[prop(optional, into)] class: String, children: Children) -> impl IntoView {
    view! {
        <div class=format!("dx-card-content {class}") data-slot="card-content">
            {children()}
        </div>
    }
}

/// Bottom section of a [`Card`] — typically holds buttons or status.
#[component]
pub fn CardFooter(#[prop(optional, into)] class: String, children: Children) -> impl IntoView {
    view! {
        <div class=format!("dx-card-footer {class}") data-slot="card-footer">
            {children()}
        </div>
    }
}
