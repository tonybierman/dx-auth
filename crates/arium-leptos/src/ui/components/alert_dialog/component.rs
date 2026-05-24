use leptos::ev::MouseEvent;
use leptos::prelude::*;

/// Context carrying the close callback to the [`AlertDialogCancel`] /
/// [`AlertDialogAction`] buttons.
#[derive(Clone, Copy)]
struct AlertDialogCtx {
    on_open_change: Option<Callback<bool>>,
}

/// Modal confirmation dialog. Controlled via `open`; closing fires
/// `on_open_change(false)`. Compose with [`AlertDialogTitle`],
/// [`AlertDialogDescription`], and [`AlertDialogActions`] children.
#[component]
pub fn AlertDialog(
    #[prop(into)] open: Signal<bool>,
    #[prop(optional)] on_open_change: Option<Callback<bool>>,
    children: Children,
) -> impl IntoView {
    provide_context(AlertDialogCtx { on_open_change });
    view! {
        <div
            class="dx-alert-dialog-backdrop"
            data-state=move || if open.get() { "open" } else { "closed" }
            style:display=move || if open.get() { "flex" } else { "none" }
        >
            <div class="dx-alert-dialog" role="alertdialog" aria-modal="true">
                {children()}
            </div>
        </div>
    }
}

/// Heading text inside an [`AlertDialog`].
#[component]
pub fn AlertDialogTitle(children: Children) -> impl IntoView {
    view! { <div class="dx-alert-dialog-title">{children()}</div> }
}

/// Body text inside an [`AlertDialog`].
#[component]
pub fn AlertDialogDescription(children: Children) -> impl IntoView {
    view! { <div class="dx-alert-dialog-description">{children()}</div> }
}

/// Footer row holding the cancel / action buttons.
#[component]
pub fn AlertDialogActions(children: Children) -> impl IntoView {
    view! { <div class="dx-alert-dialog-actions">{children()}</div> }
}

/// Dismiss button — closes the dialog without confirming.
#[component]
pub fn AlertDialogCancel(
    #[prop(optional)] on_click: Option<Callback<MouseEvent>>,
    children: Children,
) -> impl IntoView {
    let ctx = expect_context::<AlertDialogCtx>();
    view! {
        <button
            type="button"
            class="dx-alert-dialog-cancel"
            on:click=move |ev| {
                if let Some(cb) = on_click {
                    cb.run(ev);
                }
                if let Some(c) = ctx.on_open_change {
                    c.run(false);
                }
            }
        >
            {children()}
        </button>
    }
}

/// Confirm button — invokes `on_click` and closes the dialog.
#[component]
pub fn AlertDialogAction(
    #[prop(optional)] on_click: Option<Callback<MouseEvent>>,
    children: Children,
) -> impl IntoView {
    let ctx = expect_context::<AlertDialogCtx>();
    view! {
        <button
            type="button"
            class="dx-alert-dialog-action"
            on:click=move |ev| {
                if let Some(cb) = on_click {
                    cb.run(ev);
                }
                if let Some(c) = ctx.on_open_change {
                    c.run(false);
                }
            }
        >
            {children()}
        </button>
    }
}
