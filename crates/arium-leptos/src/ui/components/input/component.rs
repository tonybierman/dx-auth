use leptos::prelude::*;

/// Themed `<input>`. Controlled: bind `value` to a signal and handle `on_input`
/// (which receives the new string value). Any of `id` / `name` / `placeholder`
/// / `autocomplete` may be supplied; `input_type` defaults to `"text"`.
#[component]
pub fn Input(
    #[prop(optional, into)] id: String,
    #[prop(optional, into)] name: String,
    #[prop(default = "text")] input_type: &'static str,
    #[prop(optional, into)] placeholder: String,
    #[prop(optional, into)] autocomplete: String,
    #[prop(optional, into)] value: Signal<String>,
    #[prop(optional, into)] required: Signal<bool>,
    #[prop(optional, into)] disabled: Signal<bool>,
    #[prop(optional, into)] class: String,
    #[prop(optional)] on_input: Option<Callback<String>>,
) -> impl IntoView {
    view! {
        <input
            class=format!("dx-input {class}")
            id=id
            name=name
            type=input_type
            placeholder=placeholder
            autocomplete=autocomplete
            prop:value=move || value.get()
            required=move || required.get()
            disabled=move || disabled.get()
            on:input=move |ev| {
                if let Some(cb) = on_input {
                    cb.run(event_target_value(&ev));
                }
            }
        />
    }
}
