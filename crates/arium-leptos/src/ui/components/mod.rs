//! Catalog UI primitives — Leptos ports of the `arium-dioxus` widgets. Each is
//! a thin element wrapper carrying the shared `dx-*` classes + `data-*` state
//! attributes the catalog CSS keys off. Styling is injected once by
//! [`crate::ui::AuthStylesheets`]; the widgets themselves render only markup.

pub mod icons;

pub mod alert_dialog;
pub mod avatar;
pub mod badge;
pub mod button;
pub mod card;
pub mod checkbox;
pub mod input;
pub mod label;
pub mod pagination;
pub mod select;
pub mod separator;
pub mod skeleton;
pub mod tabs;
pub mod virtual_list;
