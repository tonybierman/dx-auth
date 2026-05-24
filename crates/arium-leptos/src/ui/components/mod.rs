//! Catalog UI primitives — Leptos ports of the `arium-dioxus` widgets. Each is
//! a thin element wrapper carrying the shared `dx-*` classes + `data-*` state
//! attributes the catalog CSS keys off. Styling is injected once by
//! [`crate::ui::AuthStylesheets`]; the widgets themselves render only markup.

/// Inline SVG glyphs (a lucide subset) so widgets need no icon-font dependency.
pub mod icons;

/// Confirmation dialog with title / description / cancel / action.
pub mod alert_dialog;
/// Round avatar that falls back to initials when an image URL fails to load.
pub mod avatar;
/// Inline status pill used for role / state labels.
pub mod badge;
/// Themed button primitive used by every form in the catalog.
pub mod button;
/// Card surface with optional header, body, and footer subcomponents.
pub mod card;
/// Themed checkbox primitive.
pub mod checkbox;
/// Themed text input primitive.
pub mod input;
/// `<label>` paired with its primitive, with the right `for=` wiring.
pub mod label;
/// Numeric page navigator used by the admin list views.
pub mod pagination;
/// Native-feeling `<select>` styled to match the rest of the catalog.
pub mod select;
/// Horizontal / vertical hairline used between sections.
pub mod separator;
/// Pulsing placeholder used while async data is loading.
pub mod skeleton;
/// Tabbed container.
pub mod tabs;
/// Windowed list that only renders visible rows.
pub mod virtual_list;
