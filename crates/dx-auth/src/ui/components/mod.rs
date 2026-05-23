//! Catalog UI primitives installed by `dx components add ...`. They're
//! scoped under `dx_auth::ui::components::*` so consumers can reach them by
//! name, although most consumers only need `dx_auth::ui::LoginPanel`.
//!
//! Each primitive is a thin, scoped copy of the matching widget from the
//! `dioxus-primitives` catalog with the dx-auth CSS module classes wired in.

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
