//! Prism eInk UI: host-testable state machine + renderer over `embedded-graphics` (`Gray4`).
//!
//! Feed `UiEvent`s in, get `UiAction`s out, call `Ui::draw` into a `Rotated` adapter of the
//! panel, then refresh the panel as told by `Ui::refresh_hint`.

mod gfx;
mod layout;
mod render;
mod types;
mod ui;

pub use gfx::{Rotated, Rotation, PANEL_H, PANEL_W};
pub use layout::{fmt_datetime, kind_label};
pub use types::*;
pub use ui::{Ui, SetupStep, MAX_PIN, MIN_PIN, MIN_SETUP_PIN};
