//! Reusable TUI widgets.
//!
//! Each widget renders to a `ratatui::buffer::Buffer` and exposes a
//! key-handler helper where applicable.

pub mod toggle;
pub mod radio;
pub mod multi_select;
pub mod picker;
pub mod stepper;
pub mod override_field;
pub mod text_input;
pub mod regex_input;

pub use toggle::Toggle;
pub use radio::{RadioGroup, handle_radio_key};
pub use multi_select::{MultiSelect, MultiSelectKeyOutcome, handle_multi_select_key};
pub use picker::{handle_picker_key, Picker, PickerItem, PickerOutcome, PickerState};
pub use stepper::{Stepper, StepperOutcome, handle_stepper_key};
pub use override_field::{OverrideField, OverrideState};
pub use text_input::{TextInput, TextInputOutcome, TextInputView};
pub use regex_input::{RegexInput, RegexValidity};
