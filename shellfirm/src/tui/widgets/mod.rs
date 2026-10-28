//! Reusable TUI widgets.
//!
//! Each widget renders to a `ratatui::buffer::Buffer` and exposes a
//! key-handler helper where applicable.

pub mod multi_select;
pub mod override_field;
pub mod picker;
pub mod radio;
pub mod regex_input;
pub mod stepper;
pub mod text_input;
pub mod toggle;

pub use multi_select::{handle_multi_select_key, MultiSelect, MultiSelectKeyOutcome};
pub use override_field::{OverrideField, OverrideState};
pub use picker::{
    handle_picker_key, handle_picker_key_with, Picker, PickerItem, PickerOutcome, PickerState,
};
pub use radio::{handle_radio_key, RadioGroup};
pub use regex_input::{RegexInput, RegexValidity};
pub use stepper::{handle_stepper_key, Stepper, StepperOutcome};
pub use text_input::{TextInput, TextInputOutcome, TextInputView};
pub use toggle::Toggle;
