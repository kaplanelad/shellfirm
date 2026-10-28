//! Custom-check authoring form.
//!
//! A standalone widget that the App renders as an overlay when
//! `CustomChecksTab` raises a `PendingAction::Create` or `Edit`.

use crate::checks::{Check, Filter, Severity};
use crate::config::{Challenge, DEFAULT_ENABLED_GROUPS};
use crate::tui::widgets::{
    handle_picker_key, handle_radio_key, Picker, PickerItem, PickerOutcome, PickerState,
    RadioGroup, TextInput,
};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::Widget;
use std::collections::HashSet;

const SEVERITY_OPTIONS: &[&str] = &["Info", "Low", "Medium", "High", "Critical"];
const SEVERITY_DESCRIPTIONS: &[&str] = &[
    "Informational only",
    "Minor risk",
    "Moderate risk (recommended default)",
    "Serious risk",
    "Destructive — almost certainly unrecoverable",
];

const CHALLENGE_OPTIONS: &[&str] = &["Math", "Enter", "Yes"];
const CHALLENGE_DESCRIPTIONS: &[&str] = &[
    "Solve a quick math problem (e.g. 3 + 7 = ?)",
    "Just press Enter to confirm",
    "Type \"yes\" to confirm",
];

/// Tracks IDs already in use across the whole config (built-in + custom).
#[derive(Debug, Clone, Default)]
pub struct IdUniquenessValidator {
    pool: HashSet<String>,
}

impl IdUniquenessValidator {
    #[must_use]
    pub fn new(builtin: Vec<String>, custom: Vec<String>) -> Self {
        let mut pool = HashSet::new();
        pool.extend(builtin);
        pool.extend(custom);
        Self { pool }
    }

    /// True iff `id` is non-empty and not in the pool.
    #[must_use]
    pub fn is_unique(&self, id: &str) -> bool {
        !id.is_empty() && !self.pool.contains(id)
    }

    /// Allow the editor to keep its own ID when editing — call this with
    /// the original ID before `is_unique` checks.
    pub fn allow_existing(&mut self, id: &str) {
        self.pool.remove(id);
    }
}

/// Form mode: are we creating a new check or editing an existing one?
#[derive(Debug, Clone)]
pub enum FormMode {
    Create,
    Edit {
        original_id: String,
        original_from: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormFocus {
    Id,
    From,
    Test,
    Description,
    Severity,
    Challenge,
    Alternative,
    AlternativeInfo,
    Filters,
    Submit,
    Cancel,
}

const FOCUS_ORDER: &[FormFocus] = &[
    FormFocus::Id,
    FormFocus::From,
    FormFocus::Test,
    FormFocus::Description,
    FormFocus::Severity,
    FormFocus::Challenge,
    FormFocus::Alternative,
    FormFocus::AlternativeInfo,
    FormFocus::Filters,
    FormFocus::Submit,
    FormFocus::Cancel,
];

#[derive(Debug)]
pub struct CheckForm {
    pub mode: FormMode,
    pub id_input: TextInput,
    pub from_picker: PickerState,
    pub from_value: String,
    pub from_options: Vec<PickerItem>,
    pub test_input: TextInput,
    pub description_input: TextInput,
    pub severity_idx: usize,
    pub challenge_idx: usize,
    pub alternative_input: TextInput,
    pub alternative_info_input: TextInput,
    pub filters: Vec<Filter>,
    /// Inline filter-add state. None = not adding.
    pub adding_filter: Option<FilterAdd>,
    pub focus_idx: usize,
    pub validator: IdUniquenessValidator,
    /// Last validation error displayed at the bottom of the form.
    pub error_message: Option<String>,
    /// Esc was pressed with input in the form: asking before discarding it.
    pub confirm_discard: bool,
    /// The field values when the form opened (see [`CheckForm::is_dirty`]).
    initial: String,
}

#[derive(Debug, Clone)]
pub enum FilterAdd {
    PickType,
    EnterValue { kind: FilterKind, buffer: String },
}

#[derive(Debug, Clone, Copy)]
pub enum FilterKind {
    Contains,
    NotContains,
}

#[derive(Debug)]
pub enum FormOutcome {
    None,
    /// User pressed Submit and the form was valid; `Check` is the result.
    Saved(Check),
    Cancelled,
}

impl PartialEq for FormOutcome {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::None, Self::None) => true,
            (Self::Cancelled, Self::Cancelled) => true,
            // `Check` does not implement `PartialEq` (it contains a `Regex`),
            // so we compare by `id` + `from` + `description` for test purposes.
            (Self::Saved(a), Self::Saved(b)) => {
                a.id == b.id && a.from == b.from && a.description == b.description
            }
            _ => false,
        }
    }
}

fn ch_idx(c: Challenge) -> usize {
    match c {
        Challenge::Math => 0,
        Challenge::Enter => 1,
        Challenge::Yes => 2,
    }
}
fn ch_from_idx(i: usize) -> Challenge {
    match i {
        1 => Challenge::Enter,
        2 => Challenge::Yes,
        _ => Challenge::Math,
    }
}
fn sev_idx(s: Severity) -> usize {
    match s {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}
fn sev_from_idx(i: usize) -> Severity {
    match i {
        0 => Severity::Info,
        1 => Severity::Low,
        2 => Severity::Medium,
        3 => Severity::High,
        _ => Severity::Critical,
    }
}

impl CheckForm {
    pub fn new_create(validator: IdUniquenessValidator, custom_groups: Vec<String>) -> Self {
        let from_options = build_from_options(&custom_groups);
        Self {
            mode: FormMode::Create,
            id_input: TextInput::default(),
            from_picker: PickerState::default(),
            from_value: String::new(),
            from_options,
            test_input: TextInput::default(),
            description_input: TextInput::default(),
            severity_idx: 2,  // Medium
            challenge_idx: 0, // Math
            alternative_input: TextInput::default(),
            alternative_info_input: TextInput::default(),
            filters: Vec::new(),
            adding_filter: None,
            focus_idx: 0,
            validator,
            error_message: None,
            confirm_discard: false,
            initial: String::new(),
        }
        .with_snapshot()
    }

    pub fn new_edit(
        existing: &Check,
        mut validator: IdUniquenessValidator,
        custom_groups: Vec<String>,
    ) -> Self {
        validator.allow_existing(&existing.id);
        let from_options = build_from_options(&custom_groups);
        Self {
            mode: FormMode::Edit {
                original_id: existing.id.clone(),
                original_from: existing.from.clone(),
            },
            id_input: TextInput::with_value(&existing.id),
            from_picker: PickerState::default(),
            from_value: existing.from.clone(),
            from_options,
            test_input: TextInput::with_value(existing.test.as_str()),
            description_input: TextInput::with_value(&existing.description),
            severity_idx: sev_idx(existing.severity),
            challenge_idx: ch_idx(existing.challenge),
            alternative_input: TextInput::with_value(existing.alternative.as_deref().unwrap_or("")),
            alternative_info_input: TextInput::with_value(
                existing.alternative_info.as_deref().unwrap_or(""),
            ),
            filters: existing.filters.clone(),
            adding_filter: None,
            focus_idx: 0,
            validator,
            error_message: None,
            confirm_discard: false,
            initial: String::new(),
        }
        .with_snapshot()
    }

    fn with_snapshot(mut self) -> Self {
        self.initial = self.snapshot();
        self
    }

    fn snapshot(&self) -> String {
        format!(
            "{}\u{0}{}\u{0}{}\u{0}{}\u{0}{}\u{0}{}\u{0}{}\u{0}{}\u{0}{:?}",
            self.id_input.value(),
            self.from_value,
            self.test_input.value(),
            self.description_input.value(),
            self.severity_idx,
            self.challenge_idx,
            self.alternative_input.value(),
            self.alternative_info_input.value(),
            self.filters
        )
    }

    /// `true` when a field differs from what the form opened with.
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.snapshot() != self.initial
    }

    fn current_focus(&self) -> FormFocus {
        FOCUS_ORDER[self.focus_idx]
    }

    fn next_focus(&mut self) {
        self.focus_idx = (self.focus_idx + 1) % FOCUS_ORDER.len();
        self.sync_group_cursor();
    }

    fn prev_focus(&mut self) {
        self.focus_idx = if self.focus_idx == 0 {
            FOCUS_ORDER.len() - 1
        } else {
            self.focus_idx - 1
        };
        self.sync_group_cursor();
    }

    /// On the Group step with an empty filter, put the list highlight on
    /// the group that is selected (`>` follows `fs`, not the first row).
    fn sync_group_cursor(&mut self) {
        if self.current_focus() != FormFocus::From || !self.from_picker.filter.is_empty() {
            return;
        }
        if let Some(i) = self
            .from_options
            .iter()
            .position(|o| o.value == self.from_value)
        {
            self.from_picker.cursor = i;
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> FormOutcome {
        let before = self.snapshot();
        let outcome = self.handle_key_inner(key);
        // A save error describes the fields as they were: once a field
        // changes it is stale (the live field lines say what is wrong now).
        if self.error_message.is_some() && self.snapshot() != before {
            self.error_message = None;
        }
        outcome
    }

    fn handle_key_inner(&mut self, key: KeyEvent) -> FormOutcome {
        // Filter-adding sub-state takes precedence
        if let Some(state) = self.adding_filter.take() {
            match state {
                FilterAdd::PickType => match key.code {
                    KeyCode::Esc => return FormOutcome::None,
                    KeyCode::Char('c') => {
                        self.adding_filter = Some(FilterAdd::EnterValue {
                            kind: FilterKind::Contains,
                            buffer: String::new(),
                        });
                        return FormOutcome::None;
                    }
                    KeyCode::Char('n') => {
                        self.adding_filter = Some(FilterAdd::EnterValue {
                            kind: FilterKind::NotContains,
                            buffer: String::new(),
                        });
                        return FormOutcome::None;
                    }
                    _ => {
                        self.adding_filter = Some(FilterAdd::PickType);
                        return FormOutcome::None;
                    }
                },
                FilterAdd::EnterValue { kind, mut buffer } => match key.code {
                    KeyCode::Esc => return FormOutcome::None,
                    KeyCode::Enter => {
                        let trimmed = buffer.trim().to_string();
                        if !trimmed.is_empty() {
                            self.filters.push(match kind {
                                FilterKind::Contains => Filter::Contains(trimmed),
                                FilterKind::NotContains => Filter::NotContains(trimmed),
                            });
                        }
                        return FormOutcome::None;
                    }
                    KeyCode::Backspace => {
                        let len = buffer.chars().count();
                        let keep = crate::tui::a11y::prev_cluster(&buffer, len);
                        buffer = buffer.chars().take(keep).collect();
                        self.adding_filter = Some(FilterAdd::EnterValue { kind, buffer });
                        return FormOutcome::None;
                    }
                    KeyCode::Char(c) => {
                        buffer.push(c);
                        self.adding_filter = Some(FilterAdd::EnterValue { kind, buffer });
                        return FormOutcome::None;
                    }
                    _ => {
                        self.adding_filter = Some(FilterAdd::EnterValue { kind, buffer });
                        return FormOutcome::None;
                    }
                },
            }
        }

        // Discard question (after Esc with input): `y` discards, anything
        // else keeps editing.
        if self.confirm_discard {
            self.confirm_discard = false;
            if matches!(key.code, KeyCode::Char('y' | 'Y' | 'd' | 'D')) {
                return FormOutcome::Cancelled;
            }
            return FormOutcome::None;
        }

        // Ctrl-S = save from anywhere
        if key.code == KeyCode::Char('s')
            && key
                .modifiers
                .contains(crossterm::event::KeyModifiers::CONTROL)
        {
            return self.try_submit();
        }

        match key.code {
            // Esc in the Group picker clears its filter first.
            KeyCode::Esc
                if self.current_focus() == FormFocus::From
                    && !self.from_picker.filter.is_empty() =>
            {
                self.from_picker = PickerState::default();
                return FormOutcome::None;
            }
            // One Esc never throws typed input away without asking.
            KeyCode::Esc if self.is_dirty() => {
                self.confirm_discard = true;
                return FormOutcome::None;
            }
            KeyCode::Esc => return FormOutcome::Cancelled,
            KeyCode::Tab => {
                self.next_focus();
                return FormOutcome::None;
            }
            KeyCode::BackTab => {
                self.prev_focus();
                return FormOutcome::None;
            }
            _ => {}
        }

        // Enter on a text-input field: advance to the next field if valid.
        // (For required fields, advance only when validation passes; for
        // optional ones, always advance.)
        let on_text_field = matches!(
            self.current_focus(),
            FormFocus::Id
                | FormFocus::Test
                | FormFocus::Description
                | FormFocus::Alternative
                | FormFocus::AlternativeInfo
        );
        if on_text_field && key.code == KeyCode::Enter {
            self.error_message = None;
            if matches!(
                self.validate_field(self.current_focus()),
                FieldValidity::Valid(_) | FieldValidity::Empty
            ) {
                self.next_focus();
            } else {
                // Surface the inline error so the user knows why advance is blocked.
                if let FieldValidity::Invalid(msg) = self.validate_field(self.current_focus()) {
                    self.error_message = Some(msg);
                }
            }
            return FormOutcome::None;
        }

        match self.current_focus() {
            FormFocus::Id => {
                let _ = self.id_input.handle(key);
                // UX: when the user types an ID like "my_team:foo", pre-fill
                // the Group field with the prefix (everything before the first
                // colon). They can still change it on the Group step. Don't
                // overwrite a user-set value.
                if self.from_value.is_empty() {
                    if let Some(prefix) = self.id_input.value().split(':').next() {
                        let p = prefix.trim();
                        if !p.is_empty() && p.len() < self.id_input.value().trim().len() {
                            self.from_value = p.to_string();
                        }
                    }
                }
            }
            FormFocus::From => {
                let outcome = handle_picker_key(key, &mut self.from_picker, &self.from_options);
                if let PickerOutcome::Selected(value) = outcome {
                    self.from_value = value;
                    self.from_picker = PickerState::default();
                    // Auto-advance after a successful pick.
                    self.next_focus();
                }
            }
            FormFocus::Test => {
                let _ = self.test_input.handle(key);
            }
            FormFocus::Description => {
                let _ = self.description_input.handle(key);
            }
            FormFocus::Severity => {
                if key.code == KeyCode::Enter {
                    self.next_focus();
                } else {
                    self.severity_idx =
                        handle_radio_key(key, self.severity_idx, SEVERITY_OPTIONS.len());
                }
            }
            FormFocus::Challenge => {
                if key.code == KeyCode::Enter {
                    self.next_focus();
                } else {
                    self.challenge_idx =
                        handle_radio_key(key, self.challenge_idx, CHALLENGE_OPTIONS.len());
                }
            }
            FormFocus::Alternative => {
                let _ = self.alternative_input.handle(key);
            }
            FormFocus::AlternativeInfo => {
                let _ = self.alternative_info_input.handle(key);
            }
            FormFocus::Filters => {
                if matches!(key.code, KeyCode::Char('+')) {
                    self.adding_filter = Some(FilterAdd::PickType);
                } else if key.code == KeyCode::Enter {
                    // Enter on Filters with no sub-state: advance.
                    self.next_focus();
                } else if matches!(key.code, KeyCode::Char('d')) {
                    self.filters.pop();
                }
            }
            FormFocus::Submit => {
                if matches!(key.code, KeyCode::Enter | KeyCode::Char(' ')) {
                    return self.try_submit();
                }
            }
            FormFocus::Cancel => {
                if matches!(key.code, KeyCode::Enter | KeyCode::Char(' ')) {
                    return FormOutcome::Cancelled;
                }
            }
        }
        FormOutcome::None
    }

    /// The problems that block saving, in step order: the names of the
    /// required steps that are still empty, and every other error.
    fn blocking_problems(&self) -> (Vec<&'static str>, Vec<String>) {
        let mut missing = Vec::new();
        let mut errors = Vec::new();
        for focus in [
            FormFocus::Id,
            FormFocus::From,
            FormFocus::Test,
            FormFocus::Description,
        ] {
            if let FieldValidity::Invalid(msg) = self.validate_field(focus) {
                let empty = match focus {
                    FormFocus::Id => self.id_input.value().trim().is_empty(),
                    FormFocus::From => self.from_value.trim().is_empty(),
                    FormFocus::Test => self.test_input.value().trim().is_empty(),
                    _ => self.description_input.value().trim().is_empty(),
                };
                if empty {
                    missing.push(Self::focus_label(focus));
                } else {
                    errors.push(msg);
                }
            }
        }
        (missing, errors)
    }

    /// One message naming every problem that blocks saving, or `None`.
    #[must_use]
    pub fn blocking_message(&self) -> Option<String> {
        let (missing, errors) = self.blocking_problems();
        let mut parts = Vec::new();
        if !missing.is_empty() {
            parts.push(format!("Required: {}", missing.join(", ")));
        }
        parts.extend(errors);
        if parts.is_empty() {
            None
        } else {
            Some(parts.join("; "))
        }
    }

    /// Validate every field and build the check (what Save / Ctrl-S do).
    pub fn try_submit(&mut self) -> FormOutcome {
        if let Some(msg) = self.blocking_message() {
            self.error_message = Some(msg);
            return FormOutcome::None;
        }
        let id = self.id_input.value().trim().to_string();
        let from = self.from_value.trim().to_string();
        let test_str = self.test_input.value().trim().to_string();
        let regex = match regex::Regex::new(&test_str) {
            Ok(r) => r,
            Err(e) => {
                self.error_message = Some(format!("Test regex does not compile: {e}"));
                return FormOutcome::None;
            }
        };
        let description = self.description_input.value().trim().to_string();
        let alternative = self.alternative_input.value().trim();
        let alternative_info = self.alternative_info_input.value().trim();

        let check = Check {
            id,
            test: regex.into(),
            description,
            from,
            challenge: ch_from_idx(self.challenge_idx),
            filters: self.filters.clone(),
            alternative: if alternative.is_empty() {
                None
            } else {
                Some(alternative.to_string())
            },
            alternative_info: if alternative_info.is_empty() {
                None
            } else {
                Some(alternative_info.to_string())
            },
            severity: sev_from_idx(self.severity_idx),
        };
        FormOutcome::Saved(check)
    }
}

fn build_from_options(custom_groups: &[String]) -> Vec<PickerItem> {
    let mut out: Vec<PickerItem> = DEFAULT_ENABLED_GROUPS
        .iter()
        .map(|g| PickerItem {
            value: (*g).to_string(),
            badge: Some("built-in"),
            description: None,
        })
        .collect();
    for g in custom_groups {
        if !DEFAULT_ENABLED_GROUPS.contains(&g.as_str()) {
            out.push(PickerItem {
                value: g.clone(),
                badge: Some("custom"),
                description: None,
            });
        }
    }
    out
}

/// Real-time validation result for a single field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldValidity {
    /// Field is filled correctly. Inner string is the success message
    /// (e.g. "Looks good", "Selected: my_team", "regex compiles").
    Valid(String),
    /// Field is empty or malformed. Inner string is shown in red.
    Invalid(String),
    /// Optional field with no input yet; nothing to show.
    Empty,
}

impl CheckForm {
    /// Validate the value currently in `focus` without mutating anything.
    /// Used for live status indicators, the progress trail, and the
    /// "Enter advances" gating.
    pub fn validate_field(&self, focus: FormFocus) -> FieldValidity {
        match focus {
            FormFocus::Id => {
                let v = self.id_input.value().trim();
                if v.is_empty() {
                    FieldValidity::Invalid("Check id is required".into())
                } else if crate::config::check_id_has_hidden_chars(v) {
                    // The loader skips such ids; say so here.
                    FieldValidity::Invalid(format!(
                        "Check id `{}` must not contain spaces, control, bidi or zero-width characters",
                        crate::context::escape_invisible(v)
                    ))
                } else if let Some(problem) = crate::config::check_id_format_problem(v) {
                    FieldValidity::Invalid(problem)
                } else if !self.validator.is_unique(v) {
                    FieldValidity::Invalid("Check id is already in use".into())
                } else {
                    FieldValidity::Valid("Looks good".into())
                }
            }
            FormFocus::From => {
                if self.from_value.trim().is_empty() {
                    FieldValidity::Invalid("Group is required".into())
                } else {
                    FieldValidity::Valid(format!("Selected: {}", self.from_value))
                }
            }
            FormFocus::Test => {
                let v = self.test_input.value().trim();
                if v.is_empty() {
                    FieldValidity::Invalid("Pattern is required".into())
                } else {
                    match regex::Regex::new(v) {
                        Ok(_) => FieldValidity::Valid("Regex compiles".into()),
                        Err(e) => FieldValidity::Invalid(format!("Invalid regex: {e}")),
                    }
                }
            }
            FormFocus::Description => {
                let v = self.description_input.value().trim();
                if v.is_empty() {
                    FieldValidity::Invalid("Description is required".into())
                } else {
                    FieldValidity::Valid("Looks good".into())
                }
            }
            FormFocus::Severity => FieldValidity::Valid(SEVERITY_OPTIONS[self.severity_idx].into()),
            FormFocus::Challenge => {
                FieldValidity::Valid(CHALLENGE_OPTIONS[self.challenge_idx].into())
            }
            FormFocus::Alternative => {
                if self.alternative_input.value().trim().is_empty() {
                    FieldValidity::Empty
                } else {
                    FieldValidity::Valid("Set".into())
                }
            }
            FormFocus::AlternativeInfo => {
                if self.alternative_info_input.value().trim().is_empty() {
                    FieldValidity::Empty
                } else {
                    FieldValidity::Valid("Set".into())
                }
            }
            FormFocus::Filters => {
                if self.filters.is_empty() {
                    FieldValidity::Empty
                } else {
                    FieldValidity::Valid(format!("{} filter(s)", self.filters.len()))
                }
            }
            FormFocus::Submit | FormFocus::Cancel => FieldValidity::Empty,
        }
    }

    /// Short label for the focus target — used in the wizard header.
    fn focus_label(focus: FormFocus) -> &'static str {
        match focus {
            FormFocus::Id => "Check id",
            FormFocus::From => "Group",
            FormFocus::Test => "Test (regex)",
            FormFocus::Description => "Description",
            FormFocus::Severity => "Severity",
            FormFocus::Challenge => "Challenge",
            FormFocus::Alternative => "Alternative",
            FormFocus::AlternativeInfo => "Alternative info",
            FormFocus::Filters => "Filters",
            FormFocus::Submit => "Save",
            FormFocus::Cancel => "Cancel",
        }
    }

    /// Help text for the focused field — shown right under the title so the
    /// user understands the field before filling it.
    fn focus_help(focus: FormFocus) -> &'static str {
        match focus {
            FormFocus::Id => "Unique name for this check across all groups. Format: <group>:<name>. Example: my_team:no_force_push.",
            FormFocus::From => "Pick the category this check belongs to, or type a new name and press Enter to create a new group.",
            FormFocus::Test => "Regular expression that matches the risky command. Validated live as you type. Example: \\bgit\\s+push\\s+--force\\b",
            FormFocus::Description => "Short message shown to the user when the check fires. Explain the risk in one sentence.",
            FormFocus::Severity => "How serious a match is (Info → Critical). Higher severity surfaces a harder challenge and can block the command in AI mode.",
            FormFocus::Challenge => "How the user must confirm: Math (solve a problem), Enter (press Enter), or Yes (type \"yes\"). Math is the default.",
            FormFocus::Alternative => "Optional safer command shown alongside the warning. Purely informational — never auto-run. Example: trash <path> instead of rm -rf <path>.",
            FormFocus::AlternativeInfo => "Optional one-line reason the alternative is safer. Helps the user decide. Example: \"Files go to Trash and can be restored.\"",
            FormFocus::Filters => "Optional conditions that must hold for the check to fire (e.g. file path exists, command contains a word). Press '+' to add, 'd' to remove the last.",
            FormFocus::Submit => "Validate all fields and save the check.",
            FormFocus::Cancel => "Discard the form and return to the Custom tab.",
        }
    }
}

impl Widget for &CheckForm {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.height < 10 || area.width < 40 {
            buf.set_string(
                area.x,
                area.y,
                "Needs at least 40x10",
                Style::default().fg(Color::Yellow),
            );
            return;
        }

        let cur = self.current_focus();
        let total = FOCUS_ORDER.len();

        // ── Inset content from the modal frame so we have breathing room.
        let pad_x = 2u16;
        let inner_x = area.x + pad_x;
        let inner_w = area.width.saturating_sub(pad_x * 2);

        // ── Row 0 (offset 1 from area.y): title with mode + step counter on the right.
        let mode_label = match &self.mode {
            FormMode::Create => "New custom check",
            FormMode::Edit { .. } => "Edit custom check",
        };
        let step_text = format!("Step {}/{}", self.focus_idx + 1, total);
        buf.set_string(
            inner_x,
            area.y + 1,
            mode_label,
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
        buf.set_string(
            inner_x + inner_w.saturating_sub(step_text.chars().count() as u16),
            area.y + 1,
            &step_text,
            Style::default().fg(Color::DarkGray),
        );

        // Small dialogs (the editor's 60x16 minimum gives about 12 rows)
        // drop the decoration first — progress dots, dividers, help text —
        // so the field being typed into, its caret and the validation line
        // always stay on screen.
        let compact = area.height < 20;

        // ── Row 2: progress dots — filled for completed/current, hollow for
        // upcoming. Without Unicode the dots carry nothing the `Step n/m`
        // counter above does not already say, so they are left out.
        let show_dots = crate::tui::a11y::caps().unicode && !compact;
        if show_dots {
            let mut dots = String::new();
            for i in 0..total {
                if i < self.focus_idx {
                    dots.push('●');
                } else if i == self.focus_idx {
                    dots.push('◉');
                } else {
                    dots.push('○');
                }
                dots.push(' ');
            }
            buf.set_string(
                inner_x,
                area.y + 2,
                dots.trim_end(),
                Style::default().fg(Color::Cyan),
            );
        }

        // Divider line
        let divider = "─".repeat(inner_w as usize);
        let divider_y = if compact { area.y + 2 } else { area.y + 3 };
        buf.set_string(
            inner_x,
            divider_y,
            &divider,
            Style::default().fg(Color::DarkGray),
        );

        // ── Footer: [divider], error row, button row, hint. In a compact
        // dialog the divider goes and the error row only when there is an
        // error.
        let notice = self.confirm_discard || self.error_message.is_some();
        let notice_lines = self.notice_lines(inner_w as usize);
        let extra = (notice_lines.len() as u16).saturating_sub(1);
        let footer_height: u16 = match (compact, notice) {
            (false, _) => 4 + extra,
            (true, true) => 3 + extra,
            (true, false) => 2,
        };
        let body_top = if compact { area.y + 3 } else { area.y + 5 };
        let body_bottom = area.y + area.height.saturating_sub(footer_height);
        let body_height = body_bottom.saturating_sub(body_top);

        // Field label (bold, accent color) — full width above the input.
        let label_text = match cur {
            FormFocus::Id => "Check id",
            FormFocus::From => "Group",
            FormFocus::Test => "Test pattern (regex)",
            FormFocus::Description => "Description",
            FormFocus::Severity => "Severity",
            FormFocus::Challenge => "Challenge",
            FormFocus::Alternative => "Alternative (optional)",
            FormFocus::AlternativeInfo => "Why is the alternative safer? (optional)",
            FormFocus::Filters => "Filters (optional)",
            FormFocus::Submit => "Ready to save",
            FormFocus::Cancel => "Cancel",
        };
        buf.set_string(
            inner_x,
            body_top,
            label_text,
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );

        // Rows the field itself needs: a framed text box takes 3, a bare
        // one-line input 1; the other widgets take what is left.
        let text_field = matches!(
            cur,
            FormFocus::Id
                | FormFocus::Test
                | FormFocus::Description
                | FormFocus::Alternative
                | FormFocus::AlternativeInfo
        );
        // A text box needs label + 3 rows + the validation line.
        let boxed = !text_field || body_height >= 5;
        // List steps keep at least three choices (Group: the filter, the
        // count and three rows) on screen; the help text gives way first.
        let field_min: u16 = match cur {
            _ if text_field => {
                if boxed {
                    3
                } else {
                    1
                }
            }
            FormFocus::From | FormFocus::Severity => 5,
            FormFocus::Challenge => 3,
            FormFocus::Filters => 2,
            FormFocus::Submit => self.submit_lines(inner_w as usize).len() as u16,
            _ => 1,
        };
        // The live validation text, wrapped to the dialog (never drawn past
        // its border); a long one takes rows from the help text first.
        let validity = self.validate_field(cur);
        let status_lines = status_lines(&validity, inner_w as usize);
        let status_rows = (status_lines.len() as u16).max(1);
        let spare = body_height.saturating_sub(1 + field_min + status_rows);

        // Description line — right under the title so the user knows what
        // the field is for before they look at the input. It gets only the
        // rows the field and its validation line do not need.
        let help_text = CheckForm::focus_help(cur);
        let max_help = spare.min(2) as usize;
        let mut help_lines = crate::tui::render::wrap_words(help_text, inner_w as usize);
        if help_lines.len() > max_help {
            help_lines.truncate(max_help);
            if let Some(last) = help_lines.last_mut() {
                let keep = (inner_w as usize).saturating_sub(1);
                *last = last.chars().take(keep).collect();
                last.push('…');
            }
        }
        let help_rows = help_lines.len() as u16;
        for (i, line) in help_lines.iter().enumerate() {
            buf.set_string(
                inner_x,
                body_top + 1 + i as u16,
                line,
                Style::default().fg(Color::DarkGray),
            );
        }

        // The field widget, below the description; the validation line
        // goes right under it.
        let field_y = body_top + 1 + help_rows;
        let widget_height = if text_field {
            field_min
        } else {
            body_bottom.saturating_sub(field_y).saturating_sub(1)
        };
        let widget_area = Rect {
            x: inner_x,
            y: field_y,
            width: inner_w,
            height: widget_height,
        };
        if text_field && !boxed {
            if let Some(input) = self.focused_text_input() {
                crate::tui::a11y::draw_text_with_caret(
                    buf,
                    inner_x,
                    field_y,
                    inner_w,
                    input.value(),
                    input.cursor(),
                    true,
                    Style::default().fg(Color::White),
                );
            }
        } else {
            self.render_focused_field(widget_area, buf);
        }

        // ── Status lines: ✓ green / ✗ red / blank (real-time validation),
        // wrapped inside the dialog; cut with `…` when the rows run out.
        let status_y = widget_area.y + widget_area.height;
        let rows = body_bottom.saturating_sub(status_y) as usize;
        let style = match &validity {
            FieldValidity::Invalid(_) => {
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
            }
            _ => Style::default().fg(Color::Green),
        };
        for (i, line) in fit_rows(status_lines, rows, inner_w as usize)
            .iter()
            .enumerate()
        {
            buf.set_stringn(inner_x, status_y + i as u16, line, inner_w as usize, style);
        }

        // ── Footer block (last rows of the area).
        let footer_y = area.y + area.height.saturating_sub(footer_height);
        let mut row = footer_y;
        if !compact {
            buf.set_string(inner_x, row, &divider, Style::default().fg(Color::DarkGray));
            row += 1;
        }
        // Error row (sticky form-level error, e.g. from try_submit()), or
        // the discard question.
        if notice {
            let style = if self.confirm_discard {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
            };
            for line in &notice_lines {
                buf.set_stringn(inner_x, row, line, inner_w as usize, style);
                row += 1;
            }
        } else if !compact {
            row += 1;
        }

        // Button row + Back/Next preview.
        let button_y = row;
        let submit_style = if cur == FormFocus::Submit {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Green)
        };
        let cancel_style = if cur == FormFocus::Cancel {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Red)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Red)
        };
        buf.set_string(inner_x, button_y, "[ Save ]", submit_style);
        buf.set_string(inner_x + 12, button_y, "[ Cancel ]", cancel_style);

        // Right-aligned Back / Next preview
        let back_label = if self.focus_idx > 0 {
            format!(
                "◄ {}",
                CheckForm::focus_label(FOCUS_ORDER[self.focus_idx - 1])
            )
        } else {
            String::new()
        };
        let next_label = if self.focus_idx + 1 < total {
            format!(
                "{} ▶",
                CheckForm::focus_label(FOCUS_ORDER[self.focus_idx + 1])
            )
        } else {
            String::new()
        };
        // Only drawn where it fits right of `[ Cancel ]` (never over it):
        // the full preview, else just the next step, else nothing.
        let buttons_end = 12 + "[ Cancel ]".len() + 2;
        let room = (inner_w as usize).saturating_sub(buttons_end);
        let full = format!("{back_label}    {next_label}");
        let preview = [full.trim().to_string(), next_label.clone()]
            .into_iter()
            .find(|p| !p.is_empty() && p.chars().count() <= room);
        if let Some(preview) = preview {
            let preview_x = inner_x + inner_w.saturating_sub(preview.chars().count() as u16);
            buf.set_string(
                preview_x,
                button_y,
                &preview,
                Style::default().fg(Color::DarkGray),
            );
        }

        // Row +3: keybinding hint
        // Shorter variants for narrow dialogs, so the hint never runs over
        // the right border.
        let hint = [
            " Tab/Shift-Tab navigate · Enter advance · Ctrl-S save · Esc cancel",
            " Tab move · Enter next · Ctrl-S save · Esc cancel",
            " Tab · Enter · ^S save · Esc",
        ]
        .into_iter()
        .find(|h| h.chars().count() <= inner_w as usize)
        .unwrap_or(" ^S save · Esc");
        buf.set_stringn(
            inner_x,
            button_y + 1,
            hint,
            inner_w as usize,
            Style::default().fg(Color::DarkGray),
        );
    }
}

/// The validation text of a field as lines of at most `width` columns:
/// `  ✓  msg` / `  ✗  msg`, continuation lines indented under the message.
/// Each line of a multi-line message (a regex error with its `^` caret)
/// starts a new row and keeps its spacing when it fits.
fn status_lines(validity: &FieldValidity, width: usize) -> Vec<String> {
    let (mark, msg) = match validity {
        FieldValidity::Valid(m) => (crate::tui::a11y::sym("✓", "OK:"), m),
        FieldValidity::Invalid(m) => (crate::tui::a11y::sym("✗", "ERROR:"), m),
        FieldValidity::Empty => return Vec::new(),
    };
    let prefix = format!("  {mark}  ");
    let indent = prefix.chars().count();
    let room = width.saturating_sub(indent).max(1);
    let mut body: Vec<String> = Vec::new();
    for piece in msg.lines().filter(|l| !l.trim().is_empty()) {
        if piece.chars().count() <= room {
            body.push(piece.trim_end().to_string());
        } else {
            body.extend(crate::tui::render::wrap_words(piece, room));
        }
    }
    body.iter()
        .enumerate()
        .map(|(i, l)| {
            if i == 0 {
                format!("{prefix}{l}")
            } else {
                format!("{}{l}", " ".repeat(indent))
            }
        })
        .collect()
}

/// At most `rows` of `lines`; when some are left out the last one shown
/// ends with `…`, so a cut message is never mistaken for a whole one.
fn fit_rows(mut lines: Vec<String>, rows: usize, width: usize) -> Vec<String> {
    if lines.len() > rows {
        lines.truncate(rows);
        if let Some(last) = lines.last_mut() {
            let mark = crate::tui::a11y::sym("…", "...");
            let keep = width
                .saturating_sub(mark.chars().count())
                .min(last.chars().count());
            *last = last
                .chars()
                .take(keep)
                .collect::<String>()
                .trim_end()
                .to_string();
            last.push_str(mark);
        }
    }
    lines
}

/// Render a single-line text input inside a framed box.
fn draw_input_box(input: &TextInput, area: Rect, buf: &mut Buffer) {
    if area.width < 4 || area.height < 3 {
        return;
    }
    let frame_style = Style::default().fg(Color::Cyan);
    let inner_w = area.width.saturating_sub(2);
    let top = format!("╭{}╮", "─".repeat(inner_w as usize));
    let bottom = format!("╰{}╯", "─".repeat(inner_w as usize));
    buf.set_string(area.x, area.y, &top, frame_style);
    buf.set_string(area.x, area.y + 2, &bottom, frame_style);
    buf.set_string(area.x, area.y + 1, "│", frame_style);
    buf.set_string(
        area.x + area.width.saturating_sub(1),
        area.y + 1,
        "│",
        frame_style,
    );
    // The value scrolls horizontally so the caret stays inside the box.
    crate::tui::a11y::draw_text_with_caret(
        buf,
        area.x + 2,
        area.y + 1,
        inner_w.saturating_sub(2),
        input.value(),
        input.cursor(),
        true,
        Style::default().fg(Color::White),
    );
}

impl CheckForm {
    /// The Save step's text, wrapped to `width`.
    fn submit_lines(&self, width: usize) -> Vec<String> {
        let mut lines =
            crate::tui::render::wrap_words("Press Enter to validate and save the check.", width);
        if self.error_message.is_none() {
            let (missing, errors) = self.blocking_problems();
            let text = if !missing.is_empty() {
                format!(
                    "Still needed: {}. Shift-Tab goes back to fill {}.",
                    missing.join(", "),
                    if missing.len() == 1 { "it" } else { "them" }
                )
            } else if !errors.is_empty() {
                format!("Fix first: {}", errors.join("; "))
            } else {
                "All required fields are filled. Shift-Tab goes back to review.".to_string()
            };
            lines.extend(crate::tui::render::wrap_words(&text, width));
        }
        lines
    }

    /// The footer notice (discard question or save error), wrapped to
    /// `width` in at most two rows.
    fn notice_lines(&self, width: usize) -> Vec<String> {
        let text = if self.confirm_discard {
            [
                "Discard this check? y = discard, n or Esc = keep editing",
                "Discard this check? y = discard, n = keep editing",
                "Discard this check? y = discard, n = keep",
                "Discard? y = discard, n = keep",
            ]
            .into_iter()
            .find(|t| t.chars().count() <= width)
            .unwrap_or("Discard? y/n")
            .to_string()
        } else if let Some(err) = &self.error_message {
            format!("{} {err}", crate::tui::a11y::sym("✗", "ERROR:"))
        } else {
            return Vec::new();
        };
        let mut lines = crate::tui::render::wrap_words(&text, width);
        if lines.len() > 2 {
            lines.truncate(2);
            if let Some(last) = lines.last_mut() {
                *last = last.chars().take(width.saturating_sub(1)).collect();
                last.push_str(crate::tui::a11y::sym("…", "~"));
            }
        }
        lines
    }

    /// The text input of the focused field, when it is a text field.
    fn focused_text_input(&self) -> Option<&TextInput> {
        match self.current_focus() {
            FormFocus::Id => Some(&self.id_input),
            FormFocus::Test => Some(&self.test_input),
            FormFocus::Description => Some(&self.description_input),
            FormFocus::Alternative => Some(&self.alternative_input),
            FormFocus::AlternativeInfo => Some(&self.alternative_info_input),
            _ => None,
        }
    }

    /// Render the widget(s) for the currently-focused field at full size.
    /// The outer wizard renders the polished label above this area; this
    /// function only renders the input/widget itself starting at `area.y`.
    fn render_focused_field(&self, area: Rect, buf: &mut Buffer) {
        match self.current_focus() {
            FormFocus::Id => {
                draw_input_box(&self.id_input, area, buf);
            }
            FormFocus::From => {
                // The selected group is named once, on the status line
                // under the list ("✓ Selected: fs").
                Picker {
                    items: &self.from_options,
                    state: &self.from_picker,
                    focused: true,
                    allow_create: true,
                }
                .render(area, buf);
            }
            FormFocus::Test => {
                draw_input_box(&self.test_input, area, buf);
            }
            FormFocus::Description => {
                draw_input_box(&self.description_input, area, buf);
            }
            FormFocus::Severity => {
                RadioGroup::new(SEVERITY_OPTIONS, self.severity_idx, true)
                    .with_descriptions(SEVERITY_DESCRIPTIONS)
                    .render(
                        Rect {
                            x: area.x + 2,
                            y: area.y,
                            width: area.width.saturating_sub(2),
                            height: area.height,
                        },
                        buf,
                    );
            }
            FormFocus::Challenge => {
                RadioGroup::new(CHALLENGE_OPTIONS, self.challenge_idx, true)
                    .with_descriptions(CHALLENGE_DESCRIPTIONS)
                    .render(
                        Rect {
                            x: area.x + 2,
                            y: area.y,
                            width: area.width.saturating_sub(2),
                            height: area.height,
                        },
                        buf,
                    );
            }
            FormFocus::Alternative => {
                draw_input_box(&self.alternative_input, area, buf);
            }
            FormFocus::AlternativeInfo => {
                draw_input_box(&self.alternative_info_input, area, buf);
            }
            FormFocus::Filters => {
                let mut y = area.y;
                for (i, filter) in self.filters.iter().enumerate() {
                    if y >= area.y + area.height {
                        break;
                    }
                    let descr = match filter {
                        Filter::PathExists(idx) => format!("PathExists({idx})"),
                        Filter::Contains(s) => format!("Contains({s:?})"),
                        Filter::NotContains(s) => format!("NotContains({s:?})"),
                        Filter::NotMatches(s) => format!("NotMatches({s:?})"),
                        Filter::Matches(s) => format!("Matches({s:?})"),
                    };
                    buf.set_string(
                        area.x + 2,
                        y,
                        format!("{}. {descr}", i + 1),
                        Style::default(),
                    );
                    y += 1;
                }
                if let Some(state) = &self.adding_filter {
                    let line = match state {
                        FilterAdd::PickType => {
                            " Add filter — c=Contains  n=NotContains  Esc=cancel".to_string()
                        }
                        FilterAdd::EnterValue { kind, buffer } => {
                            let kind_label = match kind {
                                FilterKind::Contains => "Contains",
                                FilterKind::NotContains => "NotContains",
                            };
                            format!(" {kind_label}: {buffer}   (Enter to add, Esc to cancel)")
                        }
                    };
                    buf.set_string(area.x, y, line, Style::default().fg(Color::Yellow));
                    if let FilterAdd::EnterValue { kind, buffer } = state {
                        let kind_label = match kind {
                            FilterKind::Contains => "Contains",
                            FilterKind::NotContains => "NotContains",
                        };
                        crate::tui::a11y::caret_after(
                            buf,
                            area.x,
                            y,
                            &format!(" {kind_label}: {buffer}"),
                        );
                    }
                } else {
                    buf.set_string(
                        area.x,
                        y,
                        " + Add filter (press +)   d to remove last",
                        Style::default().fg(Color::DarkGray),
                    );
                }
            }
            FormFocus::Submit => {
                // Wrapped inside the dialog; names what is still missing
                // instead of claiming the fields look good.
                let missing = self.blocking_message().is_some();
                for (i, line) in self.submit_lines(area.width as usize).iter().enumerate() {
                    if i as u16 >= area.height {
                        break;
                    }
                    let style = if i == 0 {
                        Style::default()
                    } else if missing {
                        Style::default().fg(Color::Yellow)
                    } else {
                        Style::default().fg(Color::DarkGray)
                    };
                    buf.set_stringn(area.x, area.y + i as u16, line, area.width as usize, style);
                }
            }
            FormFocus::Cancel => {
                buf.set_string(
                    area.x,
                    area.y,
                    "Press Enter to discard the form.",
                    Style::default(),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::empty())
    }

    fn fresh_form() -> CheckForm {
        let validator = IdUniquenessValidator::new(vec![], vec![]);
        CheckForm::new_create(validator, vec!["my_team".into()])
    }

    #[test]
    fn id_with_bidi_or_bad_format_is_rejected() {
        // The wizard used to say "Looks good" for `mine:b\u{202e}x`.
        let mut form = fresh_form();
        form.id_input = TextInput::with_value("mine:b\u{202e}x");
        match form.validate_field(FormFocus::Id) {
            FieldValidity::Invalid(m) => assert!(m.contains("\\u{202e}"), "{m}"),
            other => panic!("accepted: {other:?}"),
        }
        form.id_input = TextInput::with_value("mine:Bad Id");
        assert!(matches!(
            form.validate_field(FormFocus::Id),
            FieldValidity::Invalid(_)
        ));
        form.id_input = TextInput::with_value("mine:good_id");
        assert!(matches!(
            form.validate_field(FormFocus::Id),
            FieldValidity::Valid(_)
        ));
    }

    #[test]
    fn id_uniqueness_validator_works() {
        let v = IdUniquenessValidator::new(vec!["git:force".into()], vec!["my:foo".into()]);
        assert!(v.is_unique("new:check"));
        assert!(!v.is_unique("git:force"));
        assert!(!v.is_unique("my:foo"));
        assert!(!v.is_unique(""));
    }

    #[test]
    fn id_uniqueness_validator_allows_existing_for_edit() {
        let mut v = IdUniquenessValidator::new(vec!["git:force".into()], vec!["my:foo".into()]);
        assert!(!v.is_unique("my:foo"));
        v.allow_existing("my:foo");
        assert!(v.is_unique("my:foo"));
    }

    #[test]
    fn empty_form_submit_fails_with_id_error() {
        let mut form = fresh_form();
        // Skip to Submit
        form.focus_idx = FOCUS_ORDER
            .iter()
            .position(|f| *f == FormFocus::Submit)
            .unwrap();
        let outcome = form.handle_key(key(KeyCode::Enter));
        assert_eq!(outcome, FormOutcome::None);
        assert!(form
            .error_message
            .as_deref()
            .unwrap_or("")
            .to_lowercase()
            .contains("id"));
    }

    #[test]
    fn full_form_submit_returns_saved() {
        let mut form = fresh_form();
        // ID — type, Enter advances when valid.
        for c in "my_team:foo".chars() {
            form.handle_key(key(KeyCode::Char(c)));
        }
        form.handle_key(key(KeyCode::Enter));
        // Group — type filter, Enter on picker selects + auto-advances.
        for c in "my_t".chars() {
            form.handle_key(key(KeyCode::Char(c)));
        }
        form.handle_key(key(KeyCode::Enter));
        // Test regex — type, Enter advances.
        for c in "^foo$".chars() {
            form.handle_key(key(KeyCode::Char(c)));
        }
        form.handle_key(key(KeyCode::Enter));
        // Description — type, Enter advances.
        for c in "Test desc".chars() {
            form.handle_key(key(KeyCode::Char(c)));
        }
        form.handle_key(key(KeyCode::Enter));
        // Skip Severity / Challenge / Alternative / AlternativeInfo / Filters via Tab.
        for _ in 0..5 {
            form.handle_key(key(KeyCode::Tab));
        }
        assert_eq!(form.current_focus(), FormFocus::Submit);
        let outcome = form.handle_key(key(KeyCode::Enter));
        if let FormOutcome::Saved(check) = outcome {
            assert_eq!(check.id, "my_team:foo");
            assert_eq!(check.from, "my_team");
            assert_eq!(check.description, "Test desc");
            assert_eq!(check.severity, Severity::Medium);
        } else {
            panic!("expected Saved, got {outcome:?}");
        }
    }

    #[test]
    fn invalid_regex_blocks_submit() {
        let mut form = fresh_form();
        for c in "my:bar".chars() {
            form.handle_key(key(KeyCode::Char(c)));
        }
        form.handle_key(key(KeyCode::Enter));
        for c in "my".chars() {
            form.handle_key(key(KeyCode::Char(c)));
        }
        form.handle_key(key(KeyCode::Enter));
        // Test regex: "[unclosed" — invalid. Pressing Enter should NOT advance.
        for c in "[unclosed".chars() {
            form.handle_key(key(KeyCode::Char(c)));
        }
        form.handle_key(key(KeyCode::Enter));
        assert_eq!(
            form.current_focus(),
            FormFocus::Test,
            "Enter on invalid regex must not advance past the Test field"
        );
        // Move past Test with Tab to test the rest of the flow.
        form.handle_key(key(KeyCode::Tab));
        for c in "Desc".chars() {
            form.handle_key(key(KeyCode::Char(c)));
        }
        for _ in 0..6 {
            form.handle_key(key(KeyCode::Tab));
        }
        let outcome = form.handle_key(key(KeyCode::Enter));
        assert_eq!(outcome, FormOutcome::None);
        assert!(form
            .error_message
            .as_deref()
            .unwrap_or("")
            .to_lowercase()
            .contains("regex"));
    }

    fn screen(form: &CheckForm, w: u16, h: u16) -> (String, Option<(u16, u16)>) {
        crate::tui::a11y::reset_cursor();
        let mut buf = Buffer::empty(Rect::new(0, 0, w, h));
        Widget::render(form, Rect::new(0, 0, w, h), &mut buf);
        let text = (0..h)
            .map(|y| {
                (0..w)
                    .map(|x| buf[(x, y)].symbol().to_string())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        (text, crate::tui::a11y::requested_cursor())
    }

    #[test]
    fn field_and_validation_fit_the_editor_minimum() {
        // At 60x16 the dialog's inner area is 46x12; the field
        // being typed into, its caret and the live check must be visible,
        // and the step preview never overwrites the buttons.
        for (w, h) in [(46u16, 12u16), (46, 16), (66, 16), (78, 20)] {
            let mut form = fresh_form();
            for c in "mine:x".chars() {
                form.handle_key(key(KeyCode::Char(c)));
            }
            let (text, cursor) = screen(&form, w, h);
            assert!(text.contains("mine:x"), "{w}x{h}\n{text}");
            assert!(text.contains("Looks good"), "{w}x{h}\n{text}");
            assert!(cursor.is_some(), "{w}x{h}: no caret");
            assert!(
                text.contains("[ Save ]") && text.contains("[ Cancel ]"),
                "{w}x{h}\n{text}"
            );
            form.handle_key(key(KeyCode::Tab));
            form.handle_key(key(KeyCode::Tab));
            let (text, _) = screen(&form, w, h);
            assert!(text.contains("[ Cancel ]"), "{w}x{h}\n{text}");
        }
    }

    /// The form drawn in a `w`x`h` dialog at the top left of a wider
    /// screen, so anything drawn past the dialog's right edge shows up.
    fn screen_in_wider(form: &CheckForm, w: u16, h: u16) -> Vec<String> {
        let mut buf = Buffer::empty(Rect::new(0, 0, w + 20, h));
        Widget::render(form, Rect::new(0, 0, w, h), &mut buf);
        (0..h)
            .map(|y| {
                (0..w + 20)
                    .map(|x| buf[(x, y)].symbol().to_string())
                    .collect::<String>()
            })
            .collect()
    }

    #[test]
    fn field_errors_wrap_inside_the_dialog() {
        // The editor at 60x16 gives the dialog 46x12, at 80x24 62x19.
        for (w, h) in [(46u16, 12u16), (62, 19)] {
            let mut form = fresh_form();
            form.id_input = TextInput::with_value("mine:b\u{202e}x");
            let rows = screen_in_wider(&form, w, h);
            for row in &rows {
                let outside: String = row.chars().skip(w as usize).collect();
                assert!(
                    outside.trim().is_empty(),
                    "{w}x{h}: past the border: {row:?}"
                );
            }
            let flat = rows
                .iter()
                .flat_map(|r| r.split_whitespace().map(str::to_string).collect::<Vec<_>>())
                .collect::<Vec<_>>()
                .join(" ");
            assert!(
                flat.contains("must not contain spaces, control, bidi or zero-width characters"),
                "{w}x{h}\n{}",
                rows.join("\n")
            );

            // A regex error keeps its caret on its own row, or is cut with `…`.
            goto(&mut form, FormFocus::Test);
            form.test_input = TextInput::with_value("([");
            let rows = screen_in_wider(&form, w, h);
            for row in &rows {
                let outside: String = row.chars().skip(w as usize).collect();
                assert!(
                    outside.trim().is_empty(),
                    "{w}x{h}: past the border: {row:?}"
                );
            }
            let text = rows.join("\n");
            assert!(
                text.contains("error: unclosed") || text.contains('…') || text.contains("..."),
                "{w}x{h}\n{text}"
            );
            if h >= 19 {
                assert!(text.contains("error: unclosed"), "{text}");
                assert!(rows.iter().any(|r| r.trim() == "^"), "caret row\n{text}");
            }
        }
    }

    #[test]
    fn a_cut_status_line_ends_with_a_marker() {
        let lines = vec!["one".to_string(), "two".to_string(), "three".to_string()];
        let cut = fit_rows(lines.clone(), 2, 10);
        let mark = crate::tui::a11y::sym("…", "...");
        assert_eq!(cut, vec!["one".to_string(), format!("two{mark}")]);
        assert_eq!(fit_rows(lines.clone(), 3, 10), lines);
    }

    #[test]
    fn a_save_error_is_cleared_once_a_field_changes() {
        let mut form = fresh_form();
        for c in "mine:b".chars() {
            form.handle_key(key(KeyCode::Char(c)));
        }
        let ctrl_s = KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL);
        assert_eq!(form.handle_key(ctrl_s), FormOutcome::None);
        assert!(form.error_message.is_some());
        let (text, _) = screen(&form, 62, 19);
        assert!(text.contains("Required"), "{text}");
        // Moving between fields keeps it; editing one clears it.
        form.handle_key(key(KeyCode::Tab));
        assert!(form.error_message.is_some());
        form.handle_key(key(KeyCode::BackTab));
        form.handle_key(key(KeyCode::Char('x')));
        assert!(form.error_message.is_none());
        let (text, _) = screen(&form, 62, 19);
        assert!(!text.contains("Required"), "{text}");
    }

    #[test]
    fn esc_asks_before_discarding_input() {
        let mut form = fresh_form();
        for c in "mine:xyz".chars() {
            form.handle_key(key(KeyCode::Char(c)));
        }
        assert_eq!(form.handle_key(key(KeyCode::Esc)), FormOutcome::None);
        assert!(form.confirm_discard);
        let (text, _) = screen(&form, 46, 12);
        assert!(text.contains("Discard this check?"), "{text}");
        // n keeps the draft.
        assert_eq!(form.handle_key(key(KeyCode::Char('n'))), FormOutcome::None);
        assert_eq!(form.id_input.value(), "mine:xyz");
        form.handle_key(key(KeyCode::Esc));
        assert_eq!(
            form.handle_key(key(KeyCode::Char('y'))),
            FormOutcome::Cancelled
        );
    }

    fn goto(form: &mut CheckForm, target: FormFocus) {
        while form.current_focus() != target {
            form.handle_key(key(KeyCode::Tab));
        }
    }

    #[test]
    fn list_steps_show_three_choices_at_the_editor_minimum() {
        // At 60x16 (dialog 46x12) the Group list used to draw no row
        // and Severity hid High / Critical with no marker.
        for (w, h) in [(46u16, 12u16), (66, 20)] {
            let mut form = fresh_form();
            for c in "mine:x".chars() {
                form.handle_key(key(KeyCode::Char(c)));
            }
            form.handle_key(key(KeyCode::Tab));
            let (text, cursor) = screen(&form, w, h);
            let rows = ["aws", "azure", "base"]
                .iter()
                .filter(|g| text.lines().any(|l| l.trim_start().starts_with(*g)))
                .count();
            assert_eq!(rows, 3, "{w}x{h}\n{text}");
            assert!(text.contains("more"), "{w}x{h}\n{text}");
            // The count is on its own row, not over the filter label.
            let label_row = text.lines().find(|l| l.contains("Type to filter")).unwrap();
            assert!(!label_row.contains("shown"), "{label_row}");
            let (cx, cy) = cursor.expect("caret");
            let row: String = text.lines().nth(cy as usize).unwrap().to_string();
            assert!(row.contains("Type to filter"), "caret on {row:?}");
            let colon = row.chars().position(|c| c == ':').unwrap();
            assert!(cx as usize > colon, "caret after the label: {cx} {row:?}");

            goto(&mut form, FormFocus::Severity);
            for _ in 0..2 {
                form.handle_key(key(KeyCode::Down));
            }
            let (text, _) = screen(&form, w, h);
            assert!(text.contains("(•) Critical"), "{w}x{h}\n{text}");
            assert!(text.contains("Info"), "all five fit: {w}x{h}\n{text}");
        }
    }

    #[test]
    fn group_highlight_follows_the_selected_group() {
        let mut form = fresh_form();
        form.from_value = "fs".into();
        goto(&mut form, FormFocus::From);
        let fs = form
            .from_options
            .iter()
            .position(|o| o.value == "fs")
            .unwrap();
        assert_eq!(form.from_picker.cursor, fs);
        form.handle_key(key(KeyCode::Enter));
        assert_eq!(form.from_value, "fs");
    }

    #[test]
    fn save_step_names_every_missing_field_and_stays_inside_the_dialog() {
        // It used to say "Filled fields look good" with every field empty,
        // drawn past the border; Save named only the Group.
        let mut form = fresh_form();
        goto(&mut form, FormFocus::Submit);
        for (w, h) in [(46u16, 12u16), (66, 20)] {
            let (text, _) = screen(&form, w, h);
            assert!(!text.contains("look good"), "{text}");
            let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
            assert!(
                flat.contains("Still needed: Check id, Group, Test (regex),"),
                "{text}"
            );
            for line in text.lines() {
                assert!(line.chars().count() <= w as usize, "{line}");
            }
        }
        assert_eq!(form.handle_key(key(KeyCode::Enter)), FormOutcome::None);
        assert_eq!(
            form.error_message.as_deref(),
            Some("Required: Check id, Group, Test (regex), Description")
        );
        let (text, _) = screen(&form, 46, 12);
        let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(flat.contains("Required: Check id, Group, Test"), "{text}");
        assert!(flat.contains("Description"), "{text}");
        // Filled in: the Save step says so.
        let mut form = fresh_form();
        for c in "mine:x".chars() {
            form.handle_key(key(KeyCode::Char(c)));
        }
        form.test_input = TextInput::with_value("zzqq");
        form.description_input = TextInput::with_value("d");
        goto(&mut form, FormFocus::Submit);
        let (text, _) = screen(&form, 66, 20);
        assert!(text.contains("All required fields are filled"), "{text}");
    }

    #[test]
    fn discard_question_fits_at_sixty_columns() {
        let mut form = fresh_form();
        form.handle_key(key(KeyCode::Char('a')));
        form.handle_key(key(KeyCode::Esc));
        let (text, _) = screen(&form, 46, 12);
        assert!(
            text.contains("Discard this check? y = discard, n = keep"),
            "{text}"
        );
    }

    #[test]
    fn esc_cancels_form() {
        let mut form = fresh_form();
        let outcome = form.handle_key(key(KeyCode::Esc));
        assert_eq!(outcome, FormOutcome::Cancelled);
    }

    #[test]
    fn add_contains_filter() {
        let mut form = fresh_form();
        form.focus_idx = FOCUS_ORDER
            .iter()
            .position(|f| *f == FormFocus::Filters)
            .unwrap();
        // Press + to start filter add → PickType
        form.handle_key(key(KeyCode::Char('+')));
        assert!(matches!(form.adding_filter, Some(FilterAdd::PickType)));
        // Press 'c' to pick Contains
        form.handle_key(key(KeyCode::Char('c')));
        // Type "--no-verify"
        for c in "--no-verify".chars() {
            form.handle_key(key(KeyCode::Char(c)));
        }
        form.handle_key(key(KeyCode::Enter));
        assert_eq!(form.filters.len(), 1);
        assert!(matches!(&form.filters[0], Filter::Contains(s) if s == "--no-verify"));
    }

    #[test]
    fn validate_field_id_empty_is_invalid() {
        let form = fresh_form();
        let v = form.validate_field(FormFocus::Id);
        assert!(matches!(v, FieldValidity::Invalid(msg) if msg.contains("required")));
    }

    #[test]
    fn validate_field_id_unique_is_valid() {
        let mut form = fresh_form();
        for c in "my:thing".chars() {
            form.handle_key(key(KeyCode::Char(c)));
        }
        let v = form.validate_field(FormFocus::Id);
        assert!(matches!(v, FieldValidity::Valid(_)));
    }

    #[test]
    fn validate_field_id_collision_is_invalid() {
        let validator = IdUniquenessValidator::new(vec!["git:force_push".into()], vec![]);
        let mut form = CheckForm::new_create(validator, vec![]);
        for c in "git:force_push".chars() {
            form.handle_key(key(KeyCode::Char(c)));
        }
        let v = form.validate_field(FormFocus::Id);
        assert!(matches!(v, FieldValidity::Invalid(msg) if msg.contains("in use")));
    }

    #[test]
    fn validate_field_test_invalid_regex_is_invalid() {
        let mut form = fresh_form();
        // Move to Test field
        form.focus_idx = FOCUS_ORDER
            .iter()
            .position(|f| *f == FormFocus::Test)
            .unwrap();
        for c in "[unclosed".chars() {
            form.handle_key(key(KeyCode::Char(c)));
        }
        let v = form.validate_field(FormFocus::Test);
        assert!(matches!(v, FieldValidity::Invalid(msg) if msg.contains("Invalid regex")));
    }

    #[test]
    fn validate_field_alternative_empty_is_empty() {
        let form = fresh_form();
        let v = form.validate_field(FormFocus::Alternative);
        assert_eq!(v, FieldValidity::Empty);
    }

    #[test]
    fn enter_on_empty_id_does_not_advance() {
        let mut form = fresh_form();
        assert_eq!(form.current_focus(), FormFocus::Id);
        form.handle_key(key(KeyCode::Enter));
        assert_eq!(
            form.current_focus(),
            FormFocus::Id,
            "Enter on invalid required field must keep focus"
        );
        // Inline error should be set.
        assert!(form.error_message.is_some());
    }

    #[test]
    fn enter_on_valid_id_advances() {
        let mut form = fresh_form();
        for c in "my:thing".chars() {
            form.handle_key(key(KeyCode::Char(c)));
        }
        form.handle_key(key(KeyCode::Enter));
        assert_eq!(form.current_focus(), FormFocus::From);
        assert!(form.error_message.is_none());
    }

    #[test]
    fn picker_select_auto_advances_past_group() {
        let mut form = fresh_form();
        for c in "my_team:x".chars() {
            form.handle_key(key(KeyCode::Char(c)));
        }
        form.handle_key(key(KeyCode::Enter));
        assert_eq!(form.current_focus(), FormFocus::From);
        // Type a unique filter and press Enter to select.
        for c in "my_t".chars() {
            form.handle_key(key(KeyCode::Char(c)));
        }
        // 'x' would have advanced if it matched something; only "my_t" filters to my_team.
        // Wait — actually we need to start fresh because cursor went into From with picker filter.
        // Reset and try again with the right setup:
        let mut form = fresh_form();
        for c in "my:foo".chars() {
            form.handle_key(key(KeyCode::Char(c)));
        }
        form.handle_key(key(KeyCode::Enter)); // advance to From
        assert_eq!(form.current_focus(), FormFocus::From);
        for c in "my_t".chars() {
            form.handle_key(key(KeyCode::Char(c)));
        }
        form.handle_key(key(KeyCode::Enter));
        // After picker Selected, form auto-advances to Test.
        assert_eq!(form.current_focus(), FormFocus::Test);
        assert_eq!(form.from_value, "my_team");
    }

    #[test]
    fn ctrl_s_saves_when_valid() {
        let mut form = fresh_form();
        // Type ID
        for c in "my_team:foo".chars() {
            form.handle_key(key(KeyCode::Char(c)));
        }
        form.handle_key(key(KeyCode::Tab));
        // Pick group
        for c in "my_t".chars() {
            form.handle_key(key(KeyCode::Char(c)));
        }
        // Enter picks the group and moves on to the pattern.
        form.handle_key(key(KeyCode::Enter));
        // Test regex
        for c in "^foo$".chars() {
            form.handle_key(key(KeyCode::Char(c)));
        }
        form.handle_key(key(KeyCode::Tab));
        // Description
        for c in "Test desc".chars() {
            form.handle_key(key(KeyCode::Char(c)));
        }
        // Press Ctrl-S from any field — should validate + save.
        let ctrl_s = KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL);
        let outcome = form.handle_key(ctrl_s);
        match outcome {
            FormOutcome::Saved(check) => {
                assert_eq!(check.id, "my_team:foo");
            }
            other => panic!("expected Saved, got {other:?}"),
        }
    }
}
