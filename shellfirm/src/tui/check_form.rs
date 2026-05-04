//! Custom-check authoring form.
//!
//! A standalone widget that the App renders as an overlay when
//! `CustomChecksTab` raises a `PendingAction::Create` or `Edit`.

use crate::checks::{Check, Filter, Severity};
use crate::config::{Challenge, DEFAULT_ENABLED_GROUPS};
use crate::tui::widgets::{
    handle_picker_key, handle_radio_key, Picker, PickerItem, PickerOutcome,
    PickerState, RadioGroup, TextInput,
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
    Edit { original_id: String, original_from: String },
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
        }
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
            alternative_input: TextInput::with_value(
                existing.alternative.as_deref().unwrap_or(""),
            ),
            alternative_info_input: TextInput::with_value(
                existing.alternative_info.as_deref().unwrap_or(""),
            ),
            filters: existing.filters.clone(),
            adding_filter: None,
            focus_idx: 0,
            validator,
            error_message: None,
        }
    }

    fn current_focus(&self) -> FormFocus {
        FOCUS_ORDER[self.focus_idx]
    }

    fn next_focus(&mut self) {
        self.focus_idx = (self.focus_idx + 1) % FOCUS_ORDER.len();
    }

    fn prev_focus(&mut self) {
        self.focus_idx = if self.focus_idx == 0 {
            FOCUS_ORDER.len() - 1
        } else {
            self.focus_idx - 1
        };
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> FormOutcome {
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
                        buffer.pop();
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

        // Ctrl-S = save from anywhere
        if key.code == KeyCode::Char('s')
            && key.modifiers.contains(crossterm::event::KeyModifiers::CONTROL)
        {
            return self.try_submit();
        }

        match key.code {
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

    fn try_submit(&mut self) -> FormOutcome {
        let id = self.id_input.value().trim().to_string();
        if id.is_empty() {
            self.error_message = Some("ID is required.".into());
            return FormOutcome::None;
        }
        if !self.validator.is_unique(&id) {
            self.error_message = Some(format!("ID {id:?} is already in use."));
            return FormOutcome::None;
        }
        let from = self.from_value.trim().to_string();
        if from.is_empty() {
            self.error_message = Some("Group (from) is required.".into());
            return FormOutcome::None;
        }
        let test_str = self.test_input.value().trim().to_string();
        let regex = match regex::Regex::new(&test_str) {
            Ok(r) => r,
            Err(e) => {
                self.error_message = Some(format!("Test regex does not compile: {e}"));
                return FormOutcome::None;
            }
        };
        let description = self.description_input.value().trim().to_string();
        if description.is_empty() {
            self.error_message = Some("Description is required.".into());
            return FormOutcome::None;
        }
        let alternative = self.alternative_input.value().trim();
        let alternative_info = self.alternative_info_input.value().trim();

        let check = Check {
            id,
            test: regex,
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
        })
        .collect();
    for g in custom_groups {
        if !DEFAULT_ENABLED_GROUPS.contains(&g.as_str()) {
            out.push(PickerItem {
                value: g.clone(),
                badge: Some("custom"),
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
                    FieldValidity::Invalid("ID is required".into())
                } else if !self.validator.is_unique(v) {
                    FieldValidity::Invalid("ID is already in use".into())
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
            FormFocus::Challenge => FieldValidity::Valid(CHALLENGE_OPTIONS[self.challenge_idx].into()),
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
            FormFocus::Id => "ID",
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
            buf.set_string(area.x, area.y, "Need ≥ 40×10", Style::default().fg(Color::Yellow));
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
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        );
        buf.set_string(
            inner_x + inner_w.saturating_sub(step_text.chars().count() as u16),
            area.y + 1,
            &step_text,
            Style::default().fg(Color::DarkGray),
        );

        // ── Row 2: progress dots — filled for completed/current, hollow for upcoming.
        let mut dots = String::new();
        for i in 0..total {
            if i < self.focus_idx { dots.push('●'); }
            else if i == self.focus_idx { dots.push('◉'); }
            else { dots.push('○'); }
            dots.push(' ');
        }
        buf.set_string(inner_x, area.y + 2, dots.trim_end(),
            Style::default().fg(Color::Cyan));

        // Divider line
        let divider = "─".repeat(inner_w as usize);
        buf.set_string(inner_x, area.y + 3, &divider, Style::default().fg(Color::DarkGray));

        // ── Body block: from row 5 down to before the footer.
        // Footer = 4 rows: divider, error/empty, button row, hint
        let footer_height = 4u16;
        let body_top = area.y + 5;
        let body_bottom = area.y + area.height.saturating_sub(footer_height);
        let body_height = body_bottom.saturating_sub(body_top).max(3);

        // Field label (bold, accent color) — full width above the input.
        let label_text = match cur {
            FormFocus::Id => "ID",
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
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        );

        // Description line — right under the title so the user knows what
        // the field is for before they look at the input.
        let help_text = CheckForm::focus_help(cur);
        let max_help_w = inner_w as usize;
        let help_truncated = if help_text.chars().count() > max_help_w {
            let mut s: String = help_text.chars().take(max_help_w.saturating_sub(1)).collect();
            s.push('…');
            s
        } else {
            help_text.to_string()
        };
        buf.set_string(
            inner_x,
            body_top + 1,
            &help_truncated,
            Style::default().fg(Color::DarkGray),
        );

        // Field widget rendered inside a framed box for the input row.
        // Shifted down by 1 to make room for the description above.
        let widget_area = Rect {
            x: inner_x,
            y: body_top + 2,
            width: inner_w,
            height: body_height.saturating_sub(4),
        };
        self.render_focused_field(widget_area, buf);

        // ── Status line: ✓ green / ✗ red / blank (real-time validation).
        let validity = self.validate_field(cur);
        let status_y = body_top + 2 + widget_area.height;
        if status_y < body_bottom {
            match &validity {
                FieldValidity::Valid(msg) => {
                    buf.set_string(
                        inner_x,
                        status_y,
                        format!("  ✓  {msg}"),
                        Style::default().fg(Color::Green),
                    );
                }
                FieldValidity::Invalid(msg) => {
                    buf.set_string(
                        inner_x,
                        status_y,
                        format!("  ✗  {msg}"),
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    );
                }
                FieldValidity::Empty => {} // blank — optional field, no input yet
            }
        }

        // ── Footer block (last 4 rows of the area).
        // Top of footer = divider
        let footer_y = area.y + area.height.saturating_sub(footer_height);
        buf.set_string(inner_x, footer_y, &divider, Style::default().fg(Color::DarkGray));

        // Row +1: error message (sticky form-level error, e.g. from try_submit()).
        if let Some(err) = &self.error_message {
            buf.set_string(
                inner_x,
                footer_y + 1,
                format!("  ✗  {err}"),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            );
        }

        // Row +2: button row + Back/Next preview.
        let button_y = footer_y + 2;
        let submit_style = if cur == FormFocus::Submit {
            Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Green)
        };
        let cancel_style = if cur == FormFocus::Cancel {
            Style::default().fg(Color::Black).bg(Color::Red).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Red)
        };
        buf.set_string(inner_x, button_y, "[ Save ]", submit_style);
        buf.set_string(inner_x + 12, button_y, "[ Cancel ]", cancel_style);

        // Right-aligned Back / Next preview
        let back_label = if self.focus_idx > 0 {
            format!("◄ {}", CheckForm::focus_label(FOCUS_ORDER[self.focus_idx - 1]))
        } else {
            String::new()
        };
        let next_label = if self.focus_idx + 1 < total {
            format!("{} ▶", CheckForm::focus_label(FOCUS_ORDER[self.focus_idx + 1]))
        } else {
            String::new()
        };
        let preview = format!("{back_label}    {next_label}");
        let preview_x = inner_x + inner_w.saturating_sub(preview.chars().count() as u16);
        buf.set_string(preview_x, button_y, &preview, Style::default().fg(Color::DarkGray));

        // Row +3: keybinding hint
        buf.set_string(
            inner_x,
            footer_y + 3,
            " Tab/Shift-Tab navigate · Enter advance · Ctrl-S save · Esc cancel",
            Style::default().fg(Color::DarkGray),
        );
    }
}

/// Render a single-line text input inside a framed box.
fn draw_input_box(value: &str, area: Rect, buf: &mut Buffer) {
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
    buf.set_string(area.x + area.width.saturating_sub(1), area.y + 1, "│", frame_style);
    // Truncate value to fit inside the box (account for cursor and padding).
    let max_chars = inner_w.saturating_sub(2) as usize;
    let display_val: String = if value.chars().count() > max_chars {
        let start = value.chars().count() - max_chars;
        value.chars().skip(start).collect()
    } else {
        value.to_string()
    };
    let line = format!(" {display_val}_");
    buf.set_string(area.x + 1, area.y + 1, &line, Style::default().fg(Color::White));
}

impl CheckForm {
    /// Render the widget(s) for the currently-focused field at full size.
    /// The outer wizard renders the polished label above this area; this
    /// function only renders the input/widget itself starting at `area.y`.
    fn render_focused_field(&self, area: Rect, buf: &mut Buffer) {
        match self.current_focus() {
            FormFocus::Id => {
                draw_input_box(self.id_input.value(), area, buf);
            }
            FormFocus::From => {
                let current_label = if self.from_value.is_empty() {
                    "(none selected)".to_string()
                } else {
                    format!("✓ {}", self.from_value)
                };
                buf.set_string(
                    area.x,
                    area.y,
                    format!("Selected: {current_label}"),
                    Style::default().fg(Color::Cyan),
                );
                let picker_area = Rect {
                    x: area.x,
                    y: area.y + 2,
                    width: area.width,
                    height: area.height.saturating_sub(2),
                };
                Picker {
                    items: &self.from_options,
                    state: &self.from_picker,
                    focused: true,
                }
                .render(picker_area, buf);
            }
            FormFocus::Test => {
                draw_input_box(self.test_input.value(), area, buf);
            }
            FormFocus::Description => {
                draw_input_box(self.description_input.value(), area, buf);
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
                draw_input_box(self.alternative_input.value(), area, buf);
            }
            FormFocus::AlternativeInfo => {
                draw_input_box(self.alternative_info_input.value(), area, buf);
            }
            FormFocus::Filters => {
                let mut y = area.y;
                for (i, filter) in self.filters.iter().enumerate() {
                    if y >= area.y + area.height { break; }
                    let descr = match filter {
                        Filter::PathExists(idx) => format!("PathExists({idx})"),
                        Filter::Contains(s) => format!("Contains({s:?})"),
                        Filter::NotContains(s) => format!("NotContains({s:?})"),
                    };
                    buf.set_string(area.x + 2, y, format!("{}. {descr}", i + 1), Style::default());
                    y += 1;
                }
                if let Some(state) = &self.adding_filter {
                    let line = match state {
                        FilterAdd::PickType => " Add filter — c=Contains  n=NotContains  Esc=cancel".to_string(),
                        FilterAdd::EnterValue { kind, buffer } => {
                            let kind_label = match kind {
                                FilterKind::Contains => "Contains",
                                FilterKind::NotContains => "NotContains",
                            };
                            format!(" {kind_label}: {buffer}_  (Enter to add, Esc to cancel)")
                        }
                    };
                    buf.set_string(area.x, y, line, Style::default().fg(Color::Yellow));
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
                buf.set_string(
                    area.x,
                    area.y,
                    "Press Enter to validate and save the check.",
                    Style::default(),
                );
                if self.error_message.is_none() {
                    buf.set_string(
                        area.x,
                        area.y + 2,
                        "Filled fields look good. Use Shift-Tab to go back and review.",
                        Style::default().fg(Color::DarkGray),
                    );
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
        form.focus_idx = FOCUS_ORDER.iter().position(|f| *f == FormFocus::Submit).unwrap();
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
        assert_eq!(form.current_focus(), FormFocus::Test,
            "Enter on invalid regex must not advance past the Test field");
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

    #[test]
    fn esc_cancels_form() {
        let mut form = fresh_form();
        let outcome = form.handle_key(key(KeyCode::Esc));
        assert_eq!(outcome, FormOutcome::Cancelled);
    }

    #[test]
    fn add_contains_filter() {
        let mut form = fresh_form();
        form.focus_idx = FOCUS_ORDER.iter().position(|f| *f == FormFocus::Filters).unwrap();
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
        form.focus_idx = FOCUS_ORDER.iter().position(|f| *f == FormFocus::Test).unwrap();
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
        assert_eq!(form.current_focus(), FormFocus::Id,
            "Enter on invalid required field must keep focus");
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
        for c in "x".chars() {
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
        for c in "my_team:foo".chars() { form.handle_key(key(KeyCode::Char(c))); }
        form.handle_key(key(KeyCode::Tab));
        // Pick group
        for c in "my_t".chars() { form.handle_key(key(KeyCode::Char(c))); }
        form.handle_key(key(KeyCode::Enter));
        form.handle_key(key(KeyCode::Tab));
        // Test regex
        for c in "^foo$".chars() { form.handle_key(key(KeyCode::Char(c))); }
        form.handle_key(key(KeyCode::Tab));
        // Description
        for c in "Test desc".chars() { form.handle_key(key(KeyCode::Char(c))); }
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
