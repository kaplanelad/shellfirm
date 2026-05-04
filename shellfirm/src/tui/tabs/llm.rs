//! LLM tab — drill-down model.
//!
//! Sections (some only visible when LLM is enabled):
//!   1. LLM analysis (master toggle)
//!   2. Provider
//!   3. Model
//!   4. Base URL
//!   5. Timeout
//!   6. Max tokens

use crate::config::LlmConfig;
use crate::tui::draft::DraftSettings;
use crate::tui::tabs::{FieldFocus, Tab, TabOutcome};
use crate::tui::widgets::{
    handle_picker_key, handle_stepper_key, Picker, PickerItem, PickerOutcome, PickerState,
    StepperOutcome, TextInput, TextInputOutcome,
};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::Widget;

const SECTION_ENABLE: usize = 0;
const SECTION_PROVIDER: usize = 1;
const SECTION_MODEL: usize = 2;
const SECTION_BASE_URL: usize = 3;
const SECTION_TIMEOUT: usize = 4;
const SECTION_MAX_TOKENS: usize = 5;
const NUM_SECTIONS_FULL: usize = 6;

#[derive(Debug, Default)]
pub struct LLMTab {
    pub cursor: usize,
    pub edit: Option<EditState>,
    pub provider_picker: PickerState,
    pub model_input: TextInput,
    pub base_url_input: TextInput,
    initialized: bool,
}

#[derive(Debug)]
pub enum EditState {
    Enable,
    Provider,
    Model,
    BaseUrl,
    Timeout,
    MaxTokens,
}

fn provider_items() -> Vec<PickerItem> {
    vec![
        PickerItem { value: "anthropic".into(), badge: Some("known") },
        PickerItem { value: "openai-compatible".into(), badge: Some("known") },
    ]
}

impl LLMTab {
    fn ensure_initialized(&mut self, draft: &DraftSettings) {
        if self.initialized { return; }
        if let Some(llm) = &draft.current.llm {
            self.model_input = TextInput::with_value(&llm.model);
            self.base_url_input = TextInput::with_value(llm.base_url.as_deref().unwrap_or(""));
        }
        self.initialized = true;
    }

    fn flush_inputs_to_draft(&self, draft: &mut DraftSettings) {
        if let Some(llm) = draft.current.llm.as_mut() {
            llm.model = self.model_input.value().to_string();
            let url = self.base_url_input.value().to_string();
            llm.base_url = if url.is_empty() { None } else { Some(url) };
        }
    }

    fn num_sections(draft: &DraftSettings) -> usize {
        if draft.current.llm.is_some() { NUM_SECTIONS_FULL } else { 1 }
    }

    fn section_title(s: usize) -> &'static str {
        match s {
            SECTION_ENABLE => "LLM analysis",
            SECTION_PROVIDER => "Provider",
            SECTION_MODEL => "Model",
            SECTION_BASE_URL => "Base URL",
            SECTION_TIMEOUT => "Timeout",
            SECTION_MAX_TOKENS => "Max tokens",
            _ => "",
        }
    }

    fn section_blurb(s: usize) -> &'static str {
        match s {
            SECTION_ENABLE => "Optional. When enabled, shellfirm asks an LLM to analyse risky commands.",
            SECTION_PROVIDER => "Which LLM service to call.",
            SECTION_MODEL => "Specific model identifier (e.g. claude-sonnet-4-20250514).",
            SECTION_BASE_URL => "Custom base URL (only for openai-compatible providers).",
            SECTION_TIMEOUT => "Request timeout in milliseconds.",
            SECTION_MAX_TOKENS => "Maximum tokens in the LLM response.",
            _ => "",
        }
    }
}

impl Tab for LLMTab {
    fn title(&self) -> &str { "LLM" }

    fn render(&self, area: Rect, buf: &mut Buffer, draft: &DraftSettings) {
        if area.height < 14 || area.width < 60 { return; }
        let n = Self::num_sections(draft);
        let mut y = area.y;
        for section in 0..n {
            let is_focused = section == self.cursor;
            let is_editing_this = is_focused && self.edit.is_some();
            let bar_color = if is_editing_this { Color::Green }
                else if is_focused { Color::Yellow }
                else { Color::DarkGray };
            buf.set_string(area.x, y, "▌", Style::default().fg(bar_color));
            let title_style = if is_focused {
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray).add_modifier(Modifier::BOLD)
            };
            buf.set_string(area.x + 2, y, Self::section_title(section), title_style);
            let badge = "[shell + ai]";
            buf.set_string(
                area.x + area.width.saturating_sub(badge.chars().count() as u16),
                y, badge, Style::default().fg(Color::DarkGray),
            );
            y += 1;
            if is_editing_this {
                y = self.render_editing_body(buf, area.x, y, area.width, draft, section);
            } else {
                y = self.render_summary_body(buf, area.x, y, area.width, draft, section, is_focused);
            }
            y += 1;
        }
    }

    fn handle_key(&mut self, key: KeyEvent, draft: &mut DraftSettings) -> TabOutcome {
        self.ensure_initialized(draft);
        let n = Self::num_sections(draft);
        match self.edit.take() {
            None => match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    if self.cursor > 0 {
                        self.cursor -= 1;
                        return TabOutcome::FieldFocusChanged(self.current_focus());
                    }
                    TabOutcome::None
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if self.cursor + 1 < n {
                        self.cursor += 1;
                        return TabOutcome::FieldFocusChanged(self.current_focus());
                    }
                    TabOutcome::None
                }
                KeyCode::Enter => {
                    self.edit = Some(match self.cursor {
                        SECTION_ENABLE => EditState::Enable,
                        SECTION_PROVIDER => EditState::Provider,
                        SECTION_MODEL => EditState::Model,
                        SECTION_BASE_URL => EditState::BaseUrl,
                        SECTION_TIMEOUT => EditState::Timeout,
                        SECTION_MAX_TOKENS => EditState::MaxTokens,
                        _ => EditState::Enable,
                    });
                    TabOutcome::FieldFocusChanged(self.current_focus())
                }
                _ => TabOutcome::None,
            },
            Some(state) => self.handle_editing(key, draft, state),
        }
    }

    fn current_focus(&self) -> FieldFocus {
        let title = Self::section_title(self.cursor);
        let (name, help) = if self.edit.is_some() {
            (format!("Editing: {title}"), "Esc to go back".to_string())
        } else {
            (title.to_string(), "↑↓ select section · Enter to edit.".to_string())
        };
        FieldFocus { name, badges: vec!["shell", "ai"], help }
    }
}

impl LLMTab {
    fn handle_editing(
        &mut self, key: KeyEvent, draft: &mut DraftSettings, state: EditState,
    ) -> TabOutcome {
        // Esc and Left back out of edit mode (except in Model/BaseUrl where
        // the user is typing — there Left goes to the text input handler).
        if matches!(key.code, KeyCode::Esc) {
            self.edit = None;
            return TabOutcome::FieldFocusChanged(self.current_focus());
        }
        if matches!(key.code, KeyCode::Left | KeyCode::Char('h')) {
            // Left exits unless we're in a text-input section.
            if !matches!(state, EditState::Model | EditState::BaseUrl) {
                self.edit = None;
                return TabOutcome::FieldFocusChanged(self.current_focus());
            }
        }
        match state {
            EditState::Enable => {
                match key.code {
                    KeyCode::Char(' ') => {
                        if draft.current.llm.is_some() {
                            draft.current.llm = None;
                            self.cursor = SECTION_ENABLE;
                            self.initialized = false;
                        } else {
                            draft.current.llm = Some(LlmConfig::default());
                            self.initialized = false;
                            self.ensure_initialized(draft);
                        }
                        self.edit = Some(EditState::Enable);
                        TabOutcome::Mutated
                    }
                    KeyCode::Enter => {
                        // Toggles commit on Space; Enter just exits edit mode.
                        self.edit = None;
                        TabOutcome::FieldFocusChanged(self.current_focus())
                    }
                    _ => {
                        self.edit = Some(EditState::Enable);
                        TabOutcome::None
                    }
                }
            }
            EditState::Provider => {
                let items = provider_items();
                let outcome = handle_picker_key(key, &mut self.provider_picker, &items);
                match outcome {
                    PickerOutcome::Selected(value) => {
                        let mutated = match draft.current.llm.as_mut() {
                            Some(llm) => {
                                let m = llm.provider != value;
                                llm.provider = value;
                                m
                            }
                            None => false,
                        };
                        self.provider_picker = PickerState::default();
                        // Enter on picker commits + exits edit mode.
                        self.edit = None;
                        if mutated {
                            TabOutcome::Mutated
                        } else {
                            TabOutcome::FieldFocusChanged(self.current_focus())
                        }
                    }
                    _ => {
                        self.edit = Some(EditState::Provider);
                        TabOutcome::None
                    }
                }
            }
            EditState::Model => {
                let outcome = self.model_input.handle(key);
                let mutated = matches!(outcome, TextInputOutcome::Changed | TextInputOutcome::Submitted(_));
                if mutated { self.flush_inputs_to_draft(draft); }
                if matches!(outcome, TextInputOutcome::Submitted(_)) {
                    // Enter commits typed value + exits.
                    self.edit = None;
                    return if mutated {
                        TabOutcome::Mutated
                    } else {
                        TabOutcome::FieldFocusChanged(self.current_focus())
                    };
                }
                self.edit = Some(EditState::Model);
                if mutated { TabOutcome::Mutated } else { TabOutcome::None }
            }
            EditState::BaseUrl => {
                let outcome = self.base_url_input.handle(key);
                let mutated = matches!(outcome, TextInputOutcome::Changed | TextInputOutcome::Submitted(_));
                if mutated { self.flush_inputs_to_draft(draft); }
                if matches!(outcome, TextInputOutcome::Submitted(_)) {
                    self.edit = None;
                    return if mutated {
                        TabOutcome::Mutated
                    } else {
                        TabOutcome::FieldFocusChanged(self.current_focus())
                    };
                }
                self.edit = Some(EditState::BaseUrl);
                if mutated { TabOutcome::Mutated } else { TabOutcome::None }
            }
            EditState::Timeout => {
                if matches!(key.code, KeyCode::Enter) {
                    self.edit = None;
                    return TabOutcome::FieldFocusChanged(self.current_focus());
                }
                if let Some(llm) = draft.current.llm.as_mut() {
                    let outcome = handle_stepper_key(key, llm.timeout_ms as i64, 100, 60000);
                    if let StepperOutcome::Changed(v) = outcome {
                        llm.timeout_ms = v as u64;
                        self.edit = Some(EditState::Timeout);
                        return TabOutcome::Mutated;
                    }
                }
                self.edit = Some(EditState::Timeout);
                TabOutcome::None
            }
            EditState::MaxTokens => {
                if matches!(key.code, KeyCode::Enter) {
                    self.edit = None;
                    return TabOutcome::FieldFocusChanged(self.current_focus());
                }
                if let Some(llm) = draft.current.llm.as_mut() {
                    let outcome = handle_stepper_key(key, llm.max_tokens as i64, 1, 8192);
                    if let StepperOutcome::Changed(v) = outcome {
                        llm.max_tokens = v as u32;
                        self.edit = Some(EditState::MaxTokens);
                        return TabOutcome::Mutated;
                    }
                }
                self.edit = Some(EditState::MaxTokens);
                TabOutcome::None
            }
        }
    }

    fn render_summary_body(
        &self, buf: &mut Buffer, area_x: u16, y: u16, area_width: u16,
        draft: &DraftSettings, section: usize, is_focused: bool,
    ) -> u16 {
        let indent = area_x + 2;
        buf.set_string(indent, y, Self::section_blurb(section),
            Style::default().fg(Color::DarkGray));
        let y = y + 1;

        let (summary, color) = match section {
            SECTION_ENABLE => {
                if draft.current.llm.is_some() {
                    ("Currently: ✓ enabled".to_string(), Color::Cyan)
                } else {
                    ("Currently: ✗ disabled".to_string(), Color::DarkGray)
                }
            }
            _ => {
                let llm = match draft.current.llm.as_ref() {
                    Some(l) => l,
                    None => return y,
                };
                match section {
                    SECTION_PROVIDER => (llm.provider.clone(), Color::Cyan),
                    SECTION_MODEL => {
                        if llm.model.is_empty() {
                            ("(empty)".to_string(), Color::DarkGray)
                        } else {
                            (llm.model.clone(), Color::Cyan)
                        }
                    }
                    SECTION_BASE_URL => match &llm.base_url {
                        None => ("(default)".to_string(), Color::DarkGray),
                        Some(u) => (u.clone(), Color::Cyan),
                    },
                    SECTION_TIMEOUT => (format!("{} ms", llm.timeout_ms), Color::Cyan),
                    SECTION_MAX_TOKENS => (format!("{}", llm.max_tokens), Color::Cyan),
                    _ => (String::new(), Color::White),
                }
            }
        };
        buf.set_string(indent, y, &summary, Style::default().fg(color));
        if is_focused {
            let hint = "Enter to edit";
            let hint_x = area_x + area_width.saturating_sub(hint.chars().count() as u16);
            buf.set_string(hint_x, y, hint,
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));
        }
        y + 1
    }

    fn render_editing_body(
        &self, buf: &mut Buffer, area_x: u16, y: u16, area_width: u16,
        draft: &DraftSettings, section: usize,
    ) -> u16 {
        let indent = area_x + 2;
        let inner_w = area_width.saturating_sub(2);
        buf.set_string(indent, y,
            "─".repeat(inner_w as usize),
            Style::default().fg(Color::DarkGray));
        let mut y = y + 1;

        match section {
            SECTION_ENABLE => {
                let on = draft.current.llm.is_some();
                let value = if on { "[ ✓ enabled  ]" } else { "[   disabled ]" };
                buf.set_string(indent, y, "LLM analysis",
                    Style::default().fg(Color::White).add_modifier(Modifier::BOLD));
                buf.set_string(indent + 16, y, value,
                    Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD));
                y += 1;
            }
            SECTION_PROVIDER => {
                let llm = match draft.current.llm.as_ref() {
                    Some(l) => l,
                    None => return y,
                };
                buf.set_string(indent, y,
                    format!("Currently: {}", llm.provider),
                    Style::default().fg(Color::Cyan));
                y += 2;
                let items = provider_items();
                Picker { items: &items, state: &self.provider_picker, focused: true }
                    .render(Rect { x: indent, y, width: inner_w, height: 6 }, buf);
                y += 7;
            }
            SECTION_MODEL => {
                buf.set_string(indent, y, "Model ID:",
                    Style::default().fg(Color::White).add_modifier(Modifier::BOLD));
                y += 1;
                let value = self.model_input.value();
                buf.set_string(indent, y, format!(" {value}_"),
                    Style::default().fg(Color::Cyan));
                y += 1;
            }
            SECTION_BASE_URL => {
                buf.set_string(indent, y, "Base URL (optional):",
                    Style::default().fg(Color::White).add_modifier(Modifier::BOLD));
                y += 1;
                let value = self.base_url_input.value();
                let display = if value.is_empty() {
                    " (default)_".to_string()
                } else {
                    format!(" {value}_")
                };
                buf.set_string(indent, y, display, Style::default().fg(Color::Cyan));
                y += 1;
            }
            SECTION_TIMEOUT => {
                let llm = match draft.current.llm.as_ref() {
                    Some(l) => l,
                    None => return y,
                };
                buf.set_string(indent, y,
                    format!("Currently: {} ms  (range 100–60000)", llm.timeout_ms),
                    Style::default().fg(Color::Cyan));
                y += 1;
            }
            SECTION_MAX_TOKENS => {
                let llm = match draft.current.llm.as_ref() {
                    Some(l) => l,
                    None => return y,
                };
                buf.set_string(indent, y,
                    format!("Currently: {}  (range 1–8192)", llm.max_tokens),
                    Style::default().fg(Color::Cyan));
                y += 1;
            }
            _ => {}
        }
        y
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Settings;
    use crossterm::event::KeyModifiers;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::empty())
    }
    fn fresh() -> (LLMTab, DraftSettings) {
        (LLMTab::default(), DraftSettings::from_settings(Settings::default()))
    }

    #[test]
    fn drill_into_enable_and_toggle() {
        let (mut tab, mut draft) = fresh();
        tab.handle_key(key(KeyCode::Enter), &mut draft);
        assert!(tab.edit.is_some());
        tab.handle_key(key(KeyCode::Char(' ')), &mut draft);
        assert!(draft.current.llm.is_some());
    }

    #[test]
    fn down_navigates_when_enabled() {
        let (mut tab, mut draft) = fresh();
        tab.handle_key(key(KeyCode::Enter), &mut draft);
        tab.handle_key(key(KeyCode::Char(' ')), &mut draft);
        tab.handle_key(key(KeyCode::Esc), &mut draft);
        // Now Down moves to next section.
        tab.handle_key(key(KeyCode::Down), &mut draft);
        assert_eq!(tab.cursor, SECTION_PROVIDER);
    }

    #[test]
    fn timeout_stepper_changes_value() {
        let (mut tab, mut draft) = fresh();
        // Enable
        tab.handle_key(key(KeyCode::Enter), &mut draft);
        tab.handle_key(key(KeyCode::Char(' ')), &mut draft);
        tab.handle_key(key(KeyCode::Esc), &mut draft);
        // Move to Timeout
        tab.cursor = SECTION_TIMEOUT;
        tab.handle_key(key(KeyCode::Enter), &mut draft);
        let initial = draft.current.llm.as_ref().unwrap().timeout_ms;
        tab.handle_key(key(KeyCode::Up), &mut draft);
        let after = draft.current.llm.as_ref().unwrap().timeout_ms;
        assert_eq!(after, initial + 1);
    }

    #[test]
    fn typing_changes_model_value() {
        let (mut tab, mut draft) = fresh();
        tab.handle_key(key(KeyCode::Enter), &mut draft);
        tab.handle_key(key(KeyCode::Char(' ')), &mut draft);
        tab.handle_key(key(KeyCode::Esc), &mut draft);
        tab.cursor = SECTION_MODEL;
        tab.handle_key(key(KeyCode::Enter), &mut draft);
        let initial_model = draft.current.llm.as_ref().unwrap().model.clone();
        tab.handle_key(key(KeyCode::Char('x')), &mut draft);
        assert_eq!(draft.current.llm.as_ref().unwrap().model, format!("{initial_model}x"));
    }

}
