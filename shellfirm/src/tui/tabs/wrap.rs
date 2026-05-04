//! Wrap tab — drill-down model.
//!
//! Only override sections are surfaced in the TUI. The PTY-proxied
//! tools list is configured by editing `wrappers.tools` in the YAML
//! config directly — it's a power-user setting only relevant when
//! using `shellfirm wrap <tool>`.

use crate::checks::Severity;
use crate::config::{Challenge, InheritOr, Mode};
use crate::tui::draft::DraftSettings;
use crate::tui::tabs::{FieldFocus, Tab, TabOutcome};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};

const SECTION_OVR_CHALLENGE: usize = 0;
const SECTION_OVR_MIN_SEV: usize = 1;
const NUM_SECTIONS: usize = 2;

const CHALLENGE_OPTIONS: &[&str] = &["Math", "Enter", "Yes"];
const SEVERITY_OPTIONAL_OPTIONS: &[&str] =
    &["(all)", "Info", "Low", "Medium", "High", "Critical"];

#[derive(Debug, Default)]
pub struct WrapTab {
    pub cursor: usize,
    pub edit: Option<EditState>,
    cached_focus: FieldFocus,
}

impl WrapTab {
    fn compute_focus(&self, _draft: &DraftSettings) -> FieldFocus {
        let title = Self::section_title(self.cursor);
        let (name, help) = if self.edit.is_some() {
            (
                format!("Editing: {title}"),
                "↑↓ navigate · Space to select · Enter to exit · Esc to exit".to_string(),
            )
        } else {
            (title.to_string(), "↑↓ select section · Enter to edit.".to_string())
        };
        FieldFocus { name, badges: vec!["wrap"], help }
    }
}

#[derive(Debug)]
pub enum EditState {
    OvrChallenge(usize),
    OvrMinSev(usize),
}

fn ch_index(c: Challenge) -> usize {
    match c { Challenge::Math => 0, Challenge::Enter => 1, _ => 2 }
}
fn ch_from_idx(i: usize) -> Challenge {
    match i { 1 => Challenge::Enter, 2 => Challenge::Yes, _ => Challenge::Math }
}
fn opt_sev_index(s: Option<Severity>) -> usize {
    match s {
        None => 0, Some(Severity::Info) => 1, Some(Severity::Low) => 2,
        Some(Severity::Medium) => 3, Some(Severity::High) => 4, Some(Severity::Critical) => 5,
    }
}
fn opt_sev_from_idx(i: usize) -> Option<Severity> {
    match i {
        1 => Some(Severity::Info), 2 => Some(Severity::Low), 3 => Some(Severity::Medium),
        4 => Some(Severity::High), 5 => Some(Severity::Critical), _ => None,
    }
}

impl WrapTab {
    fn section_title(s: usize) -> &'static str {
        match s {
            SECTION_OVR_CHALLENGE => "Challenge override (Wrap)",
            SECTION_OVR_MIN_SEV => "Min severity override (Wrap)",
            _ => "",
        }
    }
    fn section_blurb(s: usize) -> &'static str {
        match s {
            SECTION_OVR_CHALLENGE => "Override the global Challenge type for Wrap mode.",
            SECTION_OVR_MIN_SEV => "Override the global Minimum severity for Wrap mode.",
            _ => "",
        }
    }
}

impl Tab for WrapTab {
    fn title(&self) -> &str { "Wrap" }
    fn mode_badge(&self) -> Option<&'static str> { Some("wrap") }

    fn render(&self, area: Rect, buf: &mut Buffer, draft: &DraftSettings) {
        if area.height < 14 || area.width < 60 { return; }
        let mut y = area.y;
        for section in 0..NUM_SECTIONS {
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
            let badge = "[wrap]";
            buf.set_string(
                area.x + area.width.saturating_sub(badge.chars().count() as u16),
                y, badge, Style::default().fg(Color::Yellow),
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
        match self.edit.take() {
            None => self.handle_browsing(key, draft),
            Some(state) => self.handle_editing(key, draft, state),
        }
    }

    fn current_focus(&self) -> FieldFocus {
        let title = Self::section_title(self.cursor);
        let (name, help) = if self.edit.is_some() {
            (format!("Editing: {title}"),
             "↑↓ navigate · Enter commit/exit · Esc cancel".to_string())
        } else {
            (title.to_string(),
             "↑↓ select section · Enter to edit.".to_string())
        };
        FieldFocus { name, badges: vec!["wrap"], help }
    }
}

impl WrapTab {
    fn handle_browsing(&mut self, key: KeyEvent, draft: &mut DraftSettings) -> TabOutcome {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.cursor > 0 {
                    self.cursor -= 1;
                    return TabOutcome::FieldFocusChanged(self.current_focus());
                }
                TabOutcome::None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.cursor + 1 < NUM_SECTIONS {
                    self.cursor += 1;
                    return TabOutcome::FieldFocusChanged(self.current_focus());
                }
                TabOutcome::None
            }
            KeyCode::Enter => {
                self.edit = Some(self.initial_edit_state(draft));
                TabOutcome::FieldFocusChanged(self.current_focus())
            }
            _ => TabOutcome::None,
        }
    }

    fn initial_edit_state(&self, draft: &DraftSettings) -> EditState {
        match self.cursor {
            SECTION_OVR_CHALLENGE => {
                // Cursor 0 = Inherit; cursor 1+i = Set(option i).
                let i = match draft.current.wrappers.challenge {
                    InheritOr::Inherit => 0,
                    InheritOr::Set(c) => ch_index(c) + 1,
                };
                EditState::OvrChallenge(i)
            }
            SECTION_OVR_MIN_SEV => {
                let i = match draft.current.wrappers.min_severity {
                    InheritOr::Inherit => 0,
                    InheritOr::Set(s) => opt_sev_index(s) + 1,
                };
                EditState::OvrMinSev(i)
            }
            _ => EditState::OvrChallenge(0),
        }
    }

    fn handle_editing(
        &mut self, key: KeyEvent, draft: &mut DraftSettings, state: EditState,
    ) -> TabOutcome {
        if matches!(key.code, KeyCode::Esc | KeyCode::Left | KeyCode::Char('h')) {
            self.edit = None;
            return TabOutcome::FieldFocusChanged(self.current_focus());
        }
        match state {
            EditState::OvrChallenge(mut cursor) => {
                // Radio: index 0 = Inherit; 1..=N = Set(CHALLENGE_OPTIONS[i-1]).
                let total = CHALLENGE_OPTIONS.len() + 1;
                match key.code {
                    KeyCode::Up | KeyCode::Char('k') => {
                        if cursor > 0 { cursor -= 1; }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if cursor + 1 < total { cursor += 1; }
                    }
                    KeyCode::Char(' ') => {
                        let new_value = if cursor == 0 {
                            InheritOr::Inherit
                        } else {
                            InheritOr::Set(ch_from_idx(cursor - 1))
                        };
                        let mutated = draft.current.wrappers.challenge != new_value;
                        if mutated {
                            draft.current.wrappers.challenge = new_value;
                        }
                        self.edit = Some(EditState::OvrChallenge(cursor));
                        return if mutated { TabOutcome::Mutated } else { TabOutcome::None };
                    }
                    KeyCode::Enter => {
                        self.edit = None;
                        self.cached_focus = self.compute_focus(draft);
                        return TabOutcome::FieldFocusChanged(self.cached_focus.clone());
                    }
                    _ => {}
                }
                self.edit = Some(EditState::OvrChallenge(cursor));
                TabOutcome::None
            }
            EditState::OvrMinSev(mut cursor) => {
                let total = SEVERITY_OPTIONAL_OPTIONS.len() + 1;
                match key.code {
                    KeyCode::Up | KeyCode::Char('k') => {
                        if cursor > 0 { cursor -= 1; }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if cursor + 1 < total { cursor += 1; }
                    }
                    KeyCode::Char(' ') => {
                        let new_value = if cursor == 0 {
                            InheritOr::Inherit
                        } else {
                            InheritOr::Set(opt_sev_from_idx(cursor - 1))
                        };
                        let mutated = draft.current.wrappers.min_severity != new_value;
                        if mutated {
                            draft.current.wrappers.min_severity = new_value;
                        }
                        self.edit = Some(EditState::OvrMinSev(cursor));
                        return if mutated { TabOutcome::Mutated } else { TabOutcome::None };
                    }
                    KeyCode::Enter => {
                        self.edit = None;
                        self.cached_focus = self.compute_focus(draft);
                        return TabOutcome::FieldFocusChanged(self.cached_focus.clone());
                    }
                    _ => {}
                }
                self.edit = Some(EditState::OvrMinSev(cursor));
                TabOutcome::None
            }
        }
    }

    fn render_summary_body(
        &self, buf: &mut Buffer, area_x: u16, y: u16, area_width: u16,
        draft: &DraftSettings, section: usize, is_focused: bool,
    ) -> u16 {
        let indent = area_x + 2;
        let global = draft.current.resolved_for(Mode::Shell);
        buf.set_string(indent, y, Self::section_blurb(section),
            Style::default().fg(Color::DarkGray));
        let y = y + 1;

        let summary = match section {
            SECTION_OVR_CHALLENGE => match draft.current.wrappers.challenge {
                InheritOr::Inherit => format!("inherits global → {}", global.challenge),
                InheritOr::Set(c) => format!("custom → {c}"),
            },
            SECTION_OVR_MIN_SEV => {
                let inherited = match global.min_severity {
                    None => "(all)".to_string(),
                    Some(s) => format!("{s}"),
                };
                match &draft.current.wrappers.min_severity {
                    InheritOr::Inherit => format!("inherits global → {inherited}"),
                    InheritOr::Set(s) => {
                        let v = match s {
                            None => "(all)".to_string(),
                            Some(s) => format!("{s}"),
                        };
                        format!("custom → {v}")
                    }
                }
            }
            _ => String::new(),
        };
        let max_w = area_width.saturating_sub(2 + 16) as usize;
        let summary = if summary.chars().count() > max_w {
            let mut s: String = summary.chars().take(max_w.saturating_sub(1)).collect();
            s.push('…');
            s
        } else { summary };
        buf.set_string(indent, y, &summary, Style::default().fg(Color::Cyan));
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
        let edit = self.edit.as_ref().expect("editing");

        let render_radio = |buf: &mut Buffer, mut y: u16, options: &[&str],
                            saved: usize, cursor: usize| -> u16 {
            for (i, opt) in options.iter().enumerate() {
                let bullet = if i == saved { "(•)" } else { "( )" };
                let is_cursor = i == cursor;
                let style = if is_cursor {
                    Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD)
                } else if i == saved {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default()
                };
                buf.set_string(indent, y, format!("{bullet} {opt}"), style);
                y += 1;
            }
            y
        };

        match (section, edit) {
            (SECTION_OVR_CHALLENGE, EditState::OvrChallenge(cursor)) => {
                let global = draft.current.resolved_for(Mode::Shell);
                let inherit_label = format!("Inherit global → {}", global.challenge);
                let mut options: Vec<String> = vec![inherit_label];
                options.extend(CHALLENGE_OPTIONS.iter().map(|s| (*s).to_string()));
                let saved = match draft.current.wrappers.challenge {
                    InheritOr::Inherit => 0,
                    InheritOr::Set(c) => ch_index(c) + 1,
                };
                let opt_refs: Vec<&str> = options.iter().map(String::as_str).collect();
                y = render_radio(buf, y, &opt_refs, saved, *cursor);
            }
            (SECTION_OVR_MIN_SEV, EditState::OvrMinSev(cursor)) => {
                let global = draft.current.resolved_for(Mode::Shell);
                let inherited = match global.min_severity {
                    None => "(all)".to_string(),
                    Some(s) => format!("{s}"),
                };
                let inherit_label = format!("Inherit global → {inherited}");
                let mut options: Vec<String> = vec![inherit_label];
                options.extend(SEVERITY_OPTIONAL_OPTIONS.iter().map(|s| (*s).to_string()));
                let saved = match &draft.current.wrappers.min_severity {
                    InheritOr::Inherit => 0,
                    InheritOr::Set(s) => opt_sev_index(*s) + 1,
                };
                let opt_refs: Vec<&str> = options.iter().map(String::as_str).collect();
                y = render_radio(buf, y, &opt_refs, saved, *cursor);
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
    fn fresh() -> (WrapTab, DraftSettings) {
        (WrapTab::default(), DraftSettings::from_settings(Settings::default()))
    }

    #[test]
    fn enter_drills_in() {
        let (mut tab, mut draft) = fresh();
        tab.handle_key(key(KeyCode::Enter), &mut draft);
        assert!(tab.edit.is_some());
    }

    #[test]
    fn challenge_radio_inherit_is_first_choice() {
        let (mut tab, mut draft) = fresh();
        tab.cursor = SECTION_OVR_CHALLENGE;
        // Defaults to Inherit; drilling in places the cursor on index 0 (Inherit).
        tab.handle_key(key(KeyCode::Enter), &mut draft);
        // Down once, Space → commits Set(Math) (CHALLENGE_OPTIONS[0]).
        tab.handle_key(key(KeyCode::Down), &mut draft);
        tab.handle_key(key(KeyCode::Char(' ')), &mut draft);
        assert!(matches!(
            draft.current.wrappers.challenge,
            InheritOr::Set(Challenge::Math)
        ));
    }

    #[test]
    fn challenge_radio_inherit_choice_writes_inherit() {
        let (mut tab, mut draft) = fresh();
        // Start with a Set value
        draft.current.wrappers.challenge = InheritOr::Set(Challenge::Yes);
        tab.cursor = SECTION_OVR_CHALLENGE;
        tab.handle_key(key(KeyCode::Enter), &mut draft);
        // Cursor is at index 1 + ch_index(Yes) = 3. Move up to 0 = Inherit, Space commits.
        for _ in 0..5 {
            tab.handle_key(key(KeyCode::Up), &mut draft);
        }
        tab.handle_key(key(KeyCode::Char(' ')), &mut draft);
        assert!(matches!(
            draft.current.wrappers.challenge,
            InheritOr::Inherit
        ));
    }
}
