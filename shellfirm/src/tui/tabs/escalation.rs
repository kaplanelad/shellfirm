//! Escalation tab — drill-down model.
//!
//! Two sections:
//!   1. Severity escalation (master toggle)
//!   2. Severity → Challenge (5×3 matrix)

use crate::config::Challenge;
use crate::tui::draft::DraftSettings;
use crate::tui::tabs::{FieldFocus, Tab, TabOutcome};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};

const SECTION_TOGGLE: usize = 0;
const SECTION_MATRIX: usize = 1;
const NUM_SECTIONS: usize = 2;

const SEV_LABELS: &[&str] = &["Critical", "High", "Medium", "Low", "Info"];

#[derive(Debug, Default)]
pub struct EscalationTab {
    pub section: usize,
    pub edit: Option<EditState>,
    /// Kept for back-compat with integration tests that read `row`/`col`.
    pub row: usize,
    pub col: usize,
}

#[derive(Debug)]
pub struct EditState {
    /// In matrix edit: which severity row (0..5).
    pub matrix_row: usize,
    /// In matrix edit: which challenge column (0..3).
    pub matrix_col: usize,
}

fn ch_index(c: Challenge) -> usize {
    match c {
        Challenge::Math => 0,
        Challenge::Enter => 1,
        Challenge::Yes => 2,
    }
}

fn ch_from_index(i: usize) -> Challenge {
    match i {
        1 => Challenge::Enter,
        2 => Challenge::Yes,
        _ => Challenge::Math,
    }
}

fn read_cell(draft: &DraftSettings, row_i: usize) -> Challenge {
    let e = &draft.current.severity_escalation;
    match row_i {
        0 => e.critical,
        1 => e.high,
        2 => e.medium,
        3 => e.low,
        _ => e.info,
    }
}

fn write_cell(draft: &mut DraftSettings, row_i: usize, c: Challenge) {
    let e = &mut draft.current.severity_escalation;
    match row_i {
        0 => e.critical = c,
        1 => e.high = c,
        2 => e.medium = c,
        3 => e.low = c,
        _ => e.info = c,
    }
}

impl Tab for EscalationTab {
    fn title(&self) -> &str {
        "Escalation"
    }

    fn render(&self, area: Rect, buf: &mut Buffer, draft: &DraftSettings) {
        if area.height < 14 || area.width < 60 {
            return;
        }
        let mut y = area.y;

        for section in 0..NUM_SECTIONS {
            let is_focused = section == self.section;
            let is_editing_this = is_focused && self.edit.is_some();

            // Section header bar
            let bar_color = if is_editing_this {
                Color::Green
            } else if is_focused {
                Color::Yellow
            } else {
                Color::DarkGray
            };
            buf.set_string(area.x, y, "▌", Style::default().fg(bar_color));

            let title = match section {
                SECTION_TOGGLE => "Severity escalation",
                SECTION_MATRIX => "Severity → Challenge",
                _ => "",
            };
            let title_style = if is_focused {
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
                    .fg(Color::Gray)
                    .add_modifier(Modifier::BOLD)
            };
            buf.set_string(area.x + 2, y, title, title_style);

            let badge = "[all]";
            buf.set_string(
                area.x + area.width.saturating_sub(badge.chars().count() as u16),
                y,
                badge,
                Style::default().fg(Color::DarkGray),
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
        let (name, help) = if self.edit.is_some() {
            match self.section {
                SECTION_TOGGLE => (
                    "Editing: Severity escalation",
                    "Space to toggle · Enter to exit · Esc to exit",
                ),
                SECTION_MATRIX => (
                    "Editing: Severity → Challenge",
                    "↑↓ severity · ←→ challenge · Space to set · Enter to exit · Esc to exit",
                ),
                _ => ("", ""),
            }
        } else {
            match self.section {
                SECTION_TOGGLE => (
                    "Severity escalation",
                    "↑↓ select section · Enter to edit.",
                ),
                SECTION_MATRIX => (
                    "Severity → Challenge",
                    "↑↓ select section · Enter to edit.",
                ),
                _ => ("", ""),
            }
        };
        FieldFocus {
            name: name.into(),
            badges: vec!["all"],
            help: help.into(),
        }
    }
}

impl EscalationTab {
    fn handle_browsing(&mut self, key: KeyEvent, _draft: &mut DraftSettings) -> TabOutcome {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.section > 0 {
                    self.section -= 1;
                    return TabOutcome::FieldFocusChanged(self.current_focus());
                }
                TabOutcome::None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.section + 1 < NUM_SECTIONS {
                    self.section += 1;
                    return TabOutcome::FieldFocusChanged(self.current_focus());
                }
                TabOutcome::None
            }
            KeyCode::Enter => {
                self.edit = Some(EditState {
                    matrix_row: self.row.max(0),
                    matrix_col: self.col,
                });
                TabOutcome::FieldFocusChanged(self.current_focus())
            }
            _ => TabOutcome::None,
        }
    }

    fn handle_editing(
        &mut self,
        key: KeyEvent,
        draft: &mut DraftSettings,
        mut state: EditState,
    ) -> TabOutcome {
        if matches!(key.code, KeyCode::Esc) {
            self.edit = None;
            return TabOutcome::FieldFocusChanged(self.current_focus());
        }
        match self.section {
            SECTION_TOGGLE => {
                match key.code {
                    KeyCode::Char(' ') => {
                        draft.current.severity_escalation.enabled =
                            !draft.current.severity_escalation.enabled;
                        self.edit = Some(state);
                        TabOutcome::Mutated
                    }
                    KeyCode::Enter => {
                        // Enter exits edit mode (toggles commit on Space immediately).
                        self.edit = None;
                        TabOutcome::FieldFocusChanged(self.current_focus())
                    }
                    _ => {
                        self.edit = Some(state);
                        TabOutcome::None
                    }
                }
            }
            SECTION_MATRIX => {
                match key.code {
                    KeyCode::Up | KeyCode::Char('k') => {
                        if state.matrix_row > 0 {
                            state.matrix_row -= 1;
                            // Move column cursor onto current value of new row.
                            state.matrix_col = ch_index(read_cell(draft, state.matrix_row));
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if state.matrix_row + 1 < SEV_LABELS.len() {
                            state.matrix_row += 1;
                            state.matrix_col = ch_index(read_cell(draft, state.matrix_row));
                        }
                    }
                    KeyCode::Left | KeyCode::Char('h') => {
                        if state.matrix_col > 0 {
                            state.matrix_col -= 1;
                        }
                        self.row = state.matrix_row + 1;
                        self.col = state.matrix_col;
                        self.edit = Some(state);
                        return TabOutcome::Consumed;
                    }
                    KeyCode::Right | KeyCode::Char('l') => {
                        if state.matrix_col + 1 < 3 {
                            state.matrix_col += 1;
                        }
                        self.row = state.matrix_row + 1;
                        self.col = state.matrix_col;
                        self.edit = Some(state);
                        return TabOutcome::Consumed;
                    }
                    KeyCode::Char(' ') => {
                        // Space writes the cell at the cursor and stays in edit
                        // mode, so the user can set several cells in one drill-in.
                        let new_value = ch_from_index(state.matrix_col);
                        let mutated = read_cell(draft, state.matrix_row) != new_value;
                        if mutated {
                            write_cell(draft, state.matrix_row, new_value);
                        }
                        self.row = state.matrix_row + 1;
                        self.col = state.matrix_col;
                        self.edit = Some(state);
                        return if mutated {
                            TabOutcome::Mutated
                        } else {
                            TabOutcome::None
                        };
                    }
                    KeyCode::Enter => {
                        // Enter exits edit mode (cells were committed on Space).
                        self.row = state.matrix_row + 1;
                        self.col = state.matrix_col;
                        self.edit = None;
                        return TabOutcome::FieldFocusChanged(self.current_focus());
                    }
                    _ => {}
                }
                self.row = state.matrix_row + 1; // back-compat
                self.col = state.matrix_col;
                self.edit = Some(state);
                TabOutcome::None
            }
            _ => {
                self.edit = Some(state);
                TabOutcome::None
            }
        }
    }

    fn render_summary_body(
        &self,
        buf: &mut Buffer,
        area_x: u16,
        y: u16,
        area_width: u16,
        draft: &DraftSettings,
        section: usize,
        is_focused: bool,
    ) -> u16 {
        let indent = area_x + 2;
        let summary = match section {
            SECTION_TOGGLE => {
                let v = if draft.current.severity_escalation.enabled {
                    "enabled"
                } else {
                    "disabled"
                };
                format!("Currently: {v}")
            }
            SECTION_MATRIX => {
                let e = &draft.current.severity_escalation;
                format!(
                    "Critical→{} · High→{} · Medium→{} · Low→{} · Info→{}",
                    e.critical, e.high, e.medium, e.low, e.info,
                )
            }
            _ => String::new(),
        };
        let max_w = area_width.saturating_sub(2 + 16) as usize;
        let summary = if summary.chars().count() > max_w {
            let mut s: String = summary.chars().take(max_w.saturating_sub(1)).collect();
            s.push('…');
            s
        } else {
            summary
        };
        buf.set_string(indent, y, &summary, Style::default().fg(Color::Cyan));
        if is_focused {
            let hint = "Enter to edit";
            let hint_x = area_x + area_width.saturating_sub(hint.chars().count() as u16);
            buf.set_string(
                hint_x,
                y,
                hint,
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            );
        }
        y + 1
    }

    fn render_editing_body(
        &self,
        buf: &mut Buffer,
        area_x: u16,
        y: u16,
        area_width: u16,
        draft: &DraftSettings,
        section: usize,
    ) -> u16 {
        let indent = area_x + 2;
        let inner_w = area_width.saturating_sub(2);
        buf.set_string(
            indent,
            y,
            "─".repeat(inner_w as usize),
            Style::default().fg(Color::DarkGray),
        );
        let mut y = y + 1;

        match section {
            SECTION_TOGGLE => {
                let on = draft.current.severity_escalation.enabled;
                let value_text = if on {
                    "[ ✓ enabled  ]"
                } else {
                    "[   disabled ]"
                };
                buf.set_string(
                    indent,
                    y,
                    "Severity-based escalation",
                    Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
                );
                buf.set_string(
                    indent + 28,
                    y,
                    value_text,
                    Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD),
                );
                y += 1;
                buf.set_string(
                    indent,
                    y,
                    "When enabled, matched checks at higher severity get a stricter challenge.",
                    Style::default().fg(Color::DarkGray),
                );
                y + 1
            }
            SECTION_MATRIX => {
                let edit = self.edit.as_ref().expect("editing");
                // Column headers
                let label_col = indent;
                let math_col = label_col + 12;
                let enter_col = math_col + 8;
                let yes_col = enter_col + 8;
                let header_style = Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD);
                buf.set_string(label_col, y, "Severity", header_style);
                buf.set_string(math_col, y, "Math", header_style);
                buf.set_string(enter_col, y, "Enter", header_style);
                buf.set_string(yes_col, y, "Yes", header_style);
                y += 1;
                buf.set_string(
                    label_col,
                    y,
                    "─".repeat((yes_col - label_col + 4) as usize),
                    Style::default().fg(Color::DarkGray),
                );
                y += 1;

                for (row_i, sev) in SEV_LABELS.iter().enumerate() {
                    let val = read_cell(draft, row_i);
                    let val_i = ch_index(val);
                    let row_y = y + row_i as u16;
                    let sev_style = if edit.matrix_row == row_i {
                        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    };
                    buf.set_string(label_col, row_y, sev, sev_style);

                    for col_i in 0..3 {
                        let cell_x = match col_i {
                            0 => math_col,
                            1 => enter_col,
                            _ => yes_col,
                        };
                        let mark = if col_i == val_i { "(•)" } else { "( )" };
                        let here = edit.matrix_row == row_i && edit.matrix_col == col_i;
                        let style = if here {
                            Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD)
                        } else if col_i == val_i {
                            Style::default().fg(Color::Cyan)
                        } else {
                            Style::default()
                        };
                        buf.set_string(cell_x, row_y, mark, style);
                    }
                }
                y + SEV_LABELS.len() as u16 + 1
            }
            _ => y,
        }
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

    #[test]
    fn enter_drills_into_section() {
        let mut tab = EscalationTab::default();
        let mut draft = DraftSettings::from_settings(Settings::default());
        tab.handle_key(key(KeyCode::Enter), &mut draft);
        assert!(tab.edit.is_some());
    }

    #[test]
    fn space_in_toggle_section_flips_enabled() {
        let mut tab = EscalationTab::default();
        let mut draft = DraftSettings::from_settings(Settings::default());
        tab.section = SECTION_TOGGLE;
        tab.handle_key(key(KeyCode::Enter), &mut draft);
        let initial = draft.current.severity_escalation.enabled;
        tab.handle_key(key(KeyCode::Char(' ')), &mut draft);
        assert_eq!(draft.current.severity_escalation.enabled, !initial);
    }

    #[test]
    fn matrix_space_writes_cell_and_stays_in_edit_mode() {
        let mut tab = EscalationTab::default();
        let mut draft = DraftSettings::from_settings(Settings::default());
        tab.section = SECTION_MATRIX;
        tab.handle_key(key(KeyCode::Enter), &mut draft);
        // Down to High row, Right twice → Yes column.
        tab.handle_key(key(KeyCode::Down), &mut draft);
        tab.handle_key(key(KeyCode::Right), &mut draft);
        tab.handle_key(key(KeyCode::Right), &mut draft);
        assert_eq!(draft.current.severity_escalation.high, Challenge::Enter);
        // Space writes the cell but stays in edit mode.
        tab.handle_key(key(KeyCode::Char(' ')), &mut draft);
        assert_eq!(draft.current.severity_escalation.high, Challenge::Yes);
        assert!(tab.edit.is_some(), "Space must keep edit mode active");
    }

    #[test]
    fn matrix_space_then_navigate_then_space_writes_multiple_cells() {
        // The whole point of Space-not-Enter for matrix: set several cells
        // in one drill-in.
        let mut tab = EscalationTab::default();
        let mut draft = DraftSettings::from_settings(Settings::default());
        tab.section = SECTION_MATRIX;
        tab.handle_key(key(KeyCode::Enter), &mut draft);
        // High row, Yes column, Space to set.
        tab.handle_key(key(KeyCode::Down), &mut draft);
        tab.handle_key(key(KeyCode::Right), &mut draft);
        tab.handle_key(key(KeyCode::Right), &mut draft);
        tab.handle_key(key(KeyCode::Char(' ')), &mut draft);
        assert_eq!(draft.current.severity_escalation.high, Challenge::Yes);
        // Down to Medium, Right back to Yes is already there since Down resets
        // the column to the saved value (Math = col 0). Space sets Medium = Math.
        tab.handle_key(key(KeyCode::Down), &mut draft);
        tab.handle_key(key(KeyCode::Right), &mut draft);
        tab.handle_key(key(KeyCode::Right), &mut draft);
        tab.handle_key(key(KeyCode::Char(' ')), &mut draft);
        assert_eq!(draft.current.severity_escalation.medium, Challenge::Yes);
        // Both cells changed without re-drilling.
    }

    #[test]
    fn matrix_enter_exits_edit_mode_without_extra_commit() {
        let mut tab = EscalationTab::default();
        let mut draft = DraftSettings::from_settings(Settings::default());
        tab.section = SECTION_MATRIX;
        tab.handle_key(key(KeyCode::Enter), &mut draft);
        // Navigate to a non-saved cell. Cursor is at (0, ch_index(Critical=Yes)) = (0, 2).
        // Down to High → cursor resets to High's saved (Enter = 1). Move to col 0 (Math).
        tab.handle_key(key(KeyCode::Down), &mut draft);
        tab.handle_key(key(KeyCode::Left), &mut draft);
        // High is still Enter — Space wasn't pressed, no write.
        assert_eq!(draft.current.severity_escalation.high, Challenge::Enter);
        // Enter exits without writing.
        tab.handle_key(key(KeyCode::Enter), &mut draft);
        assert_eq!(draft.current.severity_escalation.high, Challenge::Enter,
            "Enter must NOT write the cell — only Space writes");
        assert!(tab.edit.is_none());
    }

    #[test]
    fn esc_exits_editing() {
        let mut tab = EscalationTab::default();
        let mut draft = DraftSettings::from_settings(Settings::default());
        tab.handle_key(key(KeyCode::Enter), &mut draft);
        assert!(tab.edit.is_some());
        tab.handle_key(key(KeyCode::Esc), &mut draft);
        assert!(tab.edit.is_none());
    }

}
