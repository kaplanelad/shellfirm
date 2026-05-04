//! General tab — drill-down model.
//!
//! Browsing mode:  ↑↓ moves the cursor between three sections
//!                 (Challenge type, Minimum severity, Behavior).
//!                 Enter drills into the focused section.
//! Editing mode:   ↑↓ navigates options inside the active section.
//!                 Space commits the highlighted option.
//!                 Esc returns to Browsing mode.

use crate::checks::Severity;
use crate::config::Challenge;
use crate::tui::draft::DraftSettings;
use crate::tui::tabs::{FieldFocus, Tab, TabOutcome};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};

const SECTION_CHALLENGE: usize = 0;
const SECTION_SEVERITY: usize = 1;
const SECTION_BEHAVIOR: usize = 2;
const NUM_SECTIONS: usize = 3;

const CHALLENGE_OPTIONS: &[&str] = &["Math", "Enter", "Yes"];
const CHALLENGE_DESCRIPTIONS: &[&str] = &[
    "Solve a quick math problem (e.g. 3 + 7 = ?)",
    "Just press Enter to confirm",
    "Type \"yes\" to confirm",
];

const SEVERITY_OPTIONS: &[&str] = &["(all)", "Info", "Low", "Medium", "High", "Critical"];
const SEVERITY_DESCRIPTIONS: &[&str] = &[
    "Trigger on every match (paranoid)",
    "Informational only",
    "Minor risk",
    "Moderate risk (recommended)",
    "Serious risk",
    "Destructive — almost certainly unrecoverable",
];

#[derive(Debug, Default)]
pub struct GeneralTab {
    /// Which section header the cursor sits on (0..NUM_SECTIONS).
    pub section: usize,
    /// `None` = Browsing. `Some(inner)` = Editing the section, with the
    /// inner cursor at row `inner`.
    pub edit_cursor: Option<usize>,
}

fn challenge_index(c: Challenge) -> usize {
    match c {
        Challenge::Math => 0,
        Challenge::Enter => 1,
        Challenge::Yes => 2,
    }
}
fn challenge_from_index(i: usize) -> Challenge {
    match i {
        1 => Challenge::Enter,
        2 => Challenge::Yes,
        _ => Challenge::Math,
    }
}
fn severity_index(s: Option<Severity>) -> usize {
    match s {
        None => 0,
        Some(Severity::Info) => 1,
        Some(Severity::Low) => 2,
        Some(Severity::Medium) => 3,
        Some(Severity::High) => 4,
        Some(Severity::Critical) => 5,
    }
}
fn severity_from_index(i: usize) -> Option<Severity> {
    match i {
        1 => Some(Severity::Info),
        2 => Some(Severity::Low),
        3 => Some(Severity::Medium),
        4 => Some(Severity::High),
        5 => Some(Severity::Critical),
        _ => None,
    }
}

fn section_options_count(section: usize) -> usize {
    match section {
        SECTION_CHALLENGE => CHALLENGE_OPTIONS.len(),
        SECTION_SEVERITY => SEVERITY_OPTIONS.len(),
        SECTION_BEHAVIOR => 2, // Audit, Blast radius
        _ => 0,
    }
}

fn initial_inner_cursor(section: usize, draft: &DraftSettings) -> usize {
    match section {
        SECTION_CHALLENGE => challenge_index(draft.current.challenge),
        SECTION_SEVERITY => severity_index(draft.current.min_severity),
        SECTION_BEHAVIOR => 0,
        _ => 0,
    }
}

impl GeneralTab {
    fn is_editing(&self) -> bool {
        self.edit_cursor.is_some()
    }

    fn focus_for_browsing(section: usize) -> FieldFocus {
        let (name, help) = match section {
            SECTION_CHALLENGE => (
                "Challenge type",
                "↑↓ navigate sections · Enter to edit · Tab next.",
            ),
            SECTION_SEVERITY => (
                "Minimum severity",
                "↑↓ navigate sections · Enter to edit · Tab next.",
            ),
            SECTION_BEHAVIOR => (
                "Behavior",
                "↑↓ navigate sections · Enter to edit · Tab next.",
            ),
            _ => ("", ""),
        };
        FieldFocus {
            name: name.into(),
            badges: vec!["all"],
            help: help.into(),
        }
    }

    fn focus_for_editing(section: usize) -> FieldFocus {
        let (name, help) = match section {
            SECTION_CHALLENGE => (
                "Editing: Challenge type",
                "↑↓ navigate · Space to select · Enter to exit · Esc to exit.",
            ),
            SECTION_SEVERITY => (
                "Editing: Minimum severity",
                "↑↓ navigate · Space to select · Enter to exit · Esc to exit.",
            ),
            SECTION_BEHAVIOR => (
                "Editing: Behavior",
                "↑↓ navigate · Space to toggle · Enter to exit · Esc to exit.",
            ),
            _ => ("", ""),
        };
        FieldFocus {
            name: name.into(),
            badges: vec!["all"],
            help: help.into(),
        }
    }
}

impl Tab for GeneralTab {
    fn title(&self) -> &str {
        "General"
    }

    fn render(&self, area: Rect, buf: &mut Buffer, draft: &DraftSettings) {
        if area.height < 16 || area.width < 50 {
            return;
        }

        let mut y = area.y;
        for section in 0..NUM_SECTIONS {
            let is_focused = section == self.section;
            let is_editing_this = is_focused && self.is_editing();

            // Bar color: yellow when focused (browsing), green when editing,
            // dim when other.
            let bar_color = if is_editing_this {
                Color::Green
            } else if is_focused {
                Color::Yellow
            } else {
                Color::DarkGray
            };
            buf.set_string(area.x, y, "▌", Style::default().fg(bar_color));

            // Section title
            let title = match section {
                SECTION_CHALLENGE => "Challenge type",
                SECTION_SEVERITY => "Minimum severity",
                SECTION_BEHAVIOR => "Behavior",
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

            // Right-aligned [all] badge
            let badge = "[all]";
            buf.set_string(
                area.x + area.width.saturating_sub(badge.chars().count() as u16),
                y,
                badge,
                Style::default().fg(Color::DarkGray),
            );

            y += 1;

            // Section body
            if is_editing_this {
                y = self.render_editing_body(buf, area.x, y, area.width, draft, section);
            } else {
                y = render_summary_body(buf, area.x, y, area.width, draft, section, is_focused);
            }

            y += 1; // blank line between sections
        }
    }

    fn handle_key(&mut self, key: KeyEvent, draft: &mut DraftSettings) -> TabOutcome {
        match self.edit_cursor {
            None => {
                // Browsing mode — ↑↓/jk navigate sections; Enter/→ drills in.
                // ← / → at the App level switch top-level tabs, so we let
                // them fall through (return None) here.
                match key.code {
                    KeyCode::Up | KeyCode::Char('k') => {
                        if self.section > 0 {
                            self.section -= 1;
                            return TabOutcome::FieldFocusChanged(Self::focus_for_browsing(
                                self.section,
                            ));
                        }
                        TabOutcome::None
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if self.section + 1 < NUM_SECTIONS {
                            self.section += 1;
                            return TabOutcome::FieldFocusChanged(Self::focus_for_browsing(
                                self.section,
                            ));
                        }
                        TabOutcome::None
                    }
                    KeyCode::Enter | KeyCode::Char('l') => {
                        let inner = initial_inner_cursor(self.section, draft);
                        self.edit_cursor = Some(inner);
                        TabOutcome::FieldFocusChanged(Self::focus_for_editing(self.section))
                    }
                    _ => TabOutcome::None,
                }
            }
            Some(mut inner) => {
                // Editing mode — Left also exits (alias for Esc).
                let count = section_options_count(self.section);
                match key.code {
                    KeyCode::Esc | KeyCode::Left | KeyCode::Char('h') => {
                        self.edit_cursor = None;
                        TabOutcome::FieldFocusChanged(Self::focus_for_browsing(self.section))
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        if inner > 0 {
                            inner -= 1;
                        }
                        self.edit_cursor = Some(inner);
                        TabOutcome::None
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if inner + 1 < count {
                            inner += 1;
                        }
                        self.edit_cursor = Some(inner);
                        TabOutcome::None
                    }
                    KeyCode::Char(' ') => {
                        // Space writes the cursor's value to the draft (and
                        // stays in edit mode so the user can continue, or
                        // press Enter to exit).
                        let mutated = match self.section {
                            SECTION_CHALLENGE => {
                                let new_c = challenge_from_index(inner);
                                if draft.current.challenge != new_c {
                                    draft.current.challenge = new_c;
                                    true
                                } else {
                                    false
                                }
                            }
                            SECTION_SEVERITY => {
                                let new_s = severity_from_index(inner);
                                if draft.current.min_severity != new_s {
                                    draft.current.min_severity = new_s;
                                    true
                                } else {
                                    false
                                }
                            }
                            SECTION_BEHAVIOR => {
                                if inner == 0 {
                                    draft.current.audit_enabled = !draft.current.audit_enabled;
                                } else {
                                    draft.current.blast_radius = !draft.current.blast_radius;
                                }
                                true
                            }
                            _ => false,
                        };
                        if mutated { TabOutcome::Mutated } else { TabOutcome::None }
                    }
                    KeyCode::Enter => {
                        // Enter exits edit mode (Space already wrote the value).
                        self.edit_cursor = None;
                        TabOutcome::FieldFocusChanged(Self::focus_for_browsing(self.section))
                    }
                    _ => TabOutcome::None,
                }
            }
        }
    }

    fn current_focus(&self) -> FieldFocus {
        if self.is_editing() {
            Self::focus_for_editing(self.section)
        } else {
            Self::focus_for_browsing(self.section)
        }
    }
}

/// Render a section's summary line (when not in edit mode).
fn render_summary_body(
    buf: &mut Buffer,
    area_x: u16,
    y: u16,
    area_width: u16,
    draft: &DraftSettings,
    section: usize,
    is_focused: bool,
) -> u16 {
    let indent_x = area_x + 2;
    let value_text = match section {
        SECTION_CHALLENGE => format!("Currently: {}", draft.current.challenge),
        SECTION_SEVERITY => {
            let v = match draft.current.min_severity {
                None => "(all)".to_string(),
                Some(s) => format!("{s}"),
            };
            format!("Currently: {v}")
        }
        SECTION_BEHAVIOR => {
            let mark = |on: bool| if on { "✓" } else { "✗" };
            format!(
                "Audit: {}  ·  Blast radius: {}",
                mark(draft.current.audit_enabled),
                mark(draft.current.blast_radius),
            )
        }
        _ => String::new(),
    };
    buf.set_string(
        indent_x,
        y,
        &value_text,
        Style::default().fg(Color::Cyan),
    );

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

impl GeneralTab {
    fn render_editing_body(
        &self,
        buf: &mut Buffer,
        area_x: u16,
        y: u16,
        area_width: u16,
        draft: &DraftSettings,
        section: usize,
    ) -> u16 {
        let inner = self.edit_cursor.unwrap_or(0);
        let indent_x = area_x + 2;

        // Divider line below the section header
        let divider_w = area_width.saturating_sub(2) as usize;
        buf.set_string(
            indent_x,
            y,
            "─".repeat(divider_w),
            Style::default().fg(Color::DarkGray),
        );
        let mut y = y + 1;

        match section {
            SECTION_CHALLENGE => {
                let saved = challenge_index(draft.current.challenge);
                for (i, label) in CHALLENGE_OPTIONS.iter().enumerate() {
                    let bullet = if i == saved { "(•)" } else { "( )" };
                    let highlight = i == inner;
                    let line_style = if highlight {
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Green)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    };
                    let line = format!(
                        "{bullet} {label:<8}  {desc}",
                        desc = CHALLENGE_DESCRIPTIONS[i]
                    );
                    buf.set_string(indent_x, y, line, line_style);
                    y += 1;
                }
            }
            SECTION_SEVERITY => {
                let saved = severity_index(draft.current.min_severity);
                for (i, label) in SEVERITY_OPTIONS.iter().enumerate() {
                    let bullet = if i == saved { "(•)" } else { "( )" };
                    let highlight = i == inner;
                    let line_style = if highlight {
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Green)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    };
                    let line = format!(
                        "{bullet} {label:<10}  {desc}",
                        desc = SEVERITY_DESCRIPTIONS[i]
                    );
                    buf.set_string(indent_x, y, line, line_style);
                    y += 1;
                }
            }
            SECTION_BEHAVIOR => {
                let toggles = [
                    ("Audit log", draft.current.audit_enabled),
                    ("Blast radius", draft.current.blast_radius),
                ];
                for (i, (label, on)) in toggles.iter().enumerate() {
                    let highlight = i == inner;
                    let label_style = if highlight {
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Green)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    };
                    buf.set_string(indent_x, y, label, label_style);
                    let value = if *on {
                        "[ ✓ enabled  ]"
                    } else {
                        "[   disabled ]"
                    };
                    let value_style = if highlight {
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Green)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::Cyan)
                    };
                    buf.set_string(indent_x + 16, y, value, value_style);
                    y += 1;
                }
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

    fn fresh() -> (GeneralTab, DraftSettings) {
        (
            GeneralTab::default(),
            DraftSettings::from_settings(Settings::default()),
        )
    }

    #[test]
    fn down_in_browsing_moves_section() {
        let (mut tab, mut draft) = fresh();
        let _ = tab.handle_key(key(KeyCode::Down), &mut draft);
        assert_eq!(tab.section, SECTION_SEVERITY);
        assert!(tab.edit_cursor.is_none()); // still browsing
    }

    #[test]
    fn enter_in_browsing_drills_in() {
        let (mut tab, mut draft) = fresh();
        tab.section = SECTION_SEVERITY;
        let _ = tab.handle_key(key(KeyCode::Enter), &mut draft);
        assert!(tab.edit_cursor.is_some());
        // Inner cursor starts at the saved value (default = None → idx 0).
        assert_eq!(tab.edit_cursor, Some(0));
    }

    #[test]
    fn esc_in_editing_returns_to_browsing() {
        let (mut tab, mut draft) = fresh();
        tab.section = SECTION_SEVERITY;
        tab.handle_key(key(KeyCode::Enter), &mut draft);
        assert!(tab.edit_cursor.is_some());
        tab.handle_key(key(KeyCode::Esc), &mut draft);
        assert!(tab.edit_cursor.is_none());
    }

    #[test]
    fn space_on_radio_writes_value_and_stays_in_edit() {
        // Unified model: Space commits cursor's value. Enter just exits.
        let (mut tab, mut draft) = fresh();
        tab.section = SECTION_SEVERITY;
        tab.handle_key(key(KeyCode::Enter), &mut draft);
        // Default cursor = 0 ((all)). Down 5× to Critical.
        for _ in 0..5 {
            tab.handle_key(key(KeyCode::Down), &mut draft);
        }
        assert_eq!(draft.current.min_severity, None,
            "navigation alone does not write");
        // Space writes.
        let out = tab.handle_key(key(KeyCode::Char(' ')), &mut draft);
        assert!(matches!(out, TabOutcome::Mutated));
        assert_eq!(draft.current.min_severity, Some(Severity::Critical));
        // Still in edit mode.
        assert!(tab.edit_cursor.is_some(), "Space stays in edit mode");
    }

    #[test]
    fn enter_in_editing_just_exits_without_extra_write() {
        // Enter exits — does NOT write the cursor's value.
        let (mut tab, mut draft) = fresh();
        tab.section = SECTION_SEVERITY;
        tab.handle_key(key(KeyCode::Enter), &mut draft);
        for _ in 0..5 {
            tab.handle_key(key(KeyCode::Down), &mut draft);
        }
        // Cursor on Critical, but nothing was Spaced. Enter exits.
        tab.handle_key(key(KeyCode::Enter), &mut draft);
        assert_eq!(draft.current.min_severity, None,
            "Enter must NOT commit — only Space commits");
        assert!(tab.edit_cursor.is_none());
    }

    #[test]
    fn esc_in_editing_just_exits() {
        let (mut tab, mut draft) = fresh();
        tab.section = SECTION_SEVERITY;
        tab.handle_key(key(KeyCode::Enter), &mut draft);
        for _ in 0..5 {
            tab.handle_key(key(KeyCode::Down), &mut draft);
        }
        // Esc exits without writing (no Space was pressed).
        tab.handle_key(key(KeyCode::Esc), &mut draft);
        assert!(tab.edit_cursor.is_none());
        assert_eq!(draft.current.min_severity, None);
    }

    #[test]
    fn space_in_behavior_toggles_focused_toggle() {
        let (mut tab, mut draft) = fresh();
        tab.section = SECTION_BEHAVIOR;
        tab.handle_key(key(KeyCode::Enter), &mut draft);
        // Inner cursor = 0 (Audit log).
        let initial = draft.current.audit_enabled;
        tab.handle_key(key(KeyCode::Char(' ')), &mut draft);
        assert_eq!(draft.current.audit_enabled, !initial);
        // Down to Blast radius, Space.
        tab.handle_key(key(KeyCode::Down), &mut draft);
        let initial_blast = draft.current.blast_radius;
        tab.handle_key(key(KeyCode::Char(' ')), &mut draft);
        assert_eq!(draft.current.blast_radius, !initial_blast);
    }

}
