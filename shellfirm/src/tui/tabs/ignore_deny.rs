//! Ignore / Deny tab — drill-down model.
//!
//! Browsing mode: two sections (Ignore list, Deny list). Each shows a
//! summary count + first few entries. ↑↓ moves between sections; Enter
//! drills in.
//!
//! Editing mode (drilled into one list): a single panel with two zones:
//!   1. Add zone — picker for adding new IDs
//!   2. Existing zone — scrollable list of current entries with `d` to
//!      remove the highlighted one
//! Tab toggles focus between the zones; Esc returns to browsing.

use crate::tui::draft::DraftSettings;
use crate::tui::tabs::{FieldFocus, Tab, TabOutcome};
use crate::tui::widgets::{handle_picker_key_with, Picker, PickerItem, PickerOutcome, PickerState};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::Widget;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    #[default]
    Ignore,
    Deny,
}

/// Which zone of the editing screen has keyboard focus.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum EditZone {
    /// The picker — typing adds to filter, Enter adds the value.
    #[default]
    AddPicker,
    /// The list of existing entries — arrows move cursor, `d` removes.
    EntriesList,
}

#[derive(Debug)]
pub struct IgnoreDenyTab {
    pub all_ids: Vec<PickerItem>,
    /// Which section the cursor sits on in browsing mode.
    pub section: Side,
    /// `None` = Browsing. `Some` = Editing the section.
    pub edit: Option<EditState>,
}

#[derive(Debug)]
pub struct EditState {
    pub zone: EditZone,
    pub picker: PickerState,
    /// Cursor index into the existing-entries list (when zone == EntriesList).
    pub list_cursor: usize,
}

impl Default for IgnoreDenyTab {
    fn default() -> Self {
        Self::new(vec![])
    }
}

impl IgnoreDenyTab {
    #[must_use]
    pub fn new(all_ids: Vec<PickerItem>) -> Self {
        Self {
            all_ids,
            section: Side::Ignore,
            edit: None,
        }
    }

    fn current_list<'a>(&self, draft: &'a DraftSettings) -> &'a [String] {
        match self.section {
            Side::Ignore => &draft.current.ignores_patterns_ids,
            Side::Deny => &draft.current.deny_patterns_ids,
        }
    }

    fn current_list_mut<'a>(&self, draft: &'a mut DraftSettings) -> &'a mut Vec<String> {
        match self.section {
            Side::Ignore => &mut draft.current.ignores_patterns_ids,
            Side::Deny => &mut draft.current.deny_patterns_ids,
        }
    }

    fn section_title(&self, side: Side) -> &'static str {
        match side {
            Side::Ignore => "Ignore list",
            Side::Deny => "Deny list",
        }
    }

    fn section_blurb(&self, side: Side) -> &'static str {
        match side {
            Side::Ignore => "Checks with these check ids never prompt.",
            Side::Deny => "Commands matching these check ids are blocked outright.",
        }
    }
}

impl Tab for IgnoreDenyTab {
    fn claims_key(&self, key: &KeyEvent) -> bool {
        match &self.edit {
            None => false,
            // Tab / Shift-Tab switch zones while a list is open (the global
            // Tab must not pre-empt that, or the entries list is
            // unreachable from the keyboard).
            Some(_) if matches!(key.code, KeyCode::Tab | KeyCode::BackTab) => true,
            // The filter is a text field: letters, and the caret keys
            // (Left/Right must not switch tabs while typing).
            Some(e) => {
                e.zone == EditZone::AddPicker
                    && matches!(
                        key.code,
                        KeyCode::Char(_)
                            | KeyCode::Left
                            | KeyCode::Right
                            | KeyCode::Home
                            | KeyCode::End
                            | KeyCode::Backspace
                            | KeyCode::Delete
                    )
            }
        }
    }

    fn is_editing(&self) -> bool {
        self.edit.is_some()
    }

    fn title(&self) -> &str {
        "Ignore/Deny"
    }

    fn render(&self, area: Rect, buf: &mut Buffer, draft: &DraftSettings) {
        if area.height < 12 || area.width < 60 {
            return;
        }

        let mut y = area.y;
        for side in [Side::Ignore, Side::Deny] {
            let is_focused = side == self.section;
            let is_editing_this = is_focused && self.edit.is_some();
            let count = match side {
                Side::Ignore => draft.current.ignores_patterns_ids.len(),
                Side::Deny => draft.current.deny_patterns_ids.len(),
            };

            // Section bar + title
            let bar_color = if is_editing_this {
                Color::Green
            } else if is_focused {
                Color::Yellow
            } else {
                Color::DarkGray
            };
            buf.set_string(area.x, y, "▌", Style::default().fg(bar_color));

            let title = format!("{}  ({count})", self.section_title(side));
            let title_style = if is_focused {
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
                    .fg(Color::Gray)
                    .add_modifier(Modifier::BOLD)
            };
            buf.set_string(area.x + 2, y, &title, title_style);

            let badge = "[all]";
            buf.set_string(
                area.x + area.width.saturating_sub(badge.chars().count() as u16),
                y,
                badge,
                Style::default().fg(Color::DarkGray),
            );
            y += 1;

            if is_editing_this {
                // Rows still needed below this section: the other section's
                // summary when editing Ignore (title, blurb, preview, gap).
                let reserve = if side == Side::Ignore { 4 } else { 0 };
                let bottom = (area.y + area.height).saturating_sub(reserve);
                y = self.render_editing_body(buf, area.x, y, area.width, bottom, draft);
            } else {
                y = self.render_summary_body(buf, area.x, y, area.width, draft, side, is_focused);
            }
            y += 1; // blank line between sections
        }
    }

    fn handle_key(&mut self, key: KeyEvent, draft: &mut DraftSettings) -> TabOutcome {
        match self.edit.take() {
            None => self.handle_browsing_key(key, draft),
            Some(state) => self.handle_editing_key(key, draft, state),
        }
    }

    fn current_focus(&self) -> FieldFocus {
        let label = self.section_title(self.section);
        let (name, help) = if let Some(edit) = &self.edit {
            let help = match edit.zone {
                EditZone::AddPicker => {
                    "Type to filter (←→ move the caret) · ↑↓ choose · Enter add · Tab to the list (d removes) · Esc back"
                }
                EditZone::EntriesList => {
                    "↑↓ select · d remove · Tab back to the picker · Esc back"
                }
            };
            (format!("Editing: {label}"), help.to_string())
        } else {
            (
                label.to_string(),
                "↑↓ select section · Enter to edit.".to_string(),
            )
        };
        FieldFocus {
            name,
            badges: vec!["all"],
            help,
        }
    }
}

impl IgnoreDenyTab {
    fn handle_browsing_key(&mut self, key: KeyEvent, _draft: &mut DraftSettings) -> TabOutcome {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.section == Side::Deny {
                    self.section = Side::Ignore;
                    return TabOutcome::FieldFocusChanged(self.current_focus());
                }
                TabOutcome::None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.section == Side::Ignore {
                    self.section = Side::Deny;
                    return TabOutcome::FieldFocusChanged(self.current_focus());
                }
                TabOutcome::None
            }
            KeyCode::Enter => {
                self.edit = Some(EditState {
                    zone: EditZone::AddPicker,
                    picker: PickerState::requiring_choice(),
                    list_cursor: 0,
                });
                TabOutcome::FieldFocusChanged(self.current_focus())
            }
            _ => TabOutcome::None,
        }
    }

    fn handle_editing_key(
        &mut self,
        key: KeyEvent,
        draft: &mut DraftSettings,
        mut state: EditState,
    ) -> TabOutcome {
        // Esc always exits edit mode.
        if matches!(key.code, KeyCode::Esc) {
            self.edit = None;
            return TabOutcome::FieldFocusChanged(self.current_focus());
        }

        // Tab / Shift-Tab toggle between zones (only if there are entries
        // to focus).
        if matches!(key.code, KeyCode::Tab | KeyCode::BackTab) {
            let has_entries = !self.current_list(draft).is_empty();
            state.zone = match state.zone {
                EditZone::AddPicker if has_entries => EditZone::EntriesList,
                EditZone::EntriesList => EditZone::AddPicker,
                z => z,
            };
            // Reset list cursor when switching to it
            if state.zone == EditZone::EntriesList {
                let len = self.current_list(draft).len();
                state.list_cursor = state.list_cursor.min(len.saturating_sub(1));
            }
            self.edit = Some(state);
            return TabOutcome::FieldFocusChanged(self.current_focus());
        }

        match state.zone {
            EditZone::AddPicker => self.handle_picker_key(key, draft, state),
            EditZone::EntriesList => self.handle_list_key(key, draft, state),
        }
    }

    fn handle_picker_key(
        &mut self,
        key: KeyEvent,
        draft: &mut DraftSettings,
        mut state: EditState,
    ) -> TabOutcome {
        let outcome = handle_picker_key_with(key, &mut state.picker, &self.all_ids, false);
        match outcome {
            PickerOutcome::Selected(value) => {
                let trimmed = value.trim().to_string();
                if !trimmed.is_empty() {
                    let list = self.current_list_mut(draft);
                    if !list.iter().any(|x| x == &trimmed) {
                        list.push(trimmed);
                    }
                }
                state.picker = PickerState::requiring_choice();
                self.edit = Some(state);
                TabOutcome::Mutated
            }
            PickerOutcome::Cancelled => {
                self.edit = None;
                TabOutcome::FieldFocusChanged(self.current_focus())
            }
            PickerOutcome::StateChanged => {
                self.edit = Some(state);
                TabOutcome::FieldFocusChanged(self.current_focus())
            }
            PickerOutcome::None => {
                // Enter with nothing chosen: say how to choose.
                if key.code == KeyCode::Enter && state.picker.filter.is_empty() {
                    self.edit = Some(state);
                    return TabOutcome::FieldFocusChanged(FieldFocus {
                        help: "Nothing chosen: type part of a check id or press ↓ to choose one, then Enter".to_string(),
                        ..self.current_focus()
                    });
                }
                self.edit = Some(state);
                TabOutcome::None
            }
        }
    }

    fn handle_list_key(
        &mut self,
        key: KeyEvent,
        draft: &mut DraftSettings,
        mut state: EditState,
    ) -> TabOutcome {
        let len = self.current_list(draft).len();
        if len == 0 {
            // Bounce back to picker
            state.zone = EditZone::AddPicker;
            self.edit = Some(state);
            return TabOutcome::None;
        }
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if state.list_cursor > 0 {
                    state.list_cursor -= 1;
                }
                self.edit = Some(state);
                TabOutcome::None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if state.list_cursor + 1 < len {
                    state.list_cursor += 1;
                }
                self.edit = Some(state);
                TabOutcome::None
            }
            KeyCode::Char('d') | KeyCode::Backspace | KeyCode::Delete => {
                let idx = state.list_cursor.min(len - 1);
                let list = self.current_list_mut(draft);
                if idx < list.len() {
                    list.remove(idx);
                }
                let new_len = self.current_list(draft).len();
                if state.list_cursor >= new_len && new_len > 0 {
                    state.list_cursor = new_len - 1;
                }
                if new_len == 0 {
                    state.zone = EditZone::AddPicker;
                }
                self.edit = Some(state);
                TabOutcome::Mutated
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
        side: Side,
        is_focused: bool,
    ) -> u16 {
        let indent = area_x + 2;

        // Blurb
        buf.set_string(
            indent,
            y,
            self.section_blurb(side),
            Style::default().fg(Color::DarkGray),
        );
        let y = y + 1;

        // Sample of entries
        let list = match side {
            Side::Ignore => &draft.current.ignores_patterns_ids,
            Side::Deny => &draft.current.deny_patterns_ids,
        };
        let preview = if list.is_empty() {
            "(none)".to_string()
        } else {
            // Show up to 3 entries inline; "+N more" if there are more
            let shown: Vec<&str> = list.iter().take(3).map(String::as_str).collect();
            let more = list.len().saturating_sub(3);
            if more == 0 {
                shown.join("  ·  ")
            } else {
                format!("{}  ·  +{more} more", shown.join("  ·  "))
            }
        };
        // Truncate to fit
        let max_w = area_width.saturating_sub(2 + 16) as usize;
        let preview = if preview.chars().count() > max_w {
            let mut s: String = preview.chars().take(max_w.saturating_sub(1)).collect();
            s.push('…');
            s
        } else {
            preview
        };
        let preview_color = if list.is_empty() {
            Color::DarkGray
        } else {
            Color::Cyan
        };
        buf.set_string(indent, y, &preview, Style::default().fg(preview_color));

        if is_focused {
            let hint = "Enter to edit";
            let hint_x = area_x + area_width.saturating_sub(hint.chars().count() as u16);
            buf.set_string(
                hint_x,
                y,
                hint,
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
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
        bottom: u16,
        draft: &DraftSettings,
    ) -> u16 {
        let edit = self.edit.as_ref().expect("editing mode");
        let indent = area_x + 2;
        let inner_w = area_width.saturating_sub(2);

        // Divider
        buf.set_string(
            indent,
            y,
            "─".repeat(inner_w as usize),
            Style::default().fg(Color::DarkGray),
        );
        let mut y = y + 1;

        // ── Add zone ─────────────────────────────────────
        let picker_focused = edit.zone == EditZone::AddPicker;
        let add_label_style = if picker_focused {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD)
        };
        buf.set_string(indent, y, "Add a check id", add_label_style);
        y += 1;
        // Use the available height for the picker (it used to show only 3
        // matches in a large terminal), keeping room for the entries list.
        let entries = self.current_list(draft).len();
        let entries_rows = 1 + entries.clamp(1, 6) as u16 + 2 * u16::from(entries > 6);
        let picker_height = bottom
            .saturating_sub(y)
            .saturating_sub(1 + entries_rows)
            .clamp(5, 40);
        Picker {
            items: &self.all_ids,
            state: &edit.picker,
            focused: picker_focused,
            allow_create: false,
        }
        .render(
            Rect {
                x: indent,
                y,
                width: inner_w,
                height: picker_height,
            },
            buf,
        );
        y += picker_height + 1;

        // ── Existing entries zone ────────────────────────
        let list = self.current_list(draft);
        let list_focused = edit.zone == EditZone::EntriesList;
        let label = format!("Currently in this list ({})", list.len());
        let list_label_style = if list_focused {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD)
        };
        buf.set_string(indent, y, &label, list_label_style);
        y += 1;

        if list.is_empty() {
            buf.set_string(
                indent + 2,
                y,
                "(none)",
                Style::default().fg(Color::DarkGray),
            );
            y += 1;
        } else {
            // Show up to N entries
            let max_visible = 6usize;
            let start = if list_focused {
                edit.list_cursor
                    .saturating_sub(max_visible - 1)
                    .min(list.len().saturating_sub(max_visible))
            } else {
                0
            };
            if start > 0 {
                buf.set_string(
                    indent + 2,
                    y,
                    format!("▲ {start} more"),
                    Style::default().fg(Color::DarkGray),
                );
                y += 1;
            }
            let shown = list.iter().enumerate().skip(start).take(max_visible);
            for (i, value) in shown {
                let is_cursor = list_focused && i == edit.list_cursor;
                let style = if is_cursor {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Green)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Cyan)
                };
                let prefix = if is_cursor { "► " } else { "  " };
                let known = self.all_ids.iter().any(|p| &p.value == value);
                let style = if known || is_cursor {
                    style
                } else {
                    Style::default().fg(Color::Red)
                };
                let suffix = if known { "" } else { "  (unknown check id)" };
                buf.set_string(indent, y, format!("{prefix}{value}{suffix}"), style);
                y += 1;
            }
            if list.len() > start + max_visible {
                buf.set_string(
                    indent + 2,
                    y,
                    format!(
                        "▼ {} more (Tab to focus the list, then ↑↓)",
                        list.len() - start - max_visible
                    ),
                    Style::default().fg(Color::DarkGray),
                );
                y += 1;
            }
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

    fn items() -> Vec<PickerItem> {
        vec![
            PickerItem {
                value: "git:force_push".into(),
                badge: Some("built-in"),
                description: None,
            },
            PickerItem {
                value: "fs:rm_rf".into(),
                badge: Some("built-in"),
                description: None,
            },
        ]
    }

    #[test]
    fn down_in_browsing_moves_to_deny() {
        let mut tab = IgnoreDenyTab::new(items());
        let mut draft = DraftSettings::from_settings(Settings::default());
        assert_eq!(tab.section, Side::Ignore);
        tab.handle_key(key(KeyCode::Down), &mut draft);
        assert_eq!(tab.section, Side::Deny);
    }

    #[test]
    fn enter_in_browsing_drills_in() {
        let mut tab = IgnoreDenyTab::new(items());
        let mut draft = DraftSettings::from_settings(Settings::default());
        tab.handle_key(key(KeyCode::Enter), &mut draft);
        assert!(tab.edit.is_some());
    }

    #[test]
    fn esc_in_editing_returns_to_browsing() {
        let mut tab = IgnoreDenyTab::new(items());
        let mut draft = DraftSettings::from_settings(Settings::default());
        tab.handle_key(key(KeyCode::Enter), &mut draft);
        assert!(tab.edit.is_some());
        tab.handle_key(key(KeyCode::Esc), &mut draft);
        assert!(tab.edit.is_none());
    }

    #[test]
    fn picker_select_adds_to_ignore() {
        let mut tab = IgnoreDenyTab::new(items());
        let mut draft = DraftSettings::from_settings(Settings::default());
        // Drill in
        tab.handle_key(key(KeyCode::Enter), &mut draft);
        // Nothing is chosen yet: a second Enter adds nothing.
        tab.handle_key(key(KeyCode::Enter), &mut draft);
        assert!(draft.current.ignores_patterns_ids.is_empty());
        // Down chooses the first item; Enter adds it.
        tab.handle_key(key(KeyCode::Down), &mut draft);
        let out = tab.handle_key(key(KeyCode::Enter), &mut draft);
        assert!(matches!(out, TabOutcome::Mutated));
        assert!(draft
            .current
            .ignores_patterns_ids
            .iter()
            .any(|x| x == "git:force_push"));
    }

    #[test]
    fn d_removes_focused_list_entry() {
        let mut tab = IgnoreDenyTab::new(items());
        let mut draft = DraftSettings::from_settings(Settings::default());
        draft.current.ignores_patterns_ids = vec!["a".into(), "b".into(), "c".into()];
        // Drill in
        tab.handle_key(key(KeyCode::Enter), &mut draft);
        // Tab into list zone
        tab.handle_key(key(KeyCode::Tab), &mut draft);
        // List cursor at 0 → 'd' removes "a"
        tab.handle_key(key(KeyCode::Char('d')), &mut draft);
        assert_eq!(draft.current.ignores_patterns_ids, vec!["b", "c"]);
    }
}
