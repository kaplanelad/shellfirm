//! Groups tab — drill-down model with a single section.
//!
//! Browsing: shows count + sample of enabled groups.
//! Editing: full multi-select list.

use crate::config::DEFAULT_ENABLED_GROUPS;
use crate::tui::draft::DraftSettings;
use crate::tui::tabs::{FieldFocus, Tab, TabOutcome};
use crate::tui::widgets::{handle_multi_select_key, MultiSelect, MultiSelectKeyOutcome};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::Widget;

#[derive(Debug, Default)]
pub struct GroupsTab {
    pub cursor: usize,
    pub custom_groups: Vec<String>,
    pub edit_active: bool,
}

impl GroupsTab {
    #[must_use]
    pub fn new(custom_groups: Vec<String>) -> Self {
        Self {
            cursor: 0,
            custom_groups,
            edit_active: false,
        }
    }

    fn all_groups(&self) -> Vec<String> {
        let mut v: Vec<String> = DEFAULT_ENABLED_GROUPS.iter().map(|s| (*s).to_string()).collect();
        for g in &self.custom_groups {
            if !v.contains(g) {
                v.push(g.clone());
            }
        }
        v
    }

    fn is_custom(&self, name: &str) -> bool {
        self.custom_groups.iter().any(|g| g == name) && !DEFAULT_ENABLED_GROUPS.contains(&name)
    }
}

impl Tab for GroupsTab {
    fn title(&self) -> &str {
        "Groups"
    }

    fn render(&self, area: Rect, buf: &mut Buffer, draft: &DraftSettings) {
        if area.height < 8 || area.width < 50 {
            return;
        }

        let groups = self.all_groups();
        let enabled_count = groups
            .iter()
            .filter(|g| draft.current.enabled_groups.iter().any(|e| e == *g))
            .count();
        let total = groups.len();

        let mut y = area.y;

        // Section header
        let bar_color = if self.edit_active {
            Color::Green
        } else {
            Color::Yellow
        };
        buf.set_string(area.x, y, "▌", Style::default().fg(bar_color));
        let title = format!("Check groups  ({enabled_count} of {total} enabled)");
        buf.set_string(
            area.x + 2,
            y,
            &title,
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        );
        let badge = "[all]";
        buf.set_string(
            area.x + area.width.saturating_sub(badge.chars().count() as u16),
            y,
            badge,
            Style::default().fg(Color::DarkGray),
        );
        y += 1;

        // Blurb
        buf.set_string(
            area.x + 2,
            y,
            "Categories of risky commands to detect. Custom groups are marked [custom].",
            Style::default().fg(Color::DarkGray),
        );
        y += 1;

        if !self.edit_active {
            // Browsing — render every group as a status tile in a grid.
            // Right-align the Enter hint on the blurb row (y - 1).
            let hint = "Enter to edit";
            let hint_x = area.x + area.width.saturating_sub(hint.chars().count() as u16);
            buf.set_string(
                hint_x,
                y - 1,
                hint,
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            );
            y += 1;

            // Compute the widest tile string so columns line up.
            // Tile format: "✓ name" or "✓ name  [custom]"
            let mut max_label = 0usize;
            for g in &groups {
                let suffix = if self.is_custom(g) { "  [custom]".len() } else { 0 };
                let len = g.chars().count() + 2 + suffix; // "✓ " + name + suffix
                if len > max_label { max_label = len; }
            }
            let cell_gap: usize = 3;
            let cell_w = max_label + cell_gap;
            let inner_w = area.width.saturating_sub(2) as usize;
            let cols = (inner_w / cell_w).max(1);

            // Render in row-major order; preserve groups list order.
            for (i, g) in groups.iter().enumerate() {
                let row = i / cols;
                let col = i % cols;
                let cx = area.x + 2 + (col * cell_w) as u16;
                let cy = y + row as u16;

                let enabled = draft.current.enabled_groups.iter().any(|e| e == g);
                let custom = self.is_custom(g);

                let (icon, icon_style, name_style) = if enabled {
                    (
                        "✓",
                        Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                        Style::default().fg(Color::Cyan),
                    )
                } else {
                    (
                        "✗",
                        Style::default().fg(Color::DarkGray),
                        Style::default().fg(Color::DarkGray),
                    )
                };
                buf.set_string(cx, cy, icon, icon_style);
                buf.set_string(cx + 2, cy, g, name_style);
                if custom {
                    let badge_x = cx + 2 + g.chars().count() as u16 + 2;
                    buf.set_string(
                        badge_x,
                        cy,
                        "[custom]",
                        Style::default().fg(Color::Yellow),
                    );
                }
            }
            return;
        }

        // Editing — divider + multi-select
        let inner_w = area.width.saturating_sub(2);
        buf.set_string(
            area.x + 2,
            y,
            "─".repeat(inner_w as usize),
            Style::default().fg(Color::DarkGray),
        );
        y += 1;

        let item_strs: Vec<String> = groups
            .iter()
            .map(|g| {
                if self.is_custom(g) {
                    format!("{g}  [custom]")
                } else {
                    g.clone()
                }
            })
            .collect();
        let item_refs: Vec<&str> = item_strs.iter().map(String::as_str).collect();
        let selected: Vec<bool> = groups
            .iter()
            .map(|g| draft.current.enabled_groups.iter().any(|e| e == g))
            .collect();

        let list_height = area.height.saturating_sub(y - area.y).saturating_sub(2);
        MultiSelect {
            items: &item_refs,
            selected: &selected,
            cursor: self.cursor,
            focused: true,
        }
        .render(
            Rect {
                x: area.x + 2,
                y,
                width: inner_w,
                height: list_height,
            },
            buf,
        );
    }

    fn handle_key(&mut self, key: KeyEvent, draft: &mut DraftSettings) -> TabOutcome {
        if !self.edit_active {
            // Browsing — only Enter drills in. Left/Right fall through to the
            // App for top-level tab navigation.
            return match key.code {
                KeyCode::Enter | KeyCode::Char('l') => {
                    self.edit_active = true;
                    TabOutcome::FieldFocusChanged(self.current_focus())
                }
                _ => TabOutcome::None,
            };
        }
        // Editing — Esc and Left exit.
        if matches!(key.code, KeyCode::Esc | KeyCode::Left | KeyCode::Char('h')) {
            self.edit_active = false;
            return TabOutcome::FieldFocusChanged(self.current_focus());
        }
        let groups = self.all_groups();
        if groups.is_empty() {
            return TabOutcome::None;
        }
        let outcome = handle_multi_select_key(key, self.cursor, groups.len());
        match outcome {
            MultiSelectKeyOutcome::CursorMoved(c) => {
                self.cursor = c;
                TabOutcome::None
            }
            MultiSelectKeyOutcome::Toggled(i) => {
                let g = &groups[i];
                if let Some(pos) = draft.current.enabled_groups.iter().position(|x| x == g) {
                    draft.current.enabled_groups.remove(pos);
                    if !draft.current.disabled_groups.contains(g) {
                        draft.current.disabled_groups.push(g.clone());
                    }
                } else {
                    draft.current.enabled_groups.push(g.clone());
                    draft.current.disabled_groups.retain(|x| x != g);
                }
                TabOutcome::Mutated
            }
            MultiSelectKeyOutcome::SelectAll => {
                draft.current.enabled_groups = groups;
                draft.current.disabled_groups.clear();
                TabOutcome::Mutated
            }
            MultiSelectKeyOutcome::SelectNone => {
                draft.current.disabled_groups = groups;
                draft.current.enabled_groups.clear();
                TabOutcome::Mutated
            }
            MultiSelectKeyOutcome::None => TabOutcome::None,
        }
    }

    fn current_focus(&self) -> FieldFocus {
        let groups = self.all_groups();
        let name = if self.edit_active {
            let group_name = groups.get(self.cursor).cloned().unwrap_or_default();
            format!("Editing: {group_name}")
        } else {
            "Check groups".to_string()
        };
        let help = if self.edit_active {
            "↑↓ navigate · Space toggle · 'a' all · 'n' none · Esc back".into()
        } else {
            "Enter to edit which check groups are enabled.".into()
        };
        FieldFocus {
            name,
            badges: vec!["all"],
            help,
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
    fn enter_drills_in() {
        let mut tab = GroupsTab::new(vec![]);
        let mut draft = DraftSettings::from_settings(Settings::default());
        assert!(!tab.edit_active);
        tab.handle_key(key(KeyCode::Enter), &mut draft);
        assert!(tab.edit_active);
    }

    #[test]
    fn esc_exits_editing() {
        let mut tab = GroupsTab::new(vec![]);
        let mut draft = DraftSettings::from_settings(Settings::default());
        tab.handle_key(key(KeyCode::Enter), &mut draft);
        tab.handle_key(key(KeyCode::Esc), &mut draft);
        assert!(!tab.edit_active);
    }

    #[test]
    fn space_in_editing_toggles_group() {
        let mut tab = GroupsTab::new(vec![]);
        let mut draft = DraftSettings::from_settings(Settings::default());
        tab.handle_key(key(KeyCode::Enter), &mut draft);
        let initial_count = draft.current.enabled_groups.len();
        let out = tab.handle_key(key(KeyCode::Char(' ')), &mut draft);
        assert!(matches!(out, TabOutcome::Mutated));
        assert_ne!(draft.current.enabled_groups.len(), initial_count);
    }

    #[test]
    fn select_all_in_editing_includes_custom() {
        let mut tab = GroupsTab::new(vec!["my_team".into()]);
        let mut draft = DraftSettings::from_settings(Settings::default());
        tab.handle_key(key(KeyCode::Enter), &mut draft);
        tab.handle_key(key(KeyCode::Char('a')), &mut draft);
        assert!(draft.current.enabled_groups.iter().any(|g| g == "my_team"));
    }

}
