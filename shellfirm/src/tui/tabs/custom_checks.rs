//! Custom checks tab — list view (authoring form added in Phase 7).

use crate::checks::Check;
use crate::tui::check_store::CustomCheckStore;
use crate::tui::draft::DraftSettings;
use crate::tui::tabs::{FieldFocus, Tab, TabOutcome};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};

#[derive(Debug)]
pub struct CustomChecksTab {
    pub store: CustomCheckStore,
    pub checks: Vec<Check>,
    pub cursor: usize,
    /// Set when user pressed `+` or `e` — the App will then open the
    /// authoring form (Phase 7).
    pub pending_action: Option<PendingAction>,
}

#[derive(Debug, Clone)]
pub enum PendingAction {
    Create,
    Edit { index: usize },
    /// Open a confirmation modal before actually deleting the check at
    /// the given index. The App handles the modal and dispatches the
    /// real delete.
    ConfirmDelete { index: usize },
    OpenInEditor { path: std::path::PathBuf },
}

impl CustomChecksTab {
    #[must_use]
    pub fn new(store: CustomCheckStore) -> Self {
        let checks = store.list().unwrap_or_default();
        Self { store, checks, cursor: 0, pending_action: None }
    }

    pub fn reload(&mut self) {
        self.checks = self.store.list().unwrap_or_default();
        if self.cursor >= self.checks.len() && !self.checks.is_empty() {
            self.cursor = self.checks.len() - 1;
        }
    }

    pub fn take_pending_action(&mut self) -> Option<PendingAction> {
        self.pending_action.take()
    }
}

impl Tab for CustomChecksTab {
    fn title(&self) -> &str { "Custom" }

    fn render(&self, area: Rect, buf: &mut Buffer, _draft: &DraftSettings) {
        if area.height < 6 { return; }
        let indent = area.x + crate::tui::style::SECTION_INDENT;

        let title = format!("Custom checks  ({})", self.checks.len());
        let mut y = crate::tui::style::section_header(
            buf, area.x, area.y, area.width, &title, Some("all"), true,
        );

        crate::tui::style::section_help(
            buf,
            area.x,
            y,
            "[+] new   [e] edit   [d] delete   [f] open file   [r] reload",
        );
        y += 2;

        if self.checks.is_empty() {
            buf.set_string(
                indent,
                y,
                "No custom checks yet.",
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
            );
            buf.set_string(
                indent,
                y + 1,
                "Press [+] to create one. They'll be saved to ~/.shellfirm/checks/.",
                Style::default().fg(Color::DarkGray),
            );
            return;
        }

        // Column headers
        let id_col = indent;
        let sev_col = id_col + 44;
        let from_col = sev_col + 12;
        let challenge_col = from_col + 18;
        let header_style = Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD);
        buf.set_string(id_col, y, "Check ID", header_style);
        buf.set_string(sev_col, y, "Severity", header_style);
        buf.set_string(from_col, y, "Group", header_style);
        buf.set_string(challenge_col, y, "Challenge", header_style);
        y += 1;
        buf.set_string(
            id_col,
            y,
            "─".repeat((challenge_col + 10 - id_col) as usize),
            Style::default().fg(Color::DarkGray),
        );
        y += 1;

        // List rows
        let list_height = area.height.saturating_sub(y - area.y) as usize;
        for (i, c) in self.checks.iter().enumerate().take(list_height) {
            let row_y = y + i as u16;
            let highlight = i == self.cursor;

            let id_style = if highlight {
                crate::tui::style::focused_row_style()
            } else {
                Style::default().fg(Color::White)
            };
            buf.set_string(id_col, row_y, &c.id, id_style);

            let sev_color = match c.severity {
                crate::checks::Severity::Critical => Color::Red,
                crate::checks::Severity::High => Color::LightRed,
                crate::checks::Severity::Medium => Color::Yellow,
                crate::checks::Severity::Low => Color::Cyan,
                crate::checks::Severity::Info => Color::DarkGray,
            };
            let sev_style = if highlight {
                crate::tui::style::focused_row_style()
            } else {
                Style::default().fg(sev_color)
            };
            buf.set_string(sev_col, row_y, format!("{:?}", c.severity), sev_style);

            let from_style = if highlight {
                crate::tui::style::focused_row_style()
            } else {
                Style::default().fg(Color::Cyan)
            };
            buf.set_string(from_col, row_y, &c.from, from_style);

            let ch_style = if highlight {
                crate::tui::style::focused_row_style()
            } else {
                Style::default()
            };
            buf.set_string(challenge_col, row_y, format!("{}", c.challenge), ch_style);
        }

        // Description preview row for the focused check
        if let Some(c) = self.checks.get(self.cursor) {
            let preview_y = area.y + area.height.saturating_sub(2);
            buf.set_string(
                indent,
                preview_y,
                "─ description ─",
                Style::default().fg(Color::DarkGray),
            );
            buf.set_string(
                indent,
                preview_y + 1,
                &c.description,
                Style::default().fg(Color::Gray),
            );
        }
    }

    fn handle_key(&mut self, key: KeyEvent, _draft: &mut DraftSettings) -> TabOutcome {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.checks.is_empty() { return TabOutcome::None; }
                self.cursor = if self.cursor == 0 { self.checks.len() - 1 } else { self.cursor - 1 };
                TabOutcome::FieldFocusChanged(self.current_focus())
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.checks.is_empty() { return TabOutcome::None; }
                self.cursor = (self.cursor + 1) % self.checks.len();
                TabOutcome::FieldFocusChanged(self.current_focus())
            }
            KeyCode::Char('+') => {
                self.pending_action = Some(PendingAction::Create);
                TabOutcome::None
            }
            KeyCode::Char('e') if !self.checks.is_empty() => {
                self.pending_action = Some(PendingAction::Edit { index: self.cursor });
                TabOutcome::None
            }
            KeyCode::Char('d') if !self.checks.is_empty() => {
                self.pending_action = Some(PendingAction::ConfirmDelete { index: self.cursor });
                TabOutcome::None
            }
            KeyCode::Char('f') if !self.checks.is_empty() => {
                let group = &self.checks[self.cursor].from;
                self.pending_action = Some(PendingAction::OpenInEditor {
                    path: self.store.path_for_group(group),
                });
                TabOutcome::None
            }
            KeyCode::Char('r') => {
                self.reload();
                TabOutcome::None
            }
            _ => TabOutcome::None,
        }
    }

    fn current_focus(&self) -> FieldFocus {
        if self.checks.is_empty() {
            FieldFocus {
                name: "Custom checks".into(),
                badges: vec!["all"],
                help: "Press [+] to create a custom check.".into(),
            }
        } else {
            let c = &self.checks[self.cursor];
            FieldFocus {
                name: format!("Check: {}", c.id),
                badges: vec!["all"],
                help: format!("from: {} · severity: {:?} · file: {}",
                    c.from, c.severity,
                    self.store.path_for_group(&c.from).display()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::Severity;
    use crate::config::{Challenge, Settings};
    use crate::tui::check_store::CustomCheckStore;
    use crossterm::event::KeyModifiers;
    use regex::Regex;
    use std::path::PathBuf;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::empty())
    }

    fn tempdir() -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("shellfirm-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn make_check(id: &str, from: &str) -> Check {
        Check {
            id: id.into(),
            test: Regex::new("foo").unwrap(),
            description: "x".into(),
            from: from.into(),
            challenge: Challenge::Math,
            filters: vec![],
            alternative: None,
            alternative_info: None,
            severity: Severity::Medium,
        }
    }

    #[test]
    fn empty_list_renders_no_panic() {
        let store = CustomCheckStore::new(tempdir());
        let tab = CustomChecksTab::new(store);
        let draft = DraftSettings::from_settings(Settings::default());
        let mut buf = Buffer::empty(Rect::new(0, 0, 80, 8));
        let area = buf.area;
        tab.render(area, &mut buf, &draft);
        let entire: String = (0..8u16)
            .flat_map(|y| (0..80u16).map(move |x| (x, y)))
            .map(|(x, y)| buf[(x, y)].symbol().to_string())
            .collect::<Vec<_>>().join("");
        assert!(entire.contains("No custom checks yet"));
    }

    #[test]
    fn plus_sets_pending_create() {
        let store = CustomCheckStore::new(tempdir());
        let mut tab = CustomChecksTab::new(store);
        let mut draft = DraftSettings::from_settings(Settings::default());
        tab.handle_key(key(KeyCode::Char('+')), &mut draft);
        assert!(matches!(tab.pending_action, Some(PendingAction::Create)));
    }

    #[test]
    fn delete_keystroke_requests_confirmation() {
        let store = CustomCheckStore::new(tempdir());
        store.add(&make_check("my:foo", "my")).unwrap();
        let mut tab = CustomChecksTab::new(store);
        let mut draft = DraftSettings::from_settings(Settings::default());
        assert_eq!(tab.checks.len(), 1);
        let _ = tab.handle_key(key(KeyCode::Char('d')), &mut draft);
        // Check is NOT removed yet; a ConfirmDelete pending action is set.
        assert_eq!(tab.checks.len(), 1, "delete must not happen without confirmation");
        assert!(matches!(
            tab.pending_action,
            Some(PendingAction::ConfirmDelete { index: 0 })
        ));
    }

    #[test]
    fn down_moves_cursor() {
        let store = CustomCheckStore::new(tempdir());
        store.add(&make_check("my:a", "my")).unwrap();
        store.add(&make_check("my:b", "my")).unwrap();
        let mut tab = CustomChecksTab::new(store);
        let mut draft = DraftSettings::from_settings(Settings::default());
        let out = tab.handle_key(key(KeyCode::Down), &mut draft);
        assert!(matches!(out, TabOutcome::FieldFocusChanged(_)));
        assert_eq!(tab.cursor, 1);
    }

    #[test]
    fn e_sets_pending_edit() {
        let store = CustomCheckStore::new(tempdir());
        store.add(&make_check("my:foo", "my")).unwrap();
        let mut tab = CustomChecksTab::new(store);
        let mut draft = DraftSettings::from_settings(Settings::default());
        tab.handle_key(key(KeyCode::Char('e')), &mut draft);
        assert!(matches!(tab.pending_action, Some(PendingAction::Edit { .. })));
    }

    #[test]
    fn f_sets_pending_open_in_editor() {
        let store = CustomCheckStore::new(tempdir());
        store.add(&make_check("my:foo", "my")).unwrap();
        let mut tab = CustomChecksTab::new(store);
        let mut draft = DraftSettings::from_settings(Settings::default());
        tab.handle_key(key(KeyCode::Char('f')), &mut draft);
        assert!(matches!(tab.pending_action, Some(PendingAction::OpenInEditor { .. })));
    }
}
