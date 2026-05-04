//! Context tab — drill-down model.
//!
//! Five sections:
//!   1. Protected branches    (editable list)
//!   2. Production k8s        (editable list)
//!   3. Production env vars   (editable key=value list)
//!   4. Sensitive paths       (editable list)
//!   5. Escalation challenges (two radios — Elevated, Critical)

use crate::config::Challenge;
use crate::tui::draft::DraftSettings;
use crate::tui::tabs::{FieldFocus, Tab, TabOutcome};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};

const SECTION_BRANCHES: usize = 0;
const SECTION_K8S: usize = 1;
const SECTION_ENV_VARS: usize = 2;
const SECTION_PATHS: usize = 3;
const SECTION_ESCALATION: usize = 4;
const NUM_SECTIONS: usize = 5;

#[derive(Debug, Default)]
pub struct ContextTab {
    pub section: usize,
    pub edit: Option<EditState>,
}

#[derive(Debug)]
pub enum EditState {
    /// Editing a list section (Branches / K8s / Paths).
    /// `cursor` is the index in the list with focus.
    /// `adding` is Some when the user is typing a new value.
    ListEditor {
        cursor: usize,
        adding: Option<String>,
    },
    /// Editing the env-vars map.
    EnvVarsEditor {
        cursor: usize,
        adding: Option<EnvVarAddState>,
    },
    /// Editing the two escalation radios. `field` is 0 (Elevated) or 1 (Critical).
    EscalationEditor {
        field: usize,
        col: usize, // 0=Math, 1=Enter, 2=Yes
    },
}

#[derive(Debug)]
pub enum EnvVarAddState {
    Key(String),
    Value { key: String, value: String },
}

fn ch_index(c: Challenge) -> usize {
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

impl ContextTab {
    fn section_title(section: usize) -> &'static str {
        match section {
            SECTION_BRANCHES => "Protected branches",
            SECTION_K8S => "Production k8s patterns",
            SECTION_ENV_VARS => "Production env vars",
            SECTION_PATHS => "Sensitive paths",
            SECTION_ESCALATION => "Escalation challenges",
            _ => "",
        }
    }

    fn section_blurb(section: usize) -> &'static str {
        match section {
            SECTION_BRANCHES => "Branches that elevate risk when active. Supports glob (e.g. release/*).",
            SECTION_K8S => "Substring patterns flagging the current k8s context as production.",
            SECTION_ENV_VARS => "Env vars whose values mark the environment as production.",
            SECTION_PATHS => "Filesystem paths that mark commands as elevated risk.",
            SECTION_ESCALATION => "Stricter challenge type when context bumps the risk level.",
            _ => "",
        }
    }
}

impl Tab for ContextTab {
    fn title(&self) -> &str {
        "Context"
    }

    fn render(&self, area: Rect, buf: &mut Buffer, draft: &DraftSettings) {
        if area.height < 18 || area.width < 60 {
            return;
        }
        let mut y = area.y;
        for section in 0..NUM_SECTIONS {
            let is_focused = section == self.section;
            let is_editing_this = is_focused && self.edit.is_some();

            // Section header
            let bar_color = if is_editing_this {
                Color::Green
            } else if is_focused {
                Color::Yellow
            } else {
                Color::DarkGray
            };
            buf.set_string(area.x, y, "▌", Style::default().fg(bar_color));
            let title_style = if is_focused {
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray).add_modifier(Modifier::BOLD)
            };
            buf.set_string(area.x + 2, y, Self::section_title(section), title_style);

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
                y = render_summary_body(buf, area.x, y, area.width, draft, section, is_focused);
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
        let title = Self::section_title(self.section);
        let (name, help) = if self.edit.is_some() {
            match self.section {
                SECTION_ESCALATION => (
                    format!("Editing: {title}"),
                    "↑↓ between Elevated/Critical · ←→ challenge · Space to set · Enter to exit · Esc to exit".to_string(),
                ),
                SECTION_ENV_VARS => (
                    format!("Editing: {title}"),
                    "↑↓ navigate · + add · d remove · Esc back".to_string(),
                ),
                _ => (
                    format!("Editing: {title}"),
                    "↑↓ navigate · + add · d remove · Esc back".to_string(),
                ),
            }
        } else {
            (
                title.to_string(),
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

impl ContextTab {
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
                self.edit = Some(self.initial_edit_state(_draft));
                TabOutcome::FieldFocusChanged(self.current_focus())
            }
            _ => TabOutcome::None,
        }
    }

    fn initial_edit_state(&self, _draft: &DraftSettings) -> EditState {
        match self.section {
            SECTION_BRANCHES | SECTION_K8S | SECTION_PATHS => EditState::ListEditor {
                cursor: 0,
                adding: None,
            },
            SECTION_ENV_VARS => EditState::EnvVarsEditor {
                cursor: 0,
                adding: None,
            },
            SECTION_ESCALATION => EditState::EscalationEditor { field: 0, col: 0 },
            _ => EditState::ListEditor {
                cursor: 0,
                adding: None,
            },
        }
    }

    fn handle_editing(
        &mut self,
        key: KeyEvent,
        draft: &mut DraftSettings,
        state: EditState,
    ) -> TabOutcome {
        match state {
            EditState::ListEditor { cursor, adding } => {
                self.handle_list_editor(key, draft, cursor, adding)
            }
            EditState::EnvVarsEditor { cursor, adding } => {
                self.handle_env_vars_editor(key, draft, cursor, adding)
            }
            EditState::EscalationEditor { field, col } => {
                self.handle_escalation_editor(key, draft, field, col)
            }
        }
    }

    fn list_for(&self, draft: &DraftSettings) -> Vec<String> {
        match self.section {
            SECTION_BRANCHES => draft.current.context.protected_branches.clone(),
            SECTION_K8S => draft.current.context.production_k8s_patterns.clone(),
            SECTION_PATHS => draft.current.context.sensitive_paths.clone(),
            _ => vec![],
        }
    }

    fn list_for_mut<'a>(&self, draft: &'a mut DraftSettings) -> &'a mut Vec<String> {
        match self.section {
            SECTION_BRANCHES => &mut draft.current.context.protected_branches,
            SECTION_K8S => &mut draft.current.context.production_k8s_patterns,
            SECTION_PATHS => &mut draft.current.context.sensitive_paths,
            _ => unreachable!("list_for_mut on non-list section"),
        }
    }

    fn handle_list_editor(
        &mut self,
        key: KeyEvent,
        draft: &mut DraftSettings,
        mut cursor: usize,
        adding: Option<String>,
    ) -> TabOutcome {
        // If currently typing a new entry, the editor consumes keys.
        if let Some(mut buf) = adding {
            match key.code {
                KeyCode::Esc => {
                    self.edit = Some(EditState::ListEditor { cursor, adding: None });
                    return TabOutcome::None;
                }
                KeyCode::Enter => {
                    let trimmed = buf.trim().to_string();
                    if !trimmed.is_empty() {
                        self.list_for_mut(draft).push(trimmed);
                        self.edit = Some(EditState::ListEditor { cursor, adding: None });
                        return TabOutcome::Mutated;
                    }
                    self.edit = Some(EditState::ListEditor { cursor, adding: None });
                    return TabOutcome::None;
                }
                KeyCode::Backspace => {
                    buf.pop();
                    self.edit = Some(EditState::ListEditor { cursor, adding: Some(buf) });
                    return TabOutcome::None;
                }
                KeyCode::Char(c) => {
                    buf.push(c);
                    self.edit = Some(EditState::ListEditor { cursor, adding: Some(buf) });
                    return TabOutcome::None;
                }
                _ => {
                    self.edit = Some(EditState::ListEditor { cursor, adding: Some(buf) });
                    return TabOutcome::None;
                }
            }
        }

        // Browsing the list (no adding sub-mode)
        let len = self.list_for(draft).len();
        match key.code {
            KeyCode::Esc => {
                self.edit = None;
                TabOutcome::FieldFocusChanged(self.current_focus())
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if cursor > 0 { cursor -= 1; }
                self.edit = Some(EditState::ListEditor { cursor, adding: None });
                TabOutcome::None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if cursor + 1 < len { cursor += 1; }
                self.edit = Some(EditState::ListEditor { cursor, adding: None });
                TabOutcome::None
            }
            KeyCode::Char('+') | KeyCode::Enter => {
                self.edit = Some(EditState::ListEditor {
                    cursor,
                    adding: Some(String::new()),
                });
                TabOutcome::None
            }
            KeyCode::Char('d') | KeyCode::Backspace | KeyCode::Delete if len > 0 => {
                let list = self.list_for_mut(draft);
                let idx = cursor.min(list.len() - 1);
                list.remove(idx);
                let new_len = list.len();
                if cursor >= new_len && new_len > 0 {
                    cursor = new_len - 1;
                }
                self.edit = Some(EditState::ListEditor { cursor, adding: None });
                TabOutcome::Mutated
            }
            _ => {
                self.edit = Some(EditState::ListEditor { cursor, adding: None });
                TabOutcome::None
            }
        }
    }

    fn handle_env_vars_editor(
        &mut self,
        key: KeyEvent,
        draft: &mut DraftSettings,
        mut cursor: usize,
        adding: Option<EnvVarAddState>,
    ) -> TabOutcome {
        if let Some(state) = adding {
            match (state, key.code) {
                (_, KeyCode::Esc) => {
                    self.edit = Some(EditState::EnvVarsEditor { cursor, adding: None });
                    return TabOutcome::None;
                }
                (EnvVarAddState::Key(mut k), KeyCode::Enter) => {
                    if k.trim().is_empty() {
                        self.edit = Some(EditState::EnvVarsEditor { cursor, adding: None });
                        return TabOutcome::None;
                    }
                    let key_str = k.trim().to_string();
                    self.edit = Some(EditState::EnvVarsEditor {
                        cursor,
                        adding: Some(EnvVarAddState::Value {
                            key: key_str,
                            value: String::new(),
                        }),
                    });
                    let _ = &mut k;
                    return TabOutcome::None;
                }
                (EnvVarAddState::Value { key, value }, KeyCode::Enter) => {
                    draft.current.context.production_env_vars.insert(key, value);
                    self.edit = Some(EditState::EnvVarsEditor { cursor, adding: None });
                    return TabOutcome::Mutated;
                }
                (EnvVarAddState::Key(mut k), KeyCode::Backspace) => {
                    k.pop();
                    self.edit = Some(EditState::EnvVarsEditor {
                        cursor,
                        adding: Some(EnvVarAddState::Key(k)),
                    });
                    return TabOutcome::None;
                }
                (EnvVarAddState::Value { key, mut value }, KeyCode::Backspace) => {
                    value.pop();
                    self.edit = Some(EditState::EnvVarsEditor {
                        cursor,
                        adding: Some(EnvVarAddState::Value { key, value }),
                    });
                    return TabOutcome::None;
                }
                (EnvVarAddState::Key(mut k), KeyCode::Char(c)) => {
                    k.push(c);
                    self.edit = Some(EditState::EnvVarsEditor {
                        cursor,
                        adding: Some(EnvVarAddState::Key(k)),
                    });
                    return TabOutcome::None;
                }
                (EnvVarAddState::Value { key, mut value }, KeyCode::Char(c)) => {
                    value.push(c);
                    self.edit = Some(EditState::EnvVarsEditor {
                        cursor,
                        adding: Some(EnvVarAddState::Value { key, value }),
                    });
                    return TabOutcome::None;
                }
                (other, _) => {
                    self.edit = Some(EditState::EnvVarsEditor {
                        cursor,
                        adding: Some(other),
                    });
                    return TabOutcome::None;
                }
            }
        }

        let len = draft.current.context.production_env_vars.len();
        match key.code {
            KeyCode::Esc => {
                self.edit = None;
                TabOutcome::FieldFocusChanged(self.current_focus())
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if cursor > 0 { cursor -= 1; }
                self.edit = Some(EditState::EnvVarsEditor { cursor, adding: None });
                TabOutcome::None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if cursor + 1 < len { cursor += 1; }
                self.edit = Some(EditState::EnvVarsEditor { cursor, adding: None });
                TabOutcome::None
            }
            KeyCode::Char('+') | KeyCode::Enter => {
                self.edit = Some(EditState::EnvVarsEditor {
                    cursor,
                    adding: Some(EnvVarAddState::Key(String::new())),
                });
                TabOutcome::None
            }
            KeyCode::Char('d') | KeyCode::Backspace | KeyCode::Delete if len > 0 => {
                let key_to_remove: Option<String> = {
                    let mut keys: Vec<&String> = draft
                        .current
                        .context
                        .production_env_vars
                        .keys()
                        .collect();
                    keys.sort();
                    let idx = cursor.min(keys.len() - 1);
                    keys.get(idx).map(|k| (*k).clone())
                };
                if let Some(k) = key_to_remove {
                    draft.current.context.production_env_vars.remove(&k);
                }
                let new_len = draft.current.context.production_env_vars.len();
                if cursor >= new_len && new_len > 0 {
                    cursor = new_len - 1;
                }
                self.edit = Some(EditState::EnvVarsEditor { cursor, adding: None });
                TabOutcome::Mutated
            }
            _ => {
                self.edit = Some(EditState::EnvVarsEditor { cursor, adding: None });
                TabOutcome::None
            }
        }
    }

    fn handle_escalation_editor(
        &mut self,
        key: KeyEvent,
        draft: &mut DraftSettings,
        mut field: usize,
        mut col: usize,
    ) -> TabOutcome {
        match key.code {
            KeyCode::Esc => {
                // Cancel: do not write to draft, just exit edit mode.
                self.edit = None;
                TabOutcome::FieldFocusChanged(self.current_focus())
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if field > 0 { field -= 1; }
                // Move cursor onto the saved value of the new field.
                col = match field {
                    0 => ch_index(draft.current.context.escalation.elevated),
                    _ => ch_index(draft.current.context.escalation.critical),
                };
                self.edit = Some(EditState::EscalationEditor { field, col });
                TabOutcome::None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if field < 1 { field += 1; }
                col = match field {
                    0 => ch_index(draft.current.context.escalation.elevated),
                    _ => ch_index(draft.current.context.escalation.critical),
                };
                self.edit = Some(EditState::EscalationEditor { field, col });
                TabOutcome::None
            }
            KeyCode::Left | KeyCode::Char('h') => {
                if col > 0 { col -= 1; }
                self.edit = Some(EditState::EscalationEditor { field, col });
                TabOutcome::Consumed
            }
            KeyCode::Right | KeyCode::Char('l') => {
                if col < 2 { col += 1; }
                self.edit = Some(EditState::EscalationEditor { field, col });
                TabOutcome::Consumed
            }
            KeyCode::Char(' ') => {
                // Space writes cursor's value to draft (stays in edit).
                let new_value = ch_from_idx(col);
                let mutated = match field {
                    0 => {
                        if draft.current.context.escalation.elevated != new_value {
                            draft.current.context.escalation.elevated = new_value;
                            true
                        } else {
                            false
                        }
                    }
                    _ => {
                        if draft.current.context.escalation.critical != new_value {
                            draft.current.context.escalation.critical = new_value;
                            true
                        } else {
                            false
                        }
                    }
                };
                self.edit = Some(EditState::EscalationEditor { field, col });
                if mutated { TabOutcome::Mutated } else { TabOutcome::None }
            }
            KeyCode::Enter => {
                // Enter exits edit mode (Space already wrote).
                self.edit = None;
                TabOutcome::FieldFocusChanged(self.current_focus())
            }
            _ => {
                self.edit = Some(EditState::EscalationEditor { field, col });
                TabOutcome::None
            }
        }
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
        let y = y + 1;

        match section {
            SECTION_BRANCHES | SECTION_K8S | SECTION_PATHS => {
                self.render_list_editor(buf, indent, y, draft, section)
            }
            SECTION_ENV_VARS => self.render_env_vars_editor(buf, indent, y, draft),
            SECTION_ESCALATION => self.render_escalation_editor(buf, indent, y, draft),
            _ => y,
        }
    }

    fn render_list_editor(
        &self,
        buf: &mut Buffer,
        indent: u16,
        y: u16,
        draft: &DraftSettings,
        section: usize,
    ) -> u16 {
        let list = match section {
            SECTION_BRANCHES => &draft.current.context.protected_branches,
            SECTION_K8S => &draft.current.context.production_k8s_patterns,
            SECTION_PATHS => &draft.current.context.sensitive_paths,
            _ => unreachable!(),
        };
        let (cursor, adding) = match &self.edit {
            Some(EditState::ListEditor { cursor, adding }) => (*cursor, adding.as_ref()),
            _ => (0, None),
        };

        // List header
        buf.set_string(
            indent,
            y,
            format!("Currently set ({})", list.len()),
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        );
        let mut y = y + 1;

        if list.is_empty() {
            buf.set_string(indent + 2, y, "(none)", Style::default().fg(Color::DarkGray));
            y += 1;
        } else {
            let max_visible = 6usize;
            for (i, value) in list.iter().take(max_visible).enumerate() {
                let is_cursor = i == cursor && adding.is_none();
                let style = if is_cursor {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Green)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Cyan)
                };
                let prefix = if is_cursor { "► " } else { "  " };
                buf.set_string(indent, y, format!("{prefix}{value}"), style);
                y += 1;
            }
            if list.len() > max_visible {
                buf.set_string(
                    indent + 2,
                    y,
                    format!("+ {} more", list.len() - max_visible),
                    Style::default().fg(Color::DarkGray),
                );
                y += 1;
            }
        }

        // Add zone
        if let Some(buf_str) = adding {
            y += 1;
            buf.set_string(
                indent,
                y,
                format!("➤ New entry: {buf_str}_  (Enter to add, Esc to cancel)"),
                Style::default().fg(Color::Yellow),
            );
            y += 1;
        }
        y
    }

    fn render_env_vars_editor(
        &self,
        buf: &mut Buffer,
        indent: u16,
        y: u16,
        draft: &DraftSettings,
    ) -> u16 {
        let map = &draft.current.context.production_env_vars;
        let (cursor, adding) = match &self.edit {
            Some(EditState::EnvVarsEditor { cursor, adding }) => (*cursor, adding.as_ref()),
            _ => (0, None),
        };

        buf.set_string(
            indent,
            y,
            format!("Currently set ({})", map.len()),
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        );
        let mut y = y + 1;

        if map.is_empty() {
            buf.set_string(indent + 2, y, "(none)", Style::default().fg(Color::DarkGray));
            y += 1;
        } else {
            let mut entries: Vec<(&String, &String)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            for (i, (k, v)) in entries.iter().take(6).enumerate() {
                let is_cursor = i == cursor && adding.is_none();
                let style = if is_cursor {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Green)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Cyan)
                };
                let prefix = if is_cursor { "► " } else { "  " };
                buf.set_string(indent, y, format!("{prefix}{k} = {v}"), style);
                y += 1;
            }
        }

        if let Some(state) = adding {
            y += 1;
            let line = match state {
                EnvVarAddState::Key(k) => format!("➤ New key: {k}_  (Enter to continue)"),
                EnvVarAddState::Value { key, value } => {
                    format!("➤ {key} = {value}_  (Enter to add)")
                }
            };
            buf.set_string(indent, y, line, Style::default().fg(Color::Yellow));
            y += 1;
        }
        y
    }

    fn render_escalation_editor(
        &self,
        buf: &mut Buffer,
        indent: u16,
        y: u16,
        draft: &DraftSettings,
    ) -> u16 {
        let (field, col) = match &self.edit {
            Some(EditState::EscalationEditor { field, col }) => (*field, *col),
            _ => (0, 0),
        };
        let _ = col;
        let elevated = ch_index(draft.current.context.escalation.elevated);
        let critical = ch_index(draft.current.context.escalation.critical);

        let render_row =
            |buf: &mut Buffer, y: u16, label: &str, saved: usize, focused: bool, cursor_col: usize| {
                let label_style = if focused {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White).add_modifier(Modifier::BOLD)
                };
                buf.set_string(indent, y, label, label_style);
                let cols = ["Math", "Enter", "Yes"];
                let mut x = indent + 14;
                for (i, opt) in cols.iter().enumerate() {
                    let bullet = if i == saved { "(•)" } else { "( )" };
                    let is_cursor = focused && i == cursor_col;
                    let style = if is_cursor {
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Green)
                            .add_modifier(Modifier::BOLD)
                    } else if i == saved {
                        Style::default().fg(Color::Cyan)
                    } else {
                        Style::default()
                    };
                    buf.set_string(x, y, format!("{bullet} {opt}"), style);
                    x += 12;
                }
            };

        render_row(buf, y, "Elevated  →", elevated, field == 0, col);
        render_row(buf, y + 1, "Critical  →", critical, field == 1, col);
        y + 2
    }
}

fn render_summary_body(
    buf: &mut Buffer,
    area_x: u16,
    y: u16,
    area_width: u16,
    draft: &DraftSettings,
    section: usize,
    is_focused: bool,
) -> u16 {
    let indent = area_x + 2;
    buf.set_string(
        indent,
        y,
        ContextTab::section_blurb(section),
        Style::default().fg(Color::DarkGray),
    );
    let y = y + 1;

    let summary = match section {
        SECTION_BRANCHES => format_list_summary(&draft.current.context.protected_branches),
        SECTION_K8S => format_list_summary(&draft.current.context.production_k8s_patterns),
        SECTION_ENV_VARS => {
            let map = &draft.current.context.production_env_vars;
            if map.is_empty() {
                "(none)".to_string()
            } else {
                let mut entries: Vec<String> = map
                    .iter()
                    .take(3)
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect();
                let more = map.len().saturating_sub(3);
                if more > 0 {
                    entries.push(format!("+{more} more"));
                }
                entries.join("  ·  ")
            }
        }
        SECTION_PATHS => format_list_summary(&draft.current.context.sensitive_paths),
        SECTION_ESCALATION => {
            format!(
                "Elevated → {} · Critical → {}",
                draft.current.context.escalation.elevated,
                draft.current.context.escalation.critical,
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
    let preview_color = if summary == "(none)" {
        Color::DarkGray
    } else {
        Color::Cyan
    };
    buf.set_string(indent, y, &summary, Style::default().fg(preview_color));

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

fn format_list_summary(list: &[String]) -> String {
    if list.is_empty() {
        return "(none)".to_string();
    }
    let shown: Vec<&str> = list.iter().take(3).map(String::as_str).collect();
    let more = list.len().saturating_sub(3);
    if more == 0 {
        shown.join("  ·  ")
    } else {
        format!("{}  ·  +{more} more", shown.join("  ·  "))
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
    fn down_in_browsing_moves_section() {
        let mut tab = ContextTab::default();
        let mut draft = DraftSettings::from_settings(Settings::default());
        tab.handle_key(key(KeyCode::Down), &mut draft);
        assert_eq!(tab.section, SECTION_K8S);
    }

    #[test]
    fn enter_drills_in_and_esc_returns() {
        let mut tab = ContextTab::default();
        let mut draft = DraftSettings::from_settings(Settings::default());
        tab.handle_key(key(KeyCode::Enter), &mut draft);
        assert!(tab.edit.is_some());
        tab.handle_key(key(KeyCode::Esc), &mut draft);
        assert!(tab.edit.is_none());
    }

    #[test]
    fn add_branch_in_editing() {
        let mut tab = ContextTab::default();
        let mut draft = DraftSettings::from_settings(Settings::default());
        tab.handle_key(key(KeyCode::Enter), &mut draft);
        tab.handle_key(key(KeyCode::Char('+')), &mut draft);
        for c in "feat".chars() {
            tab.handle_key(key(KeyCode::Char(c)), &mut draft);
        }
        let initial_len = draft.current.context.protected_branches.len();
        tab.handle_key(key(KeyCode::Enter), &mut draft);
        assert_eq!(
            draft.current.context.protected_branches.len(),
            initial_len + 1
        );
        assert!(draft.current.context.protected_branches.iter().any(|b| b == "feat"));
    }

    #[test]
    fn d_removes_focused_branch() {
        let mut tab = ContextTab::default();
        let mut draft = DraftSettings::from_settings(Settings::default());
        // default has 4 branches
        let initial_len = draft.current.context.protected_branches.len();
        tab.handle_key(key(KeyCode::Enter), &mut draft);
        // cursor=0, 'd' removes
        tab.handle_key(key(KeyCode::Char('d')), &mut draft);
        assert_eq!(
            draft.current.context.protected_branches.len(),
            initial_len - 1
        );
    }

}
