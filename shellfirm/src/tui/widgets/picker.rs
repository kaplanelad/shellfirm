//! Searchable picker with single-step "use as new" semantics.
//!
//! The user types a value. If it matches existing items, they pick from
//! the matches. If it doesn't match, the same typed value can be used as a
//! new entry — no double-typing. The "+ Use 'value' as new" row appears at
//! the bottom whenever the filter is non-empty and isn't already an exact
//! match in the items list.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::Widget;

#[derive(Debug, Clone)]
pub struct PickerItem {
    pub value: String,
    /// Optional short badge — e.g. "built-in", "custom"
    pub badge: Option<&'static str>,
}

/// Picker state — just a filter (the typed text) and a cursor into the
/// visible rows.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PickerState {
    pub filter: String,
    pub cursor: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PickerOutcome {
    None,
    Selected(String),
    Cancelled,
    /// Caller should re-render — state changed but nothing to commit yet.
    StateChanged,
}

pub struct Picker<'a> {
    pub items: &'a [PickerItem],
    pub state: &'a PickerState,
    pub focused: bool,
}

/// Resolves which rows are visible given the current filter, plus whether
/// the "use as new" sentinel should be shown.
struct VisibleRows {
    /// Indices into `items` for matching rows, in original order.
    matches: Vec<usize>,
    /// True if a sentinel row should be appended at the bottom.
    show_create: bool,
}

fn compute_visible(items: &[PickerItem], filter: &str) -> VisibleRows {
    let f = filter.to_lowercase();
    let matches: Vec<usize> = items
        .iter()
        .enumerate()
        .filter(|(_, it)| f.is_empty() || it.value.to_lowercase().contains(&f))
        .map(|(i, _)| i)
        .collect();
    // Sentinel only when the user has typed something meaningful AND
    // it isn't already an exact existing entry.
    let exact = items.iter().any(|it| it.value == filter);
    let show_create = !filter.trim().is_empty() && !exact;
    VisibleRows { matches, show_create }
}

impl<'a> Widget for Picker<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let v = compute_visible(self.items, &self.state.filter);

        // ── Header — current filter or hint
        let header = if self.state.filter.is_empty() {
            "─ Type to filter or add a new value ─".to_string()
        } else {
            format!("─ Looking for: {} ─", self.state.filter)
        };
        buf.set_string(area.x, area.y, header, Style::default().fg(Color::DarkGray));

        let body_y = area.y + 2;
        let body_height = area.height.saturating_sub(2);

        if v.matches.is_empty() && !v.show_create {
            // Nothing typed and nothing in items — just show a placeholder.
            buf.set_string(
                area.x + 2,
                body_y,
                "(empty)",
                Style::default().fg(Color::DarkGray),
            );
            return;
        }

        // How many rows we can show
        let total_rows = v.matches.len() + if v.show_create { 1 } else { 0 };
        let display_rows = (body_height as usize).min(total_rows);
        // Scroll so the cursor stays visible (simple windowing).
        let cursor = self.state.cursor.min(total_rows.saturating_sub(1));
        let scroll_top = if cursor >= display_rows {
            cursor + 1 - display_rows
        } else {
            0
        };

        for row_offset in 0..display_rows {
            let abs = scroll_top + row_offset;
            let y = body_y + row_offset as u16;
            let highlighted = self.focused && abs == cursor;

            if abs < v.matches.len() {
                let item = &self.items[v.matches[abs]];
                let badge_str = item.badge.map(|b| format!("  [{b}]")).unwrap_or_default();
                let line_text = format!("  {}{}", item.value, badge_str);
                let style = if highlighted {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                buf.set_string(area.x, y, line_text, style);
            } else {
                // Sentinel row — "+ Use 'filter' as new value"
                let label = format!("+ Use \"{}\" as new value", self.state.filter);
                let style = if highlighted {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Yellow)
                };
                buf.set_string(area.x, y, label, style);
            }
        }
    }
}

/// Stateless key-handler. Mutates `state` in place and returns the outcome.
pub fn handle_picker_key(
    key: KeyEvent,
    state: &mut PickerState,
    items: &[PickerItem],
) -> PickerOutcome {
    let v = compute_visible(items, &state.filter);
    let total = v.matches.len() + if v.show_create { 1 } else { 0 };

    match key.code {
        KeyCode::Esc => PickerOutcome::Cancelled,
        KeyCode::Up | KeyCode::Char('k') => {
            if total == 0 {
                return PickerOutcome::None;
            }
            state.cursor = if state.cursor == 0 {
                total - 1
            } else {
                state.cursor - 1
            };
            PickerOutcome::StateChanged
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if total == 0 {
                return PickerOutcome::None;
            }
            state.cursor = (state.cursor + 1) % total;
            PickerOutcome::StateChanged
        }
        KeyCode::Enter => {
            if total == 0 {
                return PickerOutcome::None;
            }
            // Clamp cursor to valid range (resilient to filter changes).
            let cursor = state.cursor.min(total - 1);
            if cursor < v.matches.len() {
                let value = items[v.matches[cursor]].value.clone();
                PickerOutcome::Selected(value)
            } else if v.show_create {
                // Sentinel: use the filter text as a new value.
                PickerOutcome::Selected(state.filter.trim().to_string())
            } else {
                PickerOutcome::None
            }
        }
        KeyCode::Backspace => {
            state.filter.pop();
            state.cursor = 0;
            PickerOutcome::StateChanged
        }
        KeyCode::Char(c) => {
            state.filter.push(c);
            state.cursor = 0;
            PickerOutcome::StateChanged
        }
        _ => PickerOutcome::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::empty())
    }

    fn items() -> Vec<PickerItem> {
        vec![
            PickerItem {
                value: "git:force_push".into(),
                badge: Some("built-in"),
            },
            PickerItem {
                value: "git:reset_hard".into(),
                badge: Some("built-in"),
            },
            PickerItem {
                value: "my_team:no_force".into(),
                badge: Some("custom"),
            },
        ]
    }

    #[test]
    fn empty_filter_no_create_sentinel() {
        let v = compute_visible(&items(), "");
        assert_eq!(v.matches.len(), 3);
        assert!(!v.show_create);
    }

    #[test]
    fn nonexact_filter_shows_create_sentinel() {
        let v = compute_visible(&items(), "my_team");
        assert!(v.show_create);
    }

    #[test]
    fn exact_match_hides_create_sentinel() {
        let v = compute_visible(&items(), "git:force_push");
        assert!(!v.show_create);
    }

    #[test]
    fn enter_on_match_returns_selected() {
        let mut state = PickerState {
            filter: String::new(),
            cursor: 1,
        };
        let it = items();
        let out = handle_picker_key(key(KeyCode::Enter), &mut state, &it);
        assert_eq!(out, PickerOutcome::Selected("git:reset_hard".to_string()));
    }

    #[test]
    fn enter_on_create_sentinel_uses_filter_as_value() {
        // Filter "my_team" doesn't exactly match — sentinel is shown.
        // After typing 4 chars, cursor stays at 0 (a match: my_team:no_force).
        // To select the sentinel, navigate down to its index.
        let mut state = PickerState {
            filter: "totally_new".into(),
            cursor: 0,
        };
        let it = items();
        // No matches for "totally_new" → cursor=0 lands directly on the sentinel.
        let out = handle_picker_key(key(KeyCode::Enter), &mut state, &it);
        assert_eq!(out, PickerOutcome::Selected("totally_new".to_string()));
    }

    #[test]
    fn typing_filters_and_resets_cursor() {
        let mut state = PickerState {
            filter: String::new(),
            cursor: 2,
        };
        let it = items();
        let out = handle_picker_key(key(KeyCode::Char('m')), &mut state, &it);
        assert_eq!(out, PickerOutcome::StateChanged);
        assert_eq!(state.filter, "m");
        assert_eq!(state.cursor, 0);
    }

    #[test]
    fn down_wraps_around_total_rows() {
        // 3 matches + 0 sentinel (filter empty) = 3 rows, cursor 2 → 0
        let mut state = PickerState {
            filter: String::new(),
            cursor: 2,
        };
        let it = items();
        let _ = handle_picker_key(key(KeyCode::Down), &mut state, &it);
        assert_eq!(state.cursor, 0);
    }

    #[test]
    fn enter_on_no_matches_with_filter_creates_new() {
        let mut state = PickerState {
            filter: "brand_new_value".into(),
            cursor: 0,
        };
        let it = items();
        let out = handle_picker_key(key(KeyCode::Enter), &mut state, &it);
        assert_eq!(
            out,
            PickerOutcome::Selected("brand_new_value".to_string())
        );
    }

    #[test]
    fn esc_returns_cancelled() {
        let mut state = PickerState {
            filter: "anything".into(),
            cursor: 0,
        };
        let it = items();
        let out = handle_picker_key(key(KeyCode::Esc), &mut state, &it);
        assert_eq!(out, PickerOutcome::Cancelled);
    }

}
