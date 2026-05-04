//! Multi-select list: each row toggleable.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::Widget;

pub struct MultiSelect<'a> {
    pub items: &'a [&'a str],
    pub selected: &'a [bool],
    pub cursor: usize,
    pub focused: bool,
}

impl<'a> Widget for MultiSelect<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        debug_assert_eq!(self.items.len(), self.selected.len());
        for (i, name) in self.items.iter().enumerate() {
            if i as u16 >= area.height {
                break;
            }
            let mark = if self.selected.get(i).copied().unwrap_or(false) {
                "[ ✓ ]"
            } else {
                "[   ]"
            };
            let style = if self.focused && i == self.cursor {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Green)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let line = format!("{mark} {name}");
            buf.set_string(area.x, area.y + i as u16, line, style);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultiSelectKeyOutcome {
    None,
    CursorMoved(usize),
    Toggled(usize),
    SelectAll,
    SelectNone,
}

/// Stateless key-handler. Caller mutates its own `selected` and `cursor`
/// based on the returned outcome.
#[must_use]
pub fn handle_multi_select_key(
    key: KeyEvent,
    cursor: usize,
    len: usize,
) -> MultiSelectKeyOutcome {
    if len == 0 {
        return MultiSelectKeyOutcome::None;
    }
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => {
            let next = if cursor == 0 { len - 1 } else { cursor - 1 };
            MultiSelectKeyOutcome::CursorMoved(next)
        }
        KeyCode::Down | KeyCode::Char('j') => {
            MultiSelectKeyOutcome::CursorMoved((cursor + 1) % len)
        }
        KeyCode::Char(' ') => MultiSelectKeyOutcome::Toggled(cursor),
        KeyCode::Char('a') => MultiSelectKeyOutcome::SelectAll,
        KeyCode::Char('n') => MultiSelectKeyOutcome::SelectNone,
        _ => MultiSelectKeyOutcome::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::empty())
    }

    #[test]
    fn space_toggles_at_cursor() {
        let r = handle_multi_select_key(key(KeyCode::Char(' ')), 1, 3);
        assert_eq!(r, MultiSelectKeyOutcome::Toggled(1));
    }

    #[test]
    fn arrow_moves_cursor() {
        assert_eq!(
            handle_multi_select_key(key(KeyCode::Down), 0, 3),
            MultiSelectKeyOutcome::CursorMoved(1)
        );
        assert_eq!(
            handle_multi_select_key(key(KeyCode::Up), 0, 3),
            MultiSelectKeyOutcome::CursorMoved(2)
        );
    }

    #[test]
    fn a_selects_all_n_selects_none() {
        assert_eq!(
            handle_multi_select_key(key(KeyCode::Char('a')), 0, 3),
            MultiSelectKeyOutcome::SelectAll
        );
        assert_eq!(
            handle_multi_select_key(key(KeyCode::Char('n')), 0, 3),
            MultiSelectKeyOutcome::SelectNone
        );
    }

    #[test]
    fn unknown_key_is_none() {
        assert_eq!(
            handle_multi_select_key(key(KeyCode::Char('x')), 0, 3),
            MultiSelectKeyOutcome::None
        );
    }
}
