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

impl MultiSelect<'_> {
    /// First visible row so the cursor row stays inside `height` rows.
    #[must_use]
    pub fn scroll_offset(len: usize, cursor: usize, height: usize) -> usize {
        if height == 0 || len <= height {
            return 0;
        }
        cursor
            .min(len - 1)
            .saturating_sub(height - 1)
            .min(len - height)
    }
}

impl Widget for MultiSelect<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        debug_assert_eq!(self.items.len(), self.selected.len());
        let height = area.height as usize;
        let len = self.items.len();
        let offset = Self::scroll_offset(len, self.cursor, height);
        for (row, (i, name)) in self.items.iter().enumerate().skip(offset).enumerate() {
            if row >= height {
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
            buf.set_string(area.x, area.y + row as u16, line, style);
        }
        // Hidden rows are announced, so a toggle never happens off-screen
        // without the user knowing the list scrolls.
        let marker = Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD);
        let right = |text: &str| area.x + area.width.saturating_sub(text.chars().count() as u16);
        if offset > 0 {
            let m = format!("▲ {offset} more");
            buf.set_string(right(&m), area.y, &m, marker);
        }
        let below = len.saturating_sub(offset + height);
        if below > 0 && height > 0 {
            let m = format!("▼ {below} more");
            buf.set_string(right(&m), area.y + area.height - 1, &m, marker);
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
pub fn handle_multi_select_key(key: KeyEvent, cursor: usize, len: usize) -> MultiSelectKeyOutcome {
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
    fn cursor_row_is_always_visible() {
        for cursor in 0..23 {
            let off = MultiSelect::scroll_offset(23, cursor, 15);
            assert!(cursor >= off && cursor < off + 15, "{cursor} {off}");
        }
        assert_eq!(MultiSelect::scroll_offset(5, 4, 15), 0);
        assert_eq!(MultiSelect::scroll_offset(23, 22, 15), 8);
    }

    #[test]
    fn render_scrolls_to_the_cursor_and_marks_hidden_rows() {
        let items: Vec<String> = (0..23).map(|i| format!("group{i}")).collect();
        let refs: Vec<&str> = items.iter().map(String::as_str).collect();
        let selected = vec![true; 23];
        let area = Rect::new(0, 0, 40, 10);
        let mut buf = Buffer::empty(area);
        MultiSelect {
            items: &refs,
            selected: &selected,
            cursor: 20,
            focused: true,
        }
        .render(area, &mut buf);
        let text: String = (0..10)
            .map(|y| (0..40).map(|x| buf[(x, y)].symbol()).collect::<String>() + "\n")
            .collect();
        assert!(text.contains("group20"), "{text}");
        assert!(text.contains("▲"), "{text}");
        assert!(text.contains("▼ 2 more"), "{text}");
    }

    #[test]
    fn unknown_key_is_none() {
        assert_eq!(
            handle_multi_select_key(key(KeyCode::Char('x')), 0, 3),
            MultiSelectKeyOutcome::None
        );
    }
}
