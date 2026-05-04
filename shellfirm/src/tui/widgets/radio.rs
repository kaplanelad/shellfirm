//! Radio group: single-select from a list of N labels.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::Widget;

pub struct RadioGroup<'a> {
    options: &'a [&'a str],
    descriptions: Option<&'a [&'a str]>,
    description_column: Option<u16>,
    /// Index where the (•) glyph is drawn — the *saved* value.
    selected: usize,
    /// Whether any option is currently in the keyboard focus.
    focused_within: bool,
    /// When `Some(i)`, the i-th row is highlighted as the cursor — distinct
    /// from the saved selection. When `None`, the highlight falls on the
    /// selected row (legacy behaviour).
    cursor_row: Option<usize>,
}

impl<'a> RadioGroup<'a> {
    #[must_use]
    pub fn new(options: &'a [&'a str], selected: usize, focused_within: bool) -> Self {
        Self {
            options,
            descriptions: None,
            description_column: None,
            selected,
            focused_within,
            cursor_row: None,
        }
    }

    /// Independent cursor row (for the dialog-style "arrows navigate, Space
    /// selects" pattern). When set, the highlight follows the cursor and
    /// the (•) marker stays where the saved value is.
    #[must_use]
    pub fn with_cursor(mut self, cursor: usize) -> Self {
        self.cursor_row = Some(cursor);
        self
    }

    /// Attach a parallel slice of descriptions, one per option. Each
    /// description is rendered to the right of the option label in dim
    /// gray. Length must match `options.len()` or descriptions are ignored.
    #[must_use]
    pub fn with_descriptions(mut self, descriptions: &'a [&'a str]) -> Self {
        if descriptions.len() == self.options.len() {
            self.descriptions = Some(descriptions);
        }
        self
    }

    /// Pin the description start column (relative to the area's left).
    /// Use this to align descriptions across multiple radio groups in a
    /// single tab.
    #[must_use]
    pub fn description_at_column(mut self, col: u16) -> Self {
        self.description_column = Some(col);
        self
    }
}

impl<'a> Widget for RadioGroup<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Width of the longest label, for description alignment.
        let label_width = self
            .options
            .iter()
            .map(|s| s.chars().count())
            .max()
            .unwrap_or(0);
        for (i, opt) in self.options.iter().enumerate() {
            if i as u16 >= area.height {
                break;
            }
            let bullet = if i == self.selected { "(•)" } else { "( )" };
            let highlight = self.focused_within
                && match self.cursor_row {
                    Some(c) => c == i,
                    None => i == self.selected,
                };
            let style = if highlight {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Green)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let label = format!("{bullet} {opt}");
            buf.set_string(area.x, area.y + i as u16, &label, style);

            if let Some(descs) = self.descriptions {
                let desc = descs[i];
                let desc_x = match self.description_column {
                    Some(col) => area.x + col,
                    None => area.x + 4 + label_width as u16 + 4,
                };
                if desc_x < area.x + area.width {
                    let desc_style = if highlight {
                        // When the radio row is highlighted (cursor on it),
                        // the description should still be readable. Use a
                        // medium fg so the row "block" reads well.
                        Style::default().fg(Color::Black).bg(Color::Green)
                    } else {
                        Style::default().fg(Color::DarkGray)
                    };
                    let max = (area.x + area.width).saturating_sub(desc_x) as usize;
                    let truncated: String = desc.chars().take(max).collect();
                    buf.set_string(desc_x, area.y + i as u16, &truncated, desc_style);
                }
            }
        }
    }
}

/// Free-function key handler for moving the selection up/down.
/// Returns the new selected index.
#[must_use]
pub fn handle_radio_key(key: KeyEvent, current: usize, len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => {
            if current == 0 { len - 1 } else { current - 1 }
        }
        KeyCode::Down | KeyCode::Char('j') => (current + 1) % len,
        _ => current,
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
    fn down_increments_with_wrap() {
        assert_eq!(handle_radio_key(key(KeyCode::Down), 0, 3), 1);
        assert_eq!(handle_radio_key(key(KeyCode::Down), 2, 3), 0);
    }

    #[test]
    fn up_decrements_with_wrap() {
        assert_eq!(handle_radio_key(key(KeyCode::Up), 1, 3), 0);
        assert_eq!(handle_radio_key(key(KeyCode::Up), 0, 3), 2);
    }

    #[test]
    fn vim_keys_work() {
        assert_eq!(handle_radio_key(key(KeyCode::Char('j')), 0, 3), 1);
        assert_eq!(handle_radio_key(key(KeyCode::Char('k')), 0, 3), 2);
    }

    #[test]
    fn unrelated_key_is_noop() {
        assert_eq!(handle_radio_key(key(KeyCode::Char('x')), 1, 3), 1);
    }
}
