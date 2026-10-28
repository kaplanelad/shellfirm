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
        // More options than rows: show a window that keeps the cursor (or
        // the selection) visible, with `▲ more` / `▼ more` on the edge
        // rows so the hidden options are not a surprise.
        let rows = area.height as usize;
        let n = self.options.len();
        let focus = self
            .cursor_row
            .unwrap_or(self.selected)
            .min(n.saturating_sub(1));
        let first = if n <= rows || rows == 0 {
            0
        } else {
            focus.saturating_sub(rows - 1).min(n - rows)
        };
        let hidden_above = first > 0;
        let hidden_below = first + rows < n;
        let marker_w: u16 = if hidden_above || hidden_below { 7 } else { 0 };
        for (i, opt) in self.options.iter().enumerate().skip(first) {
            let row = i - first;
            if row >= rows {
                break;
            }
            let y = area.y + row as u16;
            let marker = if row == 0 && hidden_above {
                Some(crate::tui::a11y::sym("▲ more", "^ more"))
            } else if row + 1 == rows && hidden_below {
                Some(crate::tui::a11y::sym("▼ more", "v more"))
            } else {
                None
            };
            if let Some(m) = marker {
                buf.set_string(
                    area.x + area.width.saturating_sub(marker_w - 1),
                    y,
                    m,
                    Style::default().fg(Color::Yellow),
                );
            }
            let width = area.width.saturating_sub(marker_w);
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
            buf.set_stringn(area.x, y, &label, width as usize, style);

            if let Some(descs) = self.descriptions {
                let desc = descs[i];
                let desc_x = match self.description_column {
                    Some(col) => area.x + col,
                    None => area.x + 4 + label_width as u16 + 4,
                };
                if desc_x < area.x + width {
                    let desc_style = if highlight {
                        // When the radio row is highlighted (cursor on it),
                        // the description should still be readable. Use a
                        // medium fg so the row "block" reads well.
                        Style::default().fg(Color::Black).bg(Color::Green)
                    } else {
                        Style::default().fg(Color::DarkGray)
                    };
                    let max = (area.x + width).saturating_sub(desc_x) as usize;
                    let truncated: String = desc.chars().take(max).collect();
                    buf.set_string(desc_x, y, &truncated, desc_style);
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
            if current == 0 {
                len - 1
            } else {
                current - 1
            }
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

    fn draw(selected: usize, h: u16) -> Vec<String> {
        let opts = ["Info", "Low", "Medium", "High", "Critical"];
        let mut buf = Buffer::empty(Rect::new(0, 0, 30, h));
        RadioGroup::new(&opts, selected, true).render(Rect::new(0, 0, 30, h), &mut buf);
        (0..h)
            .map(|y| (0..30).map(|x| buf[(x, y)].symbol().to_string()).collect())
            .collect()
    }

    #[test]
    fn short_area_scrolls_to_the_selection_with_markers() {
        // High and Critical used to be off screen with no hint.
        let rows = draw(0, 3);
        assert!(
            rows[0].contains("Info") && rows[2].contains("Medium"),
            "{rows:?}"
        );
        assert!(
            rows[2].contains("more") && !rows[0].contains("more"),
            "{rows:?}"
        );
        let rows = draw(4, 3);
        assert!(rows[2].contains("(•) Critical"), "{rows:?}");
        assert!(
            rows[0].contains("more") && !rows[2].contains("more"),
            "{rows:?}"
        );
        let rows = draw(2, 5);
        assert!(rows.iter().all(|r| !r.contains("more")), "{rows:?}");
    }

    #[test]
    fn unrelated_key_is_noop() {
        assert_eq!(handle_radio_key(key(KeyCode::Char('x')), 1, 3), 1);
    }
}
