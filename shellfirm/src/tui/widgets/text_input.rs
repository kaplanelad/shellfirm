//! Text input wrapping `tui_input::Input`.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::Widget;
use tui_input::backend::crossterm::EventHandler;
use tui_input::Input;

#[derive(Debug, Default, Clone)]
pub struct TextInput {
    pub input: Input,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TextInputOutcome {
    None,
    Changed,
    Submitted(String),
    Cancelled,
}

impl TextInput {
    #[must_use]
    pub fn with_value(s: &str) -> Self {
        Self {
            input: Input::default().with_value(s.to_string()),
        }
    }

    /// Caret position, in characters.
    #[must_use]
    pub fn cursor(&self) -> usize {
        self.input.cursor()
    }

    #[must_use]
    pub fn value(&self) -> &str {
        self.input.value()
    }

    pub fn handle(&mut self, key: KeyEvent) -> TextInputOutcome {
        match key.code {
            KeyCode::Enter => TextInputOutcome::Submitted(self.input.value().to_string()),
            KeyCode::Esc => TextInputOutcome::Cancelled,
            // The caret moves (and Backspace / Delete remove) one
            // user-perceived character: `e` + a combining accent is one.
            KeyCode::Left | KeyCode::Right | KeyCode::Backspace | KeyCode::Delete
                if key.modifiers.is_empty() =>
            {
                self.edit_cluster(key.code)
            }
            KeyCode::Char('h') if key.modifiers == KeyModifiers::CONTROL => {
                self.edit_cluster(KeyCode::Backspace)
            }
            _ => {
                let resp = self.input.handle_event(&crossterm::event::Event::Key(key));
                if resp.is_some() {
                    TextInputOutcome::Changed
                } else {
                    TextInputOutcome::None
                }
            }
        }
    }
}

impl TextInput {
    fn edit_cluster(&mut self, code: KeyCode) -> TextInputOutcome {
        use crate::tui::a11y::{next_cluster, prev_cluster};
        let value = self.input.value().to_string();
        let caret = self.input.cursor();
        let (new_value, new_caret) = match code {
            KeyCode::Left => (None, prev_cluster(&value, caret)),
            KeyCode::Right => (None, next_cluster(&value, caret)),
            KeyCode::Backspace => {
                let from = prev_cluster(&value, caret);
                (Some(remove_chars(&value, from, caret)), from)
            }
            _ => {
                let to = next_cluster(&value, caret);
                (Some(remove_chars(&value, caret, to)), caret)
            }
        };
        let changed = new_value.as_ref().is_some_and(|v| *v != value) || new_caret != caret;
        self.input = Input::default()
            .with_value(new_value.unwrap_or(value))
            .with_cursor(new_caret);
        if changed {
            TextInputOutcome::Changed
        } else {
            TextInputOutcome::None
        }
    }
}

/// `value` without the characters `from..to` (character indices).
fn remove_chars(value: &str, from: usize, to: usize) -> String {
    value
        .chars()
        .enumerate()
        .filter(|(i, _)| *i < from || *i >= to)
        .map(|(_, c)| c)
        .collect()
}

pub struct TextInputView<'a> {
    pub label: &'a str,
    pub input: &'a TextInput,
    pub focused: bool,
}

impl<'a> Widget for TextInputView<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let label_style = if self.focused {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        buf.set_string(area.x, area.y, self.label, label_style);
        crate::tui::a11y::draw_text_with_caret(
            buf,
            area.x + 1,
            area.y + 1,
            area.width.saturating_sub(1),
            self.input.value(),
            self.input.input.cursor(),
            self.focused,
            Style::default(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::empty())
    }

    #[test]
    fn typing_changes_value() {
        let mut t = TextInput::default();
        let outcome = t.handle(key(KeyCode::Char('h')));
        assert_eq!(outcome, TextInputOutcome::Changed);
        assert_eq!(t.value(), "h");
    }

    #[test]
    fn enter_submits_value() {
        let mut t = TextInput::with_value("hello");
        let outcome = t.handle(key(KeyCode::Enter));
        assert_eq!(outcome, TextInputOutcome::Submitted("hello".to_string()));
    }

    #[test]
    fn caret_moves_over_a_letter_and_its_accent() {
        // Two Lefts from the end of `ae\u{301}b` land before
        // the accented `e`, so `Z` goes before it.
        let mut t = TextInput::with_value("ae\u{301}b");
        t.handle(key(KeyCode::Left));
        t.handle(key(KeyCode::Left));
        t.handle(key(KeyCode::Char('Z')));
        assert_eq!(t.value(), "aZe\u{301}b");
        let mut t = TextInput::with_value("ae\u{301}");
        t.handle(key(KeyCode::Backspace));
        assert_eq!(t.value(), "a");
        let mut t = TextInput::with_value("ab");
        t.handle(KeyEvent::new(KeyCode::Char('h'), KeyModifiers::CONTROL));
        assert_eq!(t.value(), "a");
    }

    #[test]
    fn caret_moves_over_flags_and_zwj_sequences() {
        // `🇮🇱x`, Left Left, `Q` -> `Q🇮🇱x` (the flag stays whole).
        let mut t = TextInput::with_value("\u{1F1EE}\u{1F1F1}x");
        t.handle(key(KeyCode::Left));
        t.handle(key(KeyCode::Left));
        t.handle(key(KeyCode::Char('Q')));
        assert_eq!(t.value(), "Q\u{1F1EE}\u{1F1F1}x");
        let mut t = TextInput::with_value("\u{1F469}\u{200D}\u{1F4BB}x");
        t.handle(key(KeyCode::Left));
        t.handle(key(KeyCode::Left));
        t.handle(key(KeyCode::Char('Z')));
        assert_eq!(t.value(), "Z\u{1F469}\u{200D}\u{1F4BB}x");
        let mut t = TextInput::with_value("a\u{1F469}\u{200D}\u{1F4BB}");
        t.handle(key(KeyCode::Backspace));
        assert_eq!(t.value(), "a");
        let mut t = TextInput::with_value("\u{1F44D}\u{1F3FD}y");
        t.handle(key(KeyCode::Left));
        t.handle(key(KeyCode::Left));
        t.handle(key(KeyCode::Delete));
        assert_eq!(t.value(), "y");
    }

    #[test]
    fn esc_cancels() {
        let mut t = TextInput::with_value("anything");
        let outcome = t.handle(key(KeyCode::Esc));
        assert_eq!(outcome, TextInputOutcome::Cancelled);
    }
}
