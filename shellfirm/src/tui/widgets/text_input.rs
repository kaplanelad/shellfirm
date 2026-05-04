//! Text input wrapping `tui_input::Input`.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::Widget;
use tui_input::Input;
use tui_input::backend::crossterm::EventHandler;

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
        Self { input: Input::default().with_value(s.to_string()) }
    }

    #[must_use]
    pub fn value(&self) -> &str {
        self.input.value()
    }

    pub fn handle(&mut self, key: KeyEvent) -> TextInputOutcome {
        match key.code {
            KeyCode::Enter => TextInputOutcome::Submitted(self.input.value().to_string()),
            KeyCode::Esc => TextInputOutcome::Cancelled,
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
        let cursor = if self.focused { "_" } else { "" };
        let line = format!(" {}{}", self.input.value(), cursor);
        buf.set_string(area.x, area.y + 1, line, Style::default());
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
    fn esc_cancels() {
        let mut t = TextInput::with_value("anything");
        let outcome = t.handle(key(KeyCode::Esc));
        assert_eq!(outcome, TextInputOutcome::Cancelled);
    }

}
