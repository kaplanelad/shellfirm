//! Regex input — text input with live compile validation.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::Widget;
use crate::tui::widgets::text_input::TextInput;

#[derive(Debug, Clone)]
pub enum RegexValidity {
    Empty,
    Valid,
    Invalid(String),
}

impl RegexValidity {
    #[must_use]
    pub fn for_value(s: &str) -> Self {
        if s.is_empty() {
            Self::Empty
        } else {
            match regex::Regex::new(s) {
                Ok(_) => Self::Valid,
                Err(e) => Self::Invalid(e.to_string()),
            }
        }
    }
}

pub struct RegexInput<'a> {
    pub label: &'a str,
    pub input: &'a TextInput,
    pub focused: bool,
}

impl<'a> Widget for RegexInput<'a> {
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
        buf.set_string(
            area.x,
            area.y + 1,
            format!(" {}{}", self.input.value(), cursor),
            Style::default(),
        );

        let validity = RegexValidity::for_value(self.input.value());
        let (msg, color) = match &validity {
            RegexValidity::Empty => ("(empty)".to_string(), Color::DarkGray),
            RegexValidity::Valid => ("✓ regex compiles".to_string(), Color::Green),
            RegexValidity::Invalid(err) => (format!("✗ {err}"), Color::Red),
        };
        buf.set_string(area.x, area.y + 2, msg, Style::default().fg(color));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_value_is_empty_validity() {
        assert!(matches!(RegexValidity::for_value(""), RegexValidity::Empty));
    }

    #[test]
    fn valid_regex_compiles() {
        assert!(matches!(RegexValidity::for_value("^foo.*"), RegexValidity::Valid));
    }

    #[test]
    fn invalid_regex_carries_error() {
        match RegexValidity::for_value("[unclosed") {
            RegexValidity::Invalid(s) => assert!(!s.is_empty()),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

}
