//! Numeric stepper widget — clamped integer input.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::Widget;

pub struct Stepper<'a> {
    pub label: &'a str,
    pub value: i64,
    pub min: i64,
    pub max: i64,
    pub focused: bool,
}

impl<'a> Widget for Stepper<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let style = if self.focused {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        let line = format!("{}: [ {:>6} ] (range {}–{})", self.label, self.value, self.min, self.max);
        buf.set_string(area.x, area.y, line, style);
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum StepperOutcome {
    None,
    Changed(i64),
    OutOfRange,
}

#[must_use]
pub fn handle_stepper_key(key: KeyEvent, current: i64, min: i64, max: i64) -> StepperOutcome {
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => {
            let next = current.saturating_add(1);
            if next > max { StepperOutcome::OutOfRange } else { StepperOutcome::Changed(next) }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            let next = current.saturating_sub(1);
            if next < min { StepperOutcome::OutOfRange } else { StepperOutcome::Changed(next) }
        }
        KeyCode::PageUp => {
            let next = (current.saturating_add(100)).min(max);
            StepperOutcome::Changed(next)
        }
        KeyCode::PageDown => {
            let next = (current.saturating_sub(100)).max(min);
            StepperOutcome::Changed(next)
        }
        _ => StepperOutcome::None,
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
    fn up_increments_within_bounds() {
        assert_eq!(handle_stepper_key(key(KeyCode::Up), 5, 0, 10), StepperOutcome::Changed(6));
    }

    #[test]
    fn up_at_max_returns_out_of_range() {
        assert_eq!(handle_stepper_key(key(KeyCode::Up), 10, 0, 10), StepperOutcome::OutOfRange);
    }

    #[test]
    fn down_at_min_returns_out_of_range() {
        assert_eq!(handle_stepper_key(key(KeyCode::Down), 0, 0, 10), StepperOutcome::OutOfRange);
    }

    #[test]
    fn pageup_clamps_to_max() {
        assert_eq!(handle_stepper_key(key(KeyCode::PageUp), 50, 0, 100), StepperOutcome::Changed(100));
    }

    #[test]
    fn pagedown_clamps_to_min() {
        assert_eq!(handle_stepper_key(key(KeyCode::PageDown), 50, 0, 100), StepperOutcome::Changed(0));
    }

}
