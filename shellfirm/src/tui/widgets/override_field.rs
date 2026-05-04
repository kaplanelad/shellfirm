//! Two-state override widget — Inherit global vs Custom.
//!
//! Per spec §6.2.2: each per-mode override field is either
//! `Inherit { inherited_display }` (showing what the global value is) or
//! `Custom` (where the inner widget — radio, picker, etc — is rendered by
//! the parent below the override widget itself).

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::Widget;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverrideState {
    Inherit,
    Custom,
}

impl Default for OverrideState {
    fn default() -> Self {
        Self::Inherit
    }
}

pub struct OverrideField<'a> {
    pub label: &'a str,
    pub state: &'a OverrideState,
    pub inherited_display: &'a str,
    pub focused: bool,
}

impl<'a> Widget for OverrideField<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let header_style = if self.focused {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        let header = format!("{}", self.label);
        buf.set_string(area.x, area.y, header, header_style);

        let inherit_bullet = if matches!(self.state, OverrideState::Inherit) { "(•)" } else { "( )" };
        let custom_bullet = if matches!(self.state, OverrideState::Custom) { "(•)" } else { "( )" };

        buf.set_string(
            area.x + 2,
            area.y + 1,
            format!("{inherit_bullet} Inherit global  →  {}", self.inherited_display),
            Style::default(),
        );
        buf.set_string(
            area.x + 2,
            area.y + 2,
            format!("{custom_bullet} Custom"),
            Style::default(),
        );
    }
}

/// Toggle the state. Returns the new state. Caller decides what to do with
/// the inner widget visibility.
#[must_use]
pub fn toggle_override(state: &OverrideState) -> OverrideState {
    match state {
        OverrideState::Inherit => OverrideState::Custom,
        OverrideState::Custom => OverrideState::Inherit,
    }
}

/// Free key handler — Tab toggles between Inherit and Custom.
#[must_use]
pub fn handle_override_key(key: KeyEvent, state: &OverrideState) -> Option<OverrideState> {
    match key.code {
        KeyCode::Tab | KeyCode::Char(' ') => Some(toggle_override(state)),
        _ => None,
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
    fn tab_toggles_state() {
        assert_eq!(handle_override_key(key(KeyCode::Tab), &OverrideState::Inherit), Some(OverrideState::Custom));
        assert_eq!(handle_override_key(key(KeyCode::Tab), &OverrideState::Custom), Some(OverrideState::Inherit));
    }

    #[test]
    fn unrelated_key_returns_none() {
        assert_eq!(handle_override_key(key(KeyCode::Char('x')), &OverrideState::Inherit), None);
    }
}
