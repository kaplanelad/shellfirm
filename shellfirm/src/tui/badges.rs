//! Mode badges (`shell`, `ai`, `wrap`, `all`) used throughout the TUI.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::widgets::Widget;

pub struct Badge<'a> {
    label: &'a str,
}

#[must_use]
pub fn badge_widget(label: &'static str) -> Badge<'static> {
    Badge { label }
}

impl<'a> Widget for Badge<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let bg = match self.label {
            "shell" => Color::Cyan,
            "ai" => Color::Magenta,
            "wrap" => Color::Yellow,
            _ => Color::Gray,
        };
        let style = Style::default().fg(Color::Black).bg(bg);
        let text = format!(" {} ", self.label);
        buf.set_string(area.x, area.y, text, style);
    }
}

