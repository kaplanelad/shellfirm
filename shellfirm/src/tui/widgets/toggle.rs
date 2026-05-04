//! On/off toggle widget bound to a `bool`.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::Widget;

pub struct Toggle<'a> {
    label: &'a str,
    value: bool,
    focused: bool,
}

impl<'a> Toggle<'a> {
    #[must_use]
    pub fn new(label: &'a str, value: bool, focused: bool) -> Self {
        Self { label, value, focused }
    }
}

impl<'a> Widget for Toggle<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let on = if self.value { "[ ✓ enabled ]" } else { "[   disabled  ]" };
        let style = if self.focused {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        let line = format!("{}  {}", self.label, on);
        buf.set_string(area.x, area.y, line, style);
    }
}

