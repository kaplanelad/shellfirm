//! Shared design primitives — section headers, spacing, alignment helpers.
//!
//! Keeping these in one module means every tab renders with the same
//! visual language: section bars, badge placement, content indent.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};

/// Left padding from the tab body's left edge to actual content. Section
/// headers sit at this column; inside a section, content is indented 2
/// more characters.
pub const CONTENT_LEFT_PAD: u16 = 0;
pub const SECTION_INDENT: u16 = 2;

/// Width reserved for a section badge on the right side of the header
/// (e.g. `[all]`, `[shell]`).
pub const BADGE_WIDTH: u16 = 8;

/// Render a section header with a colored left bar, bold title, and an
/// optional right-aligned badge. Returns the y row immediately after the
/// header (header + 1 blank row).
///
/// ```text
/// ▌ Section title                                           [badge]
/// (blank line)
/// ```
pub fn section_header(
    buf: &mut Buffer,
    area_x: u16,
    area_y: u16,
    area_width: u16,
    title: &str,
    badge: Option<&str>,
    focused: bool,
) -> u16 {
    let bar_color = if focused {
        Color::Yellow
    } else {
        Color::Cyan
    };
    buf.set_string(area_x, area_y, "▌", Style::default().fg(bar_color));
    let title_style = Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD);
    buf.set_string(area_x + 2, area_y, title, title_style);

    if let Some(b) = badge {
        let badge_text = format!("[{b}]");
        let badge_x = area_x + area_width.saturating_sub(badge_text.chars().count() as u16);
        buf.set_string(
            badge_x,
            area_y,
            &badge_text,
            Style::default().fg(Color::DarkGray),
        );
    }

    area_y + 2 // header row + one blank line for breathing room
}

/// Render an inline help text under a section, dim style.
pub fn section_help(buf: &mut Buffer, area_x: u16, area_y: u16, text: &str) {
    buf.set_string(
        area_x + SECTION_INDENT,
        area_y,
        text,
        Style::default().fg(Color::DarkGray),
    );
}

/// Compute the column where descriptions should start, given a maximum
/// label length. Used by `RadioGroup::with_descriptions` to keep all
/// radio descriptions in a consistent column.
pub const fn description_column(area_x: u16, max_label_width: u16) -> u16 {
    // bullet "( ) " = 4 chars, + label, + 4-char gap before description
    area_x + 4 + max_label_width + 4
}

/// Style for a content row that's currently focused (cursor here).
pub fn focused_row_style() -> Style {
    Style::default()
        .fg(Color::Black)
        .bg(Color::Green)
        .add_modifier(Modifier::BOLD)
}

/// Style for a value display (e.g. "[ ✓ enabled ]") in a toggle row.
pub fn value_style() -> Style {
    Style::default().fg(Color::Cyan)
}

#[allow(dead_code)]
pub fn dim_style() -> Style {
    Style::default().fg(Color::DarkGray)
}

#[allow(dead_code)]
pub fn _avoid_unused(_a: Rect) {}
