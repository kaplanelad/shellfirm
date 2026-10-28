//! Accessibility support for the TUI.
//!
//! Colour-independent focus cues, `NO_COLOR`, ASCII fallback glyphs,
//! `TERM=dumb` refusal, a real text caret, and a scroll viewport for tabs
//! that are taller than the terminal.
//!
//! Most tabs and widgets draw straight into the frame buffer with ad-hoc
//! colours. Instead of threading accessibility flags through every widget,
//! [`finalize`] post-processes the finished buffer once per frame:
//!
//! - every highlighted (selected / focused) run of cells gets a `>` marker
//!   in the blank cell to its left, so focus is visible without colour;
//! - with colour disabled, highlighted cells become reverse video + bold,
//!   dim text becomes `DIM`, and all colours are removed (modifiers stay, as
//!   the NO_COLOR spec only forbids colour);
//! - with a non-UTF-8 locale, box-drawing and symbol glyphs are replaced by
//!   ASCII equivalents.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use std::cell::Cell;
use std::sync::OnceLock;

/// Terminal capabilities that change how the TUI is drawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    /// Colours may be used (`NO_COLOR` is unset or empty).
    pub color: bool,
    /// The locale is UTF-8, so non-ASCII glyphs may be used.
    pub unicode: bool,
}

impl Default for Caps {
    fn default() -> Self {
        Self {
            color: true,
            unicode: true,
        }
    }
}

/// `NO_COLOR` disables colour only when it is set to a non-empty value
/// (<https://no-color.org>).
#[must_use]
pub fn color_enabled_from(no_color: Option<&str>) -> bool {
    no_color.is_none_or(str::is_empty)
}

/// Whether the locale (first non-empty of `LC_ALL`, `LC_CTYPE`, `LANG`) is
/// UTF-8. When none of them is set we assume UTF-8, which is what every
/// modern terminal uses.
#[must_use]
pub fn unicode_from(lc_all: Option<&str>, lc_ctype: Option<&str>, lang: Option<&str>) -> bool {
    let locale = [lc_all, lc_ctype, lang]
        .into_iter()
        .flatten()
        .find(|v| !v.is_empty());
    locale.is_none_or(|l| {
        let l = l.to_ascii_lowercase();
        l.contains("utf-8") || l.contains("utf8")
    })
}

/// Capabilities detected from the environment (computed once).
pub fn caps() -> Caps {
    static CAPS: OnceLock<Caps> = OnceLock::new();
    *CAPS.get_or_init(|| {
        let var = |k: &str| std::env::var(k).ok();
        Caps {
            // Same rule as the CLI and the challenge (empty NO_COLOR keeps
            // colour; NO_COLOR=1, CLICOLOR=0 and monochrome TERMs drop it).
            color: crate::config::color_preference(var).unwrap_or(true),
            unicode: unicode_from(
                var("LC_ALL").as_deref(),
                var("LC_CTYPE").as_deref(),
                var("LANG").as_deref(),
            ),
        }
    })
}

/// Returns the message to print instead of starting the TUI when the
/// terminal cannot run a full-screen interface (`TERM=dumb`).
#[must_use]
pub fn refusal_for_term(term: Option<&str>) -> Option<String> {
    if term == Some("dumb") {
        Some(
            "shellfirm: the settings editor needs a full-screen terminal;\n\
             TERM=dumb does not provide one. Instead use:\n  \
             shellfirm config show          view the settings\n  \
             shellfirm config <subcommand>  change one (see --help)\n  \
             shellfirm config edit          edit the file"
                .to_string(),
        )
    } else {
        None
    }
}

// ── Hardware cursor ─────────────────────────────────────────────────────

thread_local! {
    static CURSOR: Cell<Option<(u16, u16)>> = const { Cell::new(None) };
}

/// Clear the requested cursor position (called at the start of a frame).
pub fn reset_cursor() {
    CURSOR.with(|c| c.set(None));
}

/// Request that the terminal cursor be shown at `(x, y)` after this frame.
pub fn request_cursor(x: u16, y: u16) {
    CURSOR.with(|c| c.set(Some((x, y))));
}

/// The cursor position requested during this frame, if any.
#[must_use]
pub fn requested_cursor() -> Option<(u16, u16)> {
    CURSOR.with(Cell::get)
}

/// Draw a single-line text value with a caret at the logical cursor.
///
/// `cursor` is the caret position in characters. The value is scrolled
/// horizontally so the caret stays inside `width`. When `focused`, the
/// cell under the caret is drawn in reverse video (so the caret is visible
/// without colour) and the terminal cursor is requested at the same spot,
/// so screen readers and magnifiers follow the insertion point.
pub fn draw_text_with_caret(
    buf: &mut Buffer,
    x: u16,
    y: u16,
    width: u16,
    value: &str,
    cursor: usize,
    focused: bool,
    style: Style,
) {
    if width == 0 {
        return;
    }
    // One cell group per user-perceived character: a base character plus
    // the zero-width marks that follow it (`e` + U+0301 is one `é`).
    let chars: Vec<char> = value.chars().collect();
    let starts = cluster_starts(value);
    let cursor = snap_to_cluster(value, cursor.min(chars.len()));
    let clusters: Vec<(usize, String, usize)> = starts
        .iter()
        .enumerate()
        .map(|(n, &st)| {
            let end = starts.get(n + 1).copied().unwrap_or(chars.len());
            let text: String = chars[st..end].iter().collect();
            let w = cluster_width(&chars[st..end]);
            (st, text, w)
        })
        .collect();
    // Visual column of the caret, and the scroll needed to keep it (plus
    // one cell for the caret itself) inside the field.
    let col = |upto: usize| -> usize {
        clusters
            .iter()
            .take_while(|(st, _, _)| *st < upto)
            .map(|(_, _, w)| *w)
            .sum()
    };
    let caret_col = col(cursor);
    let avail = width as usize;
    let mut first = 0usize;
    while clusters.get(first).is_some_and(|(st, _, _)| *st < cursor)
        && caret_col - col(clusters[first].0) + 1 > avail
    {
        first += 1;
    }
    let mut cx = x;
    let end_x = x + width;
    for (st, text, w) in clusters.iter().skip(first) {
        let w = *w as u16;
        if cx + w > end_x {
            break;
        }
        let mut sty = style;
        if focused && *st == cursor {
            sty = sty.add_modifier(Modifier::REVERSED);
            request_cursor(cx, y);
        }
        buf.set_string(cx, y, text, sty);
        cx += w;
    }
    if focused && cursor == chars.len() && cx < end_x {
        buf.set_string(cx, y, " ", style.add_modifier(Modifier::REVERSED));
        request_cursor(cx, y);
    }
}

/// `true` for a character drawn on top of the previous one (combining
/// marks, variation selectors, zero-width joiners).
fn joins_previous(c: char) -> bool {
    !c.is_control() && char_width(c) == 0
}

/// `true` for a regional indicator (two of them form a flag: 🇮🇱).
const fn is_regional_indicator(c: char) -> bool {
    matches!(c as u32, 0x1F1E6..=0x1F1FF)
}

/// `true` for an emoji skin-tone modifier (U+1F3FB..U+1F3FF).
const fn is_emoji_modifier(c: char) -> bool {
    matches!(c as u32, 0x1F3FB..=0x1F3FF)
}

/// `true` for the emoji tag characters (subdivision flags such as 🏴󠁧󠁢󠁳󠁣󠁴󠁿).
const fn is_tag(c: char) -> bool {
    matches!(c as u32, 0xE0020..=0xE007F)
}

/// Character indices where a user-perceived character starts.
///
/// These are extended grapheme clusters, for the cases a terminal user
/// types: a base character and the zero-width marks after it stay together
/// (`e` + U+0301), as do flags (two regional indicators), emoji ZWJ
/// sequences (`👩‍💻`), skin-tone modifiers, variation selectors and tag
/// sequences.
#[must_use]
pub fn cluster_starts(value: &str) -> Vec<usize> {
    let chars: Vec<char> = value.chars().collect();
    let mut starts = Vec::new();
    // Regional indicators seen in a row in the current run (pairs).
    let mut ri_run = 0usize;
    for (i, &c) in chars.iter().enumerate() {
        let joins = i > 0 && {
            let prev = chars[i - 1];
            if prev == '\u{200D}' && !c.is_control() {
                // ZWJ glues the next character to the sequence.
                true
            } else if is_regional_indicator(c) && is_regional_indicator(prev) {
                ri_run % 2 == 1
            } else {
                is_emoji_modifier(c) || is_tag(c) || joins_previous(c)
            }
        };
        if is_regional_indicator(c) {
            ri_run = if i > 0 && is_regional_indicator(chars[i - 1]) {
                ri_run + 1
            } else {
                1
            };
        } else {
            ri_run = 0;
        }
        if !joins {
            starts.push(i);
        }
    }
    starts
}

/// Display width of a cluster (`chars`): a multi-symbol emoji (flag, ZWJ
/// sequence, skin tone) is drawn in two cells, like one emoji.
fn cluster_width(chars: &[char]) -> usize {
    let visible = chars.iter().filter(|c| char_width(**c) > 0).count();
    if visible > 1 {
        2
    } else {
        chars.iter().map(|c| char_width(*c)).sum::<usize>().max(1)
    }
}

/// `caret` (a character index) moved back to the start of its cluster.
#[must_use]
pub fn snap_to_cluster(value: &str, caret: usize) -> usize {
    let len = value.chars().count();
    if caret >= len {
        return len;
    }
    cluster_starts(value)
        .into_iter()
        .take_while(|s| *s <= caret)
        .last()
        .unwrap_or(0)
}

/// The caret position one user-perceived character to the left.
#[must_use]
pub fn prev_cluster(value: &str, caret: usize) -> usize {
    cluster_starts(value)
        .into_iter()
        .take_while(|s| *s < caret)
        .last()
        .unwrap_or(0)
}

/// The caret position one user-perceived character to the right.
#[must_use]
pub fn next_cluster(value: &str, caret: usize) -> usize {
    let len = value.chars().count();
    cluster_starts(value)
        .into_iter()
        .find(|s| *s > caret)
        .unwrap_or(len)
}

/// The caret position at the start of the word before `caret` (Ctrl-W).
#[must_use]
pub fn prev_word(value: &str, caret: usize) -> usize {
    let chars: Vec<char> = value.chars().collect();
    let mut i = caret.min(chars.len());
    while i > 0 && chars[i - 1].is_whitespace() {
        i -= 1;
    }
    while i > 0 && !chars[i - 1].is_whitespace() {
        i -= 1;
    }
    i
}

/// Display width of one character (0, 1 or 2 cells).
fn char_width(c: char) -> usize {
    ratatui::text::Span::raw(c.to_string()).width()
}

/// Mark the caret at the end of `before` (text drawn from column `x`):
/// reverse-video the cell after it and request the terminal cursor there.
/// For simple append-only input buffers.
pub fn caret_after(buf: &mut Buffer, x: u16, y: u16, before: &str) {
    let cx = x + ratatui::text::Span::raw(before).width() as u16;
    let area = buf.area;
    if cx < area.x + area.width && y < area.y + area.height {
        let cell = &mut buf[(cx, y)];
        cell.modifier.insert(Modifier::REVERSED);
        request_cursor(cx, y);
    }
}

// ── Tab viewport ────────────────────────────────────────────────────────

/// Render a tab into an off-screen buffer and show a scrolled window of it.
///
/// `render` draws into a buffer `virtual_height` rows tall; this function
/// then copies a window of `area.height` rows into `buf`, scrolled so the
/// focused row stays visible. `▲ more` / `▼ more` markers show hidden
/// content. Used when the terminal is shorter than a tab's layout.
pub fn render_scrolled(
    buf: &mut Buffer,
    area: Rect,
    virtual_height: u16,
    render: impl FnOnce(Rect, &mut Buffer),
) {
    let vrect = Rect {
        x: 0,
        y: 0,
        width: area.width,
        height: virtual_height.max(area.height),
    };
    // A tab may draw past its area (a long list plus an open entry
    // field). Give the off-screen buffer generous slack so such rows land
    // here and are scrolled to, never written outside the real frame.
    let mut vbuf = Buffer::empty(Rect {
        height: vrect.height.saturating_add(64),
        ..vrect
    });
    let outer_cursor = requested_cursor();
    reset_cursor();
    render(vrect, &mut vbuf);
    let vrect = vbuf.area;
    let inner_cursor = requested_cursor();
    reset_cursor();
    if let Some(c) = outer_cursor {
        request_cursor(c.0, c.1);
    }

    // Last row with any content bounds the scroll range.
    let row_blank = |y: u16| (0..vrect.width).all(|x| vbuf[(x, y)].symbol() == " ");
    let content_rows = (0..vrect.height)
        .rev()
        .find(|&y| !row_blank(y))
        .map_or(0, |y| y + 1);
    let visible = area.height;
    let max_offset = content_rows.saturating_sub(visible);
    let focus_row = inner_cursor
        .map(|(_, y)| y)
        .or_else(|| find_focus_row(&vbuf, vrect));
    let offset = focus_row.map_or(0, |fy| {
        if fy < visible.saturating_sub(1) {
            0
        } else {
            // Keep one row of context above the focus where possible, and
            // as much of the focused block below it as fits.
            fy.saturating_sub(visible / 3)
        }
    });
    let offset = offset.min(max_offset);

    for dy in 0..visible {
        let sy = offset + dy;
        if sy >= vrect.height {
            break;
        }
        for dx in 0..area.width {
            buf[(area.x + dx, area.y + dy)] = vbuf[(dx, sy)].clone();
        }
    }
    if let Some((cx, cy)) = inner_cursor {
        if cy >= offset && cy < offset + visible {
            request_cursor(area.x + cx, area.y + (cy - offset));
        }
    }
    let marker_style = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD);
    if offset > 0 {
        let m = "▲ more";
        buf.set_string(
            area.x + area.width.saturating_sub(m.chars().count() as u16),
            area.y,
            m,
            marker_style,
        );
    }
    if offset + visible < content_rows {
        let m = "▼ more";
        buf.set_string(
            area.x + area.width.saturating_sub(m.chars().count() as u16),
            area.y + visible.saturating_sub(1),
            m,
            marker_style,
        );
    }
}

/// A highlighted cell: the selection styling used across the TUI is a
/// coloured background plus bold.
fn is_highlight(cell: &ratatui::buffer::Cell) -> bool {
    !matches!(cell.bg, Color::Reset | Color::Black) && cell.modifier.contains(Modifier::BOLD)
}

/// A focused section bar: `▌` drawn in yellow (browsing) or green (editing).
fn is_focus_bar(cell: &ratatui::buffer::Cell) -> bool {
    cell.symbol() == "▌" && matches!(cell.fg, Color::Yellow | Color::Green)
}

fn find_focus_row(buf: &Buffer, area: Rect) -> Option<u16> {
    let row_has = |y: u16, f: &dyn Fn(&ratatui::buffer::Cell) -> bool| {
        (area.x..area.x + area.width).any(|x| f(&buf[(x, y)]))
    };
    (area.y..area.y + area.height)
        .find(|&y| row_has(y, &is_highlight))
        .or_else(|| (area.y..area.y + area.height).find(|&y| row_has(y, &is_focus_bar)))
}

// ── Frame post-processing ───────────────────────────────────────────────

/// ASCII replacement for a single-cell glyph, if it has one.
#[must_use]
pub fn ascii_glyph(s: &str) -> Option<&'static str> {
    Some(match s {
        "▌" | "│" | "┃" => "|",
        "─" | "━" | "—" | "–" | "·" => "-",
        "╭" | "╮" | "╰" | "╯" | "┌" | "┐" | "└" | "┘" => "+",
        // Success and failure differ by more than letter case (a screen
        // reader may not announce case): `+` and `X`.
        "✓" | "✔" => "+",
        "×" => "x",
        // Not `-`: that reads as a list bullet or a separator.
        "✗" | "✘" => "X",
        "●" | "•" => "*",
        "→" | "➤" | "▶" | "►" | "›" | "≥" => ">",
        "←" | "◄" | "‹" | "≤" => "<",
        "↔" => "-",
        "◉" => "@",
        "○" => "o",
        "▲" | "↑" => "^",
        "▼" | "↓" => "v",
        "…" => ".",
        "█" => "#",
        "°" => "o",
        _ => return None,
    })
}

/// `unicode` when the terminal can show it, otherwise `ascii`. For text
/// whose ASCII form is longer than one cell (`≥` → `>=`), which the
/// per-cell mapping of [`finalize`] cannot express.
#[must_use]
pub fn sym(unicode: &'static str, ascii: &'static str) -> &'static str {
    if caps().unicode {
        unicode
    } else {
        ascii
    }
}

/// Post-process a finished frame for accessibility (see module docs).
pub fn finalize(buf: &mut Buffer, caps: Caps) {
    let area = buf.area;
    // 1. Colour-independent focus marker: `>` left of each highlighted run.
    // The tab bar (first row) marks the active tab with brackets instead.
    for y in area.y + 1..area.y + area.height {
        let mut x = area.x + 1;
        while x < area.x + area.width {
            let here = is_highlight(&buf[(x, y)]);
            let left = &buf[(x - 1, y)];
            if here && !is_highlight(left) && left.symbol() == " " {
                let style = Style::default()
                    .add_modifier(Modifier::BOLD)
                    .fg(buf[(x, y)].bg);
                let bg = left.bg;
                buf.set_string(x - 1, y, ">", style.bg(bg));
            }
            x += 1;
        }
    }
    // 2. Colour removal and 3. ASCII glyphs.
    for y in area.y..area.y + area.height {
        for x in area.x..area.x + area.width {
            let cell = &mut buf[(x, y)];
            // The focused section is marked with `>` in every mode, so
            // focus never depends on colour alone (the colour is kept).
            if is_focus_bar(cell) {
                cell.set_symbol(">");
                cell.modifier.insert(Modifier::BOLD);
            }
            if !caps.color {
                if cell.symbol() == ">" {
                    cell.modifier.insert(Modifier::BOLD);
                } else if cell.symbol() == "▌" {
                    // Unfocused section bars carry no information without
                    // colour; drop them so the focused one stands out.
                    cell.set_symbol(" ");
                }
                if is_highlight(cell) {
                    cell.modifier.insert(Modifier::REVERSED | Modifier::BOLD);
                } else if matches!(cell.fg, Color::DarkGray) {
                    cell.modifier.insert(Modifier::DIM);
                }
                cell.fg = Color::Reset;
                cell.bg = Color::Reset;
            }
            // `…` is expanded to `...` in step 4.
            if !caps.unicode && cell.symbol() != "…" {
                if let Some(a) = ascii_glyph(cell.symbol()) {
                    cell.set_symbol(a);
                }
            }
        }
    }
    // 4. In ASCII a cut marker `…` becomes `...` (a lone `.` reads as a full
    // stop): it takes over up to two cells of the clipped text before it.
    if !caps.unicode {
        for y in area.y..area.y + area.height {
            for x in area.x..area.x + area.width {
                if buf[(x, y)].symbol() != "…" {
                    continue;
                }
                buf[(x, y)].set_symbol(".");
                for back in 1..=2u16 {
                    let Some(px) = x.checked_sub(back).filter(|px| *px >= area.x) else {
                        break;
                    };
                    let cell = &mut buf[(px, y)];
                    if cell.symbol() == " " || cell.symbol().is_empty() {
                        break;
                    }
                    cell.set_symbol(".");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_color_follows_spec() {
        assert!(color_enabled_from(None));
        assert!(color_enabled_from(Some("")));
        assert!(!color_enabled_from(Some("1")));
    }

    #[test]
    fn locale_detection() {
        assert!(unicode_from(None, None, None));
        assert!(!unicode_from(Some("C"), None, Some("en_US.UTF-8")));
        assert!(unicode_from(Some(""), None, Some("en_US.UTF-8")));
        assert!(unicode_from(None, Some("he_IL.utf8"), None));
        assert!(!unicode_from(None, None, Some("POSIX")));
    }

    #[test]
    fn dumb_terminal_is_refused() {
        assert!(refusal_for_term(Some("dumb")).is_some());
        assert!(refusal_for_term(Some("xterm-256color")).is_none());
        assert!(refusal_for_term(None).is_none());
    }

    #[test]
    fn caret_steps_over_flags_zwj_sequences_and_skin_tones() {
        let flag = "\u{1F1EE}\u{1F1F1}x"; // 🇮🇱x
        assert_eq!(cluster_starts(flag), vec![0, 2]);
        assert_eq!(prev_cluster(flag, 2), 0);
        let two_flags = "\u{1F1EE}\u{1F1F1}\u{1F1FA}\u{1F1F8}";
        assert_eq!(cluster_starts(two_flags), vec![0, 2]);
        let coder = "\u{1F469}\u{200D}\u{1F4BB}x"; // 👩‍💻x
        assert_eq!(cluster_starts(coder), vec![0, 3]);
        assert_eq!(next_cluster(coder, 0), 3);
        let thumbs = "\u{1F44D}\u{1F3FD}y"; // 👍🏽y
        assert_eq!(cluster_starts(thumbs), vec![0, 2]);
        let heart = "\u{2764}\u{FE0F}z";
        assert_eq!(cluster_starts(heart), vec![0, 2]);
        // Drawn as one two-cell symbol; the caret after it sits at column 2.
        reset_cursor();
        let mut buf = Buffer::empty(Rect::new(0, 0, 10, 1));
        draw_text_with_caret(&mut buf, 0, 0, 10, coder, 3, true, Style::default());
        assert_eq!(requested_cursor(), Some((2, 0)));
    }

    #[test]
    fn combining_mark_shares_its_letter_cell() {
        reset_cursor();
        let mut buf = Buffer::empty(Rect::new(0, 0, 10, 1));
        draw_text_with_caret(&mut buf, 0, 0, 10, "ae\u{301}b", 4, true, Style::default());
        // Three visible characters; the caret is after them at column 3.
        assert_eq!(requested_cursor(), Some((3, 0)));
        assert_eq!(buf[(1, 0)].symbol(), "e\u{301}");
        assert_eq!(buf[(2, 0)].symbol(), "b");
    }

    #[test]
    fn caret_is_drawn_at_cursor_not_end() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 20, 1));
        reset_cursor();
        draw_text_with_caret(&mut buf, 0, 0, 20, "abcdef", 3, true, Style::default());
        assert!(buf[(3, 0)].modifier.contains(Modifier::REVERSED));
        assert_eq!(buf[(3, 0)].symbol(), "d");
        assert!(!buf[(6, 0)].modifier.contains(Modifier::REVERSED));
        assert_eq!(requested_cursor(), Some((3, 0)));
    }

    #[test]
    fn caret_scrolls_long_values() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 5, 1));
        reset_cursor();
        draw_text_with_caret(&mut buf, 0, 0, 5, "abcdefghij", 10, true, Style::default());
        assert_eq!(requested_cursor(), Some((4, 0)));
        assert_eq!(buf[(3, 0)].symbol(), "j");
    }

    #[test]
    fn finalize_marks_focus_without_color() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 20, 2));
        let hl = Style::default()
            .fg(Color::Black)
            .bg(Color::Green)
            .add_modifier(Modifier::BOLD);
        buf.set_string(2, 1, "[x] base", hl);
        finalize(
            &mut buf,
            Caps {
                color: false,
                unicode: false,
            },
        );
        assert_eq!(buf[(1, 1)].symbol(), ">");
        assert!(buf[(2, 1)].modifier.contains(Modifier::REVERSED));
        assert_eq!(buf[(2, 1)].bg, Color::Reset);
    }

    #[test]
    fn finalize_ascii_glyphs() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 10, 1));
        buf.set_string(0, 0, "▌ ✓ — ●", Style::default());
        finalize(
            &mut buf,
            Caps {
                color: true,
                unicode: false,
            },
        );
        let row: String = (0..7).map(|x| buf[(x, 0)].symbol().to_string()).collect();
        assert_eq!(row, "| + - *");
    }

    #[test]
    fn finalize_ascii_cut_marker_and_cross() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 20, 1));
        buf.set_string(0, 0, "Example… ✗ bad", Style::default());
        finalize(
            &mut buf,
            Caps {
                color: true,
                unicode: false,
            },
        );
        let row: String = (0..14).map(|x| buf[(x, 0)].symbol().to_string()).collect();
        assert_eq!(row, "Examp... X bad");
    }

    #[test]
    fn scrolled_viewport_keeps_focus_visible() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 20, 5));
        render_scrolled(&mut buf, Rect::new(0, 0, 20, 5), 20, |a, b| {
            for y in 0..15 {
                b.set_string(a.x, y, format!("row{y}"), Style::default());
            }
            b.set_string(
                a.x + 6,
                12,
                "FOCUS",
                Style::default()
                    .bg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            );
        });
        let text: String = (0..5)
            .flat_map(|y| (0..20).map(move |x| (x, y)))
            .map(|(x, y)| buf[(x, y)].symbol().to_string())
            .collect();
        assert!(text.contains("FOCUS"));
        assert!(text.contains("more"));
    }
}
