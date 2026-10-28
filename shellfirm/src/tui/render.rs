//! Top-level frame: tab bar, active tab body, focused-field strip, hint bar,
//! preview pane (when toggled), and modal overlays.

use crate::tui::app::App;
use crate::tui::tabs::Tab;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::Widget;
use ratatui::Frame;

/// Smallest terminal the TUI lays out in. Tabs taller than the body scroll.
pub const MIN_WIDTH: u16 = 60;
pub const MIN_HEIGHT: u16 = 16;

pub fn draw(f: &mut Frame, app: &App) {
    crate::tui::a11y::reset_cursor();
    draw_frame(f, app);
    crate::tui::a11y::finalize(f.buffer_mut(), crate::tui::a11y::caps());
    if let Some(pos) = crate::tui::a11y::requested_cursor() {
        f.set_cursor_position(pos);
    }
}

/// Cut `text` to `width` characters, ending with `…` when it was longer.
fn clip(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_string();
    }
    let mut out: String = text.chars().take(width.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Greedy word wrap to `width` columns (character count).
pub fn wrap_words(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut lines = Vec::new();
    let mut cur = String::new();
    for word in text.split_whitespace() {
        let wlen = word.chars().count();
        let clen = cur.chars().count();
        if clen > 0 && clen + 1 + wlen > width {
            lines.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push(' ');
        }
        if wlen > width {
            // Hard-split a word that can never fit.
            let mut chars: Vec<char> = word.chars().collect();
            while chars.len() > width {
                let rest = chars.split_off(width);
                lines.push(chars.iter().collect());
                chars = rest;
            }
            cur.push_str(&chars.iter().collect::<String>());
        } else {
            cur.push_str(word);
        }
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    lines
}

fn draw_too_small(f: &mut Frame, app: &App) {
    let area = f.area();
    // The action comes first so it survives in the tiniest window; keys
    // other than these do nothing here (the editor is hidden).
    let text = if matches!(app.modal, Some(crate::tui::app::Modal::Quit(_))) {
        format!(
            "Unsaved changes: {}. Press s to save and quit, d to discard them and quit, Esc to go back. \
             (Terminal too small: {}x{}; the editor needs {MIN_WIDTH}x{MIN_HEIGHT}.)",
            app.unsaved_items().join("; "),
            area.width,
            area.height
        )
    } else {
        format!(
            "Press q to quit. Terminal too small: {}x{}. shellfirm config needs at least \
             {MIN_WIDTH} columns x {MIN_HEIGHT} rows; other keys do nothing until the window is \
             larger. Or use `shellfirm config show` and `shellfirm config --help`.",
            area.width, area.height
        )
    };
    let mut lines = wrap_words(&text, area.width as usize);
    if let Some(msg) = &app.status_message {
        lines.insert(0, format!("Note: {msg}"));
    }
    for (i, line) in lines.iter().enumerate() {
        if i as u16 >= area.height {
            break;
        }
        f.buffer_mut().set_stringn(
            0,
            i as u16,
            line,
            area.width as usize,
            Style::default().fg(Color::Yellow),
        );
    }
}

fn draw_frame(f: &mut Frame, app: &App) {
    let area = f.area();
    let too_small = area.width < MIN_WIDTH || area.height < MIN_HEIGHT;
    app.too_small.set(too_small);
    if too_small {
        draw_too_small(f, app);
        return;
    }

    // Vertical split: [tab_bar (1)] [body (rest)] [field_strip (2)] [hint_bar (1)]
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // tab bar
            Constraint::Min(8),    // body
            Constraint::Length(2), // field strip
            Constraint::Length(1), // hint bar
        ])
        .split(area);

    draw_tab_bar(f, app, chunks[0]);

    // Body layout: preview is either off, or split-pane on the right.
    use crate::tui::app::PreviewMode;
    match app.preview.mode {
        PreviewMode::Closed => {
            draw_active_tab(f, app, chunks[1]);
        }
        PreviewMode::Open if chunks[1].width >= 100 => {
            let body = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
                .split(chunks[1]);
            draw_active_tab(f, app, body[0]);
            draw_preview(f, app, body[1]);
        }
        PreviewMode::Open => {
            // Terminal too narrow for split — fall back to full-area preview.
            draw_preview(f, app, chunks[1]);
        }
    }

    draw_field_strip(f, app, chunks[2]);
    draw_hint_bar(f, app, chunks[3]);

    // Form overlay, then modal overlays on top (a quit dialog can sit over
    // an open form).
    if let Some(form) = &app.form {
        let outer = centered_rect(80, 90, area);
        // Clear background of the modal frame so the underlying tab doesn't bleed through.
        for y in outer.y..outer.y + outer.height {
            for x in outer.x..outer.x + outer.width {
                f.buffer_mut()[(x, y)].set_symbol(" ");
                f.buffer_mut()[(x, y)].set_style(Style::default().bg(Color::Black));
            }
        }
        // Border around the modal.
        let border_style = Style::default().fg(Color::DarkGray).bg(Color::Black);
        for x in outer.x..outer.x + outer.width {
            f.buffer_mut().set_string(x, outer.y, "─", border_style);
            f.buffer_mut().set_string(
                x,
                outer.y + outer.height.saturating_sub(1),
                "─",
                border_style,
            );
        }
        for y in outer.y..outer.y + outer.height {
            f.buffer_mut().set_string(outer.x, y, "│", border_style);
            f.buffer_mut().set_string(
                outer.x + outer.width.saturating_sub(1),
                y,
                "│",
                border_style,
            );
        }
        // Inner content area, inset by the border.
        let inner = Rect {
            x: outer.x + 1,
            y: outer.y + 1,
            width: outer.width.saturating_sub(2),
            height: outer.height.saturating_sub(2),
        };
        Widget::render(form, inner, f.buffer_mut());
    }
    if let Some(modal) = &app.modal {
        // A dialog has the focus: no caret may stay in a text box behind
        // it (screen magnifiers and readers follow the caret).
        crate::tui::a11y::reset_cursor();
        draw_modal(f, app, modal);
    }
}

fn draw_tab_bar(f: &mut Frame, app: &App, area: Rect) {
    // Tab titles. Mode-specific tabs (AI, Wrap) get a subtle color tint on
    // the title text instead of a separate inline badge — the duplicated
    // "AI ai" / "Wrap wrap" was visual noise.
    let titles: &[(&str, Option<Color>)] = &[
        ("General", None),
        ("Groups", None),
        ("Escalation", None),
        ("Context", None),
        ("Ignore/Deny", None),
        ("AI", Some(Color::Magenta)),
        ("Wrap", Some(Color::Yellow)),
        ("LLM", None),
        ("Custom", None),
    ];
    // The active tab is bracketed (`[Groups]`) so it is visible without
    // colour. When the labels don't fit, the bar scrolls to keep the active
    // tab visible and shows `‹` / `›` for hidden tabs.
    let dirty_label = "● unsaved";
    let reserve = if app.draft.is_dirty() {
        dirty_label.chars().count() as u16 + 2
    } else {
        0
    };
    let avail = area.width.saturating_sub(reserve + 2);
    let labels: Vec<String> = titles
        .iter()
        .enumerate()
        .map(|(i, (l, _))| {
            if i == app.current_tab {
                format!("[{l}]")
            } else {
                format!(" {l} ")
            }
        })
        .collect();
    let widths: Vec<u16> = labels.iter().map(|l| l.chars().count() as u16).collect();
    // First visible tab: the smallest index such that tabs first..=current fit.
    let mut first = 0usize;
    while first < app.current_tab && widths[first..=app.current_tab].iter().sum::<u16>() > avail {
        first += 1;
    }
    let mut x = area.x + 1;
    if first > 0 {
        f.buffer_mut()
            .set_string(area.x, area.y, "‹", Style::default().fg(Color::Yellow));
    }
    let mut last_shown = first;
    for i in first..titles.len() {
        if x + widths[i] > area.x + 1 + avail {
            break;
        }
        let active = i == app.current_tab;
        let style = if active {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD)
        } else if let Some(c) = titles[i].1 {
            // The tint is colour-only information; without colour the
            // name must look like every other inactive tab (not bold).
            if crate::tui::a11y::caps().color {
                Style::default().fg(c).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            }
        } else {
            Style::default()
        };
        f.buffer_mut().set_string(x, area.y, &labels[i], style);
        x += widths[i];
        last_shown = i;
    }
    if last_shown + 1 < titles.len() {
        f.buffer_mut()
            .set_string(x, area.y, "›", Style::default().fg(Color::Yellow));
    }
    // Dirty marker on the right (space for it is reserved above).
    if app.draft.is_dirty() {
        let label_x = area
            .x
            .saturating_add(area.width)
            .saturating_sub(dirty_label.chars().count() as u16 + 1);
        f.buffer_mut().set_string(
            label_x,
            area.y,
            dirty_label,
            Style::default().fg(Color::Yellow),
        );
    }
}

/// Rows a tab's layout needs. When the body is shorter, the tab is drawn
/// into a taller off-screen buffer and scrolled to the focused row.
const fn tab_min_height(tab: usize) -> u16 {
    match tab {
        0 => 16,
        1 => 8,
        2 | 6 | 7 => 14,
        3 | 5 => 18,
        4 => 12,
        _ => 6,
    }
}

fn draw_active_tab(f: &mut Frame, app: &App, area: Rect) {
    // Always draw through the off-screen viewport: a tab whose content
    // grows while editing (a list with an open "New entry" field) can need
    // more rows than the body has. Drawing it straight into the frame wrote
    // past the last row (a panic at 80x24) or under the footer; the
    // viewport clips it and scrolls to the focused row instead.
    let min = tab_min_height(app.current_tab).max(area.height);
    crate::tui::a11y::render_scrolled(f.buffer_mut(), area, min, |a, b| {
        render_tab(app, a, b);
    });
}

fn render_tab(app: &App, area: Rect, buf: &mut ratatui::buffer::Buffer) {
    match app.current_tab {
        0 => app.general.render(area, buf, &app.draft),
        1 => app.groups.render(area, buf, &app.draft),
        2 => app.escalation.render(area, buf, &app.draft),
        3 => app.context.render(area, buf, &app.draft),
        4 => app.ignore_deny.render(area, buf, &app.draft),
        5 => app.ai.render(area, buf, &app.draft),
        6 => app.wrap.render(area, buf, &app.draft),
        7 => app.llm.render(area, buf, &app.draft),
        8 => app.custom.render(area, buf, &app.draft),
        _ => {}
    }
}

fn draw_preview(f: &mut Frame, app: &App, area: Rect) {
    let yaml = crate::tui::preview::render_yaml(&app.draft.current);
    let diff = crate::tui::preview::line_diff(&app.on_disk_yaml, &yaml);
    let total = diff.len();
    let visible_height = area.height.saturating_sub(1) as usize;

    // Auto-scroll snaps to the first change; once the user manually scrolls,
    // we honor their position (clamped to a valid offset).
    let max_offset = total.saturating_sub(visible_height);
    let offset = if app.preview.auto_scroll {
        crate::tui::preview::first_change_offset(&diff, visible_height, 3)
    } else {
        (app.preview.scroll as usize).min(max_offset)
    };

    // Header: title on the left, position indicator on the right.
    f.buffer_mut().set_string(
        area.x,
        area.y,
        "─ Preview ───",
        Style::default().fg(Color::DarkGray),
    );
    let end = (offset + visible_height).min(total);
    let indicator = if total == 0 {
        "[empty]".to_string()
    } else {
        let up = if offset > 0 { "▲" } else { " " };
        let down = if end < total { "▼" } else { " " };
        format!("[{}-{} of {} {up}{down}]", offset + 1, end, total)
    };
    let indicator_x = area.x + area.width.saturating_sub(indicator.chars().count() as u16);
    f.buffer_mut().set_string(
        indicator_x,
        area.y,
        &indicator,
        Style::default().fg(Color::DarkGray),
    );

    // Reserve the rightmost column of the body for the scrollbar (only
    // when there's actual overflow). Body lines render up to body_width.
    let scrollbar_col = if total > visible_height && area.width > 2 {
        Some(area.x + area.width - 1)
    } else {
        None
    };
    let body_width = if scrollbar_col.is_some() {
        area.width.saturating_sub(2) // 1 for the bar, 1 for breathing room
    } else {
        area.width
    };

    // Body
    let mut y = area.y + 1;
    for line in diff.iter().skip(offset) {
        if y >= area.y + area.height {
            break;
        }
        let (prefix, style, text) = match line {
            crate::tui::preview::DiffLine::Same(s) => {
                ("  ", Style::default().fg(Color::Gray), s.clone())
            }
            crate::tui::preview::DiffLine::Added(s) => {
                ("+ ", Style::default().fg(Color::Green), s.clone())
            }
            crate::tui::preview::DiffLine::Removed(s) => {
                ("- ", Style::default().fg(Color::Red), s.clone())
            }
        };
        // Truncate to body width so we don't overwrite the scrollbar column.
        let mut full = format!("{prefix}{text}");
        if full.chars().count() > body_width as usize {
            let truncated: String = full.chars().take(body_width as usize).collect();
            full = truncated;
        }
        f.buffer_mut().set_string(area.x, y, &full, style);
        y += 1;
    }

    // Scrollbar: draw a track + thumb on the rightmost column. The track
    // shows the full scrollable range; the thumb shows where the current
    // visible window sits within that range.
    if let Some(col) = scrollbar_col {
        let track_top = area.y + 1;
        let track_height = area.height.saturating_sub(1);
        if track_height >= 2 {
            // Render the track (dim vertical line).
            for ty in track_top..track_top + track_height {
                f.buffer_mut()
                    .set_string(col, ty, "│", Style::default().fg(Color::DarkGray));
            }
            // Up/down caps showing direction of more content.
            if offset > 0 {
                f.buffer_mut().set_string(
                    col,
                    track_top,
                    "▲",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                );
            }
            if end < total {
                f.buffer_mut().set_string(
                    col,
                    track_top + track_height - 1,
                    "▼",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                );
            }
            // Thumb size is proportional to the visible fraction of total
            // content; clamped to ≥ 1.
            let inner_height = track_height.saturating_sub(2).max(1);
            let thumb_size =
                (((visible_height as f64 / total as f64) * inner_height as f64).round() as u16)
                    .max(1)
                    .min(inner_height);
            // Thumb position: 0..(inner_height - thumb_size).
            let scroll_range = max_offset.max(1) as f64;
            let thumb_top_offset = ((offset as f64 / scroll_range)
                * (inner_height - thumb_size) as f64)
                .round() as u16;
            let thumb_top = track_top + 1 + thumb_top_offset;
            for ty in thumb_top..thumb_top + thumb_size {
                if ty < track_top + track_height - 1 {
                    f.buffer_mut()
                        .set_string(col, ty, "█", Style::default().fg(Color::Cyan));
                }
            }
        }
    }
}

fn draw_field_strip(f: &mut Frame, app: &App, area: Rect) {
    let focus = &app.focused_field;
    let mut header = format!("Selected: {}", focus.name);
    for badge in &focus.badges {
        header.push_str(&format!("  [{badge}]"));
    }
    // Cut with `…` (not mid-word without a cue) when the window is narrow.
    let width = area.width as usize;
    f.buffer_mut().set_string(
        area.x,
        area.y,
        clip(&header, width),
        Style::default().fg(Color::White),
    );
    if !focus.help.is_empty() {
        f.buffer_mut().set_string(
            area.x,
            area.y + 1,
            clip(&focus.help, width),
            Style::default().fg(Color::DarkGray),
        );
    }
    // A status message (cleared on the next key) is labelled in words, so
    // it does not depend on its colour. It goes right of the header when
    // both fit, otherwise it replaces the help line; it never overwrites
    // the header.
    if let Some(msg) = &app.status_message {
        let note = format!("Note: {msg}");
        let note_w = note.chars().count();
        let header_w = header.chars().count().min(width);
        let style = Style::default().fg(Color::Cyan);
        if header_w + 3 + note_w <= width {
            let pos_x = area.x + (width - note_w) as u16;
            f.buffer_mut().set_string(pos_x, area.y, &note, style);
        } else if area.height > 1 {
            let row = " ".repeat(width);
            f.buffer_mut()
                .set_string(area.x, area.y + 1, row, Style::default());
            f.buffer_mut()
                .set_string(area.x, area.y + 1, clip(&note, width), style);
        }
    }
}

fn draw_hint_bar(f: &mut Frame, app: &App, area: Rect) {
    use crate::tui::app::PreviewMode;
    let preview_indicator = match app.preview.mode {
        PreviewMode::Closed => "p preview",
        PreviewMode::Open => "p close preview · Shift+↑/↓ or PgUp/PgDn to scroll",
    };
    let hint = format!(" {preview_indicator} · s save · q quit · ? help");
    f.buffer_mut().set_string(
        area.x,
        area.y,
        clip(&hint, area.width as usize),
        Style::default().fg(Color::DarkGray),
    );
}

fn draw_modal(f: &mut Frame, app: &App, modal: &crate::tui::app::Modal) {
    let area = match modal {
        crate::tui::app::Modal::Help => centered_rect(94, 92, f.area()),
        // The Save dialog carries a diff or an error list: use most of a
        // small window instead of 70% x 60% of it.
        crate::tui::app::Modal::Save(_) => {
            let full = f.area();
            let w = (full.width * 70 / 100)
                .max(56)
                .min(full.width.saturating_sub(2));
            let h = (full.height * 60 / 100)
                .max(14)
                .min(full.height.saturating_sub(2));
            Rect {
                x: full.x + (full.width - w) / 2,
                y: full.y + (full.height - h) / 2,
                width: w,
                height: h,
            }
        }
        // The quit dialog lists what is unsaved and three keyed buttons:
        // at the editor's 60x16 minimum it takes nearly the whole window.
        crate::tui::app::Modal::Quit(_) => {
            let full = f.area();
            let w = (full.width * 70 / 100)
                .max(58)
                .min(full.width.saturating_sub(2));
            let h = (full.height * 60 / 100)
                .max(12)
                .min(full.height.saturating_sub(2));
            Rect {
                x: full.x + (full.width - w) / 2,
                y: full.y + (full.height - h) / 2,
                width: w,
                height: h,
            }
        }
        _ => centered_rect(70, 60, f.area()),
    };
    // Clear background
    for y in area.y..area.y + area.height {
        for x in area.x..area.x + area.width {
            f.buffer_mut()[(x, y)].set_symbol(" ");
            f.buffer_mut()[(x, y)].set_style(Style::default().bg(Color::Black));
        }
    }
    // Border (simple)
    let border = Style::default().fg(Color::DarkGray);
    for x in area.x..area.x + area.width {
        f.buffer_mut().set_string(x, area.y, "─", border);
        f.buffer_mut()
            .set_string(x, area.y + area.height.saturating_sub(1), "─", border);
    }
    for y in area.y + 1..area.y + area.height.saturating_sub(1) {
        f.buffer_mut().set_string(area.x, y, "│", border);
        f.buffer_mut()
            .set_string(area.x + area.width.saturating_sub(1), y, "│", border);
    }
    if area.width >= 2 && area.height >= 2 {
        let right = area.x + area.width - 1;
        let bottom = area.y + area.height - 1;
        f.buffer_mut().set_string(area.x, area.y, "┌", border);
        f.buffer_mut().set_string(right, area.y, "┐", border);
        f.buffer_mut().set_string(area.x, bottom, "└", border);
        f.buffer_mut().set_string(right, bottom, "┘", border);
    }

    let inner = Rect {
        x: area.x + 2,
        y: area.y + 1,
        width: area.width.saturating_sub(4),
        height: area.height.saturating_sub(2),
    };

    match modal {
        crate::tui::app::Modal::Save(state) => draw_save_dialog(f, app, state, inner),
        crate::tui::app::Modal::Quit(state) => draw_quit_dialog(f, app, state, inner),
        crate::tui::app::Modal::Reset(state) => draw_reset_dialog(f, state, inner),
        crate::tui::app::Modal::Help => draw_help_overlay(f, app, inner),
        crate::tui::app::Modal::DeleteCustom(state) => {
            draw_delete_custom_dialog(f, state, inner);
        }
    }
}

fn draw_save_dialog(
    f: &mut Frame,
    app: &App,
    state: &crate::tui::app::SaveDialogState,
    area: Rect,
) {
    use crate::tui::app::SaveStage;
    f.buffer_mut().set_stringn(
        area.x,
        area.y,
        "Save",
        area.width as usize,
        Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    );
    let width = area.width as usize;

    // The body (verdict + diff or errors) is built as lines first, then a
    // window of it is drawn between the title and the button row. When it
    // does not fit, Up/Down/PgUp/PgDn/Home/End scroll it and `▲ more` /
    // `▼ more` say so.
    let mut body: Vec<(String, Style)> = Vec::new();
    match &state.stage {
        SaveStage::Confirm => {
            body.push((
                crate::tui::a11y::sym("✓ Valid configuration", "OK: Valid configuration")
                    .to_string(),
                Style::default().fg(Color::Green),
            ));
            body.push((String::new(), Style::default()));
            body.push((
                "Diff vs disk:".to_string(),
                Style::default().fg(Color::DarkGray),
            ));
            // The exact change to the settings file (what will be on disk,
            // against what is there now), with context lines and the
            // enclosing keys of nested changes.
            match &state.planned {
                Some(Ok((old, new))) => {
                    let diff = crate::tui::preview::diff_with_context(old, new, 2);
                    let mut any = false;
                    let gap = "...".to_string();
                    for line in &diff {
                        let (prefix, color, text) = match line {
                            None => ("  ", Color::DarkGray, &gap),
                            Some(crate::tui::preview::DiffLine::Same(s)) => ("  ", Color::Gray, s),
                            Some(crate::tui::preview::DiffLine::Added(s)) => {
                                any = true;
                                ("+ ", Color::Green, s)
                            }
                            Some(crate::tui::preview::DiffLine::Removed(s)) => {
                                any = true;
                                ("- ", Color::Red, s)
                            }
                        };
                        body.push((
                            clip(&format!("{prefix}{text}"), width),
                            Style::default().fg(color),
                        ));
                    }
                    if !any {
                        body.push((
                            "No changes to the file".to_string(),
                            Style::default().fg(Color::DarkGray),
                        ));
                    }
                }
                Some(Err(e)) => body.push((
                    clip(&format!("(could not preview the file: {e})"), width),
                    Style::default().fg(Color::Yellow),
                )),
                None => body.push((
                    "No changes".to_string(),
                    Style::default().fg(Color::DarkGray),
                )),
            }
        }
        SaveStage::Errors(errors) => {
            body.push((
                crate::tui::a11y::sym("✗ Invalid configuration", "Error: Invalid configuration")
                    .to_string(),
                Style::default().fg(Color::Red),
            ));
            body.push((String::new(), Style::default()));
            // Wrapped to the dialog width (with a hanging indent) so the
            // useful end of each message ("Did you mean …") stays visible.
            for e in errors {
                let text = format!("{}: {}", e.path, e.message);
                for (i, line) in wrap_words(&text, width.saturating_sub(4))
                    .iter()
                    .enumerate()
                {
                    let indent = if i == 0 { "  " } else { "    " };
                    body.push((format!("{indent}{line}"), Style::default().fg(Color::Red)));
                }
            }
        }
    }

    // Rows between the title (+1 blank) and the button row (-1 blank).
    let top = area.y.saturating_add(2);
    let bottom = area.y.saturating_add(area.height.saturating_sub(2));
    let visible = bottom.saturating_sub(top) as usize;
    let max_scroll = body.len().saturating_sub(visible);
    app.save_max_scroll.set(max_scroll as u16);
    let offset = (state.scroll as usize).min(max_scroll);
    for (i, (text, style)) in body.iter().skip(offset).take(visible).enumerate() {
        f.buffer_mut()
            .set_stringn(area.x, top + i as u16, text, width, *style);
    }
    let marker = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD);
    if visible > 0 && offset > 0 {
        let m = format!("▲ {offset} more");
        let x = area.x + area.width.saturating_sub(m.chars().count() as u16);
        // On the blank row under the title, so it never covers text.
        f.buffer_mut()
            .set_stringn(x, top.saturating_sub(1), &m, width, marker);
    }
    let hidden_below = body.len().saturating_sub(offset + visible);
    if visible > 0 && hidden_below > 0 {
        let m = format!("▼ {hidden_below} more (↑↓ scroll)");
        let m = clip(&m, width);
        let x = area.x + area.width.saturating_sub(m.chars().count() as u16);
        // On the blank row above the buttons, so it never covers text.
        f.buffer_mut().set_stringn(x, bottom, &m, width, marker);
    }

    let btn_y = area.y + area.height.saturating_sub(1);
    match &state.stage {
        SaveStage::Confirm => {
            // Buttons — centered, with distinct selected colors per button
            // (green for Save, yellow for Cancel). Inline because the shared
            // helper assumes a single highlight color.
            let buttons = ["[ Save ]", "[ Cancel ]"];
            let widths: Vec<u16> = buttons.iter().map(|b| b.chars().count() as u16).collect();
            const GAP: u16 = 3;
            let total: u16 = widths.iter().sum::<u16>() + GAP * (buttons.len() as u16 - 1);
            let start_x = if total <= area.width {
                area.x + (area.width - total) / 2
            } else {
                area.x
            };
            let mut x = start_x;
            for (i, button) in buttons.iter().enumerate() {
                let style = if i == state.button {
                    let bg = if i == 0 { Color::Green } else { Color::Yellow };
                    Style::default()
                        .fg(Color::Black)
                        .bg(bg)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                f.buffer_mut().set_string(x, btn_y, *button, style);
                x += widths[i] + GAP;
            }
        }
        SaveStage::Errors(_) => {
            let ok = "[ OK ]";
            let ok_w = ok.chars().count() as u16;
            let ok_x = if ok_w <= area.width {
                area.x + (area.width - ok_w) / 2
            } else {
                area.x
            };
            f.buffer_mut().set_string(
                ok_x,
                btn_y,
                ok,
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            );
        }
    }
}

fn draw_quit_dialog(
    f: &mut Frame,
    app: &App,
    state: &crate::tui::app::QuitDialogState,
    area: Rect,
) {
    let width = area.width as usize;
    f.buffer_mut().set_stringn(
        area.x,
        area.y,
        "You have unsaved changes",
        width,
        Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    );
    // Name what would be lost, then what the buttons do with it.
    let items = app.unsaved_items();
    let mut lines: Vec<String> = Vec::new();
    for item in &items {
        lines.extend(wrap_words(&format!("- {item}"), width));
    }
    let form_open = items
        .iter()
        .any(|i| i.starts_with("an unfinished custom check"));
    let what = if form_open {
        "s saves and quits (an incomplete check stays open to finish), d discards everything \
         and quits, Esc goes back."
    } else {
        "s saves and quits, d discards the changes and quits, Esc goes back."
    };
    lines.push(String::new());
    lines.extend(wrap_words(what, width));
    let max_rows = area.height.saturating_sub(3) as usize;
    for (i, line) in lines.iter().take(max_rows).enumerate() {
        f.buffer_mut().set_stringn(
            area.x,
            area.y + 2 + i as u16,
            line,
            width,
            Style::default().fg(Color::Gray),
        );
    }

    let labels = ["s Save & quit", "d Discard & quit", "Esc Cancel"];
    draw_button_row(f, area, &labels, state.button, Color::Green);
}

/// Lay out a row of `[ Label ]` buttons centered in `area`, with a
/// consistent gap between buttons regardless of individual label widths.
/// Highlights the button at index `selected` with `selected_bg`.
fn draw_button_row(
    f: &mut Frame,
    area: Rect,
    labels: &[&str],
    selected: usize,
    selected_bg: Color,
) {
    // Pre-render to know each button's real width.
    let buttons: Vec<String> = labels.iter().map(|l| format!("[ {l} ]")).collect();
    let widths: Vec<u16> = buttons.iter().map(|b| b.chars().count() as u16).collect();
    let gaps = labels.len().saturating_sub(1) as u16;
    // Three spaces between buttons; one in a narrow dialog, so the row
    // still fits inside the border.
    let gap: u16 = if widths.iter().sum::<u16>() + 3 * gaps <= area.width {
        3
    } else {
        1
    };
    let total: u16 = widths.iter().sum::<u16>() + gap * gaps;

    // Center the row; if the row is wider than the area, fall back to the
    // left edge so we don't underflow.
    let start_x = if total <= area.width {
        area.x + (area.width - total) / 2
    } else {
        area.x
    };
    let row_y = area.y + area.height.saturating_sub(1);

    let mut x = start_x;
    for (i, button) in buttons.iter().enumerate() {
        let style = if i == selected {
            Style::default()
                .fg(Color::Black)
                .bg(selected_bg)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        f.buffer_mut().set_string(x, row_y, button, style);
        x += widths[i] + gap;
    }
}

fn draw_reset_dialog(f: &mut Frame, state: &crate::tui::app::ResetDialogState, area: Rect) {
    f.buffer_mut().set_string(
        area.x,
        area.y,
        "Reset draft?",
        Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    );
    f.buffer_mut().set_string(
        area.x,
        area.y + 2,
        "All in-progress changes will be lost.",
        Style::default().fg(Color::Gray),
    );

    let labels = ["Reset", "Cancel"];
    draw_button_row(f, area, &labels, state.button, Color::Yellow);
}

fn draw_delete_custom_dialog(
    f: &mut Frame,
    state: &crate::tui::app::DeleteCustomDialogState,
    area: Rect,
) {
    f.buffer_mut().set_string(
        area.x,
        area.y,
        "Delete custom check?",
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
    );
    f.buffer_mut().set_string(
        area.x,
        area.y + 2,
        format!("Check id: {}", state.id),
        Style::default().fg(Color::White),
    );
    f.buffer_mut().set_string(
        area.x,
        area.y + 3,
        format!("Group:    {}", state.from),
        Style::default().fg(Color::Gray),
    );
    f.buffer_mut().set_string(
        area.x,
        area.y + 5,
        "This permanently removes the check from disk. This cannot be undone.",
        Style::default().fg(Color::Yellow),
    );
    f.buffer_mut().set_string(
        area.x,
        area.y + 6,
        "Tab/←→ to switch · Enter to confirm · Esc to cancel",
        Style::default().fg(Color::DarkGray),
    );

    // Delete dialog uses a distinct selection color per button: red for the
    // destructive Delete, yellow for the safe Cancel. Inline because the
    // shared button-row helper assumes a single highlight color.
    let labels = ["Delete", "Cancel"];
    let buttons: Vec<String> = labels.iter().map(|l| format!("[ {l} ]")).collect();
    let widths: Vec<u16> = buttons.iter().map(|b| b.chars().count() as u16).collect();
    const GAP: u16 = 3;
    let total: u16 = widths.iter().sum::<u16>() + GAP * (labels.len() as u16 - 1);
    let start_x = if total <= area.width {
        area.x + (area.width - total) / 2
    } else {
        area.x
    };
    let row_y = area.y + area.height.saturating_sub(1);
    let mut x = start_x;
    for (i, button) in buttons.iter().enumerate() {
        let style = if i == state.button {
            let bg = if i == 0 { Color::Red } else { Color::Yellow };
            Style::default()
                .fg(Color::Black)
                .bg(bg)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        f.buffer_mut().set_string(x, row_y, button, style);
        x += widths[i] + GAP;
    }
}

/// Help overlay content: key bindings, then what the badges mean.
const HELP_KEYS: &[(&str, &str)] = &[
    (
        "Up/Down, j/k",
        "move between sections (browsing) or rows (editing)",
    ),
    (
        "Left/Right",
        "switch tabs (General, Groups, Escalation, ...); in a text field or \
         filter they move the caret instead",
    ),
    (
        "Tab/Shift-Tab",
        "also switch tabs; in an open Ignore/Deny list they move between the \
         picker and the entries",
    ),
    ("Enter", "edit the selected section, or activate a button"),
    ("Esc", "stop editing; close a dialog"),
    (
        "Space",
        "select the highlighted option or toggle a checkbox",
    ),
    ("o", "override toggle (AI/Wrap tabs)"),
    ("+", "add a row (lists, custom checks)"),
    ("e", "edit the selected custom check"),
    ("d", "delete the selected row"),
    ("/", "filter (in pickers); type a check id to search"),
    ("p", "show or hide the settings-file preview"),
    ("s", "save (validates and shows the changes first)"),
    ("r", "reset the draft to what is on disk"),
    ("q", "quit (asks first if there are unsaved changes)"),
    (
        "Ctrl-C",
        "quit from anywhere, also while typing (asks first if there are unsaved changes)",
    ),
    ("?", "show or hide this help"),
];

const HELP_NOTES: &[&str] = &[
    "Badges: [all] = applies everywhere (shell hooks, AI agents, wrap). \
     [ai] = only for AI agents (shellfirm check / MCP). [wrap] = only inside \
     `shellfirm wrap`. [shell] = only the interactive shell hooks.",
    "Focus: the active tab is shown as [Name]; the selected row is marked with > \
     and highlighted. With NO_COLOR set, highlights use reverse video.",
    "Too short a window? Tabs scroll to the selected row; \"more\" marks hidden rows.",
];

/// Build the wrapped help lines for a given width.
fn help_lines(width: u16) -> Vec<(String, bool)> {
    const KEY_W: usize = 15;
    let mut out = Vec::new();
    let desc_w = (width as usize).saturating_sub(KEY_W + 2).max(10);
    for (key, desc) in HELP_KEYS {
        for (i, part) in wrap_words(desc, desc_w).into_iter().enumerate() {
            let k = if i == 0 { *key } else { "" };
            out.push((format!("  {k:<KEY_W$}{part}"), false));
        }
    }
    out.push((String::new(), false));
    for note in HELP_NOTES {
        for part in wrap_words(note, (width as usize).saturating_sub(2).max(10)) {
            out.push((format!("  {part}"), true));
        }
    }
    out
}

fn draw_help_overlay(f: &mut Frame, app: &App, area: Rect) {
    f.buffer_mut().set_string(
        area.x,
        area.y,
        "Keyboard shortcuts",
        Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    );
    let lines = help_lines(area.width);
    // Rows between the title (+1 blank) and the footer.
    let visible = area.height.saturating_sub(3) as usize;
    let max_scroll = lines.len().saturating_sub(visible);
    app.help_max_scroll.set(max_scroll as u16);
    let offset = (app.help_scroll as usize).min(max_scroll);
    let mut y = area.y + 2;
    for (text, note) in lines.iter().skip(offset).take(visible) {
        let truncated: String = text.chars().take(area.width as usize).collect();
        let style = if *note {
            Style::default().fg(Color::Gray)
        } else {
            Style::default()
        };
        f.buffer_mut().set_string(area.x, y, truncated, style);
        y += 1;
    }
    let footer = if max_scroll > 0 {
        format!(
            "Up/Down/PgUp/PgDn scroll ({}-{} of {}) - Esc or ? to close",
            offset + 1,
            (offset + visible).min(lines.len()),
            lines.len()
        )
    } else {
        "Esc or ? to close".to_string()
    };
    let footer: String = footer.chars().take(area.width as usize).collect();
    f.buffer_mut().set_string(
        area.x,
        area.y + area.height.saturating_sub(1),
        footer,
        Style::default().fg(Color::DarkGray),
    );
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let w = r.width * percent_x / 100;
    let h = r.height * percent_y / 100;
    Rect {
        x: r.x + (r.width.saturating_sub(w)) / 2,
        y: r.y + (r.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    }
}
