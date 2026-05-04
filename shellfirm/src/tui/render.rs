//! Top-level frame: tab bar, active tab body, focused-field strip, hint bar,
//! preview pane (when toggled), and modal overlays.

use crate::tui::app::App;
use crate::tui::tabs::Tab;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::Widget;
use ratatui::Frame;

pub fn draw(f: &mut Frame, app: &App) {
    let area = f.area();
    if area.width < 60 || area.height < 16 {
        // Render a "too small" message
        f.buffer_mut().set_string(
            0,
            0,
            "Terminal too small — needs at least 60 cols × 16 rows.",
            Style::default().fg(Color::Yellow),
        );
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

    // Modal overlays drawn last
    if let Some(modal) = &app.modal {
        draw_modal(f, app, modal);
    }
    // Form overlay also drawn last (mutually exclusive with modal in practice)
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
            f.buffer_mut()
                .set_string(x, outer.y + outer.height.saturating_sub(1), "─", border_style);
        }
        for y in outer.y..outer.y + outer.height {
            f.buffer_mut().set_string(outer.x, y, "│", border_style);
            f.buffer_mut()
                .set_string(outer.x + outer.width.saturating_sub(1), y, "│", border_style);
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
    let mut x = area.x + 1;
    for (i, (label, mode_color)) in titles.iter().enumerate() {
        let active = i == app.current_tab;
        let style = if active {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD)
        } else if let Some(c) = mode_color {
            Style::default().fg(*c).add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        let label_s = format!(" {label} ");
        f.buffer_mut().set_string(x, area.y, &label_s, style);
        x += label_s.chars().count() as u16;
    }
    // Dirty marker on the right
    if app.draft.is_dirty() {
        let label = "● unsaved";
        let label_x = area
            .x
            .saturating_add(area.width)
            .saturating_sub(label.chars().count() as u16 + 1);
        f.buffer_mut()
            .set_string(label_x, area.y, label, Style::default().fg(Color::Yellow));
    }
}

fn draw_active_tab(f: &mut Frame, app: &App, area: Rect) {
    match app.current_tab {
        0 => app.general.render(area, f.buffer_mut(), &app.draft),
        1 => app.groups.render(area, f.buffer_mut(), &app.draft),
        2 => app.escalation.render(area, f.buffer_mut(), &app.draft),
        3 => app.context.render(area, f.buffer_mut(), &app.draft),
        4 => app.ignore_deny.render(area, f.buffer_mut(), &app.draft),
        5 => app.ai.render(area, f.buffer_mut(), &app.draft),
        6 => app.wrap.render(area, f.buffer_mut(), &app.draft),
        7 => app.llm.render(area, f.buffer_mut(), &app.draft),
        8 => app.custom.render(area, f.buffer_mut(), &app.draft),
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
            crate::tui::preview::DiffLine::Same(s) => (
                "  ", Style::default().fg(Color::Gray), s.clone(),
            ),
            crate::tui::preview::DiffLine::Added(s) => (
                "+ ", Style::default().fg(Color::Green), s.clone(),
            ),
            crate::tui::preview::DiffLine::Removed(s) => (
                "- ", Style::default().fg(Color::Red), s.clone(),
            ),
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
                f.buffer_mut().set_string(
                    col,
                    ty,
                    "│",
                    Style::default().fg(Color::DarkGray),
                );
            }
            // Up/down caps showing direction of more content.
            if offset > 0 {
                f.buffer_mut().set_string(
                    col, track_top, "▲",
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                );
            }
            if end < total {
                f.buffer_mut().set_string(
                    col, track_top + track_height - 1, "▼",
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                );
            }
            // Thumb size is proportional to the visible fraction of total
            // content; clamped to ≥ 1.
            let inner_height = track_height.saturating_sub(2).max(1);
            let thumb_size = (((visible_height as f64 / total as f64)
                * inner_height as f64)
                .round() as u16)
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
                    f.buffer_mut().set_string(
                        col, ty, "█",
                        Style::default().fg(Color::Cyan),
                    );
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
    f.buffer_mut()
        .set_string(area.x, area.y, &header, Style::default().fg(Color::White));
    if !focus.help.is_empty() {
        f.buffer_mut().set_string(
            area.x,
            area.y + 1,
            &focus.help,
            Style::default().fg(Color::DarkGray),
        );
    }
    if let Some(msg) = &app.status_message {
        let pos_x = area
            .x
            .saturating_add(area.width)
            .saturating_sub(msg.chars().count() as u16 + 1);
        f.buffer_mut()
            .set_string(pos_x, area.y, msg, Style::default().fg(Color::Cyan));
    }
}

fn draw_hint_bar(f: &mut Frame, app: &App, area: Rect) {
    use crate::tui::app::PreviewMode;
    let preview_indicator = match app.preview.mode {
        PreviewMode::Closed => "p preview",
        PreviewMode::Open => "p close preview · Shift+↑/↓ or PgUp/PgDn to scroll",
    };
    let hint = format!(" {preview_indicator} · s save · q quit · ? help");
    f.buffer_mut()
        .set_string(area.x, area.y, hint, Style::default().fg(Color::DarkGray));
}

fn draw_modal(f: &mut Frame, app: &App, modal: &crate::tui::app::Modal) {
    let area = centered_rect(70, 60, f.area());
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
    for y in area.y..area.y + area.height {
        f.buffer_mut().set_string(area.x, y, "│", border);
        f.buffer_mut()
            .set_string(area.x + area.width.saturating_sub(1), y, "│", border);
    }

    let inner = Rect {
        x: area.x + 2,
        y: area.y + 1,
        width: area.width.saturating_sub(4),
        height: area.height.saturating_sub(2),
    };

    match modal {
        crate::tui::app::Modal::Save(state) => draw_save_dialog(f, app, state, inner),
        crate::tui::app::Modal::Quit(state) => draw_quit_dialog(f, state, inner),
        crate::tui::app::Modal::Reset(state) => draw_reset_dialog(f, state, inner),
        crate::tui::app::Modal::Help => draw_help_overlay(f, inner),
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
    f.buffer_mut().set_string(
        area.x,
        area.y,
        "Save",
        Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    );

    match &state.stage {
        SaveStage::Confirm => {
            f.buffer_mut().set_string(
                area.x,
                area.y + 2,
                "✓ Valid configuration",
                Style::default().fg(Color::Green),
            );
            f.buffer_mut().set_string(
                area.x,
                area.y + 4,
                "Diff vs disk:",
                Style::default().fg(Color::DarkGray),
            );
            // render diff — only changed lines (Added/Removed) in this
            // confirm dialog; user wants the at-a-glance summary.
            let yaml = crate::tui::preview::render_yaml(&app.draft.current);
            let diff = crate::tui::preview::line_diff(&app.on_disk_yaml, &yaml);
            let mut y = area.y + 5;
            for line in diff {
                if y >= area.y + area.height.saturating_sub(2) {
                    break;
                }
                let (prefix, color, text) = match &line {
                    crate::tui::preview::DiffLine::Same(_) => continue,
                    crate::tui::preview::DiffLine::Added(s) => ("+ ", Color::Green, s.clone()),
                    crate::tui::preview::DiffLine::Removed(s) => ("- ", Color::Red, s.clone()),
                };
                f.buffer_mut().set_string(
                    area.x,
                    y,
                    format!("{prefix}{text}"),
                    Style::default().fg(color),
                );
                y += 1;
            }
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
            let btn_y = area.y + area.height.saturating_sub(1);
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
        SaveStage::Errors(errors) => {
            f.buffer_mut().set_string(
                area.x,
                area.y + 2,
                "✗ Invalid configuration",
                Style::default().fg(Color::Red),
            );
            let mut y = area.y + 4;
            for e in errors
                .iter()
                .take(area.height.saturating_sub(6) as usize)
            {
                f.buffer_mut().set_string(
                    area.x,
                    y,
                    format!("  {}: {}", e.path, e.message),
                    Style::default().fg(Color::Red),
                );
                y += 1;
            }
            let ok = "[ OK ]";
            let ok_w = ok.chars().count() as u16;
            let ok_x = if ok_w <= area.width {
                area.x + (area.width - ok_w) / 2
            } else {
                area.x
            };
            f.buffer_mut().set_string(
                ok_x,
                area.y + area.height.saturating_sub(1),
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
    state: &crate::tui::app::QuitDialogState,
    area: Rect,
) {
    f.buffer_mut().set_string(
        area.x,
        area.y,
        "You have unsaved changes",
        Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    );
    f.buffer_mut().set_string(
        area.x,
        area.y + 2,
        "What would you like to do?",
        Style::default().fg(Color::Gray),
    );

    let labels = ["Save & quit", "Discard & quit", "Cancel"];
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
    const GAP: u16 = 3;
    // Pre-render to know each button's real width.
    let buttons: Vec<String> = labels.iter().map(|l| format!("[ {l} ]")).collect();
    let widths: Vec<u16> = buttons.iter().map(|b| b.chars().count() as u16).collect();
    let total: u16 = widths.iter().sum::<u16>() + GAP * (labels.len().saturating_sub(1) as u16);

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
        x += widths[i] + GAP;
    }
}

fn draw_reset_dialog(
    f: &mut Frame,
    state: &crate::tui::app::ResetDialogState,
    area: Rect,
) {
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
        Style::default()
            .fg(Color::Red)
            .add_modifier(Modifier::BOLD),
    );
    f.buffer_mut().set_string(
        area.x,
        area.y + 2,
        format!("ID:    {}", state.id),
        Style::default().fg(Color::White),
    );
    f.buffer_mut().set_string(
        area.x,
        area.y + 3,
        format!("Group: {}", state.from),
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

fn draw_help_overlay(f: &mut Frame, area: Rect) {
    f.buffer_mut().set_string(
        area.x,
        area.y,
        "Keyboard shortcuts",
        Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    );

    let help: &[(&str, &str)] = &[
        ("↑↓ / j k", "navigate sections (browsing) · navigate within a section (editing)"),
        ("←→", "switch top-level tabs (e.g. General → Groups → Escalation)"),
        ("Enter", "drill into the selected section · activate a button"),
        ("Esc", "back out of editing to section browsing"),
        ("Tab / Shift-Tab", "also switches top-level tabs"),
        ("Space", "select the highlighted row · toggle a checkbox"),
        ("o", "override toggle (AI/Wrap) / switch panel (Ignore/Deny)"),
        ("+", "add a row (lists, custom checks)"),
        ("e", "edit selected"),
        ("d", "delete selected"),
        ("/", "filter (in pickers)"),
        ("p", "toggle preview pane"),
        ("s", "save (with validate + diff)"),
        ("r", "reset to on-disk state"),
        ("q", "quit"),
        ("?", "this help"),
        ("Esc", "cancel/close current dialog"),
    ];
    let mut y = area.y + 2;
    for (key, desc) in help {
        if y >= area.y + area.height {
            break;
        }
        f.buffer_mut().set_string(
            area.x,
            y,
            format!("  {key:<24}{desc}"),
            Style::default(),
        );
        y += 1;
    }
    f.buffer_mut().set_string(
        area.x,
        area.y + area.height.saturating_sub(1),
        "Esc / ? to close",
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
