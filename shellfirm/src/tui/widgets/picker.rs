//! Searchable picker with single-step "use as new" semantics.
//!
//! The user types a value. If it matches existing items, they pick from
//! the matches. If it doesn't match, the same typed value can be used as a
//! new entry — no double-typing. The "+ Use 'value' as new" row appears at
//! the bottom whenever the filter is non-empty and isn't already an exact
//! match in the items list.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::Widget;

#[derive(Debug, Clone)]
pub struct PickerItem {
    pub value: String,
    /// Optional short badge — e.g. "built-in", "custom"
    pub badge: Option<&'static str>,
    /// Optional one-line description shown (dimmed) after the value when
    /// there is room, e.g. a check's description.
    pub description: Option<String>,
}

/// Picker state — a filter (the typed text, with a caret) and a cursor
/// into the visible rows.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PickerState {
    pub filter: String,
    pub cursor: usize,
    /// Caret position in the filter, counted in characters **from the end**
    /// (0 = after the last character), so a state built with only a
    /// `filter` has its caret at the end.
    pub caret_from_end: usize,
    /// When `true`, no row is highlighted (and Enter picks nothing) until
    /// the user types or moves with Up/Down: a stray or repeated Enter
    /// right after opening the picker must not add the first row.
    pub require_choice: bool,
    /// The user moved the cursor with Up/Down (see `require_choice`).
    pub navigated: bool,
}

impl PickerState {
    /// A state that highlights nothing until the user types or navigates.
    #[must_use]
    pub fn requiring_choice() -> Self {
        Self {
            require_choice: true,
            ..Self::default()
        }
    }

    /// Whether a row is currently chosen (highlighted, picked by Enter).
    #[must_use]
    pub fn has_choice(&self) -> bool {
        !self.require_choice || self.navigated || !self.filter.is_empty()
    }

    /// Caret position as a character index from the start of the filter.
    #[must_use]
    pub fn caret(&self) -> usize {
        let len = self.filter.chars().count();
        len - self.caret_from_end.min(len)
    }

    /// Remove the characters `from..to` (character indices); the caret,
    /// counted from the end, keeps its place relative to the text after it.
    fn remove_chars(&mut self, from: usize, to: usize) {
        if from >= to {
            return;
        }
        let (a, b) = (self.byte_at(from), self.byte_at(to));
        self.filter.replace_range(a..b, "");
    }

    fn byte_at(&self, char_idx: usize) -> usize {
        self.filter
            .char_indices()
            .nth(char_idx)
            .map_or(self.filter.len(), |(b, _)| b)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PickerOutcome {
    None,
    Selected(String),
    Cancelled,
    /// Caller should re-render — state changed but nothing to commit yet.
    StateChanged,
}

pub struct Picker<'a> {
    pub items: &'a [PickerItem],
    pub state: &'a PickerState,
    pub focused: bool,
    /// When `false`, only existing items can be picked: no "use as new
    /// value" row (used for check ids, where a typo must not be accepted).
    pub allow_create: bool,
}

/// Resolves which rows are visible given the current filter, plus whether
/// the "use as new" sentinel should be shown.
struct VisibleRows {
    /// Indices into `items` for matching rows, in original order.
    matches: Vec<usize>,
    /// True if a sentinel row should be appended at the bottom.
    show_create: bool,
}

fn compute_visible(items: &[PickerItem], filter: &str, allow_create: bool) -> VisibleRows {
    let f = filter.to_lowercase();
    let matches: Vec<usize> = items
        .iter()
        .enumerate()
        .filter(|(_, it)| f.is_empty() || it.value.to_lowercase().contains(&f))
        .map(|(i, _)| i)
        .collect();
    // Sentinel only when the user has typed something meaningful AND
    // it isn't already an exact existing entry.
    let exact = items.iter().any(|it| it.value == filter);
    let show_create = allow_create && !filter.trim().is_empty() && !exact;
    VisibleRows {
        matches,
        show_create,
    }
}

impl<'a> Widget for Picker<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let v = compute_visible(self.items, &self.state.filter, self.allow_create);

        // ── Header — current filter (with a caret while focused) or hint
        let dim = Style::default().fg(Color::DarkGray);
        if self.state.filter.is_empty() && !self.focused {
            let header = if self.allow_create {
                "─ Type to filter or add a new value ─"
            } else {
                "─ Type to filter ─"
            };
            buf.set_string(area.x, area.y, header, dim);
        } else {
            // A narrow picker gets the short label, so the typed text and
            // its caret keep room.
            let prefix = if self.state.filter.is_empty() {
                if self.allow_create && area.width >= 56 {
                    "─ Type to filter or add a new value: "
                } else {
                    "─ Type to filter: "
                }
            } else {
                "─ Looking for: "
            };
            buf.set_string(area.x, area.y, prefix, dim);
            let px = prefix.chars().count() as u16;
            let room = area.width.saturating_sub(px + 2);
            crate::tui::a11y::draw_text_with_caret(
                buf,
                area.x + px,
                area.y,
                room,
                &self.state.filter,
                self.state.caret(),
                self.focused,
                Style::default().fg(Color::White),
            );
        }

        let body_y = area.y + 2;
        let body_height = area.height.saturating_sub(2);

        if v.matches.is_empty() && !v.show_create {
            if self.state.filter.trim().is_empty() {
                // Nothing typed and nothing in items — just show a placeholder.
                buf.set_string(
                    area.x + 2,
                    body_y,
                    "(empty)",
                    Style::default().fg(Color::DarkGray),
                );
            } else {
                // Strict picker, unknown value: say so, with suggestions.
                let suggestions = crate::tui::validate::suggest_check_ids(
                    &self.state.filter,
                    self.items.iter().map(|i| i.value.as_str()),
                    3,
                );
                buf.set_string(
                    area.x + 2,
                    body_y,
                    format!("✗ Unknown check id \"{}\"", self.state.filter),
                    Style::default().fg(Color::Red),
                );
                if !suggestions.is_empty() && body_height > 1 {
                    buf.set_string(
                        area.x + 2,
                        body_y + 1,
                        format!("Did you mean: {}", suggestions.join(", ")),
                        Style::default().fg(Color::Yellow),
                    );
                }
            }
            return;
        }

        // How many rows we can show
        let total_rows = v.matches.len() + if v.show_create { 1 } else { 0 };
        let display_rows = (body_height as usize).min(total_rows);
        // Scroll so the cursor stays visible (simple windowing).
        let cursor = self.state.cursor.min(total_rows.saturating_sub(1));
        let scroll_top = if cursor >= display_rows {
            cursor + 1 - display_rows
        } else {
            0
        };

        // Scroll hint in the header row when matches are hidden.
        let hidden_above = scroll_top;
        let hidden_below = total_rows.saturating_sub(scroll_top + display_rows);
        if hidden_above + hidden_below > 0 {
            let hint = format!(
                "{} of {} shown{}{}",
                display_rows,
                total_rows,
                if hidden_above > 0 {
                    format!(
                        ", {}{hidden_above} above",
                        crate::tui::a11y::sym("▲ ", "^ ")
                    )
                } else {
                    String::new()
                },
                if hidden_below > 0 {
                    format!(", {}{hidden_below} more", crate::tui::a11y::sym("▼ ", "v "))
                } else {
                    String::new()
                },
            );
            // On its own row under the filter (never drawn over the filter
            // text or its caret).
            buf.set_stringn(
                area.x + 2,
                area.y + 1,
                hint,
                area.width.saturating_sub(2) as usize,
                Style::default().fg(Color::Yellow),
            );
        }

        for row_offset in 0..display_rows {
            let abs = scroll_top + row_offset;
            let y = body_y + row_offset as u16;
            let highlighted = self.focused && abs == cursor && self.state.has_choice();

            if abs < v.matches.len() {
                let item = &self.items[v.matches[abs]];
                let badge_str = item.badge.map(|b| format!("  [{b}]")).unwrap_or_default();
                let line_text = format!("  {}{}", item.value, badge_str);
                let style = if highlighted {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                let width = area.width as usize;
                let used = line_text.chars().count();
                buf.set_stringn(area.x, y, &line_text, width, style);
                if let Some(desc) = item.description.as_deref().filter(|d| !d.is_empty()) {
                    let room = width.saturating_sub(used + 3);
                    if room >= 12 {
                        let mut d: String = desc.chars().take(room).collect();
                        if desc.chars().count() > room {
                            d.pop();
                            d.push('…');
                        }
                        buf.set_stringn(
                            area.x + used as u16 + 3,
                            y,
                            d,
                            room,
                            Style::default().fg(Color::DarkGray),
                        );
                    }
                }
            } else {
                // Sentinel row — "+ Use 'filter' as new value"
                let label = format!("+ Use \"{}\" as new value", self.state.filter);
                let style = if highlighted {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Yellow)
                };
                buf.set_string(area.x, y, label, style);
            }
        }
    }
}

/// Stateless key-handler. Mutates `state` in place and returns the outcome.
pub fn handle_picker_key(
    key: KeyEvent,
    state: &mut PickerState,
    items: &[PickerItem],
) -> PickerOutcome {
    handle_picker_key_with(key, state, items, true)
}

/// Like [`handle_picker_key`]; with `allow_create == false` only existing
/// items can be selected (Enter on an unknown value does nothing).
pub fn handle_picker_key_with(
    key: KeyEvent,
    state: &mut PickerState,
    items: &[PickerItem],
    allow_create: bool,
) -> PickerOutcome {
    let v = compute_visible(items, &state.filter, allow_create);
    let total = v.matches.len() + if v.show_create { 1 } else { 0 };

    match key.code {
        KeyCode::Esc => PickerOutcome::Cancelled,
        KeyCode::Up => {
            if total == 0 {
                return PickerOutcome::None;
            }
            state.cursor = if !state.has_choice() {
                state.cursor.min(total - 1)
            } else if state.cursor == 0 {
                total - 1
            } else {
                state.cursor - 1
            };
            state.navigated = true;
            PickerOutcome::StateChanged
        }
        KeyCode::Down => {
            if total == 0 {
                return PickerOutcome::None;
            }
            state.cursor = if state.has_choice() {
                (state.cursor + 1) % total
            } else {
                state.cursor.min(total - 1)
            };
            state.navigated = true;
            PickerOutcome::StateChanged
        }
        KeyCode::Enter => {
            if total == 0 || !state.has_choice() {
                return PickerOutcome::None;
            }
            // Clamp cursor to valid range (resilient to filter changes).
            let cursor = state.cursor.min(total - 1);
            if cursor < v.matches.len() {
                let value = items[v.matches[cursor]].value.clone();
                PickerOutcome::Selected(value)
            } else if v.show_create {
                // Sentinel: use the filter text as a new value.
                PickerOutcome::Selected(state.filter.trim().to_string())
            } else {
                PickerOutcome::None
            }
        }
        // Text-editing keys behave like the other text fields: Ctrl-U clears
        // the filter, Ctrl-W deletes a word, Ctrl-K to the end, Ctrl-A /
        // Ctrl-E jump, Ctrl-H is Backspace. Other Ctrl/Alt keys are ignored
        // (never typed as their letter). The caret moves by user-perceived
        // character (`e` + combining accent is one step).
        KeyCode::Char(c)
            if key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
        {
            if !key.modifiers.contains(KeyModifiers::CONTROL) {
                return PickerOutcome::None;
            }
            let caret = state.caret();
            let len = state.filter.chars().count();
            match c.to_ascii_lowercase() {
                'u' => {
                    // Like the other text fields: clear the whole filter.
                    state.remove_chars(0, len);
                    state.caret_from_end = 0;
                }
                'w' => {
                    let from = crate::tui::a11y::prev_word(&state.filter, caret);
                    state.remove_chars(from, caret);
                }
                'k' => {
                    state.remove_chars(caret, len);
                    state.caret_from_end = 0;
                }
                'h' => {
                    let from = crate::tui::a11y::prev_cluster(&state.filter, caret);
                    state.remove_chars(from, caret);
                }
                'a' => {
                    state.caret_from_end = len;
                    return PickerOutcome::StateChanged;
                }
                'e' => {
                    state.caret_from_end = 0;
                    return PickerOutcome::StateChanged;
                }
                _ => return PickerOutcome::None,
            }
            state.cursor = 0;
            PickerOutcome::StateChanged
        }
        KeyCode::Backspace => {
            let caret = state.caret();
            let from = crate::tui::a11y::prev_cluster(&state.filter, caret);
            state.remove_chars(from, caret);
            state.cursor = 0;
            PickerOutcome::StateChanged
        }
        KeyCode::Delete => {
            let caret = state.caret();
            let to = crate::tui::a11y::next_cluster(&state.filter, caret);
            let removed = to - caret;
            state.remove_chars(caret, to);
            state.caret_from_end = state.caret_from_end.saturating_sub(removed);
            state.cursor = 0;
            PickerOutcome::StateChanged
        }
        // The caret moves inside the filter (the keys never leave the
        // picker, e.g. to switch tabs, while it has focus).
        KeyCode::Left => {
            let len = state.filter.chars().count();
            let to = crate::tui::a11y::prev_cluster(&state.filter, state.caret());
            state.caret_from_end = len - to;
            PickerOutcome::StateChanged
        }
        KeyCode::Right => {
            let len = state.filter.chars().count();
            let to = crate::tui::a11y::next_cluster(&state.filter, state.caret());
            state.caret_from_end = len - to;
            PickerOutcome::StateChanged
        }
        KeyCode::Home => {
            state.caret_from_end = state.filter.chars().count();
            PickerOutcome::StateChanged
        }
        KeyCode::End => {
            state.caret_from_end = 0;
            PickerOutcome::StateChanged
        }
        KeyCode::Char(c) => {
            let at = state.byte_at(state.caret());
            state.filter.insert(at, c);
            state.cursor = 0;
            PickerOutcome::StateChanged
        }
        _ => PickerOutcome::None,
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
    fn ctrl_keys_edit_the_filter_and_are_never_typed() {
        let ctrl = |c| KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL);
        let mut st = PickerState {
            filter: "for push".into(),
            ..PickerState::default()
        };
        handle_picker_key(ctrl('w'), &mut st, &[]);
        assert_eq!(st.filter, "for ");
        handle_picker_key(ctrl('h'), &mut st, &[]);
        assert_eq!(st.filter, "for");
        handle_picker_key(ctrl('a'), &mut st, &[]);
        assert_eq!(st.caret(), 0);
        handle_picker_key(ctrl('e'), &mut st, &[]);
        assert_eq!(st.caret(), 3);
        handle_picker_key(ctrl('x'), &mut st, &[]);
        handle_picker_key(
            KeyEvent::new(KeyCode::Char('q'), KeyModifiers::ALT),
            &mut st,
            &[],
        );
        assert_eq!(st.filter, "for");
        handle_picker_key(ctrl('u'), &mut st, &[]);
        assert_eq!(st.filter, "");
    }

    #[test]
    fn caret_moves_by_user_perceived_character() {
        // `e` + U+0301 is one step.
        let mut st = PickerState {
            filter: "ae\u{301}b".into(),
            ..PickerState::default()
        };
        handle_picker_key(key(KeyCode::Left), &mut st, &[]);
        handle_picker_key(key(KeyCode::Left), &mut st, &[]);
        handle_picker_key(key(KeyCode::Char('Z')), &mut st, &[]);
        assert_eq!(st.filter, "aZe\u{301}b");
        handle_picker_key(key(KeyCode::Delete), &mut st, &[]);
        assert_eq!(st.filter, "aZb");
    }

    fn items() -> Vec<PickerItem> {
        vec![
            PickerItem {
                value: "git:force_push".into(),
                badge: Some("built-in"),
                description: None,
            },
            PickerItem {
                value: "git:reset_hard".into(),
                badge: Some("built-in"),
                description: None,
            },
            PickerItem {
                value: "my_team:no_force".into(),
                badge: Some("custom"),
                description: None,
            },
        ]
    }

    #[test]
    fn empty_filter_no_create_sentinel() {
        let v = compute_visible(&items(), "", true);
        assert_eq!(v.matches.len(), 3);
        assert!(!v.show_create);
    }

    #[test]
    fn nonexact_filter_shows_create_sentinel() {
        let v = compute_visible(&items(), "my_team", true);
        assert!(v.show_create);
    }

    #[test]
    fn exact_match_hides_create_sentinel() {
        let v = compute_visible(&items(), "git:force_push", true);
        assert!(!v.show_create);
    }

    #[test]
    fn enter_on_match_returns_selected() {
        let mut state = PickerState {
            filter: String::new(),
            cursor: 1,
            ..PickerState::default()
        };
        let it = items();
        let out = handle_picker_key(key(KeyCode::Enter), &mut state, &it);
        assert_eq!(out, PickerOutcome::Selected("git:reset_hard".to_string()));
    }

    #[test]
    fn enter_on_create_sentinel_uses_filter_as_value() {
        // Filter "my_team" doesn't exactly match — sentinel is shown.
        // After typing 4 chars, cursor stays at 0 (a match: my_team:no_force).
        // To select the sentinel, navigate down to its index.
        let mut state = PickerState {
            filter: "totally_new".into(),
            cursor: 0,
            ..PickerState::default()
        };
        let it = items();
        // No matches for "totally_new" → cursor=0 lands directly on the sentinel.
        let out = handle_picker_key(key(KeyCode::Enter), &mut state, &it);
        assert_eq!(out, PickerOutcome::Selected("totally_new".to_string()));
    }

    #[test]
    fn typing_filters_and_resets_cursor() {
        let mut state = PickerState {
            filter: String::new(),
            cursor: 2,
            ..PickerState::default()
        };
        let it = items();
        let out = handle_picker_key(key(KeyCode::Char('m')), &mut state, &it);
        assert_eq!(out, PickerOutcome::StateChanged);
        assert_eq!(state.filter, "m");
        assert_eq!(state.cursor, 0);
    }

    #[test]
    fn down_wraps_around_total_rows() {
        // 3 matches + 0 sentinel (filter empty) = 3 rows, cursor 2 → 0
        let mut state = PickerState {
            filter: String::new(),
            cursor: 2,
            ..PickerState::default()
        };
        let it = items();
        let _ = handle_picker_key(key(KeyCode::Down), &mut state, &it);
        assert_eq!(state.cursor, 0);
    }

    #[test]
    fn enter_on_no_matches_with_filter_creates_new() {
        let mut state = PickerState {
            filter: "brand_new_value".into(),
            cursor: 0,
            ..PickerState::default()
        };
        let it = items();
        let out = handle_picker_key(key(KeyCode::Enter), &mut state, &it);
        assert_eq!(out, PickerOutcome::Selected("brand_new_value".to_string()));
    }

    #[test]
    fn strict_picker_rejects_unknown_value() {
        let mut state = PickerState {
            filter: "git:forcepush".into(),
            cursor: 0,
            ..PickerState::default()
        };
        let it = items();
        let out = handle_picker_key_with(key(KeyCode::Enter), &mut state, &it, false);
        assert_eq!(out, PickerOutcome::None);
        assert!(!compute_visible(&it, "git:forcepush", false).show_create);
    }

    #[test]
    fn arrows_move_the_caret_and_typing_inserts_there() {
        let it = items();
        let mut state = PickerState::requiring_choice();
        for c in "gitpush".chars() {
            handle_picker_key(key(KeyCode::Char(c)), &mut state, &it);
        }
        for _ in 0..4 {
            handle_picker_key(key(KeyCode::Left), &mut state, &it);
        }
        assert_eq!(state.caret(), 3);
        handle_picker_key(key(KeyCode::Char(':')), &mut state, &it);
        assert_eq!(state.filter, "git:push");
        handle_picker_key(key(KeyCode::Home), &mut state, &it);
        handle_picker_key(key(KeyCode::Delete), &mut state, &it);
        assert_eq!(state.filter, "it:push");
        handle_picker_key(key(KeyCode::End), &mut state, &it);
        handle_picker_key(key(KeyCode::Backspace), &mut state, &it);
        assert_eq!(state.filter, "it:pus");
        assert_eq!(state.caret(), 6);
    }

    #[test]
    fn require_choice_enter_picks_nothing_until_navigation() {
        let it = items();
        let mut state = PickerState::requiring_choice();
        assert_eq!(
            handle_picker_key_with(key(KeyCode::Enter), &mut state, &it, false),
            PickerOutcome::None
        );
        handle_picker_key_with(key(KeyCode::Down), &mut state, &it, false);
        assert_eq!(state.cursor, 0, "the first Down highlights the first row");
        assert_eq!(
            handle_picker_key_with(key(KeyCode::Enter), &mut state, &it, false),
            PickerOutcome::Selected("git:force_push".into())
        );
    }

    #[test]
    fn esc_returns_cancelled() {
        let mut state = PickerState {
            filter: "anything".into(),
            cursor: 0,
            ..PickerState::default()
        };
        let it = items();
        let out = handle_picker_key(key(KeyCode::Esc), &mut state, &it);
        assert_eq!(out, PickerOutcome::Cancelled);
    }
}
