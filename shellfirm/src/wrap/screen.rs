//! A small terminal emulator for the child's output.
//!
//! It keeps the last few hundred rows of the main screen (and a separate
//! alternate screen, used by pagers and editors) with a cursor, and
//! understands the sequences line editors use to redraw: `\r`, `\n`, `\b`,
//! `CSI A/B/C/D/E/F/G/H/J/K/P/@/X/d`, save/restore cursor and the
//! alternate-screen private modes. When the terminal width is known, long
//! lines wrap like on a real terminal, and wrapped rows are joined back into
//! one logical line. The [`super::line::Interceptor`] reads what the child
//! echoed from here.

use std::collections::VecDeque;

/// Rows kept per screen.
const MAX_ROWS: usize = 400;

#[derive(Debug, Clone, PartialEq, Eq)]
enum VtState {
    Ground,
    Esc,
    Csi(Vec<u8>),
    Osc,
    OscEsc,
    Charset,
}

#[derive(Debug, Clone, Default)]
struct Row {
    cells: Vec<char>,
    /// The row continues the previous one (soft wrap at the right margin).
    wrapped: bool,
}

impl Row {
    fn text(&self) -> String {
        let s: String = self.cells.iter().collect();
        s.trim_end().to_string()
    }
}

#[derive(Debug, Clone)]
struct Grid {
    rows: VecDeque<Row>,
    /// Absolute index of `rows[0]`.
    base: u64,
    row: u64,
    col: usize,
    saved: (u64, usize),
}

impl Grid {
    fn new() -> Self {
        let mut rows = VecDeque::new();
        rows.push_back(Row::default());
        Self {
            rows,
            base: 0,
            row: 0,
            col: 0,
            saved: (0, 0),
        }
    }

    fn last_row(&self) -> u64 {
        self.base + self.rows.len() as u64 - 1
    }

    fn idx(&self, abs: u64) -> Option<usize> {
        abs.checked_sub(self.base)
            .and_then(|i| usize::try_from(i).ok())
            .filter(|&i| i < self.rows.len())
    }

    fn get(&self, abs: u64) -> Option<&Row> {
        self.idx(abs).map(|i| &self.rows[i])
    }

    /// Make sure the cursor row exists (creating rows below as needed) and
    /// return it.
    fn cur(&mut self) -> &mut Row {
        while self.row > self.last_row() {
            self.rows.push_back(Row::default());
        }
        while self.rows.len() > MAX_ROWS {
            self.rows.pop_front();
            self.base += 1;
        }
        if self.row < self.base {
            self.row = self.base;
        }
        let i = self.idx(self.row).unwrap_or(0);
        &mut self.rows[i]
    }

    fn put(&mut self, c: char, width: Option<usize>) {
        if let Some(w) = width.filter(|w| *w > 0) {
            if self.col >= w {
                self.row += 1;
                self.col = 0;
                self.cur().wrapped = true;
            }
        }
        let col = self.col;
        let row = self.cur();
        if col < row.cells.len() {
            row.cells[col] = c;
        } else {
            while row.cells.len() < col {
                row.cells.push(' ');
            }
            row.cells.push(c);
        }
        self.col += 1;
    }

    fn line_feed(&mut self, width: Option<usize>) {
        self.row += 1;
        let _ = self.cur();
        if let Some(w) = width.filter(|w| *w > 0) {
            self.col = self.col.min(w - 1);
        }
    }

    fn clear_all(&mut self) {
        for r in &mut self.rows {
            r.cells.clear();
            r.wrapped = false;
        }
    }

    fn top(&self, height: Option<usize>) -> u64 {
        height.map_or(self.base, |h| {
            (self.last_row() + 1)
                .saturating_sub(h as u64)
                .max(self.base)
        })
    }
}

/// Emulates the child's terminal output (see the module docs).
#[derive(Debug, Clone)]
pub struct ScreenLine {
    main: Grid,
    alt: Option<Grid>,
    state: VtState,
    utf8: Vec<u8>,
    width: Option<usize>,
    height: Option<usize>,
    alt_epoch: u64,
}

impl Default for ScreenLine {
    fn default() -> Self {
        Self::new()
    }
}

impl ScreenLine {
    #[must_use]
    pub fn new() -> Self {
        Self {
            main: Grid::new(),
            alt: None,
            state: VtState::Ground,
            utf8: Vec::new(),
            width: None,
            height: None,
            alt_epoch: 0,
        }
    }

    /// Tell the emulator the terminal size (enables soft-wrap tracking).
    pub fn set_size(&mut self, cols: usize, rows: usize) {
        self.width = (cols > 0).then_some(cols);
        self.height = (rows > 0).then_some(rows);
    }

    fn grid(&self) -> &Grid {
        self.alt.as_ref().unwrap_or(&self.main)
    }

    fn grid_mut(&mut self) -> &mut Grid {
        self.alt.as_mut().unwrap_or(&mut self.main)
    }

    /// True while the child shows the alternate screen (pager, editor).
    #[must_use]
    pub const fn in_alt_screen(&self) -> bool {
        self.alt.is_some()
    }

    /// Incremented every time the child leaves the alternate screen.
    #[must_use]
    pub const fn alt_epoch(&self) -> u64 {
        self.alt_epoch
    }

    /// Cursor position: (absolute row, column).
    #[must_use]
    pub fn cursor(&self) -> (u64, usize) {
        let g = self.grid();
        (g.row, g.col)
    }

    /// The text of the cursor row (trailing blanks trimmed).
    #[must_use]
    pub fn text(&self) -> String {
        let g = self.grid();
        g.get(g.row).map(Row::text).unwrap_or_default()
    }

    /// The text left of the cursor on the cursor row (the prompt, when the
    /// user is about to type).
    #[must_use]
    pub fn text_before_cursor(&self) -> String {
        let g = self.grid();
        g.get(g.row)
            .map(|r| r.cells.iter().take(g.col).collect())
            .unwrap_or_default()
    }

    /// The text of row `abs` (trailing blanks trimmed), if it is still kept.
    #[must_use]
    pub fn row_text(&self, abs: u64) -> Option<String> {
        self.grid().get(abs).map(Row::text)
    }

    /// Index of the last row.
    #[must_use]
    pub fn last_row(&self) -> u64 {
        self.grid().last_row()
    }

    /// Index of the first row still kept.
    #[must_use]
    pub fn first_row(&self) -> u64 {
        self.grid().base
    }

    /// The logical text from (`row`, `col`) to the end of the screen.
    /// Soft-wrapped rows are joined directly, hard line breaks become `\n`.
    #[must_use]
    pub fn text_from(&self, row: u64, col: usize) -> String {
        let g = self.grid();
        let mut out = String::new();
        let mut r = row.max(g.base);
        while let Some(rw) = g.get(r) {
            let cells: String = if r == row {
                rw.cells.iter().skip(col).collect()
            } else {
                rw.cells.iter().collect()
            };
            if r != row {
                if rw.wrapped {
                    // keep the previous row's trailing blanks: they are
                    // real spaces at the wrap point.
                } else {
                    let trimmed = out.trim_end().len();
                    out.truncate(trimmed);
                    out.push('\n');
                }
            }
            out.push_str(&cells);
            r += 1;
        }
        out.trim_end().to_string()
    }

    #[allow(clippy::too_many_lines)]
    fn csi(&mut self, params: &[u8], final_byte: u8) {
        if params.first() == Some(&b'?') {
            let text = String::from_utf8_lossy(&params[1..]);
            for mode in text.split(';') {
                if matches!(mode, "1049" | "1047" | "47") {
                    match final_byte {
                        b'h' if self.alt.is_none() => {
                            if mode == "1049" {
                                self.main.saved = (self.main.row, self.main.col);
                            }
                            self.alt = Some(Grid::new());
                        }
                        b'l' if self.alt.is_some() => {
                            self.alt = None;
                            self.alt_epoch += 1;
                            if mode == "1049" {
                                (self.main.row, self.main.col) = self.main.saved;
                            }
                        }
                        _ => {}
                    }
                }
            }
            return;
        }
        if params.first().is_some_and(|b| matches!(b, b'>' | b'=')) {
            return;
        }
        let text = String::from_utf8_lossy(params);
        let nums: Vec<usize> = text
            .split(';')
            .map(|p| p.parse::<usize>().unwrap_or(0))
            .collect();
        let first = nums.first().copied().unwrap_or(0);
        let n = first.max(1);
        let height = self.height;
        let g = self.grid_mut();
        match final_byte {
            b'K' => {
                let col = g.col;
                let row = g.cur();
                let len = row.cells.len();
                match first {
                    0 => row.cells.truncate(col.min(len)),
                    1 => {
                        for cell in row.cells.iter_mut().take(col + 1) {
                            *cell = ' ';
                        }
                    }
                    _ => row.cells.clear(),
                }
            }
            b'J' => match first {
                0 => {
                    let col = g.col;
                    let row = g.cur();
                    let len = row.cells.len();
                    row.cells.truncate(col.min(len));
                    if col == 0 {
                        row.wrapped = false;
                    }
                    if let Some(i) = g.idx(g.row) {
                        g.rows.truncate(i + 1);
                    }
                }
                2 | 3 => g.clear_all(),
                _ => {}
            },
            b'A' => g.row = g.row.saturating_sub(n as u64).max(g.base),
            b'B' => g.row = (g.row + n as u64).min(g.last_row()),
            b'E' => {
                g.row = (g.row + n as u64).min(g.last_row());
                g.col = 0;
            }
            b'F' => {
                g.row = g.row.saturating_sub(n as u64).max(g.base);
                g.col = 0;
            }
            b'C' => g.col += n,
            b'D' => g.col = g.col.saturating_sub(n),
            b'G' | b'`' => g.col = n - 1,
            b'H' | b'f' => {
                let r = first.max(1);
                let c = nums.get(1).copied().unwrap_or(1).max(1);
                g.row = g.top(height) + (r as u64 - 1);
                g.col = c - 1;
                let _ = g.cur();
            }
            b'd' => {
                g.row = g.top(height) + (n as u64 - 1);
                let _ = g.cur();
            }
            b'P' => {
                let col = g.col;
                let row = g.cur();
                let len = row.cells.len();
                let start = col.min(len);
                let end = (start + n).min(len);
                row.cells.drain(start..end);
            }
            b'@' => {
                let col = g.col;
                let row = g.cur();
                if col <= row.cells.len() {
                    for _ in 0..n {
                        row.cells.insert(col, ' ');
                    }
                }
            }
            b'X' => {
                let col = g.col;
                let row = g.cur();
                for cell in row.cells.iter_mut().skip(col).take(n) {
                    *cell = ' ';
                }
            }
            b's' => g.saved = (g.row, g.col),
            b'u' => (g.row, g.col) = g.saved,
            _ => {} // SGR colours, scroll regions, insert/delete line, ...
        }
    }

    /// Feed bytes received from the child.
    pub fn feed(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.feed_byte(b);
        }
    }

    fn feed_byte(&mut self, b: u8) {
        match std::mem::replace(&mut self.state, VtState::Ground) {
            VtState::Ground => {}
            VtState::Esc => {
                let width = self.width;
                match b {
                    b'[' => self.state = VtState::Csi(Vec::new()),
                    b']' | b'P' | b'_' | b'^' => self.state = VtState::Osc,
                    b'(' | b')' | b'*' | b'+' | b'#' => self.state = VtState::Charset,
                    b'c' => {
                        self.alt = None;
                        self.main = Grid::new();
                    }
                    b'7' => {
                        let g = self.grid_mut();
                        g.saved = (g.row, g.col);
                    }
                    b'8' => {
                        let g = self.grid_mut();
                        (g.row, g.col) = g.saved;
                    }
                    b'M' => {
                        let g = self.grid_mut();
                        g.row = g.row.saturating_sub(1).max(g.base);
                    }
                    b'D' => self.grid_mut().line_feed(width),
                    b'E' => {
                        let g = self.grid_mut();
                        g.col = 0;
                        g.line_feed(width);
                    }
                    _ => {}
                }
                return;
            }
            VtState::Csi(mut params) => {
                if (0x40..=0x7E).contains(&b) {
                    self.csi(&params, b);
                } else if params.len() < 64 {
                    params.push(b);
                    self.state = VtState::Csi(params);
                }
                return;
            }
            VtState::Osc => {
                match b {
                    0x07 => {}
                    0x1B => self.state = VtState::OscEsc,
                    _ => self.state = VtState::Osc,
                }
                return;
            }
            VtState::OscEsc => {
                if b != b'\\' {
                    self.state = VtState::Osc;
                }
                return;
            }
            VtState::Charset => return,
        }

        let width = self.width;
        match b {
            0x1B => self.state = VtState::Esc,
            b'\r' => self.grid_mut().col = 0,
            b'\n' | 0x0B | 0x0C => self.grid_mut().line_feed(width),
            0x08 => {
                let g = self.grid_mut();
                if let Some(w) = width {
                    g.col = g.col.min(w);
                }
                g.col = g.col.saturating_sub(1);
            }
            b'\t' => {
                let g = self.grid_mut();
                let next = (g.col / 8 + 1) * 8;
                while g.col < next {
                    g.put(' ', width);
                }
            }
            0x00..=0x1F | 0x7F => {}
            _ => {
                self.utf8.push(b);
                match std::str::from_utf8(&self.utf8) {
                    Ok(s) => {
                        let chars: Vec<char> = s.chars().collect();
                        self.utf8.clear();
                        let g = self.alt.as_mut().unwrap_or(&mut self.main);
                        for c in chars {
                            g.put(c, width);
                        }
                    }
                    Err(e) if e.error_len().is_some() || self.utf8.len() >= 4 => {
                        self.utf8.clear();
                        self.grid_mut().put(char::REPLACEMENT_CHARACTER, width);
                    }
                    Err(_) => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readline_redraws() {
        let mut s = ScreenLine::new();
        s.feed(b"postgres=# SELECT 1");
        s.feed(b"\rpostgres=# DROP\x1b[K");
        assert_eq!(s.text(), "postgres=# DROP");
        s.feed(b"\x08 \x08");
        assert_eq!(s.text(), "postgres=# DRO");
        s.feed(b"\x1b[3D\x1b[P");
        assert_eq!(s.text(), "postgres=# RO");
        s.feed(b"\x1b[@D");
        assert_eq!(s.text(), "postgres=# DRO");
        s.feed(b"\r\nresult\r\n");
        assert_eq!(s.text(), "");
        s.feed(b"\x1b[1;32mok\x1b[0m\x1b]0;title\x07!");
        assert_eq!(s.text(), "ok!");
        assert_eq!(s.text_before_cursor(), "ok!");
    }

    #[test]
    fn multi_row_text_and_soft_wrap() {
        let mut s = ScreenLine::new();
        s.set_size(10, 24);
        s.feed(b"db=# ");
        let (row, col) = s.cursor();
        s.feed(b"UPDATE users\r\nSET a = 1;");
        assert_eq!(s.text_from(row, col), "UPDATE users\nSET a = 1;");
        let mut s = ScreenLine::new();
        s.set_size(10, 24);
        s.feed(b"db=# ");
        let (row, col) = s.cursor();
        s.feed(b"DROP TABLE users;");
        assert_eq!(s.text_from(row, col), "DROP TABLE users;");
        // cursor up + rewrite (readline redraw across rows)
        s.feed(b"\x1b[2A\r\x1b[Jdb=# SELECT 1;");
        assert_eq!(s.text_from(row, col), "SELECT 1;");
    }

    #[test]
    fn alternate_screen_is_separate() {
        let mut s = ScreenLine::new();
        s.feed(b"postgres=# SELECT * FROM big;\r\n");
        assert!(!s.in_alt_screen());
        s.feed(b"\x1b[?1049h rows... \r\n:");
        assert!(s.in_alt_screen());
        s.feed(b"\x1b[?1049l");
        assert!(!s.in_alt_screen());
        assert_eq!(s.alt_epoch(), 1);
        s.feed(b"postgres=# ");
        assert_eq!(s.text_before_cursor(), "postgres=# ");
    }
}
