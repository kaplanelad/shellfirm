//! Keystroke → statement model for the PTY proxy.
//!
//! The wrapped program (psql, mysql, redis-cli, ...) owns the real line
//! editor; shellfirm only sees the raw bytes the user types and the bytes the
//! child echoes back. To decide what the program is about to execute when the
//! user presses Enter, this module combines:
//!
//! * [`LineEditor`] — a model of the line being typed. It applies the common
//!   readline/linenoise editing keys (Backspace/DEL, Ctrl-U, Ctrl-W, Ctrl-K,
//!   Ctrl-A/E, Left/Right/Home/End, Delete, bracketed paste). Keys whose effect
//!   it cannot know (Up/Down history recall, Tab completion, Ctrl-R search,
//!   yank, Alt-sequences, unknown escape sequences) mark the line *uncertain*.
//! * [`ScreenLine`] — a small terminal emulator of the child's output
//!   (several rows, soft wraps, the alternate screen). The text the child
//!   echoed after the prompt is compared with the model on every Enter; when
//!   they disagree (history recall, Tab, keys typed into a pager, a prompt
//!   redrawn after a `\prompt` answer) the echo wins and the model is checked
//!   as a fallback. Keys typed while the child shows the alternate screen
//!   (pager, editor) never reach the model. Lines typed at a no-echo prompt
//!   (password) are dropped and never logged.
//! * [`split_statements`] (see [`super::lexer`]) / [`Interceptor`] —
//!   accumulates lines into statements with the client's own lexer rules,
//!   recognises client meta-commands (`\i`, `source`, `.read`, `load()`,
//!   `\!`, `delimiter`, `use`, dot-commands) and resyncs the pending buffer
//!   whenever the child shows its primary prompt.
//!
//! Interception happens on **Enter** (CR `0x0D` or LF `0x0A`), the byte that
//! makes the child act. The Enter byte is held back until the statement has
//! been checked.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
};

use regex::Regex;

pub use super::lexer::{
    match_prompt, normalize_ws, split_statements, Dialect, MetaCommand, MetaKind, PromptKind,
    Split, StreamSplitter,
};
pub use super::screen::ScreenLine;

// ---------------------------------------------------------------------------
// LineEditor
// ---------------------------------------------------------------------------

/// Escape-sequence parsing state for user input.
#[derive(Debug, Clone, PartialEq, Eq)]
enum KeyEsc {
    None,
    Esc,
    Csi(Vec<u8>),
    Ss3,
}

/// What a single input byte meant to the line editor model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyEvent {
    /// The byte edited (or did not affect) the line; forward it unchanged.
    Edit,
    /// Enter (CR or LF) — the caller must check the statement before
    /// forwarding the byte.
    Enter,
    /// Ctrl-C — the child discards its input; the model was reset.
    Interrupt,
    /// Ctrl-D on an empty line (EOF for most REPLs).
    Eof,
}

/// Model of the line currently being edited by the user.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct LineEditor {
    line: Vec<char>,
    cursor: usize,
    uncertain: bool,
    esc: KeyEsc,
    utf8: Vec<u8>,
    in_paste: bool,
    quoted_insert: bool,
    touched: bool,
}

impl Default for LineEditor {
    fn default() -> Self {
        Self::new()
    }
}

impl LineEditor {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            line: Vec::new(),
            cursor: 0,
            uncertain: false,
            esc: KeyEsc::None,
            utf8: Vec::new(),
            in_paste: false,
            quoted_insert: false,
            touched: false,
        }
    }

    /// The modelled line text.
    #[must_use]
    pub fn text(&self) -> String {
        self.line.iter().collect()
    }

    /// True when a key whose effect cannot be modelled was seen on this line
    /// (history recall, Tab completion, reverse search, ...).
    #[must_use]
    pub const fn is_uncertain(&self) -> bool {
        self.uncertain
    }

    /// True when no key has been pressed since the last reset.
    #[must_use]
    pub const fn is_fresh(&self) -> bool {
        !self.touched
    }

    /// Reset to an empty, certain line.
    pub fn clear(&mut self) {
        *self = Self::new();
    }

    fn insert(&mut self, c: char) {
        self.line.insert(self.cursor, c);
        self.cursor += 1;
    }

    fn backspace(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
            self.line.remove(self.cursor);
        }
    }

    fn delete_at_cursor(&mut self) {
        if self.cursor < self.line.len() {
            self.line.remove(self.cursor);
        }
    }

    fn kill_word_back(&mut self) {
        // readline `unix-word-rubout`: whitespace, then non-whitespace.
        while self.cursor > 0 && self.line[self.cursor - 1].is_whitespace() {
            self.backspace();
        }
        while self.cursor > 0 && !self.line[self.cursor - 1].is_whitespace() {
            self.backspace();
        }
    }

    fn push_utf8(&mut self, byte: u8) {
        self.utf8.push(byte);
        match std::str::from_utf8(&self.utf8) {
            Ok(s) => {
                let chars: Vec<char> = s.chars().collect();
                self.utf8.clear();
                for c in chars {
                    self.insert(c);
                }
            }
            Err(e) if e.error_len().is_some() || self.utf8.len() >= 4 => {
                self.utf8.clear();
                self.insert(char::REPLACEMENT_CHARACTER);
            }
            Err(_) => {} // incomplete multi-byte sequence — wait for more
        }
    }

    fn handle_csi(&mut self, params: &[u8], final_byte: u8) {
        match (params, final_byte) {
            (b"" | b"1", b'C') => self.cursor = (self.cursor + 1).min(self.line.len()),
            (b"" | b"1", b'D') => self.cursor = self.cursor.saturating_sub(1),
            (b"", b'H') | (b"1" | b"7", b'~') => self.cursor = 0,
            (b"", b'F') | (b"4" | b"8", b'~') => self.cursor = self.line.len(),
            (b"3", b'~') => self.delete_at_cursor(),
            (b"200", b'~') => self.in_paste = true,
            (b"201", b'~') => self.in_paste = false,
            (b"2", b'~') => {} // Insert key: overwrite toggle is rare; ignore
            // Up/Down (history), modified arrows (word moves), F-keys, ...
            _ => self.uncertain = true,
        }
    }

    /// Feed one input byte from the user's terminal.
    pub fn feed(&mut self, byte: u8) -> KeyEvent {
        self.touched = true;

        if self.quoted_insert {
            self.quoted_insert = false;
            self.insert(char::from(byte));
            return KeyEvent::Edit;
        }

        match std::mem::replace(&mut self.esc, KeyEsc::None) {
            KeyEsc::None => {}
            KeyEsc::Esc => {
                match byte {
                    b'[' => self.esc = KeyEsc::Csi(Vec::new()),
                    b'O' => self.esc = KeyEsc::Ss3,
                    0x1B => {
                        self.uncertain = true;
                        self.esc = KeyEsc::Esc;
                    }
                    // Alt-<key> (word moves, case changes, yank-pop, ...)
                    _ => self.uncertain = true,
                }
                return KeyEvent::Edit;
            }
            KeyEsc::Csi(mut params) => {
                if (0x40..=0x7E).contains(&byte) {
                    self.handle_csi(&params, byte);
                } else if params.len() < 32 {
                    params.push(byte);
                    self.esc = KeyEsc::Csi(params);
                } else {
                    self.uncertain = true;
                }
                return KeyEvent::Edit;
            }
            KeyEsc::Ss3 => {
                match byte {
                    b'C' => self.handle_csi(b"", b'C'),
                    b'D' => self.handle_csi(b"", b'D'),
                    b'H' => self.handle_csi(b"", b'H'),
                    b'F' => self.handle_csi(b"", b'F'),
                    _ => self.uncertain = true,
                }
                return KeyEvent::Edit;
            }
        }

        if self.in_paste {
            match byte {
                0x1B => self.esc = KeyEsc::Esc,
                b'\r' | b'\n' => self.insert('\n'),
                b'\t' => self.insert('\t'),
                0x00..=0x1F | 0x7F => {}
                _ => self.push_utf8(byte),
            }
            return KeyEvent::Edit;
        }

        match byte {
            b'\r' | b'\n' => return KeyEvent::Enter,
            0x03 => {
                self.clear();
                return KeyEvent::Interrupt;
            }
            0x04 => {
                if self.line.is_empty() {
                    return KeyEvent::Eof;
                }
                self.delete_at_cursor();
            }
            0x01 => self.cursor = 0,
            0x05 => self.cursor = self.line.len(),
            0x02 => self.cursor = self.cursor.saturating_sub(1),
            0x06 => self.cursor = (self.cursor + 1).min(self.line.len()),
            0x08 | 0x7F => self.backspace(),
            0x0B => self.line.truncate(self.cursor),
            0x15 => {
                self.line.drain(..self.cursor);
                self.cursor = 0;
            }
            0x17 => self.kill_word_back(),
            0x16 => self.quoted_insert = true,
            0x1B => self.esc = KeyEsc::Esc,
            0x0C | 0x1A | 0x00 => {} // Ctrl-L redraw, Ctrl-Z suspend, NUL
            // Tab (completion), Ctrl-N/P (history), Ctrl-R/S (search),
            // Ctrl-T (transpose), Ctrl-Y (yank), Ctrl-X prefix, Ctrl-_ (undo),
            // and any other control byte.
            _ if byte < 0x20 => self.uncertain = true,
            _ => self.push_utf8(byte),
        }
        KeyEvent::Edit
    }
}

// ---------------------------------------------------------------------------
// Statement modes
// ---------------------------------------------------------------------------

/// How the wrapped program groups lines into statements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementMode {
    /// Every line is a statement (redis-cli, shells, generic programs).
    Line,
    /// Statements end at a delimiter (SQL `;`).
    Delimited {
        delimiter: char,
        /// The client lexer rules (quotes, comments, meta-commands).
        dialect: Dialect,
        /// The program executes a bracket-balanced line on Enter even without
        /// the delimiter (mongosh / JavaScript shells).
        enter_completes: bool,
    },
}

/// Terminal mode of the child's side of the PTY at the moment Enter was
/// pressed (only known for local programs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TtyState {
    /// Kernel echo is on.
    pub echo: bool,
    /// Canonical (cooked) line input.
    pub icanon: bool,
}

impl TtyState {
    /// Echo off but cooked input: a password / secret prompt (`getpass`).
    #[must_use]
    pub const fn is_secret_prompt(self) -> bool {
        !self.echo && self.icanon
    }
}

/// What must be checked before the held Enter byte is forwarded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Submission {
    /// Statements the program will execute on this Enter.
    pub statements: Vec<String>,
    /// Other readings of the line (the keystroke model when it disagrees
    /// with the child's echo, the line without a suspicious pending buffer,
    /// ...), checked when nothing above matched.
    pub fallbacks: Vec<String>,
    /// Text that was typed but never echoed by the child (could be a
    /// secret). Checked like fallbacks, never logged verbatim.
    pub unconfirmed: Vec<String>,
    /// Client meta-commands that run files, shell commands or unseen SQL.
    pub metas: Vec<MetaCommand>,
    /// Whether the line text came from the child's echo.
    pub from_echo: bool,
    /// The line was typed at a no-echo prompt (password) and dropped.
    pub secret: bool,
    /// How many statements / client commands the line sends (each once;
    /// the extra readings above are not counted).
    pub count: usize,
    /// The line makes the client open a new connection (psql `\c`, mysql
    /// `connect` / `\r`, sqlcmd `:connect`): its temporary tables are gone.
    pub reconnect: bool,
}

impl Submission {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.statements.is_empty()
            && self.fallbacks.is_empty()
            && self.unconfirmed.is_empty()
            && self.metas.is_empty()
    }

    /// A log-safe summary (unconfirmed input is redacted).
    #[must_use]
    pub fn log_summary(&self) -> String {
        format!(
            "statements={:?} fallbacks={:?} unconfirmed=[{}] metas={:?} from_echo={} secret={}",
            self.statements,
            self.fallbacks,
            self.unconfirmed
                .iter()
                .map(|u| format!("<{} chars>", u.chars().count()))
                .collect::<Vec<_>>()
                .join(", "),
            self.metas
                .iter()
                .map(|m| m.raw.as_str())
                .collect::<Vec<_>>(),
            self.from_echo,
            self.secret
        )
    }
}

/// Screen facts needed for one keystroke.
struct KeyView {
    alt: bool,
    alt_epoch: u64,
    cursor: (u64, usize),
    before_cursor: String,
    anchor_row: Option<String>,
}

/// Where the user started typing the current line.
#[derive(Debug, Clone)]
struct Anchor {
    row: u64,
    col: usize,
    prompt: String,
    alt_epoch: u64,
}

/// mysql commands that run without a delimiter at the start of a line.
const MYSQL_LINE_COMMANDS: &[&str] = &[
    "use",
    "connect",
    "status",
    "charset",
    "warnings",
    "nowarning",
    "rehash",
    "tee",
    "notee",
    "pager",
    "nopager",
    "prompt",
    "quit",
    "exit",
    "help",
    "clear",
    "ego",
    "go",
    "print",
    "edit",
    "source",
    "system",
    "delimiter",
    "resetconnection",
    "query_attributes",
    "ssl_session_data_print",
];

fn var_ref_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(^|[^:]):(['"]?)([A-Za-z_][A-Za-z0-9_]*)(['"]?)"#).unwrap())
}

/// Arguments of a sqlite3 dot-command (`'...'` / `"..."` quoting).
fn sqlite_args(arg: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = arg.trim().chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        let mut word = String::new();
        if c == '\'' || c == '"' {
            chars.next();
            for d in chars.by_ref() {
                if d == c {
                    break;
                }
                word.push(d);
            }
        } else {
            while let Some(&d) = chars.peek() {
                if d.is_whitespace() {
                    break;
                }
                word.push(d);
                chars.next();
            }
        }
        out.push(word);
    }
    out
}

/// The shell command of an unquoted pipe argument of a sqlite3 dot-command:
/// `.once |rm -rf x`, `.output |gzip > f`, `.read |cmd`, `.import |cmd t`.
/// Option words (`-x`, `--csv`) before it are skipped. The command is the
/// rest of the line (without the table name for `.import`, the last word).
/// `None` when the first non-option argument is not an unquoted `|...`.
fn unquoted_pipe(arg: &str, last_is_table: bool) -> Option<String> {
    let mut rest = arg.trim_start();
    while rest.starts_with('-') {
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        rest = rest[end..].trim_start();
    }
    let cmd = rest.strip_prefix('|')?.trim();
    let cmd = if last_is_table {
        cmd.rsplit_once(char::is_whitespace)
            .map_or(cmd, |(c, _)| c.trim_end())
    } else {
        cmd
    };
    (!cmd.is_empty()).then(|| cmd.to_string())
}

fn mongo_load_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"\bload\s*\(\s*(['"`])(.+?)['"`]\s*\)"#).unwrap())
}

/// A psql variable as the target of `TRUNCATE`, `DROP <object>` or `DELETE
/// FROM` (`TRUNCATE :"t"`, `DROP TABLE IF EXISTS public.:t`); group 1 is
/// the variable name.
fn var_target_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)^\s*(?:TRUNCATE(?:\s+TABLE)?(?:\s+ONLY)?|DROP\s+(?:MATERIALIZED\s+VIEW|FOREIGN\s+TABLE|[A-Z]+)(?:\s+IF\s+EXISTS)?|DELETE\s+FROM(?:\s+ONLY)?)\s+(?:[\w."]+\s*,\s*)*[\w."]*:['"]?([A-Za-z_][A-Za-z0-9_]*)"#,
        )
        .unwrap()
    })
}

/// A sqlcmd line that is a client command, not T-SQL. sqlcmd reads its
/// commands at the start of a line, whatever the batch holds.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SqlCmdLine {
    /// `GO [count]`: the batch so far runs.
    Go,
    /// `:exit(query)`: the batch runs, then `query`.
    Exit(String),
    /// `:reset`: the batch is discarded.
    Reset,
    /// Any other command: what it runs (`!!cmd`, `:!! cmd`, `:r file`,
    /// `:ed`) and whether it opens a new connection (`:connect`).
    Command {
        meta: Option<MetaCommand>,
        reconnect: bool,
    },
}

fn sqlcmd_go_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^go(?:\s+\d+)?\s*;?$").unwrap())
}

/// sqlcmd commands that run nothing a check could see (`:setvar`, `:out`,
/// `:on error`, ...).
const SQLCMD_COMMANDS: &[&str] = &[
    "setvar",
    "listvar",
    "out",
    "error",
    "perftrace",
    "on",
    "help",
    "serverlist",
    "list",
    "xml",
    "quit",
];

/// Read `line` as a sqlcmd command (`None`: it is T-SQL). The commands are
/// case-insensitive; `!!` and `:!!` run an operating-system command, `:r`
/// reads a file into the batch.
fn sqlcmd_line(line: &str) -> Option<SqlCmdLine> {
    let t = line.trim();
    if sqlcmd_go_re().is_match(t) {
        return Some(SqlCmdLine::Go);
    }
    let shell = |cmd: &str| {
        let cmd = cmd.trim();
        SqlCmdLine::Command {
            meta: (!cmd.is_empty()).then(|| super::lexer::shell_meta(t.to_string(), cmd)),
            reconnect: false,
        }
    };
    if let Some(cmd) = t.strip_prefix("!!") {
        return Some(shell(cmd));
    }
    let rest = t.strip_prefix(':')?;
    if let Some(cmd) = rest.trim_start().strip_prefix("!!") {
        return Some(shell(cmd));
    }
    let word_end = rest
        .find(|c: char| !c.is_ascii_alphabetic())
        .unwrap_or(rest.len());
    let word = rest[..word_end].to_ascii_lowercase();
    let arg = rest[word_end..].trim();
    let command =
        |meta: Option<MetaCommand>, reconnect: bool| Some(SqlCmdLine::Command { meta, reconnect });
    match word.as_str() {
        "r" => command(
            Some(MetaCommand {
                raw: t.to_string(),
                kind: MetaKind::RunFile {
                    path: super::lexer::unquote_arg(arg),
                    relative: false,
                },
            }),
            false,
        ),
        "ed" => command(Some(super::lexer::editor_meta(t.to_string())), false),
        "connect" => command(None, true),
        "reset" => Some(SqlCmdLine::Reset),
        "exit" => {
            let query = arg
                .strip_prefix('(')
                .and_then(|a| a.strip_suffix(')'))
                .map(str::trim)
                .unwrap_or_default();
            Some(SqlCmdLine::Exit(query.to_string()))
        }
        w if SQLCMD_COMMANDS.contains(&w) => command(None, false),
        _ => None,
    }
}

/// Stateful keystroke interceptor for one wrap session.
#[derive(Debug)]
pub struct Interceptor {
    editor: LineEditor,
    pending: String,
    mode: StatementMode,
    delimiter: String,
    screen: Arc<Mutex<ScreenLine>>,
    anchor: Option<Anchor>,
    last_prompt: Option<String>,
    /// The anchor prompt went stale (the child redrew a new prompt): the
    /// keystroke model may contain keys that never reached the line editor.
    stale: bool,
    vars: HashMap<String, String>,
    /// A line typed but not echoed, kept for one more fallback check.
    shadow: Option<String>,
    tty: Option<TtyState>,
    /// The child reads statements in non-canonical mode (has a line
    /// editor), so a cooked-mode line is a side prompt (`\prompt`, ...).
    has_line_editor: bool,
    /// At least one line was confirmed by the child's echo.
    echo_seen: bool,
}

impl Interceptor {
    #[must_use]
    pub fn new(mode: StatementMode) -> Self {
        let delimiter = match mode {
            StatementMode::Delimited { delimiter, .. } => delimiter.to_string(),
            StatementMode::Line => "\n".to_string(),
        };
        Self {
            editor: LineEditor::new(),
            pending: String::new(),
            mode,
            delimiter,
            screen: Arc::new(Mutex::new(ScreenLine::new())),
            anchor: None,
            last_prompt: None,
            stale: false,
            vars: HashMap::new(),
            shadow: None,
            tty: None,
            has_line_editor: false,
            echo_seen: false,
        }
    }

    const fn dialect(&self) -> Option<Dialect> {
        match self.mode {
            StatementMode::Delimited { dialect, .. } => Some(dialect),
            StatementMode::Line => None,
        }
    }

    /// Shared handle to the echo tracker (for backends that read child
    /// output on another thread).
    #[must_use]
    pub fn screen_handle(&self) -> Arc<Mutex<ScreenLine>> {
        Arc::clone(&self.screen)
    }

    /// Feed child output to the echo tracker.
    pub fn on_child_output(&self, bytes: &[u8]) {
        if let Ok(mut s) = self.screen.lock() {
            s.feed(bytes);
        }
    }

    /// Tell the echo tracker the terminal size.
    pub fn set_size(&self, cols: usize, rows: usize) {
        if let Ok(mut s) = self.screen.lock() {
            s.set_size(cols, rows);
        }
    }

    /// Record the child's terminal mode (call before [`Self::take_submission`]).
    pub const fn set_tty_state(&mut self, tty: Option<TtyState>) {
        self.tty = tty;
    }

    /// Statement text accumulated from previous lines (not yet complete).
    #[must_use]
    pub fn pending(&self) -> &str {
        &self.pending
    }

    /// The current statement delimiter (mysql `DELIMITER` changes it).
    #[must_use]
    pub fn delimiter(&self) -> &str {
        &self.delimiter
    }

    /// The editor model (for diagnostics/tests).
    #[must_use]
    pub const fn editor(&self) -> &LineEditor {
        &self.editor
    }

    /// The line needs the child's echo (history, Tab, a stale prompt).
    #[must_use]
    pub const fn needs_echo(&self) -> bool {
        self.editor.is_uncertain() || self.stale
    }

    fn classify(&self, prompt: &str) -> Option<PromptKind> {
        self.dialect()
            .and_then(|d| match_prompt(d, prompt))
            .filter(|(_, len)| *len == prompt.chars().count())
            .map(|(k, _)| k)
    }

    fn reset_line(&mut self) {
        self.editor.clear();
        self.anchor = None;
        self.stale = false;
    }

    /// Capture where typing starts; resync the pending buffer when the
    /// child shows its primary prompt (its own buffer is empty then).
    fn capture_anchor(&mut self, view: &KeyView) {
        let prompt = view.before_cursor.clone();
        if !self.pending.trim().is_empty() && self.classify(&prompt) == Some(PromptKind::Primary) {
            tracing::debug!(
                "[wrap] resync: the child shows its primary prompt; dropping {} pending char(s)",
                self.pending.chars().count()
            );
            self.pending.clear();
            self.shadow = None;
        }
        self.anchor = Some(Anchor {
            row: view.cursor.0,
            col: view.cursor.1,
            prompt,
            alt_epoch: view.alt_epoch,
        });
    }

    fn key_view(&self) -> Option<KeyView> {
        let s = self.screen.lock().ok()?;
        Some(KeyView {
            alt: s.in_alt_screen(),
            alt_epoch: s.alt_epoch(),
            cursor: s.cursor(),
            before_cursor: s.text_before_cursor(),
            anchor_row: self.anchor.as_ref().and_then(|a| s.row_text(a.row)),
        })
    }

    /// Feed one byte typed by the user.
    pub fn feed_key(&mut self, byte: u8) -> KeyEvent {
        let Some(view) = self.key_view() else {
            return self.editor.feed(byte);
        };
        if view.alt {
            // A pager or editor owns the keyboard: nothing typed here reaches
            // the client's line editor.
            self.reset_line();
            return KeyEvent::Edit;
        }
        if let Some(a) = &self.anchor {
            if a.alt_epoch != view.alt_epoch {
                // A pager/editor ran since the line started.
                self.reset_line();
            } else if !self.editor.is_fresh() {
                let at_anchor = view
                    .anchor_row
                    .as_deref()
                    .is_some_and(|t| t.starts_with(a.prompt.trim_end()));
                let cursor_prompt = self.dialect().and_then(|d| {
                    match_prompt(d, &view.before_cursor)
                        .filter(|(_, len)| *len == view.before_cursor.chars().count())
                });
                if !at_anchor && cursor_prompt.is_some() {
                    // The child drew a fresh prompt after keys were typed
                    // (pager `q`, `\prompt` answer): those keys are gone.
                    tracing::debug!("[wrap] resync: fresh prompt after typed keys");
                    self.reset_line();
                    self.stale = true;
                }
            }
        }
        if self.editor.is_fresh() && self.anchor.is_none() && !matches!(byte, b'\r' | b'\n') {
            self.capture_anchor(&view);
        }
        let ev = self.editor.feed(byte);
        if ev == KeyEvent::Interrupt {
            self.pending.clear();
            self.shadow = None;
            self.anchor = None;
            self.stale = false;
        }
        ev
    }

    /// The text the child echoed for the current line, and whether the
    /// anchor prompt went stale.
    #[allow(clippy::significant_drop_tightening)]
    fn echoed_line(&self) -> Option<(String, bool)> {
        let screen = self.screen.lock().ok()?;
        let anchor = self.anchor.as_ref()?;
        let prompt = anchor.prompt.trim_end();
        let fix = |s: String| s.replace("^J", "\n").replace("^M", "\n");
        if prompt.is_empty() {
            return Some((fix(screen.text_from(anchor.row, anchor.col)), false));
        }
        // The latest row (since the anchor) that starts with the prompt:
        // Tab listings and Ctrl-L redraw the prompt further down.
        let first = screen.first_row();
        let last = screen.last_row();
        let plen = anchor.prompt.chars().count();
        let mut r = last;
        loop {
            if let Some(t) = screen.row_text(r) {
                if t.starts_with(prompt) && (r >= anchor.row || r + 50 >= last) {
                    return Some((fix(screen.text_from(r, plen)), false));
                }
            }
            if r == first || r + 60 < last {
                break;
            }
            r -= 1;
        }
        // Stale anchor: look for any prompt the client is known to draw.
        let d = self.dialect()?;
        let mut r = last;
        loop {
            if let Some(t) = screen.row_text(r) {
                if let Some((_, len)) = match_prompt(d, &format!("{t} ")) {
                    return Some((fix(screen.text_from(r, len)), true));
                }
            }
            if r == first || r + 20 < last {
                break;
            }
            r -= 1;
        }
        None
    }

    /// True when the echo already shows the modelled line (no need to wait
    /// for more child output).
    #[must_use]
    pub fn echo_confirms_model(&self) -> bool {
        let model: String = self.editor.text().split_whitespace().collect();
        if model.is_empty() {
            return true;
        }
        self.echoed_line().is_some_and(|(e, stale)| {
            let e: String = e.split_whitespace().collect();
            !stale && e.contains(&model)
        })
    }

    /// Decide what the line is: (`text`, `fallback`, `from_echo`, `unechoed`).
    fn choose_line(&mut self) -> (String, Option<String>, bool, bool) {
        let modelled = self.editor.text();
        let m: String = modelled.split_whitespace().collect();
        let uncertain = self.editor.is_uncertain();
        match self.echoed_line() {
            Some((echo, anchor_stale)) if !echo.trim().is_empty() => {
                let e: String = echo.split_whitespace().collect();
                let stale = anchor_stale || self.stale;
                if e == m {
                    self.echo_seen = true;
                    (modelled, None, false, false)
                } else if !uncertain && !stale && (e.contains(&m) || m.starts_with(&e)) {
                    // Echo has extra decoration, or is still arriving.
                    self.echo_seen |= e.contains(&m);
                    (modelled, None, false, false)
                } else {
                    let fallback = (!m.is_empty()).then(|| normalize_ws(&modelled));
                    (echo, fallback, true, false)
                }
            }
            _ if m.is_empty() => (modelled, None, false, false),
            // Typed but not echoed: a no-echo prompt, or a slow link.
            _ => (modelled, None, false, self.echo_seen && !uncertain),
        }
    }

    /// Called when Enter was pressed (and child output drained). Consumes the
    /// current line and returns what must be checked.
    pub fn take_submission(&mut self) -> Submission {
        let mut sub = Submission::default();
        if let Some(tty) = self.tty {
            if tty.is_secret_prompt() {
                // Password prompt: never checked, kept or logged.
                self.reset_line();
                sub.secret = true;
                return sub;
            }
        }
        let side_prompt = self.tty.is_some_and(|t| t.icanon) && self.has_line_editor;
        if self.tty.is_some_and(|t| !t.icanon) {
            self.has_line_editor = true;
        }

        let (line, fallback, from_echo, unechoed) = self.choose_line();
        sub.from_echo = from_echo;
        sub.fallbacks.extend(fallback);
        self.last_prompt = self.anchor.take().map(|a| a.prompt);
        self.editor.clear();
        self.stale = false;
        let shadow = self.shadow.take();

        match self.mode {
            StatementMode::Line => {
                let stmts: Vec<String> = line
                    .lines()
                    .map(normalize_ws)
                    .filter(|l| !l.is_empty())
                    .collect();
                sub.count = stmts.len();
                if unechoed {
                    sub.unconfirmed = stmts;
                } else {
                    sub.statements = stmts;
                }
            }
            StatementMode::Delimited {
                dialect,
                enter_completes,
                ..
            } => {
                if unechoed || side_prompt {
                    // Not (provably) part of the query buffer: check it on
                    // its own, keep the buffer as it is.
                    let alone = self.split_alone(&line, dialect, enter_completes);
                    sub.count = alone.statements.len() + alone.metas.len();
                    if unechoed {
                        self.shadow = Some(line.clone());
                        sub.unconfirmed = alone.statements;
                    } else {
                        sub.fallbacks.extend(alone.statements);
                    }
                    sub.metas = alone.metas;
                    return sub;
                }
                self.delimited(&line, dialect, enter_completes, true, &mut sub);
                if let Some(prev) = shadow {
                    let joined = format!("{prev}\n{line}");
                    let alone = self.split_alone(&joined, dialect, enter_completes);
                    sub.unconfirmed.extend(alone.statements);
                }
            }
        }
        sub
    }

    fn split_alone(&self, text: &str, dialect: Dialect, enter_completes: bool) -> Split {
        let mut split = split_statements(text, &self.delimiter, dialect);
        let rest = normalize_ws(&split.remainder);
        if !rest.is_empty() && (enter_completes || !split.in_literal) {
            split.statements.push(rest);
        }
        split
    }

    /// Client commands that are complete at the start of a line without a
    /// delimiter (mysql `use db`, sqlite3 `.tables`). Returns true when the
    /// line was such a command.
    fn line_command(&mut self, line: &str, dialect: Dialect, sub: &mut Submission) -> bool {
        let t = line.trim();
        match dialect {
            Dialect::MySql => {
                let word = t
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if !MYSQL_LINE_COMMANDS.contains(&word.as_str()) {
                    return false;
                }
                let raw_arg = t[word.len()..].trim();
                let arg = raw_arg
                    .trim_end_matches(self.delimiter.as_str())
                    .trim_end_matches(';')
                    .trim();
                let raw = t.to_string();
                match word.as_str() {
                    "delimiter" => {
                        if let Some(d) = raw_arg.split_whitespace().next() {
                            self.delimiter = d.to_string();
                        }
                    }
                    "connect" => sub.reconnect = true,
                    "source" => sub.metas.push(MetaCommand {
                        raw,
                        kind: MetaKind::RunFile {
                            path: arg.to_string(),
                            relative: false,
                        },
                    }),
                    "system" => sub.metas.push(MetaCommand {
                        raw,
                        kind: MetaKind::Shell {
                            command: arg.to_string(),
                        },
                    }),
                    "edit" => sub.metas.push(MetaCommand {
                        raw,
                        kind: MetaKind::Opaque {
                            id: "wrap:editor",
                            what: "This opens the query buffer in an editor; whatever you \
                                   write there runs without being checked."
                                .into(),
                        },
                    }),
                    _ => {}
                }
                true
            }
            Dialect::Sqlite if t.starts_with('.') => {
                let mut parts = t.splitn(2, char::is_whitespace);
                let cmd = parts.next().unwrap_or("");
                let arg = parts.next().unwrap_or("").trim();
                let raw = t.to_string();
                match cmd {
                    ".read" => {
                        let file = unquoted_pipe(arg, false).map_or_else(
                            || sqlite_args(arg).into_iter().next().unwrap_or_default(),
                            |c| format!("|{c}"),
                        );
                        let kind = file.strip_prefix('|').map_or_else(
                            || MetaKind::RunFile {
                                path: file.clone(),
                                relative: false,
                            },
                            |c| MetaKind::ShellToSql {
                                command: c.trim().to_string(),
                            },
                        );
                        sub.metas.push(MetaCommand { raw, kind });
                    }
                    ".once" | ".output" | ".import" => {
                        // `.once '|cmd'`, `.output '|cmd'` (query output is
                        // piped to a shell command), `.import '|cmd' table`
                        // (the command's output is imported).
                        // An unquoted `|cmd args...` runs the rest of the
                        // line (sqlite3 3.34+ joins the arguments).
                        let pipe = unquoted_pipe(arg, cmd == ".import").or_else(|| {
                            sqlite_args(arg)
                                .into_iter()
                                .filter(|a| !a.starts_with('-'))
                                .find_map(|a| a.strip_prefix('|').map(|c| c.trim().to_string()))
                        });
                        if let Some(command) = pipe.filter(|c| !c.is_empty()) {
                            sub.metas.push(MetaCommand {
                                raw,
                                kind: MetaKind::Shell { command },
                            });
                        }
                    }
                    ".shell" | ".system" if arg.is_empty() => {}
                    ".shell" | ".system" => sub.metas.push(MetaCommand {
                        raw,
                        kind: MetaKind::Shell {
                            command: arg.to_string(),
                        },
                    }),
                    _ => {}
                }
                true
            }
            _ => false,
        }
    }

    /// Apply a sqlcmd command line (see [`sqlcmd_line`]) typed in a
    /// session: `GO` ends the batch, `!!` / `:r` / `:ed` are client
    /// commands checked on their own.
    fn sqlcmd_command(&mut self, cmd: SqlCmdLine, enter_completes: bool, sub: &mut Submission) {
        match cmd {
            SqlCmdLine::Go => self.end_sqlcmd_batch(enter_completes, sub),
            SqlCmdLine::Exit(query) => {
                self.end_sqlcmd_batch(enter_completes, sub);
                if !query.is_empty() {
                    let delimiter = self.delimiter.clone();
                    self.delimited(
                        &format!("{query}{delimiter}"),
                        Dialect::SqlServer,
                        enter_completes,
                        false,
                        sub,
                    );
                }
            }
            SqlCmdLine::Reset => self.pending.clear(),
            SqlCmdLine::Command { meta, reconnect } => {
                sub.reconnect |= reconnect;
                sub.metas.extend(meta);
                sub.count += 1;
            }
        }
    }

    /// sqlcmd `GO`: what is pending in the batch runs now, with or without
    /// a `;`.
    fn end_sqlcmd_batch(&mut self, enter_completes: bool, sub: &mut Submission) {
        if !self.pending.trim().is_empty() {
            let delimiter = self.delimiter.clone();
            self.delimited(&delimiter, Dialect::SqlServer, enter_completes, false, sub);
        }
    }

    /// Substitute psql `:var`, `:'var'`, `:"var"` references.
    fn substitute_vars(&self, stmt: &str) -> (String, Vec<String>) {
        let mut unknown = Vec::new();
        let out = var_ref_re()
            .replace_all(stmt, |c: &regex::Captures<'_>| {
                let name = &c[3];
                let (open, close) = (&c[2], &c[4]);
                if open != close {
                    return c[0].to_string();
                }
                self.vars.get(name).map_or_else(
                    || {
                        unknown.push(name.to_string());
                        c[0].to_string()
                    },
                    |v| match open {
                        "'" => format!("{}'{v}'", &c[1]),
                        "\"" => format!("{}\"{v}\"", &c[1]),
                        _ => format!("{}{v}", &c[1]),
                    },
                )
            })
            .to_string();
        (out, unknown)
    }

    /// Add one line to the query buffer. `check_alone`: also check the line
    /// on its own when it continues a pending statement (typed input only;
    /// in a script file the buffer is known exactly).
    fn delimited(
        &mut self,
        line: &str,
        dialect: Dialect,
        enter_completes: bool,
        check_alone: bool,
        sub: &mut Submission,
    ) {
        if dialect == Dialect::SqlServer {
            if let Some(cmd) = sqlcmd_line(line) {
                self.sqlcmd_command(cmd, enter_completes, sub);
                return;
            }
        }
        let had_pending = !self.pending.trim().is_empty();
        if !had_pending && self.line_command(line, dialect, sub) {
            self.pending.clear();
            sub.count += 1;
            return;
        }
        // Does the child's own prompt confirm that its buffer is inside a
        // string/comment? Then the line really continues that literal.
        let prompt_in_literal = self.last_prompt.as_deref().and_then(|p| self.classify(p))
            == Some(PromptKind::InLiteral);
        let pending_in_literal =
            had_pending && split_statements(&self.pending, &self.delimiter, dialect).in_literal;

        let combined = if had_pending {
            format!("{}\n{line}", self.pending)
        } else {
            line.to_string()
        };
        let split = split_statements(&combined, &self.delimiter, dialect);
        if let Some(d) = &split.delimiter {
            self.delimiter.clone_from(d);
        }
        for (k, v) in &split.vars {
            self.vars.insert(k.clone(), v.clone());
        }
        sub.reconnect |= split.reconnect;
        for m in &split.metas {
            sub.metas.push(self.expand_meta(m.clone(), dialect));
        }
        sub.count += split.metas.len();
        let mut statements = split.statements.clone();
        if enter_completes && split.remainder_balanced {
            let rest = normalize_ws(&split.remainder);
            if !rest.is_empty() {
                statements.push(rest);
            }
            self.pending.clear();
        } else if !split.remainder_has_code {
            // Only whitespace / comments: the client's query buffer stays
            // empty (a following `source` / `.read` line is a command).
            self.pending.clear();
        } else {
            self.pending = split.remainder;
        }

        sub.count += statements.len();
        for stmt in statements {
            self.expand_statement(&stmt, dialect, sub);
        }

        // One confusing statement must not hide the rest of the session:
        // unless the child's prompt confirms the open literal, also check
        // this line on its own.
        if check_alone && had_pending && !(prompt_in_literal && pending_in_literal) {
            let alone = self.split_alone(line, dialect, enter_completes);
            for s in alone.statements {
                let mut readings = vec![s.clone()];
                if dialect == Dialect::Postgres && s.contains(':') {
                    readings.push(normalize_ws(&self.substitute_vars(&s).0));
                }
                for r in readings {
                    if !sub.statements.contains(&r) && !sub.fallbacks.contains(&r) {
                        sub.fallbacks.push(r);
                    }
                }
            }
            for m in alone.metas {
                if !sub.metas.contains(&m) {
                    sub.metas.push(m);
                }
            }
        }
    }

    /// psql interpolates variables in meta-command arguments: `\i :dir/x.sql`.
    fn expand_meta(&self, mut meta: MetaCommand, dialect: Dialect) -> MetaCommand {
        if dialect == Dialect::Postgres {
            if let MetaKind::RunFile { path, .. } = &mut meta.kind {
                if path.contains(':') {
                    let (expanded, _) = self.substitute_vars(path);
                    if expanded != *path {
                        // `:'dir'/x.sql`: the quotes only delimit the value.
                        *path = expanded.replace(['\'', '"'], "");
                    }
                }
            }
        }
        meta
    }

    /// Add one complete statement (with psql variables substituted and
    /// mongosh `load()` calls recognised).
    fn expand_statement(&self, stmt: &str, dialect: Dialect, sub: &mut Submission) {
        if dialect == Dialect::Postgres && stmt.contains(':') {
            let (substituted, unknown) = self.substitute_vars(stmt);
            if substituted != stmt {
                sub.statements.push(normalize_ws(&substituted));
            }
            // `SELECT 'users' AS t \gset` then `TRUNCATE :"t"`: the table
            // is not known, so the statement is not provably harmless.
            if let Some(c) = var_target_re().captures(stmt) {
                if unknown.iter().any(|u| *u == c[1]) {
                    sub.metas.push(MetaCommand {
                        raw: stmt.to_string(),
                        kind: MetaKind::UnknownTarget {
                            what: format!(
                                "This runs `{}` on the object named by psql variable `{}`; \
                                 its value (set by `\\gset` or outside this session) is not \
                                 known to the wrap, so the target may be any table.",
                                stmt.split_whitespace().next().unwrap_or("").to_uppercase(),
                                &c[1]
                            ),
                        },
                    });
                }
            }
            let only_var = unknown.len() == 1
                && var_ref_re()
                    .find(stmt.trim())
                    .is_some_and(|m| m.as_str().trim() == stmt.trim());
            if only_var {
                sub.metas.push(MetaCommand {
                    raw: stmt.to_string(),
                    kind: MetaKind::Opaque {
                        id: "wrap:sql_variable",
                        what: format!(
                            "This runs the SQL stored in psql variable `{}`; its value is not \
                             known to the wrap.",
                            unknown[0]
                        ),
                    },
                });
            }
        }
        if dialect == Dialect::JavaScript {
            for c in mongo_load_re().captures_iter(stmt) {
                sub.metas.push(MetaCommand {
                    raw: c[0].to_string(),
                    kind: MetaKind::RunFile {
                        path: c[2].to_string(),
                        relative: false,
                    },
                });
            }
        }
        sub.statements.push(stmt.to_string());
    }

    /// What a script file runs when the client reads it (`\i`, `source`,
    /// `\.`, `.read`, `load()`), following the same client model as typed
    /// input: mysql `DELIMITER` / `\d`, psql `\set` variables, line
    /// commands (`source`, `system`, `.read`, `.shell`) and backslash
    /// meta-commands. Nested includes come back as [`MetaKind::RunFile`]
    /// metas; the caller decides whether to follow them.
    ///
    /// See [`ScriptReader`] to read a large script line by line.
    #[must_use]
    pub fn split_script(dialect: Dialect, text: &str) -> Submission {
        let mut reader = ScriptReader::new(dialect);
        let mut sub = Submission::default();
        for line in text.lines() {
            reader.push_line(line, &mut sub);
        }
        reader.finish(&mut sub);
        sub
    }

    /// The prompt captured for the most recently submitted line (used to
    /// repaint it after a discard the child does not redraw itself).
    #[must_use]
    pub fn last_prompt(&self) -> Option<&str> {
        self.last_prompt.as_deref()
    }

    /// Forget the current line and pending statement (after a discard).
    pub fn discard(&mut self) {
        self.reset_line();
        self.pending.clear();
        self.shadow = None;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Streaming form of [`Interceptor::split_script`].
///
/// A script is read line by line in one linear pass (the lexer state
/// carries over between lines, pending text is never re-lexed), so files of
/// any size can be checked.
///
/// psql `COPY ... FROM stdin` data (up to `\.`) is skipped: it is data, and
/// a quote in it must not hide the statements after it.
#[derive(Debug)]
pub struct ScriptReader {
    ic: Interceptor,
    lexer: StreamSplitter,
    dialect: Dialect,
    in_copy_data: bool,
}

fn copy_from_stdin_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^\s*COPY\b.*\bFROM\s+STDIN\b").unwrap())
}

impl ScriptReader {
    #[must_use]
    pub fn new(dialect: Dialect) -> Self {
        Self {
            ic: Interceptor::new(StatementMode::Delimited {
                delimiter: ';',
                dialect,
                enter_completes: dialect == Dialect::JavaScript,
            }),
            lexer: StreamSplitter::new(";", dialect),
            dialect,
            in_copy_data: false,
        }
    }

    /// Add one line of the script; what it completes is appended to `sub`.
    pub fn push_line(&mut self, line: &str, sub: &mut Submission) {
        let dialect = self.dialect;
        if dialect == Dialect::SqlServer {
            if let Some(cmd) = sqlcmd_line(line) {
                match cmd {
                    SqlCmdLine::Go => self.feed(";", sub),
                    SqlCmdLine::Exit(query) => {
                        self.feed(";", sub);
                        self.feed(&format!("{query};"), sub);
                    }
                    SqlCmdLine::Reset => self.lexer.clear(),
                    SqlCmdLine::Command { meta, reconnect } => {
                        sub.reconnect |= reconnect;
                        sub.metas.extend(meta);
                    }
                }
                return;
            }
        }
        if self.in_copy_data {
            if line.trim_end() == "\\." {
                self.in_copy_data = false;
            } else {
                // If the COPY itself failed, psql runs these lines as SQL:
                // check each one on its own (a quote in one row does not
                // carry over to the next).
                let split = split_statements(line, ";", dialect);
                sub.statements.extend(split.statements);
            }
            return;
        }
        if !self.lexer.has_pending() {
            if self.ic.line_command(line, dialect, sub) {
                self.lexer.clear();
                self.lexer.set_delimiter(&self.ic.delimiter);
                return;
            }
            // Comments left before this line are not part of a statement.
            self.lexer.clear();
        }
        self.lexer.feed(line);
        self.lexer.feed("\n");
        let mut split = self.lexer.take();
        if dialect == Dialect::JavaScript && split.remainder_balanced && self.lexer.has_pending() {
            // mongosh runs a complete line without `;`.
            self.lexer.flush();
            split.statements.extend(self.lexer.take().statements);
        }
        self.apply(split, sub);
    }

    /// End of the script: a statement left without its delimiter still
    /// reaches the server (it stays in the query buffer).
    pub fn finish(&mut self, sub: &mut Submission) {
        if self.in_copy_data || !self.lexer.has_pending() {
            return;
        }
        let delimiter = self.ic.delimiter.clone();
        self.lexer.feed(&format!("\n{delimiter}"));
        let rest = normalize_ws(self.lexer.remainder());
        let mut split = self.lexer.take();
        if split.statements.is_empty() && !rest.is_empty() {
            split.statements.push(rest);
        }
        self.lexer.clear();
        self.apply(split, sub);
    }

    /// Lex `text` as one more line of the script.
    fn feed(&mut self, text: &str, sub: &mut Submission) {
        self.lexer.feed(text);
        self.lexer.feed("\n");
        let split = self.lexer.take();
        self.apply(split, sub);
    }

    fn apply(&mut self, split: Split, sub: &mut Submission) {
        let dialect = self.dialect;
        sub.reconnect |= split.reconnect;
        if let Some(d) = &split.delimiter {
            self.ic.delimiter.clone_from(d);
        }
        for (k, v) in split.vars {
            self.ic.vars.insert(k, v);
        }
        for m in split.metas {
            sub.metas.push(self.ic.expand_meta(m, dialect));
        }
        for stmt in split.statements {
            if dialect == Dialect::Postgres && copy_from_stdin_re().is_match(&stmt) {
                self.in_copy_data = true;
            }
            self.ic.expand_statement(&stmt, dialect, sub);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SQL: StatementMode = StatementMode::Delimited {
        delimiter: ';',
        dialect: Dialect::Postgres,
        enter_completes: false,
    };
    const MONGO: StatementMode = StatementMode::Delimited {
        delimiter: ';',
        dialect: Dialect::JavaScript,
        enter_completes: true,
    };

    /// Type `input` into the interceptor; return the submission for every Enter.
    fn type_all(ic: &mut Interceptor, input: &[u8]) -> Vec<Submission> {
        let mut subs = Vec::new();
        for &b in input {
            if ic.feed_key(b) == KeyEvent::Enter {
                subs.push(ic.take_submission());
            }
        }
        subs
    }

    /// Type with a fake child that echoes every printable key and prints
    /// `prompt` after each Enter.
    fn type_echo(ic: &mut Interceptor, input: &[u8], prompt: &str) -> Vec<Submission> {
        let mut subs = Vec::new();
        for &b in input {
            if ic.feed_key(b) == KeyEvent::Enter {
                subs.push(ic.take_submission());
                ic.on_child_output(b"\r\n");
                ic.on_child_output(prompt.as_bytes());
            } else if b >= 0x20 && b != 0x7F {
                ic.on_child_output(&[b]);
            }
        }
        subs
    }

    fn stmts(subs: &[Submission]) -> Vec<String> {
        subs.iter().flat_map(|s| s.statements.clone()).collect()
    }

    fn everything(subs: &[Submission]) -> Vec<String> {
        subs.iter()
            .flat_map(|s| {
                s.statements
                    .iter()
                    .chain(&s.fallbacks)
                    .chain(&s.unconfirmed)
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    // -- LineEditor --
    #[test]
    fn cr_is_enter() {
        let mut ed = LineEditor::new();
        assert_eq!(ed.feed(b'a'), KeyEvent::Edit);
        assert_eq!(ed.feed(b'\r'), KeyEvent::Enter);
        assert_eq!(ed.feed(b'\n'), KeyEvent::Enter);
    }

    #[test]
    fn backspace_and_del_edit_line() {
        let mut ed = LineEditor::new();
        for &b in b"DROP TABLX\x7fE us\x08\x08users" {
            ed.feed(b);
        }
        assert_eq!(ed.text(), "DROP TABLE users");
        assert!(!ed.is_uncertain());
    }

    #[test]
    fn ctrl_u_kills_to_start() {
        let mut ed = LineEditor::new();
        for &b in b"SELECT 1\x15DROP TABLE x" {
            ed.feed(b);
        }
        assert_eq!(ed.text(), "DROP TABLE x");
    }

    #[test]
    fn ctrl_w_kills_previous_word() {
        let mut ed = LineEditor::new();
        for &b in b"DROP TABLE foo  \x17users" {
            ed.feed(b);
        }
        assert_eq!(ed.text(), "DROP TABLE users");
    }

    #[test]
    fn cursor_moves_and_inserts() {
        let mut ed = LineEditor::new();
        // "TABLE users", Home, "DROP ", End, ";"
        for &b in b"TABLE users\x1b[HDROP \x05;" {
            ed.feed(b);
        }
        assert_eq!(ed.text(), "DROP TABLE users;");
        // Left arrow twice then delete-at-cursor
        let mut ed = LineEditor::new();
        for &b in b"abcd\x1b[D\x1b[D\x1b[3~" {
            ed.feed(b);
        }
        assert_eq!(ed.text(), "abd");
        assert!(!ed.is_uncertain());
    }

    #[test]
    fn ctrl_k_kills_to_end() {
        let mut ed = LineEditor::new();
        for &b in b"DROP TABLE users\x01\x06\x06\x06\x06\x0b" {
            ed.feed(b);
        }
        assert_eq!(ed.text(), "DROP");
    }

    #[test]
    fn history_and_tab_mark_uncertain() {
        let mut ed = LineEditor::new();
        ed.feed(0x1B);
        ed.feed(b'[');
        ed.feed(b'A');
        assert!(ed.is_uncertain());
        let mut ed = LineEditor::new();
        ed.feed(b'D');
        ed.feed(b'\t');
        assert!(ed.is_uncertain());
        let mut ed = LineEditor::new();
        ed.feed(0x12); // Ctrl-R
        assert!(ed.is_uncertain());
        let mut ed = LineEditor::new();
        for &b in b"\x1bOA" {
            ed.feed(b);
        }
        assert!(ed.is_uncertain());
    }

    #[test]
    fn ctrl_c_resets_and_ctrl_d_on_empty_is_eof() {
        let mut ed = LineEditor::new();
        ed.feed(b'x');
        assert_eq!(ed.feed(0x03), KeyEvent::Interrupt);
        assert_eq!(ed.text(), "");
        assert_eq!(ed.feed(0x04), KeyEvent::Eof);
        ed.feed(b'a');
        ed.feed(b'b');
        ed.feed(0x02); // left
        assert_eq!(ed.feed(0x04), KeyEvent::Edit); // delete-char
        assert_eq!(ed.text(), "a");
    }

    #[test]
    fn bracketed_paste_keeps_newlines_literal() {
        let mut ed = LineEditor::new();
        let mut events = Vec::new();
        for &b in b"\x1b[200~DROP\rTABLE x;\x1b[201~" {
            events.push(ed.feed(b));
        }
        assert!(events.iter().all(|e| *e == KeyEvent::Edit));
        assert_eq!(ed.text(), "DROP\nTABLE x;");
        assert!(!ed.is_uncertain());
    }

    #[test]
    fn utf8_input() {
        let mut ed = LineEditor::new();
        for &b in "שלום é".as_bytes() {
            ed.feed(b);
        }
        assert_eq!(ed.text(), "שלום é");
        ed.feed(0x7F);
        assert_eq!(ed.text(), "שלום ");
    }

    // -- Interceptor --

    #[test]
    fn sql_multiline_joined_with_space() {
        let mut ic = Interceptor::new(SQL);
        let subs = type_all(&mut ic, b"UPDATE users\rSET admin = true;\r");
        assert!(subs[0].statements.is_empty(), "first line is incomplete");
        assert_eq!(ic.pending(), "");
        assert_eq!(subs[1].statements, vec!["UPDATE users SET admin = true"]);

        let subs = type_all(&mut ic, b"DROP\rTABLE users;\r");
        assert_eq!(stmts(&subs), vec!["DROP TABLE users"]);
    }

    #[test]
    fn sql_backspace_typo() {
        let mut ic = Interceptor::new(SQL);
        let subs = type_all(&mut ic, b"DROP TABLX\x7fE users;\r");
        assert_eq!(stmts(&subs), vec!["DROP TABLE users"]);
    }

    #[test]
    fn sql_lf_enter_also_works() {
        let mut ic = Interceptor::new(SQL);
        let subs = type_all(&mut ic, b"SELECT 1;\n");
        assert_eq!(stmts(&subs), vec!["SELECT 1"]);
    }

    #[test]
    fn sql_meta_commands() {
        let mut ic = Interceptor::new(SQL);
        let subs = type_all(&mut ic, b"\\dt\r");
        assert!(subs[0].is_empty());
        let subs = type_all(&mut ic, b"DELETE FROM users\r\\r\rSELECT 1;\r");
        assert_eq!(stmts(&subs), vec!["SELECT 1"]);
        let subs = type_all(&mut ic, b"TRUNCATE TABLE orders\r\\g\r");
        assert_eq!(stmts(&subs), vec!["TRUNCATE TABLE orders"]);
        let subs = type_all(&mut ic, b"\\i cleanup.sql\r");
        assert!(matches!(subs[0].metas[0].kind, MetaKind::RunFile { .. }));
        assert_eq!(ic.pending(), "");
    }

    #[test]
    fn sql_paste_two_statements_one_line() {
        let mut ic = Interceptor::new(SQL);
        let subs = type_all(&mut ic, b"SELECT count(*) FROM users; DELETE FROM users;\r");
        assert_eq!(
            stmts(&subs),
            vec!["SELECT count(*) FROM users", "DELETE FROM users"]
        );
    }

    #[test]
    fn interrupt_clears_pending() {
        let mut ic = Interceptor::new(SQL);
        type_all(&mut ic, b"DROP\r");
        assert_eq!(ic.pending(), "DROP");
        assert_eq!(ic.feed_key(0x03), KeyEvent::Interrupt);
        assert_eq!(ic.pending(), "");
        let subs = type_all(&mut ic, b"TABLE x;\r");
        assert_eq!(stmts(&subs), vec!["TABLE x"]);
    }

    #[test]
    fn line_mode_each_enter_is_statement() {
        let mut ic = Interceptor::new(StatementMode::Line);
        let subs = type_all(&mut ic, b"FLUSHALL\rget k\r\r");
        assert_eq!(subs[0].statements, vec!["FLUSHALL"]);
        assert_eq!(subs[1].statements, vec!["get k"]);
        assert!(subs[2].is_empty());
    }

    #[test]
    fn line_mode_paste_with_newlines_splits_lines() {
        let mut ic = Interceptor::new(StatementMode::Line);
        let subs = type_all(&mut ic, b"\x1b[200~echo hi\nrm -rf /\x1b[201~\r");
        assert_eq!(subs[0].statements, vec!["echo hi", "rm -rf /"]);
    }

    #[test]
    fn mongo_enter_completes_balanced_statement() {
        let mut ic = Interceptor::new(MONGO);
        let subs = type_all(&mut ic, b"db.dropDatabase()\r");
        assert_eq!(stmts(&subs), vec!["db.dropDatabase()"]);
        let subs = type_all(&mut ic, b"db.users.drop();\r");
        assert_eq!(stmts(&subs), vec!["db.users.drop()"]);
        let subs = type_all(&mut ic, b"db.users.deleteMany({\r})\r");
        assert!(subs[0].statements.is_empty());
        assert_eq!(subs[1].statements, vec!["db.users.deleteMany({ })"]);
        // regex literal with a bracket does not break balancing
        let subs = type_all(&mut ic, b"db.u.find({n: /^[(]/})\rdb.users.drop()\r");
        assert_eq!(
            stmts(&subs),
            vec!["db.u.find({n: /^[(]/})", "db.users.drop()"]
        );
        let subs = type_all(&mut ic, b"load('x.js')\r");
        assert!(matches!(subs[0].metas[0].kind, MetaKind::RunFile { .. }));
    }

    #[test]
    fn uncertain_line_resyncs_from_echo() {
        let mut ic = Interceptor::new(SQL);
        ic.on_child_output(b"postgres=# ");
        for &b in b"\x1b[A" {
            assert_eq!(ic.feed_key(b), KeyEvent::Edit);
        }
        ic.on_child_output(b"DROP TABLE users;");
        assert_eq!(ic.feed_key(b'\r'), KeyEvent::Enter);
        let sub = ic.take_submission();
        assert!(sub.from_echo);
        assert_eq!(sub.statements, vec!["DROP TABLE users"]);
    }

    #[test]
    fn multi_line_history_entry_resyncs_across_rows() {
        // psql stores a multi-line query as one history entry.
        let mut ic = Interceptor::new(SQL);
        ic.set_size(80, 24);
        ic.on_child_output(b"postgres=# ");
        for &b in b"\x1b[A" {
            ic.feed_key(b);
        }
        ic.on_child_output(b"UPDATE users\r\nSET admin = true;");
        ic.feed_key(b'\r');
        let sub = ic.take_submission();
        assert_eq!(sub.statements, vec!["UPDATE users SET admin = true"]);
        // readline shows embedded newlines as ^J on one row
        let mut ic = Interceptor::new(SQL);
        ic.on_child_output(b"postgres=# ");
        for &b in b"\x1b[A" {
            ic.feed_key(b);
        }
        ic.on_child_output(b"DELETE^JFROM users;");
        ic.feed_key(b'\r');
        assert_eq!(ic.take_submission().statements, vec!["DELETE FROM users"]);
    }

    #[test]
    fn tab_completion_resyncs_from_echo() {
        let mut ic = Interceptor::new(SQL);
        ic.on_child_output(b"\r\npostgres=# ");
        for &b in b"DROP TA" {
            ic.feed_key(b);
            ic.on_child_output(&[b]);
        }
        ic.feed_key(b'\t');
        ic.on_child_output(b"BLE ");
        for &b in b"users;" {
            ic.feed_key(b);
            ic.on_child_output(&[b]);
        }
        ic.feed_key(b'\r');
        let sub = ic.take_submission();
        assert_eq!(sub.statements, vec!["DROP TABLE users"]);
        assert_eq!(sub.fallbacks, vec!["DROP TAusers;"]);
    }

    #[test]
    fn tab_listing_uses_redrawn_prompt_row() {
        let mut ic = Interceptor::new(SQL);
        ic.on_child_output(b"postgres=# ");
        for &b in b"DROP TA" {
            ic.feed_key(b);
            ic.on_child_output(&[b]);
        }
        ic.feed_key(b'\t');
        ic.on_child_output(b"\r\nTABLE  TABLESPACE\r\npostgres=# DROP TABLE users;");
        ic.feed_key(b'\r');
        assert_eq!(ic.take_submission().statements, vec!["DROP TABLE users"]);
    }

    #[test]
    fn uncertain_without_echo_falls_back_to_model() {
        let mut ic = Interceptor::new(StatementMode::Line);
        for &b in b"FLUSHALL\t" {
            ic.feed_key(b);
        }
        ic.feed_key(b'\r');
        let sub = ic.take_submission();
        assert!(!sub.from_echo);
        assert_eq!(sub.statements, vec!["FLUSHALL"]);
    }

    #[test]
    fn pager_keys_in_alt_screen_are_ignored() {
        // `q` typed into less must not prefix the next statement.
        let mut ic = Interceptor::new(SQL);
        ic.on_child_output(b"postgres=# ");
        let subs = type_echo(&mut ic, b"SELECT * FROM big_table;\r", "");
        assert_eq!(stmts(&subs), vec!["SELECT * FROM big_table"]);
        ic.on_child_output(b"\x1b[?1049h  1 | row\r\n:");
        assert_eq!(ic.feed_key(b' '), KeyEvent::Edit);
        assert_eq!(ic.feed_key(b'q'), KeyEvent::Edit);
        ic.on_child_output(b"\x1b[?1049l\r\npostgres=# ");
        let subs = type_echo(&mut ic, b"TRUNCATE orders;\r", "postgres=# ");
        assert_eq!(stmts(&subs), vec!["TRUNCATE orders"]);
    }

    #[test]
    fn pager_keys_without_alt_screen_resync_on_prompt() {
        // `less -X`: no alternate screen, the prompt is redrawn in place.
        let mut ic = Interceptor::new(SQL);
        ic.on_child_output(b"postgres=# ");
        type_echo(&mut ic, b"SELECT * FROM big_table;\r", "");
        ic.on_child_output(b"  1 | row\r\n:");
        ic.feed_key(b'q');
        ic.on_child_output(b"\r\x1b[Kpostgres=# ");
        let subs = type_echo(&mut ic, b"TRUNCATE orders;\r", "postgres=# ");
        assert!(everything(&subs).contains(&"TRUNCATE orders".to_string()));
        assert_eq!(subs[0].statements, vec!["TRUNCATE orders"]);
    }

    #[test]
    fn password_prompt_is_dropped_and_not_kept() {
        let mut ic = Interceptor::new(SQL);
        ic.on_child_output(b"Password for user postgres: ");
        ic.set_tty_state(Some(TtyState {
            echo: false,
            icanon: true,
        }));
        let subs = type_all(&mut ic, b"S3cretPw\r");
        assert!(subs[0].secret);
        assert!(subs[0].is_empty());
        assert!(!subs[0].log_summary().contains("S3cret"));
        ic.set_tty_state(Some(TtyState {
            echo: false,
            icanon: false,
        }));
        ic.on_child_output(b"\r\npostgres=# ");
        let subs = type_echo(&mut ic, b"DROP TABLE users;\r", "postgres=# ");
        assert_eq!(stmts(&subs), vec!["DROP TABLE users"]);
    }

    #[test]
    fn unechoed_line_is_checked_alone_and_redacted() {
        // Raw-mode client (mongosh passwordPrompt) that does not echo.
        let mut ic = Interceptor::new(SQL);
        ic.on_child_output(b"postgres=# ");
        type_echo(&mut ic, b"SELECT 1;\r", "Password: ");
        let subs = type_all(&mut ic, b"hunter2\r");
        assert_eq!(subs[0].unconfirmed, vec!["hunter2"]);
        assert!(subs[0].statements.is_empty());
        assert!(!subs[0].log_summary().contains("hunter2"));
        assert_eq!(ic.pending(), "");
    }

    #[test]
    fn primary_prompt_resyncs_pending() {
        // psql `\prompt` answer, or any desync: the child shows `=#` again.
        let mut ic = Interceptor::new(SQL);
        ic.on_child_output(b"postgres=# ");
        type_echo(&mut ic, b"42\r", "postgres=# ");
        assert_eq!(ic.pending(), "42");
        let subs = type_echo(&mut ic, b"DELETE FROM users;\r", "postgres=# ");
        assert_eq!(subs[0].statements, vec!["DELETE FROM users"]);
        // a continuation prompt keeps the buffer
        let mut ic = Interceptor::new(SQL);
        ic.on_child_output(b"postgres=# ");
        type_echo(&mut ic, b"DROP\r", "postgres-# ");
        let subs = type_echo(&mut ic, b"TABLE users;\r", "postgres=# ");
        assert_eq!(subs[0].statements, vec!["DROP TABLE users"]);
    }

    #[test]
    fn confusing_literal_never_disables_checking() {
        // Our lexer thinks a quote is open, the child does not (safety net).
        let mut ic = Interceptor::new(SQL);
        let subs = type_all(&mut ic, b"SELECT 'unterminated\rDROP TABLE users;\r");
        assert!(everything(&subs).contains(&"DROP TABLE users".to_string()));
    }

    #[test]
    fn psql_dollar_quote_does_not_desync() {
        let mut ic = Interceptor::new(SQL);
        let subs = type_all(
            &mut ic,
            b"COMMENT ON TABLE users IS $$Don't touch$$;\rDROP TABLE users;\r",
        );
        assert_eq!(subs[1].statements, vec!["DROP TABLE users"]);
    }

    #[test]
    fn psql_variables_are_substituted() {
        let mut ic = Interceptor::new(SQL);
        let subs = type_all(&mut ic, b"\\set cleanup 'DROP TABLE users'\r:cleanup;\r");
        assert!(stmts(&subs).contains(&"DROP TABLE users".to_string()));
        let subs = type_all(&mut ic, b":unknown_var;\r");
        assert!(matches!(
            subs[0].metas[0].kind,
            MetaKind::Opaque {
                id: "wrap:sql_variable",
                ..
            }
        ));
        let subs = type_all(&mut ic, b"SELECT now()::date;\r");
        assert!(subs[0].metas.is_empty());
    }

    #[test]
    fn mysql_line_commands_and_delimiter() {
        let my = StatementMode::Delimited {
            delimiter: ';',
            dialect: Dialect::MySql,
            enter_completes: false,
        };
        let mut ic = Interceptor::new(my);
        let subs = type_all(&mut ic, b"use billing\rTRUNCATE invoices;\r");
        assert_eq!(stmts(&subs), vec!["TRUNCATE invoices"]);
        let subs = type_all(&mut ic, b"delimiter //\rDROP TABLE users//\r");
        assert_eq!(stmts(&subs), vec!["DROP TABLE users"]);
        assert_eq!(ic.delimiter(), "//");
        let subs = type_all(
            &mut ic,
            b"CREATE PROCEDURE p() BEGIN\rDELETE FROM a;\rEND//\r",
        );
        assert_eq!(
            stmts(&subs),
            vec!["CREATE PROCEDURE p() BEGIN DELETE FROM a; END"]
        );
        let subs = type_all(
            &mut ic,
            b"DELIMITER ;\rSELECT 1 # it's fine\r;\rDROP TABLE x;\r",
        );
        assert_eq!(stmts(&subs), vec!["SELECT 1", "DROP TABLE x"]);
        let subs = type_all(&mut ic, b"source /tmp/cleanup.sql\r");
        assert!(matches!(subs[0].metas[0].kind, MetaKind::RunFile { .. }));
        let subs = type_all(&mut ic, b"\\! rm -rf /data\r");
        assert!(matches!(subs[0].metas[0].kind, MetaKind::Shell { .. }));
    }

    #[test]
    fn sqlite_dot_commands_are_line_commands() {
        let lite = StatementMode::Delimited {
            delimiter: ';',
            dialect: Dialect::Sqlite,
            enter_completes: false,
        };
        let mut ic = Interceptor::new(lite);
        let subs = type_all(&mut ic, b".tables\rDELETE FROM users;\r");
        assert_eq!(stmts(&subs), vec!["DELETE FROM users"]);
        let subs = type_all(&mut ic, b".read cleanup.sql\r.shell rm -rf /x\r");
        assert!(matches!(subs[0].metas[0].kind, MetaKind::RunFile { .. }));
        assert!(matches!(subs[1].metas[0].kind, MetaKind::Shell { .. }));
    }

    #[test]
    fn sqlite_pipe_forms_run_shell_commands() {
        let lite = StatementMode::Delimited {
            delimiter: ';',
            dialect: Dialect::Sqlite,
            enter_completes: false,
        };
        let shell = |cmd: &str| MetaKind::Shell {
            command: cmd.to_string(),
        };
        for (line, want) in [
            (
                ".once '|rm -rf /home/dev/data'",
                shell("rm -rf /home/dev/data"),
            ),
            (".once -x '|rm -rf /x'", shell("rm -rf /x")),
            (".output \"|rm -rf /x\"", shell("rm -rf /x")),
            (".output |cat", shell("cat")),
            // Unquoted, the rest of the line is the command.
            (
                ".once |rm -rf /home/dev/data",
                shell("rm -rf /home/dev/data"),
            ),
            (".output |rm -rf /x", shell("rm -rf /x")),
            (".once -x |rm -rf /x", shell("rm -rf /x")),
            (".import |rm -rf /x t", shell("rm -rf /x")),
            (".import --csv |curl -s x t", shell("curl -s x")),
            (
                ".read |rm -rf /x",
                MetaKind::ShellToSql {
                    command: "rm -rf /x".into(),
                },
            ),
            (".import '|rm -rf /x' t", shell("rm -rf /x")),
            (".import --csv '|curl -s x' t", shell("curl -s x")),
            (
                ".read '|rm -rf /x'",
                MetaKind::ShellToSql {
                    command: "rm -rf /x".into(),
                },
            ),
        ] {
            let mut ic = Interceptor::new(lite);
            let subs = type_all(&mut ic, format!("{line}\r").as_bytes());
            assert_eq!(subs[0].metas.len(), 1, "{line}");
            assert_eq!(subs[0].metas[0].kind, want, "{line}");
        }
        for line in [".once out.txt", ".output stdout", ".import data.csv t"] {
            let mut ic = Interceptor::new(lite);
            let subs = type_all(&mut ic, format!("{line}\r").as_bytes());
            assert!(subs[0].metas.is_empty(), "{line}");
        }
    }

    #[test]
    fn comment_line_leaves_the_buffer_empty() {
        // A `source` line after a comment line is a client command.
        let sub = Interceptor::split_script(Dialect::MySql, "-- cleanup\nsource /tmp/x.sql\n");
        assert!(
            matches!(
                sub.metas.first().map(|m| &m.kind),
                Some(MetaKind::RunFile { .. })
            ),
            "{sub:?}"
        );
        let sub = Interceptor::split_script(Dialect::Sqlite, "-- c\n.read /tmp/x.sql\n");
        assert!(matches!(
            sub.metas.first().map(|m| &m.kind),
            Some(MetaKind::RunFile { .. })
        ));
    }

    #[test]
    fn script_reader_skips_copy_data_and_interpolates_include_paths() {
        let text = "COPY users (id, name) FROM stdin;\n1\tO'Brien\n2\tDROP TABLE users;\n\\.\nTRUNCATE orders;\n\\set d /home/dev\n\\i :d/cleanup.sql\n\\ir :'d'/x.sql\n";
        let sub = Interceptor::split_script(Dialect::Postgres, text);
        assert_eq!(
            sub.statements,
            vec![
                "COPY users (id, name) FROM stdin",
                "2 DROP TABLE users",
                "TRUNCATE orders"
            ]
        );
        assert_eq!(
            sub.metas[0].kind,
            MetaKind::RunFile {
                path: "/home/dev/cleanup.sql".into(),
                relative: false
            }
        );
        assert_eq!(
            sub.metas[1].kind,
            MetaKind::RunFile {
                path: "/home/dev/x.sql".into(),
                relative: true
            }
        );
    }

    #[test]
    fn script_reader_is_linear_on_long_statements() {
        // One INSERT spread over 200k lines: lexed once, not re-lexed per
        // line (this took minutes with the quadratic splitter).
        let mut text = String::from("INSERT INTO t VALUES\n");
        for i in 0..200_000 {
            text.push_str(&format!("({i}, 'x'),\n"));
        }
        text.push_str("(0, 'y');\nDELETE FROM users;\n");
        let start = std::time::Instant::now();
        let sub = Interceptor::split_script(Dialect::Postgres, &text);
        assert_eq!(sub.statements.len(), 2);
        assert_eq!(sub.statements[1], "DELETE FROM users");
        assert!(start.elapsed().as_secs() < 20, "{:?}", start.elapsed());
    }
}
