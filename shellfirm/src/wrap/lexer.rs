//! Client-side statement lexers.
//!
//! Each wrapped client decides on its own where a statement ends. To check
//! exactly what the client is about to run, the splitter here follows the
//! client's lexer for its [`Dialect`]:
//!
//! * **Postgres** (psql): standard-conforming `'...'` strings (no backslash
//!   escapes, `''` doubling), `E'...'` escape strings, `"identifiers"`,
//!   dollar quoting (`$$...$$`, `$tag$...$tag$`), `--` and nested `/* */`
//!   comments, and backslash meta-commands anywhere in a line.
//! * **mysql**: `'...'` / `"..."` strings with backslash escapes,
//!   backtick identifiers, `#` and `-- ` comments, `/* */` comments (but
//!   `/*! ... */` executable comments are code), backslash commands
//!   (`\g`, `\G`, `\c`, `\.`, `\!`, `\d`, `\e`) and a changeable delimiter.
//! * **Sqlite**: `''` doubling only, `"..."` / `` `...` `` / `[...]`
//!   identifiers, `--` and `/* */` comments.
//! * **SQL Server** (sqlcmd, T-SQL): `''` doubling only, `"..."` / `[...]`
//!   identifiers, `--` and nested `/* */` comments. Its client commands
//!   (`GO`, `!!cmd`, `:r file`, ...) are whole lines, see
//!   [`crate::wrap::line`].
//! * **Generic**: quotes with backslash escapes, `$$` strings, SQL comments.
//! * **JavaScript** (mongosh): strings with escapes, template literals with
//!   `${...}`, regex literals, `//` and `/* */` comments, bracket balance.

use std::sync::OnceLock;

use regex::Regex;

/// The lexer rules of a wrapped client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    Postgres,
    MySql,
    Sqlite,
    /// sqlcmd (T-SQL).
    SqlServer,
    Generic,
    JavaScript,
}

impl Dialect {
    /// SQL dialect (vs. JavaScript).
    #[must_use]
    pub const fn is_sql(self) -> bool {
        !matches!(self, Self::JavaScript)
    }

    const fn double_quote_is_string(self) -> bool {
        matches!(self, Self::MySql | Self::Generic | Self::JavaScript)
    }

    const fn backslash_in_strings(self) -> bool {
        matches!(self, Self::MySql | Self::Generic | Self::JavaScript)
    }
}

/// A client command that runs something the statement checks cannot see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetaKind {
    /// Runs SQL/JS from a file (`\i`, `source`, `.read`, `load()`).
    /// `relative`: the path is relative to the including file (`\ir`), not
    /// to the client's working directory.
    RunFile { path: String, relative: bool },
    /// Runs a shell command (`\!`, `system`, `.shell`, `\o |cmd`).
    Shell { command: String },
    /// Runs a shell command and then runs its output as SQL (sqlite3
    /// `.read '|cmd'`).
    ShellToSql { command: String },
    /// Runs SQL the wrap cannot see (editor, `\gexec`, interactive shell,
    /// psql variable).
    Opaque { id: &'static str, what: String },
    /// A destructive statement whose target the wrap cannot know (psql
    /// `TRUNCATE :"t"` after `\gset`): High `wrap:sql_variable_target`.
    UnknownTarget { what: String },
}

/// A meta-command found while splitting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaCommand {
    /// The command as typed (for the challenge banner).
    pub raw: String,
    pub kind: MetaKind,
}

/// Result of splitting accumulated input.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct Split {
    /// Complete statements, whitespace-normalised, comments removed.
    pub statements: Vec<String>,
    /// Raw text after the last complete statement (meta-commands removed).
    pub remainder: String,
    /// The remainder has no open quote/comment and balanced brackets.
    pub remainder_balanced: bool,
    /// The remainder ends inside a string, quoted identifier or comment.
    pub in_literal: bool,
    /// The remainder holds code (not only whitespace and comments) or ends
    /// inside a string / comment.
    pub remainder_has_code: bool,
    /// Meta-commands that run files / shell commands / unseen SQL.
    pub metas: Vec<MetaCommand>,
    /// psql `\set name value` assignments, in order.
    pub vars: Vec<(String, String)>,
    /// New statement delimiter (mysql `\d` / `delimiter`).
    pub delimiter: Option<String>,
    /// The client opens a new connection (psql `\c`, mysql `\r`): the
    /// temporary tables of the old one are gone.
    pub reconnect: bool,
}

/// Collapse all whitespace runs (including newlines) into single spaces.
#[must_use]
pub fn normalize_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum St {
    Normal,
    /// A quoted string / identifier closed by `close`; `esc` = backslash
    /// escapes the next char.
    Quoted {
        close: char,
        esc: bool,
    },
    Dollar(String),
    LineComment,
    BlockComment(u32),
    /// JS template literal.
    Template,
    /// JS regex literal.
    Regex {
        class: bool,
    },
}

const fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c as u32 >= 0x80
}

/// `$tag$` starting at `i` (Postgres), returning the full delimiter.
fn dollar_tag(chars: &[char], i: usize) -> Option<String> {
    if chars.get(i) != Some(&'$') {
        return None;
    }
    if i > 0 && (is_ident(chars[i - 1]) || chars[i - 1] == '$') {
        return None;
    }
    let mut j = i + 1;
    if chars.get(j).is_some_and(char::is_ascii_digit) {
        return None; // `$1` positional parameter
    }
    while j < chars.len() && is_ident(chars[j]) {
        j += 1;
    }
    if chars.get(j) == Some(&'$') {
        Some(chars[i..=j].iter().collect())
    } else {
        None
    }
}

fn starts_with_at(chars: &[char], i: usize, pat: &[char]) -> bool {
    !pat.is_empty() && chars.len() >= i + pat.len() && chars[i..i + pat.len()] == *pat
}

/// Whether a `/` at this point starts a JS regex literal (not division).
fn js_regex_allowed(code: &str) -> bool {
    let t = code.trim_end();
    let Some(last) = t.chars().last() else {
        return true;
    };
    if "(,=:[!&|?{};+-*%<>~^".contains(last) {
        return true;
    }
    if is_ident(last) {
        let word: String = t
            .chars()
            .rev()
            .take_while(|c| is_ident(*c))
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        return matches!(
            word.as_str(),
            "return"
                | "typeof"
                | "case"
                | "do"
                | "else"
                | "in"
                | "of"
                | "new"
                | "delete"
                | "void"
                | "throw"
                | "yield"
                | "await"
        );
    }
    false
}

/// Quote state for a single-quoted string opened at `i`.
const fn single_quote_escapes(dialect: Dialect, chars: &[char], i: usize) -> bool {
    match dialect {
        Dialect::Postgres => {
            // E'...' / e'...' escape-string syntax.
            i > 0 && matches!(chars[i - 1], 'E' | 'e') && (i < 2 || !is_ident(chars[i - 2]))
        }
        Dialect::Sqlite | Dialect::SqlServer => false,
        _ => true,
    }
}

pub(crate) fn unquote_arg(s: &str) -> String {
    let s = s.trim();
    let first = s.split_whitespace().next().unwrap_or("");
    if let Some(inner) = s.strip_prefix('\'') {
        if let Some(end) = inner.find('\'') {
            return inner[..end].to_string();
        }
    }
    if let Some(inner) = s.strip_prefix('"') {
        if let Some(end) = inner.find('"') {
            return inner[..end].to_string();
        }
    }
    first.trim_end_matches(';').to_string()
}

fn psql_set_value(rest: &str) -> String {
    let rest = rest.trim();
    let mut out = String::new();
    let mut chars = rest.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\'' {
            while let Some(d) = chars.next() {
                if d == '\'' {
                    if chars.peek() == Some(&'\'') {
                        out.push('\'');
                        chars.next();
                    } else {
                        break;
                    }
                } else {
                    out.push(d);
                }
            }
        } else if c.is_whitespace() {
            // psql concatenates multiple arguments
        } else {
            out.push(c);
        }
    }
    out
}

#[derive(Debug)]
struct Splitter {
    dialect: Dialect,
    delim: Vec<char>,
    out: Split,
    cur: String,
    raw: String,
    depth: i32,
    tmpl: Vec<i32>,
    exec_comment: bool,
    /// Lexer state at the end of the text fed so far.
    st: St,
}

impl Splitter {
    fn new(delimiter: &str, dialect: Dialect) -> Self {
        let delim: Vec<char> = if delimiter.is_empty() {
            vec![';']
        } else {
            delimiter.chars().collect()
        };
        Self {
            dialect,
            delim,
            out: Split::default(),
            cur: String::new(),
            raw: String::new(),
            depth: 0,
            tmpl: Vec::new(),
            exec_comment: false,
            st: St::Normal,
        }
    }

    const fn in_literal(&self) -> bool {
        !matches!(self.st, St::Normal | St::LineComment)
    }

    /// Everything found so far (with a copy of the current remainder when
    /// `with_remainder`).
    fn take(&mut self, with_remainder: bool) -> Split {
        let mut out = std::mem::take(&mut self.out);
        if with_remainder {
            out.remainder.clone_from(&self.raw);
        }
        out.in_literal = self.in_literal();
        out.remainder_balanced = !out.in_literal && self.depth <= 0 && self.tmpl.is_empty();
        out.remainder_has_code = out.in_literal || !self.cur.trim().is_empty();
        out
    }

    fn finish(&mut self) {
        let s = normalize_ws(&self.cur);
        if !s.is_empty() {
            self.out.statements.push(s);
        }
        self.cur.clear();
        self.raw.clear();
        self.depth = 0;
        self.tmpl.clear();
        self.exec_comment = false;
    }

    fn push(&mut self, c: char) {
        self.cur.push(c);
        self.raw.push(c);
    }

    fn rest_of_line(chars: &[char], from: usize) -> (String, usize) {
        let mut j = from;
        while j < chars.len() && chars[j] != '\n' {
            j += 1;
        }
        (chars[from..j].iter().collect(), j)
    }

    /// psql backslash command at `i`; returns the index to continue at.
    fn psql_meta(&mut self, chars: &[char], i: usize) -> usize {
        let mut j = i + 1;
        while j < chars.len() && (chars[j].is_ascii_alphanumeric() || chars[j] == '_') {
            j += 1;
        }
        if j == i + 1 && j < chars.len() && chars[j] != '\n' {
            j += 1; // single-char command: `\!`, `\?`, `\;`
        }
        let name: String = chars[i + 1..j].iter().collect();
        let (args, end) = Self::rest_of_line(chars, j);
        let raw = format!("\\{name}{args}").trim().to_string();
        let a = args.trim();
        match name.as_str() {
            "g" | "gx" | "gset" | "G" | "gdesc" | "crosstabview" | "watch" => {
                self.finish();
                if let Some(cmd) = a.strip_prefix('|') {
                    self.out.metas.push(MetaCommand {
                        raw,
                        kind: MetaKind::Shell {
                            command: cmd.trim().to_string(),
                        },
                    });
                }
            }
            "gexec" => {
                self.finish();
                self.out.metas.push(MetaCommand {
                    raw,
                    kind: MetaKind::Opaque {
                        id: "wrap:psql_gexec",
                        what: "`\\gexec` runs every value the query returns as a new SQL \
                               statement; those statements are not checked."
                            .into(),
                    },
                });
            }
            "c" | "connect" => self.out.reconnect = true,
            "r" | "reset" => {
                self.cur.clear();
                self.raw.clear();
                self.depth = 0;
            }
            "i" | "ir" | "include" | "include_relative" => self.out.metas.push(MetaCommand {
                raw,
                kind: MetaKind::RunFile {
                    path: unquote_arg(a),
                    relative: matches!(name.as_str(), "ir" | "include_relative"),
                },
            }),
            "!" => self.out.metas.push(shell_meta(raw, a)),
            "e" | "edit" | "ef" | "ev" => self.out.metas.push(editor_meta(raw)),
            "o" | "out" | "w" | "write" => {
                if let Some(cmd) = a.strip_prefix('|') {
                    self.out.metas.push(MetaCommand {
                        raw,
                        kind: MetaKind::Shell {
                            command: cmd.trim().to_string(),
                        },
                    });
                }
            }
            "copy" => {
                let s = normalize_ws(&format!("COPY {a}"));
                self.out.statements.push(s);
            }
            "set" => {
                let mut parts = a.splitn(2, char::is_whitespace);
                if let Some(n) = parts.next().filter(|n| !n.is_empty()) {
                    let v = psql_set_value(parts.next().unwrap_or(""));
                    self.out.vars.push((n.to_string(), v));
                }
            }
            _ => {}
        }
        end
    }

    /// mysql backslash command at `i`; returns the index to continue at.
    fn mysql_meta(&mut self, chars: &[char], i: usize) -> usize {
        let Some(&c) = chars.get(i + 1) else {
            return i + 1;
        };
        match c {
            'g' | 'G' => {
                self.finish();
                i + 2
            }
            'c' => {
                self.cur.clear();
                self.raw.clear();
                self.depth = 0;
                i + 2
            }
            _ => {
                let (args, end) = Self::rest_of_line(chars, i + 2);
                let raw = format!("\\{c}{args}").trim().to_string();
                let a = args.trim();
                match c {
                    '.' => self.out.metas.push(MetaCommand {
                        raw,
                        kind: MetaKind::RunFile {
                            path: unquote_arg(a),
                            relative: false,
                        },
                    }),
                    '!' => self.out.metas.push(shell_meta(raw, a)),
                    'e' => self.out.metas.push(editor_meta(raw)),
                    'r' => self.out.reconnect = true,
                    'd' => {
                        if let Some(d) = a.split_whitespace().next() {
                            self.delim = d.chars().collect();
                            self.out.delimiter = Some(d.to_string());
                        }
                    }
                    _ => {}
                }
                end
            }
        }
    }

    /// Lex `chars`, continuing from the state the previous text left.
    #[allow(clippy::too_many_lines)]
    fn run(&mut self, chars: &[char]) {
        let d = self.dialect;
        let mut st = std::mem::replace(&mut self.st, St::Normal);
        let mut i = 0usize;
        while i < chars.len() {
            let c = chars[i];
            let next = chars.get(i + 1).copied();
            match st {
                St::Normal => {
                    if self.exec_comment && c == '*' && next == Some('/') {
                        self.exec_comment = false;
                        self.cur.push(' ');
                        self.raw.push_str("*/");
                        i += 2;
                        continue;
                    }
                    if self.tmpl.last() == Some(&self.depth) && c == '}' {
                        self.tmpl.pop();
                        self.push(c);
                        st = St::Template;
                        i += 1;
                        continue;
                    }
                    if starts_with_at(chars, i, &self.delim) {
                        self.finish();
                        i += self.delim.len();
                        continue;
                    }
                    match c {
                        '\'' => {
                            st = St::Quoted {
                                close: '\'',
                                esc: single_quote_escapes(d, chars, i),
                            };
                            self.push(c);
                        }
                        '"' => {
                            st = St::Quoted {
                                close: '"',
                                esc: d.double_quote_is_string() && d.backslash_in_strings(),
                            };
                            self.push(c);
                        }
                        '`' if d == Dialect::JavaScript => {
                            st = St::Template;
                            self.push(c);
                        }
                        '`' if !matches!(d, Dialect::Postgres | Dialect::SqlServer) => {
                            st = St::Quoted {
                                close: '`',
                                esc: false,
                            };
                            self.push(c);
                        }
                        '[' if matches!(d, Dialect::Sqlite | Dialect::SqlServer) => {
                            st = St::Quoted {
                                close: ']',
                                esc: false,
                            };
                            self.push(c);
                        }
                        '$' if matches!(d, Dialect::Postgres | Dialect::Generic) => {
                            let tag = dollar_tag(chars, i)
                                .filter(|t| d == Dialect::Postgres || t == "$$");
                            if let Some(tag) = tag {
                                for ch in tag.chars() {
                                    self.push(ch);
                                }
                                i += tag.chars().count();
                                st = St::Dollar(tag);
                                continue;
                            }
                            self.push(c);
                        }
                        '-' if next == Some('-')
                            && d.is_sql()
                            && (d != Dialect::MySql
                                || chars.get(i + 2).is_none_or(|n| n.is_whitespace())) =>
                        {
                            self.cur.push(' ');
                            self.raw.push_str("--");
                            st = St::LineComment;
                            i += 2;
                            continue;
                        }
                        '#' if d == Dialect::MySql => {
                            self.cur.push(' ');
                            self.raw.push('#');
                            st = St::LineComment;
                        }
                        '/' if next == Some('/') && d == Dialect::JavaScript => {
                            self.cur.push(' ');
                            self.raw.push_str("//");
                            st = St::LineComment;
                            i += 2;
                            continue;
                        }
                        '/' if next == Some('*') => {
                            if d == Dialect::MySql && matches!(chars.get(i + 2), Some('!' | '+')) {
                                // Executable comment / optimizer hint: code.
                                let mut j = i + 3;
                                while j < chars.len() && chars[j].is_ascii_digit() {
                                    j += 1;
                                }
                                self.cur.push(' ');
                                self.raw.extend(&chars[i..j]);
                                self.exec_comment = true;
                                i = j;
                                continue;
                            }
                            self.cur.push(' ');
                            self.raw.push_str("/*");
                            st = St::BlockComment(1);
                            i += 2;
                            continue;
                        }
                        '/' if d == Dialect::JavaScript && js_regex_allowed(&self.cur) => {
                            st = St::Regex { class: false };
                            self.push(c);
                        }
                        '\\' if d == Dialect::Postgres => {
                            i = self.psql_meta(chars, i);
                            continue;
                        }
                        '\\' if d == Dialect::MySql => {
                            i = self.mysql_meta(chars, i);
                            continue;
                        }
                        _ => {
                            match c {
                                '(' | '[' | '{' => self.depth += 1,
                                ')' | ']' | '}' => self.depth -= 1,
                                _ => {}
                            }
                            self.push(c);
                        }
                    }
                }
                St::Quoted { close, esc } => {
                    self.push(c);
                    if esc && c == '\\' {
                        if let Some(n) = next {
                            self.push(n);
                            i += 1;
                        }
                    } else if c == close {
                        st = St::Normal;
                    }
                }
                St::Dollar(ref tag) => {
                    let tag_chars: Vec<char> = tag.chars().collect();
                    if starts_with_at(chars, i, &tag_chars) {
                        for ch in &tag_chars {
                            self.push(*ch);
                        }
                        i += tag_chars.len();
                        st = St::Normal;
                        continue;
                    }
                    self.push(c);
                }
                St::LineComment => {
                    if c == '\n' {
                        self.push('\n');
                        st = St::Normal;
                    } else {
                        self.raw.push(c);
                    }
                }
                St::BlockComment(n) => {
                    if c == '*' && next == Some('/') {
                        self.raw.push_str("*/");
                        i += 2;
                        if n <= 1 {
                            self.cur.push(' ');
                            st = St::Normal;
                        } else {
                            st = St::BlockComment(n - 1);
                        }
                        continue;
                    }
                    if matches!(d, Dialect::Postgres | Dialect::SqlServer)
                        && c == '/'
                        && next == Some('*')
                    {
                        self.raw.push_str("/*");
                        i += 2;
                        st = St::BlockComment(n + 1);
                        continue;
                    }
                    self.raw.push(c);
                }
                St::Template => {
                    self.push(c);
                    if c == '\\' {
                        if let Some(n) = next {
                            self.push(n);
                            i += 1;
                        }
                    } else if c == '`' {
                        st = St::Normal;
                    } else if c == '$' && next == Some('{') {
                        self.push('{');
                        i += 1;
                        self.tmpl.push(self.depth);
                        st = St::Normal;
                    }
                }
                St::Regex { class } => {
                    self.push(c);
                    if c == '\\' {
                        if let Some(n) = next {
                            self.push(n);
                            i += 1;
                        }
                    } else if c == '\n' {
                        st = St::Normal; // not a regex after all
                    } else if class {
                        if c == ']' {
                            st = St::Regex { class: false };
                        }
                    } else if c == '[' {
                        st = St::Regex { class: true };
                    } else if c == '/' {
                        st = St::Normal;
                    }
                }
            }
            i += 1;
        }
        self.st = st;
    }
}

pub(crate) fn shell_meta(raw: String, args: &str) -> MetaCommand {
    if args.trim().is_empty() {
        MetaCommand {
            raw,
            kind: MetaKind::Opaque {
                id: "wrap:interactive_shell",
                what: "This opens an interactive shell; commands typed there are not checked \
                       by the wrap."
                    .into(),
            },
        }
    } else {
        MetaCommand {
            raw,
            kind: MetaKind::Shell {
                command: args.trim().to_string(),
            },
        }
    }
}

pub(crate) fn editor_meta(raw: String) -> MetaCommand {
    MetaCommand {
        raw,
        kind: MetaKind::Opaque {
            id: "wrap:editor",
            what: "This opens the query buffer in an editor; whatever you write there runs \
                   without being checked."
                .into(),
        },
    }
}

/// Split `text` into complete statements and a remainder, following the
/// client lexer of `dialect`. `delimiter` may be several characters (mysql
/// `DELIMITER //`).
#[must_use]
pub fn split_statements(text: &str, delimiter: &str, dialect: Dialect) -> Split {
    let chars: Vec<char> = text.chars().collect();
    let mut sp = Splitter::new(delimiter, dialect);
    sp.run(&chars);
    sp.take(true)
}

/// Incremental [`split_statements`]: text is fed piece by piece (whole
/// lines) and the lexer state carries over, so a long script is lexed in
/// one linear pass.
#[derive(Debug)]
pub struct StreamSplitter {
    sp: Splitter,
}

impl StreamSplitter {
    #[must_use]
    pub fn new(delimiter: &str, dialect: Dialect) -> Self {
        Self {
            sp: Splitter::new(delimiter, dialect),
        }
    }

    /// Lex more text.
    pub fn feed(&mut self, text: &str) {
        let chars: Vec<char> = text.chars().collect();
        self.sp.run(&chars);
    }

    /// The statements, meta-commands, `\set` variables and delimiter change
    /// found since the last call. `remainder` is left empty (see
    /// [`Self::remainder`]): copying it on every line would make a long
    /// statement quadratic.
    pub fn take(&mut self) -> Split {
        self.sp.take(false)
    }

    /// The text after the last complete statement.
    #[must_use]
    pub fn remainder(&self) -> &str {
        &self.sp.raw
    }

    /// The pending text holds code (not only whitespace and comments), or
    /// ends inside a string / comment.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        self.sp.in_literal() || !self.sp.cur.trim().is_empty()
    }

    /// End the pending statement as if the delimiter followed it (it shows
    /// up in the next [`Self::take`]).
    pub fn flush(&mut self) {
        self.sp.st = St::Normal;
        self.sp.finish();
    }

    /// Forget the pending text.
    pub fn clear(&mut self) {
        self.sp.st = St::Normal;
        self.sp.cur.clear();
        self.sp.raw.clear();
        self.sp.depth = 0;
        self.sp.tmpl.clear();
        self.sp.exec_comment = false;
    }

    /// Change the statement delimiter (mysql `DELIMITER //`).
    pub fn set_delimiter(&mut self, delimiter: &str) {
        if !delimiter.is_empty() {
            self.sp.delim = delimiter.chars().collect();
        }
    }
}

/// Replace the contents of string literals with nothing (`'...'` → `''`),
/// so that SQL/JS keywords inside data never match a check. Quoted
/// identifiers are kept.
#[must_use]
pub fn mask_literals(stmt: &str, dialect: Dialect) -> String {
    let (masked, _) = scan_literals(stmt, dialect);
    masked
}

/// The contents of the string literals in `stmt`.
#[must_use]
pub fn literal_contents(stmt: &str, dialect: Dialect) -> Vec<String> {
    scan_literals(stmt, dialect)
        .1
        .into_iter()
        .map(|l| l.content)
        .collect()
}

/// A string literal of a statement: its content and where it is (char
/// indices; `end` is just after the closing quote).
#[derive(Debug, Clone)]
struct Literal {
    start: usize,
    end: usize,
    content: String,
}

/// A JS string used as an object key (`{"dropDatabase": 1}`): it names a
/// command or field, it is not data, so it is not masked.
fn js_object_key(chars: &[char], start: usize, end: usize) -> bool {
    let before = chars[..start].iter().rev().find(|c| !c.is_whitespace());
    let after = chars[end.min(chars.len())..]
        .iter()
        .find(|c| !c.is_whitespace());
    matches!(before, Some('{' | ',')) && after == Some(&':')
}

fn scan_literals(stmt: &str, dialect: Dialect) -> (String, Vec<Literal>) {
    let chars: Vec<char> = stmt.chars().collect();
    let mut out = String::new();
    let mut lits = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let string_quote = c == '\''
            || (c == '"' && dialect.double_quote_is_string())
            || (c == '`' && dialect == Dialect::JavaScript);
        if string_quote {
            let esc = if c == '\'' {
                single_quote_escapes(dialect, &chars, i)
            } else {
                dialect.backslash_in_strings()
            };
            let mut j = i + 1;
            let mut content = String::new();
            while j < chars.len() {
                if esc && chars[j] == '\\' && j + 1 < chars.len() {
                    content.push(chars[j + 1]);
                    j += 2;
                    continue;
                }
                if chars[j] == c {
                    if chars.get(j + 1) == Some(&c) && c != '`' {
                        content.push(c);
                        j += 2;
                        continue;
                    }
                    break;
                }
                content.push(chars[j]);
                j += 1;
            }
            let end = (j + 1).min(chars.len());
            if dialect == Dialect::JavaScript && c != '`' && js_object_key(&chars, i, end) {
                out.extend(&chars[i..end]);
            } else {
                out.push(c);
                out.push(c);
                lits.push(Literal {
                    start: i,
                    end,
                    content,
                });
            }
            i = j + 1;
            continue;
        }
        if matches!(c, '"' | '`' | '[') && dialect.is_sql() {
            // quoted identifier: keep as is
            let close = if c == '[' { ']' } else { c };
            if c == '[' && !matches!(dialect, Dialect::Sqlite | Dialect::SqlServer) {
                out.push(c);
                i += 1;
                continue;
            }
            let mut j = i + 1;
            while j < chars.len() && chars[j] != close {
                j += 1;
            }
            out.extend(&chars[i..(j + 1).min(chars.len())]);
            i = j + 1;
            continue;
        }
        if c == '$' && matches!(dialect, Dialect::Postgres | Dialect::Generic) {
            if let Some(tag) = dollar_tag(&chars, i) {
                let tag_chars: Vec<char> = tag.chars().collect();
                let start = i + tag_chars.len();
                let mut j = start;
                while j < chars.len() && !starts_with_at(&chars, j, &tag_chars) {
                    j += 1;
                }
                let end = (j + tag_chars.len()).min(chars.len());
                lits.push(Literal {
                    start: i,
                    end,
                    content: chars[start..j.min(chars.len())].iter().collect(),
                });
                out.push_str("''");
                i = j + tag_chars.len();
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    (out, lits)
}

fn format_spec_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"%(?:\d+\$)?-?\d*([IsL%])").unwrap())
}

/// `format()` placeholders as the values they stand for: `%I` / `%s` (an
/// identifier or any text) become a name, `%L` (a quoted literal) an empty
/// literal, so `format('TRUNCATE %I', t)` reads as `TRUNCATE t`.
fn fill_format_specs(s: &str) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    format_spec_re()
        .replace_all(s, |c: &regex::Captures<'_>| match &c[1] {
            "L" => "''",
            "%" => "%",
            _ => "t",
        })
        .into_owned()
}

/// End of one operand of a `||` chain that starts at `pos`: the next `||`,
/// `,`, `;` or unbalanced `)` outside brackets and literals.
fn operand_end(chars: &[char], mut pos: usize, lits: &[Literal]) -> usize {
    let mut depth = 0i32;
    while pos < chars.len() {
        if let Some(l) = lits.iter().find(|l| l.start == pos) {
            pos = l.end.max(pos + 1);
            continue;
        }
        match chars[pos] {
            '(' | '[' => depth += 1,
            ')' | ']' | ',' | ';' if depth == 0 => return pos,
            ')' | ']' => depth -= 1,
            '|' if depth == 0 && chars.get(pos + 1) == Some(&'|') => return pos,
            _ => {}
        }
        pos += 1;
    }
    pos
}

const fn skip_ws(chars: &[char], mut pos: usize) -> usize {
    while pos < chars.len() && chars[pos].is_whitespace() {
        pos += 1;
    }
    pos
}

/// The SQL texts a dynamic statement (`EXECUTE`, `DO`, `PREPARE ... FROM`)
/// can build from its string literals.
///
/// Literals joined with `||` are joined, with a name standing in for every
/// expression between them (`'DELETE FROM ' || quote_ident(t)` reads as
/// `DELETE FROM t`, and `... || ' WHERE id = ' || id` keeps its WHERE), and
/// `format()` placeholders are filled in ([`fill_format_specs`]).
fn dynamic_strings(stmt: &str, dialect: Dialect) -> Vec<String> {
    let chars: Vec<char> = stmt.chars().collect();
    let (_, lits) = scan_literals(stmt, dialect);
    let mut out = Vec::new();
    let mut used = vec![false; lits.len()];
    for k in 0..lits.len() {
        if used[k] {
            continue;
        }
        used[k] = true;
        let mut text = lits[k].content.clone();
        let mut pos = lits[k].end;
        loop {
            let p = skip_ws(&chars, pos);
            if !(chars.get(p) == Some(&'|') && chars.get(p + 1) == Some(&'|')) {
                break;
            }
            let p = skip_ws(&chars, p + 2);
            if let Some(n) = lits.iter().position(|l| l.start == p) {
                used[n] = true;
                text.push_str(&lits[n].content);
                pos = lits[n].end;
            } else {
                let end = operand_end(&chars, p, &lits);
                if end == p {
                    break;
                }
                text.push('t');
                pos = end;
            }
        }
        out.push(fill_format_specs(&text));
    }
    out
}

fn dynamic_sql_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)^\s*(?:DO|PREPARE)\b|\b(?:EXECUTE|EXEC|dblink_exec|dblink|sp_executesql|query_to_xml)\b",
        )
        .unwrap()
    })
}

fn block_prefix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?is)^\s*(?:DECLARE\b.*?\bBEGIN\b|BEGIN\b(?:\s+ATOMIC\b)?|ATOMIC\b)\s*")
            .unwrap()
    })
}

fn explain_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?is)^\s*EXPLAIN\s+(?:\((?P<opts>[^)]*)\)\s*|(?P<an>ANALY[SZ]E)\s+(?:VERBOSE\s+)?)(?P<rest>.+)$",
        )
        .unwrap()
    })
}

fn paren_dml_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\(\s*(?:DELETE|UPDATE|MERGE)\b").unwrap())
}

/// Bodies of parenthesised data-modifying statements (`WITH d AS (DELETE
/// FROM users RETURNING *) SELECT ...`) in a statement whose literals are
/// masked.
fn paren_dml_bodies(masked: &str) -> Vec<String> {
    let mut out = Vec::new();
    for m in paren_dml_re().find_iter(masked) {
        let body = &masked[m.start() + 1..];
        let mut depth = 1i32;
        let mut end = body.len();
        for (k, c) in body.char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = k;
                        break;
                    }
                }
                _ => {}
            }
        }
        out.push(body[..end].to_string());
    }
    out
}

/// After optional whitespace at `pos`, the keyword `kw` (any case, as a
/// whole word): the position just after it.
fn keyword_at(s: &str, pos: usize, kw: &str) -> Option<usize> {
    let start = pos + s.get(pos..)?.len() - s.get(pos..)?.trim_start().len();
    let end = start + kw.len();
    let word = s.get(start..end)?;
    let boundary = s[end..]
        .chars()
        .next()
        .is_none_or(|c| !(c.is_alphanumeric() || c == '_' || c == '$'));
    (word.eq_ignore_ascii_case(kw) && boundary).then_some(end)
}

/// After optional whitespace at `pos`, a balanced `( ... )` (literals are
/// masked): the position just after its `)`.
fn paren_group_at(s: &str, pos: usize) -> Option<usize> {
    let rest = s.get(pos..)?;
    let start = pos + rest.len() - rest.trim_start().len();
    if !s[start..].starts_with('(') {
        return None;
    }
    let mut depth = 0i32;
    for (k, c) in s[start..].char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(start + k + 1);
                }
            }
            _ => {}
        }
    }
    None
}

/// After optional whitespace at `pos`, a name (`users`, `"Old Rows"`,
/// `` `t` ``): the position just after it.
fn name_at(s: &str, pos: usize) -> Option<usize> {
    let rest = s.get(pos..)?;
    let start = pos + rest.len() - rest.trim_start().len();
    let mut chars = s[start..].char_indices();
    let (_, first) = chars.next()?;
    if matches!(first, '"' | '`') {
        return s[start + 1..]
            .find(first)
            .map(|k| start + 1 + k + first.len_utf8());
    }
    let word = |c: char| c.is_alphanumeric() || c == '_' || c == '$';
    if !word(first) {
        return None;
    }
    let len = s[start..]
        .find(|c: char| !word(c))
        .unwrap_or(s.len() - start);
    Some(start + len)
}

/// The statement a `WITH` clause leads into: `WITH x AS (SELECT 1) DELETE
/// FROM users` → `DELETE FROM users`.
///
/// Skips `WITH [RECURSIVE] name [(cols)] AS [NOT] [MATERIALIZED] (...)
/// [SEARCH ... | CYCLE ...] [, ...]` on a statement whose literals are
/// masked, so the main statement is judged on its own (its WHERE, not the
/// one of a CTE's inner SELECT). `None` when `masked` has no well-formed
/// leading `WITH` clause.
fn cte_main_statement(masked: &str) -> Option<&str> {
    const MAIN: &[&str] = &[
        "SELECT", "INSERT", "UPDATE", "DELETE", "MERGE", "VALUES", "TABLE", "REPLACE",
    ];
    let mut pos = keyword_at(masked, 0, "WITH")?;
    pos = keyword_at(masked, pos, "RECURSIVE").unwrap_or(pos);
    loop {
        pos = name_at(masked, pos)?;
        pos = paren_group_at(masked, pos).unwrap_or(pos);
        pos = keyword_at(masked, pos, "AS")?;
        pos = keyword_at(masked, pos, "NOT").unwrap_or(pos);
        pos = keyword_at(masked, pos, "MATERIALIZED").unwrap_or(pos);
        pos = paren_group_at(masked, pos)?;
        // `SEARCH ... SET col` / `CYCLE ... USING path` clauses, up to the
        // next CTE or the main statement.
        loop {
            let rest = masked.get(pos..)?;
            let at = pos + rest.len() - rest.trim_start().len();
            let tail = &masked[at..];
            if tail.is_empty() {
                return None;
            }
            if let Some(after) = tail.strip_prefix(',') {
                pos = masked.len() - after.len();
                break;
            }
            if MAIN.iter().any(|kw| keyword_at(masked, at, kw).is_some()) {
                return Some(tail);
            }
            pos = paren_group_at(masked, at)
                .or_else(|| name_at(masked, at))
                .unwrap_or_else(|| at + tail.chars().next().map_or(1, char::len_utf8));
        }
    }
}

fn prepare_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?is)^\s*PREPARE\s+\w+\s*(?:\([^)]*\))?\s+AS\s+(?P<rest>.+)$").unwrap()
    })
}

/// Texts to run the checks on for one statement.
///
/// The statement with string literals masked comes first, then statements
/// it really executes (`EXPLAIN ANALYZE <stmt>`, `PREPARE x AS <stmt>`, SQL
/// inside `DO` blocks and `EXECUTE '...'` strings).
#[must_use]
pub fn statement_candidates(stmt: &str, dialect: Dialect) -> Vec<String> {
    let mut out = Vec::new();
    collect_candidates(stmt, dialect, 0, &mut out);
    out.dedup();
    out
}

fn collect_candidates(stmt: &str, dialect: Dialect, depth: u8, out: &mut Vec<String>) {
    let masked = normalize_ws(&mask_literals(stmt, dialect));
    if masked.is_empty() {
        return;
    }
    out.push(masked.clone());
    if depth > 2 || !dialect.is_sql() {
        return;
    }
    if let Some(c) = explain_re().captures(stmt) {
        let analyze = c.name("an").is_some()
            || c.name("opts").is_some_and(|o| {
                let o = o.as_str().to_ascii_lowercase();
                o.contains("analy")
                    && !o.contains("analyze false")
                    && !o.contains("analyze off")
                    && !o.contains("analyse false")
                    && !o.contains("analyse off")
            });
        if analyze {
            collect_candidates(&c["rest"], dialect, depth + 1, out);
        }
    }
    if let Some(c) = prepare_re().captures(stmt) {
        collect_candidates(&c["rest"], dialect, depth + 1, out);
    }
    for body in paren_dml_bodies(&masked) {
        collect_candidates(&body, dialect, depth + 1, out);
    }
    if let Some(main) = cte_main_statement(&masked) {
        collect_candidates(main, dialect, depth + 1, out);
    }
    if dynamic_sql_re().is_match(&masked) {
        for lit in dynamic_strings(stmt, dialect) {
            let split = split_statements(&lit, ";", dialect);
            let mut parts = split.statements;
            let rest = normalize_ws(&split.remainder);
            if !rest.is_empty() {
                parts.push(rest);
            }
            for p in parts {
                let p = block_prefix_re().replace(&p, "").to_string();
                if !p.trim().is_empty() && !p.trim().eq_ignore_ascii_case("END") {
                    collect_candidates(&p, dialect, depth + 1, out);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Prompt recognition
// ---------------------------------------------------------------------------

/// What a recognised prompt says about the client's query buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptKind {
    /// Empty query buffer (`postgres=# `, `mysql> `, `sqlite> `, `test> `).
    Primary,
    /// The buffer continues a statement (`postgres-# `, `    -> `).
    Continuation,
    /// The buffer is inside a string or comment (`postgres'# `, `    '> `).
    InLiteral,
}

fn prompt_regexes(dialect: Dialect) -> &'static [(Regex, PromptKind)] {
    static PG: OnceLock<Vec<(Regex, PromptKind)>> = OnceLock::new();
    static MY: OnceLock<Vec<(Regex, PromptKind)>> = OnceLock::new();
    static LITE: OnceLock<Vec<(Regex, PromptKind)>> = OnceLock::new();
    static JS: OnceLock<Vec<(Regex, PromptKind)>> = OnceLock::new();
    let build = |v: &[(&str, PromptKind)]| -> Vec<(Regex, PromptKind)> {
        v.iter()
            .map(|(r, k)| (Regex::new(r).unwrap(), *k))
            .collect()
    };
    match dialect {
        Dialect::Postgres => PG.get_or_init(|| {
            build(&[
                (r"^\S*?=[*!?]?[#>] ", PromptKind::Primary),
                (r"^\S*?[^=\s]['\x22$*][*!?]?[#>] ", PromptKind::InLiteral),
                (r"^\S*?[-(][*!?]?[#>] ", PromptKind::Continuation),
            ])
        }),
        Dialect::MySql => MY.get_or_init(|| {
            build(&[
                (r"^(?:mysql|MariaDB(?: \[[^\]]*\])?)> ", PromptKind::Primary),
                (r"^\s*(?:['\x22`]|/\*)> ", PromptKind::InLiteral),
                (r"^\s*-> ", PromptKind::Continuation),
            ])
        }),
        Dialect::Sqlite => LITE.get_or_init(|| {
            build(&[
                (r"^(?:sqlite|D)> ", PromptKind::Primary),
                (r"^\s*\.\.\.> ", PromptKind::Continuation),
            ])
        }),
        Dialect::JavaScript => JS.get_or_init(|| {
            build(&[
                (r"^\.\.\. ", PromptKind::Continuation),
                (r"^(?:\S.*? )?[\w.\-]+> ", PromptKind::Primary),
            ])
        }),
        Dialect::SqlServer | Dialect::Generic => &[],
    }
}

/// Recognise a client prompt at the start of `row`; returns its kind and
/// its length in chars.
#[must_use]
pub fn match_prompt(dialect: Dialect, row: &str) -> Option<(PromptKind, usize)> {
    prompt_regexes(dialect).iter().find_map(|(re, kind)| {
        re.find(row)
            .map(|m| (*kind, row[..m.end()].chars().count()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pg(s: &str) -> Split {
        split_statements(s, ";", Dialect::Postgres)
    }

    #[test]
    fn basic_and_remainder() {
        let s = pg("SELECT 1; DROP TABLE x; UPDATE");
        assert_eq!(s.statements, vec!["SELECT 1", "DROP TABLE x"]);
        assert_eq!(s.remainder, " UPDATE");
    }

    #[test]
    fn quotes_and_comments() {
        let s = pg("INSERT INTO t VALUES (';'); DROP /* x; */ TABLE users; -- c;\nSELECT 2;");
        assert_eq!(
            s.statements,
            vec!["INSERT INTO t VALUES (';')", "DROP TABLE users", "SELECT 2"]
        );
        assert!(s.remainder.is_empty());
    }

    #[test]
    fn psql_dollar_quotes_and_standard_strings() {
        let s = pg("COMMENT ON TABLE users IS $$Don't touch$$; DROP TABLE users;");
        assert_eq!(s.statements.len(), 2);
        assert_eq!(s.statements[1], "DROP TABLE users");
        let s = pg("SELECT $fn$ a; 'b $fn$; DROP TABLE x;");
        assert_eq!(s.statements[1], "DROP TABLE x");
        let s = pg(r"UPDATE s SET p = 'C:\backups\' WHERE id = 1; DROP TABLE users;");
        assert_eq!(s.statements[1], "DROP TABLE users");
        let s = pg(r"SELECT E'it\'s'; DROP TABLE users;");
        assert_eq!(s.statements[1], "DROP TABLE users");
        let s = pg("SELECT 'it''s'; DROP TABLE users;");
        assert_eq!(s.statements[1], "DROP TABLE users");
        let s = pg("SELECT $1; DROP TABLE users;");
        assert_eq!(s.statements[1], "DROP TABLE users");
        let s = pg("/* a /* nested; */ still; */ DROP TABLE users;");
        assert_eq!(s.statements, vec!["DROP TABLE users"]);
        let s = pg("SELECT $$ open");
        assert!(s.in_literal);
    }

    #[test]
    fn psql_meta_commands() {
        let s = pg("TRUNCATE TABLE orders \\g out.txt");
        assert_eq!(s.statements, vec!["TRUNCATE TABLE orders"]);
        assert!(s.remainder.trim().is_empty());
        let s = pg("\\i cleanup.sql");
        assert_eq!(
            s.metas[0].kind,
            MetaKind::RunFile {
                path: "cleanup.sql".into(),
                relative: false,
            }
        );
        assert!(s.remainder.is_empty());
        let s = pg("\\ir sub/b.sql");
        assert_eq!(
            s.metas[0].kind,
            MetaKind::RunFile {
                path: "sub/b.sql".into(),
                relative: true,
            }
        );
        let s = pg("\\! rm -rf /tmp/x");
        assert_eq!(
            s.metas[0].kind,
            MetaKind::Shell {
                command: "rm -rf /tmp/x".into()
            }
        );
        let s = pg("SELECT 'DROP TABLE ' || name FROM t \\gexec");
        assert_eq!(s.statements.len(), 1);
        assert!(matches!(
            s.metas[0].kind,
            MetaKind::Opaque {
                id: "wrap:psql_gexec",
                ..
            }
        ));
        // `\w |cmd` pipes the query buffer to a shell command
        let s = pg("\\w |rm -rf /tmp/x");
        assert_eq!(
            s.metas[0].kind,
            MetaKind::Shell {
                command: "rm -rf /tmp/x".into()
            }
        );
        assert!(pg("\\w out.sql").metas.is_empty());
        let s = pg("\\set cleanup 'DROP TABLE users'");
        assert_eq!(s.vars, vec![("cleanup".into(), "DROP TABLE users".into())]);
        let s = pg("DELETE FROM x\n\\r\nSELECT 1;");
        assert_eq!(s.statements, vec!["SELECT 1"]);
        let s = pg("\\e");
        assert!(matches!(
            s.metas[0].kind,
            MetaKind::Opaque {
                id: "wrap:editor",
                ..
            }
        ));
    }

    #[test]
    fn mysql_lexer() {
        let my = |s: &str| split_statements(s, ";", Dialect::MySql);
        let s = my("SELECT 1 # it's fine\n;\nDROP TABLE users;");
        assert_eq!(s.statements, vec!["SELECT 1", "DROP TABLE users"]);
        let s = my(r"SELECT 'it\'s'; DROP TABLE users;");
        assert_eq!(s.statements[1], "DROP TABLE users");
        let s = my("SELECT 1--1;");
        assert_eq!(s.statements, vec!["SELECT 1--1"]);
        let s = my("/*!40101 DROP TABLE users */;");
        assert_eq!(s.statements, vec!["DROP TABLE users"]);
        let s = split_statements(
            "CREATE PROCEDURE p() BEGIN DELETE FROM a; END//",
            "//",
            Dialect::MySql,
        );
        assert_eq!(
            s.statements,
            vec!["CREATE PROCEDURE p() BEGIN DELETE FROM a; END"]
        );
        let s = my("\\. /tmp/x.sql");
        assert!(matches!(s.metas[0].kind, MetaKind::RunFile { .. }));
        let s = my("\\d //");
        assert_eq!(s.delimiter.as_deref(), Some("//"));
    }

    #[test]
    fn javascript_lexer() {
        let js = |s: &str| split_statements(s, ";", Dialect::JavaScript);
        let s = js("db.users.find({name: /^[(]/})");
        assert!(s.remainder_balanced);
        let s = js("db.users.find({n: `a ${ \"(\" } )`})");
        assert!(s.remainder_balanced);
        let s = js("db.users.deleteMany({");
        assert!(!s.remainder_balanced);
        let s = js("x = a / b; db.dropDatabase()");
        assert_eq!(s.statements, vec!["x = a / b"]);
        assert!(s.remainder_balanced);
    }

    #[test]
    fn literal_masking_and_candidates() {
        assert_eq!(
            mask_literals(
                "INSERT INTO audit VALUES ('DELETE FROM users')",
                Dialect::Postgres
            ),
            "INSERT INTO audit VALUES ('')"
        );
        assert_eq!(
            mask_literals("DELETE FROM \"users\"", Dialect::Postgres),
            "DELETE FROM \"users\""
        );
        let c = statement_candidates("EXPLAIN ANALYZE DELETE FROM users", Dialect::Postgres);
        assert!(c.contains(&"DELETE FROM users".to_string()));
        let c = statement_candidates("EXPLAIN DELETE FROM users", Dialect::Postgres);
        assert_eq!(c.len(), 1);
        let c = statement_candidates("PREPARE p AS DELETE FROM users", Dialect::Postgres);
        assert!(c.contains(&"DELETE FROM users".to_string()));
        let c = statement_candidates(
            "DO $$ BEGIN EXECUTE 'DROP TABLE users'; END $$",
            Dialect::Postgres,
        );
        assert!(c.contains(&"DROP TABLE users".to_string()), "{c:?}");
        let c = statement_candidates(
            "WITH d AS (DELETE FROM users RETURNING *) SELECT count(*) FROM d",
            Dialect::Postgres,
        );
        assert!(
            c.contains(&"DELETE FROM users RETURNING *".to_string()),
            "{c:?}"
        );
        let c = statement_candidates(
            "DO 'BEGIN EXECUTE ''TRUNCATE orders''; END'",
            Dialect::Postgres,
        );
        assert!(c.contains(&"TRUNCATE orders".to_string()), "{c:?}");
    }

    #[test]
    fn leading_with_clauses_are_skipped() {
        // The statement after a WITH clause is a candidate.
        for (stmt, main) in [
            (
                "WITH x AS (SELECT 1) DELETE FROM users",
                "DELETE FROM users",
            ),
            (
                "WITH old AS (SELECT id FROM users WHERE id < 5) DELETE FROM users;",
                "DELETE FROM users;",
            ),
            (
                "with x as (select 1) update users set a = 1",
                "update users set a = 1",
            ),
            (
                "WITH RECURSIVE t(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM t), \
                 \"Y z\" AS NOT MATERIALIZED (SELECT ')' AS p) DELETE FROM users",
                "DELETE FROM users",
            ),
            (
                "WITH RECURSIVE t(id, p) AS (SELECT 1, 0) CYCLE id SET is_cycle USING path, \
                 u AS MATERIALIZED (SELECT 2) UPDATE users SET a = 1",
                "UPDATE users SET a = 1",
            ),
            (
                "WITH s AS (SELECT id FROM t) DELETE FROM users USING s WHERE users.id = s.id",
                "DELETE FROM users USING s WHERE users.id = s.id",
            ),
        ] {
            let masked = normalize_ws(&mask_literals(stmt, Dialect::Postgres));
            assert_eq!(cte_main_statement(&masked), Some(main), "{stmt}");
            let c = statement_candidates(stmt, Dialect::Postgres);
            assert!(c.iter().any(|x| x == main), "{stmt}: {c:?}");
        }
        for stmt in [
            "SELECT 1",
            "WITH",
            "WITH x AS (SELECT 1",
            "WITH x SELECT 1",
            "WITHOUT x AS (SELECT 1) DELETE FROM users",
        ] {
            assert_eq!(cte_main_statement(stmt), None, "{stmt}");
        }
    }

    #[test]
    fn dynamic_strings_join_concatenation_and_fill_format() {
        let d = Dialect::Postgres;
        assert_eq!(
            dynamic_strings("EXECUTE 'TRUNCATE ' || quote_ident(t) || ' CASCADE'", d),
            vec!["TRUNCATE t CASCADE".to_string()]
        );
        assert_eq!(
            dynamic_strings("EXECUTE format($f$DROP TABLE %I CASCADE$f$, r.t)", d),
            vec!["DROP TABLE t CASCADE".to_string()]
        );
        assert_eq!(
            dynamic_strings("EXECUTE format('DELETE FROM %I WHERE id = %L', t, 1)", d),
            vec!["DELETE FROM t WHERE id = ''".to_string()]
        );
        assert_eq!(
            dynamic_strings("EXECUTE 'a' || f(x, 'b') || 'c'", d),
            vec!["atc".to_string(), "b".to_string()]
        );
        assert_eq!(dynamic_strings("EXECUTE 'x' ||", d), vec!["x".to_string()]);
        // JS object keys are not masked; values are.
        assert_eq!(
            mask_literals(
                "db.runCommand({\"dropDatabase\": 1, x: \"y\"})",
                Dialect::JavaScript
            ),
            "db.runCommand({\"dropDatabase\": 1, x: \"\"})"
        );
        assert_eq!(
            mask_literals("f(a ? \"k\" : \"v\")", Dialect::JavaScript),
            "f(a ? \"\" : \"\")"
        );
    }

    #[test]
    fn stream_splitter_matches_one_shot_split() {
        let text =
            "SELECT 1;\nINSERT INTO t VALUES ('a;\nb');\nDROP /* x;\n */ TABLE users;\nUPDATE";
        let one = split_statements(text, ";", Dialect::Postgres);
        let mut st = StreamSplitter::new(";", Dialect::Postgres);
        let mut stmts = Vec::new();
        for line in text.lines() {
            st.feed(line);
            st.feed("\n");
            stmts.extend(st.take().statements);
        }
        assert_eq!(stmts, one.statements);
        assert!(st.has_pending());
        st.flush();
        assert_eq!(st.take().statements, vec!["UPDATE"]);
        assert!(!st.has_pending());
        st.feed("-- only a comment\n");
        assert!(!st.has_pending());
        st.feed("/* open\n");
        assert!(st.has_pending());
    }

    #[test]
    fn prompts() {
        assert_eq!(
            match_prompt(Dialect::Postgres, "postgres=# x"),
            Some((PromptKind::Primary, 11))
        );
        assert_eq!(
            match_prompt(Dialect::Postgres, "postgres=*# "),
            Some((PromptKind::Primary, 12))
        );
        assert_eq!(
            match_prompt(Dialect::Postgres, "my-db-# "),
            Some((PromptKind::Continuation, 8))
        );
        assert_eq!(
            match_prompt(Dialect::Postgres, "postgres$# "),
            Some((PromptKind::InLiteral, 11))
        );
        assert_eq!(
            match_prompt(Dialect::MySql, "    -> "),
            Some((PromptKind::Continuation, 7))
        );
        assert_eq!(
            match_prompt(Dialect::MySql, "mysql> use x"),
            Some((PromptKind::Primary, 7))
        );
        assert_eq!(
            match_prompt(Dialect::JavaScript, "test> db"),
            Some((PromptKind::Primary, 6))
        );
        assert_eq!(match_prompt(Dialect::Postgres, " id | name"), None);
    }
}
