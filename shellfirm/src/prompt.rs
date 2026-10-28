//! Challenge prompts and the [`Prompter`] trait for testability.
//!
//! Prompters never block forever and never call `process::exit`: a denied
//! command, a cancelled challenge and a missing terminal all return
//! [`ChallengeResult::Denied`] so the caller can log the outcome once and
//! choose the exit code.

use std::{cell::RefCell, fmt::Write as _, io::IsTerminal};

use console::style;
use rand::RngExt;

use crate::config::Challenge;

/// wrong answer text show when user solve the challenge incorrectly
const WRONG_ANSWER: &str = "wrong answer, try again...";
/// show math challenge text
const SOLVE_MATH_TEXT: &str = "Solve the challenge:";
/// show enter challenge text
const SOLVE_ENTER_TEXT: &str = "Press Enter to continue";
/// show yes challenge text
const SOLVE_YES_TEXT: &str = "Type `yes` to continue";
/// show to the user how can he cancel the command
const CANCEL_PROMPT_TEXT: &str = "Esc to cancel";
/// Cancel hint for the direct-tty prompter (Esc and Ctrl-C both work).
#[cfg(unix)]
const DIRECT_CANCEL_TEXT: &str = "Esc or Ctrl-C to cancel";

// ---------------------------------------------------------------------------
// ChallengeResult + DisplayContext
// ---------------------------------------------------------------------------

/// The outcome of a challenge prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeResult {
    /// User solved the challenge — command proceeds.
    Passed,
    /// The command must not run: it is denied (deny list / policy), the
    /// user cancelled or failed the challenge, or no terminal was available
    /// to ask. Prompters return immediately; they never block.
    Denied,
}

/// Information shown to the user when a risky command is detected.
/// Used by `MockPrompter` to capture what *would* be displayed.
#[derive(Debug, Clone, Default)]
pub struct DisplayContext {
    pub is_denied: bool,
    pub descriptions: Vec<String>,
    pub alternatives: Vec<AlternativeInfo>,
    pub context_labels: Vec<String>,
    pub effective_challenge: Challenge,
    /// Set only when the challenge actually got stricter than the base,
    /// e.g. "Escalated to Yes (from Math): protected branch `main`".
    pub escalation_note: Option<String>,
    /// The highest severity among the matched checks.
    pub severity_label: Option<String>,
    /// Blast radius label, e.g. `[PROJECT] — Deletes 347 files (12.4 MB) in ./src`.
    pub blast_radius_label: Option<String>,
    /// IDs of the matched checks (shown so users know what to ignore/allow).
    pub check_ids: Vec<String>,
    /// The user's configured challenge before escalation.
    pub base_challenge: Challenge,
    /// Why the challenge was escalated (empty when it was not).
    pub escalation_reasons: Vec<String>,
    /// Why the command is denied (empty when it is not).
    pub deny_reasons: Vec<String>,
    /// The command being checked (shown, escaped and truncated, so the user
    /// always sees what the challenge applies to).
    pub command: Option<String>,
    /// Each matched check (id, severity, description), so several matches
    /// can be shown one line per check instead of unlabelled duplicates.
    pub matched: Vec<MatchedCheck>,
    /// The "stop asking" hint, or `None` when ignoring is not advisable
    /// (Critical severity, production/root context, denied commands).
    pub ignore_hint: Option<String>,
    /// How to allow a denied command again (personal deny list vs. the
    /// policy file that denies it). `None` uses the personal-deny wording.
    pub deny_hint: Option<String>,
    /// Extra notes shown under the escalation line (e.g. a context
    /// escalation configured below its default).
    pub notes: Vec<String>,
}

/// One matched check, as shown in the banner.
#[derive(Debug, Clone, Default)]
pub struct MatchedCheck {
    pub id: String,
    pub severity: String,
    pub description: String,
}

/// A safer-alternative suggestion.
#[derive(Debug, Clone)]
pub struct AlternativeInfo {
    pub suggestion: String,
    pub explanation: Option<String>,
}

// ---------------------------------------------------------------------------
// Prompter trait
// ---------------------------------------------------------------------------

/// Abstracts user interaction so tests can inject mock responses.
pub trait Prompter {
    /// Display warnings and run a challenge. Returns the outcome.
    fn run_challenge(&self, display: &DisplayContext) -> ChallengeResult;

    /// Whether this prompter can currently ask a human anything (i.e. a
    /// terminal is available). Callers use this to fail closed with a clear
    /// message instead of attempting a prompt. Defaults to `true`.
    fn can_prompt(&self) -> bool {
        true
    }

    /// Called after a passed challenge (when the `approved_notice` setting
    /// is on) to say the command is now running. The terminal prompters
    /// print [`approved_line`]; the default does nothing.
    fn announce_approved(&self, _command: &str) {}
}

// ---------------------------------------------------------------------------
// Shared banner display
// ---------------------------------------------------------------------------

/// Render the warning banner. `color` enables ANSI styling.
#[must_use]
pub fn render_banner(display: &DisplayContext, color: bool) -> String {
    render_banner_width(display, color, terminal_width())
}

/// Width used to lay out the banner and the approved line.
///
/// The terminal width of stderr, else of the controlling terminal
/// (`/dev/tty`, for a shell hook whose stderr is not the terminal), else
/// `$COLUMNS`, else 80. Never below 20.
#[must_use]
pub fn terminal_width() -> usize {
    let w = console::Term::stderr()
        .size_checked()
        .map(|(_, cols)| usize::from(cols))
        .or_else(tty_columns)
        .or_else(|| std::env::var("COLUMNS").ok().and_then(|c| c.parse().ok()))
        .unwrap_or(80);
    w.max(20)
}

/// The column count of the controlling terminal, if there is one.
#[cfg(unix)]
fn tty_columns() -> Option<usize> {
    use std::os::fd::AsRawFd as _;
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .open("/dev/tty")
        .ok()?;
    // SAFETY: `winsize` is plain old data; all-zero is a valid value.
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: TIOCGWINSZ writes one `winsize` through the pointer, which
    // points at a live, correctly typed value; the descriptor is open.
    let rc = unsafe { libc::ioctl(tty.as_raw_fd(), libc::TIOCGWINSZ, &mut ws) };
    (rc == 0 && ws.ws_col > 0).then(|| usize::from(ws.ws_col))
}

#[cfg(not(unix))]
const fn tty_columns() -> Option<usize> {
    None
}

/// Longest command text shown on the `Command:` line(s).
const MAX_COMMAND_CHARS: usize = 200;

/// Most lines of a multi-line command shown in the banner.
const MAX_COMMAND_LINES: usize = 8;

/// The command as shown in the banner.
///
/// Invisible / control characters are escaped, at most 200 characters are
/// shown. A multi-line command (a pasted block)
/// keeps its line breaks (`\n` between the lines, blank lines dropped), at
/// most 8 lines and then `(+N more lines)`, so every line is readable.
#[must_use]
pub fn display_command(command: &str) -> String {
    let lines: Vec<String> = command
        .trim()
        .lines()
        .map(|l| {
            l.trim_end()
                .chars()
                .map(|c| if matches!(c, '\r' | '\t') { ' ' } else { c })
                .collect::<String>()
        })
        .filter(|l| !l.trim().is_empty())
        .collect();
    let mut out: Vec<String> = Vec::new();
    let mut used = 0usize;
    let cut = crate::config::glyph("…", "...");
    for (i, line) in lines.iter().enumerate() {
        let escaped = crate::context::escape_invisible(line);
        let n = escaped.chars().count();
        if i >= MAX_COMMAND_LINES || used + n > MAX_COMMAND_CHARS {
            let room = MAX_COMMAND_CHARS.saturating_sub(used);
            if i < MAX_COMMAND_LINES && room > 1 {
                let head: String = escaped.chars().take(room - 1).collect();
                out.push(format!("{head}{cut}"));
            }
            let left = lines.len() - i - usize::from(i < MAX_COMMAND_LINES && room > 1);
            if left > 0 {
                out.push(match left {
                    1 => "(+1 more line)".to_string(),
                    n => format!("(+{n} more lines)"),
                });
            }
            break;
        }
        used += n;
        out.push(escaped);
    }
    out.join("\n")
}

/// Display width of one character in a terminal: 0 for combining marks and
/// zero-width characters, 2 for East Asian wide / full-width characters and
/// emoji, else 1.
#[must_use]
pub const fn char_columns(c: char) -> usize {
    match c as u32 {
        0x0300..=0x036F
        | 0x0483..=0x0489
        | 0x0591..=0x05BD
        | 0x0610..=0x061A
        | 0x064B..=0x065F
        | 0x0E31
        | 0x0E34..=0x0E3A
        | 0x200B..=0x200F
        | 0x20D0..=0x20FF
        | 0xFE00..=0xFE0F
        | 0xFE20..=0xFE2F => 0,
        0x1100..=0x115F
        | 0x231A..=0x231B
        | 0x2329..=0x232A
        | 0x23E9..=0x23EC
        | 0x2614..=0x2615
        | 0x2648..=0x2653
        | 0x26A1
        | 0x26AA..=0x26AB
        | 0x26BD..=0x26BE
        | 0x26C4..=0x26C5
        | 0x26D4
        | 0x26EA
        | 0x26F2..=0x26F5
        | 0x26FA
        | 0x26FD
        | 0x2705
        | 0x270A..=0x270B
        | 0x274C
        | 0x2753..=0x2755
        | 0x2757
        | 0x2795..=0x2797
        | 0x2B1B..=0x2B1C
        | 0x2B50
        | 0x2B55
        | 0x2E80..=0x303E
        | 0x3041..=0x33FF
        | 0x3400..=0x4DBF
        | 0x4E00..=0x9FFF
        | 0xA000..=0xA4CF
        | 0xA960..=0xA97F
        | 0xAC00..=0xD7A3
        | 0xF900..=0xFAFF
        | 0xFE10..=0xFE19
        | 0xFE30..=0xFE6F
        | 0xFF00..=0xFF60
        | 0xFFE0..=0xFFE6
        | 0x1F300..=0x1F64F
        | 0x1F680..=0x1F6FF
        | 0x1F900..=0x1F9FF
        | 0x1FA70..=0x1FAFF
        | 0x20000..=0x3FFFD => 2,
        _ => 1,
    }
}

/// Display width of `s` in terminal columns (see [`char_columns`]).
#[must_use]
pub fn display_width(s: &str) -> usize {
    s.chars().map(char_columns).sum()
}

/// The longest prefix of `chars` that fits `cols` columns.
fn fit_head(chars: &[char], cols: usize) -> usize {
    let mut w = 0;
    for (i, c) in chars.iter().enumerate() {
        w += char_columns(*c);
        if w > cols {
            return i;
        }
    }
    chars.len()
}

/// The line printed after a passed challenge.
///
/// A slow command (a `helm uninstall` that prints only at the end) then
/// does not look hung: `✓ approved — running: helm uninstall web`, or in
/// plain ASCII (`unicode == false`) `ok: approved, running: helm uninstall
/// web`. The line fits `width` columns:
/// - a multi-line command shows its first line and ` (+N lines)`;
/// - invisible / control characters are escaped, as in the banner;
/// - a command that does not fit is cut in the middle (`…` / `...`), so its
///   start and its (often risky) end both stay visible. `…` appears only
///   when something was cut.
#[must_use]
pub fn approved_line(command: &str, unicode: bool, width: usize) -> String {
    let (prefix, cut) = if unicode {
        ("✓ approved — running: ", "…")
    } else {
        ("ok: approved, running: ", "...")
    };
    let lines: Vec<&str> = command
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let first = lines.first().copied().unwrap_or("");
    let more = lines.len().saturating_sub(1);
    let suffix = match more {
        0 => String::new(),
        1 => " (+1 line)".to_string(),
        n => format!(" (+{n} lines)"),
    };
    let first = collapse_blanks(first);
    let shown: Vec<char> = crate::context::escape_invisible(&first).chars().collect();
    // One column spare: a line that ends in the last column makes some
    // terminals wrap. Widths are display columns (CJK and emoji take two).
    let room = width
        .saturating_sub(display_width(prefix) + display_width(&suffix) + 1)
        .max(12);
    let text: String = if shown.iter().map(|c| char_columns(*c)).sum::<usize>() <= room {
        shown.iter().collect()
    } else {
        let keep = room - display_width(cut);
        let head_cols = keep * 2 / 5;
        let tail_cols = keep - head_cols;
        let head = fit_head(&shown, head_cols);
        let rev: Vec<char> = shown.iter().rev().copied().collect();
        let tail = fit_head(&rev, tail_cols).min(shown.len() - head);
        let h: String = shown[..head].iter().collect();
        let t: String = shown[shown.len() - tail..].iter().collect();
        format!("{}{cut}{}", h.trim_end(), t.trim_start())
    };
    format!("{prefix}{text}{suffix}")
}

/// Runs of blanks outside quotes become one space (a `\`-continued line
/// joined by the shell keeps the next line's indentation: `a &&   b` is shown
/// as `a && b`, like the banner shows it). Quoted text is kept as written.
fn collapse_blanks(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for c in text.chars() {
        let c = if c == '\t' && quote.is_none() { ' ' } else { c };
        match quote {
            Some(q) if c == q && !(escaped && q == '"') => quote = None,
            None if !escaped && matches!(c, '\'' | '"') => quote = Some(c),
            None if c == ' ' && out.ends_with(' ') => continue,
            _ => {}
        }
        escaped = c == '\\' && !escaped;
        out.push(c);
    }
    out
}

/// Print [`approved_line`] (dim when colour is on) on the terminal.
///
/// It goes to the terminal the challenge was answered on: `/dev/tty` when
/// it can be opened, else stderr. Never stdout, so the command's own output
/// stays clean. Only the interactive shell hook calls this (not the agent
/// hooks or MCP).
pub fn announce_approved(command: &str) {
    use std::io::Write as _;
    let line = approved_line(command, crate::config::unicode_output(), terminal_width());
    let line = if console::colors_enabled_stderr() {
        format!("\x1b[2m{line}\x1b[0m")
    } else {
        line
    };
    #[cfg(unix)]
    if let Ok(mut tty) = direct::open_tty() {
        let _ = write!(tty, "{line}\r\n");
        let _ = tty.flush();
        return;
    }
    let mut err = std::io::stderr().lock();
    let _ = writeln!(err, "{line}");
    let _ = err.flush();
}

/// Split text into wrap units: words, except that a backtick-quoted span
/// (a command to copy, e.g. `shellfirm config ignore x`) stays one unit.
fn wrap_units(text: &str) -> Vec<String> {
    let mut units: Vec<String> = Vec::new();
    let mut open: Option<String> = None;
    for w in text.split(' ').filter(|w| !w.is_empty()) {
        if let Some(mut cur) = open.take() {
            cur.push(' ');
            cur.push_str(w);
            if w.contains('`') {
                units.push(cur);
            } else {
                open = Some(cur);
            }
        } else if w.matches('`').count() % 2 == 1 {
            open = Some(w.to_string());
        } else {
            units.push(w.to_string());
        }
    }
    units.extend(open);
    units
}

/// Word-wrap `text` so the first line fits `first` columns and the others
/// `rest` columns. Words longer than a line are split (only then).
fn wrap_words(text: &str, first: usize, rest: usize) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut cur_len = 0usize;
    let limit = |lines: &Vec<String>| if lines.is_empty() { first } else { rest }.max(8);
    for word in wrap_units(text) {
        let mut word = word;
        loop {
            let wlen = display_width(&word);
            let max = limit(&lines);
            let needed = if cur_len == 0 {
                wlen
            } else {
                cur_len + 1 + wlen
            };
            if needed <= max {
                if cur_len > 0 {
                    cur.push(' ');
                    cur_len += 1;
                }
                cur.push_str(&word);
                cur_len += wlen;
                break;
            }
            if cur_len > 0 {
                lines.push(std::mem::take(&mut cur));
                cur_len = 0;
                continue;
            }
            // A copy-paste command is never broken: let it overflow.
            if word.contains('`') {
                lines.push(std::mem::take(&mut word));
                break;
            }
            // A single word longer than the line: split it (by columns).
            let chars: Vec<char> = word.chars().collect();
            let n = fit_head(&chars, max).max(1);
            let head: String = chars[..n].iter().collect();
            word = chars[n..].iter().collect();
            lines.push(head);
            if word.is_empty() {
                break;
            }
        }
    }
    if cur_len > 0 || lines.is_empty() {
        lines.push(cur);
    }
    lines
}

/// Word-wrap a command's report (`doctor`, `status`, `check`).
///
/// For a terminal `width` columns wide, each line that does not fit is broken between words
/// (never inside one; a word longer than the line is left whole), and its
/// continuation lines are indented under the line's text (a hanging indent
/// past a leading `[x]` / `-` marker). Colour codes do not count as width.
#[must_use]
pub fn wrap_report(text: &str, width: usize) -> String {
    let width = width.max(20);
    let mut out: Vec<String> = Vec::new();
    for line in text.split('\n') {
        if console::measure_text_width(line) <= width {
            out.push(line.to_string());
            continue;
        }
        let body = line.trim_start_matches(' ');
        let indent = line.len() - body.len();
        // Continuation lines start under the text after a list marker.
        let marker = if body.starts_with('[') {
            body.find("] ").map_or(0, |i| i + 2)
        } else if body.starts_with("- ") || body.starts_with("* ") {
            2
        } else {
            0
        };
        let hang = (indent + marker.max(2)).min(width / 2);
        let mut cur = " ".repeat(indent);
        let mut cur_w = indent;
        let mut first_word = true;
        for word in body.split(' ') {
            let w = console::measure_text_width(word);
            if !first_word && !word.is_empty() && cur_w + 1 + w > width {
                out.push(std::mem::take(&mut cur).trim_end().to_string());
                cur = " ".repeat(hang);
                cur_w = hang;
                first_word = true;
            }
            if !first_word {
                cur.push(' ');
                cur_w += 1;
            }
            cur.push_str(word);
            cur_w += w;
            first_word = false;
        }
        out.push(cur);
    }
    out.join("\n")
}

/// [`wrap_report`] for stdout: wrapped to the terminal's width when stdout
/// is a terminal, unchanged when it is piped or redirected.
#[must_use]
pub fn wrap_for_stdout(text: &str) -> String {
    let term = console::Term::stdout();
    if !term.is_term() {
        return text.to_string();
    }
    match stdout_columns().or_else(|| term.size_checked().map(|(_, c)| usize::from(c))) {
        Some(cols) if cols > 0 => wrap_report(text, cols),
        _ => text.to_string(),
    }
}

/// The column count of the terminal on stdout (also when its row count is
/// not set, as in a pseudo-terminal sized with `stty cols N` only).
#[cfg(unix)]
fn stdout_columns() -> Option<usize> {
    // SAFETY: `winsize` is plain old data; all-zero is a valid value.
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: TIOCGWINSZ writes one `winsize` through the pointer, which
    // points at a live, correctly typed value; fd 1 is checked by the ioctl.
    let rc = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) };
    (rc == 0 && ws.ws_col > 0).then(|| usize::from(ws.ws_col))
}

#[cfg(not(unix))]
const fn stdout_columns() -> Option<usize> {
    None
}

/// Render the warning banner for a terminal `width` columns wide.
/// `color` enables ANSI styling.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn render_banner_width(display: &DisplayContext, color: bool, width: usize) -> String {
    let st = |s: &str| style(s.to_string()).force_styling(color);
    let mut out = String::new();
    let width = width.max(20);

    // `label value`, word-wrapped with a 2-space hanging indent.
    let field = |out: &mut String, label: &str, value: &str, styled: &dyn Fn(&str) -> String| {
        let first = width.saturating_sub(label.chars().count() + 1);
        let lines = wrap_words(value, first, width.saturating_sub(2));
        for (i, line) in lines.iter().enumerate() {
            if i == 0 {
                if label.is_empty() {
                    let _ = writeln!(out, "{}", styled(line));
                } else {
                    let _ = writeln!(out, "{} {}", st(label).bold(), styled(line));
                }
            } else {
                let _ = writeln!(out, "  {}", styled(line));
            }
        }
    };
    let plain = |s: &str| s.to_string();

    let title = if display.is_denied {
        " COMMAND DENIED "
    } else {
        " RISKY COMMAND DETECTED "
    };
    let pad = (width.min(48).saturating_sub(title.len())) / 2;
    let separator = "=".repeat(pad.max(2));
    let _ = writeln!(
        out,
        "{}",
        st(&format!("{separator}{title}{separator}")).red().bold()
    );

    if let Some(ref cmd) = display.command {
        // A multi-line command: its first line after `Command:`, every
        // other line indented below it.
        for (i, line) in display_command(cmd).split('\n').enumerate() {
            if i == 0 {
                field(&mut out, "Command:", line, &|s| st(s).bold().to_string());
            } else {
                for part in wrap_words(line, width.saturating_sub(2), width.saturating_sub(2)) {
                    let _ = writeln!(out, "  {}", st(&part).bold());
                }
            }
        }
    }

    // Matched checks: one line per check when there are several (id,
    // severity and description together), otherwise `Check:` + the
    // description below.
    let multi = display.matched.len() > 1;
    if multi {
        let _ = writeln!(out, "{}", st("Checks:").red().bold());
        for m in &display.matched {
            field(
                &mut out,
                "",
                &format!("- {} [{}]: {}", m.id, m.severity, m.description),
                &plain,
            );
        }
    } else if !display.check_ids.is_empty() {
        let label = if display.check_ids.len() == 1 {
            "Check:"
        } else {
            "Checks:"
        };
        field(&mut out, label, &display.check_ids.join(", "), &plain);
    }

    // Severity label
    if let Some(ref sev) = display.severity_label {
        field(&mut out, "Severity:", sev, &|s| st(s).red().to_string());
    }

    // Blast radius
    if let Some(ref br) = display.blast_radius_label {
        field(&mut out, "Blast radius:", br, &|s| st(s).dim().to_string());
    }

    // Context labels
    if !display.context_labels.is_empty() {
        let labels = display.context_labels.join(", ");
        field(&mut out, "Context:", &labels, &|s| st(s).cyan().to_string());
    }

    // Descriptions (already part of the per-check lines when several).
    if !multi {
        for desc in &display.descriptions {
            field(&mut out, "Description:", desc, &plain);
        }
    }

    // Alternatives
    for alt in &display.alternatives {
        field(&mut out, "Alternative:", &alt.suggestion, &plain);
        if let Some(ref info) = alt.explanation {
            field(&mut out, "", &format!("  ({info})"), &|s| {
                st(s).dim().to_string()
            });
        }
    }

    if display.is_denied {
        for reason in &display.deny_reasons {
            field(&mut out, "Denied:", reason, &plain);
        }
        let hint = display
            .deny_hint
            .clone()
            .unwrap_or_else(|| personal_deny_hint(&display.check_ids));
        field(&mut out, "", &hint, &|s| st(s).dim().to_string());
    } else {
        // Escalation note — only present when the challenge got stricter.
        if let Some(ref note) = display.escalation_note {
            field(&mut out, "", note, &|s| st(s).magenta().bold().to_string());
        }
        for note in &display.notes {
            field(&mut out, "", note, &|s| st(s).yellow().to_string());
        }
        let hint = if display.matched.is_empty() {
            // Displays not built by `build_challenge_display`.
            match display.check_ids.as_slice() {
                [id] => Some(format!(
                    "Not risky for you? Stop asking with `shellfirm config ignore {id}`."
                )),
                _ => None,
            }
        } else {
            display.ignore_hint.clone()
        };
        if let Some(hint) = hint {
            field(&mut out, "", &hint, &|s| st(s).dim().to_string());
        }
    }

    out
}

/// "To allow it again" hint for ids on the user's personal deny list.
#[must_use]
pub fn personal_deny_hint(ids: &[String]) -> String {
    match ids {
        [id] => format!(
            "Denied commands cannot be confirmed. To allow it again: `shellfirm config deny --remove {id}`."
        ),
        ids => format!(
            "Denied commands cannot be confirmed. To allow them again: `{}`.",
            ids.iter()
                .map(|id| format!("shellfirm config deny --remove {id}"))
                .collect::<Vec<_>>()
                .join(" && ")
        ),
    }
}

/// Print the warning banner to stderr.
///
/// ANSI codes (colors, and the "clear below cursor" sequence) are only
/// emitted when stderr is a terminal that understands them (not
/// `TERM=dumb`).
pub fn display_banner(display: &DisplayContext) {
    let is_tty = std::io::stderr().is_terminal();
    let dumb = std::env::var("TERM").is_ok_and(|t| t == "dumb");
    if is_tty && !dumb {
        // Move to a new line and clear everything below the cursor.
        // This erases leftover terminal artifacts (e.g., fzf inline display)
        // so the challenge renders cleanly.
        eprint!("\n\x1b[J");
    } else {
        eprintln!();
    }
    let color = is_tty && !dumb && console::colors_enabled_stderr();
    eprintln!("{}", render_banner(display, color));
}

/// The message printed when a challenge is required but nobody can answer
/// it (no terminal). The command is blocked (fail closed).
#[must_use]
pub fn no_terminal_message(display: &DisplayContext) -> String {
    let (ids, verb) = match display.check_ids.as_slice() {
        [] => ("this command".to_string(), "requires"),
        [id] => (id.clone(), "requires"),
        ids => (ids.join(", "), "require"),
    };
    format!(
        "shellfirm: cannot prompt (no terminal); command blocked: {ids} {verb} the `{}` challenge",
        display.effective_challenge
    )
}

/// Printed by the prompters after a deny banner (which already lists the reasons).
pub const DENIED_NOTICE: &str = "shellfirm: command denied, not run.";

/// One-line deny message including the reasons, for callers without a banner.
#[must_use]
pub fn denied_message(display: &DisplayContext) -> String {
    if display.deny_reasons.is_empty() {
        "shellfirm: command denied".to_string()
    } else {
        format!(
            "shellfirm: command denied: {}",
            display.deny_reasons.join("; ")
        )
    }
}

// ---------------------------------------------------------------------------
// TerminalPrompter (requestty implementation, used by `wrap` and non-unix)
// ---------------------------------------------------------------------------

/// Prompter that uses `requestty` on stdin/stdout, banner on stderr.
pub struct TerminalPrompter;

impl Prompter for TerminalPrompter {
    fn can_prompt(&self) -> bool {
        std::io::stdin().is_terminal()
    }

    fn announce_approved(&self, command: &str) {
        announce_approved(command);
    }

    fn run_challenge(&self, display: &DisplayContext) -> ChallengeResult {
        display_banner(display);

        // Deny is absolute: return immediately (never block). The banner
        // already listed the reasons, so only confirm the outcome here.
        if display.is_denied {
            eprintln!("{DENIED_NOTICE}");
            return ChallengeResult::Denied;
        }

        if !self.can_prompt() {
            eprintln!("{}", no_terminal_message(display));
            return ChallengeResult::Denied;
        }

        flush_stdin_typeahead();

        let prefix = display
            .severity_label
            .as_deref()
            .map_or_else(String::new, |s| format!("[{s}] "));
        let passed = match display.effective_challenge {
            Challenge::Math => math_challenge(&prefix),
            Challenge::Enter => enter_challenge(&prefix),
            Challenge::Yes => yes_challenge(&prefix),
        };
        if passed {
            ChallengeResult::Passed
        } else {
            ChallengeResult::Denied
        }
    }
}

/// Discard pending typeahead on stdin's terminal so pasted text or extra
/// newlines can't answer the challenge.
fn flush_stdin_typeahead() {
    #[cfg(unix)]
    {
        let stdin = std::io::stdin();
        if stdin.is_terminal() {
            if let Err(e) =
                nix::sys::termios::tcflush(&stdin, nix::sys::termios::FlushArg::TCIFLUSH)
            {
                tracing::debug!("tcflush(stdin) failed: {e}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// MockPrompter (used in tests)
// ---------------------------------------------------------------------------

/// Test prompter that returns a preconfigured response and records displays.
pub struct MockPrompter {
    pub response: ChallengeResult,
    /// Records all `DisplayContext`s that were shown.
    pub captured_displays: RefCell<Vec<DisplayContext>>,
}

impl MockPrompter {
    /// Create a tracking mock that records displays and passes challenges.
    #[must_use]
    pub const fn passing() -> Self {
        Self {
            response: ChallengeResult::Passed,
            captured_displays: RefCell::new(Vec::new()),
        }
    }
}

thread_local! {
    /// Commands a [`MockPrompter`] on this thread was asked to announce.
    static MOCK_ANNOUNCED: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

impl MockPrompter {
    /// The commands any `MockPrompter` on this thread announced as approved
    /// (see [`Prompter::announce_approved`]) since the last call; clears
    /// the list. Lets a test check that a passed challenge announces the
    /// command and a denied one (or `approved_notice: false`) does not.
    #[must_use]
    pub fn take_announced() -> Vec<String> {
        MOCK_ANNOUNCED.with(|a| std::mem::take(&mut *a.borrow_mut()))
    }
}

impl Prompter for MockPrompter {
    fn run_challenge(&self, display: &DisplayContext) -> ChallengeResult {
        self.captured_displays.borrow_mut().push(display.clone());
        if display.is_denied {
            return ChallengeResult::Denied;
        }
        self.response
    }

    fn announce_approved(&self, command: &str) {
        MOCK_ANNOUNCED.with(|a| a.borrow_mut().push(command.to_string()));
    }
}

// ---------------------------------------------------------------------------
// DirectTtyPrompter — reads keys straight from /dev/tty
// ---------------------------------------------------------------------------

/// Prompter that reads directly from `/dev/tty`.
///
/// Used by `pre-command` on unix (all shell hooks). It bypasses crossterm's
/// event system entirely — crossterm uses `select(2)`/`poll(2)` on
/// `/dev/tty` which hangs in certain shell contexts (zsh zle widgets on
/// macOS, see <https://github.com/kaplanelad/shellfirm/issues/160>).
///
/// The terminal is switched to a minimal raw mode (no canonical input, no
/// echo, no signal keys) for the duration of the answer, with a tiny line
/// editor on top: printable characters, Backspace, Ctrl-U, Enter to submit,
/// **Esc or Ctrl-C to cancel** (same keys in every shell). Pending
/// typeahead is flushed before every prompt and bracketed-paste content is
/// ignored, so pasted text or extra newlines can never answer a challenge.
#[cfg(unix)]
pub struct DirectTtyPrompter;

#[cfg(unix)]
impl Prompter for DirectTtyPrompter {
    fn can_prompt(&self) -> bool {
        direct::open_tty().is_ok()
    }

    fn announce_approved(&self, command: &str) {
        announce_approved(command);
    }

    fn run_challenge(&self, display: &DisplayContext) -> ChallengeResult {
        display_banner(display);

        // Deny is absolute: return immediately (never block). The banner
        // already listed the reasons, so only confirm the outcome here.
        if display.is_denied {
            eprintln!("{DENIED_NOTICE}");
            return ChallengeResult::Denied;
        }

        let Ok(tty) = direct::open_tty() else {
            eprintln!("{}", no_terminal_message(display));
            return ChallengeResult::Denied;
        };

        if direct::run(
            &tty,
            display.effective_challenge,
            display.severity_label.as_deref(),
        ) {
            ChallengeResult::Passed
        } else {
            ChallengeResult::Denied
        }
    }
}

/// Raw `/dev/tty` challenge implementation.
#[cfg(unix)]
pub(crate) mod direct {
    use std::{
        fs::File,
        io::{Read, Write},
        os::fd::AsRawFd,
    };

    use nix::sys::termios::{self, FlushArg, LocalFlags, SetArg, SpecialCharacterIndices};
    use rand::RngExt;

    use super::{
        DIRECT_CANCEL_TEXT, SOLVE_ENTER_TEXT, SOLVE_MATH_TEXT, SOLVE_YES_TEXT, WRONG_ANSWER,
    };
    use crate::config::Challenge;

    /// How long to wait after an ESC byte for the rest of an escape
    /// sequence (arrow keys, bracketed paste). A lone ESC means "cancel".
    const ESC_WAIT_MS: i32 = 40;

    pub fn open_tty() -> std::io::Result<File> {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
    }

    /// A source of input bytes (the tty in production, a slice in tests).
    pub trait ByteSource {
        /// Read one byte; `Ok(None)` on EOF.
        fn read_byte(&mut self) -> std::io::Result<Option<u8>>;
        /// Whether another byte is available within `wait_ms`.
        fn has_pending(&mut self, wait_ms: i32) -> bool;
    }

    struct TtySource<'a> {
        file: &'a File,
    }

    impl ByteSource for TtySource<'_> {
        fn read_byte(&mut self) -> std::io::Result<Option<u8>> {
            let mut b = [0u8; 1];
            loop {
                match self.file.read(&mut b) {
                    Ok(0) => return Ok(None),
                    Ok(_) => return Ok(Some(b[0])),
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
        }

        fn has_pending(&mut self, wait_ms: i32) -> bool {
            let mut pfd = libc::pollfd {
                fd: self.file.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: `pfd` is a valid, initialised pollfd and we pass a count of 1.
            let r = unsafe { libc::poll(&raw mut pfd, 1, wait_ms) };
            r > 0
        }
    }

    /// Restores the original terminal attributes on drop.
    struct RawModeGuard<'a> {
        file: &'a File,
        original: termios::Termios,
    }

    impl<'a> RawModeGuard<'a> {
        fn enter(file: &'a File) -> Option<Self> {
            let original = termios::tcgetattr(file)
                .inspect_err(|e| tracing::debug!("tcgetattr failed: {e}"))
                .ok()?;
            let mut raw = original.clone();
            raw.local_flags &=
                !(LocalFlags::ICANON | LocalFlags::ECHO | LocalFlags::ISIG | LocalFlags::IEXTEN);
            raw.control_chars[SpecialCharacterIndices::VMIN as usize] = 1;
            raw.control_chars[SpecialCharacterIndices::VTIME as usize] = 0;
            if let Err(e) = termios::tcsetattr(file, SetArg::TCSANOW, &raw) {
                tracing::debug!("tcsetattr(raw) failed: {e}");
                return None;
            }
            Some(Self { file, original })
        }
    }

    impl Drop for RawModeGuard<'_> {
        fn drop(&mut self) {
            if let Err(e) = termios::tcsetattr(self.file, SetArg::TCSANOW, &self.original) {
                tracing::debug!("tcsetattr restore failed: {e}");
            }
        }
    }

    /// Run `challenge` on the tty. Returns `true` when it was passed.
    /// `severity` is repeated on the prompt line (`[HIGH] Solve …`) so it
    /// stays visible when the banner scrolls away.
    pub fn run(tty: &File, challenge: Challenge, severity: Option<&str>) -> bool {
        let _guard = RawModeGuard::enter(tty);
        let mut src = TtySource { file: tty };
        let mut out = tty;
        let mut rng = rand::rng();
        let nums = (rng.random_range(0..10), rng.random_range(0..10));
        let flush = |_: &mut TtySource<'_>| {
            if let Err(e) = termios::tcflush(tty, FlushArg::TCIFLUSH) {
                tracing::debug!("tcflush failed: {e}");
            }
        };
        challenge_loop_labeled(challenge, severity, &mut src, &mut out, nums, flush)
    }

    /// The result of reading one answer.
    #[derive(Debug, PartialEq, Eq)]
    pub enum Answer {
        Line(String),
        Cancelled,
        Eof,
    }

    fn pop_char(buf: &mut Vec<u8>) -> bool {
        if buf.is_empty() {
            return false;
        }
        while let Some(b) = buf.pop() {
            // Stop at the first byte that isn't a UTF-8 continuation byte.
            if b & 0b1100_0000 != 0b1000_0000 {
                break;
            }
        }
        true
    }

    /// Read one answer line with minimal line editing.
    pub fn read_answer(src: &mut impl ByteSource, out: &mut impl Write) -> Answer {
        let mut buf: Vec<u8> = Vec::new();
        let mut in_paste = false;
        loop {
            let Ok(Some(b)) = src.read_byte() else {
                return Answer::Eof;
            };
            if b == 0x1b {
                if !src.has_pending(ESC_WAIT_MS) {
                    return Answer::Cancelled;
                }
                let Ok(Some(n)) = src.read_byte() else {
                    return Answer::Eof;
                };
                match n {
                    b'[' => {
                        let mut params = Vec::new();
                        let fin = loop {
                            let Ok(Some(c)) = src.read_byte() else {
                                return Answer::Eof;
                            };
                            if (0x40..=0x7e).contains(&c) {
                                break c;
                            }
                            params.push(c);
                        };
                        if fin == b'~' {
                            if params == b"200" {
                                in_paste = true;
                            } else if params == b"201" {
                                in_paste = false;
                            }
                        }
                    }
                    b'O' => {
                        let _ = src.read_byte();
                    }
                    _ => {} // Alt+key: ignore
                }
                continue;
            }
            if in_paste {
                continue;
            }
            match b {
                0x03 => return Answer::Cancelled,
                0x04 if buf.is_empty() => return Answer::Cancelled,
                b'\r' | b'\n' => return Answer::Line(String::from_utf8_lossy(&buf).into_owned()),
                0x7f | 0x08 => {
                    if pop_char(&mut buf) {
                        let _ = out.write_all(b"\x08 \x08");
                    }
                }
                0x15 => {
                    while pop_char(&mut buf) {
                        let _ = out.write_all(b"\x08 \x08");
                    }
                }
                b if b < 0x20 => {}
                _ => {
                    buf.push(b);
                    let _ = out.write_all(&[b]);
                }
            }
            let _ = out.flush();
        }
    }

    /// Prompt until the challenge is passed (`true`) or cancelled (`false`).
    #[cfg(test)]
    pub fn challenge_loop<S: ByteSource>(
        challenge: Challenge,
        src: &mut S,
        out: &mut impl Write,
        nums: (u32, u32),
        before_prompt: impl FnMut(&mut S),
    ) -> bool {
        challenge_loop_labeled(challenge, None, src, out, nums, before_prompt)
    }

    /// The challenge loop with the severity shown at the start of the
    /// prompt line.
    pub fn challenge_loop_labeled<S: ByteSource>(
        challenge: Challenge,
        severity: Option<&str>,
        src: &mut S,
        out: &mut impl Write,
        (num_a, num_b): (u32, u32),
        mut before_prompt: impl FnMut(&mut S),
    ) -> bool {
        let expected = u64::from(num_a) + u64::from(num_b);
        let prefix = severity.map_or_else(String::new, |s| format!("[{s}] "));
        loop {
            before_prompt(src);
            let prompt = prefix.clone()
                + &match challenge {
                    Challenge::Math => {
                        format!("{SOLVE_MATH_TEXT} {num_a} + {num_b} = ? ({DIRECT_CANCEL_TEXT}) ")
                    }
                    Challenge::Enter => format!("{SOLVE_ENTER_TEXT} ({DIRECT_CANCEL_TEXT}) "),
                    Challenge::Yes => format!("{SOLVE_YES_TEXT} ({DIRECT_CANCEL_TEXT}) "),
                };
            let _ = out.write_all(prompt.as_bytes());
            let _ = out.flush();

            let line = match read_answer(src, out) {
                Answer::Line(l) => l,
                Answer::Cancelled => {
                    let _ = out.write_all(b"\r\nshellfirm: cancelled, command not run.\r\n");
                    let _ = out.flush();
                    return false;
                }
                Answer::Eof => {
                    let _ = out.write_all(b"\r\n");
                    let _ = out.flush();
                    return false;
                }
            };
            let _ = out.write_all(b"\r\n");

            let normalized = super::normalize_answer(&line);
            let answer = normalized.trim();
            let (ok, retry_msg) = match challenge {
                Challenge::Math => (answer.parse::<u64>().ok() == Some(expected), WRONG_ANSWER),
                Challenge::Enter => (
                    answer.is_empty(),
                    "Press Enter without typing anything to continue.",
                ),
                Challenge::Yes => (
                    answer.eq_ignore_ascii_case("yes"),
                    if answer.eq_ignore_ascii_case("y") {
                        "Please type the full word `yes`."
                    } else {
                        WRONG_ANSWER
                    },
                ),
            };
            if ok {
                let _ = out.flush();
                return true;
            }
            let _ = out.write_all(format!("{retry_msg}\r\n").as_bytes());
            let _ = out.flush();
        }
    }
}

// ---------------------------------------------------------------------------
// Answer normalization
// ---------------------------------------------------------------------------

/// First code points of Unicode blocks with the decimal digits 0-9 in a row
/// (Arabic-Indic, Devanagari, Bengali, Thai, full-width, mathematical, ...).
const DIGIT_BLOCKS: &[u32] = &[
    0x0660, 0x06F0, 0x07C0, 0x0966, 0x09E6, 0x0A66, 0x0AE6, 0x0B66, 0x0BE6, 0x0C66, 0x0CE6, 0x0D66,
    0x0DE6, 0x0E50, 0x0ED0, 0x0F20, 0x1040, 0x1090, 0x17E0, 0x1810, 0x1946, 0x19D0, 0x1A80, 0x1A90,
    0x1B50, 0x1BB0, 0x1C40, 0x1C50, 0xA620, 0xA8D0, 0xA900, 0xA9D0, 0xAA50, 0xABF0, 0xFF10,
    0x1D7CE, 0x1D7D8, 0x1D7E2, 0x1D7EC, 0x1D7F6,
];

/// Normalize a typed answer like NFKC does for the characters that matter.
///
/// Full-width ASCII (`１０`, `ｙｅｓ`) and the ideographic space
/// map to ASCII, and every Unicode decimal digit maps to `0-9`. Invisible
/// characters are dropped.
#[must_use]
pub fn normalize_answer(s: &str) -> String {
    s.chars()
        .filter(|c| !crate::context::is_invisible(*c))
        .map(|c| {
            let u = c as u32;
            if (0xFF01..=0xFF5E).contains(&u) {
                return char::from_u32(u - 0xFEE0).unwrap_or(c);
            }
            if u == 0x3000 {
                return ' ';
            }
            for &start in DIGIT_BLOCKS {
                if (start..start + 10).contains(&u) {
                    return char::from_digit(u - start, 10).unwrap_or(c);
                }
            }
            c
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Challenge implementations (used by TerminalPrompter)
// ---------------------------------------------------------------------------

/// Show math challenge to the user. Returns `false` when cancelled.
fn math_challenge(prefix: &str) -> bool {
    let mut rng = rand::rng();
    let num_a: u32 = rng.random_range(0..10);
    let num_b: u32 = rng.random_range(0..10);
    let expected = u64::from(num_a + num_b);

    let cancel = format!("{}", style(CANCEL_PROMPT_TEXT).underlined().bold().italic());
    let question = requestty::Question::input("math")
        .message(format!(
            "{prefix}{SOLVE_MATH_TEXT} {num_a} + {num_b} = ? {cancel}"
        ))
        .on_esc(requestty::OnEsc::Terminate)
        .validate(move |answer, _| {
            if normalize_answer(answer).trim().parse::<u64>().ok() == Some(expected) {
                Ok(())
            } else {
                Err(WRONG_ANSWER.to_owned())
            }
        })
        .build();

    requestty::prompt_one(question).is_ok()
}

/// Show enter challenge to the user. Returns `false` when cancelled.
fn enter_challenge(prefix: &str) -> bool {
    let cancel = format!("{}", style(CANCEL_PROMPT_TEXT).underlined().bold().italic());
    let question = requestty::Question::input("enter")
        .message(format!("{prefix}{SOLVE_ENTER_TEXT}, {cancel}"))
        .on_esc(requestty::OnEsc::Terminate)
        .validate(|answer, _| {
            if normalize_answer(answer).trim().is_empty() {
                Ok(())
            } else {
                Err("Press Enter without typing anything to continue.".to_owned())
            }
        })
        .build();

    requestty::prompt_one(question).is_ok()
}

/// Show yes challenge to the user. Returns `false` when cancelled.
fn yes_challenge(prefix: &str) -> bool {
    let cancel = format!("{}", style(CANCEL_PROMPT_TEXT).underlined().bold().italic());
    let question = requestty::Question::input("yes")
        .message(format!("{prefix}{SOLVE_YES_TEXT}, {cancel}"))
        .on_esc(requestty::OnEsc::Terminate)
        .validate(|answer, _| {
            let normalized = normalize_answer(answer);
            let a = normalized.trim();
            if a.eq_ignore_ascii_case("yes") {
                Ok(())
            } else if a.eq_ignore_ascii_case("y") {
                Err("Please type the full word `yes`.".to_owned())
            } else {
                Err(WRONG_ANSWER.to_owned())
            }
        })
        .build();

    requestty::prompt_one(question).is_ok()
}

// ---------------------------------------------------------------------------
// Interactive selection helpers (requestty-based)
// ---------------------------------------------------------------------------

/// Present a yes/no confirmation prompt with a custom message.
///
/// # Errors
///
/// Will return `Err` when the interactive prompt fails.
pub fn confirm(message: &str, default: bool) -> crate::error::Result<bool> {
    let question = requestty::Question::confirm("confirm")
        .message(message)
        .default(default)
        .build();
    let answer =
        requestty::prompt_one(question).map_err(|e| crate::error::Error::Prompt(e.to_string()))?;
    answer
        .as_bool()
        .ok_or_else(|| crate::error::Error::Prompt("confirm result is empty".into()))
}

/// Present a select prompt and return the chosen index.
///
/// # Errors
///
/// Will return `Err` when the interactive prompt fails.
pub fn select_with_default(
    message: &str,
    items: &[&str],
    default: usize,
) -> crate::error::Result<usize> {
    let question = requestty::Question::select("select")
        .message(message)
        .choices(items.iter().copied())
        .default(default)
        .build();
    let answer =
        requestty::prompt_one(question).map_err(|e| crate::error::Error::Prompt(e.to_string()))?;
    answer.as_list_item().map_or_else(
        || Err(crate::error::Error::Prompt("select option is empty".into())),
        |a| Ok(a.index),
    )
}

/// Present a multi-select prompt and return the indices of selected items.
///
/// # Errors
///
/// Will return `Err` when the interactive prompt fails.
pub fn multi_select(
    message: &str,
    items: &[&str],
    defaults: &[bool],
) -> crate::error::Result<Vec<usize>> {
    let mut builder = requestty::Question::multi_select("multi_select").message(message);
    for (i, &item) in items.iter().enumerate() {
        let checked = defaults.get(i).copied().unwrap_or(false);
        builder = builder.choice_with_default(item, checked);
    }
    let question = builder.build();
    let answer =
        requestty::prompt_one(question).map_err(|e| crate::error::Error::Prompt(e.to_string()))?;
    answer.as_list_items().map_or_else(
        || {
            Err(crate::error::Error::Prompt(
                "multi-select result is empty".into(),
            ))
        },
        |items| Ok(items.iter().map(|item| item.index).collect()),
    )
}

/// Present a text input prompt with a default value.
///
/// # Errors
///
/// Will return `Err` when the interactive prompt fails.
pub fn input_with_default(message: &str, default: &str) -> crate::error::Result<String> {
    let question = requestty::Question::input("input")
        .message(message)
        .default(default)
        .build();
    let answer =
        requestty::prompt_one(question).map_err(|e| crate::error::Error::Prompt(e.to_string()))?;
    answer.as_string().map_or_else(
        || Err(crate::error::Error::Prompt("input result is empty".into())),
        |s| Ok(s.to_string()),
    )
}

#[cfg(test)]
mod tests {

    #[test]
    fn report_lines_wrap_between_words_with_a_hanging_indent() {
        let text = "  [ok] plugin           transient prompt: its commandline -f execute is checked and the key bindings are fine\nshort line";
        let out = wrap_report(text, 40);
        for l in out.lines() {
            assert!(console::measure_text_width(l) <= 40, "{l:?}");
        }
        // No word is split: every word of the input is whole in the output.
        for w in text.split_whitespace() {
            assert!(out.split_whitespace().any(|o| o == w), "{w} split in {out}");
        }
        let lines: Vec<&str> = out.lines().collect();
        assert!(
            lines[1].starts_with("       ") && !lines[1].starts_with("        "),
            "{out}"
        );
        assert_eq!(*lines.last().unwrap(), "short line");
        // A word longer than the line is left whole.
        let long = format!("x {}", "y".repeat(60));
        assert!(wrap_report(&long, 30)
            .lines()
            .any(|l| l == "y".repeat(60).as_str() || l.trim() == "y".repeat(60)));
        // Colour codes do not count.
        let red = format!("{} {}", "\u{1b}[31mHIGH\u{1b}[0m", "word ".repeat(3).trim());
        assert_eq!(wrap_report(&red, 20), red);
    }

    use super::*;

    fn display() -> DisplayContext {
        DisplayContext {
            check_ids: vec!["git:force_push".into()],
            severity_label: Some("High".into()),
            descriptions: vec!["Force push".into()],
            context_labels: vec!["branch=main".into()],
            effective_challenge: Challenge::Yes,
            base_challenge: Challenge::Math,
            escalation_note: Some("Escalated to Yes (from Math): protected branch `main`".into()),
            escalation_reasons: vec!["protected branch `main`".into()],
            ..Default::default()
        }
    }

    #[test]
    fn banner_shows_check_id_reason_and_hint_without_ansi() {
        let out = render_banner(&display(), false);
        assert!(!out.contains('\x1b'), "no ANSI when color is off: {out:?}");
        assert!(out.contains("Check: git:force_push"));
        assert!(out.contains("Escalated to Yes (from Math): protected branch `main`"));
        assert!(out.contains("shellfirm config ignore git:force_push"));
        assert!(!out.contains("ESCALATED"));
    }

    #[test]
    fn denied_banner_has_no_escalation_line() {
        let mut d = display();
        d.is_denied = true;
        d.deny_reasons = vec!["`git:force_push` is on your deny list".into()];
        let out = render_banner(&d, false);
        assert!(out.contains("COMMAND DENIED"));
        assert!(out.contains("Denied: `git:force_push` is on your deny list"));
        assert!(out.contains("shellfirm config deny --remove git:force_push"));
        assert!(!out.contains("Escalated"));
        assert_eq!(
            denied_message(&d),
            "shellfirm: command denied: `git:force_push` is on your deny list"
        );
    }

    #[test]
    fn banner_shows_command_escaped_and_truncated() {
        let mut d = display();
        d.command = Some("git push -f origin main\u{200b}\nls".into());
        let out = render_banner_width(&d, false, 80);
        // A multi-line command keeps its lines (no literal `\n`).
        assert!(
            out.contains("Command: git push -f origin main\\u{200b}\n  ls\n"),
            "{out}"
        );
        assert!(!out.contains("\\n"), "{out}");
        d.command = Some(
            (1..=12)
                .map(|i| format!("echo {i}"))
                .collect::<Vec<_>>()
                .join("\n"),
        );
        let out = render_banner_width(&d, false, 80);
        assert!(out.contains("  echo 8\n  (+4 more lines)\n"), "{out}");
        // Display width: wide characters take two columns.
        assert_eq!(display_width("rm -rf 데이터"), 13);
        let line = approved_line(&format!("rm -rf {}", "데이터/".repeat(30)), true, 60);
        assert!(
            display_width(&line) <= 59,
            "{line} {}",
            display_width(&line)
        );
        let wrapped = wrap_words(&"데이터 ".repeat(20), 20, 20);
        assert!(
            wrapped.iter().all(|l| display_width(l) <= 20),
            "{wrapped:?}"
        );
        d.command = Some("x".repeat(500));
        let out = render_banner_width(&d, false, 1000);
        let line = out.lines().find(|l| l.starts_with("Command:")).unwrap();
        assert!(
            line.chars().count() < 220 && (line.ends_with('…') || line.ends_with("...")),
            "{line}"
        );
    }

    #[test]
    fn banner_wraps_on_words_at_narrow_width() {
        let mut d = display();
        d.descriptions = vec!["This force-pushes and can overwrite remote history.".into()];
        d.ignore_hint = Some(
            "Not risky for you? Stop asking with `shellfirm config ignore git:force_push`.".into(),
        );
        d.matched = vec![MatchedCheck {
            id: "git:force_push".into(),
            severity: "HIGH".into(),
            description: "x".into(),
        }];
        let out = render_banner_width(&d, false, 40);
        for line in out.lines() {
            assert!(
                line.chars().count() <= 40 || line.contains("`shellfirm"),
                "too long: {line:?}"
            );
        }
        // Words are never split, and the copy-paste command stays whole.
        assert!(out.contains("force-pushes"), "{out}");
        assert!(
            out.contains("`shellfirm config ignore git:force_push`"),
            "{out}"
        );
        assert!(out.lines().next().unwrap().chars().count() <= 40);
    }

    #[test]
    fn several_checks_get_one_labelled_line_each() {
        let mut d = display();
        d.check_ids = vec![
            "fs:recursively_delete".into(),
            "fs-strict:recursive_deletion".into(),
        ];
        d.descriptions = vec!["a".into(), "b".into()];
        d.matched = vec![
            MatchedCheck {
                id: "fs:recursively_delete".into(),
                severity: "CRITICAL".into(),
                description: "Deletes a critical location.".into(),
            },
            MatchedCheck {
                id: "fs-strict:recursive_deletion".into(),
                severity: "MEDIUM".into(),
                description: "Recursively deletes.".into(),
            },
        ];
        d.ignore_hint = None;
        let out = render_banner_width(&d, false, 120);
        assert!(!out.contains("Description:"), "{out}");
        assert!(out.contains("- fs:recursively_delete [CRITICAL]: Deletes a critical location."));
        assert!(!out.contains("<check-id>"), "{out}");
        assert!(!out.contains("Stop asking"), "{out}");
    }

    #[test]
    fn denied_banner_lists_usable_commands_for_several_ids() {
        let mut d = display();
        d.is_denied = true;
        d.check_ids = vec!["a:x".into(), "b:y".into()];
        let out = render_banner_width(&d, false, 200);
        assert!(
            out.contains(
                "`shellfirm config deny --remove a:x && shellfirm config deny --remove b:y`"
            ),
            "{out}"
        );
        assert!(!out.contains("<check-id>"));
    }

    #[test]
    fn approved_line_collapses_continuation_whitespace_like_the_banner() {
        assert_eq!(
            approved_line(
                "git reset --hard &&   echo step2 &&   echo step3",
                true,
                120
            ),
            "✓ approved — running: git reset --hard && echo step2 && echo step3"
        );
        // Quoted text keeps its spaces.
        assert_eq!(
            approved_line("git commit -m 'a   b' &&\t echo \"c  d\"", true, 120),
            "✓ approved — running: git commit -m 'a   b' && echo \"c  d\""
        );
    }

    #[test]
    fn approved_line_names_the_command_and_fits_the_terminal() {
        assert_eq!(
            approved_line("helm uninstall web", true, 80),
            "✓ approved — running: helm uninstall web"
        );
        assert_eq!(
            approved_line("helm uninstall web", false, 80),
            "ok: approved, running: helm uninstall web"
        );
        // A wide terminal shows a long command whole (no ~80-column cap).
        let wide = format!("git reset --hard; echo {} > /tmp/o", "a".repeat(100));
        let line = approved_line(&wide, true, 180);
        assert_eq!(line, format!("✓ approved — running: {wide}"));
        assert!(!line.contains('…'));
        // Too long: cut in the middle, the risky end stays visible.
        let long = format!(
            "kubectl get ns {} && kubectl delete ns prod",
            "x".repeat(300)
        );
        let line = approved_line(&long, true, 100);
        assert!(line.chars().count() < 100, "{line}");
        assert!(line.contains('…'), "{line}");
        assert!(line.ends_with("kubectl delete ns prod"), "{line}");
        assert!(
            line.starts_with("✓ approved — running: kubectl get ns"),
            "{line}"
        );
        // A narrow terminal: still one line.
        let line = approved_line(&long, false, 40);
        assert!(line.chars().count() <= 40, "{line}");
        assert!(line.contains("...") && line.ends_with("prod"), "{line}");
        // Multi-line: the first line plus the number of other lines.
        assert_eq!(
            approved_line("for i in 1 2; do\n  rm -rf ~/data/b$i\ndone", true, 120),
            "✓ approved — running: for i in 1 2; do (+2 lines)"
        );
        assert_eq!(
            approved_line("rm -rf a\nrm -rf b", false, 120),
            "ok: approved, running: rm -rf a (+1 line)"
        );
        // Control and bidi characters are escaped.
        let line = approved_line("rm -rf b\u{202e}x", false, 120);
        assert!(
            !line.contains('\u{202e}') && line.contains("\\u{202e}"),
            "{line}"
        );
    }

    #[test]
    fn mock_prompter_records_announcements() {
        let _ = MockPrompter::take_announced();
        let p = MockPrompter::passing();
        p.announce_approved("helm uninstall web");
        assert_eq!(MockPrompter::take_announced(), vec!["helm uninstall web"]);
        assert!(MockPrompter::take_announced().is_empty());
    }

    #[test]
    fn answers_are_nfkc_normalized() {
        assert_eq!(normalize_answer("１０"), "10");
        assert_eq!(normalize_answer("ｙｅｓ"), "yes");
        assert_eq!(normalize_answer("\u{0661}\u{0662}"), "12");
        assert_eq!(normalize_answer("\u{0967}\u{0966}"), "10");
        assert_eq!(normalize_answer("y\u{200b}es"), "yes");
        assert_eq!(normalize_answer("\u{3000}7"), " 7");
    }

    #[test]
    fn no_terminal_message_names_check_and_challenge() {
        assert_eq!(
            no_terminal_message(&display()),
            "shellfirm: cannot prompt (no terminal); command blocked: git:force_push requires the `Yes` challenge"
        );
    }

    #[test]
    fn mock_prompter_denies_denied() {
        let p = MockPrompter::passing();
        let d = DisplayContext {
            is_denied: true,
            ..Default::default()
        };
        assert_eq!(p.run_challenge(&d), ChallengeResult::Denied);
        assert!(p.can_prompt());
    }

    #[cfg(unix)]
    mod direct_tty {
        use super::super::direct::{challenge_loop, read_answer, Answer, ByteSource};
        use crate::config::Challenge;

        struct Slice {
            data: Vec<u8>,
            pos: usize,
            /// Byte offsets at which a flush (typeahead discard) happens.
            flushed_at: Vec<usize>,
        }

        impl Slice {
            fn new(data: &[u8]) -> Self {
                Self {
                    data: data.to_vec(),
                    pos: 0,
                    flushed_at: Vec::new(),
                }
            }
        }

        impl ByteSource for Slice {
            fn read_byte(&mut self) -> std::io::Result<Option<u8>> {
                let b = self.data.get(self.pos).copied();
                if b.is_some() {
                    self.pos += 1;
                }
                Ok(b)
            }
            fn has_pending(&mut self, _wait_ms: i32) -> bool {
                self.pos < self.data.len()
            }
        }

        fn answer(bytes: &[u8]) -> Answer {
            read_answer(&mut Slice::new(bytes), &mut Vec::new())
        }

        #[test]
        fn line_editing() {
            assert_eq!(answer(b"yes\r"), Answer::Line("yes".into()));
            assert_eq!(answer(b"yex\x7fs\n"), Answer::Line("yes".into()));
            assert_eq!(answer(b"abc\x15yes\r"), Answer::Line("yes".into()));
            assert_eq!(answer(b"\r"), Answer::Line(String::new()));
        }

        #[test]
        fn esc_and_ctrl_c_cancel() {
            assert_eq!(answer(b"\x1b"), Answer::Cancelled);
            assert_eq!(answer(b"ye\x03"), Answer::Cancelled);
            assert_eq!(answer(b"\x04"), Answer::Cancelled);
            assert_eq!(answer(b""), Answer::Eof);
        }

        #[test]
        fn arrow_keys_do_not_cancel() {
            assert_eq!(answer(b"\x1b[Ayes\r"), Answer::Line("yes".into()));
            assert_eq!(answer(b"\x1bOByes\r"), Answer::Line("yes".into()));
        }

        #[test]
        fn bracketed_paste_is_ignored() {
            assert_eq!(
                answer(b"\x1b[200~yes\r\r\x1b[201~\r"),
                Answer::Line(String::new())
            );
        }

        #[test]
        fn challenges() {
            let run = |c: Challenge, input: &[u8]| {
                challenge_loop(c, &mut Slice::new(input), &mut Vec::new(), (3, 4), |_| {})
            };
            assert!(run(Challenge::Math, b"7\r"));
            assert!(run(Challenge::Math, b"5\r7\r"));
            assert!(!run(Challenge::Math, b"5\r"));
            assert!(run(Challenge::Enter, b"\r"));
            assert!(!run(Challenge::Enter, b"\x1b"));
            assert!(run(Challenge::Yes, b"YES\r"));
            assert!(!run(Challenge::Yes, b"y\r"));
            assert!(!run(Challenge::Yes, b"\x03"));
        }

        #[test]
        fn full_width_answers_pass_and_severity_is_on_the_prompt_line() {
            let mut out = Vec::new();
            let passed = super::super::direct::challenge_loop_labeled(
                Challenge::Math,
                Some("HIGH"),
                &mut Slice::new("\u{ff17}\r".as_bytes()),
                &mut out,
                (3, 4),
                |_| {},
            );
            assert!(passed);
            let s = String::from_utf8(out).unwrap();
            assert!(
                s.starts_with("[HIGH] Solve the challenge: 3 + 4 = ?"),
                "{s}"
            );
            let run = |c: Challenge, input: &str| {
                challenge_loop(
                    c,
                    &mut Slice::new(input.as_bytes()),
                    &mut Vec::new(),
                    (3, 4),
                    |_| {},
                )
            };
            assert!(run(Challenge::Yes, "ｙｅｓ\r"));
            assert!(run(Challenge::Yes, "ＹＥＳ\r"));
        }

        #[test]
        fn typeahead_is_flushed_before_each_prompt() {
            // Simulate a paste of "\r\r" queued before the prompt: the flush
            // hook discards everything pending, so the queued newlines can't
            // answer the Enter challenge; then the user cancels.
            let mut src = Slice::new(b"\r\r");
            let mut out = Vec::new();
            let passed = challenge_loop(Challenge::Enter, &mut src, &mut out, (1, 1), |s| {
                s.flushed_at.push(s.pos);
                s.pos = s.data.len();
            });
            assert!(!passed, "queued newlines must not answer the challenge");
            assert_eq!(src.flushed_at, vec![0]);
        }

        #[test]
        fn prompt_texts() {
            let mut out = Vec::new();
            challenge_loop(
                Challenge::Math,
                &mut Slice::new(b"7\r"),
                &mut out,
                (3, 4),
                |_| {},
            );
            let s = String::from_utf8(out).unwrap();
            assert!(s.contains("Solve the challenge: 3 + 4 = ?"), "{s}");
            assert!(!s.contains("::"));
            let mut out = Vec::new();
            challenge_loop(
                Challenge::Enter,
                &mut Slice::new(b"\r"),
                &mut out,
                (3, 4),
                |_| {},
            );
            let s = String::from_utf8(out).unwrap();
            assert!(
                s.contains("Press Enter to continue (Esc or Ctrl-C to cancel)"),
                "{s}"
            );
        }
    }
}
