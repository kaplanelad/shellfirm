//! Shell-aware command parser and normalizer.
//!
//! The matcher used to delete quoted text with a naive regex
//! (`'[^']*'|"[^"]*"` → `""`) before matching. That hid real danger
//! (`rm -rf "/"`, `bash -c "..."`, `psql -c "DROP ..."`) and let a stray
//! apostrophe in a comment swallow whole lines.
//!
//! This module replaces that with a proper shell-aware lexer that:
//!
//! * tokenizes respecting single quotes, double quotes, `\` escapes and
//!   `$'…'` / `$"…"`;
//! * unquotes arguments so `rm -rf "/"` matches the same as `rm -rf /`;
//! * splits on `;`, `&&`, `||`, `|`, `&` and newlines (outside quotes);
//! * recurses into `bash|sh|zsh|dash -c "<payload>"`, `sudo`, `env VAR=x`,
//!   `eval`, `xargs`, `watch`, `( … )` subshells, `$( … )` and backticks;
//! * strips harmless prefixes (`nohup`, `time`, `nice`, `command`, …), a
//!   leading `\`, and absolute paths (`/bin/rm` → `rm`);
//! * drops heredoc bodies (they are data) unless they are fed to a shell;
//! * extracts the SQL payload of `psql -c`, `mysql -e`, `mongosh --eval`;
//! * keeps the quoted-argument content of *non-shell* commands
//!   (`echo "rm -rf /"`, `git commit -m "drop table"`) from forming a
//!   matchable command, by collapsing intra-word whitespace to a sentinel.
//!
//! On unbalanced quotes the parser falls back conservatively: it treats the
//! raw text as a single segment so a dangerous command still matches (fail
//! closed, not open).

/// Sentinel that replaces whitespace *inside* a single shell word.
///
/// Keeping the whitespace would let the content of a quoted argument of a
/// non-shell command (e.g. the string passed to `echo`) look like a separate
/// command and trigger a check. By collapsing intra-word whitespace to a
/// character that never matches `\s`, `rm -rf "/"` still normalizes to
/// `rm -rf /` (the `/` has no inner whitespace) while `echo "rm -rf /"`
/// normalizes to `echo rm<SENTINEL>-rf<SENTINEL>/`, which matches nothing.
pub const WS_SENTINEL: char = '\u{1}';

/// Result of parsing a command line.
#[derive(Debug, Clone, Default)]
pub struct Parsed {
    /// Normalized simple-command strings, one per command, plus any recursed
    /// payloads (shell `-c`, `eval`, SQL, subshells, …). These are what the
    /// check regexes run against.
    pub segments: Vec<String>,
    /// The whole command normalized with operators (`|`, `&&`, …) preserved,
    /// for cross-operator patterns such as `history | bash` or `curl | sh`.
    pub flat: String,
    /// The subset of `segments` that runs on another machine or inside a
    /// container (`ssh host …`, `docker exec …`, `kubectl exec …`). Local
    /// path-existence filters say nothing about those targets, so callers
    /// treat their paths as existing.
    pub remote_segments: Vec<String>,
}

/// Replace the whitespace sentinel back to a regular space.
#[must_use]
pub fn desentinel(s: &str) -> String {
    s.replace(WS_SENTINEL, " ")
}

/// A lexed word together with whether it contained quoted whitespace.
#[derive(Debug, Clone)]
struct Word {
    /// Unquoted value with intra-word whitespace preserved (for recursion/SQL).
    raw: String,
    /// Unquoted value with intra-word whitespace replaced by [`WS_SENTINEL`]
    /// (for shell-command matching).
    masked: String,
}

/// A lexeme is either a word or a control operator.
#[derive(Debug, Clone)]
enum Lexeme {
    Word(Word),
    /// `;`, `&&`, `||`, `|`, `&`, newline — command separators.
    Op(String),
    /// `(` — start of a subshell.
    SubOpen,
    /// `)` — end of a subshell.
    SubClose,
}

/// Programs whose quoted argument is executed as shell code.
const SHELLS: &[&str] = &[
    "bash",
    "sh",
    "zsh",
    "dash",
    "ksh",
    "mksh",
    "yash",
    "fish",
    "ash",
    // Shells shellfirm has hooks for: `nu -c`, `elvish -c`, `xonsh -c`,
    // Oils `osh -c` / `ysh -c`, `pwsh -c` / `-Command`.
    "nu",
    "nushell",
    "elvish",
    "xonsh",
    "osh",
    "ysh",
    "oils-for-unix",
    "pwsh",
    "powershell",
];

/// Prefix words that wrap another command and can be stripped.
const PREFIX_WORDS: &[&str] = &[
    "nohup",
    "time",
    "command",
    "builtin",
    "exec",
    "busybox",
    "stdbuf",
    "setsid",
    "nice",
    "ionice",
    // zsh precommand modifiers (`alias rm='nocorrect rm'` is a common idiom).
    "nocorrect",
    "noglob",
    "-",
];

/// Maximum number of physical lines joined to close a quote / `$(` (bounds
/// the lookahead so an unbalanced quote cannot make splitting quadratic).
const MAX_JOIN_LINES: usize = 2000;

/// Maximum nesting depth for recursive payload analysis (`bash -c` inside
/// `eval` inside `$( … )` …). Beyond it the text is matched raw (fail closed).
const MAX_DEPTH: usize = 32;

/// Total bytes of (re-)parsed text allowed for one top-level command. Every
/// recursion (`eval`, `bash -c`, `$( … )`, …) re-parses its payload; past
/// this budget the rest is matched raw and flagged as too complex, so an
/// adversarial input cannot cost unbounded time or memory.
const MAX_WORK_BYTES: usize = 2 * 1024 * 1024;

/// Maximum failed `$(` balance scans per input before the rest of the text
/// is treated literally (each failed scan reads to the end of the input).
const MAX_UNBALANCED_SUBST: usize = 32;

thread_local! {
    static DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static WORK: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static TOO_COMPLEX: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static REMOTE: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
    static EXPANSIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Operator-preserving forms of nested payloads (`bash -c 'curl … | sh'`,
    /// `ssh host 'history | sh'`, a cron line): added to the top-level flat
    /// form so cross-operator patterns see them.
    static NESTED_FLATS: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Most bytes of nested flat forms kept for one top-level command.
const MAX_NESTED_FLAT_BYTES: usize = 256 * 1024;

/// Parse and normalize a command line.
#[must_use]
pub fn parse(command: &str) -> Parsed {
    let depth = DEPTH.with(std::cell::Cell::get);
    if depth == 0 {
        // The same line is parsed by several stages (matching, context,
        // self-protection, the agent and shell views): reuse the result.
        if let Some(hit) = PARSE_CACHE.with(|c| {
            c.borrow()
                .iter()
                .find(|(k, _)| k.as_str() == command)
                .map(|(_, p)| p.clone())
        }) {
            return hit;
        }
        let parsed = parse_top(command);
        PARSE_CACHE.with(|c| {
            let mut c = c.borrow_mut();
            if c.len() >= PARSE_CACHE_ENTRIES {
                c.remove(0);
            }
            c.push((command.to_string(), parsed.clone()));
        });
        return parsed;
    }
    parse_top(command)
}

/// Lines kept in the per-thread parse cache.
const PARSE_CACHE_ENTRIES: usize = 8;

thread_local! {
    /// Whether `#` at the start of a word begins a comment in the top-level
    /// line. False for an interactive zsh without `interactivecomments` (its
    /// default) or bash without `interactive_comments`: there `#` is an
    /// ordinary character and `rm -rf a # b` removes `b` too.
    static HASH_COMMENTS: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
}

/// Set whether `#` starts a comment in the lines this thread parses.
///
/// Only the top-level line is affected (see [`hash_comments`]): the
/// payloads of `sh -c`, `eval` and the like keep comments, as the shell
/// running them does.
pub fn set_hash_comments(on: bool) {
    if HASH_COMMENTS.with(std::cell::Cell::get) != on {
        HASH_COMMENTS.with(|c| c.set(on));
        PARSE_CACHE.with(|c| c.borrow_mut().clear());
    }
}

/// Whether `#` starts a comment in the top-level line (the default; see
/// [`set_hash_comments`]).
#[must_use]
pub fn hash_comments() -> bool {
    HASH_COMMENTS.with(std::cell::Cell::get)
}

/// Whether a `#` at the start of a word begins a comment in the text being
/// parsed now: always inside nested payloads, at the top level unless
/// [`set_hash_comments`] turned it off.
fn hash_starts_comment() -> bool {
    hash_comments() || DEPTH.with(std::cell::Cell::get) > 1
}

thread_local! {
    /// Recently parsed top-level lines and their results.
    static PARSE_CACHE: std::cell::RefCell<Vec<(String, Parsed)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// [`parse`] without the cache.
fn parse_top(command: &str) -> Parsed {
    let depth = DEPTH.with(std::cell::Cell::get);
    if depth == 0 {
        WORK.with(|w| w.set(0));
        EXPANSIONS.with(|e| e.set(0));
        TOO_COMPLEX.with(|t| t.set(false));
        REMOTE.with(|r| r.borrow_mut().clear());
        NESTED_FLATS.with(|f| f.borrow_mut().clear());
    }
    if depth == 0 && command.len() > MAX_WORK_BYTES {
        // Too large to analyze structurally, which is not nesting: callers
        // report the size itself (`shellfirm:input_too_large`).
        return oversize_fallback(command);
    }
    if depth == 0 && substitution_depth_exceeds(command, MAX_SUBST_NESTING) {
        // Far deeper than any real line: the answer is already "too deeply
        // nested", so do not descend level by level (linear time, bounded
        // stack, whatever the depth).
        let mut parsed = nesting_limit_fallback(command);
        parsed.segments.insert(
            0,
            format!("{NESTING_LIMIT_MARKER} {}", truncate_chars(command, 200)),
        );
        return parsed;
    }
    let work = WORK.with(|w| {
        let v = w.get().saturating_add(command.len());
        w.set(v);
        v
    });
    if depth >= MAX_DEPTH || work > MAX_WORK_BYTES {
        return nesting_limit_fallback(command);
    }
    DEPTH.with(|d| d.set(depth + 1));
    let mut parsed = parse_inner(command);
    if depth == 0 {
        // `rd /s /q C:\Users\dev` read as a POSIX line loses its backslashes
        // (`C:Usersdev`): the same line with `/` separators is added, so the
        // checks see `C:/Users/dev`.
        if let Some(slashed) = windows_slashed(command) {
            let windows = parse_inner(&slashed);
            for seg in windows.segments {
                if !parsed.segments.contains(&seg) {
                    parsed.segments.push(seg);
                }
            }
            // The flat form too, for pipelines (`gci C:\Users\dev | ri`).
            if !windows.flat.is_empty() && windows.flat != parsed.flat {
                parsed.flat.push_str(" \n ");
                parsed.flat.push_str(&windows.flat);
            }
        }
    }
    DEPTH.with(|d| d.set(depth));
    if depth == 0 && TOO_COMPLEX.with(std::cell::Cell::get) {
        parsed.segments.insert(
            0,
            format!("{NESTING_LIMIT_MARKER} {}", truncate_chars(command, 200)),
        );
    }
    if depth == 0 {
        parsed.remote_segments = REMOTE.with(|r| std::mem::take(&mut *r.borrow_mut()));
        parsed.remote_segments.sort();
        parsed.remote_segments.dedup();
        let nested = NESTED_FLATS.with(|f| std::mem::take(&mut *f.borrow_mut()));
        for f in nested {
            if !parsed.flat.contains(&f) {
                parsed.flat.push_str(" \n ");
                parsed.flat.push_str(&f);
            }
        }
    } else if parsed.flat.contains(['|', '&', ';']) {
        // Only a payload with operators adds anything to the segments.
        NESTED_FLATS.with(|f| {
            let mut f = f.borrow_mut();
            let used: usize = f.iter().map(String::len).sum();
            if used + parsed.flat.len() <= MAX_NESTED_FLAT_BYTES {
                f.push(parsed.flat.clone());
            }
        });
    }
    parsed
}

/// `command` with every `\` turned into `/` when it has a Windows path: a
/// drive (`C:\`), a relative `.\` / `..\`, `~\`, `$HOME\`, `%VAR%\` or
/// `$env:VAR\`, each at the start of a word. `None` otherwise, so POSIX escapes (`\rm`, `a\ b`)
/// never get a second reading.
fn windows_slashed(command: &str) -> Option<String> {
    let b = command.as_bytes();
    let word_start =
        |i: usize| i == 0 || matches!(b[i - 1], b' ' | b'\t' | b'"' | b'\'' | b'=' | b'(' | b':');
    let has_marker = (0..b.len()).any(|i| {
        if !word_start(i) {
            return false;
        }
        let rest = &b[i..];
        let drive =
            rest.len() >= 3 && rest[0].is_ascii_alphabetic() && rest[1] == b':' && rest[2] == b'\\';
        let relative = rest.starts_with(b".\\")
            || rest.starts_with(b"..\\")
            || rest.starts_with(b"~\\")
            || rest.starts_with(b"$HOME\\");
        let var = |open: &[u8], close: &[u8]| {
            rest.strip_prefix(open).is_some_and(|r| {
                let n = r
                    .iter()
                    .take_while(|c| c.is_ascii_alphanumeric() || **c == b'_')
                    .count();
                n > 0 && r[n..].starts_with(close)
            })
        };
        drive || relative || var(b"%", b"%\\") || var(b"$env:", b"\\")
    });
    // A backslash that escapes a shell operator (`find … -exec rm {} \;`)
    // stays one.
    has_marker.then(|| {
        let mut out = String::with_capacity(command.len());
        let mut chars = command.chars().peekable();
        while let Some(c) = chars.next() {
            let escapes_operator = c == '\\'
                && chars
                    .peek()
                    .is_some_and(|n| matches!(n, ';' | '|' | '&' | '(' | ')' | '<' | '>'));
            out.push(if c == '\\' && !escapes_operator {
                '/'
            } else {
                c
            });
        }
        out
    })
}

/// `$( … )` / `<( … )` / `>( … )` nesting past which a line is not
/// analyzed level by level (see [`substitution_depth_exceeds`]). Well above
/// [`MAX_DEPTH`]: below it the normal parse reports the nesting itself.
const MAX_SUBST_NESTING: usize = 4 * MAX_DEPTH;

/// Whether `command` nests command / process substitutions deeper than
/// `limit` (one linear scan; single-quoted text is skipped).
fn substitution_depth_exceeds(command: &str, limit: usize) -> bool {
    let bytes = command.as_bytes();
    let mut open = 0usize;
    let mut i = 0;
    let mut in_single = false;
    while i < bytes.len() {
        let b = bytes[i];
        if in_single {
            in_single = b != b'\'';
        } else {
            match b {
                b'\\' => i += 1,
                b'\'' => in_single = true,
                b'$' | b'<' | b'>' if bytes.get(i + 1) == Some(&b'(') => {
                    open += 1;
                    if open > limit {
                        return true;
                    }
                    i += 1;
                }
                b')' => open = open.saturating_sub(1),
                _ => {}
            }
        }
        i += 1;
    }
    false
}

/// Largest piece of an oversize command that is still matched as text.
const MAX_OVERSIZE_PIECE: usize = 64 * 1024;

/// A command larger than [`MAX_WORK_BYTES`] is not analyzed structurally.
/// Fail closed: callers report it as too large to analyze, and it is split
/// on command separators so the pieces (`… && rm -rf /`) are still matched.
/// A huge piece is matched by its head and tail.
fn oversize_fallback(command: &str) -> Parsed {
    let mut segments = Vec::new();
    for piece in command.split([';', '&', '|', '\n']) {
        let t = piece.trim();
        if t.is_empty() {
            continue;
        }
        if t.len() <= MAX_OVERSIZE_PIECE {
            segments.push(t.to_string());
        } else {
            segments.push(truncate_chars(t, 4096));
            let tail: String = {
                let n = t.chars().count();
                t.chars().skip(n.saturating_sub(4096)).collect()
            };
            segments.push(tail.trim().to_string());
        }
    }
    Parsed {
        segments,
        flat: String::new(),
        remote_segments: Vec::new(),
    }
}

/// The first `n` characters of `s`.
fn truncate_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Marker segment emitted for a shell whose whole command text is only known
/// at run time (`xargs -I{} sh -c '{}'`); matched by the
/// `shell:unknown_shell_payload` check.
pub const UNKNOWN_PAYLOAD_MARKER: &str = "shellfirm-unknown-shell-payload";

/// Marker segment for an alias written to a shell startup file that makes
/// a command run a different, risky one (`echo alias ls=rm >> ~/.bashrc`);
/// matched by `fs:startup_alias_replaces_command`.
pub const STARTUP_ALIAS_MARKER: &str = "shellfirm-startup-alias";

/// Marker segment emitted when the nesting limit is hit; matched by the
/// `shell:nesting_too_deep` check.
pub const NESTING_LIMIT_MARKER: &str = "shellfirm-nesting-limit";

/// Past [`MAX_DEPTH`] the remaining text is not analyzed structurally. Fail
/// closed: report the nesting itself (High) and match the raw text plus a
/// crude flattening with quotes / substitution syntax and leading wrapper
/// words (`eval`, `bash -c`, …) removed, so `eval eval … rm -rf /` still
/// matches the payload.
fn nesting_limit_fallback(command: &str) -> Parsed {
    TOO_COMPLEX.with(|t| t.set(true));
    let flattened: String = command
        .chars()
        .map(|c| {
            if matches!(c, '\'' | '"' | '`' | '(' | ')' | '$' | '\\' | '{' | '}') {
                ' '
            } else {
                c
            }
        })
        .collect();
    let words: Vec<&str> = flattened.split_whitespace().collect();
    let mut start = 0;
    loop {
        match &words[start..] {
            ["eval" | "exec" | "command" | "sudo", ..] => start += 1,
            [sh, flag, ..]
                if SHELLS.contains(sh) && flag.starts_with('-') && flag.contains('c') =>
            {
                start += 2;
            }
            _ => break,
        }
    }
    let stripped = words[start..].join(" ");
    Parsed {
        segments: vec![command.to_string(), stripped],
        flat: command.to_string(),
        remote_segments: Vec::new(),
    }
}

fn parse_inner(command: &str) -> Parsed {
    let mut segments = Vec::new();

    // 1. Split the input into logical lines: a newline inside quotes or an
    //    open `$( … )` does not end a line, and heredoc bodies are detached
    //    (they are data unless fed to a shell).
    let lines = split_heredoc_lines(command);

    let mut flat_parts: Vec<String> = Vec::new();
    let mut ctx = ParseCtx::default();

    for line in &lines {
        // elvish `(external NAME)` is the external command NAME.
        let text = if line.text.contains("(external ") {
            unwrap_elvish_external(&line.text)
        } else {
            line.text.clone()
        };
        // 2. Command substitutions `$( … )` and backticks: their bodies are
        //    separate commands. The outer command keeps an inline copy.
        let (outer, subs) = extract_substitutions(&text);
        for sub in subs {
            segments.extend(parse(&sub).segments);
        }
        // An unquoted heredoc (`<<EOF`) expands substitutions in its body.
        for (body, quoted) in line.heredoc_bodies.iter().zip(&line.heredoc_quoted) {
            if !quoted {
                for sub in extract_substitutions_in(body, false).1 {
                    segments.extend(parse(&sub).segments);
                }
            }
        }

        if let Ok(lexemes) = lex(&outer) {
            // Build the flat (operator-preserving) representation.
            flat_parts.push(flat_from_lexemes(&lexemes));
            // Group into simple commands and normalize each.
            let cmds = group_commands(&lexemes);
            process_commands(
                &cmds,
                line.heredoc_bodies.as_slice(),
                &mut ctx,
                &mut segments,
            );
        } else {
            // Unbalanced quotes → fail closed: keep the raw line so a
            // dangerous command still matches.
            segments.push(line.text.clone());
            flat_parts.push(line.text.clone());
        }
    }

    // A trap body runs at exit: also judge it with the variables as the line
    // leaves them (`tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT; tmp=~`).
    for code in std::mem::take(&mut ctx.traps) {
        if !take_work(code.len()) {
            break;
        }
        if let Ok(lexemes) = lex(&code) {
            let cmds = group_commands(&lexemes);
            process_commands(&cmds, &[], &mut ctx, &mut segments);
        }
    }

    let flat = flat_parts.join(" \n ");

    // SQL block comments (`DROP /* x */ TABLE t`) hide the statement from the
    // keyword-anchored SQL checks: also match the comment-free form.
    let extra: Vec<String> = segments
        .iter()
        .filter_map(|s| strip_sql_comments(s))
        .collect();
    segments.extend(extra);

    // Deduplicate while preserving order; drop empties.
    let mut seen = std::collections::HashSet::new();
    segments.retain(|s| {
        let t = s.trim();
        !t.is_empty() && seen.insert(s.clone())
    });

    Parsed {
        segments,
        flat,
        remote_segments: Vec::new(),
    }
}

/// Replace elvish `(external NAME)` by `NAME` (the external command of that
/// name; `NAME` may be a variable).
fn unwrap_elvish_external(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(pos) = rest.find("(external ") {
        let after = &rest[pos + "(external ".len()..];
        let Some(close) = after.find(')') else {
            break;
        };
        let name = after[..close].trim();
        if name.is_empty() || name.contains(char::is_whitespace) {
            out.push_str(&rest[..=pos]);
            rest = &rest[pos + 1..];
            continue;
        }
        out.push_str(&rest[..pos]);
        out.push_str(name);
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    out
}

// ---------------------------------------------------------------------------
// Command substitution extraction
// ---------------------------------------------------------------------------

/// Replace `$( … )` and `` `…` `` with a placeholder and return the extracted
/// inner command strings. Respects single quotes (no expansion inside `'…'`).
fn extract_substitutions(input: &str) -> (String, Vec<String>) {
    extract_substitutions_in(input, true)
}

/// [`extract_substitutions`]; `command_text` is false for heredoc bodies
/// (text, where a `(` is never a fish command substitution).
#[allow(clippy::too_many_lines)]
fn extract_substitutions_in(input: &str, command_text: bool) -> (String, Vec<String>) {
    let mut out = String::with_capacity(input.len());
    let mut subs = Vec::new();
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    let mut in_double = false;
    let mut failures = 0usize;
    while i < len {
        let b = bytes[i];
        match b {
            // Single quotes (outside double quotes): no expansion inside.
            b'\'' if !in_double => {
                let end = input[i + 1..].find('\'').map_or(len, |e| i + 1 + e + 1);
                out.push_str(&input[i..end]);
                i = end;
            }
            b'"' => {
                in_double = !in_double;
                out.push('"');
                i += 1;
            }
            b'\\' if i + 1 < len => {
                let ch_len = utf8_len(bytes[i + 1]);
                out.push_str(&input[i..(i + 1 + ch_len).min(len)]);
                i += 1 + ch_len;
            }
            b'$' | b'`' if failures >= MAX_UNBALANCED_SUBST => {
                // Too many unbalanced substitutions: the rest is literal.
                TOO_COMPLEX.with(|t| t.set(true));
                out.push_str(&input[i..]);
                break;
            }
            b'$' if i + 2 < len && bytes[i + 1] == b'(' && bytes[i + 2] == b'(' => {
                // `$(( … ))` arithmetic: literal, not a command substitution.
                if let Some((inner, next)) = read_balanced_paren(input, i + 1) {
                    out.push_str("$(");
                    out.push_str(&inner);
                    out.push(')');
                    i = next;
                } else {
                    out.push('$');
                    i += 1;
                }
            }
            b'$' if i + 1 < len && bytes[i + 1] == b'(' => {
                if let Some((inner, next)) = read_balanced_paren(input, i + 1) {
                    if let Some(code) = executed_output(&out, &inner) {
                        subs.push(code);
                    }
                    // `"$(cat <<'EOF' … EOF)"`, `"$(echo …)"`: the output is
                    // known text, and in double quotes it is one word.
                    match literal_output(&inner, true).filter(|_| in_double) {
                        Some(text) => out.push_str(&escape_double_quoted(&text)),
                        None => out.push_str(&inline_substitution(&inner)),
                    }
                    subs.push(inner);
                    i = next;
                } else {
                    failures += 1;
                    out.push('$');
                    i += 1;
                }
            }
            // fish command substitution `cmd (…)` in argument position
            // (`eval (echo …)`). A group without spaces (`rm -rf
            // (src|build)`) is a zsh glob, left to the lexer.
            b'(' if command_text
                && !in_double
                && i > 0
                && matches!(bytes[i - 1], b' ' | b'\t')
                && !matches!(bytes.get(i + 1), Some(b'(' | b')'))
                && fish_substitution_context(&out) =>
            {
                match read_balanced_paren(input, i) {
                    // `EXPLAIN (ANALYZE, BUFFERS)` in SQL text is not one.
                    Some((inner, next))
                        if inner.contains(char::is_whitespace) && !inner.contains(',') =>
                    {
                        if let Some(code) = executed_output(&out, &inner) {
                            subs.push(code);
                        }
                        out.push_str(&inline_substitution(&inner));
                        subs.push(inner);
                        i = next;
                    }
                    _ => {
                        out.push('(');
                        i += 1;
                    }
                }
            }
            // Process substitution `<( … )` / `>( … )`: the body is a
            // command; `source <(…)` / `bash <(…)` run its output as code.
            b'<' | b'>'
                if !in_double
                    && i + 1 < len
                    && bytes[i + 1] == b'('
                    && (i == 0 || !matches!(bytes[i - 1], b'<' | b'>')) =>
            {
                if let Some((inner, next)) = read_balanced_paren(input, i + 1) {
                    if b == b'<' && executes_process_substitution(&out) {
                        if let Some(code) = literal_output(&inner, false) {
                            subs.push(code);
                        }
                    }
                    // Keep the `<( … )` shape (heredoc bodies and quotes
                    // dropped) for operator patterns such as `bash <(curl …)`.
                    let inline = inline_substitution(&inner);
                    out.push(char::from(b));
                    out.push('(');
                    out.push_str(&inline[2..inline.len() - 1]);
                    out.push(')');
                    subs.push(inner);
                    i = next;
                } else {
                    failures += 1;
                    out.push(char::from(b));
                    i += 1;
                }
            }
            b'`' => {
                if let Some((inner, next)) = read_backtick(input, i) {
                    if let Some(code) = executed_output(&out, &inner) {
                        subs.push(code);
                    }
                    let inline = inline_substitution(&inner);
                    if is_which_lookup(&inner)
                        || (!in_double && inner.trim().contains(char::is_whitespace))
                    {
                        // `` rm -rf `git rev-parse --show-toplevel` `` is one
                        // word, `$(…)`; `` `which rm` -rf / `` is
                        // `$(which rm) -rf /`. A single word keeps the
                        // backtick form (also a MySQL identifier quote:
                        // `DELETE FROM \`users\``).
                        out.push_str(&inline);
                    } else if let Some(text) = literal_output(&inner, true).filter(|_| in_double) {
                        out.push_str(&escape_double_quoted(&text));
                    } else {
                        // Keep the backtick form: it is also how MySQL quotes
                        // identifiers (`DELETE FROM \`users\``).
                        let body = &inline[2..inline.len() - 1];
                        out.push('`');
                        out.push_str(body);
                        out.push('`');
                    }
                    subs.push(inner);
                    i = next;
                } else {
                    failures += 1;
                    out.push('`');
                    i += 1;
                }
            }
            _ => {
                // Push the full UTF-8 char, not just the byte.
                let ch_len = utf8_len(b);
                out.push_str(&input[i..i + ch_len]);
                i += ch_len;
            }
        }
    }
    (out, subs)
}

/// The output of a substitution when it is known text (`cat <<'EOF' … EOF`,
/// `echo …`, `printf …`) **and** the surrounding command executes it:
/// `sh -c "$(…)"`, `eval "$(…)"`, or the substitution as the command word.
/// As an argument of any other command (`git commit -m "$(cat <<'EOF' …)"`)
/// it stays data.
fn executed_output(prefix: &str, inner: &str) -> Option<String> {
    if !executes_substitution(prefix) {
        return None;
    }
    decoded_output(inner)
        .or_else(|| transformed_output(inner))
        .or_else(|| literal_output(inner, false))
}

/// Marker segment for code generated by a text transform (`eval "$(echo …
/// | xxd -r -p | rev)"`), matched by `shell:eval_transformed_text`.
pub const TRANSFORMED_CODE_MARKER: &str = "shellfirm-transformed-code";

/// The marker for a substitution whose output is text decoded or
/// transformed by a pipeline stage (`rev`, `tr`, `xxd -r`, `base64 -d`, …).
fn transformed_output(inner: &str) -> Option<String> {
    let transforms = inner.split('|').any(|stage| {
        let words: Vec<&str> = stage.split_whitespace().collect();
        let Some(first) = words.first() else {
            return false;
        };
        let has = |f: &str| {
            words.iter().any(|w| {
                *w == f
                    || (w.starts_with('-')
                        && !w.starts_with("--")
                        && f.len() == 2
                        && w.contains(&f[1..]))
            })
        };
        match program_name(first).as_str() {
            // `tr -d '\r'` / `tr -s ' '` only delete or squeeze characters
            // (loading a CRLF `.env`): not an obfuscating mapping.
            "tr" => {
                let args: Vec<&str> = words[1..]
                    .iter()
                    .copied()
                    .take_while(|w| !w.starts_with(['<', '>']) && !w.ends_with(['<', '>']))
                    .collect();
                // `-d` deletes the characters of its one set (any other
                // word is the flattened input file); `-s` with one set only
                // squeezes, with two it also maps.
                let sets = args.iter().filter(|w| !w.starts_with('-')).count();
                !args.iter().find(|w| w.starts_with('-')).is_some_and(|w| {
                    !w.starts_with("--")
                        && w[1..].chars().all(|c| matches!(c, 'd' | 's' | 'c' | 'C'))
                        && match (w.contains('d'), w.contains('s')) {
                            (true, false) => true,
                            (false, true) => sets <= 1,
                            (true, true) => sets <= 2,
                            (false, false) => false,
                        }
                })
            }
            "rev" | "gunzip" | "zcat" | "bzcat" | "xzcat" | "uudecode" => true,
            "xxd" => has("-r"),
            "base64" | "base32" => has("-d") || has("-D") || words.contains(&"--decode"),
            "gzip" | "bzip2" | "xz" | "zstd" => has("-d"),
            "openssl" => words.get(1).is_some_and(|w| matches!(*w, "enc" | "base64")),
            _ => false,
        }
    });
    transforms.then(|| format!("{TRANSFORMED_CODE_MARKER} {}", inline_substitution(inner)))
}

/// The output of a decode pipeline with a literal input
/// (`echo cm0gLXJmIC8= | base64 -d`, `base64 -d <<< …`, `printf %s … |
/// base64 --decode`): the decoded text, when it is UTF-8.
fn decoded_output(inner: &str) -> Option<String> {
    let lexemes = lex(inner.trim()).ok()?;
    let cmds = group_commands(&lexemes);
    let is_decode = |words: &[Word]| {
        words
            .first()
            .is_some_and(|w| program_name(&w.raw) == "base64")
            && words[1..]
                .iter()
                .any(|w| matches!(w.raw.as_str(), "-d" | "--decode" | "-D" | "-di" | "-id"))
    };
    let encoded = match cmds.as_slice() {
        [producer, decoder] if decoder.piped && is_decode(&decoder.words) => {
            echo_payload(&strip_prefixes(&producer.words))?
        }
        [decoder] if is_decode(&decoder.words) => {
            let pos = decoder.words.iter().position(|w| w.raw == "<<<")?;
            decoder.words.get(pos + 1)?.raw.clone()
        }
        _ => return None,
    };
    if encoded.contains(['$', '`']) {
        return None;
    }
    let bytes = base64_decode(encoded.trim())?;
    String::from_utf8(bytes)
        .ok()
        .filter(|t| !t.trim().is_empty())
}

/// Decode standard / URL-safe base64 (whitespace ignored, padding
/// optional). `None` on any other character.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for c in text.chars() {
        let v = match c {
            'A'..='Z' => u32::from(c) - u32::from('A'),
            'a'..='z' => u32::from(c) - u32::from('a') + 26,
            '0'..='9' => u32::from(c) - u32::from('0') + 52,
            '+' | '-' => 62,
            '/' | '_' => 63,
            '=' => break,
            c if c.is_whitespace() => continue,
            _ => return None,
        };
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).ok()?);
        }
    }
    Some(out)
}

/// The text a command list prints when it is written out literally: the
/// bodies of `cat <<'EOF'` heredocs and the arguments of `echo` / `printf`.
/// With `strict`, every command must be such a producer and the text must
/// not contain further expansions (it is then exactly the output); otherwise
/// other commands are skipped (they are analyzed on their own anyway).
fn literal_output(inner: &str, strict: bool) -> Option<String> {
    let mut out: Vec<String> = Vec::new();
    for line in split_heredoc_lines(inner) {
        if line.text.trim().is_empty() {
            continue;
        }
        let Ok(lexemes) = lex(&line.text) else {
            if strict {
                return None;
            }
            continue;
        };
        for cmd in group_commands(&lexemes) {
            let words = strip_prefixes(&cmd.words);
            let prog = words.first().map(|w| program_name(&w.raw));
            let text = match prog.as_deref() {
                Some("cat") if !line.heredoc_bodies.is_empty() => {
                    let expands = line
                        .heredoc_bodies
                        .iter()
                        .zip(&line.heredoc_quoted)
                        .any(|(b, q)| !q && (b.contains('$') || b.contains('`')));
                    if strict && expands {
                        None
                    } else {
                        Some(line.heredoc_bodies.join("\n"))
                    }
                }
                Some("echo" | "printf") => {
                    let expands = words[1..]
                        .iter()
                        .any(|w| w.raw.contains('$') || w.raw.contains('`'));
                    if strict && expands {
                        None
                    } else {
                        echo_payload(&words)
                    }
                }
                _ => None,
            };
            match text {
                Some(t) => out.push(t.trim_end_matches('\n').to_string()),
                None if strict => return None,
                None => {}
            }
        }
    }
    (!out.is_empty()).then(|| out.join("\n"))
}

/// Escape text for use inside double quotes (`\`, `"`, `$`, `` ` ``).
fn escape_double_quoted(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(c, '\\' | '"' | '$' | '`') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Whether the text before a `<(` runs the process substitution's output as
/// code: `source <(…)`, `. <(…)`, `bash <(…)`.
fn executes_process_substitution(prefix: &str) -> bool {
    let last = prefix
        .rfind([';', '&', '|', '\n', '(', '{'])
        .map_or(prefix, |i| &prefix[i + 1..]);
    let words: Vec<&str> = last.split_whitespace().collect();
    let Some((first, rest)) = words.split_first() else {
        return false;
    };
    let prog = program_name(first);
    (prog == "source" || prog == "." || SHELLS.contains(&prog.as_str()))
        && rest.iter().all(|w| w.starts_with('-'))
}

/// Whether the text before a `$(` puts the substitution's output where it
/// is run as code.
fn executes_substitution(prefix: &str) -> bool {
    let last = prefix
        .rfind([';', '&', '|', '\n', '(', '{'])
        .map_or(prefix, |i| &prefix[i + 1..]);
    let last = last.trim_end().trim_end_matches(['"', '\'']).trim_end();
    let words: Vec<&str> = last.split_whitespace().collect();
    // `sudo $(…)`, `exec $(…)`, `nohup $(…)`, `env X=1 $(…)`: wrappers that
    // run the substitution's output as the command.
    let wrapper = |w: &&str| {
        let p = program_name(w);
        is_var_assignment(w)
            || (w.starts_with('-') && w.len() > 1)
            || w.chars().all(|c| c.is_ascii_digit() || c == '.')
            || PREFIX_WORDS.contains(&p.as_str())
            || matches!(
                p.as_str(),
                "sudo"
                    | "doas"
                    | "env"
                    | "timeout"
                    | "nohup"
                    | "time"
                    | "exec"
                    | "!"
                    | "then"
                    | "do"
                    | "else"
            )
    };
    if !words.is_empty() && words.iter().all(wrapper) {
        return true;
    }
    match words.as_slice() {
        [] => true,
        [.., w] if program_name(w) == "eval" => true,
        [first, .., flag] => {
            let shell = SHELLS.contains(&program_name(first).as_str())
                || words
                    .iter()
                    .any(|w| SHELLS.contains(&program_name(w).as_str()));
            shell
                && flag.starts_with('-')
                && !flag.starts_with("--")
                && flag[1..].chars().all(|c| c.is_ascii_alphabetic())
                && flag.contains('c')
        }
        _ => false,
    }
}

/// Whether a `(` after `prefix` (the text of the line so far) is in the
/// argument position of a simple command, where fish reads it as a command
/// substitution: the command has a word already and is not a compound
/// command header (`case x in (a)`, `foreach x (a b)`, `time ( … )`).
fn fish_substitution_context(prefix: &str) -> bool {
    let last = prefix
        .rfind([';', '&', '|', '\n', '(', '{', '`'])
        .map_or(prefix, |i| &prefix[i + 1..]);
    let words: Vec<&str> = last.split_whitespace().collect();
    let Some(first) = words.first() else {
        return false;
    };
    !matches!(
        program_name(first).as_str(),
        "for"
            | "foreach"
            | "case"
            | "select"
            | "function"
            | "time"
            | "!"
            | "if"
            | "then"
            | "else"
            | "elif"
            | "do"
            | "while"
            | "until"
            | "coproc"
            | "[["
            | "repeat"
    ) && !words.contains(&"in")
        && !is_var_assignment(first)
        // An upper-case first word is SQL (`EXPLAIN (…)`, `VALUES (…)`).
        && !first.chars().all(|c| c.is_ascii_uppercase() || c == '_')
}

/// Whether a substitution body is a program lookup (`which X`,
/// `command -v X`, `type -p X`, `realpath X`, `whence X`).
fn is_which_lookup(inner: &str) -> bool {
    let parts: Vec<&str> = inner.split_whitespace().collect();
    matches!(
        parts.as_slice(),
        ["which" | "whence" | "realpath", _] | ["command" | "type", "-v" | "-p" | "-P", _]
    )
}

/// Render a command substitution inline as `$(…)` so outer checks such as
/// `docker rm -f $(docker ps -aq)` still see it. Quotes, parens, backticks
/// and newlines are dropped from the inline copy (the full body is analyzed
/// separately), which keeps the outer text safe to lex.
fn inline_substitution(inner: &str) -> String {
    // Heredoc bodies inside the substitution (`$(cat <<'EOF' … EOF)`) are
    // data: keep only the command lines in the inline copy.
    let commands: Vec<String> = split_heredoc_lines(inner)
        .into_iter()
        .map(|l| l.text)
        .collect();
    let cleaned: String = commands
        .join(" ")
        .chars()
        .map(|c| if c == '\n' { ' ' } else { c })
        .filter(|c| {
            !matches!(
                c,
                '\'' | '"' | '`' | '(' | ')' | '\\' | ';' | '&' | '|' | '<' | '>'
            )
        })
        .collect();
    format!(
        "$({})",
        cleaned.split_whitespace().collect::<Vec<_>>().join(" ")
    )
}

/// Given index of an opening `(`, return `(inner, index_after_close)`.
fn read_balanced_paren(input: &str, open: usize) -> Option<(String, usize)> {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut depth = 0i32;
    let mut i = open;
    let start = open + 1;
    let mut in_single = false;
    let mut in_double = false;
    // Heredocs opened inside the substitution (`$(cat <<'EOF' … EOF)`): their
    // bodies are skipped verbatim (an apostrophe in a body is not a quote).
    let mut pending: Vec<String> = Vec::new();
    while i < len {
        let b = bytes[i];
        if in_single {
            if b == b'\'' {
                in_single = false;
            }
        } else if in_double {
            if b == b'"' {
                in_double = false;
            }
        } else {
            match b {
                b'\n' if !pending.is_empty() => {
                    i = skip_heredoc_bodies(input, i + 1, &mut pending);
                    continue;
                }
                b'<' if depth > 0 => {
                    if let Some((word, _, next)) = heredoc_word_at(bytes, i) {
                        pending.push(word);
                        i = next;
                        continue;
                    }
                }
                b'\'' => in_single = true,
                b'"' => in_double = true,
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some((input[start..i].to_string(), i + 1));
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

/// Skip the bodies of `pending` heredocs starting at line start `from`.
/// Returns the index right after the last terminator line (or the end).
fn skip_heredoc_bodies(input: &str, from: usize, pending: &mut Vec<String>) -> usize {
    let mut pos = from;
    while !pending.is_empty() && pos < input.len() {
        let end = input[pos..].find('\n').map_or(input.len(), |e| pos + e);
        if input[pos..end].trim() == pending[0] {
            pending.remove(0);
        }
        pos = (end + 1).min(input.len());
        if pending.is_empty() {
            // Resume scanning at the terminator line's newline so the caller
            // still sees the line break.
            return end.min(input.len());
        }
    }
    pending.clear();
    pos
}

/// If `bytes[i..]` starts a heredoc operator (`<<WORD`, `<<-'WORD'`, not the
/// `<<<` here-string), return `(terminator, quoted, index_after_word)`.
fn heredoc_word_at(bytes: &[u8], i: usize) -> Option<(String, bool, usize)> {
    let len = bytes.len();
    if i + 1 >= len || bytes[i] != b'<' || bytes[i + 1] != b'<' {
        return None;
    }
    if i + 2 < len && bytes[i + 2] == b'<' {
        return None;
    }
    let mut j = i + 2;
    if j < len && bytes[j] == b'-' {
        j += 1;
    }
    while j < len && (bytes[j] == b' ' || bytes[j] == b'\t') {
        j += 1;
    }
    let mut word = Vec::new();
    let mut quoted = false;
    if j < len && bytes[j] == b'\\' {
        quoted = true;
        j += 1;
    }
    if j < len && (bytes[j] == b'\'' || bytes[j] == b'"') {
        quoted = true;
        let q = bytes[j];
        j += 1;
        while j < len && bytes[j] != q {
            word.push(bytes[j]);
            j += 1;
        }
        if j < len {
            j += 1;
        }
    } else {
        while j < len
            && !bytes[j].is_ascii_whitespace()
            && !matches!(bytes[j], b';' | b'|' | b'&' | b'>' | b'<' | b'(' | b')')
        {
            word.push(bytes[j]);
            j += 1;
        }
    }
    if word.is_empty() {
        return None;
    }
    Some((String::from_utf8_lossy(&word).into_owned(), quoted, j))
}

/// Given index of an opening backtick, return `(inner, index_after_close)`.
fn read_backtick(input: &str, open: usize) -> Option<(String, usize)> {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut i = open + 1;
    let start = i;
    while i < len {
        if bytes[i] == b'`' {
            return Some((input[start..i].to_string(), i + 1));
        }
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        i += 1;
    }
    None
}

// ---------------------------------------------------------------------------
// Heredoc-aware line splitting
// ---------------------------------------------------------------------------

struct LogicalLine {
    /// The command text of the line (without the heredoc body).
    text: String,
    /// Heredoc bodies attached to this line (only meaningful when the command
    /// is a shell; otherwise they are ignored as data).
    heredoc_bodies: Vec<String>,
    /// Per body: whether its delimiter was quoted (`<<'EOF'`), i.e. the body
    /// is literal text with no `$( … )` expansion.
    heredoc_quoted: Vec<bool>,
}

/// Open-construct tracker used to decide whether a newline ends a command:
/// a newline inside quotes, backticks or `$( … )` is part of the word.
#[derive(Clone, Default)]
struct OpenState {
    in_single: bool,
    /// The last fed line ended inside a `#` comment.
    in_comment: bool,
    /// The last fed line ended with an unescaped `\` (outside single quotes).
    trailing_backslash: bool,
    stack: Vec<OpenCtx>,
    /// Terminators of heredocs opened inside `$( … )` whose bodies follow.
    pending_heredocs: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OpenCtx {
    Double,
    Paren,
    Backtick,
    /// `(( … ))` / `$(( … ))` arithmetic.
    Arith,
}

impl OpenState {
    /// Whether the last line ends with a line continuation.
    const fn continues(&self) -> bool {
        self.trailing_backslash && !self.in_single && !self.in_comment
    }

    const fn is_open(&self) -> bool {
        self.in_single || !self.stack.is_empty() || !self.pending_heredocs.is_empty()
    }

    /// Feed one physical line (without its trailing newline).
    fn feed(&mut self, line: &str) {
        self.in_comment = false;
        self.trailing_backslash = false;
        // Inside a heredoc body: the line is data until the terminator.
        if let Some(term) = self.pending_heredocs.first() {
            if line.trim() == term {
                self.pending_heredocs.remove(0);
            }
            return;
        }
        // Byte-wise (all syntax characters are ASCII), so indices line up
        // with `heredoc_word_at`.
        let bytes = line.as_bytes();
        let chars: Vec<char> = bytes.iter().map(|b| char::from(*b)).collect();
        let mut prev = ' ';
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            let next = chars.get(i + 1).copied();
            if self.in_single {
                if c == '\'' {
                    self.in_single = false;
                }
                prev = c;
                i += 1;
                continue;
            }
            match self.stack.last().copied() {
                Some(OpenCtx::Double) => match c {
                    '\\' if next.is_none() => self.trailing_backslash = true,
                    '\\' => i += 1,
                    '"' => {
                        self.stack.pop();
                    }
                    '$' if next == Some('(') => {
                        self.stack.push(OpenCtx::Paren);
                        i += 1;
                    }
                    '`' => self.stack.push(OpenCtx::Backtick),
                    _ => {}
                },
                Some(OpenCtx::Arith) => {
                    if c == ')' && next == Some(')') {
                        self.stack.pop();
                        i += 1;
                    }
                }
                Some(OpenCtx::Backtick) => match c {
                    '\\' => i += 1,
                    '`' => {
                        self.stack.pop();
                    }
                    _ => {}
                },
                top => match c {
                    '\\' if next.is_none() => self.trailing_backslash = true,
                    '\\' => i += 1,
                    '\'' => self.in_single = true,
                    '"' => self.stack.push(OpenCtx::Double),
                    '`' => self.stack.push(OpenCtx::Backtick),
                    '$' if next == Some('(') && chars.get(i + 2) == Some(&'(') => {
                        self.stack.push(OpenCtx::Arith);
                        i += 2;
                    }
                    '(' if next == Some('(') && !prev.is_alphanumeric() => {
                        self.stack.push(OpenCtx::Arith);
                        i += 1;
                    }
                    '$' if next == Some('(') => {
                        self.stack.push(OpenCtx::Paren);
                        i += 1;
                    }
                    // Process substitution `<( … )` / `>( … )`.
                    '<' | '>' if next == Some('(') && !matches!(prev, '<' | '>') => {
                        self.stack.push(OpenCtx::Paren);
                        i += 1;
                    }
                    '(' if top == Some(OpenCtx::Paren) => self.stack.push(OpenCtx::Paren),
                    '<' if top == Some(OpenCtx::Paren) => {
                        if let Some((word, _, next)) = heredoc_word_at(bytes, i) {
                            self.pending_heredocs.push(word);
                            prev = ' ';
                            i = next;
                            continue;
                        }
                    }
                    ')' if top == Some(OpenCtx::Paren) => {
                        self.stack.pop();
                    }
                    '#' if matches!(prev, ' ' | '\t' | ';' | '&' | '|' | '(')
                        && hash_starts_comment() =>
                    {
                        // Comment: the rest of the physical line is ignored.
                        self.in_comment = true;
                        return;
                    }
                    _ => {}
                },
            }
            prev = c;
            i += 1;
        }
    }
}

/// Split input into logical lines. Physical lines are joined while a quote,
/// backtick or `$( … )` is open (only when it is closed later — otherwise each
/// physical line stands alone, which fails closed). When a line opens a
/// heredoc (`<<WORD`, `<<'WORD'`, `<<-WORD`), the following lines up to the
/// terminator are collected as the heredoc body and detached from the
/// command text.
fn split_heredoc_lines(input: &str) -> Vec<LogicalLine> {
    let raw_lines: Vec<&str> = input.split('\n').collect();
    let mut result = Vec::new();
    let mut idx = 0;
    while idx < raw_lines.len() {
        let mut line = raw_lines[idx].to_string();
        let mut state = OpenState::default();
        state.feed(raw_lines[idx]);
        loop {
            // `\` + newline outside single quotes is a line continuation:
            // both characters are removed (`git push \⏎ --force`).
            if idx + 1 < raw_lines.len() && state.continues() {
                line.pop();
                idx += 1;
                line.push_str(raw_lines[idx]);
                state.feed(raw_lines[idx]);
                continue;
            }
            if !state.is_open() || idx + 1 >= raw_lines.len() {
                break;
            }
            // An open quote / `$(` / backtick: the newline is part of the
            // word — but only when the construct is closed later (bounded
            // lookahead); otherwise each physical line stands alone, which
            // fails closed.
            let mut st = state.clone();
            let mut j = idx;
            let mut joined = line.clone();
            let mut closed = false;
            while j + 1 < raw_lines.len() && j - idx < MAX_JOIN_LINES {
                j += 1;
                if st.continues() {
                    joined.pop();
                } else {
                    joined.push('\n');
                }
                joined.push_str(raw_lines[j]);
                st.feed(raw_lines[j]);
                if !st.is_open() {
                    closed = true;
                    break;
                }
            }
            if !closed {
                break;
            }
            line = joined;
            state = st;
            idx = j;
        }
        idx += 1;
        let delims = heredoc_delimiters(&line);
        if delims.is_empty() {
            result.push(LogicalLine {
                text: line,
                heredoc_bodies: Vec::new(),
                heredoc_quoted: Vec::new(),
            });
            continue;
        }
        // Collect bodies for each heredoc opened on this line (sequentially).
        let mut bodies = Vec::new();
        let mut quoted = Vec::new();
        for (delim, is_quoted) in delims {
            let mut body = String::new();
            while idx < raw_lines.len() {
                let candidate = raw_lines[idx];
                idx += 1;
                if candidate.trim() == delim {
                    break;
                }
                body.push_str(candidate);
                body.push('\n');
            }
            bodies.push(body);
            quoted.push(is_quoted);
        }
        result.push(LogicalLine {
            text: line,
            heredoc_bodies: bodies,
            heredoc_quoted: quoted,
        });
    }
    result
}

/// Return the heredoc terminator word(s) opened on a line, in order, with
/// whether the terminator was quoted.
/// Handles `<<EOF`, `<< EOF`, `<<-EOF`, `<<'EOF'`, `<<"EOF"`, `<<\EOF`.
/// Ignores `<<<` (here-string, not a heredoc).
#[allow(clippy::too_many_lines)]
fn heredoc_delimiters(line: &str) -> Vec<(String, bool)> {
    let mut delims = Vec::new();
    let bytes = line.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    let mut in_single = false;
    let mut in_double = false;
    let mut in_backtick = false;
    // `$( … )` nesting: heredocs opened inside a substitution belong to it
    // (its body is already part of this logical line).
    let mut subst = 0usize;
    // `(( … ))` / `$(( … ))` arithmetic: `<<` is a shift, not a heredoc.
    let mut arith = 0usize;
    while i < len {
        let b = bytes[i];
        if in_single {
            if b == b'\'' {
                in_single = false;
            }
            i += 1;
            continue;
        }
        if in_double {
            if b == b'"' {
                in_double = false;
            }
            i += 1;
            continue;
        }
        if in_backtick {
            if b == b'`' {
                in_backtick = false;
            }
            i += 1;
            continue;
        }
        match b {
            b'\\' => i += 2,
            b'\'' => {
                in_single = true;
                i += 1;
            }
            b'"' => {
                in_double = true;
                i += 1;
            }
            b'`' => {
                in_backtick = true;
                i += 1;
            }
            b'(' if i + 1 < len && bytes[i + 1] == b'(' => {
                arith += 1;
                i += 2;
            }
            b')' if arith > 0 && i + 1 < len && bytes[i + 1] == b')' => {
                arith -= 1;
                i += 2;
            }
            b'$' if i + 1 < len && bytes[i + 1] == b'(' => {
                subst += 1;
                i += 2;
            }
            // Process substitution `<( … )` / `>( … )`.
            b'<' | b'>'
                if i + 1 < len
                    && bytes[i + 1] == b'('
                    && (i == 0 || !matches!(bytes[i - 1], b'<' | b'>')) =>
            {
                subst += 1;
                i += 2;
            }
            b'(' if subst > 0 => {
                subst += 1;
                i += 1;
            }
            b')' if subst > 0 => {
                subst -= 1;
                i += 1;
            }
            b'<' if subst > 0 || arith > 0 => i += 1,
            b'<' if i + 1 < len && bytes[i + 1] == b'<' => {
                // `<<<` is a here-string, not a heredoc.
                if i + 2 < len && bytes[i + 2] == b'<' {
                    i += 3;
                    continue;
                }
                let mut j = i + 2;
                // optional `-`
                if j < len && bytes[j] == b'-' {
                    j += 1;
                }
                while j < len && (bytes[j] == b' ' || bytes[j] == b'\t') {
                    j += 1;
                }
                // read the delimiter word (may be quoted)
                let mut word = String::new();
                let mut quoted = false;
                if j < len && bytes[j] == b'\\' {
                    quoted = true;
                    j += 1;
                }
                if j < len && (bytes[j] == b'\'' || bytes[j] == b'"') {
                    quoted = true;
                    let q = bytes[j];
                    j += 1;
                    while j < len && bytes[j] != q {
                        word.push(bytes[j] as char);
                        j += 1;
                    }
                    if j < len {
                        j += 1; // closing quote
                    }
                } else {
                    while j < len
                        && !bytes[j].is_ascii_whitespace()
                        && bytes[j] != b';'
                        && bytes[j] != b'|'
                        && bytes[j] != b'&'
                        && bytes[j] != b'>'
                        && bytes[j] != b'<'
                    {
                        word.push(bytes[j] as char);
                        j += 1;
                    }
                }
                if !word.is_empty() {
                    delims.push((word, quoted));
                }
                i = j;
            }
            _ => i += 1,
        }
    }
    delims
}

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

/// Lex a single line into words and operators. Returns `Err(())` on unbalanced
/// quotes so the caller can fall back conservatively.
#[allow(clippy::too_many_lines, unused_assignments)]
fn lex(line: &str) -> Result<Vec<Lexeme>, ()> {
    let mut lexemes = Vec::new();
    let chars: Vec<char> = line.chars().collect();
    let len = chars.len();
    let mut i = 0;

    // Current word being built.
    let mut cur_raw = String::new();
    let mut cur_masked = String::new();
    let mut has_word = false;
    // Open brace groups (`{ …`, zsh `{cmd…`), and whether the current word
    // ends with an unquoted `}` (zsh closes a group glued to the last word:
    // `{rm -rf src}`).
    let mut brace_depth = 0usize;
    let mut tail_brace = false;

    macro_rules! flush_word {
        () => {
            if has_word {
                let closes = tail_brace
                    && brace_depth > 0
                    && cur_raw.matches('}').count() > cur_raw.matches('{').count();
                if closes {
                    cur_raw.pop();
                    cur_masked.pop();
                }
                let raw = std::mem::take(&mut cur_raw);
                let masked = std::mem::take(&mut cur_masked);
                let after_group = matches!(lexemes.last(), Some(Lexeme::Op(op)) if op == "}");
                if raw == "always" && after_group && !closes {
                    // zsh `{ … } always { … }`: two groups in sequence.
                    lexemes.push(Lexeme::Op(";".to_string()));
                } else if !raw.is_empty() || !closes {
                    lexemes.push(Lexeme::Word(Word { raw, masked }));
                }
                if closes {
                    lexemes.push(Lexeme::Op("}".to_string()));
                    brace_depth -= 1;
                }
                has_word = false;
            }
            tail_brace = false;
        };
    }

    while i < len {
        let c = chars[i];
        match c {
            // Comment: `#` only starts a comment at a word boundary.
            '#' if !has_word && hash_starts_comment() => {
                // Rest of the line is a comment.
                break;
            }
            ' ' | '\t' | '\r' => {
                flush_word!();
                i += 1;
            }
            '\n' => {
                // A newline outside quotes separates commands.
                flush_word!();
                lexemes.push(Lexeme::Op("\n".to_string()));
                i += 1;
            }
            // `$IFS` / `${IFS}` expand to whitespace (word splitting):
            // `rm${IFS}-rf${IFS}/` is `rm -rf /`.
            '$' if ifs_len(&chars, i) > 0 => {
                flush_word!();
                i += ifs_len(&chars, i);
            }
            '\\' if i + 1 < len => {
                // Escaped character → literal.
                tail_brace = false;
                cur_raw.push(chars[i + 1]);
                cur_masked.push(mask_char(chars[i + 1]));
                has_word = true;
                i += 2;
            }
            '\\' => {
                // Trailing backslash (line continuation) — drop it.
                i += 1;
            }
            '\'' => {
                // Single-quoted: literal until next `'`.
                has_word = true;
                tail_brace = false;
                i += 1;
                let mut found = false;
                while i < len {
                    if chars[i] == '\'' {
                        found = true;
                        i += 1;
                        break;
                    }
                    cur_raw.push(chars[i]);
                    cur_masked.push(mask_char(chars[i]));
                    i += 1;
                }
                if !found {
                    return Err(());
                }
            }
            '"' => {
                // Double-quoted: allow `\"`, `\\`, `\$`, `` \` ``.
                has_word = true;
                tail_brace = false;
                i += 1;
                let mut found = false;
                while i < len {
                    let d = chars[i];
                    if d == '"' {
                        found = true;
                        i += 1;
                        break;
                    }
                    if d == '$' && i + 1 < len && chars[i + 1] == '(' {
                        cur_raw.push('$');
                        cur_masked.push('$');
                        i = copy_balanced(&chars, i + 1, true, &mut cur_raw, &mut cur_masked);
                        continue;
                    }
                    if d == '\\' && i + 1 < len {
                        let n = chars[i + 1];
                        if n == '"' || n == '\\' || n == '$' || n == '`' {
                            cur_raw.push(n);
                            cur_masked.push(mask_char(n));
                            i += 2;
                            continue;
                        }
                    }
                    cur_raw.push(d);
                    cur_masked.push(mask_char(d));
                    i += 1;
                }
                if !found {
                    return Err(());
                }
            }
            '$' if i + 1 < len && chars[i + 1] == '\'' => {
                // ANSI-C quoting `$'…'`.
                has_word = true;
                tail_brace = false;
                i += 2;
                let mut found = false;
                while i < len {
                    let d = chars[i];
                    if d == '\'' {
                        found = true;
                        i += 1;
                        break;
                    }
                    if d == '\\' && i + 1 < len {
                        let (ch, adv) = ansi_c_escape(&chars, i + 1);
                        cur_raw.push(ch);
                        cur_masked.push(mask_char(ch));
                        i += 1 + adv;
                        continue;
                    }
                    cur_raw.push(d);
                    cur_masked.push(mask_char(d));
                    i += 1;
                }
                if !found {
                    return Err(());
                }
            }
            '$' if i + 1 < len && chars[i + 1] == '"' => {
                // Locale double quote `$"…"` — treat like double quote.
                i += 1; // skip `$`, fall through to `"` next iteration
            }
            ';' => {
                flush_word!();
                lexemes.push(Lexeme::Op(";".to_string()));
                i += 1;
            }
            '>' | '<' => {
                // Redirection operator. A word made only of digits right before
                // it is a file-descriptor prefix (`2>`).
                let mut op = String::new();
                if has_word && cur_raw.chars().all(|c| c.is_ascii_digit()) {
                    op.push_str(&cur_raw);
                    cur_raw.clear();
                    cur_masked.clear();
                    has_word = false;
                } else {
                    flush_word!();
                }
                op.push(c);
                i += 1;
                while i < len && op.len() < 6 && matches!(chars[i], '>' | '<' | '|' | '&') {
                    // `>>`, `>|`, `>&`, `<<`, `<<<`, `<>`, `<&`
                    if chars[i] == '|' && !op.ends_with('>') {
                        break;
                    }
                    if chars[i] == '&' && i + 1 < len && chars[i + 1] == '&' {
                        break;
                    }
                    op.push(chars[i]);
                    i += 1;
                }
                if op.ends_with("<<") && i < len && chars[i] == '-' {
                    op.push('-');
                    i += 1;
                }
                lexemes.push(Lexeme::Word(Word {
                    raw: op.clone(),
                    masked: op,
                }));
            }
            '&' if i + 1 < len && chars[i + 1] == '>' => {
                flush_word!();
                let mut op = String::from("&>");
                i += 2;
                if i < len && chars[i] == '>' {
                    op.push('>');
                    i += 1;
                }
                lexemes.push(Lexeme::Word(Word {
                    raw: op.clone(),
                    masked: op,
                }));
            }
            '&' => {
                flush_word!();
                if i + 1 < len && chars[i + 1] == '&' {
                    lexemes.push(Lexeme::Op("&&".to_string()));
                    i += 2;
                } else {
                    lexemes.push(Lexeme::Op("&".to_string()));
                    i += 1;
                }
            }
            '|' => {
                flush_word!();
                if i + 1 < len && chars[i + 1] == '|' {
                    lexemes.push(Lexeme::Op("||".to_string()));
                    i += 2;
                } else {
                    lexemes.push(Lexeme::Op("|".to_string()));
                    i += 1;
                }
            }
            // The optional `(` before a `case` pattern (`case x in (a) cmd
            // ;; esac`): dropped, so the pattern reads like `a)` and the
            // command after it starts a new simple command.
            '(' if !has_word && case_pattern_position(&lexemes) => {
                flush_word!();
                i += 1;
            }
            // zsh `f () { … }`: a function header with a space before `()`.
            '(' if !has_word
                && chars.get(i + 1) == Some(&')')
                && function_name_before(&lexemes)
                && body_follows_at(&chars, i + 2) =>
            {
                if let Some(Lexeme::Word(w)) = lexemes.last_mut() {
                    w.raw.push_str("()");
                    w.masked.push_str("()");
                }
                lexemes.push(Lexeme::Op(FUNC_HEADER_OP.to_string()));
                i += 2;
            }
            // zsh `for x (a b) …` / `for x y (1 2) {…}` / `foreach x (a)`:
            // the list is one word (not a subshell).
            '(' if !has_word && zsh_for_list_position(&lexemes) => {
                tail_brace = false;
                i = copy_balanced(&chars, i, false, &mut cur_raw, &mut cur_masked);
                has_word = true;
            }
            // zsh glob group in argument position: `rm -rf (src|build)`,
            // `(.ssh|data)`. A whole word, not a subshell.
            '(' if !has_word
                && matches!(lexemes.last(), Some(Lexeme::Word(w)) if !is_redirect_op(&w.raw))
                && !at_command_position(&lexemes)
                && glob_group_len(&chars, i).is_some() =>
            {
                let n = glob_group_len(&chars, i).unwrap_or(1);
                for &g in &chars[i..i + n] {
                    cur_raw.push(g);
                    cur_masked.push(g);
                }
                has_word = true;
                tail_brace = false;
                i += n;
            }
            '(' if !has_word => {
                flush_word!();
                lexemes.push(Lexeme::SubOpen);
                i += 1;
            }
            '(' => {
                // `(` glued to a word (`db.users.drop()`, `f()`, `arr=(a b)`)
                // is not a subshell: copy the balanced region literally. A
                // `$(…)` substitution is code, so its spaces stay real.
                let is_subst = cur_raw.ends_with('$');
                tail_brace = false;
                let before = cur_raw.len();
                i = copy_balanced(&chars, i, is_subst, &mut cur_raw, &mut cur_masked);
                // `name()` is a function definition header: its body
                // (`{ …; }` / `( … )`) is a separate command list.
                // (A bare `:` name is kept glued so the fork-bomb pattern
                // `:(){ :|:& };:` still matches as written.)
                let name = &cur_raw[..before];
                // Only a header when a body follows (`f() { …; }`, `f() (…)`,
                // `f() if …`): `now() WHERE …` in SQL text is a call.
                let body_follows = body_follows_at(&chars, i);
                if !is_subst
                    && body_follows
                    && &cur_raw[before..] == "()"
                    && name.chars().any(char::is_alphanumeric)
                    && name
                        .chars()
                        .all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | ':' | '.'))
                {
                    flush_word!();
                    lexemes.push(Lexeme::Op(FUNC_HEADER_OP.to_string()));
                }
            }
            ')' => {
                flush_word!();
                lexemes.push(Lexeme::SubClose);
                i += 1;
            }
            // `{` / `}` are brace-group delimiters only as standalone words
            // (`{ cmd; }`); `{}` (find/xargs placeholder) is a normal word.
            '{' | '}'
                if !has_word
                    && chars
                        .get(i + 1)
                        .is_none_or(|n| n.is_whitespace() || *n == ';') =>
            {
                // Brace group boundary: a command separator (also delimits a
                // function body, see [`function_body_owners`]).
                flush_word!();
                if c == '{' {
                    brace_depth += 1;
                } else {
                    brace_depth = brace_depth.saturating_sub(1);
                }
                lexemes.push(Lexeme::Op(c.to_string()));
                i += 1;
            }
            // zsh opens a brace group even when `{` is glued to the next
            // word (`{rm -rf /;}`), as long as it is in command position and
            // not a brace expansion (`{a,b}`, `{1..3}`) or `{}`.
            '{' if !has_word && at_command_position(&lexemes) && !is_brace_expansion(&chars, i) => {
                brace_depth += 1;
                lexemes.push(Lexeme::Op("{".to_string()));
                i += 1;
            }
            _ => {
                cur_raw.push(c);
                cur_masked.push(c);
                has_word = true;
                tail_brace = c == '}';
                i += 1;
            }
        }
    }
    flush_word!();
    Ok(lexemes)
}

/// Copy a balanced `( … )` region starting at `start` (which must be `(`)
/// into the current word. Returns the index after the closing `)` (or the end
/// of input). When `keep_spaces` is false, whitespace is masked.
fn copy_balanced(
    chars: &[char],
    start: usize,
    keep_spaces: bool,
    raw: &mut String,
    masked: &mut String,
) -> usize {
    let mut depth = 0usize;
    let mut i = start;
    while i < chars.len() {
        let d = chars[i];
        if d == '(' {
            depth += 1;
        } else if d == ')' {
            depth = depth.saturating_sub(1);
        }
        raw.push(d);
        masked.push(if keep_spaces { d } else { mask_char(d) });
        i += 1;
        if depth == 0 {
            break;
        }
    }
    i
}

/// Length of a `$IFS` / `${IFS}` reference starting at `chars[i]` (`$`), or 0.
fn ifs_len(chars: &[char], i: usize) -> usize {
    let rest = &chars[i + 1..];
    if rest.starts_with(&['{', 'I', 'F', 'S', '}']) {
        6
    } else if rest.starts_with(&['I', 'F', 'S'])
        && rest
            .get(3)
            .is_none_or(|c| !(c.is_ascii_alphanumeric() || *c == '_'))
    {
        4
    } else {
        0
    }
}

/// Whether a function body (`{ …`, `( …`, `if …`, …, or nothing yet)
/// follows `chars[i..]`.
fn body_follows_at(chars: &[char], i: usize) -> bool {
    let start = chars
        .get(i..)
        .and_then(|rest| rest.iter().position(|c| !c.is_whitespace()))
        .map_or(chars.len(), |p| i + p);
    let r: String = chars[start..chars.len().min(start + 8)].iter().collect();
    r.is_empty()
        || r.starts_with(['{', '('])
        || ["if", "for", "while", "until", "case", "select", "[["]
            .iter()
            .any(|k| {
                r.strip_prefix(k)
                    .is_some_and(|t| t.is_empty() || t.starts_with(char::is_whitespace))
            })
}

/// Whether the last lexeme is a plain name in command position (`f` in
/// `f () { … }`).
fn function_name_before(lexemes: &[Lexeme]) -> bool {
    let Some((Lexeme::Word(w), before)) = lexemes.split_last() else {
        return false;
    };
    w.raw.chars().any(char::is_alphanumeric)
        && w.raw
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | ':' | '.'))
        && !matches!(
            w.raw.as_str(),
            "in" | "do" | "then" | "else" | "esac" | "done" | "fi" | "function"
        )
        && (at_command_position(before)
            // `function f () { … }` (zsh, bash); zsh `function f g () { … }`
            // defines every name.
            || {
                let names = before
                    .iter()
                    .rev()
                    .take_while(|l| matches!(l, Lexeme::Word(n) if is_function_name(&n.raw)))
                    .count();
                matches!(before[..before.len() - names].split_last(),
                    Some((Lexeme::Word(f), rest)) if f.raw == "function" && at_command_position(rest))
            })
}

/// Whether a word can name a function.
fn is_function_name(w: &str) -> bool {
    w.chars().any(char::is_alphanumeric)
        && w.chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | ':' | '.'))
        && w != "function"
}

/// Separator between the names of a zsh multi-name function definition
/// (`function f g () {…}`) in a body owner.
const FUNC_NAME_SEP: char = '\u{4}';

/// Whether a `(` lexed now opens the list of a zsh `for NAME… (LIST)` /
/// `foreach NAME (LIST)` loop: the lexemes end with `for` / `foreach` (in
/// command position) and one or more variable names.
fn zsh_for_list_position(lexemes: &[Lexeme]) -> bool {
    let mut n = lexemes.len();
    let mut names = 0usize;
    while n > 0 {
        let Lexeme::Word(w) = &lexemes[n - 1] else {
            return false;
        };
        if matches!(w.raw.as_str(), "for" | "foreach") {
            return names > 0 && at_command_position(&lexemes[..n - 1]);
        }
        if w.raw.is_empty()
            || !w.raw.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            || w.raw.starts_with(|c: char| c.is_ascii_digit())
            || names >= 16
        {
            return false;
        }
        names += 1;
        n -= 1;
    }
    false
}

/// Whether a `(` lexed now opens a `case` pattern: right after `case WORD
/// in` or after a `;;` / `;&` / `;;&` terminator (newlines allowed between).
fn case_pattern_position(lexemes: &[Lexeme]) -> bool {
    let mut n = lexemes.len();
    while n > 0 && matches!(&lexemes[n - 1], Lexeme::Op(op) if op == "\n") {
        n -= 1;
    }
    let word = |i: usize| match lexemes.get(i) {
        Some(Lexeme::Word(w)) => Some(w.raw.as_str()),
        _ => None,
    };
    let op = |i: usize| match lexemes.get(i) {
        Some(Lexeme::Op(o)) => Some(o.as_str()),
        _ => None,
    };
    if n >= 3 && word(n - 1) == Some("in") && word(n - 3) == Some("case") {
        return true;
    }
    n >= 2 && op(n - 2) == Some(";") && matches!(op(n - 1), Some(";" | "&"))
}

/// Whether the `)` that is the last lexeme closes a `case` pattern (it has
/// no matching `(`, and a `case` came before), or an arithmetic `for ((…))`
/// header. Both are followed by a command.
fn closes_case_pattern_or_arith_for(lexemes: &[Lexeme]) -> bool {
    let n = lexemes.len();
    let mut depth = 0usize;
    let mut k = n;
    while k > 0 {
        k -= 1;
        match &lexemes[k] {
            Lexeme::SubClose => depth += 1,
            Lexeme::SubOpen => {
                depth -= 1;
                if depth == 0 {
                    // `for ((…))`, zsh `while ((…))` / `until ((…))`: `((`
                    // right after the keyword, `))` at the end.
                    return k >= 1
                        && matches!(lexemes.get(k + 1), Some(Lexeme::SubOpen))
                        && matches!(&lexemes[k - 1], Lexeme::Word(w)
                            if matches!(w.raw.as_str(), "for" | "while" | "until"))
                        && n >= 2
                        && matches!(lexemes[n - 2], Lexeme::SubClose);
                }
            }
            _ => {}
        }
    }
    lexemes
        .iter()
        .any(|l| matches!(l, Lexeme::Word(w) if w.raw == "case"))
}

/// Whether the next word lexed after `lexemes` is in command position (the
/// start of a simple command).
fn at_command_position(lexemes: &[Lexeme]) -> bool {
    let word = |i: usize| match lexemes.get(i) {
        Some(Lexeme::Word(w)) => Some(w.raw.as_str()),
        _ => None,
    };
    let n = lexemes.len();
    match lexemes.last() {
        None | Some(Lexeme::Op(_) | Lexeme::SubOpen) => true,
        Some(Lexeme::Word(w)) => {
            matches!(
                w.raw.as_str(),
                "then" | "do" | "else" | "elif" | "if" | "while" | "until" | "!" | "time"
                    | "coproc"
                    // zsh short forms: `if [[ … ]] { … }`, `while (( … )) { … }`.
                    | "]]"
            ) || (
                // zsh `foreach x (a) { … }` / `for x y (1 2) { … }` (the list
                // is one word).
                w.raw.starts_with('(')
                    && w.raw.ends_with(')')
                    && n >= 3
                    && zsh_for_list_position(&lexemes[..n - 1])
            ) || (
                // zsh `repeat N { … }`.
                n >= 2
                    && word(n - 2) == Some("repeat")
                    && (n == 2 || at_command_position(&lexemes[..n - 2]))
            )
        }
        Some(Lexeme::SubClose) if closes_case_pattern_or_arith_for(lexemes) => true,
        Some(Lexeme::SubClose) => {
            // zsh anonymous function `() { … }` and `foreach x (a b) { … }` /
            // `for x (a b) { … }`.
            let Some(open) = lexemes.iter().rposition(|l| matches!(l, Lexeme::SubOpen)) else {
                return false;
            };
            if open == n - 2 {
                return open == 0 || at_command_position(&lexemes[..open]);
            }
            open >= 2
                && matches!(word(open - 2), Some("foreach" | "for"))
                && word(open - 1).is_some()
        }
    }
}

/// Length of a zsh glob group (`(src|build)`) starting at `chars[open]`
/// (`(`): balanced parentheses with no whitespace or quotes inside, and not
/// empty.
fn glob_group_len(chars: &[char], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (k, &c) in chars[open..].iter().enumerate() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return (k > 1).then_some(k + 1);
                }
            }
            c if c.is_whitespace() || matches!(c, '\'' | '"' | ';' | '&' | '`' | '$') => {
                return None;
            }
            _ => {}
        }
    }
    None
}

/// Whether the `{` at `chars[open]` starts a brace expansion (`{a,b}`,
/// `{1..3}`) or the `{}` placeholder, i.e. a matching `}` with a top-level
/// `,` / `..` (or nothing) inside comes before the end of the word.
fn is_brace_expansion(chars: &[char], open: usize) -> bool {
    let mut depth = 0usize;
    let mut sep = false;
    let mut i = open;
    while let Some(&c) = chars.get(i) {
        match c {
            '{' => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return sep || i == open + 1;
                }
            }
            ',' if depth == 1 => sep = true,
            '.' if depth == 1 && chars.get(i + 1) == Some(&'.') => sep = true,
            c if c.is_whitespace() || matches!(c, ';' | '&' | '|' | '<' | '>') => return false,
            _ => {}
        }
        i += 1;
    }
    false
}

/// Replace whitespace with the sentinel, leave everything else untouched.
const fn mask_char(c: char) -> char {
    if c.is_whitespace() {
        WS_SENTINEL
    } else {
        c
    }
}

/// Minimal ANSI-C escape decoding for `$'…'`. Returns `(char, extra_consumed)`.
fn ansi_c_escape(chars: &[char], idx: usize) -> (char, usize) {
    // `\xHH`, `\uHHHH`, `\UHHHHHHHH` and `\NNN` (octal): the code point.
    let numeric = |start: usize, max: usize, radix: u32| -> Option<(char, usize)> {
        let digits: String = chars[start..]
            .iter()
            .take(max)
            .take_while(|c| c.is_digit(radix))
            .collect();
        if digits.is_empty() {
            return None;
        }
        let v = u32::from_str_radix(&digits, radix).ok()?;
        Some((char::from_u32(v)?, start - idx + digits.len()))
    };
    let c = chars[idx];
    let decoded = match c {
        'x' => numeric(idx + 1, 2, 16),
        'u' => numeric(idx + 1, 4, 16),
        'U' => numeric(idx + 1, 8, 16),
        '0'..='7' => numeric(idx, 3, 8),
        // `\cX`: control character.
        'c' => chars
            .get(idx + 1)
            .and_then(|x| char::from_u32(u32::from(*x) & 0x1f))
            .map(|ch| (ch, 2)),
        _ => None,
    };
    if let Some(d) = decoded {
        return d;
    }
    let ch = match c {
        'n' => '\n',
        't' => '\t',
        'r' => '\r',
        'a' => '\u{7}',
        'b' => '\u{8}',
        'e' | 'E' => '\u{1b}',
        'f' => '\u{c}',
        'v' => '\u{b}',
        other => other,
    };
    (ch, 1)
}

/// Byte length of a UTF-8 code point from its leading byte.
const fn utf8_len(b: u8) -> usize {
    if b < 0x80 {
        1
    } else if b >> 5 == 0b110 {
        2
    } else if b >> 4 == 0b1110 {
        3
    } else {
        4
    }
}

// ---------------------------------------------------------------------------
// Grouping + normalization
// ---------------------------------------------------------------------------

/// Operator emitted by the lexer right after a `name()` function header.
const FUNC_HEADER_OP: &str = "()";

/// For every lexeme, the name of the function whose body (`name() { … }` /
/// `function name { … }`) it belongs to, if any. Bodies are definitions:
/// they only run when the function is called.
fn function_body_owners(lexemes: &[Lexeme]) -> Vec<Option<String>> {
    let mut owners = vec![None; lexemes.len()];
    let mut pending: Option<String> = None;
    // (function name, brace depth inside its body)
    let mut frame: Option<(String, usize)> = None;
    let mut words_since_op: Vec<&str> = Vec::new();
    for (i, lx) in lexemes.iter().enumerate() {
        if let Some((name, depth)) = frame.as_mut() {
            owners[i] = Some(name.clone());
            match lx {
                Lexeme::Op(op) if op == "{" => *depth += 1,
                Lexeme::Op(op) if op == "}" => {
                    *depth -= 1;
                    if *depth == 0 {
                        frame = None;
                    }
                }
                _ => {}
            }
            continue;
        }
        match lx {
            Lexeme::Word(w) => words_since_op.push(w.raw.as_str()),
            Lexeme::Op(op) if op == FUNC_HEADER_OP => {
                pending = words_since_op
                    .last()
                    .and_then(|w| w.strip_suffix("()"))
                    .map(|n| n.trim_start_matches("function").trim().to_string())
                    .filter(|n| !n.is_empty());
                // zsh `function f g () {…}`: every name gets the body.
                if let (Some(last), ["function", names @ .., _]) =
                    (pending.as_ref(), words_since_op.as_slice())
                {
                    if !names.is_empty() {
                        let mut all: Vec<&str> = names.to_vec();
                        all.push(last);
                        pending = Some(all.join(&FUNC_NAME_SEP.to_string()));
                    }
                }
                owners[i].clone_from(&pending);
                words_since_op.clear();
            }
            Lexeme::Op(op) if op == "{" => {
                // `function name {`
                if pending.is_none() {
                    if let ["function", name] = words_since_op.as_slice() {
                        pending = Some((*name).to_string());
                    }
                }
                if let Some(name) = pending.take() {
                    owners[i] = Some(name.clone());
                    frame = Some((name, 1));
                }
                words_since_op.clear();
            }
            Lexeme::Op(op) if op == "\n" && pending.is_some() => {}
            _ => {
                pending = None;
                words_since_op.clear();
            }
        }
    }
    owners
}

/// Group a lexeme stream into simple commands (lists of words), splitting on
/// operators. Subshell markers `( )` are treated as separators (their contents
/// still become their own commands). Commands inside a function body carry
/// the function's name.
fn group_commands(lexemes: &[Lexeme]) -> Vec<SimpleCmd> {
    let owners = function_body_owners(lexemes);
    let mut cmds = Vec::new();
    let mut cur: Vec<Word> = Vec::new();
    let mut cur_func: Option<String> = None;
    let mut piped = false;
    let mut next_piped = false;
    let push =
        |cur: &mut Vec<Word>, piped: bool, func: Option<String>, cmds: &mut Vec<SimpleCmd>| {
            if cur.is_empty() {
                return;
            }
            let words = std::mem::take(cur);
            cmds.push(SimpleCmd {
                words,
                piped,
                func,
                next_op: String::new(),
            });
        };
    for (lx, owner) in lexemes.iter().zip(owners) {
        match lx {
            Lexeme::Word(w) => {
                if cur.is_empty() {
                    piped = next_piped;
                    next_piped = false;
                    cur_func.clone_from(&owner);
                }
                cur.push(w.clone());
            }
            Lexeme::Op(op) => {
                let before = cmds.len();
                push(&mut cur, piped, cur_func.take(), &mut cmds);
                if cmds.len() > before {
                    if let Some(last) = cmds.last_mut() {
                        last.next_op.clone_from(op);
                    }
                }
                next_piped = op == "|";
            }
            Lexeme::SubOpen | Lexeme::SubClose => {
                push(&mut cur, piped, cur_func.take(), &mut cmds);
            }
        }
    }
    push(&mut cur, piped, cur_func.take(), &mut cmds);
    cmds
}

/// A simple command and whether its stdin is the previous command's stdout.
#[derive(Clone)]
struct SimpleCmd {
    words: Vec<Word>,
    piped: bool,
    /// The function whose body this command belongs to (it only runs when
    /// the function is called).
    func: Option<String>,
    /// The operator after this command (`&&`, `;`, `|`, … or empty).
    next_op: String,
}

/// State carried across the commands of one parse: simple constant
/// propagation of `VAR=value` assignments and the directory of a preceding
/// `cd`.
#[derive(Default)]
struct ParseCtx {
    vars: std::collections::HashMap<String, String>,
    cwd: Option<String>,
    /// `alias name='value'` definitions: expanded when `name` is used later.
    aliases: std::collections::HashMap<String, String>,
    /// Function bodies: analyzed when the function is called later.
    functions: std::collections::HashMap<String, Vec<SimpleCmd>>,
    /// Functions being expanded (recursion guard).
    calling: Vec<String>,
    /// `pushd` directory stack.
    dir_stack: Vec<Option<String>>,
    /// The tracked directory is certain: the commands since the `cd` are an
    /// `&&` chain, so they only run when the `cd` succeeded.
    cwd_strict: bool,
    /// Nesting of variable-substituted commands being analyzed.
    subst_depth: usize,
    /// Files a downloader wrote earlier in the line (`curl -o F URL`):
    /// (path, download command).
    downloads: Vec<(String, String)>,
    /// Text attached to a file descriptor (`exec 3<<<'TEXT'`).
    fd_texts: Vec<(String, String)>,
    /// `trap` bodies: they run at exit, with the variables of that time.
    traps: Vec<String>,
    /// `set -e` (`-o errexit`) is on: a failing command stops the line
    /// even before `;` or a newline.
    errexit: bool,
    /// Scripts written earlier in the input (`cat > x.sh <<EOF … EOF`,
    /// `echo 'cmd' > x.sh`): (path, text). Running one runs its text.
    written: Vec<(String, String)>,
}

/// Deepest nesting of variable substitution (a value that refers to another
/// variable is expanded again, up to this depth).
const MAX_SUBST_DEPTH: usize = 4;

/// Longest tracked directory: past it the directory is unknown (keeps `cd`
/// chains linear).
const MAX_CWD_LEN: usize = 4096;

/// Maximum function / alias expansions per top-level command. Past it the
/// command is reported as too complex (fail closed) instead of expanding
/// exponentially (`f2` calls `f1` twice, which calls `f0` twice, …).
const MAX_EXPANSIONS: usize = 256;

/// Charge `bytes` of re-analyzed text to the work budget; `false` (and the
/// command flagged as too complex) once [`MAX_WORK_BYTES`] is spent.
fn take_work(bytes: usize) -> bool {
    let work = WORK.with(|w| {
        let v = w.get().saturating_add(bytes);
        w.set(v);
        v
    });
    if work > MAX_WORK_BYTES {
        TOO_COMPLEX.with(|t| t.set(true));
        return false;
    }
    true
}

/// A call made at the top of the input (not from inside a function or
/// alias) starts a fresh expansion budget: [`MAX_EXPANSIONS`] bounds the
/// calls one call leads to (`f2` calls `f1` twice, …), not how often a
/// script calls its `log` helper. The total stays bounded by the work
/// budget. Restores the outer count when dropped.
struct FreshExpansions(Option<usize>);

impl FreshExpansions {
    fn at_top(ctx: &ParseCtx) -> Self {
        Self(
            ctx.calling
                .is_empty()
                .then(|| EXPANSIONS.with(|e| e.replace(0))),
        )
    }
}

impl Drop for FreshExpansions {
    fn drop(&mut self) {
        if let Some(saved) = self.0 {
            EXPANSIONS.with(|e| e.set(saved));
        }
    }
}

/// Count one function / alias expansion; `false` once the budget is spent
/// (the command is then flagged as too complex).
fn take_expansion() -> bool {
    let n = EXPANSIONS.with(|e| {
        let v = e.get() + 1;
        e.set(v);
        v
    });
    if n > MAX_EXPANSIONS {
        TOO_COMPLEX.with(|t| t.set(true));
        return false;
    }
    true
}

/// Normalize a sequence of simple commands, tracking assignments, `cd` and
/// `echo … |` payloads between them.
#[allow(clippy::too_many_lines)]
fn process_commands(
    cmds: &[SimpleCmd],
    heredoc_bodies: &[String],
    ctx: &mut ParseCtx,
    out: &mut Vec<String>,
) {
    let mut prev: Option<Vec<Word>> = None;
    for cmd in cmds {
        let words = &cmd.words;
        // A function body is a definition: remember it for later calls.
        if let Some(ref name) = cmd.func {
            for name in name.split(FUNC_NAME_SEP) {
                ctx.functions
                    .entry(name.to_string())
                    .or_default()
                    .push(cmd.clone());
            }
            prev = None;
            continue;
        }
        // A command word built at run time: `{rm,-rf,/}` (bash brace
        // expansion), `$(echo rm) -rf /`, `` `echo rm` -rf ~ ``: analyze the
        // command it expands to.
        if let Some(text) = generated_command(words) {
            if take_expansion() && take_work(text.len()) {
                if let Ok(lexemes) = lex(&text) {
                    let mut sub = group_commands(&lexemes);
                    if let Some(last) = sub.last_mut() {
                        last.next_op.clone_from(&cmd.next_op);
                    }
                    if let Some(first) = sub.first_mut() {
                        first.piped = cmd.piped;
                    }
                    process_commands(&sub, heredoc_bodies, ctx, out);
                }
            }
            prev = None;
            continue;
        }
        // `set -e`, `set -euo pipefail`, `set -o errexit` / `set +e`.
        if words.first().is_some_and(|w| w.raw == "set") {
            let mut k = 1;
            while let Some(w) = words.get(k) {
                let r = w.raw.as_str();
                let next = words.get(k + 1).map(|n| n.raw.as_str());
                match r {
                    "-o" if next == Some("errexit") => ctx.errexit = true,
                    "+o" if next == Some("errexit") => ctx.errexit = false,
                    _ if r.starts_with('-') && !r.starts_with("--") && r[1..].contains('e') => {
                        ctx.errexit = true;
                    }
                    _ if r.starts_with('+') && r[1..].contains('e') => ctx.errexit = false,
                    _ => {}
                }
                k += 1;
            }
        }
        // fish `set NAME VALUE…` / bash `set -- WORDS…` (`"$@"`).
        if let Some((name, value)) = set_assignment(words) {
            match value {
                Some(v) => ctx.vars.insert(name, v),
                None => ctx.vars.remove(&name),
            };
            prev = None;
            continue;
        }
        // `alias name='value'`: a definition, not a command. The value is
        // analyzed where the alias is used.
        if words
            .first()
            .is_some_and(|w| program_name(&w.raw) == "alias")
        {
            for w in &words[1..] {
                if let Some((name, value)) = w.raw.split_once('=') {
                    ctx.aliases.insert(name.to_string(), value.to_string());
                }
            }
            prev = None;
            continue;
        }
        // `if f; then`, `! f`, `time f`, `while f; do`: the rest is an
        // ordinary command (aliases and functions are expanded in it too).
        let kw = words
            .iter()
            .take_while(|w| {
                matches!(
                    w.raw.as_str(),
                    "if" | "then" | "else" | "elif" | "do" | "while" | "until" | "!" | "time" | "{"
                )
            })
            .count();
        // `time -p cmd`: the POSIX option of the `time` keyword.
        let kw = if kw > 0 && words[kw - 1].raw == "time" {
            kw + words[kw..]
                .iter()
                .take_while(|w| matches!(w.raw.as_str(), "-p" | "--"))
                .count()
        } else {
            kw
        };
        // zsh `for i (1 2) cmd` / `foreach i (a) cmd`: the short loop form,
        // whose body is the command after the `(…)` list word.
        let list_at = if kw == 0 && matches!(words[0].raw.as_str(), "for" | "foreach") {
            words
                .iter()
                .position(|w| w.raw.starts_with('(') && w.raw.ends_with(')'))
                .filter(|&k| k >= 2)
        } else {
            None
        };
        let kw = match list_at {
            Some(k) if words.len() > k + 1 => {
                if k == 2 {
                    track_var_writes(&words[..3], &mut ctx.vars);
                } else {
                    // `for x y (1 2)`: the names take turns; unknown.
                    for w in &words[1..k] {
                        ctx.vars.remove(&w.raw);
                    }
                }
                k + 1
            }
            _ => kw,
        };
        if kw > 0 && kw < words.len() {
            let inner = SimpleCmd {
                words: words[kw..].to_vec(),
                piped: cmd.piped,
                func: None,
                next_op: cmd.next_op.clone(),
            };
            process_commands(std::slice::from_ref(&inner), heredoc_bodies, ctx, out);
            prev = None;
            continue;
        }
        // `trap 'CMD' SIGNAL…` runs CMD later; `eval CMD`: CMD is code. Both
        // are analyzed with the line's aliases, functions and directory.
        let first = words.first().map(|w| program_name(&w.raw));
        let code = match first.as_deref() {
            Some("trap")
                if words.len() >= 3 && words[1].raw != "-" && !words[1].raw.starts_with('-') =>
            {
                Some(words[1].raw.clone())
            }
            // `trap -- 'CMD' SIGNAL…`: `--` ends the options.
            Some("trap") if words.len() >= 4 && words[1].raw == "--" && words[2].raw != "-" => {
                Some(words[2].raw.clone())
            }
            // `x='rm -rf /'; eval "$x"`: the variable's value is the code.
            Some("eval") if words.len() >= 2 => Some(
                substitute_vars(&words[1..], &ctx.vars).unwrap_or_else(|| raw_join(&words[1..])),
            ),
            _ => None,
        };
        if let Some(code) = code {
            let is_eval = first.as_deref() == Some("eval");
            if !is_eval && ctx.traps.len() < 16 {
                ctx.traps.push(code.clone());
            }
            if is_eval {
                // `eval tmp=~`: assignments made by the code.
                if let Ok(lexemes) = lex(&code) {
                    for c in group_commands(&lexemes) {
                        for w in c.words.iter().take_while(|w| is_var_assignment(&w.raw)) {
                            if let Some((name, _)) = w.raw.split_once('=') {
                                ctx.vars.remove(name);
                            }
                        }
                        track_var_writes(&c.words, &mut ctx.vars);
                    }
                }
            }
            // `eval` text is also re-parsed below; analyzing it in this
            // context only matters when it may call a known alias/function.
            let needs_ctx = !is_eval || !ctx.functions.is_empty() || !ctx.aliases.is_empty();
            // A trap body is literal text (it cannot multiply like a
            // function calling functions): only its size is charged.
            if needs_ctx && take_work(code.len()) && (!is_eval || take_expansion()) {
                if let Ok(lexemes) = lex(&code) {
                    let sub = group_commands(&lexemes);
                    process_commands(&sub, heredoc_bodies, ctx, out);
                }
            }
            if is_eval {
                // Also the plain payload (substitutions, nested quoting).
                out.extend(parse(&code).segments);
                // `eval "$S"` with `S=$(curl …)`: runs a download.
                if let Some(fetch) = remote_fetch_command(&code) {
                    out.push(format!("eval $({fetch})"));
                }
            }
            prev = None;
            continue;
        }
        if let Some(value) = words.first().and_then(|w| ctx.aliases.get(&w.raw)) {
            let fresh = FreshExpansions::at_top(ctx);
            if !ctx.calling.contains(&words[0].raw) && take_expansion() && take_work(value.len()) {
                // An alias whose value ends in a blank also alias-expands the
                // next word (`alias s='sudo '; s r`).
                let mut text = value.clone();
                let mut rest = &words[1..];
                while text.ends_with([' ', '\t']) {
                    let Some(next) = rest.first().and_then(|w| ctx.aliases.get(&w.raw)) else {
                        break;
                    };
                    if !take_expansion() || !take_work(next.len()) {
                        break;
                    }
                    text.push_str(next);
                    rest = &rest[1..];
                }
                let expanded = format!("{text} {}", argv_join(rest));
                let name = words[0].raw.clone();
                ctx.calling.push(name);
                // Re-lex with the current context (vars, functions, cwd).
                if let Ok(lexemes) = lex(&expanded) {
                    let sub = group_commands(&lexemes);
                    process_commands(&sub, heredoc_bodies, ctx, out);
                }
                ctx.calling.pop();
                drop(fresh);
                prev = None;
                continue;
            }
            drop(fresh);
        }
        // Calling a function defined earlier: analyze its body, with `$@`,
        // `$*` and `$1`… replaced by the call's arguments.
        if let Some(body) = words
            .first()
            .and_then(|w| ctx.functions.get(&w.raw))
            .cloned()
        {
            let name = words[0].raw.clone();
            let body_bytes: usize = body
                .iter()
                .flat_map(|c| c.words.iter())
                .map(|w| w.raw.len() + 1)
                .sum();
            let fresh = FreshExpansions::at_top(ctx);
            if !ctx.calling.contains(&name) && take_expansion() && take_work(body_bytes) {
                // `shift` / `shift N` in the body moves the arguments for
                // the commands after it; a computed count makes them unknown.
                let all_args = &words[1..];
                let mut offset = Some(0usize);
                let body: Vec<SimpleCmd> = body
                    .into_iter()
                    .map(|c| {
                        let new_words = match offset {
                            Some(o) => substitute_positional(
                                &c.words,
                                all_args.get(o..).unwrap_or_default(),
                            ),
                            None => c.words.clone(),
                        };
                        let shift_at = c.words.iter().position(|w| {
                            !matches!(w.raw.as_str(), "if" | "then" | "else" | "do" | "{" | "!")
                        });
                        if let Some(k) = shift_at.filter(|&k| c.words[k].raw == "shift") {
                            let by = c
                                .words
                                .get(k + 1)
                                .map_or(Some(1), |w| w.raw.parse::<usize>().ok());
                            offset = offset.zip(by).map(|(o, n)| o + n);
                        }
                        SimpleCmd {
                            words: new_words,
                            piped: c.piped,
                            func: None,
                            next_op: c.next_op,
                        }
                    })
                    .collect();
                ctx.calling.push(name);
                process_commands(&body, heredoc_bodies, ctx, out);
                ctx.calling.pop();
            }
            drop(fresh);
            prev = None;
            continue;
        }
        // `read v`, `for v in …`, `v+=x`, `printf -v v …`, `unset v`, …
        // change a variable: its tracked value is replaced or forgotten.
        track_var_writes(words, &mut ctx.vars);
        // `a=rm` alone (or `export a=rm`, `local a=rm`): remember the value
        // for later `$a`.
        let declares = words.first().is_some_and(|w| {
            matches!(
                w.raw.as_str(),
                "export" | "local" | "declare" | "typeset" | "readonly"
            )
        }) && words.len() > 1
            && words[1..]
                .iter()
                .all(|w| is_var_assignment(&w.raw) || w.raw.starts_with('-'));
        if declares || words.iter().all(|w| is_var_assignment(&w.raw)) {
            for w in words {
                if let Some((name, value)) =
                    w.raw.split_once('=').filter(|_| is_var_assignment(&w.raw))
                {
                    // `tmp=${tmp%/*}`, `tmp=${tmp/x/y}`: an edit of itself.
                    let self_ref = value.contains(&format!("${name}"))
                        || value.contains(&format!("${{{name}"));
                    if is_pure_mktemp(value) {
                        // A fresh temporary file / directory.
                        ctx.vars.insert(name.to_string(), MKTEMP_PATH.to_string());
                    } else if let Some(items) = value
                        .strip_prefix('(')
                        .and_then(|v| v.strip_suffix(')'))
                        .filter(|v| !v.contains("$(") && !v.contains('`'))
                    {
                        // `c=(rm -rf /)`: an array, used as `"${c[@]}"`.
                        ctx.vars.insert(name.to_string(), items.trim().to_string());
                    } else if let Some(fetch) = remote_fetch_command(value) {
                        // `S=$(curl …)`: a downloaded script; `eval "$S"`,
                        // `sh -c "$S"` run it.
                        ctx.vars.insert(name.to_string(), format!("$({fetch})"));
                    } else if let Some(v) = expand_word_vars(value, &ctx.vars)
                        .filter(|v| !v.contains(['$', '`']) && !value.contains("$("))
                    {
                        // `OUT=${OUT:-dist}`, `dir=$base/x`: the value now.
                        ctx.vars.insert(name.to_string(), v);
                    } else if value.contains("$(") || value.contains('`') || self_ref {
                        ctx.vars.remove(name);
                    } else {
                        ctx.vars.insert(name.to_string(), value.to_string());
                    }
                }
            }
            prev = None;
            continue;
        }
        // `D=~ sh -c 'rm -rf "$D"'`, `env D=~ bash -c …`: the child shell
        // sees the command's own assignments, whatever `D` was before.
        if let Some((at, child)) = child_shell_vars(words, &ctx.vars) {
            if let Some(q) =
                substitute_vars_as(&words[at..], &child, true).filter(|q| take_work(q.len()))
            {
                out.extend(parse(&q).segments);
            }
        }
        // `$a -rf /` with a known `a`: analyze the expanded command, with
        // this line's directory, aliases and functions.
        if let Some(expanded) = substitute_vars(words, &ctx.vars) {
            let mut handled = false;
            if ctx.subst_depth < MAX_SUBST_DEPTH && take_work(expanded.len()) {
                if let Ok(lexemes) = lex(&expanded) {
                    let mut sub = group_commands(&lexemes);
                    if let Some(last) = sub.last_mut() {
                        last.next_op.clone_from(&cmd.next_op);
                    }
                    if let Some(first) = sub.first_mut() {
                        first.piped = cmd.piped;
                    }
                    ctx.subst_depth += 1;
                    process_commands(&sub, heredoc_bodies, ctx, out);
                    ctx.subst_depth -= 1;
                    handled = true;
                }
            }
            if !handled {
                out.extend(parse(&expanded).segments);
            }
            // `c='rm -rf /'; bash -c "$c"`: the value is one word, the script.
            let runs_shell = strip_prefixes(words)
                .first()
                .is_some_and(|w| SHELLS.contains(&program_name(&w.raw).as_str()));
            if runs_shell {
                if let Some(q) = substitute_vars_as(words, &ctx.vars, true)
                    .filter(|q| *q != expanded && take_work(q.len()))
                {
                    out.extend(parse(&q).segments);
                }
            }
            prev = None;
            continue;
        }

        // `exec 3<<<'TEXT'`: TEXT is readable from `/dev/fd/3` later.
        if words.first().is_some_and(|w| w.raw == "exec") {
            for pair in words[1..].windows(2) {
                if let Some(fd) = pair[0].raw.strip_suffix("<<<") {
                    if !fd.is_empty()
                        && fd.chars().all(|c| c.is_ascii_digit())
                        && ctx.fd_texts.len() < 16
                    {
                        ctx.fd_texts.push((fd.to_string(), pair[1].raw.clone()));
                    }
                }
            }
        }
        let stripped = strip_prefixes(words);
        if stripped.is_empty() {
            prev = None;
            continue;
        }
        let prog = program_name(&stripped[0].raw);
        // `source /dev/fd/3` after `exec 3<<<'TEXT'`: runs TEXT.
        if !ctx.fd_texts.is_empty()
            && (SHELLS.contains(&prog.as_str()) || matches!(prog.as_str(), "source" | "."))
        {
            for w in &stripped[1..] {
                let fd = w
                    .raw
                    .strip_prefix("/dev/fd/")
                    .or_else(|| w.raw.strip_prefix("/proc/self/fd/"));
                if let Some((_, text)) =
                    fd.and_then(|fd| ctx.fd_texts.iter().find(|(n, _)| n == fd))
                {
                    if take_work(text.len()) {
                        out.extend(parse(text).segments);
                    }
                }
            }
        }
        // `curl -o i.sh URL && sh i.sh`: running a file downloaded earlier
        // in the line is running the download.
        // Reading the file on the same line (`cat x.sh && bash x.sh`,
        // `head -1`, `cat x.sh > /dev/null`) is not a review: nobody can stop
        // between the read and the run. Only a verification that stops the
        // line when it fails (`sha256sum -c`, `gpg --verify`, `cosign
        // verify-blob`, `minisign -V`) makes the run the reviewed file.
        let verifies = match prog.as_str() {
            "sha256sum" | "sha512sum" | "sha1sum" | "shasum" | "b2sum" | "md5sum" => {
                stripped[1..].iter().any(|w| {
                    w.raw == "--check"
                        || (w.raw.starts_with('-')
                            && !w.raw.starts_with("--")
                            && w.raw.contains('c'))
                })
            }
            "gpg" | "gpgv" => prog == "gpgv" || stripped[1..].iter().any(|w| w.raw == "--verify"),
            "cosign" => stripped.get(1).is_some_and(|w| w.raw.starts_with("verify")),
            "minisign" => stripped[1..].iter().any(|w| w.raw == "-V"),
            _ => false,
        };
        // (`echo "HASH  i.sh" | sha256sum -c` names no file: any
        // verification counts.) It must gate what follows: `&&`, or `;` /
        // a newline under `set -e`. After `;`, `||`, `&` or `|| true` the
        // run happens even when the check fails.
        let gates =
            cmd.next_op == "&&" || (ctx.errexit && matches!(cmd.next_op.as_str(), ";" | "\n" | ""));
        if verifies && gates {
            ctx.downloads.clear();
        }
        if !ctx.downloads.is_empty() {
            let runs = |w: &Word| {
                let p = normalize_path(&w.raw);
                ctx.downloads
                    .iter()
                    .find(|(d, _)| *d == p)
                    .map(|(_, f)| f.clone())
            };
            let runner = SHELLS.contains(&prog.as_str())
                || matches!(prog.as_str(), "source" | ".")
                || interpreter_code_flags(&prog).is_some();
            let fetched = if runner {
                stripped[1..]
                    .iter()
                    .find(|w| !w.raw.starts_with('-'))
                    .and_then(runs)
            } else {
                runs(&stripped[0])
            };
            if let Some(fetch) = fetched {
                let shell = if runner && !matches!(prog.as_str(), "source" | ".") {
                    prog.clone()
                } else {
                    "sh".to_string()
                };
                out.push(format!("{fetch} | {shell}"));
            }
        }
        // `cat > x.sh <<EOF … EOF; bash x.sh`, `echo 'cmd' > x.sh && sh
        // x.sh`: running a script written earlier in the input runs its text.
        let redirect_target = stripped.iter().enumerate().find_map(|(i, w)| {
            matches!(w.raw.as_str(), ">" | ">>" | ">|")
                .then(|| stripped.get(i + 1).map(|t| t.raw.clone()))
                .flatten()
        });
        if !ctx.written.is_empty() {
            let runner = SHELLS.contains(&prog.as_str())
                || matches!(prog.as_str(), "source" | ".")
                || interpreter_code_flags(&prog).is_some();
            let script = if runner {
                stripped[1..].iter().find(|w| !w.raw.starts_with('-'))
            } else {
                stripped.first()
            }
            .map(|w| normalize_path(&w.raw));
            let text = script.and_then(|p| {
                ctx.written
                    .iter()
                    .rev()
                    .find(|(d, _)| *d == p)
                    .map(|(_, t)| t.clone())
            });
            if let Some(t) = text.filter(|t| take_work(t.len())) {
                if interpreter_code_flags(&prog).is_some() && !SHELLS.contains(&prog.as_str()) {
                    for c in inline_code_commands(&t) {
                        out.extend(parse(&c).segments);
                    }
                    out.push(interpreter_code_segment(&prog, &t));
                } else {
                    out.extend(parse(&t).segments);
                }
            }
        }
        if let Some(t) = redirect_target
            .as_deref()
            .filter(|t| !t.contains(['$', '`']) && !t.starts_with("/dev/"))
        {
            let text = match prog.as_str() {
                "cat" | "tee" => (!heredoc_bodies.is_empty()).then(|| heredoc_bodies.join("\n")),
                "echo" | "printf" => echo_payload(&stripped),
                _ => None,
            };
            let path = normalize_path(t);
            ctx.written.retain(|(p, _)| *p != path);
            if let Some(text) = text {
                if ctx.written.len() < 16 {
                    ctx.written.push((path, text));
                }
            }
        }
        if FETCHERS.contains(&prog.as_str()) {
            // `-o F`, `-fsSLo F`, `-o/tmp/F`, `--output=F`, wget `-qO F` /
            // `-qOF`; `-O-` (stdout) leaves a `> F` redirection in charge.
            let explicit = fetch_output_file(&prog, &stripped).filter(|t| t != "-");
            // `curl URL > F`, `curl -O URL` / `wget URL` (the URL's file name).
            let url_name = || {
                stripped[1..]
                    .iter()
                    .find(|w| w.raw.contains("://"))
                    .and_then(|w| {
                        let path = w.raw.split(['?', '#']).next().unwrap_or("");
                        let name = path.rsplit('/').next().unwrap_or("");
                        (!name.is_empty()
                            && !path.ends_with("://")
                            && path.matches('/').count() > 2)
                            .then(|| name.to_string())
                    })
            };
            let remote_name = prog == "curl"
                && stripped[1..].iter().any(|w| {
                    w.raw == "--remote-name"
                        || (w.raw.starts_with('-')
                            && !w.raw.starts_with("--")
                            && w.raw.contains('O'))
                });
            let wget_default = prog == "wget"
                && !stripped[1..].iter().any(|w| {
                    w.raw.starts_with("--output-document")
                        || (w.raw.starts_with('-')
                            && !w.raw.starts_with("--")
                            && w.raw.contains('O'))
                });
            let target = explicit
                .or_else(|| redirect_target.clone())
                .or_else(|| (remote_name || wget_default).then(url_name).flatten());
            if let Some(t) = target.filter(|t| t != "-" && !t.is_empty()) {
                if ctx.downloads.len() < 64 {
                    // Spelled as `curl …` so one rule covers every fetcher.
                    let url = stripped[1..]
                        .iter()
                        .find(|w| w.raw.contains("://"))
                        .map_or_else(|| raw_join(&stripped[1..]), |w| w.raw.clone());
                    ctx.downloads
                        .push((normalize_path(&t), format!("curl {url}")));
                }
            }
        }

        // `echo 'rm -rf /' | sh`, `echo "DROP TABLE t" | psql`: the echoed
        // text is the code the next command runs.
        if cmd.piped && consumes_stdin_code(&prog, &stripped) {
            let heredoc_cat = prev.as_deref().and_then(|p| {
                let is_cat = p.first().is_some_and(|w| program_name(&w.raw) == "cat");
                let has_heredoc = p.iter().any(|w| w.raw.starts_with("<<") && w.raw != "<<<");
                (is_cat && has_heredoc)
                    .then(|| heredoc_bodies.join("\n"))
                    .filter(|b| !b.is_empty())
            });
            if let Some(payload) = prev.as_deref().and_then(echo_payload).or(heredoc_cat) {
                if SHELLS.contains(&prog.as_str())
                    || matches!(prog.as_str(), "source" | "." | "at" | "batch")
                {
                    out.extend(parse(&payload).segments);
                } else if matches!(prog.as_str(), "mongosh" | "mongo" | "redis-cli") {
                    out.extend(parse(&sql_code(&payload)).segments);
                } else {
                    // SQL is one unit per statement, not shell text.
                    out.extend(sql_payload_segments(&prog, &payload));
                }
            }
        }
        // `echo "import os; os.system('…')" | python3`: the echoed text is
        // the interpreter's program.
        if cmd.piped
            && interpreter_code_flags(&prog).is_some()
            && interpreter_code(&prog, &stripped).is_none()
            && interpreter_reads_stdin(&stripped)
        {
            if let Some(code) = prev.as_deref().and_then(echo_payload) {
                for c in inline_code_commands(&code) {
                    out.extend(parse(&c).segments);
                }
                out.push(interpreter_code_segment(&prog, &code));
            }
        }

        // `(crontab -l; echo '* * * * * curl x | sh') | crontab -`,
        // `crontab - <<EOF`: the cron lines' commands run later.
        if prog == "crontab" && !stripped[1..].iter().any(|w| w.raw.starts_with("-l")) {
            let mut table: Vec<String> = stdin_payloads(&stripped, heredoc_bodies);
            if cmd.piped {
                table.extend(prev.as_deref().and_then(echo_payload));
            }
            for t in table {
                for c in cron_commands(&t) {
                    if take_work(c.len()) {
                        out.extend(parse(&c).segments);
                    }
                }
            }
        }
        // `echo 'curl x | sh' >> ~/.bashrc`, `cat >> ~/.zshrc <<'EOF'`: the
        // appended text runs in every new shell.
        // `tee -a ~/.bashrc <<< '…'` / `echo '…' | tee -a ~/.bashrc` too.
        let tee_startup = prog == "tee"
            && stripped[1..].iter().any(|w| {
                !w.raw.starts_with('-')
                    && STARTUP_FILES.contains(&w.raw.rsplit('/').next().unwrap_or(""))
            });
        if (matches!(prog.as_str(), "echo" | "printf" | "cat") && writes_startup_file(&stripped))
            || tee_startup
        {
            let text = if prog == "tee" {
                let here = stripped
                    .iter()
                    .position(|w| w.raw == "<<<")
                    .and_then(|p| stripped.get(p + 1))
                    .map(|w| w.raw.clone());
                here.or_else(|| (!heredoc_bodies.is_empty()).then(|| heredoc_bodies.join("\n")))
                    .or_else(|| {
                        cmd.piped
                            .then(|| prev.as_deref().and_then(echo_payload))
                            .flatten()
                    })
            } else if prog == "cat" {
                (!heredoc_bodies.is_empty()).then(|| heredoc_bodies.join("\n"))
            } else {
                echo_payload(&stripped)
            };
            if let Some(t) = text.filter(|t| take_work(t.len())) {
                let parsed = parse(&t);
                out.extend(parsed.segments);
                // Cross-word forms (`eval "$(curl …)"`) are matched on the
                // payload as written.
                out.push(parsed.flat);
                // `alias ls="rm -rf"`: the alias body runs as a command.
                if let Ok(lexemes) = lex(&t) {
                    for c in group_commands(&lexemes) {
                        if c.words
                            .first()
                            .is_some_and(|w| program_name(&w.raw) == "alias")
                        {
                            for w in &c.words[1..] {
                                // Its arguments come where it is used: unknown.
                                // (`alias rm='rm -i'` only adds options to the
                                // same program.)
                                if let Some((name, value)) = w.raw.split_once('=') {
                                    let first = value.split_whitespace().next();
                                    let same = first == Some(name);
                                    let risky = first.is_some_and(|f| {
                                        matches!(
                                            program_name(f).as_str(),
                                            "rm" | "rmdir"
                                                | "shred"
                                                | "srm"
                                                | "unlink"
                                                | "dd"
                                                | "wipefs"
                                                | "truncate"
                                                | "kill"
                                                | "killall"
                                                | "pkill"
                                                | "shutdown"
                                                | "reboot"
                                                | "halt"
                                                | "poweroff"
                                        ) || program_name(f).starts_with("mkfs")
                                    });
                                    // `alias ls=rm`: every later `ls` deletes
                                    // its arguments. Named for what it is, not
                                    // as a delete of unknown files.
                                    if !same && risky {
                                        out.push(format!("{STARTUP_ALIAS_MARKER} {name}={value}"));
                                    }
                                    let own_args = value.split_whitespace().nth(1).is_some();
                                    if !same && (own_args || !risky) {
                                        out.extend(parse(&format!("{value} {{}}")).segments);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        // After `cd dir`, relative operands are relative to `dir`: analyze
        // the rebased form so path filters see the real target. When the
        // command only runs if the `cd` succeeded (`cd dir && rm -rf *`), the
        // rebased form replaces the original one (`*` is `dir/*`, not the
        // current directory).
        // `env -C DIR cmd` / `env --chdir=DIR cmd` runs cmd in DIR (env
        // fails without running it when the change fails).
        let env_dir = env_chdir(&words[..words.len() - stripped.len()], ctx.cwd.as_deref());
        let rebased = match env_dir.as_deref().or(ctx.cwd.as_deref()) {
            Some(base) if !matches!(prog.as_str(), "cd" | "pushd" | "popd") => {
                let idx = words.len() - stripped.len();
                if PATH_COMMANDS.contains(&prog.as_str())
                    || REBASE_ALL_COMMANDS.contains(&prog.as_str())
                {
                    rebase_operands(words, idx, base, true)
                } else {
                    rebase_operands(words, idx, base, false)
                }
            }
            _ => None,
        };
        match rebased {
            Some(r) if ctx.cwd_strict || env_dir.is_some() => {
                normalize_simple(&r, heredoc_bodies, out);
            }
            Some(r) => {
                normalize_simple(words, heredoc_bodies, out);
                normalize_simple(&r, heredoc_bodies, out);
            }
            None => normalize_simple(words, heredoc_bodies, out),
        }
        // `cd ~ && bash -c 'rm -rf projects'`: the child shell starts in the
        // directory the line changed to.
        if let Some(base) = env_dir.as_deref().or(ctx.cwd.as_deref()) {
            if SHELLS.contains(&prog.as_str()) {
                if let Some(payload) = find_dash_c(&stripped) {
                    let text = format!("cd {} && {payload}", shell_quote(base));
                    if take_work(text.len()) {
                        out.extend(parse(&text).segments);
                    }
                }
            }
        }

        match prog.as_str() {
            "cd" => {
                ctx.cwd = cd_target(&stripped, ctx.cwd.as_deref());
                ctx.cwd_strict = cmd.next_op == "&&";
            }
            "pushd" => {
                let has_dir = stripped[1..].iter().any(|w| !w.raw.starts_with(['-', '+']));
                if has_dir {
                    ctx.dir_stack.push(ctx.cwd.clone());
                    ctx.cwd = cd_target(&stripped, ctx.cwd.as_deref());
                    ctx.cwd_strict = cmd.next_op == "&&";
                } else {
                    ctx.cwd = None;
                    ctx.cwd_strict = false;
                }
            }
            "popd" => {
                ctx.cwd = ctx.dir_stack.pop().flatten();
                ctx.cwd_strict = false;
            }
            _ => {
                if cmd.next_op != "&&" {
                    ctx.cwd_strict = false;
                }
            }
        }
        if ctx.cwd.as_ref().is_some_and(|c| c.len() > MAX_CWD_LEN) {
            ctx.cwd = None;
            ctx.cwd_strict = false;
        }
        prev = Some(stripped);
    }
}

/// The command text a run-time-built command word expands to:
/// `{rm,-rf,/}` → `rm -rf /`, `$(echo rm) -rf /` → `rm -rf /` (wrapper
/// prefixes such as `sudo` are kept).
fn generated_command(words: &[Word]) -> Option<String> {
    let stripped = strip_prefixes(words);
    let first = stripped.first()?;
    let raw = first.raw.as_str();
    let generated = if raw.starts_with('{') && raw.ends_with('}') && raw.contains(',') {
        let items = expand_braces(raw);
        if items.len() < 2 {
            return None;
        }
        items
            .iter()
            .map(|w| shell_quote(w))
            .collect::<Vec<_>>()
            .join(" ")
    } else {
        let inner = raw
            .strip_prefix("$(")
            .and_then(|r| r.strip_suffix(')'))
            .or_else(|| raw.strip_prefix('`').and_then(|r| r.strip_suffix('`')))?;
        let text = literal_output(inner, true)?;
        if text.trim().is_empty() || text.contains('\n') {
            return None;
        }
        text
    };
    let idx = words.len() - stripped.len();
    let mut parts = Vec::new();
    if idx > 0 {
        parts.push(argv_join(&words[..idx]));
    }
    parts.push(generated);
    if stripped.len() > 1 {
        parts.push(argv_join(&stripped[1..]));
    }
    Some(parts.join(" "))
}

/// fish `set [-g|-l|-x|-U…] NAME VALUE…` (the value, or `None` for `set -e
/// NAME` / a computed value) and bash `set -- WORDS…` (the positional
/// parameters, as `@`).
fn set_assignment(words: &[Word]) -> Option<(String, Option<String>)> {
    // elvish `var NAME = VALUE` / `set NAME = VALUE`.
    if let [kw, name, eq, values @ ..] = words {
        if matches!(kw.raw.as_str(), "var" | "set")
            && eq.raw == "="
            && !values.is_empty()
            && name
                .raw
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            let computed = values.iter().any(|w| w.raw.contains(['$', '`', '(']));
            return Some((name.raw.clone(), (!computed).then(|| raw_join(values))));
        }
    }
    if words.first().map(|w| w.raw.as_str()) != Some("set") || words.len() < 3 {
        return None;
    }
    let mut i = 1;
    let mut erase = false;
    while let Some(w) = words.get(i) {
        if w.raw == "--" {
            let rest = &words[i + 1..];
            let computed = rest.iter().any(|w| w.raw.contains(['$', '`']));
            return Some(("@".to_string(), (!computed).then(|| argv_join(rest))));
        }
        if !w.raw.starts_with('-') {
            break;
        }
        erase |= matches!(w.raw.as_str(), "-e" | "--erase");
        i += 1;
    }
    let name = words.get(i)?.raw.clone();
    if name.is_empty()
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        || name.starts_with(|c: char| c.is_ascii_digit())
    {
        return None;
    }
    let values = &words[i + 1..];
    if erase {
        return Some((name, None));
    }
    if values.is_empty() {
        return None;
    }
    let computed = values.iter().any(|w| w.raw.contains(['$', '`', '(']));
    Some((name, (!computed).then(|| raw_join(values))))
}

/// Whether `value` is exactly one `mktemp` command substitution
/// (`$(mktemp)`, `$(mktemp -d)`, `$(mktemp -d -t x.XXXXXX)`, `` `mktemp` ``)
/// with no other command or fallback in it (`$(mktemp -d || echo ~)` is not
/// a fresh temporary path).
fn is_pure_mktemp(value: &str) -> bool {
    let inner = value
        .strip_prefix("$(")
        .and_then(|r| r.strip_suffix(')'))
        .or_else(|| value.strip_prefix('`').and_then(|r| r.strip_suffix('`')));
    inner.is_some_and(is_pure_mktemp_command)
}

/// Whether a substitution body is a plain `mktemp [options] [template]`.
fn is_pure_mktemp_command(inner: &str) -> bool {
    if inner.contains(['|', ';', '&', '<', '>', '(', ')', '$', '`', '\n']) {
        return false;
    }
    let words: Vec<&str> = inner.split_whitespace().collect();
    let Some((first, rest)) = words.split_first() else {
        return false;
    };
    if program_name(first) != "mktemp" {
        return false;
    }
    let mut templates = 0;
    let mut i = 0;
    while i < rest.len() {
        let w = rest[i];
        if w.starts_with('-') {
            if matches!(w, "-p" | "--tmpdir" | "-t" | "--suffix") {
                i += 1;
            }
        } else if w.contains("XXX") && templates == 0 {
            templates += 1;
        } else {
            return false;
        }
        i += 1;
    }
    true
}

/// Forget (or update) the tracked value of variables a command writes:
/// `read v`, `for v in …`, `v+=x`, `printf -v v …`, `unset v`, `mapfile v`,
/// `getopts s v`, `local v`. `read v <<< WORD` and `printf -v v TEXT` with
/// literal text set the value.
#[allow(clippy::too_many_lines)]
fn track_var_writes(words: &[Word], vars: &mut std::collections::HashMap<String, String>) {
    if vars.is_empty()
        && !words.iter().any(|w| {
            matches!(
                w.raw.as_str(),
                "read" | "printf" | "for" | "foreach" | "mapfile" | "readarray"
            )
        })
    {
        return;
    }
    let start = words
        .iter()
        .position(|w| !is_var_assignment(&w.raw))
        .unwrap_or(words.len());
    let words = &words[start..];
    let Some(first) = words.first() else {
        return;
    };
    let ident = |w: &str| {
        !w.is_empty()
            && w.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && !w.starts_with(|c: char| c.is_ascii_digit())
    };
    // Operands that are not redirections (or their targets).
    let operands = |from: usize| -> Vec<&Word> {
        let mut out = Vec::new();
        let mut i = from;
        while i < words.len() {
            if is_redirect_op(&words[i].raw) {
                i += 2;
                continue;
            }
            out.push(&words[i]);
            i += 1;
        }
        out
    };
    if let Some(name) = first
        .raw
        .split_once("+=")
        .map(|(n, _)| n)
        .filter(|n| ident(n))
    {
        vars.remove(name);
        return;
    }
    match program_name(&first.raw).as_str() {
        "read" => {
            let mut names = Vec::new();
            let ops = operands(1);
            let mut i = 0;
            while i < ops.len() {
                let w = ops[i].raw.as_str();
                if matches!(w, "-a" | "-d" | "-n" | "-N" | "-p" | "-t" | "-u" | "-i") {
                    if w == "-a" {
                        if let Some(a) = ops.get(i + 1) {
                            names.push(a.raw.clone());
                        }
                    }
                    i += 2;
                    continue;
                }
                if !w.starts_with('-') && ident(w) {
                    names.push(w.to_string());
                }
                i += 1;
            }
            let here = words
                .iter()
                .position(|w| w.raw == "<<<")
                .and_then(|p| words.get(p + 1))
                .map(|w| w.raw.clone())
                .filter(|v| !v.contains('$') && !v.contains('`'));
            for n in &names {
                vars.remove(n);
            }
            if let ([one], Some(v)) = (names.as_slice(), here) {
                vars.insert(one.clone(), v.trim().to_string());
            }
        }
        "printf" if words.get(1).is_some_and(|w| w.raw == "-v") => {
            let Some(name) = words.get(2).map(|w| w.raw.clone()) else {
                return;
            };
            vars.remove(&name);
            let rest: Vec<&str> = words[3..]
                .iter()
                .map(|w| w.raw.as_str())
                .take_while(|w| !is_redirect_op(w))
                .collect();
            let value = match rest.as_slice() {
                [fmt] if !fmt.contains('%') => Some((*fmt).to_string()),
                ["%s" | "%b", arg] => Some((*arg).to_string()),
                _ => None,
            };
            if let Some(v) = value.filter(|v| !v.contains('$') && !v.contains('`')) {
                if ident(&name) {
                    vars.insert(name, v);
                }
            }
        }
        "for" | "select" | "foreach" => {
            if let Some(v) = words.get(1) {
                // `for f in *.log`: in the loop `$f` is the literal word.
                // zsh `for d (src)` / `foreach d (src)`: the list word.
                let paren: Vec<Word> = words
                    .get(2)
                    .and_then(|w| w.raw.strip_prefix('(').and_then(|r| r.strip_suffix(')')))
                    .map(|inner| {
                        inner
                            .split_whitespace()
                            .map(|t| Word {
                                raw: t.to_string(),
                                masked: t.to_string(),
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let values: Vec<&Word> = if paren.is_empty() {
                    words
                        .get(2)
                        .filter(|w| w.raw == "in")
                        .map(|_| words[3..].iter().collect())
                        .unwrap_or_default()
                } else {
                    paren.iter().collect()
                };
                // Several values: `rm -rf /$d` is one delete per value, not
                // one of all of them (see [`LIST_SEP`]).
                let values: Vec<&Word> = values
                    .into_iter()
                    .take_while(|w| !matches!(w.raw.as_str(), ";" | "do"))
                    .collect();
                let literal = !values.is_empty()
                    && values.len() <= 64
                    && values.iter().all(|w| {
                        !w.raw.contains(['$', '`', '(', LIST_SEP])
                            && !w.raw.contains(char::is_whitespace)
                    });
                if literal && ident(&v.raw) {
                    vars.insert(
                        v.raw.clone(),
                        values
                            .iter()
                            .map(|w| w.raw.as_str())
                            .collect::<Vec<_>>()
                            .join(&LIST_SEP.to_string()),
                    );
                } else {
                    vars.remove(&v.raw);
                }
            }
        }
        "unset" | "mapfile" | "readarray" => {
            for w in operands(1) {
                vars.remove(&w.raw);
            }
            // `mapfile -t a <<< $'x\ny'`: one element per line.
            if first.raw != "unset" {
                let here = words
                    .iter()
                    .position(|w| w.raw == "<<<")
                    .and_then(|p| words.get(p + 1))
                    .map(|w| w.raw.clone())
                    .filter(|v| !v.contains(['$', '`']));
                let name = operands(1)
                    .into_iter()
                    .map(|w| w.raw.as_str())
                    .filter(|w| !w.starts_with('-'))
                    .find(|w| ident(w));
                if let (Some(n), Some(v)) = (name, here) {
                    vars.insert(n.to_string(), v.split('\n').collect::<Vec<_>>().join(" "));
                }
            }
        }
        "getopts" => {
            if let Some(v) = words.get(2) {
                vars.remove(&v.raw);
            }
        }
        "local" | "declare" | "typeset" => {
            for w in &words[1..] {
                if ident(&w.raw) {
                    vars.remove(&w.raw);
                }
            }
        }
        _ => {}
    }
}

/// Replace the positional parameters of a function body (`$@`, `$*`,
/// `"$@"`, `$1`…`$9`) with the call's arguments.
fn substitute_positional(words: &[Word], args: &[Word]) -> Vec<Word> {
    let mut out = Vec::with_capacity(words.len());
    for w in words {
        match w.raw.as_str() {
            "$@" | "$*" | "${@}" | "${*}" => out.extend(args.iter().cloned()),
            r => {
                let n = r
                    .strip_prefix('$')
                    .map(|d| d.trim_start_matches('{').trim_end_matches('}'))
                    .and_then(|d| d.parse::<usize>().ok())
                    .filter(|n| (1..=9).contains(n));
                match n {
                    Some(n) => {
                        if let Some(a) = args.get(n - 1) {
                            out.push(a.clone());
                        }
                    }
                    None => out.push(w.clone()),
                }
            }
        }
    }
    out
}

/// Replace `$name` / `${name}` of known variables. Returns the re-quoted
/// command text when anything was substituted (substituted words are left
/// unquoted so their value is word-split like the shell does).
fn substitute_vars(
    words: &[Word],
    vars: &std::collections::HashMap<String, String>,
) -> Option<String> {
    substitute_vars_as(words, vars, false)
}

/// Short options of curl / wget that take a value: in a cluster
/// (`-fsSLo F`) the first of them takes the rest of the word, or the next
/// word.
fn fetch_value_letters(prog: &str) -> &'static str {
    if prog == "wget" {
        "OoaeiBtTwQPlARDIXU"
    } else {
        "AbcCdDeEFHKmoPQrtTuUwxXyYz"
    }
}

/// The file a curl / wget command writes the download to (`-o F`, `-fsSLo
/// F`, `-o/tmp/F`, `--output=F`; wget `-O F`, `-qO F`, `-qOF`,
/// `--output-document=F`).
fn fetch_output_file(prog: &str, words: &[Word]) -> Option<String> {
    let out_letter = if prog == "wget" { 'O' } else { 'o' };
    let value_letters = fetch_value_letters(prog);
    let mut i = 1;
    while i < words.len() {
        let r = words[i].raw.as_str();
        if r == "--" {
            break;
        }
        if let Some(long) = r.strip_prefix("--") {
            let (name, value) = long
                .split_once('=')
                .map_or((long, None), |(n, v)| (n, Some(v)));
            let is_out = if prog == "wget" {
                name == "output-document"
            } else {
                name == "output"
            };
            if is_out {
                return value.map_or_else(
                    || words.get(i + 1).map(|w| w.raw.clone()),
                    |v| Some(v.to_string()),
                );
            }
            i += 1;
            continue;
        }
        if let Some(cluster) = r.strip_prefix('-').filter(|c| !c.is_empty()) {
            for (k, c) in cluster.char_indices() {
                if value_letters.contains(c) {
                    let rest = &cluster[k + c.len_utf8()..];
                    if c == out_letter {
                        return if rest.is_empty() {
                            words.get(i + 1).map(|w| w.raw.clone())
                        } else {
                            Some(rest.to_string())
                        };
                    }
                    if rest.is_empty() {
                        // The next word is this option's value.
                        i += 1;
                    }
                    break;
                }
            }
        }
        i += 1;
    }
    None
}

/// The variables a child shell started by this command sees, when the
/// command sets some of them itself (`D=~ sh -c 'rm -rf "$D"'`, `env D=x
/// bash -c …`, `D=x xargs sh -c …`): the line's variables with those
/// assignments applied, and the index of the shell word. `None` when no
/// shell with `-c` is run or nothing is assigned for it.
fn child_shell_vars(
    words: &[Word],
    vars: &std::collections::HashMap<String, String>,
) -> Option<(usize, std::collections::HashMap<String, String>)> {
    let shell_at = words.iter().position(|w| {
        SHELLS.contains(&program_name(&w.raw).as_str())
            && !matches!(program_name(&w.raw).as_str(), "pwsh" | "powershell")
    })?;
    if !has_dash_c(&words[shell_at + 1..]) {
        return None;
    }
    let assigned: Vec<(&str, &str)> = words[..shell_at]
        .iter()
        .filter(|w| is_var_assignment(&w.raw))
        .filter_map(|w| w.raw.split_once('='))
        .collect();
    if assigned.is_empty() {
        return None;
    }
    let mut child = vars.clone();
    for (name, value) in assigned {
        // A leading `~` is expanded in an assignment: the child gets the
        // home directory (`"$D"` in the child is the path, not `~`).
        let value = value.strip_prefix('~').map_or_else(
            || value.to_string(),
            |rest| {
                if rest.is_empty() || rest.starts_with('/') {
                    format!("$HOME{rest}")
                } else {
                    value.to_string()
                }
            },
        );
        if value.contains("$(") || value.contains('`') {
            // Known only when it runs.
            child.remove(name);
        } else {
            let v = expand_word_vars(&value, vars).unwrap_or(value);
            child.insert(name.to_string(), v);
        }
    }
    Some((shell_at, child))
}

/// Separator between the items of a loop variable bound to a literal list
/// (`for d in build dist`): a word that uses it expands once per item.
const LIST_SEP: char = '\u{2}';

/// Variables that are always set in a shell, so a `${NAME:-default}` never
/// takes its default.
const ALWAYS_SET_VARS: &[&str] = &[
    "HOME", "PWD", "OLDPWD", "USER", "LOGNAME", "SHELL", "PATH", "HOSTNAME", "UID", "EUID", "PPID",
    "RANDOM", "SECONDS", "LINENO", "IFS", "PS1", "TERM", "LANG", "BASH", "ZSH_NAME",
];

/// Whether `c` can be part of a shell variable name.
const fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Expand the known variables of one word: `$name`, `${name}`,
/// `${arr[@]}`, `${name:?…}`, and `${name:-default}` / `${name:=default}`
/// (the value, or the literal default when `name` is not set on the line).
/// The word is scanned once, so the cost is linear in its length (not in
/// the number of variables). `None` when nothing was expanded.
fn expand_word_vars(
    word: &str,
    vars: &std::collections::HashMap<String, String>,
) -> Option<String> {
    expand_word_vars_with(word, vars, None)
}

/// [`expand_word_vars`] with one variable bound to `pin` instead of its
/// tracked value.
#[allow(clippy::too_many_lines)]
fn expand_word_vars_with(
    word: &str,
    vars: &std::collections::HashMap<String, String>,
    pin: Option<(&str, &str)>,
) -> Option<String> {
    let lookup = |name: &str| -> Option<String> {
        match pin {
            Some((n, v)) if n == name => Some(v.to_string()),
            _ => vars.get(name).cloned(),
        }
    };
    if !word.contains('$') {
        return None;
    }
    let mut out = String::with_capacity(word.len());
    let mut replaced = false;
    let mut rest = word;
    while let Some(pos) = rest.find('$') {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 1..];
        if let Some(inner_start) = after.strip_prefix('{') {
            // `${…}`: find the matching close brace.
            let mut depth = 1usize;
            let mut close = None;
            for (k, c) in inner_start.char_indices() {
                match c {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            close = Some(k);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let Some(close) = close else {
                out.push_str(&rest[pos..]);
                rest = "";
                break;
            };
            let whole = &rest[pos..=pos + 2 + close];
            // zsh `${=x}` (split) / `${~x}` (glob) / `${^x}`: the value.
            let inner = inner_start[..close].trim_start_matches(['=', '~', '^']);
            // bash `${!n}`: the variable named by `n`'s value.
            let indirect = inner
                .strip_prefix('!')
                .filter(|n| !n.is_empty() && n.chars().all(is_name_char))
                .and_then(lookup)
                .filter(|target| !target.is_empty() && target.chars().all(is_name_char));
            if let Some(target) = indirect {
                match lookup(&target) {
                    Some(v) => {
                        out.push_str(&v);
                        replaced = true;
                    }
                    None => out.push_str(whole),
                }
                rest = &rest[pos + whole.len()..];
                continue;
            }
            let name_len = if inner.starts_with('@') || inner.starts_with('*') {
                1
            } else {
                inner
                    .find(|c: char| !is_name_char(c))
                    .unwrap_or(inner.len())
            };
            let (name, op) = inner.split_at(name_len);
            let name = if name == "*" { "@" } else { name };
            let value = lookup(name);
            let expansion: Option<String> = match op {
                "" | "[@]" | "[*]" => value,
                o if o.starts_with(":?") || o.starts_with('?') => value,
                o if ["-", ":-", "=", ":="].iter().any(|p| o.starts_with(p)) => {
                    value.or_else(|| {
                        let default =
                            o.trim_start_matches(':')[1..].trim_matches(|c| c == '"' || c == '\'');
                        (!name.is_empty()
                            && !name.starts_with(|c: char| c.is_ascii_digit())
                            && !ALWAYS_SET_VARS.contains(&name))
                        .then(|| default.to_string())
                    })
                }
                _ => None,
            };
            match expansion {
                Some(v) => {
                    out.push_str(&v);
                    replaced = true;
                }
                None => out.push_str(whole),
            }
            rest = &rest[pos + whole.len()..];
        } else {
            let name_len = if after.starts_with('@') || after.starts_with('*') {
                1
            } else {
                after
                    .find(|c: char| !is_name_char(c))
                    .unwrap_or(after.len())
            };
            let name = &after[..name_len];
            let key = if name == "*" { "@" } else { name };
            if let Some(v) = lookup(key).filter(|_| !name.is_empty()) {
                out.push_str(&v);
                replaced = true;
            } else {
                out.push('$');
                out.push_str(name);
            }
            rest = &after[name_len..];
        }
    }
    out.push_str(rest);
    replaced.then_some(out)
}

/// [`substitute_vars`], with every word that changed kept as one word
/// (`bash -c "$c"` passes the whole value as the script) when `quote`.
fn substitute_vars_as(
    words: &[Word],
    vars: &std::collections::HashMap<String, String>,
    quote: bool,
) -> Option<String> {
    if !words.iter().any(|w| w.raw.contains('$')) {
        return None;
    }
    let mut changed = false;
    let mut parts: Vec<String> = Vec::with_capacity(words.len());
    // `IFS=,; x=rm,-rf,/; $x`: the line's IFS splits substituted values.
    let ifs: Vec<char> = vars
        .get("IFS")
        .map(|v| v.chars().filter(|c| !c.is_whitespace()).collect())
        .unwrap_or_default();
    for w in words {
        match expand_word_vars(&w.raw, vars) {
            Some(s) => {
                changed = true;
                let s = if ifs.is_empty() || quote {
                    s
                } else {
                    s.chars()
                        .map(|c| if ifs.contains(&c) { ' ' } else { c })
                        .collect()
                };
                if quote {
                    parts.push(shell_quote(&s.replace(LIST_SEP, " ")));
                } else if s.contains(LIST_SEP) {
                    // A loop over a literal list: one word per item, with
                    // the word's prefix and suffix (`/$d` → `/a /b`).
                    let expanded = list_word_items(&w.raw, vars);
                    parts.extend(expanded);
                } else {
                    parts.push(s);
                }
            }
            // An unknown variable stays a variable (`"$T"`, not the literal
            // `'$T'` a banner would show).
            None if w.raw.contains('$')
                && !w.raw.contains(['"', '\\', '`', '\n'])
                && !w.raw.contains(char::is_whitespace) =>
            {
                parts.push(format!("\"{}\"", w.raw));
            }
            None => parts.push(shell_quote(&w.raw)),
        }
    }
    changed.then(|| parts.join(" "))
}

/// The words a word that uses a list-bound loop variable expands to: the
/// word once per item of the (first) list it uses.
fn list_word_items(word: &str, vars: &std::collections::HashMap<String, String>) -> Vec<String> {
    let list = vars
        .iter()
        .filter(|(_, v)| v.contains(LIST_SEP))
        .find(|(n, _)| {
            word.contains(&format!("${{{n}}}"))
                || word.match_indices(&format!("${n}")).any(|(i, m)| {
                    word[i + m.len()..]
                        .chars()
                        .next()
                        .is_none_or(|c| !is_name_char(c))
                })
        });
    let Some((name, value)) = list else {
        return vec![expand_word_vars(word, vars)
            .unwrap_or_else(|| word.to_string())
            .replace(LIST_SEP, " ")];
    };
    value
        .split(LIST_SEP)
        .map(|item| {
            let w = expand_word_vars_with(word, vars, Some((name, item)))
                .unwrap_or_else(|| word.to_string());
            shell_quote(&w.replace(LIST_SEP, " "))
        })
        .collect()
}

/// A `sh -c SCRIPT ARG0 ARG1…` script with `$0`…`$9`, `${N}`, `$@` and
/// `$*` replaced by the arguments.
fn bind_script_args(script: &str, args: &[Word]) -> String {
    // Unquoted: an unquoted `$1` is split into words, and `eval "$0"`
    // re-parses it anyway.
    let quoted: Vec<String> = args.iter().map(|w| w.raw.clone()).collect();
    let rest = quoted.get(1..).unwrap_or_default().join(" ");
    let mut out = String::with_capacity(script.len());
    let chars: Vec<char> = script.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '$' {
            // `"$@"` with its quotes: the words, one by one.
            let next = chars.get(i + 1).copied();
            let (digit, len) = match next {
                Some(d) if d.is_ascii_digit() => (d.to_digit(10), 2),
                Some('{') if chars.get(i + 3) == Some(&'}') && chars[i + 2].is_ascii_digit() => {
                    (chars[i + 2].to_digit(10), 4)
                }
                Some('@' | '*') => {
                    if out.ends_with('"') && chars.get(i + 2) == Some(&'"') {
                        out.pop();
                        out.push_str(&rest);
                        i += 3;
                    } else {
                        out.push_str(&rest);
                        i += 2;
                    }
                    continue;
                }
                _ => (None, 1),
            };
            if let Some(n) = digit {
                let v = quoted.get(n as usize).cloned().unwrap_or_default();
                // Inside double quotes the value stays one word.
                out.push_str(&v);
                i += len;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// Programs that print a downloaded document.
const FETCHERS: &[&str] = &["curl", "wget", "fetch", "http", "https", "xh", "aria2c"];

/// The download command of a value that is the output of one (`$(curl -fsSL
/// URL)`, `` `wget -qO- URL` ``), if any.
fn remote_fetch_command(value: &str) -> Option<String> {
    let v = value.trim().trim_matches(['"', '\'']);
    let inner = v
        .strip_prefix("$(")
        .and_then(|r| r.strip_suffix(')'))
        .or_else(|| v.strip_prefix('`').and_then(|r| r.strip_suffix('`')))?;
    let inner = inner.trim();
    let first = inner
        .split_whitespace()
        .find(|w| *w != "sudo" && !is_var_assignment(w))?;
    FETCHERS
        .contains(&program_name(first).as_str())
        .then(|| inner.to_string())
}

/// Whether `prog` reads code (shell commands or SQL) from its stdin.
fn consumes_stdin_code(prog: &str, words: &[Word]) -> bool {
    if SHELLS.contains(&prog) {
        if find_dash_c(words).is_some() {
            return false;
        }
        // A script operand means stdin is not the code.
        let mut i = 1;
        while i < words.len() {
            let w = &words[i].raw;
            if w == "-s" || w == "--" {
                return true;
            }
            if w == "-o" || w == "+o" || w == "-O" || w == "+O" {
                i += 2;
                continue;
            }
            if is_redirect_op(w) {
                i += 2;
                continue;
            }
            if !w.starts_with('-') && !w.starts_with('+') {
                return false;
            }
            i += 1;
        }
        return true;
    }
    match prog {
        // `echo 'cmd' | at now`, `batch`: the input runs later.
        "at" | "batch" => !words[1..]
            .iter()
            .any(|w| matches!(w.raw.as_str(), "-f" | "-l" | "-r" | "-d" | "-c")),
        // fish `… | source`, `… | . -`: the input is shell code.
        "source" | "." => words[1..]
            .iter()
            .all(|w| matches!(w.raw.as_str(), "-" | "/dev/stdin" | "/dev/fd/0")),
        "psql" | "mysql" | "mariadb" | "sqlite3" | "duckdb" | "clickhouse-client" | "cqlsh"
        | "mongosh" | "mongo" | "redis-cli" => !words.iter().any(|w| {
            matches!(
                w.raw.as_str(),
                "-c" | "--command" | "-e" | "--execute" | "--eval" | "-f" | "--file"
            )
        }),
        _ => false,
    }
}

/// The commands of a crontab text: each non-comment line without its
/// schedule (five time fields, or one `@reboot`-style field).
fn cron_commands(table: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in table.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let first = t.split_whitespace().next().unwrap_or("");
        if is_var_assignment(first) && !t.contains(char::is_whitespace) {
            continue;
        }
        let skip = if first.starts_with('@') { 1 } else { 5 };
        let mut rest = t;
        for _ in 0..skip {
            rest = rest.trim_start();
            rest = rest.find(char::is_whitespace).map_or("", |p| &rest[p..]);
        }
        let cmd = rest.trim();
        if !cmd.is_empty() {
            out.push(cmd.to_string());
        }
    }
    out
}

/// Shell startup files: text appended to them runs in every new shell.
const STARTUP_FILES: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".profile",
    ".zshrc",
    ".zprofile",
    ".zshenv",
    ".zlogin",
    ".kshrc",
    ".mkshrc",
    "config.fish",
    ".xonshrc",
    "config.nu",
    "env.nu",
    "rc.elv",
    "bash.bashrc",
    "zshrc",
];

/// Whether the command redirects its output into a shell startup file.
fn writes_startup_file(words: &[Word]) -> bool {
    words.windows(2).any(|w| {
        is_redirect_op(&w[0].raw)
            && w[0].raw.contains('>')
            && STARTUP_FILES.contains(&w[1].raw.rsplit('/').next().unwrap_or(""))
    })
}

/// Whether the command text (a remote / container payload) is a program that
/// reads code from stdin (`bash -s`, `sh`, `psql`, …).
fn reads_stdin_code(cmd: &str) -> bool {
    let Ok(lexemes) = lex(cmd) else {
        return false;
    };
    let words: Vec<Word> = lexemes
        .into_iter()
        .map_while(|l| match l {
            Lexeme::Word(w) => Some(w),
            _ => None,
        })
        .collect();
    let stripped = strip_prefixes(&words);
    stripped
        .first()
        .is_some_and(|w| consumes_stdin_code(&program_name(&w.raw), &stripped))
}

/// The text printed by an `echo` / `printf` command (its arguments as code).
fn echo_payload(words: &[Word]) -> Option<String> {
    let prog = program_name(&words.first()?.raw);
    let mut args: Vec<&str> = words[1..]
        .iter()
        .map(|w| w.raw.as_str())
        .take_while(|w| !is_redirect_op(w))
        .collect();
    match prog.as_str() {
        "echo" => {
            let mut escapes = false;
            while let Some(first) = args.first() {
                if first.len() > 1
                    && first.starts_with('-')
                    && first[1..].chars().all(|c| matches!(c, 'n' | 'e' | 'E'))
                {
                    escapes |= first.contains('e');
                    args.remove(0);
                } else {
                    break;
                }
            }
            let text = args.join(" ");
            Some(if escapes {
                text.replace("\\n", "\n")
            } else {
                text
            })
        }
        "printf" => {
            let format = args.first()?.replace("\\n", "\n");
            if format.contains('%') && args.len() > 1 {
                Some(args[1..].join("\n"))
            } else {
                Some(format)
            }
        }
        _ => None,
    }
}

/// The directory of an `env -C DIR` / `env --chdir=DIR` / `env -CDIR` or a
/// `sudo -D DIR` / `sudo --chdir=DIR` (also `doas`, `run0`) among the prefix
/// words of a command, resolved against `cur`.
fn env_chdir(prefix: &[Word], cur: Option<&str>) -> Option<String> {
    let mut dir: Option<String> = None;
    // The wrapper whose options are being read: `-C` is env's directory but
    // sudo's close-from descriptor.
    let mut wrapper = "";
    let mut i = 0;
    while let Some(w) = prefix.get(i) {
        let r = w.raw.as_str();
        let prog = program_name(r);
        if !r.starts_with('-') {
            // A wrapper word starts its own options; other words are option
            // values (`sudo -u postgres -D /srv …`) or assignments.
            match prog.as_str() {
                "env" => wrapper = "env",
                "sudo" | "doas" | "run0" => wrapper = "sudo",
                p if PREFIX_WORDS.contains(&p)
                    || matches!(
                        p,
                        "nice"
                            | "ionice"
                            | "timeout"
                            | "strace"
                            | "ltrace"
                            | "chrt"
                            | "taskset"
                            | "nsenter"
                            | "unshare"
                            | "flock"
                            | "runuser"
                            | "pkexec"
                            | "chroot"
                    ) =>
                {
                    wrapper = "";
                }
                _ => {}
            }
            i += 1;
            continue;
        }
        let (short, glued_short) = match wrapper {
            "env" => ("-C", "-C"),
            "sudo" => ("-D", "-D"),
            _ => {
                i += 1;
                continue;
            }
        };
        if r == short || r == "--chdir" {
            dir = prefix.get(i + 1).map(|d| d.raw.clone());
            i += 2;
            continue;
        }
        if let Some(d) = r
            .strip_prefix("--chdir=")
            .or_else(|| r.strip_prefix(glued_short).filter(|d| !d.is_empty()))
        {
            dir = Some(d.to_string());
        }
        i += 1;
    }
    let dir = dir?;
    let words = [
        Word {
            raw: "cd".into(),
            masked: "cd".into(),
        },
        Word {
            masked: dir.chars().map(mask_char).collect(),
            raw: dir,
        },
    ];
    cd_target(&words, cur)
}

/// Directory after `cd ARGS` given the current tracked directory.
fn cd_target(words: &[Word], cur: Option<&str>) -> Option<String> {
    let target = words[1..]
        .iter()
        .map(|w| w.raw.as_str())
        .find(|w| !w.starts_with('-') || *w == "-");
    // `cd "$(git rev-parse --show-toplevel)"`, `cd ${DIR:-.}`, `` cd `pwd` ``.
    let resolved = target.filter(|t| *t != "-").map(|t| match operand_path(t) {
        // The output of another command: an unknown directory.
        p if p == "{}" => "$UNKNOWN_DIR".to_string(),
        p => p,
    });
    match resolved.as_deref().or(target) {
        None => Some("~".to_string()),
        Some("-") => None,
        Some(t) if t.starts_with('/') || t.starts_with('~') || t.starts_with('$') => {
            Some(normalize_path(t))
        }
        Some(t) => Some(cur.map_or_else(
            || normalize_path(t),
            |base| normalize_path(&format!("{base}/{t}")),
        )),
    }
}

/// Programs whose operands (sources and destinations) are all paths:
/// rebased after a `cd` like [`PATH_COMMANDS`].
const REBASE_ALL_COMMANDS: &[&str] = &[
    "cp", "ln", "install", "tee", "touch", "truncate", "dd", "rsync", "mkdir",
];

/// Prefix relative path operands (after the program at `prog_idx`) with
/// `base`; with `operands == false` only redirection targets (`> file`).
/// Returns `None` when nothing changed.
fn rebase_operands(
    words: &[Word],
    prog_idx: usize,
    base: &str,
    operands: bool,
) -> Option<Vec<Word>> {
    let rebase = |raw: &str| -> Option<Word> {
        let resolved = operand_path(raw);
        let raw = if operands { resolved.as_str() } else { raw };
        if raw.is_empty()
            || raw.starts_with('-')
            || raw.starts_with('/')
            || raw.starts_with('~')
            || raw.starts_with('$')
            || raw.starts_with('&')
            || raw == "{}"
        {
            return None;
        }
        let n = normalize_path(&format!("{base}/{raw}"));
        Some(Word {
            masked: n.chars().map(mask_char).collect(),
            raw: n,
        })
    };
    let mut out = words.to_vec();
    let mut changed = false;
    // A bare redirection (`> .zshrc`) has no program word.
    let mut i = if words.get(prog_idx).is_some_and(|w| is_redirect_op(&w.raw)) {
        prog_idx
    } else {
        prog_idx + 1
    };
    while i < out.len() {
        let raw = out[i].raw.clone();
        if is_redirect_op(&raw) {
            if raw.contains('>') {
                if let Some(w) = out.get(i + 1).and_then(|t| rebase(&t.raw)) {
                    out[i + 1] = w;
                    changed = true;
                }
            }
            i += 2;
            continue;
        }
        if let Some(of) = raw.strip_prefix("of=") {
            if let Some(w) = rebase(of) {
                let v = format!("of={}", w.raw);
                out[i] = Word {
                    masked: v.chars().map(mask_char).collect(),
                    raw: v,
                };
                changed = true;
            }
            i += 1;
            continue;
        }
        if !operands {
            i += 1;
            continue;
        }
        if let Some(w) = rebase(&raw) {
            out[i] = w;
            changed = true;
        }
        i += 1;
    }
    changed.then_some(out)
}

/// Remove SQL block comments (`/* … */`) and collapse the resulting spaces.
/// Returns `None` when the text has no complete block comment.
fn strip_sql_comments(s: &str) -> Option<String> {
    let start = s.find("/*")?;
    s[start + 2..].find("*/")?;
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(a) = rest.find("/*") {
        let Some(b) = rest[a + 2..].find("*/") else {
            break;
        };
        out.push_str(&rest[..a]);
        out.push(' ');
        // MySQL `/*! … */` / `/*!40101 … */`: the content runs.
        let body = &rest[a + 2..a + 2 + b];
        if let Some(code) = body.strip_prefix('!').or_else(|| body.strip_prefix("M!")) {
            out.push_str(code.trim_start_matches(|c: char| c.is_ascii_digit()));
            out.push(' ');
        }
        rest = &rest[a + 2 + b + 2..];
    }
    out.push_str(rest);
    let collapsed = out
        .split(' ')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    (collapsed != s).then_some(collapsed)
}

/// Build the flat operator-preserving string from a lexeme stream.
fn flat_from_lexemes(lexemes: &[Lexeme]) -> String {
    let mut parts: Vec<String> = Vec::new();
    // Whether we are at the first word of a command, and whether the current
    // command is a data command (its arguments are not code).
    let mut at_start = true;
    let mut in_data = false;
    let mut keep_next = false;
    // `history` / `print` whose next word decides (`-s` → data).
    let mut history_like = false;
    let owners = function_body_owners(lexemes);
    // After a pipe, a privilege / environment wrapper's options are dropped
    // (`curl … | sudo -E bash -` reads `curl … | sudo bash -`, `| env X=1
    // sh` reads `| sh`), so pipe-to-shell patterns see the shell.
    let mut after_pipe = false;
    let mut wrapper: Option<&'static str> = None;
    let mut skip_value = false;
    for (lx, owner) in lexemes.iter().zip(owners) {
        // Function bodies are definitions; they are analyzed at the call.
        if owner.is_some() {
            continue;
        }
        if let (Some(kind), Lexeme::Word(w)) = (wrapper, lx) {
            let r = w.raw.as_str();
            if skip_value {
                skip_value = false;
                continue;
            }
            if r == "--" {
                wrapper = None;
                at_start = true;
                continue;
            }
            if kind == "env" && is_var_assignment(r) {
                continue;
            }
            if r.starts_with('-') && r.len() > 1 {
                skip_value = if kind == "env" {
                    matches!(r, "-u" | "--unset" | "-C" | "--chdir" | "-S")
                } else {
                    privilege_option(r, None).0 == 2
                };
                continue;
            }
            wrapper = None;
            at_start = true;
        }
        match lx {
            Lexeme::Word(w) => {
                if at_start && after_pipe {
                    let prog = program_name(&w.raw);
                    match prog.as_str() {
                        "sudo" | "doas" | "run0" | "pkexec" => {
                            parts.push("sudo".to_string());
                            wrapper = Some("sudo");
                            continue;
                        }
                        "env" => {
                            wrapper = Some("env");
                            continue;
                        }
                        _ => {}
                    }
                }
                if at_start {
                    at_start = false;
                    after_pipe = false;
                    let prog = program_name(&w.raw);
                    in_data = DATA_COMMANDS.contains(&prog.as_str()) || prog == "alias";
                    history_like = prog == "history" || prog == "print";
                    parts.push(prog);
                } else if history_like && matches!(w.raw.as_str(), "-s" | "-S") {
                    history_like = false;
                    in_data = true;
                    parts.push(w.masked.clone());
                } else if !in_data || keep_next || is_redirect_op(&w.raw) {
                    history_like = false;
                    keep_next = in_data && is_redirect_op(&w.raw);
                    parts.push(w.masked.clone());
                }
            }
            Lexeme::Op(op) => {
                at_start = true;
                in_data = false;
                after_pipe = op == "|" || op == "|&";
                wrapper = None;
                skip_value = false;
                parts.push(op.clone());
            }
            Lexeme::SubOpen => {
                at_start = true;
                in_data = false;
                parts.push("(".to_string());
            }
            Lexeme::SubClose => {
                at_start = true;
                in_data = false;
                parts.push(")".to_string());
            }
        }
    }
    parts.join(" ")
}

/// Normalize a single simple command (after prefix stripping, recursion, etc.)
/// and push the resulting segment(s) into `out`.
#[allow(clippy::too_many_lines)]
fn normalize_simple(words: &[Word], heredoc_bodies: &[String], out: &mut Vec<String>) {
    let mut stripped = strip_prefixes(words);
    if stripped.is_empty() {
        return;
    }

    // `npx firebase-tools@latest …`, `npx supabase@1.2 …`, `bunx
    // netlify-cli …`: the package's command.
    let prog = package_binary(&stripped[0].raw).unwrap_or_else(|| program_name(&stripped[0].raw));
    // kubectl-compatible front-ends are matched as kubectl.
    let prog = if matches!(prog.as_str(), "oc" | "kubecolor") {
        "kubectl".to_string()
    } else {
        prog
    };
    // Normalize argv[0] to its base name in the emitted text so `/bin/rm` and
    // `\rm` match the same as `rm`. A path argv0 (`./deploy.sh`) is also
    // emitted as written, so policy checks on a script path still match.
    let orig_argv0 = stripped[0].clone();
    stripped[0].raw.clone_from(&prog);
    stripped[0].masked.clone_from(&prog);

    // `rimraf PATH…` (usually via `npx`) is `rm -rf PATH…`.
    if prog.starts_with("rimraf") {
        let mut rm = vec![
            Word {
                raw: "rm".into(),
                masked: "rm".into(),
            },
            Word {
                raw: "-rf".into(),
                masked: "-rf".into(),
            },
        ];
        rm.extend(
            stripped[1..]
                .iter()
                .filter(|w| !w.raw.starts_with('-'))
                .cloned(),
        );
        normalize_simple(&rm, heredoc_bodies, out);
        return;
    }

    // `for x in …`, `case … in`, `select`, `function name`: headers, not commands.
    if matches!(prog.as_str(), "for" | "case" | "select" | "function") {
        return;
    }

    // Windows `cmd /c "payload"` / `cmd /k …`: the payload is a command too
    // (the invocation itself is still normalized below).
    if matches!(prog.as_str(), "cmd" | "cmd.exe") {
        if let Some(payload) = cmd_command(&stripped) {
            if take_work(payload.len()) {
                out.extend(parse(&payload).segments);
            }
        }
    }

    // Shell with `-c "payload"` → recurse into the payload. Also, when a shell
    // reads a heredoc / here-string body, that body is code.
    if SHELLS.contains(&prog.as_str()) {
        let payload = if matches!(prog.as_str(), "pwsh" | "powershell") {
            powershell_command(&stripped)
        } else {
            find_dash_c(&stripped)
        };
        if let Some(payload) = payload {
            // `xargs -I{} sh -c '{}'`: the whole command comes from input.
            if payload.trim() == "{}" {
                out.push(format!(
                    "{UNKNOWN_PAYLOAD_MARKER} {}",
                    masked_join(&stripped)
                ));
            }
            // `sh -c '"$@"' _ rm -rf /`, `bash -c 'eval "$0"' 'rm -rf /'`:
            // the words after the script are its `$0`, `$1`, ….
            let mut bound_all = false;
            if let Some(pos) = stripped.iter().skip(1).position(|w| w.raw == payload) {
                let args = &stripped[pos + 2..];
                if !args.is_empty() && payload.contains('$') {
                    let bound = bind_script_args(&payload, args);
                    if bound != payload && take_work(bound.len()) {
                        out.extend(parse(&bound).segments);
                        // Every `$N` the script uses has a value: the bound
                        // script is the one that runs (`bash -c 'rm -rf
                        // "$1"' _ ./node_modules` deletes `./node_modules`).
                        let chars: Vec<char> = payload.chars().collect();
                        bound_all = chars.windows(2).all(|p| {
                            p[0] != '$'
                                || p[1].to_digit(10).is_none_or(|d| (d as usize) < args.len())
                        }) && !payload.contains("${");
                    }
                }
            }
            if !bound_all {
                for s in parse(&payload).segments {
                    out.push(s);
                }
            }
        }
        // `bash <<EOF … EOF`: the heredoc body is code.
        for body in heredoc_bodies {
            for s in parse(body).segments {
                out.push(s);
            }
        }
        // `bash <<< "…"`: the here-string is code.
        if let Some(pos) = stripped.iter().position(|w| w.raw == "<<<") {
            if let Some(w) = stripped.get(pos + 1) {
                for s in parse(&w.raw).segments {
                    out.push(s);
                }
            }
        }
        // Still emit the shell invocation itself (masked) so e.g. a dangerous
        // program path in argv[0] is visible.
        out.push(masked_join(&stripped));
        return;
    }

    match prog.as_str() {
        // `su [-] [user] -c CMD`, `runuser -l user -c CMD`, `flock FILE -c CMD`,
        // `script -q -c CMD /dev/null`.
        "su" | "runuser" | "flock" | "script" => {
            // Also a clustered `-c` (`script -qc CMD`, `su -lc CMD`).
            let clustered = || {
                stripped.iter().enumerate().skip(1).find_map(|(i, w)| {
                    let r = w.raw.as_str();
                    (r.len() > 2
                        && r.starts_with('-')
                        && !r.starts_with("--")
                        && r.ends_with('c')
                        && r[1..].chars().all(|c| c.is_ascii_alphabetic()))
                    .then(|| stripped.get(i + 1).map(|w| w.raw.clone()))
                    .flatten()
                })
            };
            if let Some(payload) = find_sql_flag(&stripped, &["-c", "--command"]).or_else(clustered)
            {
                out.extend(parse(&payload).segments);
            }
            out.push(masked_join(&stripped));
        }
        "eval" => {
            // Everything after `eval` is code.
            let payload = raw_join(&stripped[1..]);
            for s in parse(&payload).segments {
                out.push(s);
            }
        }
        "xargs" => {
            // Skip xargs options, the rest is a command.
            if let Some(cmd) = after_xargs(&stripped[1..]) {
                for s in parse(&cmd).segments {
                    out.push(s);
                }
            }
            // Emit the xargs invocation itself so `xargs rm -rf` style checks fire.
            out.push(masked_join(&stripped));
        }
        "watch" => {
            // Skip watch options, the rest is a command.
            if let Some(cmd) = after_watch(&stripped[1..]) {
                for s in parse(&cmd).segments {
                    out.push(s);
                }
            }
            // Emit the invocation itself (real spaces: its arguments are a
            // command) so repeated-execution checks can see it.
            out.push(raw_join(&stripped));
        }
        p if interpreter_code_flags(p).is_some() || p == "deno" => {
            let code = interpreter_code(p, &stripped);
            let stdin_code = if code.is_none() && interpreter_reads_stdin(&stripped) {
                stdin_payloads(&stripped, heredoc_bodies)
            } else {
                Vec::new()
            };
            // `python3 -c "$(curl …)"`: the program is downloaded, like
            // `curl … | python3`.
            if let Some(fetch) = code.as_deref().and_then(remote_fetch_command) {
                out.push(format!("{fetch} | {p}"));
            }
            for (k, code) in code.iter().chain(&stdin_code).enumerate() {
                for c in inline_code_commands(code) {
                    out.extend(parse(&c).segments);
                }
                // A program read from stdin is matched like inline code.
                if k > 0 || code_is_stdin(code, &stdin_code) {
                    out.push(interpreter_code_segment(p, code));
                }
            }
            out.push(masked_join(&stripped));
        }
        "psql" | "mysql" | "mariadb" => {
            // Extract the SQL payload of `-c`/`--command`/`-e`/`--execute`
            // (also clustered: `-tAc`, `-Ne`, glued `-e"…"`) and emit the
            // invocation with the real SQL spaces preserved so both the CLI
            // check (psql:drop) and the SQL checks fire. String literals and
            // `--` comments are removed from the SQL first: they are data.
            if let Some(sql) = sql_client_payload(&prog, &stripped) {
                let code = sql_code(&client_sql(&prog, &sql));
                let shown: Vec<String> = stripped
                    .iter()
                    .enumerate()
                    .map(|(i, w)| {
                        let next_is_sql = stripped.get(i + 1).is_some_and(|n| n.raw == sql);
                        if next_is_sql && w.raw.starts_with('-') && !w.raw.starts_with("--") {
                            // A clustered flag (`-tAc`) before the SQL.
                            if prog == "psql" { "-c" } else { "-e" }.to_string()
                        } else if w.raw == sql {
                            code.clone()
                        } else if let Some(flag) = w.raw.strip_suffix(sql.as_str()) {
                            format!("{flag} {code}")
                        } else {
                            w.raw.clone()
                        }
                    })
                    .collect();
                out.push(shown.join(" "));
                // SQL is analyzed per statement, not re-parsed as shell
                // (`now()` is not a function definition, `(SELECT …)` is
                // not a subshell).
                out.extend(sql_payload_segments(&prog, &sql));
            }
            for payload in stdin_payloads(&stripped, heredoc_bodies) {
                out.extend(sql_payload_segments(&prog, &payload));
            }
            out.push(masked_join(&stripped));
        }
        "mongosh" | "mongo" => {
            if let Some(js) = find_sql_flag(&stripped, &["--eval", "-e"]) {
                out.push(raw_join(&stripped));
                out.extend(parse(&js).segments);
            }
            for payload in stdin_payloads(&stripped, heredoc_bodies) {
                out.extend(parse(&payload).segments);
            }
            out.push(masked_join(&stripped));
        }
        // `sqlcmd -Q SQL`, `cockroach sql -e SQL`, `cqlsh -e CQL`,
        // `clickhouse-client --query=SQL`: the statements are analyzed like
        // psql's `-c`, so the generic SQL checks (drop database / keyspace,
        // truncate, DELETE without WHERE) fire too.
        "sqlcmd" | "cockroach" | "cqlsh" | "clickhouse-client"
            if sql_query_flag(&prog, &stripped).is_some() =>
        {
            if let Some(sql) = sql_query_flag(&prog, &stripped) {
                let code = sql_code(&sql);
                let shown: Vec<String> = stripped
                    .iter()
                    .map(|w| {
                        if w.raw == sql {
                            code.clone()
                        } else {
                            w.raw.clone()
                        }
                    })
                    .collect();
                out.push(shown.join(" "));
                out.extend(sql_payload_segments(&prog, &sql));
            }
            for payload in stdin_payloads(&stripped, heredoc_bodies) {
                out.extend(sql_payload_segments(&prog, &payload));
            }
            out.push(masked_join(&stripped));
        }
        // `wrangler d1 execute DB --remote --command "SQL"`: SQL run on the
        // Cloudflare D1 database (`--local`, the default, is a dev copy).
        "wrangler"
            if stripped.iter().any(|w| w.raw == "d1")
                && stripped.iter().any(|w| w.raw == "execute")
                && stripped.iter().any(|w| w.raw == "--remote") =>
        {
            if let Some(sql) = find_sql_flag(&stripped, &["--command"]) {
                out.extend(sql_payload_segments("sqlite3", &sql));
            }
            out.push(masked_join(&stripped));
        }
        "sqlite3" | "duckdb" | "clickhouse-client" | "psql-c" => {
            // `sqlite3 -cmd '.shell rm -rf ~' app.db`: `-cmd` runs before
            // the input, as SQL or a dot-command.
            for (i, w) in stripped.iter().enumerate() {
                if w.raw == "-cmd" {
                    if let Some(cmd) = stripped.get(i + 1) {
                        let t = cmd.raw.trim_start();
                        if let Some(sh) = t
                            .strip_prefix(".shell ")
                            .or_else(|| t.strip_prefix(".system "))
                        {
                            out.extend(parse(sh).segments);
                        }
                        out.extend(sql_payload_segments("sqlite3", &cmd.raw));
                    }
                }
            }
            // sqlite3 <db> "SQL" — last quoted arg is SQL.
            let last = stripped
                .iter()
                .skip(1)
                .rev()
                .find(|w| !w.raw.starts_with('-'))
                .map(|w| w.raw.clone());
            if let Some(sql) = last {
                // `.shell CMD` / `.system CMD` run a shell command.
                let t = sql.trim_start();
                if let Some(cmd) = t
                    .strip_prefix(".shell ")
                    .or_else(|| t.strip_prefix(".system "))
                {
                    out.extend(parse(cmd).segments);
                }
                for st in dollar_quoted_statements(&sql_code(&sql)) {
                    out.extend(parse(&st).segments);
                }
                out.push(sql);
            }
            out.push(masked_join(&stripped));
        }
        "find" => {
            // Filters that select everything (`-name '*'`) or the opposite of
            // something (`-not -name x`) do not narrow the delete.
            let stripped = drop_unselective_find_filters(&stripped);
            out.extend(find_critical_targets(&stripped));
            for c in find_exec_commands(&stripped) {
                for s in parse(&c).segments {
                    out.push(s);
                }
            }
            // `find . -name x -o -delete`: the filter is in another branch,
            // so the delete is unfiltered.
            if find_has_or(&stripped) && stripped.iter().any(|w| w.raw == "-delete") {
                let starts = find_start_points(&stripped);
                out.push(format!("find {} -delete", starts.join(" ")));
            }
            out.push(masked_join(&normalize_operands(&stripped)));
        }
        // `tmux new -d 'cmd'`, `tmux new-window 'cmd'`, `tmux split-window
        // 'cmd'`: the last operand is a shell command.
        "tmux" => {
            let sub = stripped[1..]
                .iter()
                .position(|w| !w.raw.starts_with('-'))
                .map(|p| p + 1);
            let runs = sub.is_some_and(|i| {
                matches!(
                    stripped[i].raw.as_str(),
                    "new"
                        | "new-session"
                        | "neww"
                        | "new-window"
                        | "splitw"
                        | "split-window"
                        | "respawn-pane"
                        | "respawnp"
                        | "respawn-window"
                        | "respawnw"
                        | "run-shell"
                        | "run"
                )
            });
            if let (true, Some(i)) = (runs, sub) {
                let mut j = i + 1;
                while let Some(w) = stripped.get(j) {
                    let r = w.raw.as_str();
                    if r == "--" {
                        j += 1;
                        break;
                    }
                    if !r.starts_with('-') {
                        break;
                    }
                    // Options with a value.
                    let takes = matches!(
                        r,
                        "-s" | "-n" | "-t" | "-c" | "-x" | "-y" | "-e" | "-F" | "-l" | "-f"
                    );
                    j += if takes { 2 } else { 1 };
                }
                if let Some(rest) = stripped.get(j..).filter(|r| !r.is_empty()) {
                    out.extend(parse(&raw_join(rest)).segments);
                }
            }
            out.push(masked_join(&stripped));
        }
        // `vim -c ':!cmd'`, `vim +'!cmd'`: an ex command that runs a shell
        // command.
        "vim" | "vi" | "nvim" | "view" | "ex" => {
            for (k, w) in stripped.iter().enumerate().skip(1) {
                let ex = if w.raw == "-c" || w.raw == "--cmd" {
                    stripped.get(k + 1).map(|v| v.raw.as_str())
                } else {
                    w.raw.strip_prefix('+')
                };
                if let Some(bang) = ex
                    .map(|e| e.trim_start_matches(':').trim_start())
                    .and_then(|e| e.strip_prefix('!').or_else(|| e.strip_prefix("silent !")))
                {
                    out.extend(parse(bang).segments);
                }
            }
            out.push(masked_join(&stripped));
        }
        // `at now <<< 'cmd'`, `at now <<EOF … EOF`: the input runs later.
        "at" | "batch" => {
            if let Some(w) = stripped
                .iter()
                .position(|w| w.raw == "<<<")
                .and_then(|p| stripped.get(p + 1))
            {
                out.extend(parse(&w.raw).segments);
            }
            for body in heredoc_bodies {
                out.extend(parse(body).segments);
            }
            out.push(masked_join(&stripped));
        }
        // `parallel CMD ::: ARG…` runs CMD once per argument (`{}` is the
        // argument, else it is appended).
        "parallel" => {
            for c in parallel_commands(&stripped) {
                out.extend(parse(&c).segments);
            }
            out.push(masked_join(&stripped));
        }
        p if DATA_COMMANDS.contains(&p) => {
            let mut kept = program_and_redirects(&stripped);
            kept.extend(read_file_operands(p, &stripped));
            out.push(masked_join(&kept));
        }
        // `alias name='value'` is a definition (handled in
        // `process_commands`): the value is analyzed where it is used.
        "alias" => {}
        // `history -s TEXT` / `print -s TEXT` only add TEXT to the history.
        "history" | "print"
            if stripped
                .get(1)
                .is_some_and(|w| matches!(w.raw.as_str(), "-s" | "-S")) =>
        {
            out.push(masked_join(&stripped[..2]));
        }
        _ => {
            let payload = exec_payload(&prog, &stripped);
            let is_remote_wrapper = payload.is_some()
                || (prog == "ssh" && !heredoc_bodies.is_empty())
                || (prog == "ssh" && stripped.iter().any(|w| w.raw == "<<<"));
            if is_remote_wrapper {
                let mut remote = payload
                    .as_deref()
                    .map(|inner| parse(inner).segments)
                    .unwrap_or_default();
                // `ssh host bash -s <<'EOF'`, `docker exec -i c sh <<EOF`, and
                // `ssh host <<EOF` (the remote login shell reads stdin): the
                // heredoc / here-string is the remote script.
                if payload.as_deref().is_none_or(reads_stdin_code) {
                    for body in heredoc_bodies {
                        remote.extend(parse(body).segments);
                    }
                    if let Some(pos) = stripped.iter().position(|w| w.raw == "<<<") {
                        if let Some(w) = stripped.get(pos + 1) {
                            remote.extend(parse(&w.raw).segments);
                        }
                    }
                }
                REMOTE.with(|r| r.borrow_mut().extend(remote.iter().cloned()));
                out.extend(remote);
            }
            // Drop tool-global options that appear *before* the subcommand so
            // `git -C dir push -f`, `kubectl --context=x delete ns`,
            // `helm -n x uninstall` and `terraform -chdir=x destroy` match the
            // same as the plain form.
            // `git -c core.hooksPath=DIR …` runs a program for this one
            // invocation: report it like `git config core.hooksPath DIR`.
            if prog == "git" {
                out.extend(git_exec_config(&stripped));
                // `GIT_SSH_COMMAND='…' git fetch`, `GIT_EXTERNAL_DIFF=…`,
                // `GIT_PAGER=…`, `GIT_EDITOR=…`: git runs the value.
                for w in words.iter().take_while(|w| is_var_assignment(&w.raw)) {
                    if let Some((k, v)) = w.raw.split_once('=') {
                        if matches!(
                            k,
                            "GIT_SSH_COMMAND"
                                | "GIT_SSH"
                                | "GIT_EXTERNAL_DIFF"
                                | "GIT_PAGER"
                                | "GIT_EDITOR"
                                | "GIT_SEQUENCE_EDITOR"
                                | "GIT_ASKPASS"
                                | "GIT_PROXY_COMMAND"
                        ) && !v.is_empty()
                        {
                            out.extend(parse(v).segments);
                        }
                    }
                }
            }
            // `<tool> … -- rm -rf /`: an unknown runner passes the words after
            // a lone `--` on as a command (`dotenv -- cmd`, `xyz exec --
            // cmd`). When they start with a command shellfirm knows to be
            // risky, that command is analysed too.
            if !is_remote_wrapper {
                if let Some(inner) = runner_inner_command(&prog, &stripped) {
                    normalize_simple(inner, &[], out);
                }
            }
            let normalized = strip_tool_globals(&prog, &stripped);
            if is_remote_wrapper {
                let outer = masked_join(&normalized);
                REMOTE.with(|r| r.borrow_mut().push(outer));
            }
            let as_written = (orig_argv0.raw.contains('/') && orig_argv0.raw != prog).then(|| {
                let mut w = normalized.clone();
                w[0] = orig_argv0.clone();
                masked_join(&w)
            });
            let normalized = if PATH_COMMANDS.contains(&prog.as_str()) {
                normalize_operands(&expand_brace_words(&normalized))
            } else if REBASE_ALL_COMMANDS.contains(&prog.as_str()) {
                expand_brace_words(&normalized)
            } else {
                normalized
            };
            out.push(masked_join(&normalized));
            out.extend(as_written);
        }
    }
}

/// The command an npm package runs when it is started by name (`npx
/// firebase-tools@latest`, `bunx supabase@1.2`, `pnpm dlx @railway/cli`):
/// the version or tag is dropped and a few package names map to their
/// command. `None` for an ordinary program word.
fn package_binary(word: &str) -> Option<String> {
    if word.contains('/') && !word.starts_with('@') {
        return None;
    }
    // `@scope/name@1.2` → `@scope/name`; `name@latest` → `name`.
    let skip = word.chars().next().map_or(0, char::len_utf8);
    let name = match word[skip..].rfind('@') {
        Some(at) => {
            let (name, version) = word.split_at(at + skip);
            let version = &version[1..];
            if version.is_empty()
                || !version
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '^' | '~' | '_'))
            {
                return None;
            }
            name
        }
        None => word,
    };
    let mapped = match name {
        "firebase-tools" => "firebase",
        "netlify-cli" => "netlify",
        "@railway/cli" => "railway",
        "@planetscale/cli" => "pscale",
        "@tursodatabase/turso" => "turso",
        "@neondatabase/neonctl" => "neonctl",
        "@cloudflare/wrangler" => "wrangler",
        "@supabase/cli" => "supabase",
        n if n != word => n,
        _ => return None,
    };
    Some(mapped.to_string())
}

/// Programs whose words after a lone `--` are paths, patterns or arguments
/// of their own (never a command), or that run them elsewhere (handled as
/// remote commands).
const DASHDASH_NOT_A_COMMAND: &[&str] = &[
    "git",
    "grep",
    "egrep",
    "fgrep",
    "rg",
    "ag",
    "ls",
    "cat",
    "echo",
    "printf",
    "cp",
    "mv",
    "rm",
    "rmdir",
    "touch",
    "mkdir",
    "ln",
    "diff",
    "kill",
    "set",
    "getopt",
    "getopts",
    "chmod",
    "chown",
    "chgrp",
    "find",
    "tar",
    "zip",
    "unzip",
    "sed",
    "awk",
    "head",
    "tail",
    "less",
    "more",
    "wc",
    "sort",
    "uniq",
    "cut",
    "tr",
    "test",
    "[",
    "ssh",
    "mosh",
    "kubectl",
    "oc",
    "docker",
    "podman",
    "nerdctl",
    "cargo",
    "go",
    "npm",
    "yarn",
    "pnpm",
    "make",
    "mise",
    "rtx",
    "argocd",
    "vault",
    "gh",
    "shellfirm",
    "fly",
    "flyctl",
    "heroku",
    "render",
    "railway",
];

/// Commands that make the words after an unknown runner's `--` worth
/// analysing as a command of their own (see [`runner_inner_command`]).
const RISKY_INNER_COMMANDS: &[&str] = &[
    "rm",
    "rmdir",
    "shred",
    "srm",
    "unlink",
    "dd",
    "mkfs",
    "mke2fs",
    "mkswap",
    "wipefs",
    "blkdiscard",
    "sgdisk",
    "fdisk",
    "parted",
    "chmod",
    "chown",
    "chgrp",
    "mv",
    "cp",
    "truncate",
    "find",
    "git",
    "kubectl",
    "oc",
    "helm",
    "terraform",
    "tofu",
    "terragrunt",
    "pulumi",
    "docker",
    "podman",
    "psql",
    "mysql",
    "mariadb",
    "redis-cli",
    "mongosh",
    "mongo",
    "sqlite3",
    "prisma",
    "rails",
    "rake",
    "aws",
    "gcloud",
    "az",
    "sudo",
    "doas",
    "eval",
    "xargs",
    "curl",
    "wget",
    "npx",
    "bunx",
    "shutdown",
    "reboot",
    "halt",
    "poweroff",
    "kill",
    "killall",
    "pkill",
    "systemctl",
    "crontab",
    "iptables",
    "nft",
    "heroku",
    "flyctl",
    "fly",
    "vercel",
    "netlify",
    "firebase",
    "supabase",
    "wrangler",
    "rimraf",
    "zfs",
    "zpool",
    "lvremove",
    "vgremove",
    "pvremove",
    "cryptsetup",
    "mdadm",
    "drush",
    "artisan",
    "php",
    "python",
    "python3",
    "node",
    "perl",
    "ruby",
];

/// The command after a lone `--` of a program shellfirm does not know as a
/// wrapper (`doppler run -- rm -rf /`, `xyz -- terraform destroy`), when it
/// starts with a risky command (or a shell).
fn runner_inner_command<'w>(prog: &str, words: &'w [Word]) -> Option<&'w [Word]> {
    if DASHDASH_NOT_A_COMMAND.contains(&prog) || SHELLS.contains(&prog) {
        return None;
    }
    let pos = words.iter().skip(1).position(|w| w.raw == "--")? + 2;
    let inner = words.get(pos..).filter(|w| !w.is_empty())?;
    let first = &inner[0].raw;
    if first.starts_with('-') || first.contains('=') {
        return None;
    }
    let name = program_name(first);
    (RISKY_INNER_COMMANDS.contains(&name.as_str())
        || SHELLS.contains(&name.as_str())
        || name.starts_with("mkfs."))
    .then_some(inner)
}

/// Marker between `git` and `config` in the segment emitted for a `git -c
/// key=value` option (a setting for one invocation, not a persistent one).
pub const GIT_ONE_SHOT_CONFIG: &str = "--shellfirm-one-shot";

/// `git -c key=value` / `--config-env=key=ENV` global options that make git
/// run a program, as `git config <key> <value>` segments.
fn git_exec_config(words: &[Word]) -> Vec<String> {
    const EXEC_KEYS: &[&str] = &[
        "core.hookspath",
        "core.sshcommand",
        "core.fsmonitor",
        "core.pager",
        "core.editor",
        "core.askpass",
        "uploadpack.packobjectshook",
        "protocol.ext.allow",
    ];
    let mut out = Vec::new();
    let mut i = 1;
    while i < words.len() {
        let w = words[i].raw.as_str();
        if !w.starts_with('-') {
            break;
        }
        let kv = if w == "-c" || w == "--config-env" {
            i += 1;
            words.get(i).map(|v| v.raw.clone())
        } else {
            w.strip_prefix("--config-env=")
                .or_else(|| w.strip_prefix("-c").filter(|r| r.contains('=')))
                .map(str::to_string)
        };
        if let Some((k, v)) = kv.as_deref().and_then(|kv| kv.split_once('=')) {
            // `git -c alias.x='!CMD' x`: a shell alias runs CMD.
            if k.to_ascii_lowercase().starts_with("alias.") {
                if let Some(cmd) = v.strip_prefix('!') {
                    out.extend(parse(cmd).segments);
                }
            }
            if EXEC_KEYS.contains(&k.to_ascii_lowercase().as_str()) && !v.is_empty() {
                let canonical = match k.to_ascii_lowercase().as_str() {
                    "core.hookspath" => "core.hooksPath",
                    "core.sshcommand" => "core.sshCommand",
                    "core.fsmonitor" => "core.fsmonitor",
                    "uploadpack.packobjectshook" => "uploadpack.packObjectsHook",
                    _ => k,
                };
                // Marked one-shot: it applies to this invocation only (the
                // program checks match it, the persistence check does not).
                out.push(format!(
                    "git {GIT_ONE_SHOT_CONFIG} config {canonical} {}",
                    shell_quote(v)
                ));
            }
        } else if matches!(w, "-C" | "--git-dir" | "--work-tree" | "--namespace") {
            i += 1;
        }
        i += 1;
    }
    out
}

/// Most words one brace expansion may produce.
const MAX_BRACE_WORDS: usize = 64;

/// Bash brace expansion of comma lists: `{src,build}` → `src build`,
/// `src{,.bak}` → `src src.bak`, nested lists too. Ranges (`{1..3}`) and
/// `${VAR}` are left as they are. At most [`MAX_BRACE_WORDS`] results.
fn expand_braces(w: &str) -> Vec<String> {
    let bytes = w.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' && (i == 0 || bytes[i - 1] != b'$') {
            // Find the matching `}` and the top-level commas.
            let mut depth = 0usize;
            let mut commas = Vec::new();
            let mut end = None;
            for (j, &b) in bytes.iter().enumerate().skip(i) {
                match b {
                    b'{' => depth += 1,
                    b'}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = Some(j);
                            break;
                        }
                    }
                    b',' if depth == 1 => commas.push(j),
                    _ => {}
                }
            }
            if let Some(end) = end {
                if commas.is_empty() {
                    if let Some(items) = brace_range(&w[i + 1..end]) {
                        let prefix = &w[..i];
                        let suffix = &w[end + 1..];
                        let mut out = Vec::new();
                        for item in items {
                            for e in expand_braces(&format!("{prefix}{item}{suffix}")) {
                                if out.len() >= MAX_BRACE_WORDS {
                                    return out;
                                }
                                out.push(e);
                            }
                        }
                        return out;
                    }
                } else {
                    let prefix = &w[..i];
                    let suffix = &w[end + 1..];
                    let mut bounds = vec![i];
                    bounds.extend(&commas);
                    bounds.push(end);
                    let mut out = Vec::new();
                    for pair in bounds.windows(2) {
                        let alt = &w[pair[0] + 1..pair[1]];
                        for e in expand_braces(&format!("{prefix}{alt}{suffix}")) {
                            if out.len() >= MAX_BRACE_WORDS {
                                return out;
                            }
                            out.push(e);
                        }
                    }
                    return out;
                }
            }
        }
        i += 1;
    }
    vec![w.to_string()]
}

/// zsh glob alternation: `(src|build)` → `src build`, `~/(.ssh|data)` →
/// `~/.ssh ~/data` (nested groups too). At most [`MAX_BRACE_WORDS`] results.
fn expand_alternation(w: &str) -> Vec<String> {
    let bytes = w.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b != b'(' || (i > 0 && bytes[i - 1] == b'$') {
            continue;
        }
        let mut depth = 0usize;
        let mut bars = Vec::new();
        let mut end = None;
        for (j, &c) in bytes.iter().enumerate().skip(i) {
            match c {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(j);
                        break;
                    }
                }
                b'|' if depth == 1 => bars.push(j),
                _ => {}
            }
        }
        let Some(end) = end else {
            return vec![w.to_string()];
        };
        let (prefix, suffix) = (&w[..i], &w[end + 1..]);
        if bars.is_empty() {
            // A one-branch group (`~/(.s)sh`, `s(r)c`, `((src))`) matches its
            // body. A group that ends the word without a nested group is a
            // glob qualifier (`src(N)`), but a qualifier can also be a
            // typo'd group: both readings are kept.
            let body = &w[i + 1..end];
            if body.is_empty() || body.contains(char::is_whitespace) {
                continue;
            }
            let inline = expand_alternation(&format!("{prefix}{body}{suffix}"));
            if suffix.is_empty() && !body.contains('(') {
                let mut out = vec![w.to_string()];
                out.extend(inline.into_iter().take(MAX_BRACE_WORDS - 1));
                return out;
            }
            return inline;
        }
        let mut bounds = vec![i];
        bounds.extend(&bars);
        bounds.push(end);
        let mut out = Vec::new();
        for pair in bounds.windows(2) {
            for e in expand_alternation(&format!("{prefix}{}{suffix}", &w[pair[0] + 1..pair[1]])) {
                if out.len() >= MAX_BRACE_WORDS {
                    return out;
                }
                out.push(e);
            }
        }
        return out;
    }
    vec![w.to_string()]
}

/// The items of a brace sequence body (`1..5`, `a..e`, `10..1..2`), capped
/// at [`MAX_BRACE_WORDS`]; `None` when `body` is not a sequence.
fn brace_range(body: &str) -> Option<Vec<String>> {
    let parts: Vec<&str> = body.split("..").collect();
    let (from, to, step) = match parts.as_slice() {
        [a, b] => (*a, *b, None),
        [a, b, s] => (*a, *b, Some(*s)),
        _ => return None,
    };
    let step: i64 = step.map_or(Some(1), |s| s.parse::<i64>().ok().map(i64::abs))?;
    let step = step.max(1);
    let (a, b, letters, width) = if let (Ok(a), Ok(b)) = (from.parse::<i64>(), to.parse::<i64>()) {
        // `{01..10}`: zero-padded to the widest bound.
        let padded = from.starts_with('0') && from.len() > 1 || to.starts_with('0') && to.len() > 1;
        (
            a,
            b,
            false,
            if padded { from.len().max(to.len()) } else { 0 },
        )
    } else {
        let (mut fa, mut fb) = (from.chars(), to.chars());
        match (fa.next(), fa.next(), fb.next(), fb.next()) {
            (Some(x), None, Some(y), None)
                if x.is_ascii_alphabetic() && y.is_ascii_alphabetic() =>
            {
                (i64::from(u32::from(x)), i64::from(u32::from(y)), true, 0)
            }
            _ => return None,
        }
    };
    let mut out = Vec::new();
    let mut v = a;
    loop {
        if out.len() >= MAX_BRACE_WORDS {
            break;
        }
        if letters {
            let c = u32::try_from(v).ok().and_then(char::from_u32)?;
            out.push(c.to_string());
        } else {
            out.push(format!("{v:0width$}"));
        }
        if v == b {
            break;
        }
        v += if a < b { step } else { -step };
        if (a < b && v > b) || (a > b && v < b) {
            break;
        }
    }
    Some(out)
}

/// Apply [`expand_braces`] to the operands of a command.
fn expand_brace_words(words: &[Word]) -> Vec<Word> {
    let mut out = Vec::with_capacity(words.len());
    for (i, w) in words.iter().enumerate() {
        let braces = w.raw.contains('{') && (w.raw.contains(',') || w.raw.contains(".."));
        // A trailing zsh glob qualifier (`src(/)`, `src(N)`) is not an
        // alternation: [`operand_path`] drops it.
        let qualifier = w.raw.ends_with(')')
            && w.raw.rfind('(').is_some_and(|open| {
                let body = &w.raw[open + 1..w.raw.len() - 1];
                // Letters only (`.gi(t)`, `src(N)`) may also be a one-branch
                // group: both readings are kept.
                open > 0
                    && !body.is_empty()
                    && !w.raw[..open].contains(['(', ')'])
                    && !body.chars().all(|c| c.is_ascii_alphabetic())
                    && body
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "#/.@=*%^:-+[],!".contains(c))
            });
        let alternation = w.raw.contains('(')
            && w.raw.contains(')')
            && !qualifier
            && !w.raw.contains("(#")
            && !w.raw.contains(char::is_whitespace)
            && !w.raw.contains("$(");
        if i == 0 || !(braces || alternation) {
            out.push(w.clone());
            continue;
        }
        let expanded = expand_braces(&w.raw)
            .into_iter()
            .flat_map(|e| expand_alternation(&e))
            .take(MAX_BRACE_WORDS);
        // An empty unquoted result is dropped (`{src,}` is just `src`), and a
        // repeated one counted once (`src(|)`).
        let mut seen: Vec<String> = Vec::new();
        for e in expanded.filter(|e| !e.is_empty()) {
            if seen.contains(&e) {
                continue;
            }
            seen.push(e.clone());
            out.push(Word {
                masked: e.chars().map(mask_char).collect(),
                raw: e,
            });
        }
    }
    out
}

/// Placeholder path for a variable assigned from `mktemp` (a fresh temporary
/// file or directory).
const MKTEMP_PATH: &str = "/tmp/shellfirm-mktemp.XXXXXX";

/// The path an operand names when its spelling says more than its text:
///
/// * a zsh glob qualifier is dropped (`src(N)` → `src`, `*(.)` → `*`);
/// * `` `cmd` `` is `$(cmd)`;
/// * the current directory: `$(pwd)`, `$PWD`, `${PWD}`, `~+` → `.`, and the
///   repository root `$(git rev-parse --show-toplevel)` → `.`;
/// * `$(echo X)` / `$(printf %s X)` → `X`, `$(mktemp …)` → a temp path;
/// * any other command substitution is output of another command: the
///   unknown-target placeholder `{}`;
/// * `${VAR:-D}` with a critical default (`.`, `~`, `/`, …) → `D`.
fn operand_path(raw: &str) -> String {
    let mut s = raw.to_string();
    // `` `cmd` `` → `$(cmd)`.
    while let Some(a) = s.find('`') {
        let Some(b) = s[a + 1..].find('`') else { break };
        let inner = s[a + 1..a + 1 + b].to_string();
        s.replace_range(a..=a + 1 + b, &format!("$({inner})"));
    }
    // zsh extendedglob flags: `(#i)` / `(#l)` match case-insensitively
    // (`~/(#i).SSH` is `~/.ssh`); other `(#…)` flags (approximate matching)
    // make the target unknown.
    while let Some(pos) = s.find("(#") {
        let Some(close) = s[pos..].find(')').map(|c| pos + c) else {
            break;
        };
        let flags = &s[pos + 2..close];
        if !flags.is_empty() && flags.chars().all(|c| matches!(c, 'i' | 'l' | 'I')) {
            let tail = if flags.contains(['i', 'l']) {
                s[close + 1..].to_lowercase()
            } else {
                s[close + 1..].to_string()
            };
            s = format!("{}{tail}", &s[..pos]);
        } else {
            return "{}".to_string();
        }
    }
    // zsh glob qualifier: a trailing `(…)` of qualifier characters.
    if s.ends_with(')') {
        if let Some(open) = s.rfind('(') {
            let before = s[..open].chars().next_back();
            let body = &s[open + 1..s.len() - 1];
            if open > 0
                && !matches!(before, Some('$' | '<' | '>' | '\\'))
                && !body.is_empty()
                && body
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "#/.@=*%^:-+[],!".contains(c))
            {
                s.truncate(open);
            }
        }
    }
    // Directory-stack tildes: `~-` is `$OLDPWD`; `~-/x`, `~N`, `~+N`, `~-N`
    // are directories of the stack, unknown here.
    if s == "~-" {
        return "$OLDPWD".to_string();
    }
    if let Some(rest) = s.strip_prefix('~') {
        let head = rest.split('/').next().unwrap_or("");
        let digits = head.trim_start_matches(['+', '-']);
        let stack = (head.starts_with('-') && rest.len() > 1 && head == "-")
            || (!digits.is_empty()
                && digits.chars().all(|c| c.is_ascii_digit())
                && head.len() - digits.len() <= 1);
        if stack {
            return "{}".to_string();
        }
    }
    // zsh extended glob: `^README.md` is everything except README.md, and
    // `*~README.md` is `*` without it.
    if s.len() > 1 && s.starts_with('^') && !s.contains('/') {
        return "*".to_string();
    }
    if let Some((glob, _)) = s
        .split_once('~')
        .filter(|(g, rest)| g.contains('*') && !rest.is_empty())
    {
        return normalize_path(glob);
    }
    let cwd_alias = |s: &str| -> Option<String> {
        for p in ["~+", "$PWD", "${PWD}"] {
            if s == p {
                return Some(".".to_string());
            }
            if let Some(rest) = s.strip_prefix(p).and_then(|r| r.strip_prefix('/')) {
                return Some(rest.to_string());
            }
        }
        None
    };
    if let Some(p) = cwd_alias(&s) {
        return normalize_path(&p);
    }
    // The parent of the current directory: zsh `${PWD:h}` / `$PWD:h`,
    // `${PWD%/*}`, `$(dirname $PWD)`.
    for p in ["${PWD:h}", "$PWD:h", "${PWD%/*}"] {
        if s == p {
            return "..".to_string();
        }
        if let Some(rest) = s.strip_prefix(p).and_then(|r| r.strip_prefix('/')) {
            return normalize_path(&format!("../{rest}"));
        }
    }
    if let Some(r) = s.strip_prefix("$(") {
        if let Some(close) = r.find(')') {
            let inner: Vec<&str> = r[..close].split_whitespace().collect();
            let rest = &r[close + 1..];
            let base = match inner.as_slice() {
                ["pwd" | "/bin/pwd" | "/usr/bin/pwd"]
                | ["pwd", "-P" | "-L"]
                | ["git", "rev-parse", "--show-toplevel"] => Some(".".to_string()),
                ["echo" | "printf", x] | ["printf", "%s" | "%s\\n", x] => Some((*x).to_string()),
                ["dirname", "$PWD" | "${PWD}" | "$(pwd)" | "."] => Some("..".to_string()),
                ["mktemp", ..] if is_pure_mktemp_command(&r[..close]) => {
                    Some(MKTEMP_PATH.to_string())
                }
                _ => None,
            };
            return match base {
                Some(b) if rest.is_empty() => normalize_path(&b),
                Some(b) => normalize_path(&format!("{b}{rest}")),
                // Output of another command: the unknown-target placeholder.
                None if rest.is_empty() => "{}".to_string(),
                None => s,
            };
        }
    }
    if let Some((body, rest)) = s.strip_prefix("${").and_then(|r| r.split_once('}')) {
        if let Some((name, default)) = body.split_once(":-").or_else(|| body.split_once('-')) {
            if name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                && matches!(
                    default,
                    "." | ".." | "~" | "/" | "*" | "$HOME" | "./*" | "~/*"
                )
                && rest.is_empty()
            {
                return normalize_path(default);
            }
        }
        // `${HOME:-/x}`, `${~HOME}`, `${=HOME}`, `${HOME:a}`, `${HOME:?}`:
        // the home directory (its strongest reading). `${HOME:h}` /
        // `${HOME%/*}` (its parent) and any other operator on a variable:
        // not known until it runs.
        let name_start = body.trim_start_matches(['~', '=', '^', '#', '!']);
        let name_len = name_start
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(name_start.len());
        let (name, op) = name_start.split_at(name_len);
        if !name.is_empty() && (name_len < body.len()) {
            let parent = matches!(op, ":h" | "%/*" | "%%/*") || op.starts_with(":h");
            let base = if name == "HOME" && !parent {
                "$HOME".to_string()
            } else if op.starts_with(":?") || op.starts_with('?') {
                // `${DIR:?}`: the variable, or an error.
                format!("${name}")
            } else {
                return "{}".to_string();
            };
            return home_tilde(&normalize_path(&format!("{base}{rest}")));
        }
    }
    home_tilde(&normalize_path(&s))
}

/// `$HOME` / `${HOME}` (and `$HOME/…`) spelled as `~` (`~/…`), the one
/// spelling every home-directory check matches.
fn home_tilde(s: &str) -> String {
    for p in ["$HOME", "${HOME}"] {
        if s == p {
            return "~".to_string();
        }
        if let Some(rest) = s.strip_prefix(p).filter(|r| r.starts_with('/')) {
            return format!("~{rest}");
        }
    }
    s.to_string()
}

/// Apply [`normalize_path`] to every operand of a path-taking command.
fn normalize_operands(words: &[Word]) -> Vec<Word> {
    let mut out = Vec::with_capacity(words.len());
    out.push(words[0].clone());
    // The owner of `chown OWNER …` / group of `chgrp GROUP …` is not a path
    // (`$(whoami)` names a user, not another command's output).
    let owner_at = matches!(program_name(&words[0].raw).as_str(), "chown" | "chgrp")
        .then(|| words.iter().skip(1).position(|w| !w.raw.starts_with('-')))
        .flatten()
        .map(|p| p + 1);
    for (k, w) in words.iter().enumerate().skip(1) {
        if Some(k) == owner_at {
            out.push(w.clone());
            continue;
        }
        let n = operand_path(&w.raw);
        if n == w.raw {
            out.push(w.clone());
        } else {
            out.push(Word {
                masked: n.chars().map(mask_char).collect(),
                raw: n,
            });
        }
    }
    out
}

/// Value-taking global flags per tool (space-separated form).
fn tool_value_flags(tool: &str) -> &'static [&'static str] {
    match tool {
        "git" => &[
            "-C",
            "-c",
            "--git-dir",
            "--work-tree",
            "--namespace",
            "--exec-path",
        ],
        "kubectl" | "k" | "oc" => &[
            "-n",
            "--namespace",
            "--context",
            "--kubeconfig",
            "-s",
            "--server",
            "--as",
            "--as-group",
            "--token",
            "--user",
            "--cluster",
            "--cache-dir",
            "--request-timeout",
            "-v",
            "--v",
        ],
        "helm" => &[
            "-n",
            "--namespace",
            "--kube-context",
            "--kubeconfig",
            "--kube-apiserver",
            "--registry-config",
            "--repository-config",
            "--repository-cache",
        ],
        "docker" => &["-H", "--host", "--config", "--context", "-l", "--log-level"],
        "gcloud" => &[
            "--project",
            "--account",
            "--configuration",
            "--impersonate-service-account",
            "--billing-project",
            "--verbosity",
            "--format",
            "--region",
            "--zone",
            "--flags-file",
        ],
        "az" => &["--subscription", "--output", "-o", "--query"],
        "heroku" => &["--app", "-a", "--remote", "-r"],
        "aws" => &[
            "--profile",
            "--region",
            "--output",
            "--endpoint-url",
            "--query",
            "--color",
            "--ca-bundle",
            "--cli-read-timeout",
            "--cli-connect-timeout",
        ],
        _ => &[],
    }
}

/// Whether a tool participates in global-flag normalization.
fn is_global_flag_tool(tool: &str) -> bool {
    matches!(
        tool,
        "git"
            | "kubectl"
            | "k"
            | "oc"
            | "helm"
            | "docker"
            | "terraform"
            | "tofu"
            | "terragrunt"
            | "gcloud"
            | "az"
            | "heroku"
            | "aws"
    )
}

/// Drop leading global options (and their values) that appear before the
/// subcommand/verb for known tools. Returns the tool word followed by the
/// subcommand and the rest.
fn strip_tool_globals(tool: &str, words: &[Word]) -> Vec<Word> {
    if !is_global_flag_tool(tool) || words.len() < 2 {
        return words.to_vec();
    }
    let value_flags = tool_value_flags(tool);
    let mut i = 1;
    while i < words.len() {
        let w = &words[i].raw;
        if w.starts_with('-') {
            // `--flag=value` / `-chdir=x` are a single token.
            if w.contains('=') {
                i += 1;
                continue;
            }
            // Separate value form: consume the following value token.
            if value_flags.contains(&w.as_str()) && i + 1 < words.len() {
                i += 2;
            } else {
                // Boolean flag (or unknown) — consume just the flag.
                i += 1;
            }
        } else {
            break;
        }
    }
    let mut result = vec![words[0].clone()];
    result.extend_from_slice(&words[i..]);
    result
}

/// Input fed to a command's stdin as code: heredoc bodies and `<<< word`
/// here-strings.
fn stdin_payloads(words: &[Word], heredoc_bodies: &[String]) -> Vec<String> {
    let mut out: Vec<String> = heredoc_bodies.to_vec();
    for (i, w) in words.iter().enumerate() {
        if w.raw == "<<<" {
            if let Some(next) = words.get(i + 1) {
                out.push(next.raw.clone());
            }
        }
    }
    out
}

/// Join words into a normalized, matchable string using masked values.
fn masked_join(words: &[Word]) -> String {
    words
        .iter()
        .map(|w| w.masked.as_str())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Join words preserving real whitespace (for recursion / SQL).
fn raw_join(words: &[Word]) -> String {
    words
        .iter()
        .map(|w| w.raw.as_str())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Short options of `sudo` / `doas` / `run0` that take a value (`-u USER`,
/// `-uUSER`, and as the last letter of a cluster: `-iu USER`).
const PRIVILEGE_SHORT_VALUE_OPTS: &[char] =
    &['u', 'g', 'p', 'C', 'D', 'R', 'h', 'r', 't', 'T', 'U'];

/// Long options of `sudo` / `doas` / `run0` that take the next word as their
/// value (unless written `--opt=value`).
const PRIVILEGE_LONG_VALUE_OPTS: &[&str] = &[
    "--user",
    "--group",
    "--prompt",
    "--chdir",
    "--chroot",
    "--host",
    "--role",
    "--type",
    "--close-from",
    "--other-user",
    "--command-timeout",
    // run0
    "--nice",
    "--setenv",
    "--unit",
    "--property",
    "--description",
    "--slice",
    "--background",
    "--machine",
];

/// One option word of `sudo` / `doas` / `run0`: the words it uses and the
/// user it names.
///
/// It uses 1 word, or 2 when its value is the next word; the user comes from
/// `-u USER`, `-uUSER`, `-iu USER`, `--user USER` or
/// `--user=USER`. Short options are read as a cluster, as sudo does:
/// `-iu postgres` is `-i -u postgres`, and `-Hu`, `-su`, `-nu`, `-Eu` and
/// `-kiu` take the next word as the user.
#[must_use]
pub fn privilege_option(opt: &str, next: Option<&str>) -> (usize, Option<String>) {
    if let Some(long) = opt.strip_prefix("--") {
        if let Some((name, value)) = long.split_once('=') {
            return (1, (name == "user").then(|| value.to_string()));
        }
        if PRIVILEGE_LONG_VALUE_OPTS.contains(&opt) {
            let user = (opt == "--user")
                .then(|| next.map(str::to_string))
                .flatten();
            return (2, user);
        }
        return (1, None);
    }
    let Some(cluster) = opt.strip_prefix('-') else {
        return (1, None);
    };
    for (i, c) in cluster.char_indices() {
        if PRIVILEGE_SHORT_VALUE_OPTS.contains(&c) {
            let rest = &cluster[i + c.len_utf8()..];
            return if rest.is_empty() {
                (2, (c == 'u').then(|| next.map(str::to_string)).flatten())
            } else {
                (1, (c == 'u').then(|| rest.to_string()))
            };
        }
    }
    (1, None)
}

/// Where the command of a secret / environment runner starts
/// (`doppler run -- cmd`, `op run --env-file .env -- cmd`, `dotenv -e .env
/// -- cmd`, `railway run cmd`, `bundle exec cmd`, `aws-vault exec prof --
/// cmd`), or `None` when `words[idx]` does not run a command.
fn runner_command_start(prog: &str, words: &[Word], idx: usize) -> Option<usize> {
    let n = words.len();
    let sub = words.get(idx + 1).map(|w| w.raw.as_str());
    // The words after the program (and its run sub-command).
    let first = match (prog, sub) {
        (
            "dotenv" | "doppler" | "op" | "infisical" | "dotenvx" | "phase" | "railway" | "devbox"
            | "teller",
            Some("run"),
        )
        | ("bundle" | "aws-vault" | "chamber", Some("exec")) => idx + 2,
        ("dotenv" | "envchain", _) => idx + 1,
        _ => return None,
    };
    // A lone `--` ends the runner's own options.
    if let Some(dd) = words[first.min(n)..].iter().position(|w| w.raw == "--") {
        let at = first + dd + 1;
        return (at < n).then_some(at);
    }
    let value_flags: &[&str] = &[
        "--env-file",
        "-e",
        "--environment",
        "--env",
        "-s",
        "--service",
        "-p",
        "--project",
        "-c",
        "--config",
        "--token",
        "--path",
        "--gemfile",
        "-v",
    ];
    let mut i = first;
    // `aws-vault exec PROFILE cmd`, `envchain NS cmd`, `chamber exec SVC
    // -- cmd`: the profile / namespace comes first.
    if matches!(prog, "aws-vault" | "envchain") {
        while i < n && words[i].raw.starts_with('-') {
            i += 1;
        }
        i += 1;
    }
    while i < n && words[i].raw.starts_with('-') {
        let w = words[i].raw.as_str();
        i += 1;
        if value_flags.contains(&w) {
            i += 1;
        }
    }
    (i < n).then_some(i)
}

/// Whether `w` names a tool version for `nvm exec` / `nvm run` (`18`,
/// `v20.1.0`, `lts/iron`, `--lts` is an option): the command follows it.
fn is_tool_version(w: &str) -> bool {
    let v = w.strip_prefix('v').unwrap_or(w);
    (!v.is_empty() && v.chars().all(|c| c.is_ascii_digit() || c == '.'))
        || w.starts_with("lts/")
        || matches!(w, "stable" | "system" | "default" | "iojs")
}

/// Strip wrapper prefixes (`sudo`, `env VAR=x`, `nice -n N`, `nohup`, …), a
/// leading `\`, and leading `VAR=val` assignments. Returns the residual words.
#[allow(clippy::too_many_lines)]
fn strip_prefixes(words: &[Word]) -> Vec<Word> {
    let mut idx = 0;
    let n = words.len();
    while idx < n {
        let prog = program_name(&words[idx].raw);
        // Leading VAR=val assignment.
        if is_var_assignment(&words[idx].raw) {
            idx += 1;
            continue;
        }
        match prog.as_str() {
            "sudo" | "doas" | "run0" => {
                idx += 1;
                // skip sudo options and their args (`-iu USER` is a cluster)
                while idx < n {
                    let w = &words[idx].raw;
                    if w == "--" {
                        idx += 1;
                        break;
                    }
                    if w.starts_with('-') && w.len() > 1 {
                        let next = words.get(idx + 1).map(|v| v.raw.as_str());
                        idx += privilege_option(w, next).0;
                    } else if is_var_assignment(w) {
                        idx += 1;
                    } else {
                        break;
                    }
                }
            }
            "env" => {
                idx += 1;
                while idx < n {
                    let w = &words[idx].raw;
                    // `env -S 'cmd args'` splits the string into the command.
                    let split = if w == "-S" || w == "--split-string" {
                        words.get(idx + 1).map(|v| (v.raw.clone(), idx + 2))
                    } else {
                        w.strip_prefix("--split-string=")
                            .or_else(|| w.strip_prefix("-S").filter(|v| !v.is_empty()))
                            .map(|v| (v.to_string(), idx + 1))
                    };
                    if let Some((text, next)) = split {
                        let mut new: Vec<Word> = lex(&text)
                            .unwrap_or_default()
                            .into_iter()
                            .filter_map(|l| match l {
                                Lexeme::Word(w) => Some(w),
                                _ => None,
                            })
                            .collect();
                        new.extend_from_slice(&words[next.min(n)..]);
                        return strip_prefixes(&new);
                    }
                    if matches!(w.as_str(), "-u" | "--unset" | "-C" | "--chdir") {
                        idx += 2;
                    } else if w.starts_with('-') || is_var_assignment(w) {
                        idx += 1;
                    } else {
                        break;
                    }
                }
            }
            "nice" | "ionice" => {
                idx += 1;
                while idx < n {
                    let w = &words[idx].raw;
                    if w == "-n" || w == "-c" || w == "-p" {
                        idx += 2;
                    } else if w.starts_with('-') {
                        idx += 1;
                    } else {
                        break;
                    }
                }
            }
            "timeout" => {
                idx += 1;
                // skip flags, then the duration argument
                while idx < n && words[idx].raw.starts_with('-') {
                    if matches!(
                        words[idx].raw.as_str(),
                        "-s" | "--signal" | "-k" | "--kill-after"
                    ) {
                        idx += 2;
                    } else {
                        idx += 1;
                    }
                }
                if idx < n {
                    idx += 1; // the duration
                }
            }
            "strace" | "ltrace" => {
                idx += 1;
                while idx < n && words[idx].raw.starts_with('-') {
                    idx += if matches!(
                        words[idx].raw.as_str(),
                        "-e" | "-o"
                            | "-p"
                            | "-s"
                            | "-u"
                            | "-E"
                            | "-a"
                            | "-b"
                            | "-I"
                            | "-O"
                            | "-S"
                            | "-P"
                            | "-X"
                    ) {
                        2
                    } else {
                        1
                    };
                }
            }
            // `uv run python -c …`, `poetry run …`: run a command in an
            // environment.
            "uv" | "poetry" | "pipenv" | "pdm" | "rye" | "hatch"
                if words.get(idx + 1).is_some_and(|w| w.raw == "run") =>
            {
                idx += 2;
                while idx < n && words[idx].raw.starts_with('-') {
                    idx += if matches!(
                        words[idx].raw.as_str(),
                        "--with" | "--python" | "-p" | "--env-file" | "--project" | "--directory"
                    ) {
                        2
                    } else {
                        1
                    };
                }
            }
            // Version managers that run a command with a tool version:
            // `nvm exec 18 cmd`, `nvm run 18 script`, `asdf exec cmd`,
            // `pyenv exec cmd`, `mise exec node@20 -- cmd`, `rtx x -- cmd`,
            // `sdk env exec cmd`, `fnm exec --using 18 cmd`, `volta run
            // --node 18 cmd`, `conda run -n env cmd`, `direnv exec DIR cmd`.
            "nvm"
                if words
                    .get(idx + 1)
                    .is_some_and(|w| matches!(w.raw.as_str(), "exec" | "run")) =>
            {
                idx += 2;
                while idx < n && words[idx].raw.starts_with('-') {
                    idx += 1;
                }
                if words.get(idx).is_some_and(|w| is_tool_version(&w.raw)) {
                    idx += 1;
                }
            }
            "asdf" | "pyenv" | "rbenv" | "nodenv" | "goenv" | "jenv" | "phpenv" | "plenv"
                if words.get(idx + 1).is_some_and(|w| w.raw == "exec") =>
            {
                idx += 2;
            }
            "sdk"
                if words.get(idx + 1).is_some_and(|w| w.raw == "env")
                    && words.get(idx + 2).is_some_and(|w| w.raw == "exec") =>
            {
                idx += 3;
            }
            "mise" | "rtx"
                if words
                    .get(idx + 1)
                    .is_some_and(|w| matches!(w.raw.as_str(), "exec" | "x")) =>
            {
                idx += 2;
                if let Some(dd) = words[idx..].iter().position(|w| w.raw == "--") {
                    idx += dd + 1;
                } else {
                    while idx < n
                        && (words[idx].raw.starts_with('-') || words[idx].raw.contains('@'))
                    {
                        idx += 1;
                    }
                }
            }
            "fnm" | "volta" | "conda" | "mamba" | "micromamba"
                if words.get(idx + 1).is_some_and(|w| {
                    matches!(
                        (prog.as_str(), w.raw.as_str()),
                        ("fnm", "exec") | ("volta" | "conda" | "mamba" | "micromamba", "run")
                    )
                }) =>
            {
                idx += 2;
                while idx < n && words[idx].raw.starts_with('-') {
                    let w = words[idx].raw.as_str();
                    idx += 1;
                    if w == "--" {
                        break;
                    }
                    if matches!(
                        w,
                        "--using"
                            | "--node"
                            | "--npm"
                            | "--yarn"
                            | "--pnpm"
                            | "--env"
                            | "-n"
                            | "--name"
                            | "-p"
                            | "--prefix"
                            | "--cwd"
                    ) {
                        idx += 1;
                    }
                }
            }
            "direnv" if words.get(idx + 1).is_some_and(|w| w.raw == "exec") => idx += 3,
            // `pnpm dlx rimraf src`, `pnpm exec …`, `yarn dlx …`, `npm exec
            // [--] rimraf src` / `npm x …` (like `npx`).
            "pnpm" | "yarn" | "npm"
                if words.get(idx + 1).is_some_and(|w| {
                    matches!(w.raw.as_str(), "dlx" | "exec") || (prog == "npm" && w.raw == "x")
                }) =>
            {
                idx += 2;
                while idx < n && words[idx].raw.starts_with('-') {
                    let w = words[idx].raw.as_str();
                    idx += 1;
                    if w == "--" {
                        break;
                    }
                    if matches!(w, "-p" | "--package" | "-c" | "--call") {
                        idx += 1;
                    }
                }
            }
            "systemd-run" => {
                idx += 1;
                while idx < n && words[idx].raw.starts_with('-') {
                    idx += if matches!(
                        words[idx].raw.as_str(),
                        "-p" | "--property"
                            | "-u"
                            | "--unit"
                            | "-E"
                            | "--setenv"
                            | "--uid"
                            | "--gid"
                            | "-M"
                            | "--machine"
                            | "-H"
                            | "--host"
                            | "--description"
                            | "--slice"
                    ) {
                        2
                    } else {
                        1
                    };
                }
            }
            // `screen -dmS name cmd…`: runs cmd in a detached session.
            "screen" => {
                idx += 1;
                while idx < n && words[idx].raw.starts_with('-') {
                    let w = words[idx].raw.as_str();
                    let takes = matches!(
                        w,
                        "-S" | "-t" | "-c" | "-p" | "-T" | "-h" | "-e" | "-Logfile"
                    ) || (w.len() > 2 && !w.starts_with("--") && w.ends_with('S'));
                    idx += if takes { 2 } else { 1 };
                }
            }
            "unbuffer" | "fakeroot" | "catchsegv" | "proxychains" | "proxychains4" | "torsocks" => {
                idx += 1;
                while idx < n && words[idx].raw.starts_with('-') {
                    idx += 1;
                }
            }
            // `exec -a NAME cmd`
            "exec" if words.get(idx + 1).is_some_and(|w| w.raw == "-a") => idx += 3,
            // `npx rimraf dist`, `bunx …`: run a package binary.
            "npx" | "bunx" | "pnpx" => {
                idx += 1;
                while idx < n && words[idx].raw.starts_with('-') {
                    idx += if matches!(words[idx].raw.as_str(), "-p" | "--package") {
                        2
                    } else {
                        1
                    };
                }
            }
            "coproc" => idx += 1,
            // zsh `repeat N cmd` runs cmd N times.
            "repeat" if idx + 2 < n => idx += 2,
            // `shellfirm wrap [--tool X] [-d D] [--] CLIENT ARGS…` starts
            // CLIENT with ARGS: its `-c` / `-f` / `-e` run before any
            // interactive input reaches the wrapper.
            // Global options may come first (`shellfirm --log debug wrap …`),
            // and `--tool psql ./wrapper ARGS` runs the wrapper as psql.
            "shellfirm" if shellfirm_wrap_at(&words[idx..]).is_some() => {
                idx += shellfirm_wrap_at(&words[idx..]).unwrap_or(1) + 1;
                let mut tool: Option<String> = None;
                while idx < n && words[idx].raw.starts_with('-') {
                    let w = words[idx].raw.as_str();
                    if w == "--" {
                        idx += 1;
                        break;
                    }
                    if let Some(t) = w
                        .strip_prefix("--tool=")
                        .or_else(|| w.strip_prefix("--as="))
                    {
                        tool = Some(t.to_string());
                        idx += 1;
                        continue;
                    }
                    if matches!(w, "--tool" | "--as") {
                        tool = words.get(idx + 1).map(|t| t.raw.clone());
                    }
                    idx += if matches!(w, "--tool" | "--as" | "-d" | "--delimiter") {
                        2
                    } else {
                        1
                    };
                }
                if let Some(t) = tool.filter(|_| idx < n) {
                    let mut rest = words[idx..].to_vec();
                    rest[0] = Word {
                        masked: t.chars().map(mask_char).collect(),
                        raw: t,
                    };
                    return strip_prefixes(&rest);
                }
            }
            // `chrt [opts] PRIORITY cmd`, `taskset [opts] MASK cmd` /
            // `taskset -c LIST cmd`, `nsenter|unshare [opts] [--] cmd`.
            "chrt" | "taskset" | "nsenter" | "unshare" => {
                let value_flags: &[&str] = match prog.as_str() {
                    "chrt" => &[
                        "-T",
                        "-P",
                        "-D",
                        "--sched-runtime",
                        "--sched-period",
                        "--sched-deadline",
                    ],
                    "taskset" => &["-c", "--cpu-list"],
                    "nsenter" => &[
                        "-t", "--target", "-S", "--setuid", "-G", "--setgid", "-w", "--wd",
                    ],
                    _ => &["--map-user", "--map-group", "--setgroups", "--propagation"],
                };
                let mut list = false;
                idx += 1;
                while idx < n && words[idx].raw.starts_with('-') {
                    let w = words[idx].raw.as_str();
                    if w == "--" {
                        idx += 1;
                        break;
                    }
                    if prog == "taskset" && (w == "-c" || w == "--cpu-list") {
                        list = true;
                    }
                    idx += if value_flags.contains(&w) { 2 } else { 1 };
                }
                // The priority / mask operand.
                if (prog == "chrt" || (prog == "taskset" && !list)) && idx < n {
                    idx += 1;
                }
            }
            "pkexec" => {
                idx += 1;
                while idx < n && words[idx].raw.starts_with('-') {
                    idx += if words[idx].raw == "--user" { 2 } else { 1 };
                }
            }
            "chroot" => {
                idx += 1;
                while idx < n && words[idx].raw.starts_with('-') {
                    idx += 1;
                }
                idx += 1; // the new root directory
            }
            // `runuser -u x -- cmd`, `flock FILE cmd`: wrappers. Their `-c CMD`
            // form is handled in `normalize_simple` (like `su -c`).
            "runuser" | "flock" if !has_dash_c(&words[idx + 1..]) => {
                let is_flock = prog == "flock";
                idx += 1;
                while idx < n {
                    let w = words[idx].raw.as_str();
                    if w == "--" {
                        idx += 1;
                        break;
                    }
                    if matches!(
                        w,
                        "-u" | "--user"
                            | "-g"
                            | "--group"
                            | "-G"
                            | "--supp-group"
                            | "-w"
                            | "--timeout"
                            | "-E"
                            | "--conflict-exit-code"
                    ) {
                        idx += 2;
                    } else if w.starts_with('-') {
                        idx += 1;
                    } else {
                        break;
                    }
                }
                if is_flock && idx < n {
                    idx += 1; // the lock file / directory
                }
            }
            // Secret / environment runners that start a command with extra
            // variables: `doppler run -- cmd`, `op run --env-file=.env --
            // cmd`, `infisical run -- cmd`, `dotenvx run -- cmd`, `dotenv -e
            // .env -- cmd`, `railway run cmd`, `devbox run -- cmd`,
            // `bundle exec cmd`.
            "doppler" | "op" | "infisical" | "dotenvx" | "phase" | "railway" | "devbox"
            | "teller" | "envchain" | "aws-vault" | "chamber" | "bundle" | "dotenv"
                if runner_command_start(&prog, words, idx).is_some() =>
            {
                idx = runner_command_start(&prog, words, idx).unwrap_or(n);
            }
            // `chronic cmd`, `caffeinate -i cmd`, `firejail --noprofile cmd`,
            // `corepack pnpm exec …`: run the command that follows.
            "chronic" | "caffeinate" | "firejail" | "corepack" => {
                idx += 1;
                while idx < n && words[idx].raw.starts_with('-') {
                    let w = words[idx].raw.as_str();
                    idx += 1;
                    if w == "--" {
                        break;
                    }
                    if prog == "caffeinate" && matches!(w, "-t" | "-w") {
                        idx += 1;
                    }
                }
            }
            // `nix develop -c cmd`, `nix shell pkgs -c cmd`.
            "nix"
                if words
                    .get(idx + 1)
                    .is_some_and(|w| matches!(w.raw.as_str(), "develop" | "shell"))
                    && words[idx..]
                        .iter()
                        .any(|w| matches!(w.raw.as_str(), "-c" | "--command")) =>
            {
                let at = words[idx..]
                    .iter()
                    .position(|w| matches!(w.raw.as_str(), "-c" | "--command"))
                    .unwrap_or(0);
                idx += at + 1;
            }
            // `nix-shell --run 'cmd'` / `--command 'cmd'`: a shell line.
            "nix-shell" => {
                if let Some(text) = find_sql_flag(&words[idx..], &["--run", "--command"]) {
                    let new: Vec<Word> = lex(&text)
                        .unwrap_or_default()
                        .into_iter()
                        .filter_map(|l| match l {
                            Lexeme::Word(w) => Some(w),
                            _ => None,
                        })
                        .collect();
                    return strip_prefixes(&new);
                }
                break;
            }
            // `setpriv --reuid=postgres cmd`, `chpst -u postgres cmd`:
            // run cmd with other credentials.
            "setpriv" | "chpst" => {
                let value_flags: &[&str] = if prog == "setpriv" {
                    &[
                        "--reuid",
                        "--regid",
                        "--ruid",
                        "--rgid",
                        "--euid",
                        "--egid",
                        "--groups",
                        "--inh-caps",
                        "--ambient-caps",
                        "--bounding-set",
                        "--securebits",
                        "--pdeathsig",
                        "--selinux-label",
                        "--apparmor-profile",
                        "--landlock-access",
                        "--landlock-rule",
                    ]
                } else {
                    &[
                        "-u", "-U", "-e", "-/", "-n", "-l", "-L", "-m", "-d", "-o", "-p", "-f",
                        "-c",
                    ]
                };
                idx += 1;
                while idx < n && words[idx].raw.starts_with('-') {
                    let w = words[idx].raw.as_str();
                    idx += 1;
                    if w == "--" {
                        break;
                    }
                    if value_flags.contains(&w) {
                        idx += 1;
                    }
                }
            }
            // `machinectl shell [opts] [user@]machine [cmd args…]`.
            "machinectl" if words.get(idx + 1).is_some_and(|w| w.raw == "shell") => {
                idx += 2;
                while idx < n && words[idx].raw.starts_with('-') {
                    let w = words[idx].raw.as_str();
                    idx += 1;
                    if matches!(w, "-E" | "--setenv" | "--uid" | "-M" | "--machine") {
                        idx += 1;
                    }
                }
                // The machine; without a command it opens a login shell.
                if idx + 1 < n {
                    idx += 1;
                } else {
                    break;
                }
            }
            // `wsl [opts] [cmd…]`, `wsl -e <cmd>`, `wsl bash -c …`: the command
            // runs inside WSL. Skip `wsl` and its options (some take a value:
            // `-d <distro>`, `-u <user>`, `--cd <dir>`) so the real command
            // (`rm -rf /`) is analyzed, not the distro name.
            "wsl" => {
                idx += 1;
                while idx < n && words[idx].raw.starts_with('-') {
                    let w = words[idx].raw.as_str();
                    idx += 1;
                    if matches!(w, "--" | "-e" | "--exec") {
                        break;
                    }
                    if matches!(
                        w,
                        "-d" | "--distribution"
                            | "--distribution-id"
                            | "-u"
                            | "--user"
                            | "--cd"
                            | "--shell-type"
                    ) {
                        idx += 1;
                    }
                }
            }
            // Compound-command keywords: the rest is an ordinary command
            // (`if true; then rm -rf /; fi`, `while …; do rm …; done`).
            "if" | "then" | "else" | "elif" | "do" | "while" | "until" | "!" => {
                idx += 1;
            }
            p if PREFIX_WORDS.contains(&p) => {
                idx += 1;
                // stdbuf has option args like -oL; skip leading flags.
                while idx < n && words[idx].raw.starts_with('-') {
                    idx += 1;
                }
            }
            _ => break,
        }
    }
    words[idx..].to_vec()
}

/// The index of `wrap` in `shellfirm [global options] wrap …` (`--log
/// LEVEL`, `--log=LEVEL`, `--config-dir DIR`), if it is a wrap invocation.
fn shellfirm_wrap_at(words: &[Word]) -> Option<usize> {
    let mut i = 1;
    while let Some(w) = words.get(i) {
        match w.raw.as_str() {
            "wrap" => return Some(i),
            "--log" | "--config-dir" => i += 2,
            r if r.starts_with('-') => i += 1,
            _ => return None,
        }
    }
    None
}

/// Whether the words contain a `-c` / `--command` option.
fn has_dash_c(words: &[Word]) -> bool {
    words
        .iter()
        .any(|w| w.raw == "-c" || w.raw == "--command" || w.raw.starts_with("--command="))
}

/// Return true if a word is a `VAR=value` assignment.
fn is_var_assignment(w: &str) -> bool {
    if let Some(eq) = w.find('=') {
        if eq == 0 {
            return false;
        }
        let name = &w[..eq];
        name.chars()
            .enumerate()
            .all(|(i, c)| c == '_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit()))
    } else {
        false
    }
}

/// Reduce a program token to its base name, dropping a leading `\` and any
/// directory components (`/usr/bin/rm` → `rm`, `\rm` → `rm`).
fn program_name(tok: &str) -> String {
    let t = tok.strip_prefix('\\').unwrap_or(tok);
    // nushell `^cmd` runs the external command `cmd`.
    let t = t
        .strip_prefix('^')
        .filter(|r| r.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '/' || c == '_'))
        .unwrap_or(t);
    // elvish `e:cmd` is the external command `cmd`.
    let t = t
        .strip_prefix("e:")
        .filter(|r| r.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '/' || c == '_'))
        .unwrap_or(t);
    // zsh `=cmd` (equals expansion) is the path of `cmd`: `=rm` → `/bin/rm`.
    let t = t
        .strip_prefix('=')
        .filter(|r| r.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '/' || c == '_'))
        .unwrap_or(t);
    // `${RM:-rm}` / `${RM-rm}` with an unknown variable runs the default.
    let t = t
        .strip_prefix("${")
        .and_then(|r| r.strip_suffix('}'))
        .and_then(|r| r.split_once(":-").or_else(|| r.split_once('-')))
        .filter(|(name, default)| {
            !name.is_empty()
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                && !default.is_empty()
                && !default.contains(char::is_whitespace)
        })
        .map_or(t, |(_, default)| default);
    // `$(which X)` / `$(command -v X)` / `` `which X` `` as argv0 is `X`.
    let inner = t
        .strip_prefix("$(")
        .and_then(|r| r.strip_suffix(')'))
        .or_else(|| t.strip_prefix('`').and_then(|r| r.strip_suffix('`')));
    if let Some(inner) = inner {
        let parts: Vec<&str> = inner.split_whitespace().collect();
        match parts.as_slice() {
            ["which" | "whence" | "realpath", x] | ["command" | "type", "-v" | "-p" | "-P", x] => {
                return program_name(x)
            }
            _ => {}
        }
    }
    let base = t.rsplit('/').next().unwrap_or(t);
    // Windows shells by any spelling: `powershell.exe`, `PWSH.EXE`, `Cmd.exe`.
    let lower = base.to_ascii_lowercase();
    let stem = lower.strip_suffix(".exe").unwrap_or(&lower);
    if matches!(stem, "pwsh" | "powershell" | "cmd") {
        return stem.to_string();
    }
    // A Windows `.exe` suffix is dropped so `bash.exe -c …` / `GIT.EXE …` are
    // classified like `bash` / `git` (Windows program names are case-insensitive,
    // so the stem is lowercased, like the shells above).
    if !stem.is_empty() && stem.len() < lower.len() {
        return stem.to_string();
    }
    base.to_string()
}

/// The command of `pwsh|powershell [options] -Command|-c TEXT…` (any
/// unambiguous abbreviation of `-Command`, case-insensitive): the remaining
/// arguments joined.
fn powershell_command(words: &[Word]) -> Option<String> {
    let pos = words.iter().skip(1).position(|w| {
        let l = w.raw.to_ascii_lowercase();
        l.len() >= 2 && "-command".starts_with(&l)
    });
    if let Some(pos) = pos.map(|p| p + 1) {
        return (pos + 1 < words.len()).then(|| raw_join(&words[pos + 1..]));
    }
    // Windows PowerShell (`powershell`, not `pwsh`) runs a bare argument as
    // the command: `powershell -NoProfile "Remove-Item …"`.
    if program_name(&words[0].raw) != "powershell" {
        return None;
    }
    let mut i = 1;
    while let Some(w) = words.get(i) {
        let l = w.raw.to_ascii_lowercase();
        if !l.starts_with('-') {
            return Some(raw_join(&words[i..]));
        }
        // `-File` / `-EncodedCommand` run something else; options that take a value skip it.
        if ["-file", "-encodedcommand", "-ec", "-e", "-enc"].contains(&l.as_str()) {
            return None;
        }
        let takes_value = [
            "-executionpolicy",
            "-ep",
            "-ex",
            "-windowstyle",
            "-w",
            "-version",
            "-v",
            "-psconsolefile",
            "-inputformat",
            "-outputformat",
            "-of",
            "-configurationname",
            "-workingdirectory",
            "-wd",
        ];
        i += if takes_value.contains(&l.as_str()) {
            2
        } else {
            1
        };
    }
    None
}

/// The command of `cmd [/q /d …] /c|/k TEXT…` (flags are case-insensitive).
fn cmd_command(words: &[Word]) -> Option<String> {
    let pos = words.iter().skip(1).position(|w| {
        let l = w.raw.to_ascii_lowercase();
        l.starts_with("/c") || l.starts_with("/k")
    })? + 1;
    // `/c"rd /s /q D:\"`: the command may start in the same word.
    let glued = &words[pos].raw[2..];
    let rest = raw_join(&words[pos + 1..]);
    let payload = match (glued.is_empty(), rest.is_empty()) {
        (true, _) => rest,
        (false, true) => glued.to_string(),
        (false, false) => format!("{glued} {rest}"),
    };
    (!payload.trim().is_empty()).then_some(payload)
}

/// Find the argument of a `-c` flag (shell command string).
fn find_dash_c(words: &[Word]) -> Option<String> {
    let mut has_c = false;
    let mut i = 1;
    while i < words.len() {
        let w = &words[i].raw;
        if w == "--" {
            i += 1;
            break;
        }
        if w == "-o" || w == "+o" || w == "-O" || w == "+O" || w == "--rcfile" || w == "--init-file"
        {
            i += 2;
            continue;
        }
        if w.starts_with('-') && !w.starts_with("--") {
            if w[1..].chars().all(|c| c.is_ascii_alphabetic()) && w.contains('c') {
                has_c = true;
            }
            i += 1;
            continue;
        }
        if w.starts_with("--") {
            i += 1;
            continue;
        }
        break;
    }
    if has_c {
        words.get(i).map(|w| w.raw.clone())
    } else {
        None
    }
}

/// Commands whose arguments are data (text to print or search for), never
/// executed. Their arguments are not matched; redirections are kept.
const DATA_COMMANDS: &[&str] = &[
    "echo", "printf", "grep", "egrep", "fgrep", "rg", "ag", "ack", "man", "info", "whatis",
    "apropos", "which", "type", "whereis", "help", "tldr",
];

/// The files a data command reads: `grep PATTERN FILE…` / `rg` / `ag` /
/// `ack` (the pattern is dropped, unless `-e` / `-f` gave it) and cmd's
/// `type FILE`. Only path-like operands (`/`, `~`, `$VAR`, `%VAR%`) are
/// kept, so `type rm` and search patterns stay data.
fn read_file_operands(prog: &str, words: &[Word]) -> Vec<Word> {
    let path_like = |w: &Word| {
        let r = w.raw.as_str();
        r.contains('/') || r.starts_with('~') || r.starts_with('$') || r.starts_with('%')
    };
    match prog {
        "grep" | "egrep" | "fgrep" | "rg" | "ag" | "ack" => {
            // Options whose value is the next word (`-e PATTERN`, `-m 1`, `-A 2`).
            const TAKES_VALUE: &[&str] = &[
                "-e",
                "-f",
                "-m",
                "-A",
                "-B",
                "-C",
                "-d",
                "-D",
                "-g",
                "-t",
                "-T",
                "-j",
                "-M",
                "--regexp",
                "--file",
                "--max-count",
                "--after-context",
                "--before-context",
                "--context",
                "--include",
                "--exclude",
                "--exclude-dir",
                "--glob",
                "--type",
            ];
            // Quiet / list-only / count greps print no file content, so they
            // are not a read of the file (`grep -q`, `grep -l`, `grep -c`).
            let silent = words.iter().skip(1).any(|w| {
                let r = w.raw.as_str();
                matches!(
                    r,
                    "--quiet" | "--silent" | "--files-with-matches" | "--count"
                ) || (r.starts_with('-')
                    && !r.starts_with("--")
                    && r[1..].chars().all(|c| c.is_ascii_alphabetic())
                    && r[1..].chars().any(|c| matches!(c, 'q' | 'l' | 'c')))
            });
            if silent {
                return Vec::new();
            }
            let mut pattern_given = false;
            let mut operands = Vec::new();
            let mut i = 1;
            while let Some(w) = words.get(i) {
                let r = w.raw.as_str();
                if TAKES_VALUE.contains(&r) {
                    pattern_given |= matches!(r, "-e" | "-f" | "--regexp" | "--file");
                    i += 2;
                    continue;
                }
                pattern_given |= r.starts_with("--regexp=") || r.starts_with("--file=");
                if !r.starts_with('-') {
                    operands.push(w);
                }
                i += 1;
            }
            operands
                .into_iter()
                .skip(usize::from(!pattern_given))
                .filter(|w| path_like(w))
                .cloned()
                .collect()
        }
        "type" => words
            .iter()
            .skip(1)
            .filter(|w| !w.raw.starts_with('-') && path_like(w))
            .cloned()
            .collect(),
        _ => Vec::new(),
    }
}

/// Keep only the program name and any redirections (`> file`, `2>&1`, …).
fn program_and_redirects(words: &[Word]) -> Vec<Word> {
    let mut out = vec![words[0].clone()];
    let mut i = 1;
    while i < words.len() {
        let w = &words[i].raw;
        if is_redirect_op(w) {
            out.push(words[i].clone());
            if let Some(t) = words.get(i + 1) {
                out.push(t.clone());
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    out
}

/// Whether a word of a normalized segment is a redirection operator
/// (`>`, `2>>`, `&>`, `<`, ...).
#[must_use]
pub fn is_redirect_word(w: &str) -> bool {
    is_redirect_op(w)
}

/// A normalized segment without its redirections (`git reset --hard 2>& 1`
/// → `git reset --hard`): the operator words and the word after each.
#[must_use]
pub fn without_redirects(segment: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    let mut words = segment.split(' ');
    while let Some(w) = words.next() {
        if is_redirect_op(w) {
            words.next();
        } else {
            out.push(w);
        }
    }
    out.join(" ")
}

/// Whether a token is a redirection operator produced by the lexer.
fn is_redirect_op(w: &str) -> bool {
    let t = w.trim_start_matches(|c: char| c.is_ascii_digit());
    !t.is_empty()
        && (t.starts_with('>') || t.starts_with('<') || t.starts_with("&>"))
        && t.chars().all(|c| matches!(c, '>' | '<' | '|' | '&' | '-'))
}

/// For remote/container exec wrappers, return the inner command words.
///
/// * `ssh [opts] host CMD…` — joined and re-parsed (the remote shell re-parses).
/// * `kubectl exec … -- CMD…`
/// * `docker|podman exec [opts] CONTAINER CMD…`
#[allow(clippy::too_many_lines)]
fn exec_payload(prog: &str, words: &[Word]) -> Option<String> {
    // Redirections (`<<EOF`, `> out`) apply to the local wrapper command,
    // not to the remote / container command.
    let end = words
        .iter()
        .position(|w| is_redirect_op(&w.raw))
        .unwrap_or(words.len());
    let words = &words[..end];
    match prog {
        "ssh" => {
            const VAL: &[&str] = &[
                "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o",
                "-p", "-Q", "-R", "-S", "-W", "-w", "-B",
            ];
            let mut i = 1;
            while i < words.len() && words[i].raw.starts_with('-') {
                if words[i].raw == "--" {
                    i += 1;
                    break;
                }
                i += if VAL.contains(&words[i].raw.as_str()) {
                    2
                } else {
                    1
                };
            }
            // words[i] is the host; `ssh host -- cmd`
            let mut start = i + 1;
            if words.get(start).is_some_and(|w| w.raw == "--") {
                start += 1;
            }
            if start < words.len() {
                Some(raw_join(&words[start..]))
            } else {
                None
            }
        }
        "kubectl" | "k" | "oc" => {
            // `kubectl exec|debug|run … -- CMD`: CMD runs in the cluster.
            let verb = words
                .iter()
                .position(|w| w.raw == "--")
                .map_or(words, |p| &words[..p]);
            if !verb
                .iter()
                .any(|w| matches!(w.raw.as_str(), "exec" | "debug" | "run"))
            {
                return None;
            }
            let pos = words.iter().position(|w| w.raw == "--")?;
            if pos + 1 < words.len() {
                Some(argv_join(&words[pos + 1..]))
            } else {
                None
            }
        }
        // `ansible HOSTS -m shell -a 'CMD' [-b]`: CMD runs on every host
        // (the default `command` module too).
        "ansible" => {
            let module = find_sql_flag(words, &["-m", "--module-name"]);
            let args = find_sql_flag(words, &["-a", "--args"])?;
            matches!(
                module.as_deref(),
                None | Some(
                    "shell"
                        | "command"
                        | "raw"
                        | "ansible.builtin.shell"
                        | "ansible.builtin.command"
                        | "ansible.builtin.raw"
                )
            )
            .then_some(args)
        }
        // `pssh -h hosts "CMD"`, `pdsh -w hosts CMD`, `clush -w hosts CMD`.
        "pssh" | "parallel-ssh" | "pdsh" | "clush" => {
            const VAL: &[&str] = &[
                "-h", "-H", "-l", "-p", "-t", "-o", "-e", "-x", "-X", "-O", "-w", "-R", "-f", "-u",
                "-g", "-L",
            ];
            let mut i = 1;
            while i < words.len() && words[i].raw.starts_with('-') {
                if words[i].raw == "--" {
                    i += 1;
                    break;
                }
                i += if VAL.contains(&words[i].raw.as_str()) {
                    2
                } else {
                    1
                };
            }
            (i < words.len()).then(|| raw_join(&words[i..]))
        }
        // `heroku run CMD`, `heroku pg:psql -c SQL`, `fly ssh console -C
        // CMD`, `render ssh SERVICE -- CMD`: CMD runs on the platform.
        "heroku" | "fly" | "flyctl" | "render" => {
            let raw: Vec<&str> = words.iter().map(|w| w.raw.as_str()).collect();
            paas_remote_command(&raw).map(|r| r.command)
        }
        "docker" | "podman" => {
            const VAL: &[&str] = &[
                "-e",
                "--env",
                "-u",
                "--user",
                "-w",
                "--workdir",
                "--env-file",
            ];
            if words.get(1).map(|w| w.raw.as_str()) != Some("exec") {
                return None;
            }
            let mut i = 2;
            while i < words.len() && words[i].raw.starts_with('-') {
                i += if VAL.contains(&words[i].raw.as_str()) {
                    2
                } else {
                    1
                };
            }
            // words[i] is the container
            if i + 1 < words.len() {
                Some(argv_join(&words[i + 1..]))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// A command run on a hosting platform (see [`paas_remote_command`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaasRemote {
    /// Where it runs: `heroku:APP`, `fly:APP`, `render:SERVICE` (without the
    /// app when the line does not name it).
    pub target: String,
    /// The command line that runs there (`psql -c '…'` for `pg:psql`).
    pub command: String,
}

/// Options of `heroku` / `fly` / `render` that take the next word as their
/// value.
const PAAS_VALUE_FLAGS: &[&str] = &[
    "-a",
    "--app",
    "-r",
    "--remote",
    "-s",
    "--size",
    "-e",
    "--env",
    "-t",
    "--type",
    "-c",
    "--config",
    "-o",
    "--org",
    "--region",
    "--machine",
    "--process-group",
    "-u",
    "--user",
    "--pty",
    "--address",
    "-o",
    "--output",
];

/// The command a hosting-platform CLI runs remotely.
///
/// `heroku run [flags] CMD…` (one quoted word is a shell line), `heroku pg:psql [DB] (-c |
/// --command) SQL`, `fly|flyctl ssh console [flags] (-C | --command) CMD`,
/// `render ssh [SERVICE] [flags] -- CMD`.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn paas_remote_command(words: &[&str]) -> Option<PaasRemote> {
    let prog = program_name(words.first()?);
    let value = |flags: &[&str]| -> Option<String> {
        words.iter().enumerate().skip(1).find_map(|(i, w)| {
            if flags.contains(w) {
                return words.get(i + 1).map(|v| (*v).to_string());
            }
            flags
                .iter()
                .find_map(|f| w.strip_prefix(&format!("{f}=")).map(str::to_string))
        })
    };
    // One word is a shell line; several are quoted one by one (as the
    // heroku CLI builds the command it sends).
    let line = |argv: &[&str]| -> String {
        match argv {
            [one] => (*one).to_string(),
            _ => argv
                .iter()
                .map(|w| shell_quote(w))
                .collect::<Vec<_>>()
                .join(" "),
        }
    };
    let target = |app: Option<String>| app.map_or_else(|| prog.clone(), |a| format!("{prog}:{a}"));
    // The first non-option word after `words[from]`, skipping option values.
    let operands = |from: usize| -> usize {
        let mut i = from;
        while i < words.len() && words[i].starts_with('-') && words[i] != "--" {
            i += if PAAS_VALUE_FLAGS.contains(&words[i]) && !words[i].contains('=') {
                2
            } else {
                1
            };
        }
        i
    };
    // Trailing platform options after the command (`heroku run 'cmd' -a app`).
    let trim_trailing = |mut end: usize, start: usize| -> usize {
        while end >= start + 2 && matches!(words[end - 2], "-a" | "--app" | "-r" | "--remote") {
            end -= 2;
        }
        while end > start
            && ["--app=", "-a=", "--remote="]
                .iter()
                .any(|p| words[end - 1].starts_with(p))
        {
            end -= 1;
        }
        end
    };
    match prog.as_str() {
        "heroku" => {
            let verb = words[1..].iter().position(|w| !w.starts_with('-'))? + 1;
            let app = value(&["-a", "--app"]);
            match words[verb] {
                "run" | "run:detached" | "run:inside" => {
                    let mut start = operands(verb + 1);
                    if words.get(start) == Some(&"--") {
                        start += 1;
                        let command = line(words.get(start..)?);
                        return (!command.trim().is_empty()).then(|| PaasRemote {
                            target: target(app),
                            command,
                        });
                    }
                    let end = trim_trailing(words.len(), start);
                    let command = line(words.get(start..end)?);
                    (!command.trim().is_empty()).then(|| PaasRemote {
                        target: target(app),
                        command,
                    })
                }
                "pg:psql" | "psql" => {
                    let sql = value(&["-c", "--command"])?;
                    Some(PaasRemote {
                        target: target(app),
                        command: format!("psql -c {}", shell_quote(&sql)),
                    })
                }
                _ => None,
            }
        }
        "fly" | "flyctl" => {
            let ssh = words.iter().position(|w| *w == "ssh")?;
            if words.get(ssh + 1) != Some(&"console") {
                return None;
            }
            let command = value(&["-C", "--command"])?;
            Some(PaasRemote {
                target: target(value(&["-a", "--app"])),
                command,
            })
        }
        "render" => {
            if words.get(1) != Some(&"ssh") {
                return None;
            }
            let service = words[2..]
                .iter()
                .take_while(|w| **w != "--")
                .find(|w| !w.starts_with('-'))
                .map(|w| (*w).to_string());
            let command = match words.iter().position(|w| *w == "--") {
                Some(dd) => line(words.get(dd + 1..)?),
                // `render ssh 'bin/rails db:drop'`: one quoted shell line.
                None => words[2..]
                    .iter()
                    .rev()
                    .find(|w| !w.starts_with('-') && w.contains(' '))
                    .map(|w| (*w).to_string())?,
            };
            let service = service.filter(|s| !s.contains(' '));
            (!command.trim().is_empty()).then(|| PaasRemote {
                target: target(service),
                command,
            })
        }
        _ => None,
    }
}

/// Join argv words into a command string that re-parses to the same words
/// (each word single-quoted when it contains characters the lexer treats
/// specially).
fn argv_join(words: &[Word]) -> String {
    words
        .iter()
        .map(|w| shell_quote(&w.raw))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Quote a word for re-parsing if needed.
fn shell_quote(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:,+@%~^*{}[]".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// The query passed on the command line of `sqlcmd` (`-Q`/`-q`/`--query`),
/// `cockroach sql` (`-e`/`--execute`), `clickhouse-client` (`-q`/`--query`)
/// and `cqlsh` (`-e`/`--execute`).
fn sql_query_flag(prog: &str, words: &[Word]) -> Option<String> {
    match prog {
        "sqlcmd" => find_sql_flag(words, &["-Q", "-q", "--query"]),
        "cockroach" if words.get(1).is_some_and(|w| w.raw == "sql") => {
            find_sql_flag(words, &["-e", "--execute"])
        }
        "clickhouse-client" => find_sql_flag(words, &["-q", "--query"]),
        "cqlsh" => find_sql_flag(words, &["-e", "--execute"]),
        _ => None,
    }
}

/// Find the SQL/JS payload of one of the given flags.
fn find_sql_flag(words: &[Word], flags: &[&str]) -> Option<String> {
    let mut i = 1;
    while i < words.len() {
        let w = &words[i].raw;
        if flags.contains(&w.as_str()) {
            return words.get(i + 1).map(|w| w.raw.clone());
        }
        for f in flags {
            if let Some(value) = w.strip_prefix(f).and_then(|r| r.strip_prefix('=')) {
                return Some(value.to_string());
            }
        }
        i += 1;
    }
    None
}

/// The SQL passed on the command line of `psql` / `mysql` / `mariadb`:
/// `-c SQL`, `--command=SQL`, `-e SQL`, and clustered short options
/// (`psql -tAc SQL`, `psql -tc SQL`, `mysql -Ne SQL`, `mysql -e"SQL"`).
fn sql_client_payload(prog: &str, words: &[Word]) -> Option<String> {
    if let Some(sql) = find_sql_flag(words, &["-c", "--command", "-e", "--execute"]) {
        return Some(sql);
    }
    // getopt semantics: in a cluster, the first option that takes a value
    // consumes the rest of the word (or the next word).
    let (target, value_opts) = if prog == "psql" {
        ('c', "cdfhLopPRTUvF")
    } else {
        // Value-taking short options of mysql / mariadb (`-B`, `-N`, `-s`
        // and `-W` are flags, so `-BNe SQL` still reaches `-e`).
        ('e', "eDhPuSp")
    };
    let mut i = 1;
    while i < words.len() {
        let w = &words[i].raw;
        if w == "--" {
            return None;
        }
        if let Some(cluster) = w.strip_prefix('-').filter(|c| !c.starts_with('-')) {
            for (pos, ch) in cluster.char_indices() {
                if value_opts.contains(ch) {
                    let rest = &cluster[pos + ch.len_utf8()..];
                    if ch == target {
                        return if rest.is_empty() {
                            words.get(i + 1).map(|w| w.raw.clone())
                        } else {
                            Some(rest.to_string())
                        };
                    }
                    break;
                }
            }
        }
        i += 1;
    }
    None
}

/// The SQL a client runs, with comments of that client's dialect that
/// [`sql_code`] does not know removed: `MySQL` / `MariaDB` `#` comments run to
/// the end of the line (`DELETE FROM users # WHERE id=1` has no WHERE).
fn client_sql(prog: &str, sql: &str) -> String {
    if matches!(prog, "mysql" | "mariadb") {
        strip_hash_comments(sql)
    } else {
        sql.to_string()
    }
}

/// Remove `#` comments (outside quotes and backticks) up to the end of the
/// line.
fn strip_hash_comments(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut quote: Option<char> = None;
    let mut chars = sql.chars().peekable();
    while let Some(c) = chars.next() {
        match quote {
            Some(q) => {
                out.push(c);
                if c == '\\' && q != '`' {
                    if let Some(n) = chars.next() {
                        out.push(n);
                    }
                } else if c == q {
                    quote = None;
                }
            }
            None if matches!(c, '\'' | '"' | '`') => {
                quote = Some(c);
                out.push(c);
            }
            None if c == '#' => {
                while chars.peek().is_some_and(|n| *n != '\n') {
                    chars.next();
                }
            }
            None => out.push(c),
        }
    }
    out
}

/// Every segment the SQL text a client runs contributes: its statements
/// (string literals and comments removed), the statements of `DO` blocks and
/// their dynamic `EXECUTE` strings, the data-modifying statements nested in
/// `WITH … AS (…)`, and the shell commands of client meta-commands (psql
/// `\!`, `\o |cmd`, `\g |cmd`, `\copy … from program '…'`, mysql `system`).
fn sql_payload_segments(prog: &str, raw: &str) -> Vec<String> {
    let clean = client_sql(prog, raw);
    let code = sql_code(&clean);
    let mut stmts = sql_statements(&code);
    for st in dollar_quoted_statements(&code) {
        stmts.extend(sql_statements(&st));
    }
    stmts.extend(do_block_statements(&clean, 0));
    let nested: Vec<String> = stmts.iter().flat_map(|s| cte_statements(s, 0)).collect();
    stmts.extend(nested);
    for cmd in client_shell_commands(prog, &clean) {
        stmts.extend(parse(&cmd).segments);
    }
    stmts
}

/// The segments of SQL text that `prog` (`psql`, `mysql`, …) runs from a
/// file: the same analysis as SQL passed with `-c` / `-e` (statements, `DO`
/// blocks, CTEs, meta-commands).
#[must_use]
pub fn sql_text_segments(prog: &str, sql: &str) -> Vec<String> {
    sql_payload_segments(prog, sql)
}

/// Shell commands run by SQL-client meta-commands in `sql`.
fn client_shell_commands(prog: &str, sql: &str) -> Vec<String> {
    let mut out = Vec::new();
    let chars: Vec<char> = sql.chars().collect();
    let mut quote: Option<char> = None;
    let mut i = 0;
    let rest_of_line = |from: usize| -> (String, usize) {
        let mut j = from;
        while j < chars.len() && chars[j] != '\n' {
            j += 1;
        }
        (chars[from..j].iter().collect(), j)
    };
    while i < chars.len() {
        let c = chars[i];
        if let Some(q) = quote {
            if c == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        match c {
            '\'' | '"' => {
                quote = Some(c);
                i += 1;
            }
            '\\' => {
                let mut j = i + 1;
                while j < chars.len() && (chars[j].is_ascii_alphanumeric() || chars[j] == '_') {
                    j += 1;
                }
                if j == i + 1 && j < chars.len() && chars[j] != '\n' {
                    j += 1; // single-character command: `\!`
                }
                let name: String = chars[i + 1..j].iter().collect();
                let (args, end) = rest_of_line(j);
                let a = args.trim();
                match name.as_str() {
                    "!" | "system" if !a.is_empty() => out.push(a.to_string()),
                    "o" | "out" | "g" | "gx" | "w" | "write" | "G" | "gset" | "watch" => {
                        if let Some(cmd) = a.strip_prefix('|') {
                            out.push(cmd.trim().to_string());
                        }
                    }
                    _ => {}
                }
                // `\copy … from program '…'` is handled below, from the text.
                if name == "copy" {
                    out.extend(program_literals(&args));
                }
                // A meta-command takes the rest of its line.
                i = end;
            }
            _ => i += 1,
        }
    }
    // `COPY … FROM|TO PROGRAM '…'` (server side) and mysql `system CMD` lines.
    if prog == "psql" {
        let outside_meta: String = sql
            .lines()
            .filter(|l| !l.trim_start().starts_with("\\copy"))
            .collect::<Vec<_>>()
            .join("\n");
        out.extend(program_literals(&outside_meta));
    } else {
        for line in sql.lines() {
            let t = line.trim_start();
            if let Some(cmd) = t
                .strip_prefix("system ")
                .or_else(|| t.strip_prefix("SYSTEM "))
            {
                out.push(cmd.trim().trim_end_matches(';').to_string());
            }
        }
    }
    out
}

/// The quoted strings that follow a `PROGRAM` keyword (`COPY t FROM PROGRAM
/// 'cmd'`).
fn program_literals(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let lower = text.to_ascii_lowercase();
    let mut from = 0;
    while let Some(pos) = lower[from..].find("program").map(|p| p + from) {
        let before_ok = pos == 0 || !lower.as_bytes()[pos - 1].is_ascii_alphanumeric();
        let after = &text[pos + 7..];
        from = pos + 7;
        if !before_ok {
            continue;
        }
        let t = after.trim_start();
        if let Some(q) = t.chars().next().filter(|c| matches!(c, '\'' | '"')) {
            let (lit, _) = read_sql_literal(&t[1..], q);
            if !lit.trim().is_empty() {
                out.push(lit);
            }
        }
    }
    out
}

/// Read a quoted SQL literal body (after its opening quote `q`): `''` is an
/// escaped quote. Returns the unescaped text and the byte length consumed
/// (including the closing quote).
fn read_sql_literal(s: &str, q: char) -> (String, usize) {
    let mut out = String::new();
    let mut chars = s.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if c == q {
            if chars.peek().is_some_and(|(_, n)| *n == q) {
                out.push(q);
                chars.next();
                continue;
            }
            return (out, i + c.len_utf8());
        }
        out.push(c);
    }
    (out, s.len())
}

/// Deepest nesting of `DO` / `EXECUTE` / `WITH` bodies analyzed.
const MAX_SQL_NESTING: usize = 4;

/// Statements of anonymous `DO` blocks (`DO $$ … $$`, `DO $tag$ … $tag$`,
/// `DO 'BEGIN … END'`, optionally with `LANGUAGE x`): the body runs, and so
/// do the strings its `EXECUTE` statements pass (`EXECUTE 'DROP …'`,
/// `EXECUTE $q$DROP …$q$`, `EXECUTE format($f$DROP TABLE %I$f$, …)`).
fn do_block_statements(sql: &str, depth: usize) -> Vec<String> {
    let mut out = Vec::new();
    if depth > MAX_SQL_NESTING {
        return out;
    }
    let upper = sql.to_ascii_uppercase();
    let bytes = upper.as_bytes();
    let mut from = 0;
    while let Some(pos) = upper[from..].find("DO").map(|p| p + from) {
        from = pos + 2;
        let boundary_before =
            pos == 0 || !(bytes[pos - 1].is_ascii_alphanumeric() || bytes[pos - 1] == b'_');
        let boundary_after = bytes
            .get(pos + 2)
            .is_none_or(|b| !(b.is_ascii_alphanumeric() || *b == b'_'));
        if !boundary_before || !boundary_after {
            continue;
        }
        let mut rest = sql[pos + 2..].trim_start();
        if rest.to_ascii_uppercase().starts_with("LANGUAGE") {
            rest = rest[8..].trim_start();
            let n = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            rest = rest[n..].trim_start();
        }
        let Some(body) = quoted_body(rest) else {
            continue;
        };
        out.extend(block_statements(&sql_code(&body)));
        out.extend(execute_statements(&body, depth + 1));
    }
    out
}

/// The body of a literal at the start of `s`: `'…'` (with `''` escapes) or
/// `$tag$…$tag$`.
fn quoted_body(s: &str) -> Option<String> {
    if let Some(r) = s.strip_prefix('\'') {
        return Some(read_sql_literal(r, '\'').0);
    }
    let chars: Vec<char> = s.chars().collect();
    let n = dollar_tag_len(&chars)?;
    let delim: String = chars[..n].iter().collect();
    let rest = &s[delim.len()..];
    let end = rest.find(&delim).unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

/// The statements of the dynamic SQL strings of `EXECUTE` (optionally
/// through `format(…)`) in a procedural body.
fn execute_statements(body: &str, depth: usize) -> Vec<String> {
    let mut out = Vec::new();
    if depth > MAX_SQL_NESTING {
        return out;
    }
    let upper = body.to_ascii_uppercase();
    let mut from = 0;
    while let Some(pos) = upper[from..].find("EXECUTE").map(|p| p + from) {
        from = pos + 7;
        if pos > 0 && upper.as_bytes()[pos - 1].is_ascii_alphanumeric() {
            continue;
        }
        let mut rest = body[pos + 7..].trim_start();
        if rest.to_ascii_lowercase().starts_with("format") {
            rest = rest[6..].trim_start();
            match rest.strip_prefix('(') {
                Some(r) => rest = r.trim_start(),
                None => continue,
            }
        }
        if let Some(payload) = quoted_body(rest) {
            out.extend(block_statements(&sql_code(&payload)));
            out.extend(execute_statements(&payload, depth + 1));
        }
    }
    out
}

/// Statements of a procedural block (already reduced by [`sql_code`]),
/// split on `;`, with leading block keywords (`BEGIN`, `DECLARE`, `THEN`,
/// `LOOP`, `EXECUTE`, …) removed.
fn block_statements(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    for st in code.split(';') {
        let mut t = st.trim();
        loop {
            let lower = t.to_ascii_lowercase();
            let kw = ["begin ", "declare ", "then ", "else ", "loop ", "execute "]
                .iter()
                .find(|k| lower.starts_with(**k));
            match kw {
                Some(k) => t = t[k.len()..].trim_start(),
                None => break,
            }
        }
        if !t.is_empty() && !t.eq_ignore_ascii_case("end") {
            out.push(t.to_string());
        }
    }
    out
}

/// The statements nested in a `WITH name AS (…)` common table expression
/// (`WITH d AS (DELETE FROM users RETURNING *) SELECT …` deletes every row),
/// plus the main statement after the CTEs.
fn cte_statements(stmt: &str, depth: usize) -> Vec<String> {
    let mut out = Vec::new();
    let t = stmt.trim_start();
    if depth > MAX_SQL_NESTING || !t.get(..5).is_some_and(|w| w.eq_ignore_ascii_case("with ")) {
        return out;
    }
    let chars: Vec<char> = t.chars().collect();
    let mut i = 4;
    let mut last_end = 0;
    while i < chars.len() {
        if chars[i] == '(' {
            // Only the body of `AS (`, `AS MATERIALIZED (`, ….
            let before: String = chars[..i].iter().collect();
            let words: Vec<String> = before
                .split_whitespace()
                .rev()
                .take(3)
                .map(str::to_ascii_uppercase)
                .collect();
            let is_body = matches!(
                words.first().map(String::as_str),
                Some("AS" | "MATERIALIZED")
            );
            let mut depth_p = 0usize;
            let mut j = i;
            while j < chars.len() {
                match chars[j] {
                    '(' => depth_p += 1,
                    ')' => {
                        depth_p -= 1;
                        if depth_p == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            if is_body {
                let inner: String = chars[i + 1..j.min(chars.len())].iter().collect();
                let inner = inner.trim().to_string();
                out.extend(cte_statements(&inner, depth + 1));
                out.push(inner);
                last_end = j + 1;
            }
            i = j + 1;
            continue;
        }
        i += 1;
    }
    if last_end > 0 && last_end < chars.len() {
        let main: String = chars[last_end..].iter().collect();
        let main = main.trim().trim_start_matches(',').trim();
        if !main.is_empty() {
            out.push(main.to_string());
        }
    }
    out
}

/// Statements inside `PostgreSQL` dollar-quoted bodies (`DO $$ BEGIN DROP
/// TABLE t; END $$`, `CREATE FUNCTION … AS $fn$ … $fn$`): the body is code
/// that runs, not string data. Each statement is returned on its own, with
/// a leading `BEGIN` / `DECLARE` block keyword removed.
fn dollar_quoted_statements(sql: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = sql;
    while let Some(start) = rest.find('$') {
        let after = &rest[start + 1..];
        let Some(tag_len) = after.find('$') else {
            break;
        };
        let tag = &after[..tag_len];
        if !tag.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            rest = &rest[start + 1..];
            continue;
        }
        let delim = format!("${tag}$");
        let body_start = start + delim.len();
        let Some(end) = rest[body_start..].find(&delim) else {
            break;
        };
        let body = &rest[body_start..body_start + end];
        // Only `DO $$ … $$` and function bodies (`AS $$ … $$`) are code; any
        // other dollar-quoted string (`SELECT $$DROP TABLE t$$`) is data.
        if !dollar_body_is_code(&rest[..start]) {
            rest = &rest[body_start + end + delim.len()..];
            continue;
        }
        for st in body.split(';') {
            let mut t = st.trim();
            loop {
                let lower = t.to_ascii_lowercase();
                let kw = ["begin ", "declare ", "then ", "else ", "loop ", "execute "]
                    .iter()
                    .find(|k| lower.starts_with(**k));
                match kw {
                    Some(k) => t = t[k.len()..].trim_start(),
                    None => break,
                }
            }
            if !t.is_empty() && !t.eq_ignore_ascii_case("end") {
                out.push(t.to_string());
            }
        }
        out.extend(dollar_quoted_statements(body));
        rest = &rest[body_start + end + delim.len()..];
        if out.len() > 64 {
            break;
        }
    }
    out
}

/// Split SQL (already reduced by [`sql_code`]) into statements: on `;`
/// outside quotes and dollar-quoted bodies, whitespace collapsed. A psql
/// backslash meta-command (`\i file`, `\! cmd`) is a statement up to the end
/// of its line and is kept as written.
fn sql_statements(code: &str) -> Vec<String> {
    let chars: Vec<char> = code.chars().collect();
    let mut out = Vec::new();
    let mut cur = String::new();
    let flush = |cur: &mut String, out: &mut Vec<String>| {
        let t = cur.split_whitespace().collect::<Vec<_>>().join(" ");
        if !t.is_empty() {
            out.push(t);
        }
        cur.clear();
    };
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '\\' if cur.trim().is_empty() => {
                flush(&mut cur, &mut out);
                while i < chars.len() && chars[i] != '\n' {
                    cur.push(chars[i]);
                    i += 1;
                }
                flush(&mut cur, &mut out);
                continue;
            }
            '\'' | '"' | '`' => {
                cur.push(c);
                i += 1;
                while i < chars.len() {
                    cur.push(chars[i]);
                    i += 1;
                    if chars[i - 1] == c {
                        break;
                    }
                }
                continue;
            }
            '$' if dollar_tag_len(&chars[i..]).is_some() => {
                let n = dollar_tag_len(&chars[i..]).unwrap_or(2);
                let delim: String = chars[i..i + n].iter().collect();
                let rest: String = chars[i + n..].iter().collect();
                let end = rest.find(&delim).map_or(rest.len(), |e| e + delim.len());
                cur.push_str(&delim);
                cur.push_str(&rest[..end]);
                i += n + rest[..end].chars().count();
                continue;
            }
            ';' => flush(&mut cur, &mut out),
            _ => cur.push(c),
        }
        i += 1;
    }
    flush(&mut cur, &mut out);
    out
}

/// Whether a dollar-quoted body that follows `before` is code: it comes
/// right after `DO` (optionally `DO LANGUAGE x`) or after `AS` (a function or
/// procedure body).
fn dollar_body_is_code(before: &str) -> bool {
    let words: Vec<String> = before
        .split_whitespace()
        .rev()
        .take(3)
        .map(str::to_ascii_uppercase)
        .collect();
    match words.as_slice() {
        [w, ..] if w == "DO" || w == "AS" => true,
        [_, l, d] if l == "LANGUAGE" && d == "DO" => true,
        _ => false,
    }
}

/// SQL with the parts that are data removed.
///
/// The contents of `'…'` string literals are dropped (kept as `''`), and so
/// are `--` line comments and `/* */` block comments. `UPDATE t SET x=1 -- WHERE id=1` becomes `UPDATE t SET x=1`
/// (no WHERE), and `INSERT … VALUES ('DELETE FROM users')` no longer looks
/// like a DELETE.
#[must_use]
pub fn sql_code(sql: &str) -> String {
    let chars: Vec<char> = sql.chars().collect();
    let mut out = String::with_capacity(sql.len());
    let mut i = 0;
    let mut in_exec_comment = false;
    // The delimiter of the `DO` / function body being scanned.
    let mut code_dollar: Option<String> = None;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '\'' => {
                out.push_str("''");
                i += 1;
                while i < chars.len() {
                    if chars[i] == '\\' {
                        i += 2;
                        continue;
                    }
                    if chars[i] == '\'' {
                        if chars.get(i + 1) == Some(&'\'') {
                            i += 2;
                            continue;
                        }
                        i += 1;
                        break;
                    }
                    i += 1;
                }
            }
            '-' if chars.get(i + 1) == Some(&'-') => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            // MySQL executable comment `/*! … */` / `/*!40101 … */` /
            // `/*M! … */`: the server runs its content.
            '/' if chars.get(i + 1) == Some(&'*')
                && (chars.get(i + 2) == Some(&'!')
                    || (chars.get(i + 2) == Some(&'M') && chars.get(i + 3) == Some(&'!'))) =>
            {
                i += if chars[i + 2] == '!' { 3 } else { 4 };
                while i < chars.len() && chars[i].is_ascii_digit() {
                    i += 1;
                }
                in_exec_comment = true;
                out.push(' ');
            }
            '*' if in_exec_comment && chars.get(i + 1) == Some(&'/') => {
                in_exec_comment = false;
                i += 2;
                out.push(' ');
            }
            '/' if chars.get(i + 1) == Some(&'*') => {
                i += 2;
                while i < chars.len() && !(chars[i] == '*' && chars.get(i + 1) == Some(&'/')) {
                    i += 1;
                }
                i += 2;
                out.push(' ');
            }
            // A dollar-quoted string that is not a `DO` / function body is
            // data: dropped like a `'…'` literal.
            '$' if dollar_tag_len(&chars[i..]).is_some() => {
                let tag_len = dollar_tag_len(&chars[i..]).unwrap_or(2);
                let delim: String = chars[i..i + tag_len].iter().collect();
                if code_dollar.as_deref() == Some(delim.as_str()) {
                    // End of a code body.
                    code_dollar = None;
                    out.push_str(&delim);
                    i += tag_len;
                } else if code_dollar.is_none() && dollar_body_is_code(&out) {
                    code_dollar = Some(delim.clone());
                    out.push_str(&delim);
                    i += tag_len;
                } else {
                    let body: String = chars[i + tag_len..].iter().collect();
                    if let Some(end) = body.find(&delim) {
                        out.push_str("''");
                        i += tag_len + body[..end].chars().count() + tag_len;
                    } else {
                        out.push(c);
                        i += 1;
                    }
                }
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    out.split(' ')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Length of a dollar-quote delimiter (`$$`, `$tag$`) at the start of
/// `chars`, if there is one.
fn dollar_tag_len(chars: &[char]) -> Option<usize> {
    if chars.first() != Some(&'$') {
        return None;
    }
    let mut n = 1;
    while let Some(c) = chars.get(n) {
        if *c == '$' {
            return Some(n + 1);
        }
        if !(c.is_ascii_alphanumeric() || *c == '_') || (n == 1 && c.is_ascii_digit()) {
            return None;
        }
        n += 1;
    }
    None
}

/// After `xargs`, skip options (and `-I{}`, `-n N`, `-P N`, `-d X`) and return
/// the remaining command string.
///
/// The arguments xargs appends come from stdin and are unknown: they are
/// represented by the placeholder word `{}` (an `-I X` / `-i` replacement
/// string is rewritten to `{}` too), so `xargs rm -rf` is analyzed as
/// `rm -rf {}` — a delete of an unverifiable target.
fn after_xargs(words: &[Word]) -> Option<String> {
    let mut i = 0;
    let mut replace: Option<String> = None;
    while i < words.len() {
        let w = &words[i].raw;
        if w == "-I" || w == "-J" {
            replace = words.get(i + 1).map(|w| w.raw.clone());
            i += 2;
        } else if w == "-i" || w == "--replace" {
            replace = Some("{}".to_string());
            i += 1;
        } else if let Some(r) = w.strip_prefix("--replace=") {
            replace = Some(r.to_string());
            i += 1;
        } else if w.len() > 2 && (w.starts_with("-I") || w.starts_with("-J")) {
            replace = Some(w[2..].to_string());
            i += 1;
        } else if w == "-n"
            || w == "-P"
            || w == "-d"
            || w == "-E"
            || w == "-s"
            || w == "-L"
            || w == "-a"
        {
            i += 2;
        } else if w.starts_with('-') {
            i += 1;
        } else {
            break;
        }
    }
    if i >= words.len() {
        return None;
    }
    let mut cmd: Vec<Word> = words[i..].to_vec();
    match replace {
        Some(r) if !r.is_empty() => {
            for w in &mut cmd {
                if w.raw.contains(r.as_str()) {
                    w.raw = w.raw.replace(r.as_str(), "{}");
                }
            }
        }
        _ => cmd.push(Word {
            raw: "{}".to_string(),
            masked: "{}".to_string(),
        }),
    }
    Some(argv_join(&cmd))
}

/// The commands `parallel [opts] CMD… ::: ARG…` runs (at most 16).
fn parallel_commands(words: &[Word]) -> Vec<String> {
    let mut i = 1;
    while i < words.len() && words[i].raw.starts_with('-') && words[i].raw != ":::" {
        i += if matches!(
            words[i].raw.as_str(),
            "-j" | "--jobs" | "-N" | "-S" | "--sshlogin" | "--delay" | "--timeout" | "-I"
        ) {
            2
        } else {
            1
        };
    }
    let Some(sep) = words[i.min(words.len())..]
        .iter()
        .position(|w| w.raw == ":::")
        .map(|p| p + i)
    else {
        return Vec::new();
    };
    let cmd = &words[i..sep];
    if cmd.is_empty() {
        return Vec::new();
    }
    words[sep + 1..]
        .iter()
        .take_while(|w| w.raw != ":::" && w.raw != "::::")
        .take(16)
        .map(|arg| {
            let mut c: Vec<Word> = cmd.to_vec();
            if c.iter().any(|w| w.raw.contains("{}")) {
                for w in &mut c {
                    w.raw = w.raw.replace("{}", &arg.raw);
                }
            } else {
                c.push(arg.clone());
            }
            argv_join(&c)
        })
        .collect()
}

/// After `watch`, skip options and return the remaining command string.
fn after_watch(words: &[Word]) -> Option<String> {
    let mut i = 0;
    while i < words.len() {
        let w = &words[i].raw;
        if w == "-n" || w == "--interval" || w == "-d" {
            i += 2;
        } else if w.starts_with('-') {
            i += 1;
        } else {
            break;
        }
    }
    if i + 1 == words.len() {
        Some(words[i].raw.clone())
    } else if i < words.len() {
        Some(raw_join(&words[i..]))
    } else {
        None
    }
}

/// `find` predicates that narrow the matched set by name, time, size, owner
/// or emptiness. Without any of them, `find DIR -delete` / `-exec rm {}`
/// acts on everything under `DIR`.
const FIND_SCOPING_PREDICATES: &[&str] = &[
    "-name",
    "-iname",
    "-path",
    "-ipath",
    "-wholename",
    "-iwholename",
    "-regex",
    "-iregex",
    "-newer",
    "-anewer",
    "-cnewer",
    "-newermt",
    "-mtime",
    "-mmin",
    "-atime",
    "-amin",
    "-ctime",
    "-cmin",
    "-size",
    "-user",
    "-group",
    "-uid",
    "-gid",
    "-perm",
    "-empty",
    "-links",
    "-inum",
    "-samefile",
    "-lname",
    "-ilname",
    "-used",
];

/// Whether a `find` command narrows its matches with a scoping predicate.
#[must_use]
fn find_is_scoped(words: &[Word]) -> bool {
    // find evaluates its expression left to right: a filter after the action
    // (`find . -delete -name x`) does not narrow it, and neither does a filter
    // in another `-o` branch (`find . -name x -o -delete` deletes the rest).
    let before: Vec<&Word> = words
        .iter()
        .take_while(|w| !is_find_action(&w.raw))
        .collect();
    !find_has_or(words)
        && before
            .iter()
            .any(|w| FIND_SCOPING_PREDICATES.contains(&w.raw.as_str()))
}

/// Name / path filters that match everything.
fn find_value_matches_all(pred: &str, value: &str) -> bool {
    let v = value.trim_matches(['\'', '"']);
    if pred.ends_with("regex") {
        matches!(v, ".*" | ".+" | "^.*$" | "^.*" | ".*$" | "^.+$")
    } else {
        !v.is_empty() && v.chars().all(|c| c == '*')
    }
}

/// `find` words without the filters that do not narrow what is matched: a
/// name / path filter that matches everything (`-name '*'`, `-regex
/// '.*'`), and a negated filter (`-not -name x`, `! -name x`).
fn drop_unselective_find_filters(words: &[Word]) -> Vec<Word> {
    let takes_value = |w: &str| FIND_SCOPING_PREDICATES.contains(&w) && w != "-empty";
    let mut out = Vec::with_capacity(words.len());
    let mut i = 0;
    while i < words.len() {
        let w = words[i].raw.as_str();
        if is_find_action(w) {
            out.extend_from_slice(&words[i..]);
            break;
        }
        if matches!(w, "-not" | "!" | "\\!") {
            if let Some(pred) = words.get(i + 1).map(|p| p.raw.as_str()) {
                if FIND_SCOPING_PREDICATES.contains(&pred) {
                    i += if takes_value(pred) { 3 } else { 2 };
                    continue;
                }
            }
        }
        if takes_value(w) {
            if let Some(v) = words.get(i + 1) {
                if find_value_matches_all(w, &v.raw) {
                    i += 2;
                    continue;
                }
            }
        }
        out.push(words[i].clone());
        i += 1;
    }
    out
}

/// Credential directories of the home directory (a `find` started inside
/// one deletes keys whatever its filter).
const CREDENTIAL_DIRS: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".aws",
    ".kube",
    ".azure",
    ".docker",
    ".password-store",
];

/// What a deleting `find` reaches that a filter does not make harmless: the
/// repository's `.git` when the filter names it (`find . -name .git
/// -exec rm -rf {} +`), and the keys of a credential directory it starts in
/// (`find ~/.ssh -name 'id_*' -delete`), as `rm -rf` segments.
fn find_critical_targets(words: &[Word]) -> Vec<String> {
    let deletes = words.iter().enumerate().any(|(i, w)| {
        w.raw == "-delete"
            || (matches!(w.raw.as_str(), "-exec" | "-execdir" | "-ok" | "-okdir")
                && words.get(i + 1).is_some_and(|p| {
                    matches!(program_name(&p.raw).as_str(), "rm" | "shred" | "unlink")
                }))
    });
    if !deletes {
        return Vec::new();
    }
    let starts = find_start_points(words);
    let mut out = Vec::new();
    let names_git = words.windows(2).any(|p| {
        matches!(p[0].raw.as_str(), "-name" | "-iname")
            && p[1]
                .raw
                .trim_matches(['\'', '"'])
                .eq_ignore_ascii_case(".git")
    });
    for root in &starts {
        if names_git {
            out.push(format!(
                "rm -rf {}",
                normalize_path(&format!("{root}/.git"))
            ));
        }
        let under_credentials = CREDENTIAL_DIRS.iter().any(|d| {
            ["~/", "$HOME/"].iter().any(|h| {
                let base = format!("{h}{d}");
                *root == base || root.starts_with(&format!("{base}/"))
            })
        });
        if under_credentials {
            out.push(format!("rm -rf {root}/*"));
        }
    }
    out
}

/// Whether a `find` word is an action that deletes or runs a command.
fn is_find_action(w: &str) -> bool {
    matches!(w, "-delete" | "-exec" | "-execdir" | "-ok" | "-okdir")
}

/// Whether an `-o` / `-or` comes before the first deleting / exec action.
fn find_has_or(words: &[Word]) -> bool {
    words
        .iter()
        .take_while(|w| !is_find_action(&w.raw))
        .any(|w| matches!(w.raw.as_str(), "-o" | "-or"))
}

/// The starting points of a `find` command (operands before the first
/// expression token), normalized. Defaults to `.`.
fn find_start_points(words: &[Word]) -> Vec<String> {
    let mut i = 1;
    while i < words.len() && matches!(words[i].raw.as_str(), "-H" | "-L" | "-P") {
        i += 1;
    }
    let mut points = Vec::new();
    while i < words.len() {
        let w = &words[i].raw;
        if w.starts_with('-') || w == "(" || w == "!" || w == "\\(" {
            break;
        }
        points.push(normalize_path(w));
        i += 1;
    }
    if points.is_empty() {
        points.push(".".to_string());
    }
    points
}

/// Collect the commands run by `find … -exec|-execdir|-ok|-okdir CMD … ;|+`.
///
/// Without a scoping predicate every file under the starting point is
/// passed to the command, so `{}` is replaced by the starting point
/// (`find ~ -exec rm -rf {} +` ≈ `rm -rf ~`). With one, `{}` stays as the
/// unknown-target placeholder.
fn find_exec_commands(words: &[Word]) -> Vec<String> {
    let scoped = find_is_scoped(words);
    let starts = find_start_points(words);
    let mut cmds = Vec::new();
    let mut i = 1;
    while i < words.len() {
        let w = words[i].raw.as_str();
        if matches!(w, "-exec" | "-execdir" | "-ok" | "-okdir") {
            let start = i + 1;
            let mut j = start;
            while j < words.len() && words[j].raw != ";" && words[j].raw != "+" {
                j += 1;
            }
            if j > start {
                let argv = &words[start..j];
                // `find . -type d -name __pycache__ -exec rm -rf {} +`: a
                // filtered recursive delete of the matches is the same as
                // `find . -type d -name __pycache__ -delete` (and is judged
                // like it: Medium, unless the start point is critical).
                let rm_matches = scoped
                    && argv.first().is_some_and(|w| program_name(&w.raw) == "rm")
                    && argv[1..].iter().any(|w| {
                        w.raw == "--recursive"
                            || (w.raw.starts_with('-')
                                && !w.raw.starts_with("--")
                                && w.raw.contains(['r', 'R']))
                    })
                    && argv[1..]
                        .iter()
                        .filter(|w| !w.raw.starts_with('-'))
                        .all(|w| w.raw == "{}");
                if rm_matches {
                    let mut expr: Vec<Word> = words[..i].to_vec();
                    expr[0] = Word {
                        raw: "find".into(),
                        masked: "find".into(),
                    };
                    // `-prune` stops find descending, not the delete.
                    expr.retain(|w| w.raw != "-prune");
                    cmds.push(format!("{} -delete", argv_join(&expr)));
                } else if scoped || !argv.iter().any(|w| w.raw.contains("{}")) {
                    cmds.push(argv_join(argv));
                } else {
                    for root in &starts {
                        let replaced: Vec<Word> = argv
                            .iter()
                            .map(|w| {
                                let raw = w.raw.replace("{}", root);
                                Word {
                                    masked: raw.chars().map(mask_char).collect(),
                                    raw,
                                }
                            })
                            .collect();
                        cmds.push(argv_join(&replaced));
                    }
                }
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    cmds
}

/// Code-string flags of inline-code interpreters (`python -c CODE`, …).
fn interpreter_code_flags(prog: &str) -> Option<&'static [&'static str]> {
    let is_python = prog
        .strip_prefix("python")
        .is_some_and(|v| v.chars().all(|c| c.is_ascii_digit() || c == '.'));
    if is_python {
        return Some(&["-c"]);
    }
    match prog {
        "perl" => Some(&["-e", "-E"]),
        "ruby" | "lua" | "luajit" | "Rscript" | "osascript" => Some(&["-e"]),
        "node" | "nodejs" | "bun" | "tsx" | "ts-node" => Some(&["-e", "--eval", "-p", "--print"]),
        "php" => Some(&["-r"]),
        "awk" | "gawk" | "mawk" | "nawk" => Some(&[]),
        _ => None,
    }
}

/// The inline code of an interpreter invocation, if any.
fn interpreter_code(prog: &str, words: &[Word]) -> Option<String> {
    if prog == "deno" {
        return (words.get(1)?.raw == "eval")
            .then(|| words.get(2).map(|w| w.raw.clone()))
            .flatten();
    }
    // `awk [-F x] [-v a=b] 'PROGRAM' file…`: the first operand is code.
    if matches!(prog, "awk" | "gawk" | "mawk" | "nawk") {
        let mut i = 1;
        while let Some(w) = words.get(i) {
            match w.raw.as_str() {
                "-f" | "--file" => return None,
                "-F" | "-v" | "--assign" | "--field-separator" => i += 2,
                "--" => return words.get(i + 1).map(|w| w.raw.clone()),
                r if r.starts_with('-') && r.len() > 1 => i += 1,
                _ => return Some(w.raw.clone()),
            }
        }
        return None;
    }
    let flags = interpreter_code_flags(prog)?;
    if let Some(code) = find_sql_flag(words, flags) {
        return Some(code);
    }
    // Clustered short options: `python3 -Ic CODE`, `perl -we CODE`.
    for (i, w) in words.iter().enumerate().skip(1) {
        let r = w.raw.as_str();
        if r == "--" {
            break;
        }
        if r.len() > 2
            && r.starts_with('-')
            && !r.starts_with("--")
            && r[1..].chars().all(|c| c.is_ascii_alphabetic())
        {
            if let Some(f) = flags.iter().find(|f| f.len() == 2 && r.ends_with(&f[1..])) {
                let _ = f;
                return words.get(i + 1).map(|w| w.raw.clone());
            }
        }
    }
    None
}

/// Whether `code` is one of the stdin programs (not the inline code).
fn code_is_stdin(code: &str, stdin_code: &[String]) -> bool {
    stdin_code.iter().any(|s| std::ptr::eq(s.as_str(), code))
}

/// `PROG -c CODE` (with the language's inline-code flag) for a program the
/// interpreter reads from stdin, so it is matched like inline code.
fn interpreter_code_segment(prog: &str, code: &str) -> String {
    let flag = if prog.starts_with("python") {
        "-c"
    } else {
        match prog {
            "php" => "-r",
            "deno" => "eval",
            _ => "-e",
        }
    };
    let masked: String = code.trim().chars().map(mask_char).collect();
    format!("{prog} {flag} {masked}")
}

/// Whether an interpreter invocation reads its program from stdin
/// (`python3 -`, `python3 <<EOF`, `perl <<<'…'`): no inline code and no
/// script operand.
fn interpreter_reads_stdin(words: &[Word]) -> bool {
    let mut i = 1;
    while let Some(w) = words.get(i) {
        let r = w.raw.as_str();
        if r == "-" || r == "/dev/stdin" || r == "/dev/fd/0" {
            return true;
        }
        if is_redirect_op(r) {
            i += 2;
            continue;
        }
        if !r.starts_with('-') {
            return false;
        }
        i += 1;
    }
    true
}

/// Shell commands embedded in inline interpreter code:
/// * string literals passed to process-spawning calls (`os.system("…")`,
///   `subprocess.run(["rm", "-rf", "/"])`, perl `system("…")`, backticks,
///   node `execSync("…")`);
/// * file-deletion calls on a literal path, translated to the equivalent
///   `rm` (`shutil.rmtree("/home")` → `rm -rf /home`).
#[allow(clippy::too_many_lines)]
fn inline_code_commands(code: &str) -> Vec<String> {
    const SPAWN: &[&str] = &[
        "system",
        "popen",
        "exec",
        "execSync",
        "spawnSync",
        "check_output",
        "check_call",
        "call",
        "run",
        "Popen",
        "getoutput",
        "getstatusoutput",
        "shell_exec",
        "passthru",
        "proc_open",
        "spawn",
        // Lua `os.execute("…")`.
        "execute",
    ];
    const RECURSIVE: &[&str] = &[
        "rmtree",
        "rm_rf",
        "rm_r",
        "remove_tree",
        "remove_dir",
        "rmSync",
        "rmdirSync",
        // Deno `Deno.removeSync(path, { recursive: true })`.
        "removeSync",
    ];
    const SINGLE: &[&str] = &[
        "remove",
        "unlink",
        "unlinkSync",
        "rmdir",
        "removedirs",
        "rm_f",
    ];
    let mut out = Vec::new();
    for (name, args) in call_string_args(code) {
        if args.is_empty() {
            continue;
        }
        if SPAWN.contains(&name.as_str()) {
            out.push(args.join(" "));
        } else if RECURSIVE.contains(&name.as_str()) {
            out.push(format!("rm -rf {}", shell_quote(&args[0])));
        } else if name == "unlink" && code.contains("recursive") {
            // R `unlink(path, recursive = TRUE)`.
            out.push(format!("rm -rf {}", shell_quote(&args[0])));
        } else if SINGLE.contains(&name.as_str()) {
            out.push(format!("rm -f {}", shell_quote(&args[0])));
        }
    }
    // AppleScript `do shell script "…"`.
    let mut rest = code;
    while let Some(pos) = rest.find("do shell script") {
        let after = rest[pos + 15..].trim_start();
        if let Some(q) = after.chars().next().filter(|c| *c == '"' || *c == '\'') {
            if let Some(end) = after[1..].find(q) {
                out.push(after[1..=end].to_string());
            }
        }
        rest = &rest[pos + 15..];
    }
    // Perl / Ruby `system "…"` / `exec '…'` without parentheses.
    for kw in ["system", "exec"] {
        let mut rest = code;
        while let Some(pos) = rest.find(kw) {
            let before_ok = rest[..pos]
                .chars()
                .next_back()
                .is_none_or(|c| !(c.is_alphanumeric() || c == '_' || c == '.'));
            let after = &rest[pos + kw.len()..];
            let trimmed = after.trim_start();
            if before_ok && trimmed.len() < after.len() {
                if let Some(q) = trimmed.chars().next().filter(|c| *c == '"' || *c == '\'') {
                    if let Some(end) = trimmed[1..].find(q) {
                        out.push(trimmed[1..=end].to_string());
                    }
                }
            }
            rest = &rest[pos + kw.len()..];
        }
    }
    // Ruby `%x(…)` / `%x{…}` / `%x[…]` run a shell command.
    let mut rest = code;
    while let Some(pos) = rest.find("%x") {
        let after = &rest[pos + 2..];
        let close = match after.chars().next() {
            Some('(') => Some(')'),
            Some('{') => Some('}'),
            Some('[') => Some(']'),
            _ => None,
        };
        if let Some(close) = close {
            if let Some(end) = after[1..].find(close) {
                out.push(after[1..=end].to_string());
            }
        }
        rest = after;
    }
    // Perl / Ruby backticks run a shell command.
    let mut rest = code;
    while let Some(a) = rest.find('`') {
        let Some(b) = rest[a + 1..].find('`') else {
            break;
        };
        out.push(rest[a + 1..a + 1 + b].to_string());
        rest = &rest[a + 2 + b..];
    }
    out
}

/// Find `name(` calls in code and return each call name with the string
/// literals of its first argument (a single literal, or a `[…]` list of
/// literals).
fn call_string_args(code: &str) -> Vec<(String, Vec<String>)> {
    let chars: Vec<char> = code.chars().collect();
    let mut out = Vec::new();
    for (i, &c) in chars.iter().enumerate() {
        if c != '(' {
            continue;
        }
        // Identifier right before `(` (allow whitespace in between).
        let mut e = i;
        while e > 0 && chars[e - 1] == ' ' {
            e -= 1;
        }
        let mut s = e;
        while s > 0 && (chars[s - 1].is_alphanumeric() || chars[s - 1] == '_') {
            s -= 1;
        }
        if s == e {
            continue;
        }
        let name: String = chars[s..e].iter().collect();
        let mut j = i + 1;
        let skip_ws = |j: &mut usize| {
            while *j < chars.len() && chars[*j].is_whitespace() {
                *j += 1;
            }
        };
        skip_ws(&mut j);
        let list = j < chars.len() && chars[j] == '[';
        if list {
            j += 1;
        }
        let mut args = Vec::new();
        loop {
            skip_ws(&mut j);
            let Some(&q) = chars.get(j) else { break };
            if q != '"' && q != '\'' {
                break;
            }
            let mut literal = String::new();
            j += 1;
            while j < chars.len() && chars[j] != q {
                if chars[j] == '\\' && j + 1 < chars.len() {
                    j += 1;
                }
                literal.push(chars[j]);
                j += 1;
            }
            j += 1;
            args.push(literal);
            if !list {
                break;
            }
            skip_ws(&mut j);
            if chars.get(j) == Some(&',') {
                j += 1;
            } else {
                break;
            }
        }
        out.push((name, args));
    }
    out
}

/// Programs whose operands are filesystem paths that get normalized.
const PATH_COMMANDS: &[&str] = &[
    "rm", "rmdir", "chmod", "chown", "chgrp", "mv", "find", "shred", "unlink", "srm",
];

/// Lexically normalize a path operand: `${HOME}` → `$HOME`, collapse `//`,
/// drop `.` components, resolve `..`, drop a trailing `/`.
/// `/home/..` → `/`, `~/` → `~`, `./` → `.`, `../../` → `../..`.
#[must_use]
pub fn normalize_path(p: &str) -> String {
    if p.is_empty() || p.starts_with('-') || !(p.contains('/') || p.starts_with("${HOME}")) {
        return p.to_string();
    }
    let p = p.replacen("${HOME}", "$HOME", 1);
    let (prefix, rest) = p.strip_prefix('/').map_or_else(
        || {
            if p == "~" || p.starts_with("~/") {
                ("~", p.get(1..).unwrap_or(""))
            } else if p == "$HOME" || p.starts_with("$HOME/") {
                ("$HOME", p.get(5..).unwrap_or(""))
            } else {
                ("", p.as_str())
            }
        },
        |r| ("/", r),
    );
    let mut comps: Vec<&str> = Vec::new();
    for c in rest.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                if comps.last().is_some_and(|l| *l != "..") {
                    comps.pop();
                } else if prefix.is_empty() {
                    comps.push("..");
                }
                // `..` at an absolute/home root stays at that root
            }
            other => comps.push(other),
        }
    }
    let body = comps.join("/");
    match (prefix, body.is_empty()) {
        ("/", true) => "/".to_string(),
        ("/", false) => format!("/{body}"),
        ("", true) => ".".to_string(),
        ("", false) => body,
        (pre, true) => pre.to_string(),
        (pre, false) => format!("{pre}/{body}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segs(cmd: &str) -> Vec<String> {
        parse(cmd).segments
    }

    fn joined(cmd: &str) -> String {
        parse(cmd).segments.join(" || ")
    }

    #[test]
    fn unquotes_simple_target() {
        assert!(joined(r#"rm -rf "/""#).contains("rm -rf /"));
        assert!(joined("rm -rf '/home'").contains("rm -rf /home"));
        assert!(joined(r#"rm -rf "$HOME""#).contains("rm -rf ~"));
    }

    #[test]
    fn quoted_arg_of_echo_is_not_a_command() {
        let s = joined(r#"echo "rm -rf /""#);
        assert!(!s.contains("rm -rf /"), "got: {s:?}");
    }

    #[test]
    fn grep_pattern_is_not_a_command() {
        let s = joined("grep 'rm -rf' .");
        assert!(!s.contains("rm -rf /"));
        assert!(!s.contains("rm -rf "));
    }

    #[test]
    fn git_commit_message_is_not_matched() {
        let s = joined(r#"git commit -m "drop table users""#);
        assert!(!s.to_lowercase().contains("drop table"), "got {s:?}");
    }

    #[test]
    fn recurses_bash_dash_c() {
        assert!(joined(r#"bash -c "rm -rf /""#).contains("rm -rf /"));
        assert!(joined("sh -c 'git push -f origin main'").contains("git push -f origin main"));
        assert!(joined("sudo bash -c 'rm -rf /'").contains("rm -rf /"));
    }

    #[test]
    fn recurses_eval() {
        assert!(joined(r#"eval "rm -rf /""#).contains("rm -rf /"));
    }

    #[test]
    fn strips_prefixes() {
        for c in [
            "command rm -rf /",
            "/bin/rm -rf /",
            "/usr/bin/rm -rf /",
            "env rm -rf /",
            "env -i rm -rf /",
            "sudo -u root rm -rf /",
            "nice -n 10 rm -rf /",
            "timeout 5 rm -rf /",
            "nohup rm -rf /",
            "time rm -rf /",
            "doas rm -rf /",
            r"\rm -rf /",
            "FOO=1 rm -rf /",
        ] {
            assert!(segs(c).iter().any(|s| s.starts_with("rm ")), "failed: {c}");
        }
    }

    #[test]
    fn splits_chains() {
        for c in [
            "ls; rm -rf /",
            "ls && rm -rf /",
            "false || rm -rf /",
            "true | rm -rf /",
        ] {
            assert!(joined(c).contains("rm -rf /"), "failed: {c}");
        }
    }

    #[test]
    fn splits_newline() {
        assert!(joined("ls\nrm -rf /").contains("rm -rf /"));
    }

    #[test]
    fn subshell_and_substitution() {
        assert!(joined("(rm -rf /)").contains("rm -rf /"));
        assert!(joined("(cd /tmp && rm -rf /)").contains("rm -rf /"));
        assert!(joined("echo $(rm -rf /)").contains("rm -rf /"));
        assert!(joined("echo `rm -rf /`").contains("rm -rf /"));
    }

    #[test]
    fn apostrophe_in_comment_does_not_swallow() {
        // `# it's fine` is a comment; the rm on the next line must still show.
        let s = joined("# it's fine\nrm -rf /\necho done");
        assert!(s.contains("rm -rf /"), "got {s:?}");
    }

    /// Parse with `#` comments off (zsh without `interactivecomments`).
    fn joined_no_comments(cmd: &str) -> String {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                set_hash_comments(true);
            }
        }
        let _reset = Reset;
        set_hash_comments(false);
        joined(cmd)
    }

    #[test]
    fn hash_is_a_word_without_interactive_comments() {
        // zsh's default: `rm -rf nothere # victim` removes victim too.
        let s = joined_no_comments("rm -rf nothere # victim");
        assert!(s.contains("rm -rf nothere # victim"), "got {s:?}");
        let s = joined_no_comments("ls # ; rm -rf x");
        assert!(s.contains("rm -rf x"), "got {s:?}");
        let s = joined_no_comments("echo a\n#x\nrm -rf y");
        assert!(s.contains("rm -rf y"), "got {s:?}");
        // With comments (the default) the same text is a comment.
        let s = joined("rm -rf nothere # victim");
        assert!(!s.contains("victim"), "got {s:?}");
        assert!(!joined("ls # ; rm -rf x").contains("rm -rf x"));
        // The setting is restored for the lines parsed afterwards.
        assert!(hash_comments());
    }

    #[test]
    fn hash_inside_words_is_unchanged_without_interactive_comments() {
        for cmd in [
            "echo $# ${#x} a#b; rm -rf z",
            "git log --format=%h#x",
            "echo \"# quoted\" '# single'",
        ] {
            assert_eq!(joined_no_comments(cmd), joined(cmd), "{cmd}");
        }
    }

    #[test]
    fn nested_payloads_keep_comments_without_interactive_comments() {
        // The shell running `-c` / eval text is not interactive: `#` there
        // is a comment.
        let s = joined_no_comments("bash -c 'ls # rm -rf victim'");
        assert!(!s.contains("rm -rf victim"), "got {s:?}");
        let s = joined_no_comments("eval 'ls # rm -rf victim'");
        assert!(!s.contains("rm -rf victim"), "got {s:?}");
    }

    #[test]
    fn dont_apostrophe_midline() {
        // `echo don't; rm -rf /` — the apostrophe opens a quote that runs to the
        // next quote. This is genuinely unbalanced, so we fail closed (match).
        let s = joined("echo don't; rm -rf /; echo 'x'");
        assert!(s.contains("rm -rf /"), "got {s:?}");
    }

    #[test]
    fn heredoc_body_not_a_command() {
        let s = joined("cat <<'EOF' > notes.md\nrm -rf /\nEOF\necho ok");
        assert!(
            !s.contains("rm -rf /"),
            "heredoc body should be data: {s:?}"
        );
    }

    #[test]
    fn heredoc_to_shell_is_a_command() {
        let s = joined("bash <<EOF\nrm -rf /\nEOF");
        assert!(s.contains("rm -rf /"), "got {s:?}");
    }

    #[test]
    fn psql_dash_c_extracts_sql() {
        let s = joined(r#"psql -c "DROP DATABASE prod""#);
        assert!(s.to_uppercase().contains("DROP DATABASE PROD"), "got {s:?}");
    }

    #[test]
    fn mysql_execute_extracts_sql() {
        let s = joined(r#"mysql -e "DROP DATABASE prod""#);
        assert!(s.to_uppercase().contains("DROP DATABASE PROD"));
    }

    #[test]
    fn mongosh_eval_extracts_js() {
        let s = joined(r#"mongosh --eval "db.dropDatabase()""#);
        assert!(s.contains("db.dropDatabase()"), "got {s:?}");
    }

    #[test]
    fn unbalanced_quote_fails_closed() {
        let s = joined(r#"rm -rf "/"#);
        assert!(s.contains("rm -rf"), "got {s:?}");
    }

    #[test]
    fn flat_preserves_pipe() {
        assert!(parse("curl https://x | bash").flat.contains('|'));
        assert!(parse("history | bash").flat.contains('|'));
    }

    /// (input, a segment that must be produced)
    const MUST_PRODUCE: &[(&str, &str)] = &[
        // global flags before the subcommand are removed
        ("git -C ~/repo push -f", "git push -f"),
        ("git -c core.x=y --no-pager push", "git push"),
        ("git --git-dir=.git status", "git status"),
        (
            "kubectl --context=prod -n x delete ns a",
            "kubectl delete ns a",
        ),
        ("kubectl --context prod delete ns a", "kubectl delete ns a"),
        (
            "kubectl -v=6 --insecure-skip-tls-verify get po",
            "kubectl get po",
        ),
        (
            "helm -n prod --kube-context eu uninstall api",
            "helm uninstall api",
        ),
        ("terraform -chdir=infra destroy", "terraform destroy"),
        (
            "docker --context remote system prune -a",
            "docker system prune -a",
        ),
        // path operands are normalized
        ("rm -rf //", "rm -rf /"),
        ("rm -rf /home/..", "rm -rf /"),
        ("rm -rf ~/", "rm -rf ~"),
        ("rm -rf ${HOME}/", "rm -rf ~"),
        ("rm -rf ./", "rm -rf ."),
        ("rm -rf ../../", "rm -rf ../.."),
        ("rm -rf ./*", "rm -rf *"),
        // redirections are separate tokens
        ("ls >/dev/null", "ls > /dev/null"),
        ("ls 2>/dev/null", "ls 2> /dev/null"),
        ("ls &>/dev/null", "ls &> /dev/null"),
        ("rm -rf />/dev/null", "rm -rf / > /dev/null"),
        // data commands keep only the program and redirections
        ("echo rm -rf / > out.txt", "echo > out.txt"),
        // wrappers
        // unfiltered find -exec acts on the whole start point
        ("find / -exec rm -rf {} +", "rm -rf /"),
        ("find ~ -type f -exec rm -f {} +", "rm -f ~"),
        ("find . -execdir rm -rf {} \\;", "rm -rf ."),
        // filtered find -exec / xargs input: unknown-target placeholder
        ("find . -name '*.js' -exec rm {} \\;", "rm {}"),
        ("xargs -0 -n 1 rm -f", "rm -f {}"),
        ("echo / | xargs rm -rf", "rm -rf {}"),
        ("ls / | xargs -I{} rm -rf {}", "rm -rf {}"),
        ("xargs -I X mv X /tmp", "mv {} /tmp"),
        (
            "kubectl get pods -o name | xargs kubectl delete",
            "kubectl delete {}",
        ),
        // shell keywords, function bodies, loops
        ("if true; then rm -rf /; fi", "rm -rf /"),
        ("f(){ rm -rf /; }; f", "rm -rf /"),
        ("function f { rm -rf /; }; f", "rm -rf /"),
        ("function f { rm -rf /; }\nf", "rm -rf /"),
        // a called function's body sees the call's arguments
        (
            "nuke() { rm -rf \"$@\"; }; nuke build src",
            "rm -rf build src",
        ),
        (
            "f() { git push -f origin \"$1\"; }; f main",
            "git push -f origin main",
        ),
        // an alias defined earlier is expanded where it is used
        ("alias g=git; g reset --hard", "git reset --hard"),
        ("alias grhh='git reset --hard'\ngrhh", "git reset --hard"),
        // clustered / glued SQL client flags
        ("psql -tAc 'DROP TABLE users'", "DROP TABLE users"),
        ("psql -tc 'DROP TABLE users'", "DROP TABLE users"),
        ("psql -tAc 'DROP TABLE users'", "psql -c DROP TABLE users"),
        ("mysql -Ne 'DROP TABLE users'", "DROP TABLE users"),
        ("mysql -e\"DROP TABLE users\"", "DROP TABLE users"),
        // a commented-out WHERE does not count
        (
            "psql -c \"UPDATE users SET a=1 -- WHERE id=1\"",
            "UPDATE users SET a=1",
        ),
        // `git -c core.hooksPath=…` runs a hook from that directory
        (
            "git -c core.hooksPath=/tmp/h commit -m x",
            "git --shellfirm-one-shot config core.hooksPath /tmp/h",
        ),
        // `` `which rm` `` as argv0 is `rm`
        ("`which rm` -rf /", "rm -rf /"),
        ("for d in a b; do rm -rf /$d; done", "rm -rf /a /b"),
        ("while true; do git push -f; done", "git push -f"),
        // obfuscation
        ("rm${IFS}-rf${IFS}/", "rm -rf /"),
        ("rm$IFS-rf$IFS/", "rm -rf /"),
        ("a=rm; $a -rf /", "rm -rf /"),
        ("a='rm -rf'; ${a} /", "rm -rf /"),
        // echoed payload piped to a shell / SQL client / redis-cli
        ("echo 'rm -rf /' | sh", "rm -rf /"),
        ("printf '%s\\n' 'git push -f' | bash", "git push -f"),
        ("echo \"DROP TABLE users;\" | psql", "DROP TABLE users"),
        ("echo FLUSHALL | redis-cli", "FLUSHALL"),
        // SQL block comments
        ("DROP /* x */ TABLE users;", "DROP TABLE users"),
        // cd before a relative path: the rebased path is analyzed too
        ("cd src && rm -rf components", "rm -rf src/components"),
        ("cd ~ && rm -rf projects", "rm -rf ~/projects"),
        ("cd /srv && cd app && rm -rf data", "rm -rf /srv/app/data"),
        // inline interpreter code
        ("perl -e 'system(\"rm -rf /\")'", "rm -rf /"),
        (
            "python3 -c 'import shutil; shutil.rmtree(\"/home\")'",
            "rm -rf /home",
        ),
        (
            "python3 -c 'import subprocess; subprocess.run([\"git\", \"push\", \"-f\"])'",
            "git push -f",
        ),
        (
            "node -e 'require(\"fs\").rmSync(\"/data\", {recursive: true})'",
            "rm -rf /data",
        ),
        ("ruby -e '`git reset --hard`'", "git reset --hard"),
        // privilege / environment wrappers
        ("su -c 'rm -rf /'", "rm -rf /"),
        ("sudo su - root -c 'git push -f'", "git push -f"),
        ("runuser -u app -- rm -rf /", "rm -rf /"),
        ("runuser -l app -c 'rm -rf /'", "rm -rf /"),
        ("pkexec --user root rm -rf /", "rm -rf /"),
        ("chroot /mnt rm -rf /", "rm -rf /"),
        ("flock /tmp/lock rm -rf /", "rm -rf /"),
        ("flock /tmp/lock -c 'rm -rf /'", "rm -rf /"),
        ("watch -n1 rm -rf /tmp/x", "rm -rf /tmp/x"),
        ("docker exec c sh -c 'rm -rf /data'", "rm -rf /data"),
        // kubectl front-ends and more global flags
        ("oc delete ns prod", "kubectl delete ns prod"),
        (
            "kubecolor --context x delete ns prod",
            "kubectl delete ns prod",
        ),
        (
            "gcloud --project p -q sql instances delete db",
            "gcloud sql instances delete db",
        ),
        (
            "gcloud --verbosity=debug spanner instances delete i",
            "gcloud spanner instances delete i",
        ),
        (
            "az --subscription s sql db delete -n a",
            "az sql db delete -n a",
        ),
        ("heroku --app web pg:reset", "heroku pg:reset"),
        (
            "aws --no-cli-pager --profile p rds delete-db-instance",
            "aws rds delete-db-instance",
        ),
        // argv0 from `$(which X)`
        ("$(which rm) -rf /", "rm -rf /"),
        // line continuations (`\` + newline) join the command
        ("git push \\\n  --force", "git push --force"),
        ("git reset \\\n --hard", "git reset --hard"),
        ("bash -c \\\n 'rm -rf /'", "rm -rf /"),
        // a multi-line quoted argument does not hide the next command
        ("git commit -m \"a\n\nb\" && rm -rf ~", "rm -rf ~"),
        (
            "git commit -m \"$(cat <<'EOF'\nfix: it's done (really)\nEOF\n)\" && rm -rf ~",
            "rm -rf ~",
        ),
        // arithmetic `<<` is a shift, not a heredoc
        ("(( x = 1 << 2 ))\ngit push -f", "git push -f"),
        ("echo $(( 1 << 2 ))\ngit push -f", "git push -f"),
        // keywords and groups never hide the following command
        ("while true; do rm -rf /; done", "rm -rf /"),
        ("until false; do git push -f; done", "git push -f"),
        ("if x; then :; elif y; then rm -rf /; fi", "rm -rf /"),
        ("if x; then :; else git push -f; fi", "git push -f"),
        ("! rm -rf /", "rm -rf /"),
        ("{ rm -rf /; }", "rm -rf /"),
        ("coproc rm -rf /", "rm -rf /"),
        ("time rm -rf /", "rm -rf /"),
        // more wrappers
        ("script -q -c 'rm -rf /' /dev/null", "rm -rf /"),
        ("sudo -p x rm -rf /", "rm -rf /"),
        ("env -C /tmp rm -rf /", "rm -rf /"),
        ("env -S 'rm -rf /'", "rm -rf /"),
        ("timeout -k 5 10 rm -rf /", "rm -rf /"),
        ("strace -f -o /tmp/t rm -rf /", "rm -rf /"),
        ("npx rimraf node_modules", "rm -rf node_modules"),
        ("npx --yes rimraf ~", "rm -rf ~"),
        // a substitution inside double quotes is code even after an apostrophe
        ("echo \"it's $(rm -rf /)\"", "rm -rf /"),
        ("ssh -p 22 host 'git push -f'", "git push -f"),
        ("kubectl exec -it pod -- rm -rf /data", "rm -rf /data"),
        ("docker exec -u root web rm -rf /data", "rm -rf /data"),
        ("mysql -e 'DROP TABLE t; DROP TABLE u'", "DROP TABLE u"),
        ("psql <<< 'TRUNCATE t'", "TRUNCATE t"),
        ("psql <<EOF\nDROP TABLE t;\nEOF", "DROP TABLE t"),
        (
            "docker rm -f $(docker ps -aq)",
            "docker rm -f $(docker ps -aq)",
        ),
        ("db.users.drop()", "db.users.drop()"),
    ];

    #[test]
    fn table_must_produce() {
        for (input, want) in MUST_PRODUCE {
            let got = segs(input);
            assert!(
                got.iter().any(|s| s == want),
                "input {input:?}: expected segment {want:?}, got {got:?}"
            );
        }
    }

    /// (input, a substring that must NOT appear in any segment or the flat form)
    const MUST_NOT_PRODUCE: &[(&str, &str)] = &[
        // definitions are not runs
        ("alias grhh='git reset --hard'", "reset"),
        ("alias gbD='git branch -D'; alias gpf='git push -f'", "push"),
        ("nuke() { rm -rf \"$@\"; }", "rm -rf"),
        ("function deploy { git push -f origin main; }", "git push"),
        // history -s / print -s only add text to the history
        ("history -s kubectl delete namespace prod", "delete"),
        ("print -s git push -f origin main", "git push"),
        // SQL string literals are data
        ("psql -c \"INSERT INTO log VALUES ('DELETE FROM users')\"", "DELETE FROM"),
        ("mysql -e \"SELECT 'DROP TABLE x'\"", "DROP TABLE"),
        ("echo \"rm -rf /\"", "rm -rf"),
        ("echo rm -rf / is bad", "rm -rf"),
        ("printf '%s' 'git push -f'", "git push"),
        ("grep -r 'drop table' .", "drop table"),
        ("git commit -m \"git push -f\"", "git push -f"),
        ("cat > notes.md <<'EOF'\ngit push -f\nEOF", "git push"),
        ("cat <<EOF\nrm -rf /\nEOF", "rm -rf"),
        ("ls # rm -rf /", "rm -rf"),
        // a newline inside quotes does not split the command
        ("echo \"start\nrm -rf /\necho end\"", "rm -rf"),
        ("git commit -m 'line one\ngit push -f origin main'", "git push"),
        // quoted heredoc bodies are data, also combined with redirects
        (
            "cat > f.md <<'EOF'\nNever run `git reset --hard` here\nEOF",
            "reset",
        ),
        (
            "cat <<'EOF' > doc.md\nUse `rm -rf /` never. $(git push -f)\nEOF",
            "rm -rf",
        ),
        (
            "cat <<'EOF' > doc.md\nUse `rm -rf /` never. $(git push -f)\nEOF",
            "git push",
        ),
        // Claude Code's commit / PR shapes: a quoted heredoc inside `$( )`
        (
            "git commit -m \"$(cat <<'EOF'\nfix: avoid git push -f and rm -rf in docs, don't\nEOF\n)\"",
            "git push",
        ),
        (
            "git commit -m \"$(cat <<'EOF'\nfix: avoid git push -f and rm -rf in docs, don't\nEOF\n)\"",
            "rm -rf",
        ),
        (
            "gh pr create --title t --body \"$(cat <<'EOF'\n## Summary\n- never `git reset --hard`; it's bad\n- $(rm -rf /)\nEOF\n)\"",
            "reset --hard",
        ),
        (
            "gh pr create --title t --body \"$(cat <<'EOF'\n## Summary\n- never `git reset --hard`; it's bad\n- $(rm -rf /)\nEOF\n)\"",
            "rm -rf",
        ),
    ];

    #[test]
    fn table_must_not_produce() {
        for (input, bad) in MUST_NOT_PRODUCE {
            let parsed = parse(input);
            for s in parsed.segments.iter().chain(std::iter::once(&parsed.flat)) {
                assert!(
                    !s.contains(bad),
                    "input {input:?}: {bad:?} leaked into {s:?}"
                );
            }
        }
    }

    #[test]
    fn normalize_path_table() {
        for (input, want) in [
            ("/", "/"),
            ("//", "/"),
            ("/.", "/"),
            ("/home/..", "/"),
            ("/home/../..", "/"),
            ("/etc/", "/etc"),
            ("~/", "~"),
            ("~/./", "~"),
            ("$HOME/", "$HOME"),
            ("${HOME}/x/..", "$HOME"),
            ("./", "."),
            ("../../", "../.."),
            ("./*", "*"),
            ("a/b/../c", "a/c"),
            ("file.txt", "file.txt"),
            ("-rf", "-rf"),
        ] {
            assert_eq!(normalize_path(input), want, "input {input:?}");
        }
    }

    #[test]
    fn deep_nesting_terminates() {
        // Nested payloads and large inputs must not blow up.
        let mut cmd = String::from("git push -f");
        for _ in 0..6 {
            cmd = format!("bash -c {}", shell_quote(&cmd));
        }
        assert!(segs(&cmd).iter().any(|s| s == "git push -f"));
        // Beyond MAX_DEPTH the remaining text is matched raw (fail closed).
        let deep = "eval ".repeat(200) + "git push -f";
        assert!(segs(&deep).iter().any(|s| s.contains("git push -f")));
        let big = "ls && ".repeat(5000) + "git push -f";
        assert!(segs(&big).iter().any(|s| s == "git push -f"));
    }

    #[test]
    fn unquoted_heredoc_body_substitutions_are_code() {
        assert!(joined("cat <<EOF > doc.md\nUse $(rm -rf /) now\nEOF").contains("rm -rf /"));
        assert!(joined("cat > f <<EOF\n`git push -f`\nEOF").contains("git push -f"));
    }

    #[test]
    fn nesting_limit_fails_closed() {
        let deep = "eval ".repeat(40) + "rm -rf /";
        let s = segs(&deep);
        assert!(
            s.iter().any(|x| x.starts_with(NESTING_LIMIT_MARKER)),
            "{s:?}"
        );
        assert!(s.iter().any(|x| x == "rm -rf /"), "{s:?}");
        let subst = "$(".repeat(40) + "rm -rf /" + &")".repeat(40);
        let s = segs(&subst);
        assert!(
            s.iter().any(|x| x.starts_with(NESTING_LIMIT_MARKER)),
            "{s:?}"
        );
        assert!(s.iter().any(|x| x.contains("rm -rf /")), "{s:?}");
        // below the limit there is no marker
        let ok = "eval ".repeat(10) + "ls";
        assert!(!segs(&ok)
            .iter()
            .any(|x| x.starts_with(NESTING_LIMIT_MARKER)));
    }

    #[test]
    fn quoted_heredoc_body_is_literal_text() {
        let s = joined("cat <<'EOF'\nit's $(rm -rf /) `git push -f`\nEOF");
        assert!(!s.contains("rm -rf") && !s.contains("git push"), "{s:?}");
    }

    #[test]
    fn remote_heredoc_is_a_script_and_remote() {
        for c in [
            "ssh host bash -s <<'EOF'\nrm -rf /srv/app\nEOF",
            "kubectl exec -i pod -- sh <<'EOF'\nrm -rf /srv/app\nEOF",
            "docker exec -i c sh <<EOF\nrm -rf /srv/app\nEOF",
        ] {
            let p = parse(c);
            assert!(
                p.segments.iter().any(|s| s == "rm -rf /srv/app"),
                "{c}: {p:?}"
            );
            assert!(
                p.remote_segments.iter().any(|s| s == "rm -rf /srv/app"),
                "{c}: {p:?}"
            );
        }
        // A local command is never marked remote.
        let p = parse("rm -rf /srv/app && ssh host 'rm -rf /x'");
        assert!(!p.remote_segments.iter().any(|s| s == "rm -rf /srv/app"));
        assert!(p.remote_segments.iter().any(|s| s == "rm -rf /x"));
        // A heredoc fed to a remote command that is not a shell stays data.
        let p = parse("ssh host cat <<'EOF'\nrm -rf /srv/app\nEOF");
        assert!(!p.segments.iter().any(|s| s.contains("rm -rf")), "{p:?}");
    }

    #[test]
    fn adversarial_inputs_are_bounded_and_fail_closed() {
        // 200k unbalanced `$(`: linear-ish and flagged as too complex.
        let t = std::time::Instant::now();
        let s = segs(&("$(".repeat(200_000) + "ls"));
        assert!(t.elapsed().as_secs() < 20, "took {:?}", t.elapsed());
        assert!(s.iter().any(|x| x.starts_with(NESTING_LIMIT_MARKER)));
        // A 1 MB eval chain stops at the work budget and still sees the payload.
        let t = std::time::Instant::now();
        let s = segs(&("eval ".repeat(200_000) + "rm -rf /"));
        assert!(t.elapsed().as_secs() < 20, "took {:?}", t.elapsed());
        assert!(s.iter().any(|x| x.starts_with(NESTING_LIMIT_MARKER)));
        assert!(s.iter().any(|x| x == "rm -rf /"));
        // Many lines with an unterminated quote do not join quadratically.
        let t = std::time::Instant::now();
        let _ = segs(&"echo \"x\nls\n".repeat(20_000));
        assert!(t.elapsed().as_secs() < 20, "took {:?}", t.elapsed());
    }

    #[test]
    fn deep_substitution_nesting_is_linear_and_flagged() {
        // Past the nesting limit the line is not descended level by level:
        // linear time and a bounded stack at any depth, and the payload is
        // still matched.
        for depth in [5_000, 15_000, 50_000] {
            let t = std::time::Instant::now();
            let cmd = format!("echo {}rm -rf /{}", "$(".repeat(depth), ")".repeat(depth));
            let s = segs(&cmd);
            assert!(t.elapsed().as_secs() < 10, "{depth}: {:?}", t.elapsed());
            assert!(
                s.iter().any(|x| x.starts_with(NESTING_LIMIT_MARKER)),
                "{depth}"
            );
            assert!(s.iter().any(|x| x.contains("rm -rf /")), "{depth}");
        }
        assert!(substitution_depth_exceeds(
            &"$(".repeat(200),
            MAX_SUBST_NESTING
        ));
        assert!(!substitution_depth_exceeds(
            &"$(a) ".repeat(500),
            MAX_SUBST_NESTING
        ));
        assert!(!substitution_depth_exceeds(
            &format!("echo '{}'", "$(".repeat(500)),
            MAX_SUBST_NESTING
        ));
    }

    #[test]
    fn hosting_platform_remote_commands() {
        let rc = |c: &str| {
            let w: Vec<&str> = lex(c)
                .unwrap()
                .into_iter()
                .filter_map(|l| match l {
                    Lexeme::Word(w) => Some(w.raw),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .leak()
                .iter()
                .map(String::as_str)
                .collect();
            paas_remote_command(&w)
        };
        let r = rc("heroku run 'bin/rails db:drop' -a app-prod").unwrap();
        assert_eq!(r.target, "heroku:app-prod");
        assert_eq!(r.command, "bin/rails db:drop");
        let r = rc("heroku run -a app psql -c 'DROP TABLE users'").unwrap();
        assert_eq!(r.command, "psql -c 'DROP TABLE users'");
        let r = rc("heroku pg:psql --command 'DELETE FROM users' -a app").unwrap();
        assert_eq!(r.command, "psql -c 'DELETE FROM users'");
        let r = rc("flyctl ssh console -a web -C 'rm -rf /data'").unwrap();
        assert_eq!(
            (r.target.as_str(), r.command.as_str()),
            ("flyctl:web", "rm -rf /data")
        );
        let r = rc("render ssh srv-1 -- rm -rf /data").unwrap();
        assert_eq!(
            (r.target.as_str(), r.command.as_str()),
            ("render:srv-1", "rm -rf /data")
        );
        assert!(rc("heroku apps").is_none());
        assert!(rc("fly ssh issue").is_none());
        // Marked as remote: local path filters do not apply.
        let p = parse("heroku run 'rm -rf /app/data' -a app");
        assert!(
            p.remote_segments.iter().any(|s| s == "rm -rf /app/data"),
            "{p:?}"
        );
    }

    #[test]
    fn runners_reveal_their_command() {
        for (cmd, want) in [
            ("doppler run -- rm -rf /", "rm -rf /"),
            ("op run --env-file .env -- rm -rf /", "rm -rf /"),
            ("infisical run --env=prod -- rm -rf /", "rm -rf /"),
            ("dotenv -e .env -- rm -rf /", "rm -rf /"),
            ("dotenvx run -- rm -rf /", "rm -rf /"),
            ("bundle exec rm -rf /", "rm -rf /"),
            ("railway run -e production rm -rf /", "rm -rf /"),
            ("aws-vault exec prod -- rm -rf /", "rm -rf /"),
            ("devbox run -- rm -rf /", "rm -rf /"),
            ("chronic rm -rf /", "rm -rf /"),
            ("caffeinate -i rm -rf /", "rm -rf /"),
            ("firejail --noprofile rm -rf /", "rm -rf /"),
            ("nix develop -c rm -rf /", "rm -rf /"),
            ("nix-shell --run 'rm -rf /'", "rm -rf /"),
            (
                "setpriv --reuid=postgres --regid postgres rm -rf /",
                "rm -rf /",
            ),
            ("chpst -u postgres rm -rf /", "rm -rf /"),
            ("machinectl shell root@ /usr/bin/rm -rf /", "rm -rf /"),
            ("sudo -R /mnt rm -rf /etc", "rm -rf /etc"),
            ("sudo --chroot=/mnt rm -rf /etc", "rm -rf /etc"),
            ("xyz exec -- rm -rf /", "rm -rf /"),
            ("xyz -- terraform destroy", "terraform destroy"),
        ] {
            assert!(
                segs(cmd).iter().any(|s| s == want),
                "{cmd}: {:?}",
                segs(cmd)
            );
        }
        // `--` of programs that take paths after it is not a command.
        for cmd in ["git checkout -- rm", "grep -- rm file", "xyz -- notes.txt"] {
            assert!(
                !segs(cmd)
                    .iter()
                    .any(|s| s == "rm" || s.starts_with("notes")),
                "{cmd}: {:?}",
                segs(cmd)
            );
        }
        // `sudo -D DIR` / `--chdir=DIR`: relative paths are under DIR.
        for cmd in ["sudo -D / rm -rf ./etc", "sudo --chdir=/ rm -rf ./etc"] {
            assert!(
                segs(cmd).iter().any(|s| s == "rm -rf /etc"),
                "{cmd}: {:?}",
                segs(cmd)
            );
        }
    }

    #[test]
    fn npm_package_names_run_their_command() {
        assert_eq!(
            package_binary("firebase-tools").as_deref(),
            Some("firebase")
        );
        assert_eq!(
            package_binary("firebase-tools@latest").as_deref(),
            Some("firebase")
        );
        assert_eq!(
            package_binary("supabase@1.200.3").as_deref(),
            Some("supabase")
        );
        assert_eq!(package_binary("@railway/cli@3").as_deref(), Some("railway"));
        assert_eq!(package_binary("netlify-cli").as_deref(), Some("netlify"));
        assert_eq!(package_binary("rm"), None);
        assert_eq!(package_binary("/usr/bin/rm"), None);
        assert_eq!(package_binary("\u{e9}x@1"), Some("\u{e9}x".to_string()));
        assert!(segs("npx -y firebase-tools@latest projects:delete p")
            .iter()
            .any(|s| s.starts_with("firebase projects:delete")));
    }

    #[test]
    fn fork_bomb_stays_glued() {
        assert!(parse(":(){ :|:& };:").flat.contains(":(){"));
    }

    #[test]
    fn xargs_recurses() {
        let s = joined("echo / | xargs rm -rf");
        assert!(
            s.contains("xargs rm -rf") || s.contains("rm -rf"),
            "got {s:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Parser regressions
    // -----------------------------------------------------------------------

    #[test]
    fn zsh_precommand_modifiers_are_stripped() {
        for cmd in ["nocorrect rm -rf ~", "noglob rm -rf ~", "- rm -rf ~"] {
            assert!(
                segs(cmd).iter().any(|s| s == "rm -rf ~"),
                "{cmd}: {:?}",
                segs(cmd)
            );
        }
        let s = segs("alias rm='nocorrect rm'; rm -rf build");
        assert!(s.iter().any(|x| x == "rm -rf build"), "{s:?}");
    }

    #[test]
    fn pushd_is_tracked_like_cd() {
        let s = segs("pushd src && rm -rf components; popd");
        assert!(s.iter().any(|x| x == "rm -rf src/components"), "{s:?}");
        // After popd, relative paths are relative to the start again.
        let s = segs("pushd src; popd; rm -rf components");
        assert!(s.iter().any(|x| x == "rm -rf components"), "{s:?}");
    }

    #[test]
    fn cd_and_chain_rebases_globs_and_redirects() {
        // Only runs if the cd succeeded: `*` is build's contents.
        let s = segs("cd build && rm -rf *");
        assert!(s.iter().any(|x| x == "rm -rf build/*"), "{s:?}");
        assert!(!s.iter().any(|x| x == "rm -rf *"), "{s:?}");
        // With `;` the rm also runs when the cd failed.
        let s = segs("cd build; rm -rf *");
        assert!(s.iter().any(|x| x == "rm -rf *"), "{s:?}");
        // Redirect targets and cp / ln destinations are rebased too.
        let s = segs("cd /etc && echo x > hosts");
        assert!(s.iter().any(|x| x.contains("> /etc/hosts")), "{s:?}");
        let s = segs("cd ~/.claude; cp x settings.json");
        assert!(
            s.iter()
                .any(|x| x == "cp ~/.claude/x ~/.claude/settings.json"),
            "{s:?}"
        );
    }

    #[test]
    fn brace_expansion_of_path_operands() {
        assert!(segs("rm -rf {src,build}")
            .iter()
            .any(|x| x == "rm -rf src build"));
        assert!(segs("rm -rf src{,.bak}")
            .iter()
            .any(|x| x == "rm -rf src src.bak"));
        assert!(segs("rm -rf src/{a,b/{c,d}}")
            .iter()
            .any(|x| x == "rm -rf src/a src/b/c src/b/d"));
        assert_eq!(expand_braces("${HOME}"), vec!["${HOME}".to_string()]);
        // Sequences expand too (zsh / bash `{1..3}`).
        assert_eq!(
            expand_braces("{1..3}"),
            vec!["1".to_string(), "2".to_string(), "3".to_string()]
        );
    }

    #[test]
    fn heredoc_substitution_executed_is_code() {
        for cmd in [
            "sh -c \"$(cat <<'EOF'\nrm -rf /\nEOF\n)\"",
            "bash -c \"$(cat <<'EOF'\nrm -rf /\nEOF\n)\"",
            "eval \"$(cat <<'EOF'\nrm -rf /\nEOF\n)\"",
            "$(cat <<'EOF'\nrm -rf /\nEOF\n)",
            "cat <<'EOF' | sh\nrm -rf /\nEOF",
        ] {
            assert!(
                segs(cmd).iter().any(|s| s == "rm -rf /"),
                "{cmd:?}: {:?}",
                segs(cmd)
            );
        }
        for cmd in [
            "git commit -m \"$(cat <<'EOF'\nrm -rf /\nEOF\n)\"",
            "gh pr create --body \"$(cat <<'EOF'\nrm -rf /\nEOF\n)\"",
            "echo \"$(cat <<'EOF'\nrm -rf /\nEOF\n)\"",
        ] {
            assert!(
                !segs(cmd).iter().any(|s| s == "rm -rf /"),
                "{cmd:?}: {:?}",
                segs(cmd)
            );
        }
    }

    #[test]
    fn oversize_input_is_split_not_called_nested() {
        let cmd = format!("echo {} && rm -rf /", "x".repeat(MAX_WORK_BYTES + 10));
        let s = segs(&cmd);
        // Too large is reported by the callers (`shellfirm:input_too_large`),
        // not as nesting.
        assert!(!s.iter().any(|x| x.starts_with(NESTING_LIMIT_MARKER)));
        assert!(
            s.iter().any(|x| x == "rm -rf /"),
            "{:?}",
            &s[..s.len().min(3)]
        );
    }

    #[test]
    fn exponential_function_expansion_is_bounded() {
        let mut cmd = String::from("f0() { rm -rf \"$1\"; }; ");
        for i in 1..=30 {
            cmd.push_str(&format!(
                "f{i}() {{ f{p} \"$1\"; f{p} \"$1\"; }}; ",
                p = i - 1
            ));
        }
        cmd.push_str("f30 build");
        let t = std::time::Instant::now();
        let s = segs(&cmd);
        assert!(t.elapsed().as_secs() < 10, "took {:?}", t.elapsed());
        assert!(
            s.iter().any(|x| x.starts_with(NESTING_LIMIT_MARKER)),
            "{s:?}"
        );
        assert!(s.iter().any(|x| x == "rm -rf build"), "{s:?}");
        // Same for aliases.
        let mut cmd = String::from("alias a0='rm -rf x'; ");
        for i in 1..=30 {
            cmd.push_str(&format!("alias a{i}='a{p}; a{p}'; ", p = i - 1));
        }
        cmd.push_str("a30");
        let t = std::time::Instant::now();
        let _ = segs(&cmd);
        assert!(t.elapsed().as_secs() < 10, "took {:?}", t.elapsed());
    }

    #[test]
    fn nested_functions_traps_and_keywords_are_followed() {
        let s = segs("inner() { rm -rf \"$1\"; }; outer() { inner \"$1\"; }; outer build");
        assert!(s.iter().any(|x| x == "rm -rf build"), "{s:?}");
        assert!(segs("trap 'rm -rf ~' EXIT").iter().any(|x| x == "rm -rf ~"));
        let s = segs("cleanup() { rm -rf /tmp/x; }; trap cleanup EXIT");
        assert!(s.iter().any(|x| x == "rm -rf /tmp/x"), "{s:?}");
        let s = segs("nuke() { rm -rf /; }; if nuke; then echo ok; fi");
        assert!(s.iter().any(|x| x == "rm -rf /"), "{s:?}");
        let s = segs("nuke() { rm -rf /; }; eval nuke");
        assert!(s.iter().any(|x| x == "rm -rf /"), "{s:?}");
    }

    #[test]
    fn find_filter_after_delete_does_not_scope() {
        let w: Vec<Word> = lex("find . -delete -name x")
            .unwrap()
            .into_iter()
            .filter_map(|l| match l {
                Lexeme::Word(w) => Some(w),
                _ => None,
            })
            .collect();
        assert!(!find_is_scoped(&w));
    }

    #[test]
    fn sql_clusters_dollar_bodies_and_sqlite_shell() {
        for cmd in [
            "mysql -BNe \"DROP TABLE x\"",
            "mysql -Be \"DROP TABLE x\"",
            "mysql -sBe \"DROP TABLE x\"",
            "mariadb -BNe \"DROP TABLE x\"",
        ] {
            assert!(
                segs(cmd).iter().any(|s| s.contains("DROP TABLE x")),
                "{cmd}: {:?}",
                segs(cmd)
            );
        }
        let s = segs("psql -c 'DO $$ BEGIN DROP TABLE users; END $$'");
        assert!(s.iter().any(|x| x == "DROP TABLE users"), "{s:?}");
        let s = segs("sqlite3 db \".shell rm -rf /\"");
        assert!(s.iter().any(|x| x == "rm -rf /"), "{s:?}");
    }

    #[test]
    fn interpreters_wrappers_and_argv0_paths() {
        for (cmd, want) in [
            (
                "python3 -Ic 'import os; os.system(\"rm -rf /\")'",
                "rm -rf /",
            ),
            (
                "uv run python -c 'import os; os.system(\"rm -rf /\")'",
                "rm -rf /",
            ),
            (
                "poetry run python -c 'import os; os.system(\"rm -rf /\")'",
                "rm -rf /",
            ),
            ("perl -e 'system \"rm -rf /\"'", "rm -rf /"),
            ("ruby -e '%x(rm -rf /)'", "rm -rf /"),
            ("php -r 'shell_exec(\"rm -rf /\");'", "rm -rf /"),
            ("awk 'BEGIN { system(\"rm -rf /\") }'", "rm -rf /"),
            ("pnpm dlx rimraf src", "rm -rf src"),
            ("systemd-run --user rm -rf /", "rm -rf /"),
            ("unbuffer rm -rf /", "rm -rf /"),
            ("fakeroot rm -rf /", "rm -rf /"),
            ("exec -a x rm -rf /", "rm -rf /"),
            ("ssh host -- sudo rm -rf /", "rm -rf /"),
            ("ssh host bash <<< 'rm -rf /'", "rm -rf /"),
            ("./deploy.sh --prod", "./deploy.sh --prod"),
        ] {
            assert!(
                segs(cmd).iter().any(|s| s == want),
                "{cmd}: {:?}",
                segs(cmd)
            );
        }
        let p = parse("python3 - <<'EOF'\nimport os\nos.system(\"rm -rf /\")\nEOF");
        assert!(
            p.segments.iter().any(|s| s == "rm -rf /"),
            "{:?}",
            p.segments
        );
        let p = parse("ssh host <<'EOF'\nrm -rf /\nEOF");
        assert!(
            p.segments.iter().any(|s| s == "rm -rf /"),
            "{:?}",
            p.segments
        );
        assert!(p.remote_segments.iter().any(|s| s == "rm -rf /"));
        // The unquoted `ssh host cmd` invocation itself is remote too.
        let p = parse("ssh bastion kubectl delete ns payments");
        assert!(
            p.remote_segments
                .iter()
                .any(|s| s.starts_with("ssh bastion kubectl")),
            "{:?}",
            p.remote_segments
        );
    }

    #[test]
    fn scheduling_and_namespace_wrappers_are_unwrapped() {
        for cmd in [
            "chrt -f 10 rm -rf /",
            "chrt 5 rm -rf /",
            "taskset -c 0 rm -rf /",
            "taskset 0x1 rm -rf /",
            "nsenter -t 1 -m -- rm -rf /",
            "unshare -r rm -rf /",
            "script -qc 'rm -rf /' /dev/null",
            "su -lc 'rm -rf /'",
        ] {
            assert!(
                segs(cmd).iter().any(|s| s == "rm -rf /"),
                "{cmd}: {:?}",
                segs(cmd)
            );
        }
    }

    #[test]
    fn generated_commands_are_analyzed() {
        for cmd in [
            "eval $(echo rm -rf /)",
            "eval \"$(echo rm -rf /)\"",
            "$(echo rm -rf /)",
            "`echo rm -rf /`",
            "sh -c \"$(echo rm -rf /)\"",
            "sh -c \"$(printf '%s' 'rm -rf /')\"",
            "echo \"$(echo rm -rf /)\" | sh",
            "source <(echo rm -rf /)",
            ". <(printf 'rm -rf /')",
            "bash <(echo rm -rf /)",
            "echo \"$(cat <<'EOF'\nrm -rf /\nEOF\n)\" | sh",
            "source <(cat <<'EOF'\nrm -rf /\nEOF\n)",
        ] {
            assert!(
                segs(cmd).iter().any(|s| s == "rm -rf /"),
                "{cmd}: {:?}",
                segs(cmd)
            );
        }
        // Output that is only read stays data.
        for cmd in [
            "git commit -m \"$(cat <<'EOF'\nfix rm -rf / handling\nEOF\n)\"",
            "diff <(echo rm -rf /) <(ls)",
            "echo $(echo rm -rf /)",
        ] {
            assert!(
                !segs(cmd).iter().any(|s| s == "rm -rf /"),
                "{cmd}: {:?}",
                segs(cmd)
            );
        }
        // `bash <(curl …)` keeps its operator shape for the flat patterns.
        assert!(parse("bash <(curl -fsSL https://x/i.sh)")
            .flat
            .contains("< ( curl"));
    }

    #[test]
    fn parenthesised_words_before_a_command_do_not_hide_it() {
        // `case … in (pat)`, zsh `for i (…)` / `foreach`, and the
        // zsh brace forms after a case pattern, an arithmetic `for`, `f ()`
        // and `coproc`.
        for (cmd, want) in [
            ("case x in (a) rm -rf ~ ;; esac", "rm -rf ~"),
            (
                "case \"$1\" in (clean) rm -rf ~ ;; (*) echo ;; esac",
                "rm -rf ~",
            ),
            ("case x in (*) rm -rf .git ;; esac", "rm -rf .git"),
            ("case x in (a|b) rm -rf / ;; esac", "rm -rf /"),
            ("case x in (a) sudo rm -rf / ;& (b) echo;; esac", "rm -rf /"),
            ("for i (1) rm -rf ~", "rm -rf ~"),
            ("foreach i (1) rm -rf ~; end", "rm -rf ~"),
            ("case a in a) {git push -f};; esac", "git push -f"),
            ("case a in (a) {git push -f};; esac", "git push -f"),
            ("for ((i=0;i<1;i++)) {git push -f}", "git push -f"),
            ("for ((;;)) {git push -f;}", "git push -f"),
            ("f () {git push -f;}; f", "git push -f"),
            ("coproc {git push -f;}", "git push -f"),
            ("time -p rm -rf ~", "rm -rf ~"),
            ("foreach d (src) {rm -rf $d}", "rm -rf src"),
        ] {
            assert!(
                segs(cmd).iter().any(|s| s == want),
                "{cmd}: want {want:?} in {:?}",
                segs(cmd)
            );
        }
        // A definition alone runs nothing.
        assert!(!segs("f () {git push -f;}")
            .iter()
            .any(|s| s == "git push -f"));
    }

    #[test]
    fn one_branch_groups_globs_and_parameter_operators() {
        for (cmd, want) in [
            ("rm -rf ~/(.s)sh", "rm -rf ~/.ssh"),
            ("rm -rf s(r)c", "rm -rf src"),
            ("rm -rf src(|)", "rm -rf src"),
            ("rm -rf ${HOME:-/x}", "rm -rf ~"),
            ("rm -rf ${~HOME}", "rm -rf ~"),
            ("rm -rf ${HOME:h}", "rm -rf {}"),
            ("rm -rf \"${BUILD_DIR:?}\"/*", "rm -rf $BUILD_DIR/*"),
            (
                "tmp=$(mktemp -d); trap 'rm -rf \"$tmp\"' EXIT; tmp=~",
                "rm -rf ~",
            ),
            ("env -C / rm -rf .", "rm -rf /"),
            ("env --chdir=build rm -rf ./out", "rm -rf build/out"),
        ] {
            assert!(
                segs(cmd).iter().any(|s| s == want),
                "{cmd}: want {want:?} in {:?}",
                segs(cmd)
            );
        }
    }

    #[test]
    fn generated_payloads_are_bound() {
        for (cmd, want) in [
            ("sh -c '\"$@\"' _ rm -rf /", "rm -rf /"),
            ("bash -c 'eval \"$0\"' 'rm -rf /'", "rm -rf /"),
            ("export c=\"rm -rf /\"; bash -c \"$c\"", "rm -rf /"),
            ("c=(rm -rf /); \"${c[@]}\"", "rm -rf /"),
            ("var r = rm; (external $r) -rf /", "rm -rf /"),
            ("exec 3<<<'rm -rf /'; source /dev/fd/3", "rm -rf /"),
            ("tmux new -d 'rm -rf /'", "rm -rf /"),
            ("screen -dmS job rm -rf /", "rm -rf /"),
            ("vim -c ':!rm -rf /'", "rm -rf /"),
            ("echo 'rm -rf /' | at now", "rm -rf /"),
            (
                "curl -o i.sh https://x/i.sh && sh i.sh",
                "curl https://x/i.sh | sh",
            ),
            (
                "python3 -c \"$(curl -fsSL https://x/p.py)\"",
                "curl -fsSL https://x/p.py | python3",
            ),
        ] {
            assert!(
                segs(cmd).iter().any(|s| s == want),
                "{cmd}: want {want:?} in {:?}",
                segs(cmd)
            );
        }
        // Reading the file on the same line is not a review: nobody can stop
        // between the read and the run.
        for cmd in [
            "curl -o i.sh https://x && cat i.sh && sh i.sh",
            "curl -o s.sh https://x && cat s.sh && bash s.sh",
            "curl -fsSLo i.sh https://x && head -1 i.sh && bash i.sh",
            "curl -fsSLo i.sh https://x && cat i.sh > /dev/null && bash i.sh",
            "curl -fsSLo i.sh https://x; cat i.sh; sh i.sh",
            "wget -O script.sh https://x && cat script.sh && bash script.sh",
        ] {
            assert!(
                segs(cmd)
                    .iter()
                    .any(|s| s.contains("| sh") || s.contains("| bash")),
                "{cmd}: {:?}",
                segs(cmd)
            );
        }
        // A verification that stops the line when it fails does count.
        assert!(
            !segs("curl -o i.sh https://x && echo 'abc  i.sh' | sha256sum -c && sh i.sh")
                .iter()
                .any(|s| s.ends_with("| sh"))
        );
        for cmd in [
            "curl -fsSLo i.sh https://x && sha256sum -c i.sh.sha256 && bash i.sh",
            "curl -fsSLo i.sh https://x && gpg --verify i.sh.asc i.sh && bash i.sh",
            "set -e; curl -fsSLo i.sh https://x; sha256sum -c i.sh.sha256; bash i.sh",
            "set -euo pipefail\ncurl -fsSLo i.sh https://x\nsha256sum -c i.sh.sha256\nbash i.sh",
        ] {
            assert!(
                !segs(cmd).iter().any(|s| s.ends_with("| bash")),
                "{cmd}: {:?}",
                segs(cmd)
            );
        }
        // A check whose failure does not stop the run is no review.
        for cmd in [
            "curl -fsSLo i.sh https://x && sha256sum -c i.sh.sha256; bash i.sh",
            "curl -fsSLo i.sh https://x && sha256sum -c i.sh.sha256 || true && bash i.sh",
            "curl -fsSLo i.sh https://x && { sha256sum -c i.sh.sha256 || true; } && bash i.sh",
            "curl -fsSLo i.sh https://x && (sha256sum -c i.sh.sha256; bash i.sh)",
            "curl -fsSLo i.sh https://x; sha256sum -c i.sh.sha256 & bash i.sh",
            "curl -fsSLo i.sh https://x && sha256sum -c i.sh.sha256 | tee log && bash i.sh",
            "set -e; set +e; curl -fsSLo i.sh https://x; sha256sum -c i.sh.sha256; bash i.sh",
        ] {
            assert!(
                segs(cmd).iter().any(|s| s.ends_with("| bash")),
                "{cmd}: {:?}",
                segs(cmd)
            );
        }
        assert!(segs("eval \"$(echo x | rev)\"")
            .iter()
            .any(|s| s.starts_with(TRANSFORMED_CODE_MARKER)));
    }

    #[test]
    fn substitution_targets_are_resolved() {
        for (cmd, want) in [
            ("rm -rf `pwd`", "rm -rf ."),
            ("rm -rf \"`pwd`\"", "rm -rf ."),
            ("rm -rf \"$(pwd)\"", "rm -rf ."),
            ("rm -rf ~+", "rm -rf ."),
            ("rm -rf $PWD/src", "rm -rf src"),
            ("rm -rf `echo ~`", "rm -rf ~"),
            ("rm -rf $(git rev-parse --show-toplevel)", "rm -rf ."),
            ("rm -rf $(cat list)", "rm -rf {}"),
            ("rm -rf ${DIR:-.}", "rm -rf ."),
            // A trailing group is a qualifier or a one-branch group.
            ("rm -rf src(N)", "rm -rf src srcN"),
            ("rm -rf *(.)", "rm -rf *"),
            (
                "cd \"$(git rev-parse --show-toplevel)\" && rm -rf *",
                "rm -rf *",
            ),
            ("cd build && rm -rf $(pwd)", "rm -rf build"),
            (
                "tmp=$(mktemp -d); trap 'rm -rf \"$tmp\"' EXIT",
                "rm -rf /tmp/shellfirm-mktemp.XXXXXX",
            ),
            ("export OUT=dist; rm -rf \"$OUT\"", "rm -rf dist"),
            ("rm -rf src/{a..c}", "rm -rf src/a src/b src/c"),
            ("rm -rf build-{1..3}", "rm -rf build-1 build-2 build-3"),
            ("rm -rf {src,}", "rm -rf src"),
        ] {
            assert!(
                segs(cmd).iter().any(|s| s == want),
                "{cmd}: want {want:?} in {:?}",
                segs(cmd)
            );
        }
        assert_eq!(
            brace_range("01..03"),
            Some(vec!["01".into(), "02".into(), "03".into()])
        );
        assert_eq!(
            brace_range("c..a"),
            Some(vec!["c".into(), "b".into(), "a".into()])
        );
        assert_eq!(
            brace_range("1..10..4"),
            Some(vec!["1".into(), "5".into(), "9".into()])
        );
        assert_eq!(brace_range("a,b"), None);
        assert_eq!(
            brace_range("1..100000").map(|v| v.len()),
            Some(MAX_BRACE_WORDS)
        );
    }

    #[test]
    fn zsh_command_word_spellings() {
        for (cmd, want) in [
            ("=rm -rf ~", "rm -rf ~"),
            ("noglob =rm -rf src", "rm -rf src"),
            ("{rm -rf /;}", "rm -rf /"),
            ("true;{git reset --hard;}", "git reset --hard"),
            ("if true;then {git reset --hard;};fi", "git reset --hard"),
            ("{ {git reset --hard;} }", "git reset --hard"),
            ("f(){rm -rf /;}; f", "rm -rf /"),
            ("repeat 3 rm -rf src", "rm -rf src"),
            ("${RM:-rm} -rf ~", "rm -rf ~"),
            (
                "shellfirm wrap --tool psql psql -c 'DROP TABLE users'",
                "psql -c DROP TABLE users",
            ),
        ] {
            assert!(
                segs(cmd).iter().any(|s| s == want),
                "{cmd}: want {want:?} in {:?}",
                segs(cmd)
            );
        }
        // `{}` and brace expansion are still words.
        assert!(segs("find . -name x -exec rm {} +")
            .iter()
            .any(|s| s == "rm {}"));
        // bash expands a brace list in command position into the command
        // (`{git,push,-f}` is `git push -f`).
        assert!(segs("{a,b}").iter().any(|s| s == "a b"));
        assert!(segs("echo {a,b}").iter().any(|s| s == "echo"));
    }

    #[test]
    fn interpreters_aliases_and_wrappers_more() {
        for (cmd, want) in [
            (
                "echo \"import os; os.system('rm -rf ~')\" | python3",
                "rm -rf ~",
            ),
            (
                "python3 /dev/stdin <<'EOF'\nimport os\nos.system('rm -rf ~')\nEOF",
                "rm -rf ~",
            ),
            (
                "deno eval \"Deno.removeSync('/', { recursive: true })\"",
                "rm -rf /",
            ),
            ("lua -e 'os.execute(\"rm -rf ~\")'", "rm -rf ~"),
            ("Rscript -e 'unlink(\"~\", recursive=TRUE)'", "rm -rf ~"),
            ("osascript -e 'do shell script \"rm -rf ~\"'", "rm -rf ~"),
            ("git -c alias.x='!rm -rf ~' x", "rm -rf ~"),
            ("parallel rm -rf ::: /", "rm -rf /"),
            ("alias s='sudo '; alias r='rm -rf /'; s r", "rm -rf /"),
            ("alias c='cd a && '\nc c rm -rf /", "rm -rf /"),
            ("D=~; cd $D && rm -rf projects", "rm -rf ~/projects"),
            (
                "kubectl debug -it api-1 --image=busybox -- rm -rf /data",
                "rm -rf /data",
            ),
            (
                "kubectl run tmp --rm -it --image=busybox -- rm -rf /data",
                "rm -rf /data",
            ),
            ("find . -name x -o -delete", "find . -delete"),
        ] {
            assert!(
                segs(cmd).iter().any(|s| s == want),
                "{cmd}: want {want:?} in {:?}",
                segs(cmd)
            );
        }
        // A program read from stdin is matched like inline code.
        let s = segs("python3 - <<'EOF'\nimport shutil\nshutil.rmtree('x')\nEOF");
        assert!(s.iter().any(|x| x.starts_with("python3 -c ")), "{s:?}");
        // A self-referencing variable does not expand forever.
        let p = parse("PATH=$PATH:/x\necho $PATH\nls");
        assert!(!p
            .segments
            .iter()
            .any(|s| s.starts_with(NESTING_LIMIT_MARKER)));
    }

    #[test]
    fn sql_payloads_are_split_as_sql() {
        // `now()` is a call and `(SELECT …)` a subquery, not shell syntax.
        let s = segs("psql -c \"UPDATE users SET last_login = now() WHERE id = 42\"");
        assert!(
            s.iter()
                .any(|x| x == "UPDATE users SET last_login = now() WHERE id = 42"),
            "{s:?}"
        );
        let s = segs("psql -c \"DELETE FROM t WHERE id IN (SELECT id FROM b); DROP TABLE x\"");
        assert!(
            s.iter()
                .any(|x| x == "DELETE FROM t WHERE id IN (SELECT id FROM b)"),
            "{s:?}"
        );
        assert!(s.iter().any(|x| x == "DROP TABLE x"), "{s:?}");
        // A multi-line statement stays one statement.
        let s = segs("psql <<'EOF'\nUPDATE users SET a = now()\nWHERE id = 1;\nEOF");
        assert!(
            s.iter()
                .any(|x| x == "UPDATE users SET a = now() WHERE id = 1"),
            "{s:?}"
        );
        // psql meta-commands are kept as written.
        let s = segs("psql <<'EOF'\n\\i cleanup.sql\nSELECT 1;\nEOF");
        assert!(s.iter().any(|x| x == "\\i cleanup.sql"), "{s:?}");
        assert_eq!(
            sql_statements("DO $$ BEGIN a; b; END $$; SELECT 1"),
            vec![
                "DO $$ BEGIN a; b; END $$".to_string(),
                "SELECT 1".to_string()
            ]
        );
        // A function header needs a body.
        assert!(segs("f() { rm -rf /; }; f").iter().any(|x| x == "rm -rf /"));
        assert!(segs("nuke() if true; then rm -rf /; fi; nuke")
            .iter()
            .any(|x| x == "rm -rf /"));
    }

    #[test]
    fn sql_dollar_strings_and_executable_comments() {
        // Only `DO` / function bodies are code.
        for sql in [
            "SELECT $$DROP TABLE users$$",
            "INSERT INTO audit(note) VALUES ($$DELETE FROM users$$)",
            "SELECT $tag$TRUNCATE orders$tag$",
            "COMMENT ON TABLE users IS $$never DROP TABLE users$$",
        ] {
            assert!(!sql_code(sql).contains("DROP TABLE") && !sql_code(sql).contains("DELETE"));
            assert!(dollar_quoted_statements(&sql_code(sql)).is_empty(), "{sql}");
        }
        let s = dollar_quoted_statements(&sql_code(
            "DO $$ BEGIN DROP TABLE a; END $$; DO $$ BEGIN DROP TABLE b; END $$",
        ));
        assert!(
            s.contains(&"DROP TABLE a".to_string()) && s.contains(&"DROP TABLE b".to_string()),
            "{s:?}"
        );
        let s = dollar_quoted_statements(&sql_code(
            "CREATE FUNCTION f() RETURNS void AS $fn$ DELETE FROM users $fn$ LANGUAGE sql",
        ));
        assert!(s.contains(&"DELETE FROM users".to_string()), "{s:?}");
        assert!(sql_code("/*! DROP TABLE users */").contains("DROP TABLE users"));
        assert!(sql_code("/*!40101 DROP TABLE users */").contains("DROP TABLE users"));
        assert!(!sql_code("/* DROP TABLE users */").contains("DROP"));
        assert_eq!(
            strip_sql_comments("mysql -e /*!40101 DROP TABLE t */").as_deref(),
            Some("mysql -e DROP TABLE t")
        );
    }

    #[test]
    fn sql_client_payloads() {
        for (cmd, want) in [
            (r"psql -c '\! rm -rf /data'", "rm -rf /data"),
            (r"psql -c 'SELECT 1 \g |rm -rf /data'", "rm -rf /data"),
            (
                r#"psql -c "\copy t from program 'rm -rf /data'""#,
                "rm -rf /data",
            ),
            (
                "mysql -e \"DELETE FROM users # WHERE id=1\"",
                "DELETE FROM users",
            ),
            (
                "psql -c \"WITH d AS (DELETE FROM users RETURNING *) SELECT 1\"",
                "DELETE FROM users RETURNING *",
            ),
            (
                "psql -c 'DO $$ BEGIN EXECUTE $q$DROP TABLE t$q$; END $$'",
                "DROP TABLE t",
            ),
            ("psql -c \"DO 'BEGIN DROP TABLE t; END'\"", "DROP TABLE t"),
        ] {
            assert!(
                segs(cmd).iter().any(|s| s == want),
                "{cmd}: {:?}",
                segs(cmd)
            );
        }
        assert!(!segs("psql -c 'SELECT $$DROP TABLE t$$'")
            .iter()
            .any(|s| s.starts_with("DROP")));
    }

    #[test]
    fn generated_commands_and_shells() {
        for (cmd, want) in [
            ("{git push -f}", "git push -f"),
            ("{true} always {git push -f}", "git push -f"),
            ("{rm,-rf,/}", "rm -rf /"),
            ("$(echo rm) -rf /", "rm -rf /"),
            ("sudo $(echo rm -rf /)", "rm -rf /"),
            ("sh -c \"$(echo cm0gLXJmIC8= | base64 -d)\"", "rm -rf /"),
            ("x='rm -rf /'; eval \"$x\"", "rm -rf /"),
            ("set c kubectl; $c delete ns x", "kubectl delete ns x"),
            ("eval (echo kubectl delete ns x)", "kubectl delete ns x"),
            ("echo kubectl delete ns x | source", "kubectl delete ns x"),
            ("nu -c 'kubectl delete ns x'", "kubectl delete ns x"),
            ("pwsh -Command 'kubectl delete ns x'", "kubectl delete ns x"),
            ("$'\\x6bubectl' delete ns x", "kubectl delete ns x"),
            ("rm -rf (src|build)", "rm -rf src build"),
            ("rm -rf ~-", "rm -rf $OLDPWD"),
            ("rm -rf ~1", "rm -rf {}"),
            ("rm -rf ^README.md", "rm -rf *"),
            (
                "shellfirm --log debug wrap psql -c 'DROP TABLE t'",
                "DROP TABLE t",
            ),
            (
                "shellfirm wrap --tool psql ./pgw -c 'DROP TABLE t'",
                "DROP TABLE t",
            ),
        ] {
            assert!(
                segs(cmd).iter().any(|s| s == want),
                "{cmd}: {:?}",
                segs(cmd)
            );
        }
        // Not a fish substitution: SQL text.
        assert!(!segs("EXPLAIN (ANALYZE, BUFFERS) SELECT 1")
            .iter()
            .any(|s| s.contains("$(ANALYZE")));
    }

    #[test]
    fn mktemp_trust_and_reassignment() {
        let unknown = |cmd: &str| segs(cmd).iter().any(|s| s == "rm -rf $tmp");
        assert!(segs("tmp=$(mktemp -d); rm -rf \"$tmp\"")
            .iter()
            .any(|s| s == &format!("rm -rf {MKTEMP_PATH}")));
        for cmd in [
            "tmp=$(mktemp -d || echo ~); rm -rf \"$tmp\"",
            "tmp=$(mktemp -d); read tmp; rm -rf \"$tmp\"",
            "tmp=$(mktemp -d); tmp+=/..; rm -rf \"$tmp\"",
            "tmp=$(mktemp -d); eval tmp=~; rm -rf \"$tmp\"",
        ] {
            assert!(unknown(cmd), "{cmd}: {:?}", segs(cmd));
        }
        // A loop over a literal list: every item (not the mktemp path).
        let cmd = "tmp=$(mktemp -d); for tmp in ~ /; do :; done; rm -rf \"$tmp\"";
        assert!(
            segs(cmd).iter().any(|s| s == "rm -rf ~ /"),
            "{cmd}: {:?}",
            segs(cmd)
        );
        assert!(
            segs("tmp=$(mktemp -d); printf -v tmp %s /; rm -rf \"$tmp\"")
                .iter()
                .any(|s| s == "rm -rf /")
        );
    }

    #[test]
    fn variable_tracking_is_linear() {
        // 3000 distinct assignments followed by 3000 commands used to cost
        // O(vars × commands) (tens of seconds); the bound is generous for
        // debug builds on a loaded CI machine.
        let mut script: String = (0..3000).map(|i| format!("v{i}={i}\n")).collect();
        script.push_str(&":\n".repeat(3000));
        script.push_str("rm -rf ~\n");
        let used: String = (0..2000)
            .map(|i| format!("c{i}=ls; $c{i} d{i}\n"))
            .collect();
        for text in [&script, &used] {
            PARSE_CACHE.with(|c| c.borrow_mut().clear());
            let start = std::time::Instant::now();
            let p = parse(text);
            let took = start.elapsed();
            assert!(
                took < std::time::Duration::from_secs(3),
                "{took:?} for {}",
                &text[..20]
            );
            assert!(!p.segments.is_empty());
        }
        assert!(segs(&script).iter().any(|s| s == "rm -rf ~"));
        assert!(segs(&used).iter().any(|s| s == "ls d1999"));
        // Flat traps are not nesting.
        let traps = "trap \"ls\" EXIT; ".repeat(300);
        assert!(!segs(&traps)
            .iter()
            .any(|s| s.starts_with(NESTING_LIMIT_MARKER)));
    }

    #[test]
    fn defaults_lists_shift_and_zsh_forms() {
        for (cmd, want) in [
            ("rm -rf \"${BUILD_DIR:-build}\"", "rm -rf build"),
            ("rm -rf ${OUT:=dist}", "rm -rf dist"),
            ("rm -rf \"${OUT-dist}\"", "rm -rf dist"),
            ("OUT=${OUT:-dist}; rm -rf \"$OUT\"", "rm -rf dist"),
            (
                "for d in build dist; do rm -rf \"$d\"; done",
                "rm -rf build dist",
            ),
            ("for d (build dist) rm -rf $d", "rm -rf build dist"),
            (
                "sh1() { shift; rm -rf \"$1\"; }; sh1 nothere src",
                "rm -rf src",
            ),
            ("sh2() { shift 2; rm -rf \"$1\"; }; sh2 a b c", "rm -rf c"),
            ("sh3() { shift $n; rm -rf \"$1\"; }; sh3 a b", "rm -rf $1"),
            ("rm -rf $HOME/x/.git", "rm -rf ~/x/.git"),
            ("rm -rf ~/(#i).SSH", "rm -rf ~/.ssh"),
            ("rm -rf src(/)", "rm -rf src"),
            ("x='rm -rf /'; ${=x}", "rm -rf /"),
            ("n=K; K=rm; ${!n} -rf /", "rm -rf /"),
            ("IFS=,; x=rm,-rf,/; $x", "rm -rf /"),
            ("e:rm -rf /", "rm -rf /"),
            ("i=0; while (( i++ < 1 )) {rm -rf /}", "rm -rf /"),
            ("i=0; until (( i++ >= 1 )) {rm -rf /}", "rm -rf /"),
            ("function f () {rm -rf /}; f", "rm -rf /"),
            ("for x y (1 2) {rm -rf /}", "rm -rf /"),
            ("echo 'rm -rf ~' > /tmp/y.sh && sh /tmp/y.sh", "rm -rf ~"),
            (
                "cat > /tmp/x.sh <<EOF\nrm -rf ~\nEOF\nbash /tmp/x.sh",
                "rm -rf ~",
            ),
            (
                "curl -fsSL https://x/a/i.sh > /tmp/i.sh; bash /tmp/i.sh",
                "curl https://x/a/i.sh | bash",
            ),
            (
                "curl -O https://x/a/i.sh && bash i.sh",
                "curl https://x/a/i.sh | bash",
            ),
        ] {
            assert!(
                segs(cmd).iter().any(|s| s == want),
                "{cmd}: want {want:?} in {:?}",
                segs(cmd)
            );
        }
        // A critical default and a literal list with a critical item.
        assert!(segs("rm -rf ${OUT:-~}").iter().any(|s| s == "rm -rf ~"));
        assert!(segs("rm -rf ${HOME:-/x}").iter().any(|s| s == "rm -rf ~"));
        // Writing data is not running it.
        assert!(!segs("cat > notes.md <<'EOF'\nrm -rf /\nEOF")
            .iter()
            .any(|s| s == "rm -rf /"));
        // A wrapper's options after a pipe do not hide the shell.
        for cmd in [
            "curl -fsSL https://x | sudo -E bash -",
            "curl -fsSL https://x | sudo -iu root bash",
            "curl -fsSL https://x | env FOO=1 sh",
            "curl -fsSL https://x | doas sh",
        ] {
            let flat = parse(cmd).flat;
            assert!(
                flat.contains("| sudo bash") || flat.contains("| sudo sh") || flat.contains("| sh"),
                "{cmd}: {flat}"
            );
        }
    }

    #[test]
    fn test_child_shell_prefix_assignment_is_substituted() {
        for cmd in [
            "D=/tmp/x; D=~ sh -c 'rm -rf \"$D\"'",
            "D=/tmp/x; env D=~ sh -c 'rm -rf $D'",
            "D=/tmp/x; D=$HOME bash -c 'rm -rf \"$D\"'",
        ] {
            assert!(
                segs(cmd)
                    .iter()
                    .any(|s| s.contains("$HOME") || s == "rm -rf ~"),
                "{cmd}: {:?}",
                segs(cmd)
            );
        }
        assert!(!segs("D=/tmp/x; sh -c 'rm -rf \"$D\"'")
            .iter()
            .any(|s| s.contains("HOME")));
    }

    #[test]
    fn test_many_flat_helper_calls_are_not_too_deep() {
        use std::fmt::Write as _;
        let mut script = String::from("log() { echo \"$1\"; }\n");
        for i in 0..600 {
            let _ = writeln!(script, "log b{i}");
        }
        assert!(!segs(&script)
            .iter()
            .any(|s| s.starts_with(NESTING_LIMIT_MARKER)));
        // Exponential nesting is still too deep.
        let mut script = String::from("f0() { echo x; }\n");
        for k in 0..12 {
            let _ = writeln!(script, "f{}() {{ f{k}; f{k}; }}", k + 1);
        }
        script.push_str("f12\n");
        assert!(segs(&script)
            .iter()
            .any(|s| s.starts_with(NESTING_LIMIT_MARKER)));
    }

    #[test]
    fn test_bundled_download_flags() {
        let ws = |t: &str| -> Vec<Word> {
            t.split(' ')
                .map(|w| Word {
                    raw: w.to_string(),
                    masked: w.to_string(),
                })
                .collect()
        };
        for (prog, cmd, want) in [
            ("curl", "curl -fsSLo f.sh https://x", Some("f.sh")),
            ("curl", "curl -so f.sh https://x", Some("f.sh")),
            ("curl", "curl https://x -sLo f.sh", Some("f.sh")),
            ("curl", "curl -o/tmp/f.sh https://x", Some("/tmp/f.sh")),
            ("curl", "curl --output=f.sh https://x", Some("f.sh")),
            ("curl", "curl -H X -O https://x", None),
            ("curl", "curl -d -oops https://x", None),
            ("wget", "wget -qO f.sh https://x", Some("f.sh")),
            ("wget", "wget -qOf.sh https://x", Some("f.sh")),
            ("wget", "wget -O- https://x", Some("-")),
            ("wget", "wget -o log https://x", None),
        ] {
            assert_eq!(fetch_output_file(prog, &ws(cmd)).as_deref(), want, "{cmd}");
        }
    }

    #[test]
    fn test_trap_double_dash_and_multi_name_function() {
        assert!(segs("trap -- 'rm -rf ~' EXIT")
            .iter()
            .any(|s| s == "rm -rf ~"));
        assert!(segs("function f g () {git push -f}; g")
            .iter()
            .any(|s| s == "git push -f"));
        assert!(!segs("function f g () {git push -f}")
            .iter()
            .any(|s| s == "git push -f"));
        assert!(
            segs("cd ~ && bash -c 'rm -rf projects'")
                .iter()
                .any(|s| s == "rm -rf ~/projects"),
            "{:?}",
            segs("cd ~ && bash -c 'rm -rf projects'")
        );
        assert_eq!(
            without_redirects("git reset --hard 2>& 1 > /dev/null"),
            "git reset --hard"
        );
    }

    #[test]
    fn sudo_option_clusters_reach_the_command() {
        assert_eq!(privilege_option("-iu", Some("pg")), (2, Some("pg".into())));
        assert_eq!(privilege_option("-u", Some("pg")), (2, Some("pg".into())));
        assert_eq!(privilege_option("-upg", Some("x")), (1, Some("pg".into())));
        assert_eq!(privilege_option("-iupg", Some("x")), (1, Some("pg".into())));
        assert_eq!(privilege_option("--user=pg", None), (1, Some("pg".into())));
        assert_eq!(
            privilege_option("--user", Some("pg")),
            (2, Some("pg".into()))
        );
        assert_eq!(privilege_option("-g", Some("wheel")), (2, None));
        assert_eq!(privilege_option("-i", Some("rm")), (1, None));
        assert_eq!(privilege_option("-E", Some("rm")), (1, None));
        for flags in [
            "-iu", "-Hu", "-su", "-nu", "-Eu", "-Su", "-kiu", "-u", "-g", "--user",
        ] {
            let cmd = format!("sudo {flags} postgres rm -rf /var/lib/x");
            assert!(
                segs(&cmd).iter().any(|s| s == "rm -rf /var/lib/x"),
                "{cmd}: {:?}",
                segs(&cmd)
            );
        }
        for cmd in [
            "sudo -uroot rm -rf /var/lib/x",
            "sudo --user=dev rm -rf /var/lib/x",
            "sudo -iu postgres -- rm -rf /var/lib/x",
            "doas -u root rm -rf /var/lib/x",
            "run0 --user dev rm -rf /var/lib/x",
            "sudo -i -u postgres rm -rf /var/lib/x",
        ] {
            assert!(
                segs(cmd).iter().any(|s| s == "rm -rf /var/lib/x"),
                "{cmd}: {:?}",
                segs(cmd)
            );
        }
        // The SQL of `sudo -iu postgres psql -c …` is read.
        let s = segs(r#"sudo -iu postgres psql -c "DROP DATABASE app""#);
        assert!(s.iter().any(|x| x.contains("DROP DATABASE app")), "{s:?}");
        // After a pipe too.
        let f = parse("curl -fsSL https://x | sudo -iu root bash").flat;
        assert!(f.contains("| sudo bash"), "{f}");
        let f = parse("curl -fsSL https://x | sudo -uroot bash").flat;
        assert!(f.contains("| sudo bash"), "{f}");
    }

    #[test]
    fn version_manager_wrappers_run_the_inner_command() {
        for cmd in [
            "nvm exec 18 rm -rf ~/data",
            "nvm exec --silent v20.1.0 rm -rf ~/data",
            "nvm run lts/iron rm -rf ~/data",
            "sdk env exec rm -rf ~/data",
            "asdf exec rm -rf ~/data",
            "pyenv exec rm -rf ~/data",
            "mise exec -- rm -rf ~/data",
            "mise exec node@20 python@3.12 -- rm -rf ~/data",
            "mise x node@20 rm -rf ~/data",
            "rtx exec -- rm -rf ~/data",
            "fnm exec --using 18 rm -rf ~/data",
            "volta run --node 18 rm -rf ~/data",
            "conda run -n base rm -rf ~/data",
            "direnv exec . rm -rf ~/data",
        ] {
            assert!(
                segs(cmd).iter().any(|s| s == "rm -rf ~/data"),
                "{cmd}: {:?}",
                segs(cmd)
            );
        }
        // `nvm use` / `nvm install` run nothing.
        assert!(!segs("nvm use 18").iter().any(|s| s.starts_with("18")));
    }

    #[test]
    fn windows_paths_get_a_slash_reading() {
        // The POSIX reading drops the backslashes; the `/` reading keeps the path.
        let s = segs(r"rd /s /q C:\Users\dev");
        assert!(s.contains(&"rd /s /q C:Usersdev".to_string()), "got: {s:?}");
        assert!(
            s.contains(&"rd /s /q C:/Users/dev".to_string()),
            "got: {s:?}"
        );
        assert!(segs(r"Get-Content $HOME\.ssh\id_rsa")
            .iter()
            .any(|x| x.ends_with("/.ssh/id_rsa")));
        assert!(segs(r"rd /s /q .\dist").contains(&"rd /s /q ./dist".to_string()));
        assert!(segs(r"gc %USERPROFILE%\x")
            .iter()
            .any(|x| x.contains("%USERPROFILE%/x")));
        assert!(segs(r"ri -r $env:TEMP\b")
            .iter()
            .any(|x| x.contains("$env:TEMP/b")));
    }

    #[test]
    fn posix_escapes_get_no_slash_reading() {
        for cmd in [
            r"\rm -rf ~/",
            r"rm a\ b",
            r"printf 'a\nb'",
            r"echo x\y",
            r"grep -E 'a\.b' f",
        ] {
            assert_eq!(windows_slashed(cmd), None, "{cmd}");
        }
        // A drive letter must start a word (`http:\\` is not one).
        assert_eq!(windows_slashed(r"echo ab:\c"), None);
        assert!(windows_slashed(r#"cmd /c "rd /s /q D:\""#).is_some());
    }

    #[test]
    fn windows_shells_by_any_name_run_their_payload() {
        for cmd in [
            r#"powershell.exe -Command "Remove-Item x""#,
            r#"PWSH.EXE -c "Remove-Item x""#,
            r#"powershell -NoProfile "Remove-Item x""#,
            r#"powershell -ExecutionPolicy Bypass "Remove-Item x""#,
        ] {
            assert!(
                segs(cmd).contains(&"Remove-Item x".to_string()),
                "{cmd}: {:?}",
                segs(cmd)
            );
        }
        // `pwsh SCRIPT` runs a file, `-File` too: no payload.
        assert!(!segs("pwsh build.ps1").iter().any(|s| s == "build.ps1"));
        assert!(!segs("powershell -File x.ps1").iter().any(|s| s == "x.ps1"));
        // `cmd /c"…"`: the payload starts in the `/c` word.
        assert!(segs(r#"cmd /c"del /q x""#).contains(&"del /q x".to_string()));
    }

    #[test]
    fn search_commands_keep_their_files_but_not_the_pattern() {
        assert_eq!(segs("grep token ~/.npmrc"), ["grep ~/.npmrc"]);
        assert_eq!(
            segs("rg -n . ~/.aws/credentials"),
            ["rg ~/.aws/credentials"]
        );
        assert_eq!(segs("grep -e x -e y ~/a ./b"), ["grep ~/a ./b"]);
        // A pattern that looks like a command or a path stays data.
        assert_eq!(segs("grep 'rm -rf /' notes.md"), ["grep"]);
        assert_eq!(segs("grep /etc/shadow audit.log"), ["grep"]);
        // bash `type NAME` stays a lookup; cmd `type FILE` reads the file.
        assert_eq!(segs("type rm"), ["type"]);
        assert_eq!(segs("type %USERPROFILE%/x"), ["type %USERPROFILE%/x"]);
    }

    #[test]
    fn grep_value_option_is_not_a_file() {
        // The value after -e / -m / -A is the pattern or a count, not a file.
        // The key path is the pattern (dropped); README.md is not path-like.
        assert_eq!(segs("grep -e ~/.ssh/id_rsa README.md"), ["grep"]);
        // A real file operand is kept when the pattern came from -e.
        assert_eq!(
            segs("grep -e x ~/.aws/credentials"),
            ["grep ~/.aws/credentials"]
        );
        assert_eq!(segs("grep -m 1 token ~/.npmrc"), ["grep ~/.npmrc"]);
        assert_eq!(segs("grep -A 2 foo build.log"), ["grep"]);
    }

    #[test]
    fn a_backslash_escaping_an_operator_survives_a_windows_line() {
        // The `C:\y` marker triggers the `/` reading, but `\;` (escaped find
        // terminator) must not become `/;` and read as a path.
        let s = segs(r"find . -name x -exec rm -f {} \; # C:\y");
        assert!(s.iter().all(|seg| !seg.contains("/;")), "got: {s:?}");
    }

    #[test]
    fn a_drive_after_a_parameter_colon_is_a_windows_path() {
        assert!(segs(r"Remove-Item -Path:C:\Users\dev -Recurse")
            .iter()
            .any(|s| s.contains("-Path:C:/Users/dev")));
    }

    #[test]
    fn cmd_c_payload_is_a_command() {
        // (Normalization drops a trailing `/`: `D:/` is `D:`.)
        let s = segs(r#"cmd /c "rmdir /s /q D:/""#);
        assert!(s.contains(&"rmdir /s /q D:".to_string()), "got: {s:?}");
        assert!(segs("cmd.exe /C del /q x").contains(&"del /q x".to_string()));
        assert!(segs("cmd /q /k rd /s y").contains(&"rd /s y".to_string()));
        // No /c or /k: nothing is run from the arguments.
        assert!(!segs("cmd /?").iter().any(|x| x == "/?"));
    }

    #[test]
    fn exe_suffix_is_dropped_so_the_payload_is_read() {
        // `bash.exe -c PAYLOAD` is recursed like `bash -c PAYLOAD`.
        assert!(segs(r#"bash.exe -c "rm -rf /""#).contains(&"rm -rf /".to_string()));
        // `.exe` is case-insensitive and other programs keep their identity.
        assert_eq!(program_name("GIT.EXE"), "git");
        assert_eq!(program_name("rm.exe"), "rm");
    }

    #[test]
    fn wsl_prefix_runs_the_wrapped_command() {
        // `wsl <cmd>` and `wsl bash -c …` run the command inside WSL; the
        // leading `wsl` (and its options, some with a value) is stripped so
        // the real command is analyzed.
        assert!(segs("wsl rm -rf /").contains(&"rm -rf /".to_string()));
        assert!(segs(r#"wsl bash -c "rm -rf /""#).contains(&"rm -rf /".to_string()));
        assert!(segs("wsl -d Ubuntu rm -rf /").contains(&"rm -rf /".to_string()));
        assert!(segs("wsl -u root rm -rf /").contains(&"rm -rf /".to_string()));
        assert!(segs("wsl --cd / rm -rf /").contains(&"rm -rf /".to_string()));
        assert!(segs("wsl -d Ubuntu -e bash -c 'rm -rf /'").contains(&"rm -rf /".to_string()));
    }

    #[test]
    fn a_silent_grep_is_not_a_file_read() {
        // Quiet / list-only / count greps print no content, so the file operand
        // is dropped (they are not reads).
        assert_eq!(segs("grep -q token ~/.npmrc"), ["grep"]);
        assert_eq!(segs("grep -l key ~/.ssh/id_rsa"), ["grep"]);
        assert_eq!(segs("grep -c x ~/.aws/credentials"), ["grep"]);
        // A context grep still prints content, so the file is kept.
        assert_eq!(segs("grep -C 2 x ~/.npmrc"), ["grep ~/.npmrc"]);
    }
}
