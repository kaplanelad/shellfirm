//! Platform-agnostic types and logic for the PTY proxy.

use std::{collections::HashMap, sync::OnceLock};

use regex::Regex;
use tracing::{debug, warn};

use crate::{
    audit,
    checks::{self, Check},
    config::{Config, Settings, WrappersConfig},
    env::Environment,
    prompt::{ChallengeResult, Prompter},
};

// ---------------------------------------------------------------------------
// Delimiter
// ---------------------------------------------------------------------------

/// Statement delimiter for the wrapped program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delimiter {
    /// A specific character (e.g. `;`).
    Char(char),
    /// Newline (`\n`).
    Newline,
}

impl Delimiter {
    /// Parse a delimiter from a config string.
    ///
    /// Falls back to `;` for multi-character strings that aren't `\n`.
    #[must_use]
    pub fn from_str_config(s: &str) -> Self {
        match s {
            "\\n" | "\n" => Self::Newline,
            _ => s
                .chars()
                .next()
                .filter(|_| s.len() == 1)
                .map_or(Self::Char(';'), Self::Char),
        }
    }

    /// The byte value that triggers statement completion.
    #[must_use]
    pub const fn trigger_byte(self) -> u8 {
        match self {
            Self::Char(c) => c as u8,
            Self::Newline => b'\n',
        }
    }
}

// ---------------------------------------------------------------------------
// WrapperConfig (resolved per-invocation)
// ---------------------------------------------------------------------------

/// Resolved configuration for a single `shellfirm wrap` invocation.
#[derive(Debug, Clone)]
pub struct WrapperConfig {
    pub program: String,
    pub delimiter: Delimiter,
    pub check_groups: Vec<String>,
    pub display_name: String,
}

/// Built-in defaults for known tools.
fn builtin_defaults() -> &'static HashMap<&'static str, (&'static str, &'static [&'static str])> {
    static DEFAULTS: OnceLock<HashMap<&str, (&str, &[&str])>> = OnceLock::new();
    DEFAULTS.get_or_init(|| {
        let mut m = HashMap::new();
        m.insert("psql", (";", &["database"] as &[&str]));
        m.insert("mysql", (";", &["database"] as &[&str]));
        m.insert("redis-cli", ("\\n", &["database"] as &[&str]));
        m.insert("mongosh", (";", &["database"] as &[&str]));
        m.insert("mongo", (";", &["database"] as &[&str]));
        m
    })
}

impl WrapperConfig {
    /// Resolve the wrapper config for a given program.
    ///
    /// Priority: CLI `--delimiter` flag > user config > built-in defaults > generic fallback.
    #[must_use]
    #[allow(clippy::option_if_let_else)]
    pub fn resolve(
        program: &str,
        cli_delimiter: Option<&str>,
        user_config: &WrappersConfig,
    ) -> Self {
        let base_name = std::path::Path::new(program)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(program);

        // Look up user config, then built-in defaults
        let user_tool = user_config.tools.get(base_name);
        let builtin = builtin_defaults().get(base_name);

        // Resolve delimiter
        let delimiter = if let Some(d) = cli_delimiter {
            Delimiter::from_str_config(d)
        } else if let Some(tool) = user_tool {
            Delimiter::from_str_config(&tool.delimiter)
        } else if let Some((d, _)) = builtin {
            Delimiter::from_str_config(d)
        } else {
            Delimiter::Newline // generic fallback
        };

        // Resolve check groups
        let check_groups = if let Some(tool) = user_tool.filter(|t| !t.check_groups.is_empty()) {
            tool.check_groups.clone()
        } else if let Some((_, groups)) = builtin {
            groups.iter().map(|s| (*s).to_string()).collect()
        } else {
            vec![] // empty = use global setting
        };

        Self {
            program: program.to_string(),
            delimiter,
            check_groups,
            display_name: base_name.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// InputBuffer — quote-aware delimiter detection
// ---------------------------------------------------------------------------

/// Tracks quote/escape state for delimiter detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuoteState {
    Normal,
    SingleQuoted,
    DoubleQuoted,
    /// The next character is escaped (after `\` in Normal).
    EscapedNormal,
    /// The next character is escaped (after `\` in `DoubleQuoted`).
    EscapedDouble,
}

/// Result of feeding a byte to the input buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BufferResult {
    /// Byte was buffered, no statement complete yet.
    Buffered,
    /// A complete statement was detected (delimiter found outside quotes).
    Statement(String),
}

/// Accumulates input bytes and detects statement boundaries,
/// respecting single/double quotes and backslash escapes.
#[derive(Debug)]
pub struct InputBuffer {
    buf: Vec<u8>,
    state: QuoteState,
    delimiter: Delimiter,
}

impl InputBuffer {
    /// Create a new buffer with the given delimiter.
    #[must_use]
    pub fn new(delimiter: Delimiter) -> Self {
        Self {
            buf: Vec::with_capacity(256),
            state: QuoteState::Normal,
            delimiter,
        }
    }

    /// Feed a single byte. Returns `Statement(text)` when a delimiter is
    /// found outside of quotes, consuming the buffer up to (but not
    /// including) the delimiter byte.
    pub fn feed(&mut self, byte: u8) -> BufferResult {
        match self.state {
            QuoteState::EscapedNormal => {
                self.buf.push(byte);
                self.state = QuoteState::Normal;
                BufferResult::Buffered
            }
            QuoteState::EscapedDouble => {
                self.buf.push(byte);
                self.state = QuoteState::DoubleQuoted;
                BufferResult::Buffered
            }
            QuoteState::SingleQuoted => {
                self.buf.push(byte);
                if byte == b'\'' {
                    self.state = QuoteState::Normal;
                }
                BufferResult::Buffered
            }
            QuoteState::DoubleQuoted => {
                self.buf.push(byte);
                if byte == b'"' {
                    self.state = QuoteState::Normal;
                } else if byte == b'\\' {
                    self.state = QuoteState::EscapedDouble;
                }
                BufferResult::Buffered
            }
            QuoteState::Normal => {
                if byte == b'\\' {
                    self.buf.push(byte);
                    self.state = QuoteState::EscapedNormal;
                    return BufferResult::Buffered;
                }
                if byte == b'\'' {
                    self.buf.push(byte);
                    self.state = QuoteState::SingleQuoted;
                    return BufferResult::Buffered;
                }
                if byte == b'"' {
                    self.buf.push(byte);
                    self.state = QuoteState::DoubleQuoted;
                    return BufferResult::Buffered;
                }
                // Check delimiter
                if byte == self.delimiter.trigger_byte() {
                    let stmt = String::from_utf8_lossy(&self.buf).to_string();
                    self.buf.clear();
                    self.state = QuoteState::Normal;
                    return BufferResult::Statement(stmt);
                }
                self.buf.push(byte);
                BufferResult::Buffered
            }
        }
    }

    /// Reset the buffer and quote state.
    pub fn reset(&mut self) {
        self.buf.clear();
        self.state = QuoteState::Normal;
    }
}

// ---------------------------------------------------------------------------
// Statement handling (reuses the existing analysis pipeline)
// ---------------------------------------------------------------------------

/// Outcome after analyzing a statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementAction {
    /// Statement is safe or user passed the challenge — forward the delimiter.
    Forward,
    /// Statement was blocked — send Ctrl-C to cancel.
    Block,
}

fn strip_quotes_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"'[^']*'|"[^"]*""#).unwrap())
}

/// Analyze a statement and optionally challenge the user.
///
/// Fail-open: if analysis errors out, we return `Forward` to avoid
/// breaking the user's interactive session.
#[allow(clippy::too_many_arguments)]
pub fn handle_statement(
    statement: &str,
    settings: &Settings,
    checks: &[Check],
    env: &dyn Environment,
    prompter: &dyn Prompter,
    config: &Config,
    tool_name: &str,
) -> StatementAction {
    let trimmed = statement.trim();
    if trimmed.is_empty() {
        return StatementAction::Forward;
    }

    debug!("[wrap:{tool_name}] analyzing: {trimmed:?}");

    let pipeline =
        match checks::analyze_command(trimmed, settings, checks, env, strip_quotes_regex()) {
            Ok(p) => p,
            Err(e) => {
                warn!("[wrap:{tool_name}] analysis failed (fail-open): {e}");
                return StatementAction::Forward;
            }
        };

    if pipeline.active_matches.is_empty() {
        return StatementAction::Forward;
    }

    let active_refs: Vec<&Check> = pipeline.active_matches.iter().collect();

    // Audit: pre-challenge entry
    let event_id = uuid::Uuid::new_v4().to_string();
    if settings.audit_enabled {
        let event = audit::AuditEvent {
            event_id: event_id.clone(),
            timestamp: audit::now_timestamp(),
            command: format!("[wrap:{tool_name}] {trimmed}"),
            matched_ids: pipeline
                .active_matches
                .iter()
                .map(|c| c.id.clone())
                .collect(),
            challenge_type: format!("{}", settings.challenge),
            outcome: audit::AuditOutcome::Cancelled,
            context_labels: pipeline.context.labels.clone(),
            severity: pipeline.max_severity,
            agent_name: None,
            agent_session_id: None,
            blast_radius_scope: None,
            blast_radius_detail: None,
        };
        if let Err(e) = audit::log_event(&config.audit_log_path(), &event) {
            warn!("Failed to write audit log: {e}");
        }
    }

    // Run challenge
    let result = match checks::challenge_with_context(
        settings,
        &active_refs,
        &pipeline.context,
        &pipeline.merged_policy,
        prompter,
        &pipeline.blast_radii,
    ) {
        Ok(r) => r,
        Err(e) => {
            warn!("[wrap:{tool_name}] challenge failed (fail-open): {e}");
            return StatementAction::Forward;
        }
    };

    // Audit: post-challenge entry
    if settings.audit_enabled {
        let outcome = match result {
            ChallengeResult::Passed => audit::AuditOutcome::Allowed,
            ChallengeResult::Denied => audit::AuditOutcome::Denied,
        };
        let event = audit::AuditEvent {
            event_id,
            timestamp: audit::now_timestamp(),
            command: format!("[wrap:{tool_name}] {trimmed}"),
            matched_ids: pipeline
                .active_matches
                .iter()
                .map(|c| c.id.clone())
                .collect(),
            challenge_type: format!("{}", settings.challenge),
            outcome,
            context_labels: pipeline.context.labels,
            severity: pipeline.max_severity,
            agent_name: None,
            agent_session_id: None,
            blast_radius_scope: None,
            blast_radius_detail: None,
        };
        if let Err(e) = audit::log_event(&config.audit_log_path(), &event) {
            warn!("Failed to write audit log: {e}");
        }
    }

    match result {
        ChallengeResult::Passed => StatementAction::Forward,
        ChallengeResult::Denied => StatementAction::Block,
    }
}

/// Returns true for control bytes that should be forwarded immediately
/// without being fed to the input buffer.
#[must_use]
pub const fn is_control_passthrough(byte: u8) -> bool {
    matches!(
        byte,
        0x01..=0x02 // Ctrl-A, Ctrl-B
        | 0x03      // Ctrl-C
        | 0x04      // Ctrl-D
        | 0x05..=0x06 // Ctrl-E, Ctrl-F
        | 0x09      // Tab
        | 0x0D      // CR (Enter in raw mode) — forward to child, don't buffer
        | 0x0E..=0x10 // Ctrl-N, Ctrl-O, Ctrl-P
        | 0x12..=0x14 // Ctrl-R, Ctrl-S, Ctrl-T
        | 0x15..=0x17 // Ctrl-U, Ctrl-V, Ctrl-W
        | 0x1A      // Ctrl-Z
        | 0x1B      // ESC
        | 0x7F      // DEL (backspace)
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WrapperToolConfig;

    // -- Delimiter tests --

    #[test]
    fn delimiter_from_semicolon() {
        let d = Delimiter::from_str_config(";");
        assert_eq!(d, Delimiter::Char(';'));
        assert_eq!(d.trigger_byte(), b';');
    }

    #[test]
    fn delimiter_from_newline_escape() {
        let d = Delimiter::from_str_config("\\n");
        assert_eq!(d, Delimiter::Newline);
        assert_eq!(d.trigger_byte(), b'\n');
    }

    #[test]
    fn delimiter_from_literal_newline() {
        let d = Delimiter::from_str_config("\n");
        assert_eq!(d, Delimiter::Newline);
    }

    // -- InputBuffer tests --

    #[test]
    fn basic_semicolon_delimiter() {
        let mut buf = InputBuffer::new(Delimiter::Char(';'));
        assert_eq!(buf.feed(b'S'), BufferResult::Buffered);
        assert_eq!(buf.feed(b'E'), BufferResult::Buffered);
        assert_eq!(buf.feed(b'L'), BufferResult::Buffered);
        assert_eq!(buf.feed(b';'), BufferResult::Statement("SEL".to_string()));
    }

    #[test]
    fn delimiter_inside_single_quotes_not_split() {
        let mut buf = InputBuffer::new(Delimiter::Char(';'));
        for &b in b"INSERT INTO t VALUES('" {
            buf.feed(b);
        }
        // Semicolon inside single quotes — should NOT trigger
        assert_eq!(buf.feed(b';'), BufferResult::Buffered);
        buf.feed(b'\''); // close quote
        buf.feed(b')');
        assert_eq!(
            buf.feed(b';'),
            BufferResult::Statement("INSERT INTO t VALUES(';')".to_string())
        );
    }

    #[test]
    fn delimiter_inside_double_quotes_not_split() {
        let mut buf = InputBuffer::new(Delimiter::Char(';'));
        for &b in b"SELECT \"col;name\" FROM t" {
            buf.feed(b);
        }
        assert_eq!(
            buf.feed(b';'),
            BufferResult::Statement("SELECT \"col;name\" FROM t".to_string())
        );
    }

    #[test]
    fn escaped_quote_handling() {
        let mut buf = InputBuffer::new(Delimiter::Char(';'));
        // SELECT "col\"name" FROM t;
        for &b in b"SELECT \"col\\" {
            buf.feed(b);
        }
        // The \" should not end the double-quote
        buf.feed(b'"'); // this is escaped, stays in DoubleQuoted
        for &b in b"name\" FROM t" {
            buf.feed(b);
        }
        assert_eq!(
            buf.feed(b';'),
            BufferResult::Statement("SELECT \"col\\\"name\" FROM t".to_string())
        );
    }

    #[test]
    fn multiple_statements() {
        let mut buf = InputBuffer::new(Delimiter::Char(';'));
        for &b in b"SELECT 1" {
            buf.feed(b);
        }
        assert_eq!(
            buf.feed(b';'),
            BufferResult::Statement("SELECT 1".to_string())
        );
        for &b in b" DROP TABLE x" {
            buf.feed(b);
        }
        assert_eq!(
            buf.feed(b';'),
            BufferResult::Statement(" DROP TABLE x".to_string())
        );
    }

    #[test]
    fn newline_delimiter() {
        let mut buf = InputBuffer::new(Delimiter::Newline);
        for &b in b"FLUSHALL" {
            buf.feed(b);
        }
        assert_eq!(
            buf.feed(b'\n'),
            BufferResult::Statement("FLUSHALL".to_string())
        );
    }

    #[test]
    fn empty_statement() {
        let mut buf = InputBuffer::new(Delimiter::Char(';'));
        assert_eq!(buf.feed(b';'), BufferResult::Statement(String::new()));
    }

    #[test]
    fn whitespace_only_statement() {
        let mut buf = InputBuffer::new(Delimiter::Char(';'));
        buf.feed(b' ');
        buf.feed(b' ');
        assert_eq!(buf.feed(b';'), BufferResult::Statement("  ".to_string()));
    }

    #[test]
    fn multi_line_sql() {
        let mut buf = InputBuffer::new(Delimiter::Char(';'));
        let input = b"SELECT *\nFROM users\nWHERE id = 1";
        for &b in input {
            buf.feed(b);
        }
        assert_eq!(
            buf.feed(b';'),
            BufferResult::Statement("SELECT *\nFROM users\nWHERE id = 1".to_string())
        );
    }

    #[test]
    fn reset_clears_buffer() {
        let mut buf = InputBuffer::new(Delimiter::Char(';'));
        buf.feed(b'A');
        buf.feed(b'B');
        buf.reset();
        buf.feed(b'C');
        assert_eq!(buf.feed(b';'), BufferResult::Statement("C".to_string()));
    }

    // -- WrapperConfig resolution tests --

    #[test]
    fn known_tool_gets_builtin_defaults() {
        let cfg = WrapperConfig::resolve("psql", None, &WrappersConfig::default());
        assert_eq!(cfg.delimiter, Delimiter::Char(';'));
        assert_eq!(cfg.check_groups, vec!["database"]);
        assert_eq!(cfg.display_name, "psql");
    }

    #[test]
    fn redis_cli_gets_newline_delimiter() {
        let cfg = WrapperConfig::resolve("redis-cli", None, &WrappersConfig::default());
        assert_eq!(cfg.delimiter, Delimiter::Newline);
        assert_eq!(cfg.check_groups, vec!["database"]);
    }

    #[test]
    fn user_override_takes_precedence() {
        let mut tools = HashMap::new();
        tools.insert(
            "psql".to_string(),
            WrapperToolConfig {
                delimiter: "\\n".to_string(),
                check_groups: vec!["custom".to_string()],
            },
        );
        let user_cfg = WrappersConfig { tools };

        let cfg = WrapperConfig::resolve("psql", None, &user_cfg);
        assert_eq!(cfg.delimiter, Delimiter::Newline);
        assert_eq!(cfg.check_groups, vec!["custom"]);
    }

    #[test]
    fn cli_delimiter_overrides_all() {
        let cfg = WrapperConfig::resolve("psql", Some("\\n"), &WrappersConfig::default());
        assert_eq!(cfg.delimiter, Delimiter::Newline);
    }

    #[test]
    fn unknown_tool_gets_generic_fallback() {
        let cfg = WrapperConfig::resolve("some-tool", None, &WrappersConfig::default());
        assert_eq!(cfg.delimiter, Delimiter::Newline);
        assert!(cfg.check_groups.is_empty());
    }

    #[test]
    fn path_in_program_name_uses_basename() {
        let cfg = WrapperConfig::resolve("/usr/bin/psql", None, &WrappersConfig::default());
        assert_eq!(cfg.display_name, "psql");
        assert_eq!(cfg.delimiter, Delimiter::Char(';'));
    }

    // -- handle_statement tests --

    #[test]
    fn safe_statement_forwards() {
        let settings = Settings::default();
        let checks = settings.get_active_checks().unwrap();
        let env = crate::env::MockEnvironment {
            cwd: "/tmp".into(),
            ..Default::default()
        };
        let prompter = crate::prompt::MockPrompter::passing();
        let temp = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = Config::new(Some(&temp.root.join("app").display().to_string())).unwrap();

        let action = handle_statement(
            "SELECT 1", &settings, &checks, &env, &prompter, &config, "psql",
        );
        assert_eq!(action, StatementAction::Forward);
    }

    #[test]
    fn drop_table_triggers_challenge() {
        let settings = Settings::default();
        let checks = settings.get_active_checks().unwrap();
        let env = crate::env::MockEnvironment {
            cwd: "/tmp".into(),
            ..Default::default()
        };
        let prompter = crate::prompt::MockPrompter::passing();
        let temp = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = Config::new(Some(&temp.root.join("app").display().to_string())).unwrap();

        let action = handle_statement(
            "DROP TABLE users",
            &settings,
            &checks,
            &env,
            &prompter,
            &config,
            "psql",
        );
        // MockPrompter::passing() passes the challenge
        assert_eq!(action, StatementAction::Forward);

        // Verify the prompter was invoked (challenge was shown)
        let displays = prompter.captured_displays.borrow();
        assert_eq!(displays.len(), 1);
        assert!(displays[0]
            .descriptions
            .iter()
            .any(|d| d.contains("Dropping a table")));
    }

    #[test]
    fn empty_statement_forwards() {
        let settings = Settings::default();
        let checks = settings.get_active_checks().unwrap();
        let env = crate::env::MockEnvironment::default();
        let prompter = crate::prompt::MockPrompter::passing();
        let temp = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = Config::new(Some(&temp.root.join("app").display().to_string())).unwrap();

        assert_eq!(
            handle_statement("", &settings, &checks, &env, &prompter, &config, "test"),
            StatementAction::Forward
        );
        assert_eq!(
            handle_statement("   ", &settings, &checks, &env, &prompter, &config, "test"),
            StatementAction::Forward
        );
    }

    #[test]
    fn cr_is_control_passthrough() {
        // 0x0D (CR / Enter in raw mode) must be a control passthrough so it
        // never pollutes the input buffer with stray \r bytes.
        assert!(is_control_passthrough(0x0D));
    }

    #[test]
    fn interactive_flushall_triggers_challenge() {
        let settings = Settings::default();
        let checks = settings.get_active_checks().unwrap();
        let env = crate::env::MockEnvironment {
            cwd: "/tmp".into(),
            ..Default::default()
        };
        let prompter = crate::prompt::MockPrompter::passing();
        let temp = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = Config::new(Some(&temp.root.join("app").display().to_string())).unwrap();

        let action = handle_statement(
            "FLUSHALL",
            &settings,
            &checks,
            &env,
            &prompter,
            &config,
            "redis-cli",
        );
        assert_eq!(action, StatementAction::Forward);

        let displays = prompter.captured_displays.borrow();
        assert_eq!(displays.len(), 1);
        assert!(displays[0]
            .descriptions
            .iter()
            .any(|d| d.contains("FLUSHALL")));
    }
}
