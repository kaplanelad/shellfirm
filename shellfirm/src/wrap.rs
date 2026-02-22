//! PTY proxy for wrapping interactive programs (psql, mysql, redis-cli, etc.).
//!
//! Forwards all keystrokes to the child process in real-time so that echoing,
//! tab-completion, and line-editing work naturally. Intercepts only at the
//! statement delimiter boundary (`;` or `\n`), running the accumulated
//! statement through [`crate::checks::analyze_command`] before forwarding.

use std::{
    collections::HashMap,
    ffi::CString,
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
    sync::OnceLock,
};

use anyhow::{bail, Context, Result};
use log::{debug, warn};
use nix::{
    poll::{PollFd, PollFlags, PollTimeout},
    pty::openpty,
    sys::termios::{self, SetArg, Termios},
    unistd::{self, ForkResult, Pid},
};
use regex::Regex;

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
        &settings.challenge,
        &active_refs,
        &settings.deny_patterns_ids,
        &pipeline.context,
        &pipeline.merged_policy,
        &settings.context.escalation,
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

// ---------------------------------------------------------------------------
// RawModeGuard — RAII helper for terminal raw mode
// ---------------------------------------------------------------------------

/// RAII guard that restores terminal settings on drop.
struct RawModeGuard {
    fd: OwnedFd,
    original: Termios,
}

impl RawModeGuard {
    /// Enter raw mode on stdin. Returns a guard that restores on drop.
    fn enter() -> Result<Self> {
        let stdin_raw = std::io::stdin().as_raw_fd();
        // Safety: stdin is open for the lifetime of the process; we duplicate
        // the fd so the OwnedFd won't close stdin on drop.
        let fd = unsafe { OwnedFd::from_raw_fd(libc::dup(stdin_raw)) };
        let original = termios::tcgetattr(&fd)?;
        let mut raw = original.clone();
        termios::cfmakeraw(&mut raw);
        termios::tcsetattr(&fd, SetArg::TCSANOW, &raw)?;
        Ok(Self { fd, original })
    }

    /// Temporarily restore cooked mode for challenge prompts.
    fn restore_cooked(&self) -> Result<()> {
        termios::tcsetattr(&self.fd, SetArg::TCSANOW, &self.original)?;
        Ok(())
    }

    /// Re-enter raw mode after a challenge prompt.
    fn re_enter_raw(&self) -> Result<()> {
        let mut raw = self.original.clone();
        termios::cfmakeraw(&mut raw);
        termios::tcsetattr(&self.fd, SetArg::TCSANOW, &raw)?;
        Ok(())
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = termios::tcsetattr(&self.fd, SetArg::TCSANOW, &self.original);
    }
}

// ---------------------------------------------------------------------------
// Sync terminal size
// ---------------------------------------------------------------------------

fn sync_term_size(master_fd: BorrowedFd<'_>) {
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &mut ws) == 0 {
            let _ = libc::ioctl(master_fd.as_raw_fd(), libc::TIOCSWINSZ, &ws);
        }
    }
}

// ---------------------------------------------------------------------------
// PtyProxy
// ---------------------------------------------------------------------------

/// PTY proxy that wraps an interactive program.
pub struct PtyProxy<'a> {
    pub wrapper_config: WrapperConfig,
    pub settings: &'a Settings,
    pub checks: &'a [Check],
    pub env: &'a dyn Environment,
    pub prompter: &'a dyn Prompter,
    pub config: &'a Config,
}

impl PtyProxy<'_> {
    /// Spawn the wrapped program in a PTY and run the proxy event loop.
    ///
    /// Returns the child's exit code.
    ///
    /// # Errors
    /// Returns an error if PTY creation, fork, or exec fails.
    pub fn run(&self, program: &str, args: &[String]) -> Result<i32> {
        // Open PTY pair
        let pty = openpty(None, None).context("failed to open PTY")?;
        let master_fd = pty.master;
        let slave_fd = pty.slave;

        // Fork
        match unsafe { unistd::fork() }.context("fork failed")? {
            ForkResult::Child => {
                // Child: close master, set up slave as controlling terminal
                drop(master_fd);
                child_setup(slave_fd, program, args);
            }
            ForkResult::Parent { child } => {
                // Parent: close slave
                drop(slave_fd);

                sync_term_size(master_fd.as_fd());

                // Enter raw mode
                let guard = RawModeGuard::enter().context("failed to enter raw mode")?;

                let exit_code = self.event_loop(&master_fd, child, &guard);

                // Guard will restore terminal on drop
                drop(guard);

                // Reap child
                let status = nix::sys::wait::waitpid(child, None).context("waitpid failed")?;

                exit_code.map_or_else(
                    || match status {
                        nix::sys::wait::WaitStatus::Exited(_, code) => Ok(code),
                        nix::sys::wait::WaitStatus::Signaled(_, sig, _) => Ok(128 + sig as i32),
                        _ => Ok(1),
                    },
                    Ok,
                )
            }
        }
    }

    /// Main event loop: poll stdin and master PTY.
    #[allow(clippy::too_many_lines)]
    fn event_loop(&self, master_fd: &OwnedFd, child: Pid, guard: &RawModeGuard) -> Option<i32> {
        let stdin = std::io::stdin();
        let stdin_fd = stdin.as_fd();
        let master_borrow = master_fd.as_fd();
        let mut input_buffer = InputBuffer::new(self.wrapper_config.delimiter);
        let mut buf = [0u8; 4096];

        loop {
            let mut poll_fds = [
                PollFd::new(stdin_fd, PollFlags::POLLIN),
                PollFd::new(master_borrow, PollFlags::POLLIN),
            ];

            match nix::poll::poll(&mut poll_fds, PollTimeout::from(100u16)) {
                Ok(0) => {
                    // Timeout — check if child is still alive
                    match nix::sys::wait::waitpid(child, Some(nix::sys::wait::WaitPidFlag::WNOHANG))
                    {
                        Ok(nix::sys::wait::WaitStatus::Exited(_, code)) => return Some(code),
                        Ok(nix::sys::wait::WaitStatus::Signaled(_, sig, _)) => {
                            return Some(128 + sig as i32);
                        }
                        _ => continue,
                    }
                }
                Ok(_) => {}
                Err(nix::errno::Errno::EINTR) => continue,
                Err(e) => {
                    warn!("[wrap] poll error: {e}");
                    return None;
                }
            }

            // Child output → user (stdout)
            if poll_fds[1]
                .revents()
                .is_some_and(|r| r.contains(PollFlags::POLLIN))
            {
                match unistd::read(master_fd.as_raw_fd(), &mut buf) {
                    Ok(0) | Err(nix::errno::Errno::EIO) => return None,
                    Ok(n) => {
                        let _ = write_all_fd(libc::STDOUT_FILENO, &buf[..n]);
                    }
                    Err(nix::errno::Errno::EINTR) => {}
                    Err(e) => {
                        warn!("[wrap] read master error: {e}");
                        return None;
                    }
                }
            }

            // Check for hangup on master (child exited)
            if poll_fds[1]
                .revents()
                .is_some_and(|r| r.contains(PollFlags::POLLHUP))
            {
                // Drain remaining output
                loop {
                    match unistd::read(master_fd.as_raw_fd(), &mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let _ = write_all_fd(libc::STDOUT_FILENO, &buf[..n]);
                        }
                    }
                }
                return None;
            }

            // User input → child (master)
            if poll_fds[0]
                .revents()
                .is_some_and(|r| r.contains(PollFlags::POLLIN))
            {
                let stdin_raw = stdin_fd.as_raw_fd();
                match unistd::read(stdin_raw, &mut buf) {
                    Ok(0) => return None, // stdin EOF
                    Ok(n) => {
                        let master_raw = master_fd.as_raw_fd();
                        for &byte in &buf[..n] {
                            if Self::is_control_passthrough(byte) {
                                // Forward control chars immediately, bypass buffer
                                let _ = write_all_fd(master_raw, &[byte]);
                                if byte == 0x03 || byte == 0x04 {
                                    // Ctrl-C or Ctrl-D: reset buffer
                                    input_buffer.reset();
                                }
                                continue;
                            }

                            // Feed to our buffer for delimiter detection
                            match input_buffer.feed(byte) {
                                BufferResult::Buffered => {
                                    // Not a delimiter — forward to child for echoing
                                    let _ = write_all_fd(master_raw, &[byte]);
                                }
                                BufferResult::Statement(stmt) => {
                                    debug!(
                                        "[wrap] statement detected ({} bytes): {:?}",
                                        stmt.len(),
                                        stmt
                                    );

                                    // Drain pending child output before showing challenge
                                    Self::drain_child_output(master_fd);

                                    // Temporarily restore cooked mode for challenge
                                    if let Err(e) = guard.restore_cooked() {
                                        warn!("[wrap] failed to restore cooked mode: {e}");
                                    }

                                    let action = handle_statement(
                                        &stmt,
                                        self.settings,
                                        self.checks,
                                        self.env,
                                        self.prompter,
                                        self.config,
                                        &self.wrapper_config.display_name,
                                    );

                                    if let Err(e) = guard.re_enter_raw() {
                                        warn!("[wrap] failed to re-enter raw mode: {e}");
                                    }

                                    match action {
                                        StatementAction::Forward => {
                                            // Forward the delimiter byte
                                            let delim =
                                                self.wrapper_config.delimiter.trigger_byte();
                                            let _ = write_all_fd(master_raw, &[delim]);
                                        }
                                        StatementAction::Block => {
                                            // Send Ctrl-C to cancel pending input
                                            let _ = write_all_fd(master_raw, &[0x03]);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(nix::errno::Errno::EINTR) => {}
                    Err(e) => {
                        warn!("[wrap] read stdin error: {e}");
                        return None;
                    }
                }
            }
        }
    }

    /// Returns true for control bytes that should be forwarded immediately
    /// without being fed to the input buffer.
    const fn is_control_passthrough(byte: u8) -> bool {
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

    /// Drain any pending output from the child PTY before showing a challenge.
    ///
    /// This prevents psql's echo/prompt output from mixing with the challenge
    /// display.
    fn drain_child_output(master_fd: &OwnedFd) {
        let mut drain_buf = [0u8; 4096];
        loop {
            let mut pfd = [PollFd::new(master_fd.as_fd(), PollFlags::POLLIN)];
            match nix::poll::poll(&mut pfd, PollTimeout::from(10u16)) {
                Ok(0) => break, // no more data
                Ok(_) => match unistd::read(master_fd.as_raw_fd(), &mut drain_buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let _ = write_all_fd(libc::STDOUT_FILENO, &drain_buf[..n]);
                    }
                },
                _ => break,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Child setup (runs after fork in child process)
// ---------------------------------------------------------------------------

fn child_setup(slave_fd: OwnedFd, program: &str, args: &[String]) -> ! {
    // Create new session
    let _ = unistd::setsid();

    let raw_fd = slave_fd.as_raw_fd();

    // Set controlling terminal
    unsafe {
        libc::ioctl(raw_fd, u64::from(libc::TIOCSCTTY), 0);
    }

    // Redirect stdin/stdout/stderr to slave
    let _ = unistd::dup2(raw_fd, libc::STDIN_FILENO);
    let _ = unistd::dup2(raw_fd, libc::STDOUT_FILENO);
    let _ = unistd::dup2(raw_fd, libc::STDERR_FILENO);

    // Close original slave fd if it's not one of 0/1/2
    if raw_fd > 2 {
        drop(slave_fd);
    }

    // Build argv
    let c_program = CString::new(program).unwrap_or_else(|_| {
        eprintln!("shellfirm wrap: invalid program name");
        std::process::exit(1);
    });

    let mut c_args: Vec<CString> = vec![c_program.clone()];
    for arg in args {
        c_args.push(CString::new(arg.as_str()).unwrap_or_else(|_| {
            eprintln!("shellfirm wrap: invalid argument");
            std::process::exit(1);
        }));
    }

    // execvp
    let _ = unistd::execvp(&c_program, &c_args);
    eprintln!(
        "shellfirm wrap: failed to exec '{}': {}",
        program,
        std::io::Error::last_os_error()
    );
    std::process::exit(127);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn write_all_fd(fd: i32, data: &[u8]) -> Result<()> {
    let mut written = 0;
    while written < data.len() {
        let n = unsafe { libc::write(fd, data[written..].as_ptr().cast(), data.len() - written) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            bail!("write error: {err}");
        }
        written += n.cast_unsigned();
    }
    Ok(())
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
        let temp = tempfile::tempdir().unwrap();
        let config = Config::new(Some(&temp.path().join("app").display().to_string())).unwrap();

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
        let temp = tempfile::tempdir().unwrap();
        let config = Config::new(Some(&temp.path().join("app").display().to_string())).unwrap();

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
        let temp = tempfile::tempdir().unwrap();
        let config = Config::new(Some(&temp.path().join("app").display().to_string())).unwrap();

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
        assert!(PtyProxy::is_control_passthrough(0x0D));
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
        let temp = tempfile::tempdir().unwrap();
        let config = Config::new(Some(&temp.path().join("app").display().to_string())).unwrap();

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
