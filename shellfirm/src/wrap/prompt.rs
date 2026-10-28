//! Challenge prompter used inside a wrap session.
//!
//! The regular [`crate::prompt::TerminalPrompter`] exits the process when the
//! user cancels and blocks forever on a deny. Inside `shellfirm wrap` that
//! would kill the user's database session, so this prompter:
//!
//! * runs while the terminal stays in raw mode, doing its own minimal line
//!   input (Backspace, Ctrl-U) and writing `\r\n` line endings;
//! * treats Esc, Ctrl-C and Ctrl-D as "discard this statement" and returns
//!   [`ChallengeResult::Denied`];
//! * returns immediately for policy denies.

use std::{
    cell::{Cell, RefCell},
    io::Write,
};

use console::style;
use rand::RngExt;

use crate::{
    config::Challenge,
    prompt::{ChallengeResult, DisplayContext, Prompter},
};

/// Reads one byte of user input; `None` on EOF / error.
pub type ByteReader = Box<dyn FnMut() -> Option<u8>>;

/// How the last challenge ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptOutcome {
    Passed,
    /// User pressed Esc / Ctrl-C / Ctrl-D, or input closed.
    Cancelled,
    /// The matched check is on a deny list.
    PolicyDenied,
}

/// Raw-mode challenge prompter for wrap sessions.
pub struct WrapPrompter {
    input: RefCell<ByteReader>,
    output: RefCell<Box<dyn Write>>,
    /// Called before reading answers and after the challenge ends (flushes
    /// pending terminal input).
    before_read: Box<dyn Fn()>,
    statement: RefCell<Option<String>>,
    tool: String,
    last_outcome: Cell<Option<PromptOutcome>>,
    last_challenge: Cell<Option<Challenge>>,
}

impl WrapPrompter {
    #[must_use]
    pub fn new(
        tool: &str,
        input: ByteReader,
        output: Box<dyn Write>,
        before_read: Box<dyn Fn()>,
    ) -> Self {
        Self {
            input: RefCell::new(input),
            output: RefCell::new(output),
            before_read,
            statement: RefCell::new(None),
            tool: tool.to_string(),
            last_outcome: Cell::new(None),
            last_challenge: Cell::new(None),
        }
    }

    /// Set the statement shown in the banner for the next challenge.
    pub fn set_statement(&self, statement: &str) {
        *self.statement.borrow_mut() = Some(statement.to_string());
    }

    /// Outcome of the most recent challenge (if one ran).
    #[must_use]
    pub const fn last_outcome(&self) -> Option<PromptOutcome> {
        self.last_outcome.get()
    }

    /// Effective challenge of the most recent prompt.
    #[must_use]
    pub const fn last_challenge(&self) -> Option<Challenge> {
        self.last_challenge.get()
    }

    /// Write a line (raw mode: explicit CRLF).
    pub fn say(&self, msg: &str) {
        let mut out = self.output.borrow_mut();
        let _ = write!(out, "{msg}\r\n");
        let _ = out.flush();
    }

    fn write(&self, msg: &str) {
        let mut out = self.output.borrow_mut();
        let _ = write!(out, "{msg}");
        let _ = out.flush();
    }

    fn banner(&self, display: &DisplayContext) {
        // Leave the child's prompt line and clear anything below it.
        self.write("\r\n\x1b[J");
        let sep = "=".repeat(12);
        let title = if display.is_denied {
            format!(
                "{sep} STATEMENT DENIED (shellfirm wrap:{}) {sep}",
                self.tool
            )
        } else {
            format!(
                "{sep} RISKY STATEMENT DETECTED (shellfirm wrap:{}) {sep}",
                self.tool
            )
        };
        self.say(&style(title).red().bold().to_string());
        if let Some(stmt) = self.statement.borrow().as_deref() {
            let shown: String = if stmt.chars().count() > 200 {
                format!("{}...", stmt.chars().take(200).collect::<String>())
            } else {
                stmt.to_string()
            };
            self.say(&format!("{} {shown}", style("Statement:").white().bold()));
        }
        // Matched checks, laid out like the shell banner: one line per
        // check when there are several (id, severity and description),
        // otherwise `Check:` + the description below.
        let multi = display.matched.len() > 1;
        if multi {
            self.say(&style("Checks:").red().bold().to_string());
            for m in &display.matched {
                self.say(&format!("- {} [{}]: {}", m.id, m.severity, m.description));
            }
        } else if !display.check_ids.is_empty() {
            let label = if display.check_ids.len() == 1 {
                "Check:"
            } else {
                "Checks:"
            };
            self.say(&format!(
                "{} {}",
                style(label).bold(),
                display.check_ids.join(", ")
            ));
        }
        if let Some(ref sev) = display.severity_label {
            self.say(&format!(
                "{} {}",
                style("Severity:").red().bold(),
                style(sev).red()
            ));
        }
        if let Some(ref br) = display.blast_radius_label {
            self.say(&format!(
                "{} {}",
                style("Blast radius:").red().bold(),
                style(br).dim()
            ));
        }
        if !display.context_labels.is_empty() {
            self.say(&format!(
                "{} {}",
                style("Context:").cyan().bold(),
                style(display.context_labels.join(", ")).cyan()
            ));
        }
        if !multi {
            for desc in &display.descriptions {
                self.say(&format!("{} {desc}", style("Description:").white().bold()));
            }
        }
        for alt in &display.alternatives {
            self.say(&format!(
                "{} {}",
                style("Alternative:").green().bold(),
                alt.suggestion
            ));
            if let Some(ref info) = alt.explanation {
                self.say(&format!("  {}", style(format!("({info})")).dim()));
            }
        }
        if !display.is_denied {
            // Same wording as the shell banner: the note already says
            // "Escalated to Yes (from Math): ...".
            if let Some(ref note) = display.escalation_note {
                self.say(&style(note).magenta().bold().to_string());
            }
            for note in &display.notes {
                self.say(&style(note).yellow().to_string());
            }
            let hint = if display.matched.is_empty() {
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
                self.say(&style(hint).dim().to_string());
            }
        }
        self.say("");
    }

    /// Read a line in raw mode. `None` = cancelled.
    fn read_line(&self) -> Option<String> {
        let mut line = String::new();
        let mut utf8 = Vec::new();
        loop {
            let byte = (self.input.borrow_mut())()?;
            match byte {
                0x03 | 0x04 | 0x1B => {
                    self.write("\r\n");
                    return None;
                }
                b'\r' | b'\n' => {
                    self.write("\r\n");
                    return Some(line);
                }
                0x7F | 0x08 => {
                    if line.pop().is_some() {
                        self.write("\x08 \x08");
                    }
                }
                0x15 => {
                    for _ in 0..line.chars().count() {
                        self.write("\x08 \x08");
                    }
                    line.clear();
                }
                0x00..=0x1F => {}
                _ => {
                    utf8.push(byte);
                    if let Ok(s) = std::str::from_utf8(&utf8) {
                        if line.len() < 256 {
                            line.push_str(s);
                            self.write(s);
                        }
                        utf8.clear();
                    } else if utf8.len() >= 4 {
                        utf8.clear();
                    }
                }
            }
        }
    }

    fn ask(&self, question: &str, accept: &dyn Fn(&str) -> bool) -> bool {
        let hint = style("Esc or Ctrl-C to discard the statement")
            .underlined()
            .italic();
        loop {
            self.write(&format!("{question} ({hint}) "));
            let Some(answer) = self.read_line() else {
                return false;
            };
            if accept(&answer) {
                return true;
            }
            self.say("wrong answer, try again...");
        }
    }

    /// Why the statement is denied, and how to allow it again: only the ids
    /// that are on the user's own deny list get a `deny --remove` hint.
    fn deny_notice(&self, display: &DisplayContext) {
        if display.deny_reasons.is_empty() {
            self.say(
                &style("The statement is not allowed by policy.")
                    .red()
                    .bold()
                    .to_string(),
            );
            return;
        }
        for reason in &display.deny_reasons {
            self.say(&format!(
                "{} {}",
                style("Denied:").red().bold(),
                style(reason).red()
            ));
        }
        let personal: Vec<&str> = display
            .deny_reasons
            .iter()
            .filter(|r| r.ends_with("is on your deny list"))
            .filter_map(|r| r.split('`').nth(1))
            .collect();
        let by_policy = personal.len() < display.deny_reasons.len();
        let mut hint = vec!["Denied statements cannot be confirmed.".to_string()];
        if !personal.is_empty() {
            let cmds = personal
                .iter()
                .map(|id| format!("shellfirm config deny --remove {id}"))
                .collect::<Vec<_>>()
                .join(" && ");
            let them = if personal.len() == 1 { "it" } else { "them" };
            hint.push(format!("To allow {them} again: `{cmds}`."));
        }
        if by_policy {
            hint.push("Project-policy denies are changed in .shellfirm.yaml.".to_string());
        }
        self.say(&style(hint.join(" ")).dim().to_string());
    }

    fn run(&self, display: &DisplayContext) -> PromptOutcome {
        self.banner(display);
        if display.is_denied {
            self.deny_notice(display);
            return PromptOutcome::PolicyDenied;
        }
        (self.before_read)();
        // `[CRITICAL] ` before the question, as in the shell prompt.
        let prefix = display
            .severity_label
            .as_deref()
            .map_or_else(String::new, |s| format!("[{s}] "));
        let passed = match display.effective_challenge {
            Challenge::Math => {
                let mut rng = rand::rng();
                let a: i64 = rng.random_range(0..10);
                let b: i64 = rng.random_range(0..10);
                self.ask(
                    &format!("{prefix}Solve the challenge: {a} + {b} = ?"),
                    &move |s| s.trim().parse::<i64>().ok() == Some(a + b),
                )
            }
            Challenge::Enter => self.ask(&format!("{prefix}Press Enter to continue"), &|s| {
                s.trim().is_empty()
            }),
            Challenge::Yes => self.ask(&format!("{prefix}Type `yes` to continue"), &|s| {
                s.trim() == "yes"
            }),
        };
        if passed {
            PromptOutcome::Passed
        } else {
            PromptOutcome::Cancelled
        }
    }
}

impl Prompter for WrapPrompter {
    fn run_challenge(&self, display: &DisplayContext) -> ChallengeResult {
        self.last_challenge.set(Some(display.effective_challenge));
        let outcome = self.run(display);
        // Drop leftovers (e.g. the rest of an arrow-key sequence after Esc)
        // so they don't reach the wrapped program as typed text.
        (self.before_read)();
        self.last_outcome.set(Some(outcome));
        *self.statement.borrow_mut() = None;
        match outcome {
            PromptOutcome::Passed => ChallengeResult::Passed,
            PromptOutcome::Cancelled | PromptOutcome::PolicyDenied => ChallengeResult::Denied,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{rc::Rc, sync::Mutex};

    #[derive(Clone, Default)]
    struct Sink(Rc<Mutex<Vec<u8>>>);
    impl Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn prompter(input: &[u8]) -> (WrapPrompter, Sink) {
        let mut bytes = std::collections::VecDeque::from(input.to_vec());
        let sink = Sink::default();
        let p = WrapPrompter::new(
            "psql",
            Box::new(move || bytes.pop_front()),
            Box::new(sink.clone()),
            Box::new(|| {}),
        );
        (p, sink)
    }

    fn display(challenge: Challenge, denied: bool) -> DisplayContext {
        DisplayContext {
            is_denied: denied,
            descriptions: vec!["Dropping a table".into()],
            effective_challenge: challenge,
            ..Default::default()
        }
    }

    #[test]
    fn yes_challenge_passes_after_wrong_answer() {
        let (p, sink) = prompter(b"no\ryes\r");
        p.set_statement("DROP TABLE users");
        assert_eq!(
            p.run_challenge(&display(Challenge::Yes, false)),
            ChallengeResult::Passed
        );
        assert_eq!(p.last_outcome(), Some(PromptOutcome::Passed));
        let out = String::from_utf8_lossy(&sink.0.lock().unwrap()).to_string();
        assert!(out.contains("DROP TABLE users"));
        assert!(out.contains("wrong answer"));
    }

    #[test]
    fn esc_and_ctrl_c_cancel_without_exiting() {
        for input in [&b"\x1b"[..], b"ye\x03", b"\x04", b""] {
            let (p, _) = prompter(input);
            assert_eq!(
                p.run_challenge(&display(Challenge::Yes, false)),
                ChallengeResult::Denied
            );
            assert_eq!(p.last_outcome(), Some(PromptOutcome::Cancelled));
        }
    }

    #[test]
    fn enter_challenge_and_backspace() {
        let (p, sink) = prompter(b"x\x7f\r");
        assert_eq!(
            p.run_challenge(&display(Challenge::Enter, false)),
            ChallengeResult::Passed
        );
        assert_eq!(p.last_challenge(), Some(Challenge::Enter));
        let out = String::from_utf8_lossy(&sink.0.lock().unwrap()).to_string();
        assert!(out.contains("Press Enter to continue"), "{out}");
    }

    #[test]
    fn banner_matches_the_shell_layout() {
        // `Check:` line, `[SEVERITY]` prefix on the prompt,
        // the shell's escalation wording and cancel keys.
        let (p, sink) = prompter(b"\x1b");
        p.set_statement("DROP TABLE users");
        let d = DisplayContext {
            check_ids: vec!["database:drop_table".into()],
            severity_label: Some("CRITICAL".into()),
            escalation_note: Some("Escalated to Yes (from Math): severity CRITICAL".into()),
            ..display(Challenge::Yes, false)
        };
        assert_eq!(p.run_challenge(&d), ChallengeResult::Denied);
        let out = String::from_utf8_lossy(&sink.0.lock().unwrap()).to_string();
        assert!(out.contains("Check: database:drop_table"), "{out}");
        assert!(out.contains("[CRITICAL] Type `yes` to continue"), "{out}");
        assert!(
            out.contains("Esc or Ctrl-C to discard the statement"),
            "{out}"
        );
        assert!(out.contains("Escalated to Yes (from Math)"), "{out}");
        assert!(!out.contains("ESCALATED"), "{out}");
        assert!(
            out.contains("shellfirm config ignore database:drop_table"),
            "{out}"
        );

        // Several checks: one line each, with severity and description.
        let (p, sink) = prompter(b"\x1b");
        let d = DisplayContext {
            check_ids: vec!["psql:drop".into(), "database:drop_table".into()],
            matched: vec![
                crate::prompt::MatchedCheck {
                    id: "psql:drop".into(),
                    severity: "CRITICAL".into(),
                    description: "psql drop".into(),
                },
                crate::prompt::MatchedCheck {
                    id: "database:drop_table".into(),
                    severity: "CRITICAL".into(),
                    description: "drops a table".into(),
                },
            ],
            ..display(Challenge::Math, false)
        };
        assert_eq!(p.run_challenge(&d), ChallengeResult::Denied);
        let out = String::from_utf8_lossy(&sink.0.lock().unwrap()).to_string();
        assert!(
            out.contains("- database:drop_table [CRITICAL]: drops a table"),
            "{out}"
        );
        assert!(!out.contains("Description:"), "{out}");
    }

    #[test]
    fn policy_deny_returns_immediately() {
        let (p, sink) = prompter(b"");
        assert_eq!(
            p.run_challenge(&display(Challenge::Yes, true)),
            ChallengeResult::Denied
        );
        assert_eq!(p.last_outcome(), Some(PromptOutcome::PolicyDenied));
        let out = String::from_utf8_lossy(&sink.0.lock().unwrap()).to_string();
        assert!(out.contains("not allowed"));
    }

    #[test]
    fn personal_deny_says_deny_list_and_hints_only_denied_ids() {
        // A personal deny is not "policy", and the hint must
        // only name the id that is really on the deny list.
        let (p, sink) = prompter(b"");
        let d = DisplayContext {
            check_ids: vec!["psql:drop".into(), "database:drop_database".into()],
            deny_reasons: vec!["`database:drop_database` is on your deny list".into()],
            ..display(Challenge::Yes, true)
        };
        assert_eq!(p.run_challenge(&d), ChallengeResult::Denied);
        let out = String::from_utf8_lossy(&sink.0.lock().unwrap()).to_string();
        assert!(out.contains("is on your deny list"), "{out}");
        assert!(!out.contains("not allowed by policy"), "{out}");
        assert!(
            out.contains("shellfirm config deny --remove database:drop_database"),
            "{out}"
        );
        assert!(!out.contains("--remove psql:drop"), "{out}");
        assert!(!out.contains(".shellfirm.yaml"), "{out}");

        let (p, sink) = prompter(b"");
        let d = DisplayContext {
            deny_reasons: vec![
                "`database:drop_table` is denied by the project policy (.shellfirm.yaml)".into(),
            ],
            ..display(Challenge::Yes, true)
        };
        assert_eq!(p.run_challenge(&d), ChallengeResult::Denied);
        let out = String::from_utf8_lossy(&sink.0.lock().unwrap()).to_string();
        assert!(out.contains("denied by the project policy"), "{out}");
        assert!(!out.contains("deny --remove"), "{out}");
    }
}
