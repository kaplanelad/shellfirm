//! Challenge prompts and the [`Prompter`] trait for testability.

use std::{cell::RefCell, thread, time::Duration};

use console::style;
use rand::RngExt;

use crate::config::Challenge;
#[cfg(unix)]
use nix::sys::termios::{self, LocalFlags, SetArg};

/// wrong answer text show when user solve the challenge incorrectly
const WRONG_ANSWER: &str = "wrong answer, try again...";
/// show math challenge text
const SOLVE_MATH_TEXT: &str = "Solve the challenge:";
/// show enter challenge text
const SOLVE_ENTER_TEXT: &str = "Type `Enter` to continue";
/// show yes challenge text
const SOLVE_YES_TEXT: &str = "Type `yes` to continue";
/// show denied text
const DENIED_TEXT: &str = "The command is not allowed.";
/// show to the user how can he cancel the command
const CANCEL_PROMPT_TEXT: &str = "Esc to cancel";

// ---------------------------------------------------------------------------
// ChallengeResult + DisplayContext
// ---------------------------------------------------------------------------

/// The outcome of a challenge prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeResult {
    /// User solved the challenge — command proceeds.
    Passed,
    /// Command was denied — blocks forever in real impl.
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
    pub escalation_note: Option<String>,
    /// The highest severity among the matched checks.
    pub severity_label: Option<String>,
    /// Blast radius label, e.g. `[PROJECT] — Deletes 347 files (12.4 MB) in ./src`.
    pub blast_radius_label: Option<String>,
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
}

// ---------------------------------------------------------------------------
// Shared banner display
// ---------------------------------------------------------------------------

/// Print the warning banner to stderr.
///
/// Shared by all interactive prompter implementations.
fn display_banner(display: &DisplayContext) {
    // Move to a new line and clear everything below the cursor.
    // This erases leftover terminal artifacts (e.g., fzf inline display)
    // so the challenge renders cleanly.
    eprint!("\n\x1b[J");

    // Banner
    let separator = "=".repeat(12);
    if display.is_denied {
        eprintln!(
            "{}",
            style(format!("{separator} COMMAND DENIED {separator}"))
                .red()
                .bold()
        );
    } else {
        eprintln!(
            "{}",
            style(format!("{separator} RISKY COMMAND DETECTED {separator}"))
                .red()
                .bold()
        );
    }

    // Severity label
    if let Some(ref sev) = display.severity_label {
        eprintln!("{} {}", style("Severity:").red().bold(), style(sev).red());
    }

    // Blast radius
    if let Some(ref br) = display.blast_radius_label {
        eprintln!(
            "{} {}",
            style("Blast radius:").red().bold(),
            style(br).dim()
        );
    }

    // Context labels
    if !display.context_labels.is_empty() {
        let labels = display.context_labels.join(", ");
        eprintln!(
            "{} {}",
            style("Context:").cyan().bold(),
            style(labels).cyan()
        );
    }

    // Descriptions
    for desc in &display.descriptions {
        eprintln!("{} {desc}", style("Description:").white().bold());
    }

    // Alternatives
    for alt in &display.alternatives {
        eprintln!(
            "{} {}",
            style("Alternative:").green().bold(),
            alt.suggestion
        );
        if let Some(ref info) = alt.explanation {
            eprintln!("  {}", style(format!("({info})")).dim());
        }
    }

    // Escalation note
    if let Some(ref note) = display.escalation_note {
        eprintln!(
            "{}",
            style(format!("Challenge ESCALATED: {note}"))
                .magenta()
                .bold()
        );
    }

    eprintln!();
}

// ---------------------------------------------------------------------------
// TerminalPrompter (real implementation)
// ---------------------------------------------------------------------------

/// Production prompter — reads from stdin, writes to stderr.
pub struct TerminalPrompter;

impl Prompter for TerminalPrompter {
    fn run_challenge(&self, display: &DisplayContext) -> ChallengeResult {
        display_banner(display);

        // Deny
        if display.is_denied {
            eprintln!(
                "{DENIED_TEXT} {}",
                style("Press ^C to exit.").underlined().bold().italic()
            );
            loop {
                thread::sleep(Duration::from_secs(60));
            }
        }

        // Challenge
        match display.effective_challenge {
            Challenge::Math => {
                let _ = math_challenge();
            }
            Challenge::Enter => {
                let _ = enter_challenge();
            }
            Challenge::Yes => {
                let _ = yes_challenge();
            }
        }
        ChallengeResult::Passed
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

impl Prompter for MockPrompter {
    fn run_challenge(&self, display: &DisplayContext) -> ChallengeResult {
        self.captured_displays.borrow_mut().push(display.clone());
        if display.is_denied {
            return ChallengeResult::Denied;
        }
        self.response
    }
}

// ---------------------------------------------------------------------------
// DirectTtyPrompter — fallback when stdin is not a terminal
// ---------------------------------------------------------------------------

/// Prompter that reads directly from `/dev/tty` using line-buffered I/O.
///
/// Used when stdin is not a terminal (e.g., inside zsh zle widgets on macOS).
/// This bypasses crossterm's event system entirely — crossterm uses
/// `select(2)`/`poll(2)` on `/dev/tty` which hangs in certain shell contexts.
/// Simple cooked-mode `read_line()` works where crossterm's raw-mode event
/// loop does not.
///
/// See: <https://github.com/kaplanelad/shellfirm/issues/160>
#[cfg(unix)]
pub struct DirectTtyPrompter;

#[cfg(unix)]
impl Prompter for DirectTtyPrompter {
    fn run_challenge(&self, display: &DisplayContext) -> ChallengeResult {
        display_banner(display);

        // Deny
        if display.is_denied {
            eprintln!(
                "{DENIED_TEXT} {}",
                style("Press ^C to exit.").underlined().bold().italic()
            );
            loop {
                thread::sleep(Duration::from_secs(60));
            }
        }

        // Open /dev/tty for reading — bypasses crossterm entirely.
        let Ok(tty) = std::fs::OpenOptions::new().read(true).open("/dev/tty") else {
            std::process::exit(exitcode::DATAERR);
        };

        // Ensure ECHO and ICANON are enabled on /dev/tty.
        // Inside zsh zle widgets, the terminal may have ECHO disabled,
        // causing typed text to be invisible (like password input).
        let original = termios::tcgetattr(&tty)
            .inspect_err(|e| tracing::debug!("tcgetattr failed: {e}"))
            .ok();

        if let Some(ref orig) = original {
            let mut attrs = orig.clone();
            attrs.local_flags |= LocalFlags::ECHO | LocalFlags::ICANON;
            if let Err(e) = termios::tcsetattr(&tty, SetArg::TCSANOW, &attrs) {
                tracing::debug!("tcsetattr failed: {e}");
            }
        }

        let mut reader = std::io::BufReader::new(tty);

        let passed = match display.effective_challenge {
            Challenge::Math => direct_math_challenge(&mut reader),
            Challenge::Enter => direct_enter_challenge(&mut reader),
            Challenge::Yes => direct_yes_challenge(&mut reader),
        };

        // Restore original terminal attributes.
        if let Some(ref orig) = original {
            let tty = reader.get_ref();
            if let Err(e) = termios::tcsetattr(tty, SetArg::TCSANOW, orig) {
                tracing::debug!("tcsetattr restore failed: {e}");
            }
        }

        if passed {
            ChallengeResult::Passed
        } else {
            std::process::exit(exitcode::DATAERR)
        }
    }
}

// ---------------------------------------------------------------------------
// Challenge implementations (used by TerminalPrompter)
// ---------------------------------------------------------------------------

/// Show math challenge to the user.
fn math_challenge() -> bool {
    let mut rng = rand::rng();
    let num_a = rng.random_range(0..10);
    let num_b = rng.random_range(0..10);
    let expected: i64 = (num_a + num_b).into();

    let cancel = format!("{}", style(CANCEL_PROMPT_TEXT).underlined().bold().italic());
    let question = requestty::Question::int("math")
        .message(format!("{SOLVE_MATH_TEXT}: {num_a} + {num_b} = ? {cancel}"))
        .on_esc(requestty::OnEsc::Terminate)
        .validate(move |n, _| {
            if n == expected {
                Ok(())
            } else {
                Err(WRONG_ANSWER.to_owned())
            }
        })
        .build();

    match requestty::prompt_one(question) {
        Ok(_) => true,
        Err(_) => std::process::exit(exitcode::DATAERR),
    }
}

/// Show enter challenge to the user.
fn enter_challenge() -> bool {
    let cancel = format!("{}", style(CANCEL_PROMPT_TEXT).underlined().bold().italic());
    let question = requestty::Question::input("enter")
        .message(format!("{SOLVE_ENTER_TEXT} {cancel}"))
        .on_esc(requestty::OnEsc::Terminate)
        .validate(|answer, _| {
            if answer.is_empty() {
                Ok(())
            } else {
                Err(WRONG_ANSWER.to_owned())
            }
        })
        .build();

    match requestty::prompt_one(question) {
        Ok(_) => true,
        Err(_) => std::process::exit(exitcode::DATAERR),
    }
}

/// Show yes challenge to the user.
fn yes_challenge() -> bool {
    let cancel = format!("{}", style(CANCEL_PROMPT_TEXT).underlined().bold().italic());
    let question = requestty::Question::input("yes")
        .message(format!("{SOLVE_YES_TEXT} {cancel}"))
        .on_esc(requestty::OnEsc::Terminate)
        .validate(|answer, _| {
            if answer.trim() == "yes" {
                Ok(())
            } else {
                Err(WRONG_ANSWER.to_owned())
            }
        })
        .build();

    match requestty::prompt_one(question) {
        Ok(_) => true,
        Err(_) => std::process::exit(exitcode::DATAERR),
    }
}

// ---------------------------------------------------------------------------
// Direct-tty challenge implementations (used by DirectTtyPrompter)
// ---------------------------------------------------------------------------

/// Read one line from a buffered reader, returning `None` on EOF or error.
#[cfg(unix)]
fn read_tty_line(reader: &mut impl std::io::BufRead) -> Option<String> {
    let mut line = String::new();
    match reader.read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line),
    }
}

/// Math challenge via direct `/dev/tty` I/O.
#[cfg(unix)]
fn direct_math_challenge(reader: &mut impl std::io::BufRead) -> bool {
    let mut rng = rand::rng();
    let num_a = rng.random_range(0..10);
    let num_b = rng.random_range(0..10);
    let expected: i64 = (num_a + num_b).into();

    loop {
        eprint!("{SOLVE_MATH_TEXT} {num_a} + {num_b} = ? (^C to cancel) ");
        let _ = std::io::Write::flush(&mut std::io::stderr());

        let Some(line) = read_tty_line(reader) else {
            return false;
        };

        match line.trim().parse::<i64>() {
            Ok(n) if n == expected => return true,
            _ => eprintln!("{WRONG_ANSWER}"),
        }
    }
}

/// Enter challenge via direct `/dev/tty` I/O.
#[cfg(unix)]
fn direct_enter_challenge(reader: &mut impl std::io::BufRead) -> bool {
    loop {
        eprint!("{SOLVE_ENTER_TEXT} (^C to cancel) ");
        let _ = std::io::Write::flush(&mut std::io::stderr());

        let Some(line) = read_tty_line(reader) else {
            return false;
        };

        if line.trim().is_empty() {
            return true;
        }
        eprintln!("{WRONG_ANSWER}");
    }
}

/// Yes challenge via direct `/dev/tty` I/O.
#[cfg(unix)]
fn direct_yes_challenge(reader: &mut impl std::io::BufRead) -> bool {
    loop {
        eprint!("{SOLVE_YES_TEXT} (^C to cancel) ");
        let _ = std::io::Write::flush(&mut std::io::stderr());

        let Some(line) = read_tty_line(reader) else {
            return false;
        };

        if line.trim() == "yes" {
            return true;
        }
        eprintln!("{WRONG_ANSWER}");
    }
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
