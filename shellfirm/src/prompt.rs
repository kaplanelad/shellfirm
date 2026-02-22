//! Challenge prompts and the [`Prompter`] trait for testability.

use std::{cell::RefCell, io, thread, time::Duration};

use console::style;
use rand::RngExt;

use crate::config::Challenge;

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
const CANCEL_PROMPT_TEXT: &str = "^C to cancel";

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
// TerminalPrompter (real implementation)
// ---------------------------------------------------------------------------

/// Production prompter — reads from stdin, writes to stderr.
pub struct TerminalPrompter;

impl Prompter for TerminalPrompter {
    fn run_challenge(&self, display: &DisplayContext) -> ChallengeResult {
        // Banner
        if display.is_denied {
            eprintln!("{}", style("##################").red().bold());
            eprintln!("{}", style("# COMMAND DENIED #").red().bold());
            eprintln!("{}", style("##################").red().bold());
        } else {
            eprintln!("{}", style("#######################").yellow().bold());
            eprintln!("{}", style("# RISKY COMMAND FOUND #").yellow().bold());
            eprintln!("{}", style("#######################").yellow().bold());
        }

        // Severity label
        if let Some(ref sev) = display.severity_label {
            eprintln!("{}", style(format!("  Severity: [{sev}]")).red().bold());
        }

        // Blast radius
        if let Some(ref br) = display.blast_radius_label {
            eprintln!(
                "  {} {}",
                style("Blast radius:").red().bold(),
                style(br).dim()
            );
        }

        // Context labels
        if !display.context_labels.is_empty() {
            let labels = display.context_labels.join(", ");
            eprintln!("{}", style(format!("  Context: {labels}")).cyan().bold());
        }

        // Descriptions
        for desc in &display.descriptions {
            eprintln!("* {desc}");
        }

        // Alternatives
        for alt in &display.alternatives {
            eprintln!();
            eprintln!(
                "  {} {}",
                style("Safer alternative:").green().bold(),
                alt.suggestion
            );
            if let Some(ref info) = alt.explanation {
                eprintln!("  {}", style(format!("({info})")).dim());
            }
        }

        // Escalation note
        if let Some(ref note) = display.escalation_note {
            eprintln!();
            eprintln!(
                "  {}",
                style(format!("Challenge ESCALATED: {note}"))
                    .magenta()
                    .bold()
            );
        }

        eprintln!();

        // Deny
        if display.is_denied {
            eprintln!("{} type {}", DENIED_TEXT, get_cancel_string());
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
// Challenge implementations (used by TerminalPrompter)
// ---------------------------------------------------------------------------

/// Show math challenge to the user.
#[must_use]
fn math_challenge() -> bool {
    let mut rng = rand::rng();
    let num_a = rng.random_range(0..10);
    let num_b = rng.random_range(0..10);
    let expected_answer = num_a + num_b;

    eprintln!(
        "{}: {} + {} = ? {}",
        SOLVE_MATH_TEXT,
        num_a,
        num_b,
        get_cancel_string()
    );
    loop {
        let answer = show_stdin_prompt();

        let answer: u32 = match answer.trim().parse() {
            Ok(num) => num,
            Err(_) => continue,
        };
        if answer == expected_answer {
            break;
        }
        eprintln!("{WRONG_ANSWER}");
    }
    true
}

/// Show enter challenge to the user.
#[must_use]
fn enter_challenge() -> bool {
    eprintln!("{} {}", SOLVE_ENTER_TEXT, get_cancel_string());
    loop {
        let answer = show_stdin_prompt();
        if answer == "\n" {
            break;
        }
        eprintln!("{WRONG_ANSWER}");
    }
    true
}

/// Show yes challenge to the user.
#[must_use]
fn yes_challenge() -> bool {
    eprintln!("{} {}", SOLVE_YES_TEXT, get_cancel_string());
    loop {
        if show_stdin_prompt().trim() == "yes" {
            break;
        }
        eprintln!("{WRONG_ANSWER}");
    }
    true
}

/// Catch user stdin and return the user's input.
/// If stdin is closed or unreadable, exits gracefully instead of panicking.
fn show_stdin_prompt() -> String {
    let mut answer = String::new();
    match io::stdin().read_line(&mut answer) {
        Ok(_) => answer,
        Err(_) => {
            // stdin closed or error — treat as cancellation and exit gracefully
            std::process::exit(exitcode::OK);
        }
    }
}

/// return cancel string with colorize format
fn get_cancel_string() -> String {
    format!("{}", style(CANCEL_PROMPT_TEXT).underlined().bold().italic())
}

// ---------------------------------------------------------------------------
// Interactive selection helpers (requestty-based)
// ---------------------------------------------------------------------------

/// Prompt the user to confirm or cancel a configuration reset.
///
/// # Errors
///
/// Will return `Err` when the interactive prompt fails.
pub fn reset_config() -> anyhow::Result<usize> {
    let answer = requestty::prompt_one(
        requestty::Question::raw_select("reset")
            .message("Rest configuration will reset all checks settings. Select how to continue...")
            .choices(vec![
                "Yes, i want to override the current configuration".into(),
                "Override and backup the existing file".into(),
                requestty::DefaultSeparator,
                "Cancel Or ^C".into(),
            ])
            .build(),
    )?;
    match answer.as_list_item() {
        Some(a) => Ok(a.index),
        _ => anyhow::bail!("select option is empty"),
    }
}

/// Present a select prompt and return the chosen index.
///
/// # Errors
///
/// Will return `Err` when the interactive prompt fails.
pub fn select_with_default(message: &str, items: &[&str], default: usize) -> anyhow::Result<usize> {
    let question = requestty::Question::select("select")
        .message(message)
        .choices(items.iter().copied())
        .default(default)
        .build();
    let answer = requestty::prompt_one(question)?;
    match answer.as_list_item() {
        Some(a) => Ok(a.index),
        _ => anyhow::bail!("select option is empty"),
    }
}
