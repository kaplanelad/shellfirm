///! Manage command checks
///
use crate::config::{Challenge, Method};
use rand::Rng;
use rayon::prelude::*;
use regex::Regex;
use serde_derive::Deserialize;
use std::io;

/// Describe single check
#[derive(Debug, Deserialize, Clone)]
pub struct Check {
    pub is: String,
    pub method: Method,
    pub enable: bool,
    pub description: String,
}

impl Check {
    /// Show challenge to the user.
    pub fn show(&self, challenge: &Challenge) -> bool {
        match challenge {
            Challenge::Math => self.prompt_math(),
            Challenge::Enter => self.prompt_enter(),
            Challenge::YesNo => self.prompt_yesno(),
        }
    }

    /// Show prompt text + details of the challenge.
    ///
    /// # Arguments
    ///
    /// * `extra` - String with more text to the prompt question (usually for more detail of how solve the question).
    fn prompt_text(&self, extra: String) -> String {
        format!("{}, {}", self.description, extra)
    }

    /// Show math challenge prompt question to the user. creates random number between 0-10.
    fn prompt_math(&self) -> bool {
        let mut rng = rand::thread_rng();
        let num_a = rng.gen_range(0..10);
        let num_b = rng.gen_range(0..10);
        let expected_answer = num_a + num_b;

        eprintln!("{}", self.prompt_text(format!("{} + {} = ?", num_a, num_b)));
        loop {
            let answer = self.show_stdin_prompt();

            let answer: u32 = match answer.trim().parse() {
                Ok(num) => num,
                Err(_) => continue,
            };
            if answer == expected_answer {
                break;
            }
            eprintln!("wrong answer, try again...");
        }
        true
    }

    /// Show enter challenge to the user.
    fn prompt_enter(&self) -> bool {
        eprintln!("{}", self.prompt_text(format!("Type `Enter` to continue")));

        loop {
            let answer = self.show_stdin_prompt();
            if answer == "\n" {
                break;
            }
            eprintln!("wrong answer, try again...");
        }
        true
    }

    /// Show enter yes/no challenge to the user.
    fn prompt_yesno(&self) -> bool {
        eprintln!(
            "{}",
            self.prompt_text(format!("Type `yes` to continue `no` to cancel"))
        );
        let mut is_approve = true;

        loop {
            let answer = self.show_stdin_prompt();
            let answer = answer.trim();
            if answer == "yes" {
                break;
            } else if answer == "no" {
                is_approve = false;
                break;
            }
            eprintln!("wrong answer, try again...");
        }
        is_approve
    }

    /// Catch user stdin.
    fn show_stdin_prompt(&self) -> String {
        let mut answer = String::new();
        io::stdin()
            .read_line(&mut answer)
            .expect("Failed to read line");

        answer
    }
}

/// Check if the given command matched to on of the checks
///
/// # Arguments
///
/// * `checks` - List of checks that we want to validate.
/// * `command` - Command check.
pub fn run_check_on_command(checks: &[Check], command: &str) -> Vec<Check> {
    checks
        .par_iter()
        .filter(|&v| v.enable)
        .filter(|&v| is_match(v, command))
        .map(|v| v.clone())
        .collect()
}

/// returns true/false if the check match to the given command
fn is_match(check: &Check, command: &str) -> bool {
    match check.method {
        Method::Contains => is_contains(&check.is, command),
        Method::StartWith => is_start_with(&check.is, command),
        Method::Regex => is_regex(&check.is, command),
    }
}

// Checks if the given check contains the command.
fn is_contains(check: &str, command: &str) -> bool {
    command.contains(check)
}

// Checks if the given check start with the command.
fn is_start_with(check: &str, command: &str) -> bool {
    command.starts_with(check)
}

// Checks if the given check match to the command using regex.
fn is_regex(r: &str, command: &str) -> bool {
    // let search_regex = format!("r\"{}\"", r);
    Regex::new(r).unwrap().is_match(command)
}
