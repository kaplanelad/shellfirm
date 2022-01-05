//! Manage command checks
///
use crate::config::{Challenge, Method};
use colored::Colorize;
use rand::Rng;
use rayon::prelude::*;
use regex::Regex;
use serde_derive::{Deserialize, Serialize};
use std::io;

/// Describe single check
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Check {
    /// test ia a value that we check the command.
    pub test: String,
    /// The type of the check.
    pub method: Method,
    /// boolean for ignore check
    pub enable: bool,
    /// description of what is risky in this command
    pub description: String,
    /// the group of the check see files in `checks` folder
    pub from: String,
}

impl Check {
    /// Return current check struct as yaml format.
    pub fn to_yaml(&self) -> Result<String, serde_yaml::Error> {
        serde_yaml::to_string(self)
    }

    /// Show prompt challenge text to the user.
    ///
    /// # Arguments
    ///
    /// * `challenge` - type of the challenge
    /// * `dry_run` - if true the check will print to stderr.
    pub fn show(&self, challenge: &Challenge, dry_run: bool) -> bool {
        if dry_run {
            eprintln!("{}", self.to_yaml().unwrap());
            return true;
        }
        match challenge {
            Challenge::Math => self.prompt_math(),
            Challenge::Enter => self.prompt_enter(),
            Challenge::Yes => self.prompt_yes(),
        }
    }

    /// Show prompt text + details of the challenge.
    ///
    /// # Arguments
    ///
    /// * `extra` - String with more text to the prompt question (usually for more detail of how solve the question).
    fn prompt_text(&self, extra: String) {
        eprintln!("{}", "#######################".yellow().bold());
        eprintln!("{}", "# RISKY COMMAND FOUND #".yellow().bold());
        eprintln!("{}", "#######################".yellow().bold());

        eprintln!(
            "* {}\n {} ({})",
            self.description.underline(),
            extra,
            "^C to cancel".underline().bold().italic()
        )
    }

    /// Show math challenge prompt question to the user. creates random number between 0-10.
    fn prompt_math(&self) -> bool {
        let mut rng = rand::thread_rng();
        let num_a = rng.gen_range(0..10);
        let num_b = rng.gen_range(0..10);
        let expected_answer = num_a + num_b;

        self.prompt_text(format!(
            "\nSolve the challenge: {} + {} = ?",
            num_a.to_string(),
            num_b.to_string()
        ));
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
        self.prompt_text("\nType `Enter` to continue".to_string());

        loop {
            let answer = self.show_stdin_prompt();
            if answer == "\n" {
                break;
            }
            eprintln!("wrong answer, try again...");
        }
        true
    }

    /// Show yes challenge to the user.
    fn prompt_yes(&self) -> bool {
        self.prompt_text("\nType `yes` to continue".to_string());

        loop {
            if self.show_stdin_prompt().trim() == "yes" {
                break;
            }
            eprintln!("wrong answer, try again...");
        }
        true
    }

    /// Catch user stdin. and return the user type
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

/// Check if the given command match to one of the existing checks
///
/// # Arguments
///
/// * `check` - Check struct
/// * `command` - command for the check
fn is_match(check: &Check, command: &str) -> bool {
    match check.method {
        Method::Contains => is_contains(&check.test, command),
        Method::StartWith => is_start_with(&check.test, command),
        Method::Regex => is_regex(&check.test, command),
    }
}

/// Is the command contains the given check.
///
/// # Arguments
///
/// * `test` - check value
/// * `command` - command value
fn is_contains(test: &str, command: &str) -> bool {
    command.contains(test)
}

/// is the command start with the given check.
///
/// # Arguments
///
/// * `test` - check value
/// * `command` - command value
fn is_start_with(test: &str, command: &str) -> bool {
    command.starts_with(test)
}

/// Is the command match to the given regex.
///
/// # Arguments
///
/// * `test_r` - check value
/// * `command` - command value
fn is_regex(test_r: &str, command: &str) -> bool {
    Regex::new(test_r).unwrap().is_match(command)
}

#[cfg(test)]
mod checks {
    use super::*;

    #[test]
    fn is_match_command() {
        let regex_check = Check {
            test: String::from("rm.+(-r|-f|-rf|-fr)*"),
            method: Method::Regex,
            enable: true,
            description: String::from(""),
            from: String::from(""),
        };
        let contains_check = Check {
            test: String::from("test"),
            method: Method::Contains,
            enable: true,
            description: String::from(""),
            from: String::from(""),
        };
        let startwith_check = Check {
            test: String::from("start"),
            method: Method::StartWith,
            enable: true,
            description: String::from(""),
            from: String::from(""),
        };
        assert!(is_match(&regex_check, "rm -rf"));
        assert!(is_match(&contains_check, "test command"));
        assert!(is_match(&startwith_check, "start command"));
    }
    #[test]
    fn can_check_is_contains() {
        assert!(is_contains("test", "test is valid"));
        assert!(!is_contains("test is valid", "not-found"));
    }

    #[test]
    fn can_check_is_start_with() {
        assert!(is_start_with("test is", "test is valid"));
        assert!(!is_start_with("test is valid", "is"));
    }

    #[test]
    fn can_check_is_regex_match() {
        assert!(is_regex("rm.+(-r|-f|-rf|-fr)*", "rm -rf"));
        assert!(!is_regex("^f", "rm -rf"));
    }

    #[test]
    fn can_convert_check_to_yaml() {
        let check = Check {
            test: String::from("start"),
            method: Method::StartWith,
            enable: true,
            description: String::from("desc"),
            from: String::from(""),
        };
        assert_eq!(
            check.to_yaml().unwrap(),
            "---\ntest: start\nmethod: StartWith\nenable: true\ndescription: desc\nfrom: \"\"\n"
        );
    }
}
