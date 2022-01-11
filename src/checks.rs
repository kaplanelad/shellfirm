//! Manage command checks

///
use crate::config::{Challenge, Method};
use crate::prompt;
use colored::Colorize;
use rayon::prelude::*;
use regex::Regex;
use serde_derive::{Deserialize, Serialize};

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
    #[serde(default)]
    pub challenge: Challenge,
}

pub fn challenge(challenge: &Challenge, checks: &[Check], dryrun: bool) -> bool {
    if dryrun {
        eprintln!("{}", serde_yaml::to_string(checks).unwrap());
        return true;
    }
    eprintln!("{}", "#######################".yellow().bold());
    eprintln!("{}", "# RISKY COMMAND FOUND #".yellow().bold());
    eprintln!("{}", "#######################".yellow().bold());

    for check in checks {
        eprintln!("* {}", check.description)
    }

    let show_challenge = challenge;

    match show_challenge {
        Challenge::Default => prompt::math_challenge(),
        Challenge::Math => prompt::math_challenge(),
        Challenge::Enter => prompt::enter_challenge(),
        Challenge::Yes => prompt::yes_challenge(),
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
            challenge: Challenge::Default,
        };
        let contains_check = Check {
            test: String::from("test"),
            method: Method::Contains,
            enable: true,
            description: String::from(""),
            from: String::from(""),
            challenge: Challenge::Default,
        };
        let startwith_check = Check {
            test: String::from("start"),
            method: Method::StartWith,
            enable: true,
            description: String::from(""),
            from: String::from(""),
            challenge: Challenge::Default,
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
}
