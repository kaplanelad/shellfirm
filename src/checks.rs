///! Manage command checks
///
use crate::config::Method;
use rayon::prelude::*;
use regex::Regex;
use serde_derive::Deserialize;

/// Describe single check
#[derive(Debug, Deserialize, Clone)]
pub struct Check {
    pub is: String,
    pub method: Method,
    pub enable: bool,
    pub description: String,
}

impl Check {
    pub fn show(&self) {
        println!("show")
    }
}

/// Check if the given command matched to on of the checks
///
/// # Arguments
///
/// * `checks` - List of checks that we want to validate.
/// * `command` - Command check.
pub fn run_check_on_command(checks: &Vec<Check>, command: &str) -> Vec<Check> {
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
