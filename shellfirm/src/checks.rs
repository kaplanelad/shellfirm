//! Manage command checks

///
use crate::config::{Challenge, Method};
use crate::prompt;
use anyhow::Result;
use console::style;
use log::debug;
use rayon::prelude::*;
use regex::Regex;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;

// list of custom filter
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
pub enum FilterType {
    IsFileExists,
}

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
    #[serde(default)]
    pub filters: HashMap<FilterType, String>,
}

/// prompt a challenge to the user
///
/// # Errors
///
/// Will return `Err` when could not convert checks to yaml
pub fn challenge(challenge: &Challenge, checks: &[Check], dryrun: bool) -> Result<bool> {
    if dryrun {
        eprintln!("{}", serde_yaml::to_string(checks)?);
        return Ok(true);
    }
    eprintln!("{}", style("#######################").yellow().bold());
    eprintln!("{}", style("# RISKY COMMAND FOUND #").yellow().bold());
    eprintln!("{}", style("#######################").yellow().bold());

    let mut descriptions: Vec<String> = Vec::new();
    for check in checks {
        if !descriptions.contains(&check.description) {
            descriptions.push(check.description.to_string());
        }
    }
    for description in descriptions {
        eprintln!("* {}", description);
    }
    eprintln!();

    let show_challenge = challenge;

    Ok(match show_challenge {
        Challenge::Math | Challenge::Default => prompt::math_challenge(),
        Challenge::Enter => prompt::enter_challenge(),
        Challenge::Yes => prompt::yes_challenge(),
    })
}

/// Check if the given command matched to on of the checks
///
/// # Arguments
///
/// * `checks` - List of checks that we want to validate.
/// * `command` - Command check.
#[must_use]
pub fn run_check_on_command(checks: &[Check], command: &str) -> Vec<Check> {
    checks
        .par_iter()
        .filter(|&v| v.enable)
        .filter(|&v| is_match(v, command))
        .filter(|&v| check_custom_filter(v, command))
        .map(std::clone::Clone::clone)
        .collect()
}

/// filter custom checks
///
/// When true is returned it mean the filter should keep the check and not filter our the check.
///
/// # Arguments
///
/// * `check` - Check struct
/// * `command` - Command.
fn check_custom_filter(check: &Check, command: &str) -> bool {
    // if check is not regex type or custom filters are not configure return true.
    if check.method != Method::Regex || check.filters.is_empty() {
        return true;
    }
    // Capture command groups from the current check
    let caps = Regex::new(&check.test).unwrap().captures(command).unwrap();

    // by default true is return. it mean the check not filter out (safe side security).
    let mut keep_check = true;
    for (filter_type, filter_params) in &check.filters {
        debug!(
            "filter information: command {} include filter: {:?} filter_params: {}",
            command, filter_type, filter_params
        );

        let keep_filter = match filter_type {
            FilterType::IsFileExists => filter_is_file_exists(
                caps.get(filter_params.parse().unwrap())
                    .map_or("", |m| m.as_str()),
            ),
        };

        if !keep_filter {
            keep_check = false;
            break;
        }
    }

    keep_check
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

/// check if the path exists (file and folder).
///
/// # Arguments
///
/// * `file_path` - check path.
fn filter_is_file_exists(file_path: &str) -> bool {
    let mut file_path: String = file_path.trim().into();
    if file_path.starts_with('~') {
        match dirs::home_dir() {
            Some(path) => {
                file_path = file_path.replace('~', &path.display().to_string());
            }
            None => return true,
        };
    }
    debug!("check is file {} exists", file_path);
    return std::path::Path::new(file_path.trim()).exists();
}

#[cfg(test)]
mod test_checks {
    use super::*;
    use insta::assert_debug_snapshot;

    #[test]
    fn is_match_command() {
        let regex_check = Check {
            test: String::from("rm.+(-r|-f|-rf|-fr)*"),
            method: Method::Regex,
            enable: true,
            description: String::from(""),
            from: String::from(""),
            challenge: Challenge::Default,
            filters: HashMap::new(),
        };
        let contains_check = Check {
            test: String::from("test"),
            method: Method::Contains,
            enable: true,
            description: String::from(""),
            from: String::from(""),
            challenge: Challenge::Default,
            filters: HashMap::new(),
        };
        let startwith_check = Check {
            test: String::from("start"),
            method: Method::StartWith,
            enable: true,
            description: String::from(""),
            from: String::from(""),
            challenge: Challenge::Default,
            filters: HashMap::new(),
        };
        assert_debug_snapshot!(&regex_check);
        assert_debug_snapshot!(&contains_check);
        assert_debug_snapshot!(&startwith_check);
    }
    #[test]
    fn can_check_is_contains() {
        assert_debug_snapshot!(is_contains("test", "test is valid"));
        assert_debug_snapshot!(is_contains("test is valid", "not-found"));
    }

    #[test]
    fn can_check_is_start_with() {
        assert_debug_snapshot!(is_start_with("test is", "test is valid"));
        assert_debug_snapshot!(is_start_with("test is valid", "is"));
    }

    #[test]
    fn can_check_is_regex_match() {
        assert_debug_snapshot!(is_regex("rm.+(-r|-f|-rf|-fr)*", "rm -rf"));
        assert_debug_snapshot!(is_regex("^f", "rm -rf"));
    }
}
