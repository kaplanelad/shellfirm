//! Manage command checks

use std::collections::HashMap;

use anyhow::Result;
use console::style;
use log::debug;
use rayon::prelude::*;
use regex::Regex;
use serde_derive::{Deserialize, Serialize};

use crate::{
    config::{Challenge, Method},
    prompt,
};

/// String with all checks from `checks` folder (prepared in build.rs) in YAML
/// format.
const ALL_CHECKS: &str = include_str!(concat!(env!("OUT_DIR"), "/all-checks.yaml"));

// list of custom filter
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
pub enum FilterType {
    IsFileExists,
}

/// Describe single check
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Check {
    pub id: String,
    /// test ia a value that we check the command.
    pub test: String,
    /// The type of the check.
    pub method: Method,
    /// description of what is risky in this command
    pub description: String,
    /// the group of the check see files in `checks` folder
    pub from: String,
    #[serde(default)]
    pub challenge: Challenge,
    #[serde(default)]
    pub filters: HashMap<FilterType, String>,
}

pub fn get_all_checks() -> Result<Vec<Check>> {
    Ok(serde_yaml::from_str(ALL_CHECKS)?)
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
        .filter(|&v| is_match(v, command))
        .filter(|&v| check_custom_filter(v, command))
        .map(std::clone::Clone::clone)
        .collect()
}

/// filter custom checks
///
/// When true is returned it mean the filter should keep the check and not
/// filter our the check.
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

    // by default true is return. it mean the check not filter out (safe side
    // security).
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
    use std::fs;

    use insta::assert_debug_snapshot;
    use tempdir::TempDir;

    use super::*;

    const CHECKS: &str = r###"
- from: test-1
  test: test-(1)
  method: Regex
  enable: true
  description: ""
  id: ""
- from: test-2
  test: test-(1|2)
  method: Regex
  enable: true
  description: ""
  id: ""
- from: test-disabled
  test: test-disabled
  method: Regex
  enable: true
  description: ""
  id: ""
"###;

    #[test]
    fn is_match_command() {
        let regex_check = Check {
            id: "id".to_string(),
            test: String::from("rm.+(-r|-f|-rf|-fr)*"),
            method: Method::Regex,
            description: String::from(""),
            from: String::from(""),
            challenge: Challenge::Default,
            filters: HashMap::new(),
        };
        let contains_check = Check {
            id: "id".to_string(),
            test: String::from("test"),
            method: Method::Contains,
            description: String::from(""),
            from: String::from(""),
            challenge: Challenge::Default,
            filters: HashMap::new(),
        };
        let startwith_check = Check {
            id: "id".to_string(),
            test: String::from("start"),
            method: Method::StartWith,
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
    fn can_is_match_contains() {
        let check = Check {
            id: "id".to_string(),
            test: String::from("test"),
            method: Method::Contains,
            description: String::from(""),
            from: String::from(""),
            challenge: Challenge::Default,
            filters: HashMap::new(),
        };

        assert_debug_snapshot!(is_match(&check, "test is valid"));
        assert_debug_snapshot!(is_match(&check, "not-found"));
    }

    #[test]
    fn can_is_match_start_with() {
        let check = Check {
            id: "id".to_string(),
            test: String::from("test"),
            method: Method::StartWith,
            description: String::from(""),
            from: String::from(""),
            challenge: Challenge::Default,
            filters: HashMap::new(),
        };
        assert_debug_snapshot!(is_match(&check, "test is valid"));
        assert_debug_snapshot!(is_match(&check, "1test not valid"));
    }

    #[test]
    fn can_check_is_regex_match() {
        let check = Check {
            id: "id".to_string(),
            test: String::from(r#"rm\s*(-r|-fr|-rf)\s*(\*)"#),
            method: Method::Regex,
            description: String::from(""),
            from: String::from(""),
            challenge: Challenge::Default,
            filters: HashMap::new(),
        };
        assert_debug_snapshot!(is_match(&check, "rm -rf *"));
        assert_debug_snapshot!(is_match(&check, "rm -rf /test"));
    }

    #[test]
    fn can_run_check_on_command() {
        let checks: Vec<Check> = serde_yaml::from_str(CHECKS).unwrap();
        assert_debug_snapshot!(run_check_on_command(&checks, "test-1"));
        assert_debug_snapshot!(run_check_on_command(&checks, "unknown command"));
    }

    #[test]
    fn can_check_custom_filter() {
        let mut filters: HashMap<FilterType, String> = HashMap::new();
        filters.insert(FilterType::IsFileExists, "1".to_string());

        let check = Check {
            id: "id".to_string(),
            test: ".*>(.*)".to_string(),
            method: Method::Regex,
            description: "some description".to_string(),
            from: "test".to_string(),
            challenge: Challenge::Default,
            filters,
        };

        let temp_dir = TempDir::new("config-app").unwrap();
        let app_path = temp_dir.path().join("app");
        fs::create_dir_all(&app_path).unwrap();
        let message_file = app_path.join("message.txt");

        let command = format!("cat 'write message' > {}", message_file.display());
        assert_debug_snapshot!(check_custom_filter(&check, command.as_ref()));
        std::fs::File::create(message_file).unwrap();
        assert_debug_snapshot!(check_custom_filter(&check, command.as_ref()));
    }
}
