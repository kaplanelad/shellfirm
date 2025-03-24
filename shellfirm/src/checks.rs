//! Manage command checks

use std::{collections::HashMap, env};

use anyhow::Result;
use console::style;
use log::debug;
use rayon::prelude::*;
use regex::Regex;
use serde_derive::{Deserialize, Serialize};
use serde_regex;

use crate::{config::Challenge, prompt};

/// String with all checks from `checks` folder (prepared in build.rs) in YAML
/// format.
const ALL_CHECKS: &str = include_str!(concat!(env!("OUT_DIR"), "/all-checks.yaml"));

// list of custom filter
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
pub enum FilterType {
    IsExists,
    NotContains,
}

/// Describe single check
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Check {
    pub id: String,
    /// test ia a value that we check the command.
    #[serde(with = "serde_regex")]
    pub test: Regex,
    /// description of what is risky in this command
    pub description: String,
    /// the group of the check see files in `checks` folder
    pub from: String,
    #[serde(default)]
    pub challenge: Challenge,
    #[serde(default)]
    pub filters: HashMap<FilterType, String>,
}

/// Return all shellfirm check patterns
///
/// # Errors
/// when has an error when parsing check str to [`Check`] list
pub fn get_all() -> Result<Vec<Check>> {
    Ok(serde_yaml::from_str(ALL_CHECKS)?)
}

/// prompt a challenge to the user
///
/// # Errors
///
/// Will return `Err` when could not convert checks to yaml
pub fn challenge(
    challenge: &Challenge,
    checks: &[Check],
    deny_pattern_ids: &[String],
) -> Result<bool> {
    let mut descriptions: Vec<String> = Vec::new();
    let mut should_deny_command = false;

    debug!("list of denied pattern ids {:?}", deny_pattern_ids);

    for check in checks {
        if !descriptions.contains(&check.description) {
            descriptions.push(check.description.to_string());
        }
        if !should_deny_command && deny_pattern_ids.contains(&check.id) {
            should_deny_command = true;
        }
    }

    if should_deny_command {
        eprintln!("{}", style("##################").red().bold());
        eprintln!("{}", style("# COMMAND DENIED #").red().bold());
        eprintln!("{}", style("##################").red().bold());
    } else {
        eprintln!("{}", style("#######################").yellow().bold());
        eprintln!("{}", style("# RISKY COMMAND FOUND #").yellow().bold());
        eprintln!("{}", style("#######################").yellow().bold());
    }

    for description in descriptions {
        eprintln!("* {description}");
    }
    eprintln!();

    let show_challenge = challenge;
    if should_deny_command {
        debug!("command denied.");
        prompt::deny();
    }

    Ok(match show_challenge {
        Challenge::Math => prompt::math_challenge(),
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
        .filter(|&v| v.test.is_match(command))
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
    if check.filters.is_empty() {
        return true;
    }
    // Capture command groups from the current check
    let caps = check.test.captures(command).unwrap();

    // by default true is return. it mean the check not filter out (safe side
    // security).
    let mut keep_check = true;
    for (filter_type, filter_params) in &check.filters {
        debug!(
            "filter information: command {} include filter: {:?} filter_params: {}",
            command, filter_type, filter_params
        );

        let keep_filter = match filter_type {
            FilterType::IsExists => filter_is_file_or_directory_exists(
                caps.get(filter_params.parse().unwrap())
                    .map_or("", |m| m.as_str()),
            ),
            FilterType::NotContains => filter_is_command_contains_string(command, filter_params),
        };

        if !keep_filter {
            keep_check = false;
            break;
        }
    }

    keep_check
}

/// check if the path exists (file and folder).
///
/// # Arguments
///
/// * `file_path` - check path.
fn filter_is_file_or_directory_exists(file_path: &str) -> bool {
    let mut file_path: String = file_path.trim().into();
    if file_path.starts_with('~') {
        match dirs::home_dir() {
            Some(path) => {
                file_path = file_path.replace('~', &path.display().to_string());
            }
            None => return true,
        };
    }

    if file_path.contains('*') {
        return true;
    }

    let full_path = match env::current_dir() {
        Ok(e) => e.join(file_path).display().to_string(),
        Err(err) => {
            log::debug!("could not get current dir. err: {:?}", err);
            return true;
        }
    };

    log::debug!("check is {} path is exists", full_path);
    std::path::Path::new(full_path.trim()).exists()
        || std::path::Path::new(full_path.trim()).is_dir()
}

fn filter_is_command_contains_string(command: &str, filter_params: &str) -> bool {
    !command.contains(filter_params)
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
  enable: true
  description: ""
  id: ""
- from: test-2
  test: test-(1|2)
  enable: true
  description: ""
  id: ""
- from: test-disabled
  test: test-disabled
  enable: true
  description: ""
  id: ""
"###;

    #[test]
    fn can_run_check_on_command() {
        let checks: Vec<Check> = serde_yaml::from_str(CHECKS).unwrap();
        assert_debug_snapshot!(run_check_on_command(&checks, "test-1"));
        assert_debug_snapshot!(run_check_on_command(&checks, "unknown command"));
    }

    #[test]
    fn can_check_custom_filter_with_file_exists() {
        let mut filters: HashMap<FilterType, String> = HashMap::new();
        filters.insert(FilterType::IsExists, "1".to_string());

        let check = Check {
            id: "id".to_string(),
            test: Regex::new(".*>(.*)").unwrap(),
            description: "some description".to_string(),
            from: "test".to_string(),
            challenge: Challenge::default(),
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

    #[test]
    fn can_check_custom_filter_with_str_contains() {
        let mut filters: HashMap<FilterType, String> = HashMap::new();
        filters.insert(FilterType::NotContains, "--dry-run".to_string());

        let check = Check {
            id: "id".to_string(),
            test: Regex::new("(delete)").unwrap(),
            description: "some description".to_string(),
            from: "test".to_string(),
            challenge: Challenge::default(),
            filters,
        };

        assert_debug_snapshot!(check_custom_filter(&check, "delete"));
        assert_debug_snapshot!(check_custom_filter(&check, "delete --dry-run"));
    }

    #[test]
    fn can_get_all_checks() {
        assert_debug_snapshot!(get_all().is_ok());
    }
}
