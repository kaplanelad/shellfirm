//! Manage command checks - Platform-specific wrapper around `shellfirm_core`
//!
//! This module provides the platform-specific functionality for the CLI,
//! including file system access, terminal output, and user prompts.
use anyhow::Result;
use console::style;
pub use shellfirm_core::{
    checks::{
        get_all_checks, validate_command_with_split, Challenge, Check, FilterType, ValidationResult,
    },
    filters::FilterContext,
    ValidationOptions,
};
use std::collections::HashSet;
use tracing::debug;

use crate::prompt;

/// Prompt a challenge to the user
///
/// # Errors
/// Will return `Err` when could not convert checks to yaml
pub fn show(
    challenge: &Challenge,
    checks: &[Check],
    ignored_checks: &[Check],
    deny_pattern_ids: &[String],
) -> Result<bool> {
    let mut seen_ids: HashSet<String> = HashSet::new();
    let mut matched_rules: Vec<(String, String)> = Vec::new(); // (id, description)
    let mut should_deny_command = false;

    debug!(deny_pattern_ids = ?deny_pattern_ids, "list of denied pattern ids");

    for check in checks {
        if seen_ids.insert(check.id.clone()) {
            matched_rules.push((check.id.clone(), check.description.clone()));
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

    for (id, description) in matched_rules {
        eprintln!("* [{id}] {description}");
    }
    if !ignored_checks.is_empty() {
        let mut ignored_seen: HashSet<String> = HashSet::new();
        eprintln!();
        eprintln!("Note: The following rules are ignored by your config:");
        for c in ignored_checks {
            if ignored_seen.insert(c.id.clone()) {
                eprintln!("* [{}] {}", c.id, c.description);
            }
        }
    }
    eprintln!();

    let show_challenge = challenge;
    if should_deny_command {
        debug!("command denied");
        prompt::deny();
    }

    Ok(match show_challenge {
        Challenge::Math => prompt::math_challenge(),
        Challenge::Word => prompt::word_challenge(),
        Challenge::Confirm => prompt::confirm_challenge(),
        Challenge::Enter => prompt::enter_challenge(),
        Challenge::Yes => prompt::yes_challenge(),
        Challenge::Block => prompt::block_challenge(),
    })
}
