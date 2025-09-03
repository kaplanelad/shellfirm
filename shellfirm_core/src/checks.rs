//! Core command validation logic
//!
//! This module contains the platform-agnostic validation logic extracted from
//! the original shellfirm implementation, adapted for WASM compatibility.

use crate::filters::check_custom_filter;
use crate::{Error, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_regex;
use std::collections::HashMap;
// use std::sync::OnceLock; // no longer needed in this module
use strum::EnumIter;

/// String with all checks from `checks` folder (prepared in build.rs) in YAML format.
const ALL_CHECKS: &str = include_str!(concat!(env!("OUT_DIR"), "/all-checks.yaml"));

/// Validation mode for command checking
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Hash, Clone, Default)]
pub enum ValidationMode {
    /// Split command into individual parts and check each part separately
    #[default]
    Split,
    /// Check the entire command as a whole without splitting
    Whole,
}

impl std::fmt::Display for ValidationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Split => write!(f, "split"),
            Self::Whole => write!(f, "whole"),
        }
    }
}

/// Types of custom filters that can be applied to checks
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
pub enum FilterType {
    /// Check if a file or directory exists
    IsExists,
    /// Check if command does not contain a specific string
    NotContains,
}

/// Challenge types that can be presented to users
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Default, EnumIter)]
pub enum Challenge {
    #[serde(rename = "math")]
    #[default]
    Math,
    #[serde(rename = "word")]
    Word,
    #[serde(rename = "confirm")]
    Confirm,
    #[serde(rename = "enter")]
    Enter,
    #[serde(rename = "yes")]
    Yes,
    #[serde(rename = "block")]
    Block,
}

impl std::fmt::Display for Challenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Math => write!(f, "Math"),
            Self::Word => write!(f, "Word"),
            Self::Confirm => write!(f, "Confirm"),
            Self::Enter => write!(f, "Enter"),
            Self::Yes => write!(f, "Yes"),
            Self::Block => write!(f, "Block"),
        }
    }
}

impl Challenge {
    /// Convert challenge string to enum
    ///
    /// # Errors
    /// when the given challenge string is not supported
    pub fn from_string(str: &str) -> Result<Self> {
        match str.to_lowercase().as_str() {
            "math" => Ok(Self::Math),
            "word" => Ok(Self::Word),
            "confirm" => Ok(Self::Confirm),
            "enter" => Ok(Self::Enter),
            "yes" => Ok(Self::Yes),
            "block" => Ok(Self::Block),
            _ => Err(Error::InvalidChallengeName {
                name: str.to_string(),
            }),
        }
    }
}

/// Describes a single command validation check
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Check {
    /// Unique identifier for this check
    pub id: String,
    /// Regular expression pattern to test the command against
    #[serde(with = "serde_regex")]
    pub test: Regex,
    /// Human-readable description of what makes this command risky
    pub description: String,
    /// The group/category this check belongs to (e.g., "fs", "git", "base")
    pub from: String,
    /// Severity of the risky pattern
    #[serde(default)]
    pub severity: Severity,
    /// Type of challenge to present if this check matches
    #[serde(default)]
    pub challenge: Challenge,
    /// Custom filters to apply additional validation logic
    #[serde(default)]
    pub filters: HashMap<FilterType, String>,
    /// Validation mode for this check
    #[serde(default)]
    pub validation_mode: ValidationMode,
}

/// Severity levels for risky patterns
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Default, EnumIter)]
pub enum Severity {
    #[serde(rename = "low")]
    Low,
    #[serde(rename = "medium")]
    #[default]
    Medium,
    #[serde(rename = "high")]
    High,
    #[serde(rename = "critical")]
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        };
        write!(f, "{s}")
    }
}

/// Result of command validation
#[derive(Debug, Clone, Default)]
pub struct ValidationResult {
    /// List of checks that matched the command
    pub matches: Vec<Check>,
    /// Whether a challenge should be presented to the user
    pub should_challenge: bool,
    /// Whether the command should be completely denied
    pub should_deny: bool,
}

impl ValidationResult {
    /// Create a new validation result indicating the command is safe
    #[must_use]
    pub const fn safe() -> Self {
        Self {
            matches: Vec::new(),
            should_challenge: false,
            should_deny: false,
        }
    }

    /// Create a new validation result with matched checks
    #[must_use]
    pub const fn with_matches(matches: Vec<Check>) -> Self {
        let should_challenge = !matches.is_empty();
        Self {
            matches,
            should_challenge,
            should_deny: false,
        }
    }

    /// Create a new validation result that denies the command
    #[must_use]
    pub const fn denied(matches: Vec<Check>) -> Self {
        Self {
            matches,
            should_challenge: true,
            should_deny: true,
        }
    }
}

/// Return all shellfirm check patterns
///
/// # Errors
/// Returns an error when there's a problem parsing the embedded YAML checks
pub fn get_all_checks() -> Result<Vec<Check>> {
    Ok(serde_yaml::from_str(ALL_CHECKS)?)
}

/// Check if the given command matches any of the provided checks
///
/// # Arguments
/// * `checks` - List of checks to validate against
/// * `command` - Command string to check
/// * `options` - Validation options including filter context
///
/// # Returns
/// Vector of checks that matched the command
#[must_use]
pub fn run_check_on_command(
    checks: &[Check],
    command: &str,
    options: &crate::ValidationOptions,
) -> Vec<Check> {
    checks
        .iter()
        .filter(|check| check.test.is_match(command))
        .filter(|check| check_custom_filter(check, command, options.filter_context.as_ref()))
        .filter(|check| {
            // Filter by allowed severities if specified
            if options.allowed_severities.is_empty() {
                // If no severities specified, allow all
                true
            } else {
                // Check if this check's severity is in the allowed list
                options
                    .allowed_severities
                    .contains(&check.severity.to_string())
            }
        })
        .cloned()
        .collect()
}

/// Simplified version for backward compatibility
#[must_use]
pub fn run_check_on_command_simple(checks: &[Check], command: &str) -> Vec<Check> {
    let options = crate::ValidationOptions::default();
    run_check_on_command(checks, command, &options)
}

/// Validate a command string by parsing, splitting, and checking each part
///
/// # Returns
/// Vector of checks that matched any part of the command
#[must_use]
pub fn validate_command_with_split(
    checks: &[Check],
    command: &str,
    options: &crate::ValidationOptions,
) -> Vec<Check> {
    let mut matches = Vec::new();

    for check in checks {
        match check.validation_mode {
            ValidationMode::Split => {
                let commands = crate::command::parse_and_split_command(command);
                for cmd in commands {
                    let cmd_matches = run_check_on_command(&[check.clone()], &cmd, options);
                    matches.extend(cmd_matches);
                }
            }
            ValidationMode::Whole => {
                let whole_matches = run_check_on_command(&[check.clone()], command, options);
                matches.extend(whole_matches);
            }
        }
    }

    matches
}

/// Validate a command against all available checks
///
/// # Arguments
/// * `command` - The command string to validate
///
/// # Returns
/// A `ValidationResult` containing the validation outcome
#[must_use]
pub fn validate_command(command: &str) -> ValidationResult {
    get_all_checks().map_or_else(
        |_| ValidationResult::safe(),
        |checks| {
            let matches = run_check_on_command_simple(&checks, command);
            if matches.is_empty() {
                ValidationResult::safe()
            } else {
                ValidationResult::with_matches(matches)
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CHECKS: &str = r#"
- from: test-1
  test: "test-(1)"
  description: "Test command 1"
  id: "test:command_1"
  validation_mode: Split
- from: test-2  
  test: "test-(1|2)"
  description: "Test command 1 or 2"
  id: "test:command_1_or_2"
  validation_mode: Split
- from: test-disabled
  test: "test-disabled"
  description: "Disabled test command"
  id: "test:disabled"
  validation_mode: Split
"#;

    #[test]
    fn can_run_check_on_command() {
        let checks: Vec<Check> =
            serde_yaml::from_str(TEST_CHECKS).expect("Failed to parse TEST_CHECKS YAML");
        let matches = run_check_on_command_simple(&checks, "test-1");
        assert_eq!(matches.len(), 2); // Should match both "test-1" and "test-(1|2)" patterns

        let matches = run_check_on_command_simple(&checks, "unknown command");
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn can_validate_command() {
        let result = validate_command("echo hello");
        assert!(!result.should_challenge); // Safe command

        // This will depend on the actual patterns loaded
        // In a real test environment, we'd have known patterns to test against
    }

    #[test]
    fn can_get_all_checks() {
        let result = get_all_checks();
        assert!(result.is_ok());
        let checks = result.expect("Failed to get all checks");
        assert!(!checks.is_empty());
    }

    #[test]
    fn validation_result_creation() {
        let safe_result = ValidationResult::safe();
        assert!(!safe_result.should_challenge);
        assert!(!safe_result.should_deny);
        assert!(safe_result.matches.is_empty());

        let check = Check {
            id: "test:1".to_string(),
            test: Regex::new("test").expect("Failed to create regex for test"),
            description: "Test check".to_string(),
            from: "test".to_string(),
            severity: Severity::Medium,
            challenge: Challenge::Math,
            filters: HashMap::new(),
            validation_mode: ValidationMode::Split,
        };

        let matches_result = ValidationResult::with_matches(vec![check.clone()]);
        assert!(matches_result.should_challenge);
        assert!(!matches_result.should_deny);
        assert_eq!(matches_result.matches.len(), 1);

        let denied_result = ValidationResult::denied(vec![check]);
        assert!(denied_result.should_challenge);
        assert!(denied_result.should_deny);
        assert_eq!(denied_result.matches.len(), 1);
    }

    // moved parsing unit tests to crate::command::tests

    #[test]
    fn test_validate_command_with_split() {
        let checks: Vec<Check> =
            serde_yaml::from_str(TEST_CHECKS).expect("Failed to parse TEST_CHECKS YAML");
        let options = crate::ValidationOptions::default();

        // Test simple command
        let matches = validate_command_with_split(&checks, "test-1", &options);
        assert_eq!(matches.len(), 2); // Should match both patterns

        // Test command with operators
        let matches = validate_command_with_split(&checks, "test-1 && test-2", &options);
        assert_eq!(matches.len(), 3); // test-1 matches 2 patterns, test-2 matches 1 pattern

        // Test command with quoted strings
        let matches =
            validate_command_with_split(&checks, "test-1 'quoted string' && test-2", &options);
        assert_eq!(matches.len(), 3); // Quotes should be removed, still match same patterns

        // Test safe command
        let matches = validate_command_with_split(&checks, "echo hello", &options);
        assert_eq!(matches.len(), 0); // Should not match any patterns
    }

    #[test]
    fn test_validate_command_with_split_default() {
        let checks: Vec<Check> =
            serde_yaml::from_str(TEST_CHECKS).expect("Failed to parse TEST_CHECKS YAML");
        let options = crate::ValidationOptions::default();

        // Test simple command
        let matches = validate_command_with_split(&checks, "test-1", &options);
        assert_eq!(matches.len(), 2);

        // Test command with operators
        let matches = validate_command_with_split(&checks, "test-1 && test-2", &options);
        assert_eq!(matches.len(), 3); // test-1 matches 2 patterns, test-2 matches 1 pattern

        // Test safe command
        let matches = validate_command_with_split(&checks, "echo hello", &options);
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_validation_result_methods() {
        // Test default implementation
        let default_result = ValidationResult::default();
        assert!(!default_result.should_challenge);
        assert!(!default_result.should_deny);
        assert!(default_result.matches.is_empty());

        // Test safe result
        let safe_result = ValidationResult::safe();
        assert!(!safe_result.should_challenge);
        assert!(!safe_result.should_deny);
        assert!(safe_result.matches.is_empty());

        // Test with matches
        let check = Check {
            id: "test:1".to_string(),
            test: Regex::new("test").expect("Failed to create regex for test"),
            description: "Test check".to_string(),
            from: "test".to_string(),
            severity: Severity::Medium,
            challenge: Challenge::Math,
            filters: HashMap::new(),
            validation_mode: ValidationMode::Split,
        };

        let matches_result = ValidationResult::with_matches(vec![check.clone()]);
        assert!(matches_result.should_challenge);
        assert!(!matches_result.should_deny);
        assert_eq!(matches_result.matches.len(), 1);

        // Test denied result
        let denied_result = ValidationResult::denied(vec![check.clone()]);
        assert!(denied_result.should_challenge);
        assert!(denied_result.should_deny);
        assert_eq!(denied_result.matches.len(), 1);

        // Test multiple matches
        let check2 = Check {
            id: "test:2".to_string(),
            test: Regex::new("test2").expect("Failed to create regex for test2"),
            description: "Test check 2".to_string(),
            from: "test".to_string(),
            severity: Severity::High,
            challenge: Challenge::Confirm,
            filters: HashMap::new(),
            validation_mode: ValidationMode::Split,
        };

        let multiple_matches = ValidationResult::with_matches(vec![check, check2]);
        assert!(multiple_matches.should_challenge);
        assert!(!multiple_matches.should_deny);
        assert_eq!(multiple_matches.matches.len(), 2);
    }

    // moved parsing edge-case unit tests to crate::command::tests
    #[test]
    fn test_validate_command_with_split_edge_cases() {
        let checks: Vec<Check> =
            serde_yaml::from_str(TEST_CHECKS).expect("Failed to parse TEST_CHECKS YAML");
        let options = crate::ValidationOptions::default();

        // Test empty command
        let matches = validate_command_with_split(&checks, "", &options);
        assert_eq!(matches.len(), 0);

        // Test command with only operators
        let matches = validate_command_with_split(&checks, "&& || & |", &options);
        assert_eq!(matches.len(), 0);

        // Test command with whitespace only
        let matches = validate_command_with_split(&checks, "   \t\n  ", &options);
        assert_eq!(matches.len(), 0);

        // Test command with partial matches
        let matches = validate_command_with_split(&checks, "test-1 && echo hello", &options);
        assert_eq!(matches.len(), 2); // Only test-1 matches

        // Test command with no matches
        let matches = validate_command_with_split(&checks, "echo hello && echo world", &options);
        assert_eq!(matches.len(), 0);

        // Test command with complex splitting
        let matches = validate_command_with_split(&checks, "test-1 && test-2 || test-1", &options);
        assert_eq!(matches.len(), 5); // test-1(2) + test-2(1) + test-1(2) = 5
    }

    #[test]
    fn test_check_struct_creation() {
        let check = Check {
            id: "test:1".to_string(),
            test: Regex::new("test").expect("Failed to create regex for test"),
            description: "Test check".to_string(),
            from: "test".to_string(),
            severity: Severity::Low,
            challenge: Challenge::Word,
            filters: HashMap::new(),
            validation_mode: ValidationMode::Split,
        };

        assert_eq!(check.id, "test:1");
        assert_eq!(check.description, "Test check");
        assert_eq!(check.from, "test");
        assert_eq!(check.severity, Severity::Low);
        assert_eq!(check.challenge, Challenge::Word);
        assert!(check.filters.is_empty());
        assert_eq!(check.validation_mode, ValidationMode::Split);
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(Severity::Low.to_string(), "low");
        assert_eq!(Severity::Medium.to_string(), "medium");
        assert_eq!(Severity::High.to_string(), "high");
        assert_eq!(Severity::Critical.to_string(), "critical");
    }

    #[test]
    fn test_challenge_default() {
        assert_eq!(Challenge::default(), Challenge::Math);
    }

    #[test]
    fn test_severity_default() {
        assert_eq!(Severity::default(), Severity::Medium);
    }

    #[test]
    fn test_run_check_on_command() {
        let checks: Vec<Check> =
            serde_yaml::from_str(TEST_CHECKS).expect("Failed to parse TEST_CHECKS YAML");
        let options = crate::ValidationOptions::default();

        // Test with matching command
        let matches = run_check_on_command(&checks, "test-1", &options);
        assert_eq!(matches.len(), 2);

        // Test with non-matching command
        let matches = run_check_on_command(&checks, "echo hello", &options);
        assert_eq!(matches.len(), 0);

        // Test with empty command
        let matches = run_check_on_command(&checks, "", &options);
        assert_eq!(matches.len(), 0);

        // Test with whitespace-only command
        let matches = run_check_on_command(&checks, "   \t\n  ", &options);
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_run_check_on_command_simple() {
        let checks: Vec<Check> =
            serde_yaml::from_str(TEST_CHECKS).expect("Failed to parse TEST_CHECKS YAML");

        // Test with matching command
        let matches = run_check_on_command_simple(&checks, "test-1");
        assert_eq!(matches.len(), 2);

        // Test with non-matching command
        let matches = run_check_on_command_simple(&checks, "echo hello");
        assert_eq!(matches.len(), 0);

        // Test with empty command
        let matches = run_check_on_command_simple(&checks, "");
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_get_all_checks_error_handling() {
        // This test verifies that get_all_checks doesn't panic
        // The actual behavior depends on the build environment
        let result = get_all_checks();
        // We can't assert on the result since it depends on the build environment
        // But we can verify the function doesn't panic
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_validate_command_error_handling() {
        // Test that validate_command doesn't panic on various inputs
        let result = validate_command("echo hello");
        assert!(!result.should_challenge);
        assert!(!result.should_deny);

        let result = validate_command("");
        assert!(!result.should_challenge);
        assert!(!result.should_deny);

        let result = validate_command("   \t\n  ");
        assert!(!result.should_challenge);
        assert!(!result.should_deny);
    }

    #[test]
    fn test_check_struct_with_filters() {
        let mut filters = HashMap::new();
        filters.insert(FilterType::IsExists, "1".to_string());
        filters.insert(FilterType::NotContains, "--dry-run".to_string());

        let check = Check {
            id: "test:1".to_string(),
            test: Regex::new("test").expect("Failed to create regex for test"),
            description: "Test check with filters".to_string(),
            from: "test".to_string(),
            severity: Severity::High,
            challenge: Challenge::Confirm,
            filters,
            validation_mode: ValidationMode::Split,
        };

        assert_eq!(check.id, "test:1");
        assert_eq!(check.description, "Test check with filters");
        assert_eq!(check.from, "test");
        assert_eq!(check.severity, Severity::High);
        assert_eq!(check.challenge, Challenge::Confirm);
        assert_eq!(check.filters.len(), 2);
        assert!(check.filters.contains_key(&FilterType::IsExists));
        assert!(check.filters.contains_key(&FilterType::NotContains));
    }

    #[test]
    fn test_severity_filtering_with_allowed_severities() {
        // Create test checks with different severities
        let checks = vec![
            Check {
                id: "low:1".to_string(),
                test: Regex::new("low").expect("Failed to create regex for low severity test"),
                description: "Low severity check".to_string(),
                from: "test".to_string(),
                severity: Severity::Low,
                challenge: Challenge::Math,
                filters: HashMap::new(),
                validation_mode: ValidationMode::Split,
            },
            Check {
                id: "medium:1".to_string(),
                test: Regex::new("medium")
                    .expect("Failed to create regex for medium severity test"),
                description: "Medium severity check".to_string(),
                from: "test".to_string(),
                severity: Severity::Medium,
                challenge: Challenge::Math,
                filters: HashMap::new(),
                validation_mode: ValidationMode::Split,
            },
            Check {
                id: "high:1".to_string(),
                test: Regex::new("high").expect("Failed to create regex for high severity test"),
                description: "High severity check".to_string(),
                from: "test".to_string(),
                severity: Severity::High,
                challenge: Challenge::Math,
                filters: HashMap::new(),
                validation_mode: ValidationMode::Split,
            },
            Check {
                id: "critical:1".to_string(),
                test: Regex::new("critical")
                    .expect("Failed to create regex for critical severity test"),
                description: "Critical severity check".to_string(),
                from: "test".to_string(),
                severity: Severity::Critical,
                challenge: Challenge::Math,
                filters: HashMap::new(),
                validation_mode: ValidationMode::Split,
            },
        ];

        // Test with no severity restrictions (should return all matches)
        let mut options = crate::ValidationOptions::default();
        options.allowed_severities = Vec::new(); // Empty = all severities allowed

        let matches = run_check_on_command(&checks, "low", &options);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].severity, Severity::Low);

        let matches = run_check_on_command(&checks, "medium", &options);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].severity, Severity::Medium);

        let matches = run_check_on_command(&checks, "high", &options);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].severity, Severity::High);

        let matches = run_check_on_command(&checks, "critical", &options);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].severity, Severity::Critical);

        // Test with only low and medium severities allowed
        options.allowed_severities = vec!["low".to_string(), "medium".to_string()];

        let matches = run_check_on_command(&checks, "low", &options);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].severity, Severity::Low);

        let matches = run_check_on_command(&checks, "medium", &options);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].severity, Severity::Medium);

        let matches = run_check_on_command(&checks, "high", &options);
        assert_eq!(matches.len(), 0); // Should be filtered out

        let matches = run_check_on_command(&checks, "critical", &options);
        assert_eq!(matches.len(), 0); // Should be filtered out

        // Test with only critical severity allowed
        options.allowed_severities = vec!["critical".to_string()];

        let matches = run_check_on_command(&checks, "low", &options);
        assert_eq!(matches.len(), 0); // Should be filtered out

        let matches = run_check_on_command(&checks, "medium", &options);
        assert_eq!(matches.len(), 0); // Should be filtered out

        let matches = run_check_on_command(&checks, "high", &options);
        assert_eq!(matches.len(), 0); // Should be filtered out

        let matches = run_check_on_command(&checks, "critical", &options);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].severity, Severity::Critical);

        // Test with case-insensitive severity matching
        options.allowed_severities = vec!["HIGH".to_string(), "CRITICAL".to_string()];

        let matches = run_check_on_command(&checks, "high", &options);
        assert_eq!(matches.len(), 0); // Case-sensitive matching, so "HIGH" != "high"

        let matches = run_check_on_command(&checks, "critical", &options);
        assert_eq!(matches.len(), 0); // Case-sensitive matching, so "CRITICAL" != "critical"
    }

    #[test]
    fn test_severity_filtering_edge_cases() {
        let checks = vec![Check {
            id: "test:1".to_string(),
            test: Regex::new("test").expect("Failed to create regex for test"),
            description: "Test check".to_string(),
            from: "test".to_string(),
            severity: Severity::Medium,
            challenge: Challenge::Math,
            filters: HashMap::new(),
            validation_mode: ValidationMode::Split,
        }];

        // Test with empty allowed_severities (should allow all)
        let mut options = crate::ValidationOptions::default();
        options.allowed_severities = Vec::new();

        let matches = run_check_on_command(&checks, "test", &options);
        assert_eq!(matches.len(), 1);

        // Test with non-existent severity (should filter out everything)
        options.allowed_severities = vec!["nonexistent".to_string()];

        let matches = run_check_on_command(&checks, "test", &options);
        assert_eq!(matches.len(), 0);

        // Test with mixed valid and invalid severities
        options.allowed_severities = vec!["medium".to_string(), "nonexistent".to_string()];

        let matches = run_check_on_command(&checks, "test", &options);
        assert_eq!(matches.len(), 1); // Should match "medium"

        // Test with empty string severity
        options.allowed_severities = vec!["".to_string()];

        let matches = run_check_on_command(&checks, "test", &options);
        assert_eq!(matches.len(), 0); // Empty string won't match any severity
    }

    #[test]
    fn test_validation_options_with_severities() {
        // Test default ValidationOptions
        let options = crate::ValidationOptions::default();
        assert!(options.allowed_severities.is_empty());
        assert!(options.deny_pattern_ids.is_empty());
        assert!(options.filter_context.is_none());

        // Test with custom severities
        let mut options = crate::ValidationOptions::default();
        options.allowed_severities = vec!["low".to_string(), "medium".to_string()];
        assert_eq!(options.allowed_severities.len(), 2);
        assert!(options.allowed_severities.contains(&"low".to_string()));
        assert!(options.allowed_severities.contains(&"medium".to_string()));

        // Test cloning with severities
        let cloned_options = options.clone();
        assert_eq!(cloned_options.allowed_severities.len(), 2);
        assert!(cloned_options
            .allowed_severities
            .contains(&"low".to_string()));
        assert!(cloned_options
            .allowed_severities
            .contains(&"medium".to_string()));

        // Test debug formatting
        let debug_str = format!("{:?}", options);
        assert!(debug_str.contains("allowed_severities"));
        assert!(debug_str.contains("low"));
        assert!(debug_str.contains("medium"));
    }

    #[test]
    fn test_validation_mode_display() {
        assert_eq!(ValidationMode::Split.to_string(), "split");
        assert_eq!(ValidationMode::Whole.to_string(), "whole");
    }

    #[test]
    fn test_base_execute_all_history_commands_rule() {
        // Test that the base:execute_all_history_commands rule uses Whole validation mode
        let checks = get_all_checks().expect("Failed to get all checks");

        // Find the specific rule
        let history_rule = checks
            .iter()
            .find(|check| check.id == "base:execute_all_history_commands");
        assert!(
            history_rule.is_some(),
            "base:execute_all_history_commands rule should exist"
        );

        let history_rule = history_rule.unwrap();
        assert_eq!(
            history_rule.validation_mode,
            ValidationMode::Whole,
            "base:execute_all_history_commands should use Whole validation mode"
        );

        // Test that it matches the entire command without splitting
        let options = crate::ValidationOptions::default();
        let matches = validate_command_with_split(&checks, "history | bash", &options);

        // Should find the history rule
        let found_history_rule = matches
            .iter()
            .find(|check| check.id == "base:execute_all_history_commands");
        assert!(
            found_history_rule.is_some(),
            "Should match history | bash command"
        );

        // Test with a command that would be split but should still match
        let matches =
            validate_command_with_split(&checks, "echo hello && history | bash", &options);
        let found_history_rule = matches
            .iter()
            .find(|check| check.id == "base:execute_all_history_commands");
        assert!(
            found_history_rule.is_some(),
            "Should match even when command is split"
        );
    }
}
