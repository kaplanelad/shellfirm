//! Manage command checks

use std::sync::OnceLock;

use anyhow::Result;
use log::{debug, warn};
use rayon::prelude::*;
use regex::Regex;
use serde_derive::{Deserialize, Serialize};
use serde_regex;

use crate::{
    config::Challenge,
    context::{self, RuntimeContext},
    env::Environment,
    policy::MergedPolicy,
    prompt::{AlternativeInfo, ChallengeResult, DisplayContext, Prompter},
};

/// String with all checks from `checks` folder (prepared in build.rs) in YAML
/// format.
const ALL_CHECKS: &str = include_str!(concat!(env!("OUT_DIR"), "/all-checks.yaml"));

/// Severity level of a check — determines how critical a matched pattern is.
///
/// The natural ordering (`Info < Low < Medium < High < Critical`) is used
/// for filtering: when a `min_severity` is configured, only checks at or
/// above that threshold trigger a challenge.
#[derive(Debug, Default, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    #[default]
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// A single post-match filter that gates whether a check should fire.
///
/// Filters are evaluated after the regex matches. **All** filters in the
/// list must pass (logical AND) for the check to be kept.
///
/// YAML format (adjacently tagged):
/// ```yaml
/// filters:
///   - type: PathExists
///     value: 1
///   - type: NotContains
///     value: "--dry-run"
/// ```
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(tag = "type", content = "value")]
pub enum Filter {
    /// Keep the check only if the captured path exists on disk.
    /// The value is the regex capture-group index (1-based).
    PathExists(usize),
    /// Keep the check only if the command does **not** contain this substring.
    NotContains(String),
    /// Keep the check only if the command **does** contain this substring.
    Contains(String),
}

/// Describe single check
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Check {
    pub id: String,
    /// test is a value that we check the command.
    #[serde(with = "serde_regex")]
    pub test: Regex,
    /// description of what is risky in this command
    pub description: String,
    /// the group of the check see files in `checks` folder
    pub from: String,
    #[serde(default)]
    pub challenge: Challenge,
    #[serde(default)]
    pub filters: Vec<Filter>,
    /// Safer command alternative suggestion (shown to user).
    #[serde(default)]
    pub alternative: Option<String>,
    /// Explanation of why the alternative is safer.
    #[serde(default)]
    pub alternative_info: Option<String>,
    /// Severity level — determines how critical this check is.
    #[serde(default)]
    pub severity: Severity,
}

/// Return a cached reference to all built-in check patterns.
///
/// The YAML is parsed and regexes are compiled exactly once (on first call).
/// Subsequent calls return a reference to the cached static slice.
pub(crate) fn all_checks_cached() -> &'static [Check] {
    static CHECKS: OnceLock<Vec<Check>> = OnceLock::new();
    CHECKS.get_or_init(|| {
        serde_yaml::from_str(ALL_CHECKS).expect("built-in checks are valid YAML")
    })
}

/// Return all built-in shellfirm check patterns
///
/// # Errors
/// when has an error when parsing check str to [`Check`] list
pub fn get_all() -> Result<Vec<Check>> {
    Ok(all_checks_cached().to_vec())
}

/// Load custom checks from YAML files in a directory.
///
/// # Errors
/// When a file cannot be read or parsed.
pub fn load_custom_checks(checks_dir: &std::path::Path) -> Result<Vec<Check>> {
    let mut custom_checks = Vec::new();
    if !checks_dir.is_dir() {
        return Ok(custom_checks);
    }
    let entries = std::fs::read_dir(checks_dir)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "yaml" || e == "yml") {
            let content = std::fs::read_to_string(&path)?;
            let checks: Vec<Check> = serde_yaml::from_str(&content)?;
            custom_checks.extend(checks);
        }
    }
    Ok(custom_checks)
}

/// Validate check definitions and return a list of warning messages.
///
/// Currently checks:
/// - `PathExists(n)` — warns when `n` exceeds the number of capture groups
///   in the check's regex.
#[must_use]
pub fn validate_checks(checks: &[Check]) -> Vec<String> {
    let mut warnings = Vec::new();
    for check in checks {
        let num_captures = check.test.captures_len(); // group 0 + real groups
        for filter in &check.filters {
            if let Filter::PathExists(group_idx) = filter {
                if *group_idx >= num_captures {
                    warnings.push(format!(
                        "check {:?}: PathExists({}) references a capture group that \
                         does not exist (regex has {} groups including group 0)",
                        check.id, group_idx, num_captures
                    ));
                }
            }
        }
    }
    warnings
}

/// New challenge flow that is context-aware and uses the Prompter trait.
///
/// This is the primary entry point for the v1.0 pipeline.
///
/// # Errors
/// Returns an error if the prompter fails.
pub fn challenge_with_context(
    base_challenge: &Challenge,
    checks: &[&Check],
    deny_pattern_ids: &[String],
    context: &RuntimeContext,
    merged_policy: &MergedPolicy,
    escalation_config: &context::EscalationConfig,
    prompter: &dyn Prompter,
) -> Result<ChallengeResult> {
    let mut descriptions: Vec<String> = Vec::new();
    let mut alternatives: Vec<AlternativeInfo> = Vec::new();
    let mut should_deny_command = false;

    debug!("list of denied pattern ids {deny_pattern_ids:?}");

    for check in checks {
        if !descriptions.contains(&check.description) {
            descriptions.push(check.description.clone());
        }
        // Check deny from global settings
        if !should_deny_command && deny_pattern_ids.contains(&check.id) {
            should_deny_command = true;
        }
        // Check deny from project policy
        if !should_deny_command && merged_policy.is_denied(&check.id) {
            should_deny_command = true;
        }
        // Collect alternatives
        if let Some(ref alt) = check.alternative {
            let already_has = alternatives.iter().any(|a| a.suggestion == *alt);
            if !already_has {
                alternatives.push(AlternativeInfo {
                    suggestion: alt.clone(),
                    explanation: check.alternative_info.clone(),
                });
            }
        }
    }

    // Compute effective challenge with context escalation + policy overrides
    let context_escalated =
        context::escalate_challenge(base_challenge, context.risk_level, escalation_config);

    // Apply per-pattern policy overrides (take the strictest)
    let mut effective = context_escalated;
    for check in checks {
        let policy_effective =
            merged_policy.effective_challenge(&check.id, &effective);
        effective = max_challenge(effective, policy_effective);
    }

    // Build escalation note
    let escalation_note = if effective == *base_challenge {
        None
    } else {
        Some(format!("{base_challenge} -> {effective}"))
    };

    // Compute highest severity for display
    let max_severity = checks
        .iter()
        .map(|c| c.severity)
        .max();
    let severity_label = max_severity.map(|s| format!("{s}"));

    let display = DisplayContext {
        is_denied: should_deny_command,
        descriptions,
        alternatives,
        context_labels: context.labels.clone(),
        effective_challenge: effective,
        escalation_note,
        severity_label,
    };

    Ok(prompter.run_challenge(&display))
}

/// Check if the given command matched to one of the checks.
///
/// Uses [`crate::env::RealEnvironment`] for filter evaluation (filesystem checks).
/// For testing, prefer [`run_check_on_command_with_env`] with a mock environment.
///
/// # Arguments
///
/// * `checks` - List of checks that we want to validate.
/// * `command` - Command check.
#[must_use]
pub fn run_check_on_command<'a>(checks: &'a [Check], command: &str) -> Vec<&'a Check> {
    run_check_on_command_with_env(checks, command, &crate::env::RealEnvironment)
}

/// Like `run_check_on_command` but uses the Environment trait for filters.
#[must_use]
pub fn run_check_on_command_with_env<'a>(
    checks: &'a [Check],
    command: &str,
    env: &dyn Environment,
) -> Vec<&'a Check> {
    checks
        .par_iter()
        .filter(|v| v.test.is_match(command))
        .filter(|v| check_custom_filter_with_env(v, command, env))
        .collect()
}

/// Evaluate filters using the [`Environment`] trait (testable version).
///
/// Returns `true` when the check should be kept (all filters pass).
fn check_custom_filter_with_env(
    check: &Check,
    command: &str,
    env: &dyn Environment,
) -> bool {
    if check.filters.is_empty() {
        return true;
    }
    let caps = check.test.captures(command);

    for filter in &check.filters {
        debug!("filter information: command {command:?} filter: {filter:?}");

        let keep = match filter {
            Filter::PathExists(group_idx) => {
                let file_path = caps
                    .as_ref()
                    .and_then(|c| c.get(*group_idx))
                    .map_or_else(
                        || {
                            warn!(
                                "check {:?}: PathExists references capture group {} which does not exist in regex",
                                check.id, group_idx
                            );
                            ""
                        },
                        |m| m.as_str(),
                    );
                if file_path.is_empty() {
                    // No path captured → treat as "path doesn't exist" → suppress check
                    false
                } else {
                    filter_path_exists_with_env(file_path, env)
                }
            }
            Filter::NotContains(ref s) => !command.contains(s.as_str()),
            Filter::Contains(ref s) => command.contains(s.as_str()),
        };

        if !keep {
            return false;
        }
    }

    true
}

/// Check if path exists using [`Environment`] trait.
fn filter_path_exists_with_env(file_path: &str, env: &dyn Environment) -> bool {
    use std::borrow::Cow;

    let trimmed = file_path.trim();
    let file_path: Cow<'_, str> = if trimmed.starts_with('~') {
        match env.home_dir() {
            Some(home) => Cow::Owned(trimmed.replacen('~', &home.display().to_string(), 1)),
            None => return true,
        }
    } else {
        Cow::Borrowed(trimmed)
    };

    if file_path.contains('*') {
        return true;
    }

    let full_path = match env.current_dir() {
        Ok(cwd) => cwd.join(&*file_path),
        Err(err) => {
            debug!("could not get current dir. err: {err:?}");
            return true;
        }
    };

    debug!("check if {} path exists", full_path.display());
    env.path_exists(&full_path)
}

/// Return the stricter of two challenges.
pub(crate) fn max_challenge(a: Challenge, b: Challenge) -> Challenge {
    a.stricter(b)
}

/// Split a command string into parts by shell operators.
/// Handles `&&`, `||`, `|`, and `;` while respecting single and double quotes.
/// Operators inside quoted strings are not treated as separators.
#[must_use]
pub fn split_command(command: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let bytes = command.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    let mut start = i;
    let mut in_single_quote = false;
    let mut in_double_quote = false;

    while i < len {
        let b = bytes[i];

        // Track quote state (all delimiters are ASCII, safe to scan bytes)
        if b == b'\'' && !in_double_quote {
            in_single_quote = !in_single_quote;
            i += 1;
        } else if b == b'"' && !in_single_quote {
            in_double_quote = !in_double_quote;
            i += 1;
        } else if !in_single_quote && !in_double_quote {
            // Check for two-character operators first
            let (is_split, advance) = if i + 1 < len
                && ((b == b'&' && bytes[i + 1] == b'&') || (b == b'|' && bytes[i + 1] == b'|'))
            {
                (true, 2)
            } else if b == b'|' || b == b';' {
                (true, 1)
            } else {
                (false, 1)
            };

            if is_split {
                parts.push(command[start..i].to_string());
                i += advance;
                start = i;
            } else {
                i += 1;
            }
        } else {
            // Inside quotes — pass through without splitting
            i += 1;
        }
    }
    if start < len {
        parts.push(command[start..].to_string());
    }
    parts
}

#[cfg(test)]
mod test_checks {
    use insta::{assert_debug_snapshot, with_settings};

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
        with_settings!({filters => vec![
            // Normalize Regex debug format across insta/regex crate versions
            (r#"(?s)test:\s*Regex\(\s*"([^"]+)",?\s*\)"#, "test: $1"),
        ]}, {
            assert_debug_snapshot!(run_check_on_command(&checks, "test-1"));
            assert_debug_snapshot!(run_check_on_command(&checks, "unknown command"));
        });
    }

    #[test]
    fn can_check_custom_filter_with_file_exists() {
        use std::collections::HashSet;
        let filters = vec![Filter::PathExists(1)];

        let check = Check {
            id: "id".to_string(),
            test: Regex::new(".*>(.*)").unwrap(),
            description: "some description".to_string(),
            from: "test".to_string(),
            challenge: Challenge::default(),
            filters,
            alternative: None,
            alternative_info: None,
            severity: Severity::default(),
        };

        // Use mock environment: file does NOT exist
        let env_no_file = crate::env::MockEnvironment {
            cwd: "/mock".into(),
            ..Default::default()
        };
        let command = "cat 'write message' > /mock/app/message.txt";
        assert_debug_snapshot!(check_custom_filter_with_env(&check, command, &env_no_file));

        // Use mock environment: file DOES exist
        let mut existing = HashSet::new();
        existing.insert(std::path::PathBuf::from("/mock/app/message.txt"));
        let env_with_file = crate::env::MockEnvironment {
            cwd: "/mock".into(),
            existing_paths: existing,
            ..Default::default()
        };
        assert_debug_snapshot!(check_custom_filter_with_env(&check, command, &env_with_file));
    }

    #[test]
    fn can_check_custom_filter_with_str_contains() {
        let filters = vec![Filter::NotContains("--dry-run".to_string())];

        let check = Check {
            id: "id".to_string(),
            test: Regex::new("(delete)").unwrap(),
            description: "some description".to_string(),
            from: "test".to_string(),
            challenge: Challenge::default(),
            filters,
            alternative: None,
            alternative_info: None,
            severity: Severity::default(),
        };

        let env = crate::env::MockEnvironment::default();
        assert_debug_snapshot!(check_custom_filter_with_env(&check, "delete", &env));
        assert_debug_snapshot!(check_custom_filter_with_env(&check, "delete --dry-run", &env));
    }

    #[test]
    fn can_check_custom_filter_with_contains() {
        let filters = vec![Filter::Contains("--force".to_string())];

        let check = Check {
            id: "id".to_string(),
            test: Regex::new("(push)").unwrap(),
            description: "some description".to_string(),
            from: "test".to_string(),
            challenge: Challenge::default(),
            filters,
            alternative: None,
            alternative_info: None,
            severity: Severity::default(),
        };

        let env = crate::env::MockEnvironment::default();
        // Without --force the filter suppresses the check
        assert!(!check_custom_filter_with_env(&check, "git push origin main", &env));
        // With --force the filter keeps the check
        assert!(check_custom_filter_with_env(&check, "git push --force origin main", &env));
    }

    #[test]
    fn can_check_custom_filter_with_missing_capture_group() {
        // PathExists references group 5, but regex only has 1 group
        let filters = vec![Filter::PathExists(5)];

        let check = Check {
            id: "test-missing-group".to_string(),
            test: Regex::new("rm (.*)").unwrap(),
            description: "some description".to_string(),
            from: "test".to_string(),
            challenge: Challenge::default(),
            filters,
            alternative: None,
            alternative_info: None,
            severity: Severity::default(),
        };

        let env = crate::env::MockEnvironment::default();
        // Should return false (suppress check) because group 5 doesn't exist
        assert!(!check_custom_filter_with_env(&check, "rm /tmp/foo", &env));
    }

    #[test]
    fn can_check_multiple_filters_all_must_pass() {
        let filters = vec![
            Filter::NotContains("--dry-run".to_string()),
            Filter::NotContains("--check".to_string()),
        ];

        let check = Check {
            id: "id".to_string(),
            test: Regex::new("(delete)").unwrap(),
            description: "some description".to_string(),
            from: "test".to_string(),
            challenge: Challenge::default(),
            filters,
            alternative: None,
            alternative_info: None,
            severity: Severity::default(),
        };

        let env = crate::env::MockEnvironment::default();
        // Both absent → check fires
        assert!(check_custom_filter_with_env(&check, "delete", &env));
        // --dry-run present → suppressed
        assert!(!check_custom_filter_with_env(&check, "delete --dry-run", &env));
        // --check present → suppressed
        assert!(!check_custom_filter_with_env(&check, "delete --check", &env));
        // Both present → suppressed
        assert!(!check_custom_filter_with_env(&check, "delete --dry-run --check", &env));
    }

    #[test]
    fn can_get_all_checks() {
        assert_debug_snapshot!(get_all().is_ok());
    }

    #[test]
    fn test_split_command_and_and() {
        let parts = split_command("ls && rm -rf /");
        assert_eq!(parts, vec!["ls ", " rm -rf /"]);
    }

    #[test]
    fn test_split_command_pipe() {
        let parts = split_command("cat foo | grep bar");
        assert_eq!(parts, vec!["cat foo ", " grep bar"]);
    }

    #[test]
    fn test_split_command_mixed() {
        let parts = split_command("a && b || c; d");
        assert_eq!(parts, vec!["a ", " b ", " c", " d"]);
    }

    #[test]
    fn test_split_command_single() {
        let parts = split_command("git push -f");
        assert_eq!(parts, vec!["git push -f"]);
    }

    #[test]
    fn test_split_command_double_quoted_operator() {
        // Operators inside double quotes should NOT cause a split
        let parts = split_command(r#"echo "hello && world""#);
        assert_eq!(parts, vec![r#"echo "hello && world""#]);
    }

    #[test]
    fn test_split_command_single_quoted_pipe() {
        // Pipe inside single quotes should NOT cause a split
        let parts = split_command("echo 'a | b'");
        assert_eq!(parts, vec!["echo 'a | b'"]);
    }

    #[test]
    fn test_split_command_quoted_then_operator() {
        // Quoted section followed by a real operator
        let parts = split_command(r#"echo "safe" && rm -rf /"#);
        assert_eq!(parts, vec![r#"echo "safe" "#, " rm -rf /"]);
    }

    #[test]
    fn test_all_builtin_checks_pass_validation() {
        let checks = get_all().unwrap();
        let warnings = validate_checks(&checks);
        assert!(
            warnings.is_empty(),
            "Built-in checks have validation warnings:\n{}",
            warnings.join("\n")
        );
    }

    #[test]
    fn test_validate_catches_bad_capture_group() {
        let checks = vec![Check {
            id: "bad".to_string(),
            test: Regex::new("rm (.*)").unwrap(),
            description: "test".to_string(),
            from: "test".to_string(),
            challenge: Challenge::default(),
            filters: vec![Filter::PathExists(5)], // only 2 groups (0 + 1)
            alternative: None,
            alternative_info: None,
            severity: Severity::default(),
        }];
        let warnings = validate_checks(&checks);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("PathExists(5)"));
    }
}
