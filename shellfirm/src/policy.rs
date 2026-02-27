//! Project-level policies (`.shellfirm.yaml`).
//!
//! A `.shellfirm.yaml` file committed to a repository lets teams codify
//! safety rules that travel with the code. Policies are **additive only** —
//! they can escalate severity or add deny-listed patterns, but can never
//! weaken global protections.

use std::path::Path;

use crate::error::Result;
use serde_derive::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::{
    checks::{self, Check},
    config::{Challenge, Settings},
    context::ContextConfig,
    env::Environment,
};

/// The canonical filename searched for when walking up directories.
pub const POLICY_FILENAME: &str = ".shellfirm.yaml";

/// A project-level policy loaded from `.shellfirm.yaml`.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct ProjectPolicy {
    /// Schema version (currently `1`). Required field.
    pub version: u32,
    /// Additional check patterns specific to this project.
    #[serde(default)]
    pub checks: Vec<Check>,
    /// Override severity for existing patterns.
    #[serde(default)]
    pub overrides: Vec<Override>,
    /// Pattern IDs that are unconditionally denied in this project.
    #[serde(default)]
    pub deny: Vec<String>,
    /// Project-specific context configuration (merged with global).
    #[serde(default)]
    pub context: Option<ContextConfig>,
}

/// A severity override for a single pattern in this project.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Override {
    /// The pattern ID to override (e.g. `"git:force_push"`).
    pub id: String,
    /// The new challenge level (must be >= the current level).
    #[serde(default)]
    pub challenge: Option<Challenge>,
    /// Optional: only apply this override when on specific branches.
    #[serde(default)]
    pub on_branches: Option<Vec<String>>,
}

/// Discover a `.shellfirm.yaml` file by walking up from `start_dir`.
pub fn discover(env: &dyn Environment, start_dir: &Path) -> Option<ProjectPolicy> {
    let path = env.find_file_upward(start_dir, POLICY_FILENAME)?;
    debug!("found project policy at: {}", path.display());

    let content = match env.read_file(&path) {
        Ok(c) => c,
        Err(e) => {
            warn!("could not read policy file {}: {}", path.display(), e);
            return None;
        }
    };

    match parse_policy(&content) {
        Ok(policy) => Some(policy),
        Err(e) => {
            warn!("invalid policy file {}: {}", path.display(), e);
            None
        }
    }
}

/// Parse a policy YAML string.
///
/// # Errors
/// Returns an error if the YAML is invalid.
pub fn parse_policy(content: &str) -> Result<ProjectPolicy> {
    Ok(serde_yaml::from_str(content)?)
}

/// Merge a project policy into the effective settings.
///
/// **Additive-only rule**: policies can only make things stricter.
/// - New checks are appended.
/// - Deny-list entries are merged (union).
/// - Challenge overrides are applied only if they escalate.
#[must_use]
pub fn merge_into_settings(
    _settings: &Settings,
    policy: &ProjectPolicy,
    current_branch: Option<&str>,
) -> MergedPolicy {
    let extra_checks = policy.checks.clone();
    let extra_deny: Vec<String> = policy.deny.clone();
    let mut challenge_overrides: std::collections::HashMap<String, Challenge> =
        std::collections::HashMap::new();

    for ov in &policy.overrides {
        // If on_branches is specified, only apply when on a matching branch
        if let Some(ref branches) = ov.on_branches {
            if let Some(branch) = current_branch {
                if !branch_matches(branch, branches) {
                    continue;
                }
            } else {
                continue; // No branch info, skip branch-specific override
            }
        }

        if let Some(ref ch) = ov.challenge {
            challenge_overrides.insert(ov.id.clone(), *ch);
        }
    }

    MergedPolicy {
        extra_checks,
        extra_deny,
        challenge_overrides,
    }
}

/// The result of merging a project policy. Consumed by the pipeline.
#[derive(Debug, Clone, Default)]
pub struct MergedPolicy {
    /// Additional checks from the project policy.
    pub extra_checks: Vec<Check>,
    /// Additional deny-listed pattern IDs.
    pub extra_deny: Vec<String>,
    /// Challenge overrides (`pattern_id` → new challenge).
    /// These are only applied if they **escalate** (see `effective_challenge`).
    pub challenge_overrides: std::collections::HashMap<String, Challenge>,
}

impl MergedPolicy {
    /// Get the effective challenge for a pattern, respecting the
    /// additive-only rule. Returns the stricter of: base challenge,
    /// context-escalated challenge, or policy override.
    #[must_use]
    pub fn effective_challenge(&self, pattern_id: &str, base: &Challenge) -> Challenge {
        self.challenge_overrides
            .get(pattern_id)
            .map_or(*base, |&override_ch| {
                checks::max_challenge(*base, override_ch)
            })
    }

    /// Check if a pattern ID is in the project deny list.
    #[must_use]
    pub fn is_denied(&self, pattern_id: &str) -> bool {
        self.extra_deny.iter().any(|id| id == pattern_id)
    }
}

/// Reuse the shared branch-matching helper from the context module.
fn branch_matches(branch: &str, patterns: &[String]) -> bool {
    crate::context::branch_matches_any(branch, patterns)
}

/// Generate a default `.shellfirm.yaml` template.
#[must_use]
pub fn scaffold_policy() -> String {
    r#"# shellfirm project policy
# Docs: https://github.com/kaplanelad/shellfirm
version: 1

# Additional patterns specific to this project
checks: []

# Override severity for existing patterns
# overrides:
#   - id: git:force_push
#     challenge: Deny
#   - id: git:reset
#     on_branches: [main, master]
#     challenge: Yes

# Patterns that are unconditionally denied in this project
deny: []
#   - git:force_push
#   - kubernetes:delete_namespace

# Project-specific context settings
# context:
#   protected_branches: [main, master, develop, "release/*"]
#   production_k8s_patterns: [prod, production]
"#
    .to_string()
}

/// Validate a policy file and return a list of warnings.
///
/// # Errors
/// Returns an error if the YAML is invalid.
pub fn validate_policy(content: &str) -> Result<Vec<String>> {
    let policy: ProjectPolicy = serde_yaml::from_str(content)?;
    let mut warnings = Vec::new();

    if policy.version != 1 {
        warnings.push(format!(
            "Unknown policy version: {}. Only version 1 is supported.",
            policy.version
        ));
    }

    for check in &policy.checks {
        if check.id.is_empty() {
            warnings.push("Check pattern has empty id.".into());
        }
        if check.description.is_empty() {
            warnings.push(format!(
                "Check pattern '{}' has empty description.",
                check.id
            ));
        }
    }

    for ov in &policy.overrides {
        if ov.id.is_empty() {
            warnings.push("Override has empty id.".into());
        }
    }

    Ok(warnings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::MockEnvironment;
    use std::collections::HashMap;
    use std::path::PathBuf;

    #[test]
    fn test_parse_simple_policy() {
        let yaml = r#"
version: 1
deny:
  - git:force_push
  - kubernetes:delete_namespace
"#;
        let policy = parse_policy(yaml).unwrap();
        assert_eq!(policy.version, 1);
        assert_eq!(policy.deny.len(), 2);
        assert!(policy.deny.contains(&"git:force_push".to_string()));
    }

    #[test]
    fn test_discover_policy_walks_up() {
        let mut files = HashMap::new();
        files.insert(
            PathBuf::from("/repo/.shellfirm.yaml"),
            "version: 1\ndeny:\n  - git:force_push\n".into(),
        );
        let env = MockEnvironment {
            cwd: PathBuf::from("/repo/src/deep/nested"),
            files,
            ..Default::default()
        };
        let policy = discover(&env, &env.cwd);
        assert!(policy.is_some());
        assert!(policy.unwrap().deny.contains(&"git:force_push".to_string()));
    }

    #[test]
    fn test_discover_no_policy() {
        let env = MockEnvironment {
            cwd: PathBuf::from("/home/user/project"),
            ..Default::default()
        };
        let policy = discover(&env, &env.cwd);
        assert!(policy.is_none());
    }

    #[test]
    fn test_merge_adds_deny() {
        let settings = Settings {
            challenge: Challenge::Math,
            enabled_groups: vec![],
            disabled_groups: vec![],
            ignores_patterns_ids: vec![],
            deny_patterns_ids: vec![],
            context: crate::context::ContextConfig::default(),
            audit_enabled: false,
            blast_radius: true,
            min_severity: None,
            agent: crate::config::AgentConfig::default(),
            llm: None,
            wrappers: crate::config::WrappersConfig::default(),
        };
        let policy = ProjectPolicy {
            version: 1,
            deny: vec!["git:force_push".into()],
            ..Default::default()
        };
        let merged = merge_into_settings(&settings, &policy, None);
        assert!(merged.is_denied("git:force_push"));
    }

    #[test]
    fn test_effective_challenge_escalates() {
        let mut overrides = std::collections::HashMap::new();
        overrides.insert("git:reset".into(), Challenge::Yes);
        let merged = MergedPolicy {
            challenge_overrides: overrides,
            ..Default::default()
        };
        assert_eq!(
            merged.effective_challenge("git:reset", &Challenge::Math),
            Challenge::Yes
        );
    }

    #[test]
    fn test_effective_challenge_cannot_weaken() {
        let mut overrides = std::collections::HashMap::new();
        // Policy tries to lower from Yes to Enter
        overrides.insert("git:reset".into(), Challenge::Enter);
        let merged = MergedPolicy {
            challenge_overrides: overrides,
            ..Default::default()
        };
        // Should stay at Yes (the base is stricter)
        assert_eq!(
            merged.effective_challenge("git:reset", &Challenge::Yes),
            Challenge::Yes
        );
    }

    #[test]
    fn test_branch_specific_override() {
        let settings = Settings {
            challenge: Challenge::Math,
            enabled_groups: vec![],
            disabled_groups: vec![],
            ignores_patterns_ids: vec![],
            deny_patterns_ids: vec![],
            context: crate::context::ContextConfig::default(),
            audit_enabled: false,
            blast_radius: true,
            min_severity: None,
            agent: crate::config::AgentConfig::default(),
            llm: None,
            wrappers: crate::config::WrappersConfig::default(),
        };
        let policy = ProjectPolicy {
            version: 1,
            overrides: vec![Override {
                id: "git:reset".into(),
                challenge: Some(Challenge::Yes),
                on_branches: Some(vec!["main".into(), "master".into()]),
            }],
            ..Default::default()
        };

        // On main → override applies
        let merged = merge_into_settings(&settings, &policy, Some("main"));
        assert_eq!(
            merged.effective_challenge("git:reset", &Challenge::Math),
            Challenge::Yes
        );

        // On feature branch → override does not apply
        let merged = merge_into_settings(&settings, &policy, Some("feature/foo"));
        assert_eq!(
            merged.effective_challenge("git:reset", &Challenge::Math),
            Challenge::Math
        );
    }

    #[test]
    fn test_validate_policy() {
        let yaml = "version: 1\ndeny:\n  - git:force_push\n";
        let warnings = validate_policy(yaml).unwrap();
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_validate_policy_bad_version() {
        let yaml = "version: 99\n";
        let warnings = validate_policy(yaml).unwrap();
        assert!(!warnings.is_empty());
    }

    #[test]
    fn test_scaffold_policy() {
        let yaml = scaffold_policy();
        assert!(yaml.contains("version: 1"));
        assert!(yaml.contains("deny:"));
    }
}
