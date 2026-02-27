//! Runtime context detection.
//!
//! Detects environment signals (SSH, root, git branch, k8s context, etc.)
//! and computes a [`RiskLevel`] used to escalate challenge severity.

use serde_derive::{Deserialize, Serialize};
use tracing::debug;

use crate::{checks, config::Challenge, env::Environment};

/// Risk level computed from environment context signals.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskLevel {
    /// No risk signals detected.
    #[default]
    Normal,
    /// Moderate signals: SSH session, staging-like env, etc.
    Elevated,
    /// High-risk signals: root, production k8s, protected branch, production env.
    Critical,
}

/// Snapshot of environment context at the time a command is evaluated.
#[derive(Debug, Clone, Default)]
pub struct RuntimeContext {
    pub is_ssh: bool,
    pub is_root: bool,
    pub git_branch: Option<String>,
    pub k8s_context: Option<String>,
    pub env_signals: Vec<String>,
    pub risk_level: RiskLevel,
    /// Human-readable labels shown in the banner (e.g. "branch=main").
    pub labels: Vec<String>,
}

/// User-configurable context settings (stored in `settings.yaml`).
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ContextConfig {
    #[serde(default = "default_protected_branches")]
    pub protected_branches: Vec<String>,
    #[serde(default = "default_production_k8s_patterns")]
    pub production_k8s_patterns: Vec<String>,
    #[serde(default = "default_production_env_vars")]
    pub production_env_vars: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub sensitive_paths: Vec<String>,
    #[serde(default)]
    pub escalation: EscalationConfig,
}

fn default_protected_branches() -> Vec<String> {
    vec![
        "main".into(),
        "master".into(),
        "production".into(),
        "release/*".into(),
    ]
}

fn default_production_k8s_patterns() -> Vec<String> {
    vec![
        "prod".into(),
        "production".into(),
        "prd".into(),
        "live".into(),
    ]
}

fn default_production_env_vars() -> std::collections::BTreeMap<String, String> {
    let mut m = std::collections::BTreeMap::new();
    m.insert("NODE_ENV".into(), "production".into());
    m.insert("RAILS_ENV".into(), "production".into());
    m.insert("ENVIRONMENT".into(), "production".into());
    m
}

impl Default for ContextConfig {
    fn default() -> Self {
        Self {
            protected_branches: default_protected_branches(),
            production_k8s_patterns: default_production_k8s_patterns(),
            production_env_vars: default_production_env_vars(),
            sensitive_paths: vec![],
            escalation: EscalationConfig::default(),
        }
    }
}

/// Maps risk levels to the minimum challenge type.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct EscalationConfig {
    #[serde(default = "default_elevated_challenge")]
    pub elevated: Challenge,
    #[serde(default = "default_critical_challenge")]
    pub critical: Challenge,
}

const fn default_elevated_challenge() -> Challenge {
    Challenge::Enter
}
const fn default_critical_challenge() -> Challenge {
    Challenge::Yes
}

impl Default for EscalationConfig {
    fn default() -> Self {
        Self {
            elevated: default_elevated_challenge(),
            critical: default_critical_challenge(),
        }
    }
}

impl RuntimeContext {
    /// Return a filtered copy that only contains signals relevant to the
    /// matched check groups.
    ///
    /// **Global signals** (`is_ssh`, `is_root`, `env_signals`) are always
    /// kept — they apply regardless of what command matched.
    ///
    /// **Domain signals** are kept only when the corresponding group is
    /// present in `matched_groups`:
    /// - `git_branch` → `"git"`
    /// - `k8s_context` → `"kubernetes"`
    ///
    /// Labels and `risk_level` are recomputed from the kept signals.
    #[must_use]
    pub fn filter_for_groups(
        &self,
        matched_groups: &std::collections::HashSet<&str>,
        config: &ContextConfig,
    ) -> Self {
        let keep_git = matched_groups.contains("git");
        let keep_k8s = matched_groups.contains("kubernetes");

        let git_branch = if keep_git {
            self.git_branch.clone()
        } else {
            None
        };
        let k8s_context = if keep_k8s {
            self.k8s_context.clone()
        } else {
            None
        };

        // Rebuild labels from kept signals
        let mut labels = Vec::new();
        if self.is_ssh {
            labels.push("ssh=true".into());
        }
        if self.is_root {
            labels.push("root=true".into());
        }
        if let Some(ref branch) = git_branch {
            labels.push(format!("branch={branch}"));
        }
        if let Some(ref k8s) = k8s_context {
            labels.push(format!("k8s={k8s}"));
        }

        let filtered = Self {
            is_ssh: self.is_ssh,
            is_root: self.is_root,
            git_branch,
            k8s_context,
            env_signals: self.env_signals.clone(),
            risk_level: RiskLevel::Normal, // placeholder
            labels,
        };

        Self {
            risk_level: compute_risk_level(&filtered, config),
            ..filtered
        }
    }
}

/// Detect runtime context from the given environment.
///
/// This is called once per shellfirm invocation.
pub fn detect(env: &dyn Environment, config: &ContextConfig) -> RuntimeContext {
    let mut ctx = RuntimeContext {
        is_ssh: env.var("SSH_CONNECTION").is_some() || env.var("SSH_TTY").is_some(),
        ..RuntimeContext::default()
    };
    if ctx.is_ssh {
        ctx.labels.push("ssh=true".into());
    }

    // Root user
    ctx.is_root = env.var("EUID").is_some_and(|v| v == "0");
    if ctx.is_root {
        ctx.labels.push("root=true".into());
    }

    // Git branch
    ctx.git_branch = env.run_command("git", &["rev-parse", "--abbrev-ref", "HEAD"], 100);
    if let Some(ref branch) = ctx.git_branch {
        ctx.labels.push(format!("branch={branch}"));
    }

    // Kubernetes context
    ctx.k8s_context = env.run_command("kubectl", &["config", "current-context"], 100);
    if let Some(ref k8s) = ctx.k8s_context {
        ctx.labels.push(format!("k8s={k8s}"));
    }

    // Production environment variables
    for (key, expected_val) in &config.production_env_vars {
        if let Some(val) = env.var(key) {
            if val.eq_ignore_ascii_case(expected_val) {
                ctx.env_signals.push(format!("{key}={val}"));
            }
        }
    }

    // Compute risk level
    ctx.risk_level = compute_risk_level(&ctx, config);

    debug!("detected context: {ctx:?}");
    ctx
}

/// Compute the aggregate risk level from context signals.
pub(crate) fn compute_risk_level(ctx: &RuntimeContext, config: &ContextConfig) -> RiskLevel {
    // Critical signals
    if ctx.is_root {
        return RiskLevel::Critical;
    }
    if let Some(ref branch) = ctx.git_branch {
        if branch_matches_any(branch, &config.protected_branches) {
            return RiskLevel::Critical;
        }
    }
    if let Some(ref k8s) = ctx.k8s_context {
        if matches_any_pattern(k8s, &config.production_k8s_patterns) {
            return RiskLevel::Critical;
        }
    }
    if !ctx.env_signals.is_empty() {
        return RiskLevel::Critical;
    }

    // Elevated signals
    if ctx.is_ssh {
        return RiskLevel::Elevated;
    }

    RiskLevel::Normal
}

/// Check if a branch name matches any of the given branch patterns.
/// Supports exact matches and wildcard prefixes like `"release/*"`.
#[must_use]
pub fn branch_matches_any(branch: &str, patterns: &[String]) -> bool {
    for pattern in patterns {
        if pattern.ends_with("/*") {
            let prefix = &pattern[..pattern.len() - 1]; // "release/"
            if branch.starts_with(prefix) {
                return true;
            }
        } else if branch == pattern {
            return true;
        }
    }
    false
}

/// Check if a string contains any of the given substrings (case-insensitive).
fn matches_any_pattern(value: &str, patterns: &[String]) -> bool {
    let lower = value.to_ascii_lowercase();
    patterns
        .iter()
        .any(|p| lower.contains(p.to_ascii_lowercase().as_str()))
}

/// Given a base challenge level and a risk level, return the escalated
/// challenge. Escalation can only make things **stricter**, never weaker.
#[must_use]
pub fn escalate_challenge(
    base: &Challenge,
    risk_level: RiskLevel,
    escalation: &EscalationConfig,
) -> Challenge {
    let context_min = match risk_level {
        RiskLevel::Normal => return *base,
        RiskLevel::Elevated => &escalation.elevated,
        RiskLevel::Critical => &escalation.critical,
    };

    // Return the stricter of the two
    checks::max_challenge(*base, *context_min)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::MockEnvironment;
    use std::collections::HashMap;

    fn default_config() -> ContextConfig {
        ContextConfig::default()
    }

    #[test]
    fn test_detect_normal_context() {
        let env = MockEnvironment {
            cwd: "/Users/dev/project".into(),
            ..Default::default()
        };
        let ctx = detect(&env, &default_config());
        assert_eq!(ctx.risk_level, RiskLevel::Normal);
        assert!(!ctx.is_ssh);
        assert!(!ctx.is_root);
    }

    #[test]
    fn test_detect_ssh_session() {
        let mut env_vars = HashMap::new();
        env_vars.insert("SSH_CONNECTION".into(), "10.0.0.1 22 10.0.0.2 54321".into());
        let env = MockEnvironment {
            env_vars,
            cwd: "/home/user".into(),
            ..Default::default()
        };
        let ctx = detect(&env, &default_config());
        assert!(ctx.is_ssh);
        assert_eq!(ctx.risk_level, RiskLevel::Elevated);
    }

    #[test]
    fn test_detect_root_user() {
        let mut env_vars = HashMap::new();
        env_vars.insert("EUID".into(), "0".into());
        let env = MockEnvironment {
            env_vars,
            cwd: "/root".into(),
            ..Default::default()
        };
        let ctx = detect(&env, &default_config());
        assert!(ctx.is_root);
        assert_eq!(ctx.risk_level, RiskLevel::Critical);
    }

    #[test]
    fn test_detect_protected_branch() {
        let mut cmd_outputs = HashMap::new();
        cmd_outputs.insert("git rev-parse --abbrev-ref HEAD".into(), "main".into());
        let env = MockEnvironment {
            command_outputs: cmd_outputs,
            cwd: "/repo".into(),
            ..Default::default()
        };
        let ctx = detect(&env, &default_config());
        assert_eq!(ctx.git_branch, Some("main".into()));
        assert_eq!(ctx.risk_level, RiskLevel::Critical);
    }

    #[test]
    fn test_detect_production_k8s() {
        let mut cmd_outputs = HashMap::new();
        cmd_outputs.insert(
            "kubectl config current-context".into(),
            "prod-us-east-1".into(),
        );
        let env = MockEnvironment {
            command_outputs: cmd_outputs,
            cwd: "/app".into(),
            ..Default::default()
        };
        let ctx = detect(&env, &default_config());
        assert_eq!(ctx.k8s_context, Some("prod-us-east-1".into()));
        assert_eq!(ctx.risk_level, RiskLevel::Critical);
    }

    #[test]
    fn test_detect_production_env() {
        let mut env_vars = HashMap::new();
        env_vars.insert("NODE_ENV".into(), "production".into());
        let env = MockEnvironment {
            env_vars,
            cwd: "/app".into(),
            ..Default::default()
        };
        let ctx = detect(&env, &default_config());
        assert_eq!(ctx.risk_level, RiskLevel::Critical);
        assert_eq!(ctx.env_signals, vec!["NODE_ENV=production"]);
    }

    #[test]
    fn test_feature_branch_is_normal() {
        let mut cmd_outputs = HashMap::new();
        cmd_outputs.insert(
            "git rev-parse --abbrev-ref HEAD".into(),
            "feature/my-thing".into(),
        );
        let env = MockEnvironment {
            command_outputs: cmd_outputs,
            cwd: "/repo".into(),
            ..Default::default()
        };
        let ctx = detect(&env, &default_config());
        assert_eq!(ctx.risk_level, RiskLevel::Normal);
    }

    #[test]
    fn test_release_wildcard_branch() {
        let mut cmd_outputs = HashMap::new();
        cmd_outputs.insert(
            "git rev-parse --abbrev-ref HEAD".into(),
            "release/v2.0".into(),
        );
        let env = MockEnvironment {
            command_outputs: cmd_outputs,
            cwd: "/repo".into(),
            ..Default::default()
        };
        let ctx = detect(&env, &default_config());
        assert_eq!(ctx.risk_level, RiskLevel::Critical);
    }

    #[test]
    fn test_escalate_challenge_normal() {
        let esc = EscalationConfig::default();
        assert_eq!(
            escalate_challenge(&Challenge::Math, RiskLevel::Normal, &esc),
            Challenge::Math
        );
    }

    #[test]
    fn test_escalate_challenge_elevated() {
        let esc = EscalationConfig::default();
        assert_eq!(
            escalate_challenge(&Challenge::Math, RiskLevel::Elevated, &esc),
            Challenge::Enter
        );
    }

    #[test]
    fn test_escalate_challenge_critical() {
        let esc = EscalationConfig::default();
        assert_eq!(
            escalate_challenge(&Challenge::Math, RiskLevel::Critical, &esc),
            Challenge::Yes
        );
    }

    #[test]
    fn test_escalate_cannot_lower() {
        let esc = EscalationConfig::default();
        // Yes is already stricter than Enter (elevated escalation)
        assert_eq!(
            escalate_challenge(&Challenge::Yes, RiskLevel::Elevated, &esc),
            Challenge::Yes
        );
    }

    // -----------------------------------------------------------------------
    // filter_for_groups tests
    // -----------------------------------------------------------------------

    fn full_context() -> RuntimeContext {
        RuntimeContext {
            is_ssh: true,
            is_root: false,
            git_branch: Some("main".into()),
            k8s_context: Some("prod-us-east-1".into()),
            env_signals: vec!["NODE_ENV=production".into()],
            risk_level: RiskLevel::Critical,
            labels: vec![
                "ssh=true".into(),
                "branch=main".into(),
                "k8s=prod-us-east-1".into(),
            ],
        }
    }

    #[test]
    fn test_filter_git_command_hides_k8s() {
        let ctx = full_context();
        let groups: std::collections::HashSet<&str> = ["git"].into_iter().collect();
        let filtered = ctx.filter_for_groups(&groups, &default_config());

        assert_eq!(filtered.git_branch, Some("main".into()));
        assert!(filtered.k8s_context.is_none());
        assert!(filtered.labels.contains(&"branch=main".to_string()));
        assert!(!filtered.labels.iter().any(|l| l.starts_with("k8s=")));
    }

    #[test]
    fn test_filter_k8s_command_hides_branch() {
        let ctx = full_context();
        let groups: std::collections::HashSet<&str> = ["kubernetes"].into_iter().collect();
        let filtered = ctx.filter_for_groups(&groups, &default_config());

        assert!(filtered.git_branch.is_none());
        assert_eq!(filtered.k8s_context, Some("prod-us-east-1".into()));
        assert!(!filtered.labels.iter().any(|l| l.starts_with("branch=")));
        assert!(filtered.labels.contains(&"k8s=prod-us-east-1".to_string()));
    }

    #[test]
    fn test_filter_fs_command_global_only() {
        let ctx = full_context();
        let groups: std::collections::HashSet<&str> = ["fs"].into_iter().collect();
        let filtered = ctx.filter_for_groups(&groups, &default_config());

        assert!(filtered.git_branch.is_none());
        assert!(filtered.k8s_context.is_none());
        assert!(filtered.is_ssh);
        assert!(filtered.labels.contains(&"ssh=true".to_string()));
        assert!(!filtered.labels.iter().any(|l| l.starts_with("branch=")));
        assert!(!filtered.labels.iter().any(|l| l.starts_with("k8s=")));
    }

    #[test]
    fn test_filter_compound_git_and_k8s() {
        let ctx = full_context();
        let groups: std::collections::HashSet<&str> = ["git", "kubernetes"].into_iter().collect();
        let filtered = ctx.filter_for_groups(&groups, &default_config());

        assert_eq!(filtered.git_branch, Some("main".into()));
        assert_eq!(filtered.k8s_context, Some("prod-us-east-1".into()));
        assert!(filtered.labels.contains(&"branch=main".to_string()));
        assert!(filtered.labels.contains(&"k8s=prod-us-east-1".to_string()));
    }

    #[test]
    fn test_filter_global_signals_never_hidden() {
        let ctx = RuntimeContext {
            is_ssh: true,
            is_root: true,
            git_branch: Some("main".into()),
            k8s_context: Some("prod".into()),
            env_signals: vec!["NODE_ENV=production".into()],
            risk_level: RiskLevel::Critical,
            labels: vec![
                "ssh=true".into(),
                "root=true".into(),
                "branch=main".into(),
                "k8s=prod".into(),
            ],
        };
        // Even with an unrelated group, SSH, root, and env_signals remain
        let groups: std::collections::HashSet<&str> = ["fs"].into_iter().collect();
        let filtered = ctx.filter_for_groups(&groups, &default_config());

        assert!(filtered.is_ssh);
        assert!(filtered.is_root);
        assert_eq!(filtered.env_signals, vec!["NODE_ENV=production"]);
        assert!(filtered.labels.contains(&"ssh=true".to_string()));
        assert!(filtered.labels.contains(&"root=true".to_string()));
    }

    #[test]
    fn test_filter_risk_level_recomputed() {
        // Context with only branch=main making it Critical
        let ctx = RuntimeContext {
            is_ssh: false,
            is_root: false,
            git_branch: Some("main".into()),
            k8s_context: None,
            env_signals: vec![],
            risk_level: RiskLevel::Critical,
            labels: vec!["branch=main".into()],
        };
        // Matched groups: {"fs"} — branch is irrelevant, so risk drops
        let groups: std::collections::HashSet<&str> = ["fs"].into_iter().collect();
        let filtered = ctx.filter_for_groups(&groups, &default_config());

        assert!(filtered.git_branch.is_none());
        assert_eq!(filtered.risk_level, RiskLevel::Normal);
    }
}
