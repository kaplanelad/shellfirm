//! Runtime context detection.
//!
//! Detects environment signals (SSH, root, git branch, k8s context, etc.)
//! and computes a [`RiskLevel`] used to escalate challenge severity.

use log::debug;
use serde_derive::{Deserialize, Serialize};

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
            if val.to_lowercase() == expected_val.to_lowercase() {
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
fn compute_risk_level(ctx: &RuntimeContext, config: &ContextConfig) -> RiskLevel {
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
    let lower = value.to_lowercase();
    patterns.iter().any(|p| lower.contains(&p.to_lowercase()))
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
}
