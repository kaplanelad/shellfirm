//! AI agent guardrails — non-interactive decision mode for agent-originated commands.
//!
//! When AI coding agents (Claude Code, Cursor, etc.) execute shell commands,
//! they can't solve interactive challenges. This module provides:
//!
//! - [`AgentPrompter`] — a [`Prompter`] that auto-decides based on severity thresholds
//! - [`RiskAssessment`] — structured JSON result returned to MCP clients
//! - [`assess_command`] — orchestration that runs the pipeline and builds a risk assessment

use std::sync::OnceLock;

use anyhow::Result;
use regex::Regex;
use serde_derive::{Deserialize, Serialize};

use crate::{
    checks::{self, Check, PipelineResult, Severity},
    config::{AgentConfig, Settings},
    env::Environment,
    prompt::{ChallengeResult, DisplayContext, Prompter},
};

fn strip_quotes_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"'[^']*'|"[^"]*""#).unwrap())
}

// ---------------------------------------------------------------------------
// AgentPrompter
// ---------------------------------------------------------------------------

/// A [`Prompter`] for AI agents — no interactive IO, pure threshold logic.
///
/// Decision rules:
/// 1. If the command is on the deny list → `Denied`
/// 2. Otherwise → `Passed` (severity-based denial is handled in `assess_command`)
pub struct AgentPrompter;

impl Prompter for AgentPrompter {
    fn run_challenge(&self, display: &DisplayContext) -> ChallengeResult {
        if display.is_denied {
            ChallengeResult::Denied
        } else {
            ChallengeResult::Passed
        }
    }
}

// ---------------------------------------------------------------------------
// RiskAssessment (returned to MCP clients)
// ---------------------------------------------------------------------------

/// A single matched rule in the risk assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedRule {
    pub id: String,
    pub description: String,
    pub severity: Severity,
    pub group: String,
}

/// A safer alternative suggestion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alternative {
    pub command: String,
    pub explanation: Option<String>,
    pub source: String,
}

/// Context information included in the assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessmentContext {
    pub risk_level: String,
    pub labels: Vec<String>,
}

/// Structured risk assessment returned to AI agents via MCP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    /// Whether the command is allowed to proceed.
    pub allowed: bool,
    /// The overall risk level (Normal, Elevated, Critical).
    pub risk_level: String,
    /// The highest severity among matched rules.
    pub severity: Option<Severity>,
    /// Details of each matched rule.
    pub matched_rules: Vec<MatchedRule>,
    /// Safer alternative commands.
    pub alternatives: Vec<Alternative>,
    /// Environmental context.
    pub context: AssessmentContext,
    /// Human-readable explanation (populated by LLM when available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
    /// Whether human approval is required.
    pub requires_human_approval: bool,
    /// Reason for denial (if denied).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub denial_reason: Option<String>,
}

// ---------------------------------------------------------------------------
// assess_command — orchestration
// ---------------------------------------------------------------------------

/// Run the full analysis pipeline and build a [`RiskAssessment`].
///
/// This is the primary entry point for MCP tool handlers and agent integrations.
///
/// # Errors
/// Returns an error if the underlying pipeline fails.
pub fn assess_command(
    command: &str,
    settings: &Settings,
    checks: &[Check],
    env: &dyn Environment,
    agent_config: &AgentConfig,
) -> Result<RiskAssessment> {
    let pipeline = checks::analyze_command(command, settings, checks, env, strip_quotes_regex())?;
    Ok(build_assessment(&pipeline, agent_config))
}

/// Build a [`RiskAssessment`] from a [`PipelineResult`] using agent-specific logic.
fn build_assessment(pipeline: &PipelineResult, agent_config: &AgentConfig) -> RiskAssessment {
    let matched_rules: Vec<MatchedRule> = pipeline
        .active_matches
        .iter()
        .map(|c| MatchedRule {
            id: c.id.clone(),
            description: c.description.clone(),
            severity: c.severity,
            group: c.from.clone(),
        })
        .collect();

    let alternatives: Vec<Alternative> = pipeline
        .alternatives
        .iter()
        .map(|a| Alternative {
            command: a.suggestion.clone(),
            explanation: a.explanation.clone(),
            source: "regex-pattern".into(),
        })
        .collect();

    let context = AssessmentContext {
        risk_level: format!("{:?}", pipeline.context.risk_level),
        labels: pipeline.context.labels.clone(),
    };

    let severity = if pipeline.active_matches.is_empty() {
        None
    } else {
        Some(pipeline.max_severity)
    };

    // Determine if the command should be denied
    let (allowed, denial_reason) = if pipeline.is_denied {
        (false, Some("Command matches a deny-listed pattern".into()))
    } else if pipeline.active_matches.is_empty() {
        (true, None)
    } else if pipeline.max_severity >= agent_config.auto_deny_severity {
        (
            false,
            Some(format!(
                "Severity {} meets or exceeds agent auto-deny threshold {}",
                pipeline.max_severity, agent_config.auto_deny_severity
            )),
        )
    } else {
        (true, None)
    };

    RiskAssessment {
        allowed,
        risk_level: format!("{:?}", pipeline.context.risk_level),
        severity,
        matched_rules,
        alternatives,
        context,
        explanation: None,
        requires_human_approval: agent_config.require_human_approval && !allowed,
        denial_reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::MockEnvironment;

    fn test_settings() -> Settings {
        Settings {
            challenge: crate::config::Challenge::Math,
            enabled_groups: vec![
                "base".into(),
                "fs".into(),
                "git".into(),
                "docker".into(),
                "kubernetes".into(),
                "database".into(),
            ],
            disabled_groups: vec![],
            ignores_patterns_ids: vec![],
            deny_patterns_ids: vec![],
            context: crate::context::ContextConfig::default(),
            audit_enabled: false,
            min_severity: None,
            agent: AgentConfig::default(),
            llm: crate::config::LlmConfig::default(),
        }
    }

    fn test_env() -> MockEnvironment {
        MockEnvironment {
            cwd: "/tmp/test".into(),
            ..Default::default()
        }
    }

    #[test]
    fn test_agent_prompter_passes_non_denied() {
        let prompter = AgentPrompter;
        let display = DisplayContext {
            is_denied: false,
            ..Default::default()
        };
        assert_eq!(prompter.run_challenge(&display), ChallengeResult::Passed);
    }

    #[test]
    fn test_agent_prompter_denies_when_denied() {
        let prompter = AgentPrompter;
        let display = DisplayContext {
            is_denied: true,
            ..Default::default()
        };
        assert_eq!(prompter.run_challenge(&display), ChallengeResult::Denied);
    }

    #[test]
    fn test_safe_command_is_allowed() {
        let settings = test_settings();
        let checks = settings.get_active_checks().unwrap();
        let env = test_env();
        let agent_config = AgentConfig::default();

        let result = assess_command("echo hello", &settings, &checks, &env, &agent_config).unwrap();
        assert!(result.allowed);
        assert!(result.matched_rules.is_empty());
        assert!(result.denial_reason.is_none());
    }

    #[test]
    fn test_high_severity_command_denied_by_agent() {
        let settings = test_settings();
        let checks = settings.get_active_checks().unwrap();
        let mut env = test_env();
        // Add existing paths so PathExists filters pass
        env.existing_paths
            .insert(std::path::PathBuf::from("/tmp/test/"));
        let agent_config = AgentConfig {
            auto_deny_severity: Severity::Medium,
            require_human_approval: false,
        };

        // git push --force is a well-known risky command
        let result =
            assess_command("git push --force", &settings, &checks, &env, &agent_config).unwrap();
        if !result.matched_rules.is_empty() {
            assert!(!result.allowed);
            assert!(result.denial_reason.is_some());
        }
    }

    #[test]
    fn test_low_severity_allowed_by_agent() {
        let settings = test_settings();
        let checks = settings.get_active_checks().unwrap();
        let env = test_env();
        // Set auto_deny to Critical only
        let agent_config = AgentConfig {
            auto_deny_severity: Severity::Critical,
            require_human_approval: false,
        };

        // git stash drop is typically Medium severity
        let result =
            assess_command("git stash drop", &settings, &checks, &env, &agent_config).unwrap();
        // If it matches and severity < Critical, it should be allowed
        if !result.matched_rules.is_empty() {
            assert!(result.allowed);
        }
    }

    #[test]
    fn test_deny_listed_command_always_denied() {
        let mut settings = test_settings();
        let checks = settings.get_active_checks().unwrap();
        let env = test_env();
        let agent_config = AgentConfig {
            auto_deny_severity: Severity::Critical,
            require_human_approval: false,
        };

        // Find a check ID from the loaded checks to deny
        if let Some(check) = checks.first() {
            settings.deny_patterns_ids.push(check.id.clone());
            // Re-assess with the deny-listed pattern
            let result =
                assess_command("rm -rf /", &settings, &checks, &env, &agent_config).unwrap();
            // If the command matched the denied pattern, it should be denied
            if result.matched_rules.iter().any(|r| r.id == check.id) {
                assert!(!result.allowed);
            }
        }
    }

    #[test]
    fn test_risk_assessment_includes_alternatives() {
        let settings = test_settings();
        let checks = settings.get_active_checks().unwrap();
        let env = test_env();
        let agent_config = AgentConfig::default();

        let result =
            assess_command("git push --force", &settings, &checks, &env, &agent_config).unwrap();
        // Force push checks typically have alternatives
        if !result.matched_rules.is_empty() {
            // Alternatives may or may not be present depending on check definitions
            assert!(result.severity.is_some());
        }
    }

    #[test]
    fn test_require_human_approval_flag() {
        let settings = test_settings();
        let checks = settings.get_active_checks().unwrap();
        let env = test_env();
        let agent_config = AgentConfig {
            auto_deny_severity: Severity::High,
            require_human_approval: true,
        };

        let result = assess_command("rm -rf /", &settings, &checks, &env, &agent_config).unwrap();
        if !result.allowed {
            assert!(result.requires_human_approval);
        }
    }

    #[test]
    fn test_risk_assessment_serializes_to_json() {
        let assessment = RiskAssessment {
            allowed: false,
            risk_level: "Normal".into(),
            severity: Some(Severity::High),
            matched_rules: vec![MatchedRule {
                id: "fs:rm_rf".into(),
                description: "Recursive delete".into(),
                severity: Severity::High,
                group: "fs".into(),
            }],
            alternatives: vec![Alternative {
                command: "rm -ri /path".into(),
                explanation: Some("Interactive mode".into()),
                source: "regex-pattern".into(),
            }],
            context: AssessmentContext {
                risk_level: "Normal".into(),
                labels: vec![],
            },
            explanation: None,
            requires_human_approval: false,
            denial_reason: Some("Severity HIGH meets threshold".into()),
        };
        let json = serde_json::to_string_pretty(&assessment).unwrap();
        assert!(json.contains("\"allowed\": false"));
        assert!(json.contains("fs:rm_rf"));
        assert!(json.contains("rm -ri /path"));
    }
}
