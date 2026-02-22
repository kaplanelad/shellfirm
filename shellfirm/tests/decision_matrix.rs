//! Tier 3: Decision Matrix — YAML-driven test scenarios.
//!
//! Each scenario defines a (command, context, policy) tuple and the
//! expected outcome. This is the single source of truth for shellfirm's
//! product behavior. Anyone can add scenarios without writing Rust code.

use std::{collections::HashMap, path::PathBuf};

use serde_derive::Deserialize;
use shellfirm::{
    checks,
    context::{self, ContextConfig, RiskLevel},
    env::MockEnvironment,
    policy::{self, MergedPolicy, ProjectPolicy},
    prompt::MockPrompter,
    Challenge, Settings,
};

// ---------------------------------------------------------------------------
// YAML schema
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct Scenario {
    name: String,
    command: String,
    #[serde(default)]
    context: ScenarioContext,
    #[serde(default)]
    policy: Option<ScenarioPolicy>,
    expected: Expected,
}

#[derive(Debug, Deserialize, Default)]
struct ScenarioContext {
    #[serde(default)]
    ssh: Option<bool>,
    #[serde(default)]
    root: Option<bool>,
    #[serde(default)]
    git_branch: Option<String>,
    #[serde(default)]
    k8s_context: Option<String>,
    #[serde(default)]
    env: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct ScenarioPolicy {
    #[serde(default)]
    deny: Vec<String>,
    #[serde(default)]
    overrides: Vec<ScenarioOverride>,
    #[serde(default)]
    checks: Vec<serde_yaml::Value>,
}

#[derive(Debug, Deserialize)]
struct ScenarioOverride {
    id: String,
    #[serde(default)]
    challenge: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Expected {
    #[serde(default)]
    matched_ids: Vec<String>,
    #[serde(default)]
    effective_challenge: Option<String>,
    #[serde(default)]
    risk_level: Option<String>,
    #[serde(default)]
    is_denied: Option<bool>,
    #[serde(default)]
    alternative_shown: Option<String>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

impl ScenarioContext {
    fn to_mock_environment(&self) -> MockEnvironment {
        let mut env_vars: HashMap<String, String> = HashMap::new();

        if self.ssh == Some(true) {
            env_vars.insert("SSH_CONNECTION".into(), "10.0.0.1 22".into());
        }
        if self.root == Some(true) {
            env_vars.insert("EUID".into(), "0".into());
        }
        if let Some(ref env_map) = self.env {
            for (k, v) in env_map {
                env_vars.insert(k.clone(), v.clone());
            }
        }

        let mut command_outputs = HashMap::new();
        if let Some(ref branch) = self.git_branch {
            command_outputs.insert("git rev-parse --abbrev-ref HEAD".into(), branch.clone());
        }
        if let Some(ref k8s) = self.k8s_context {
            command_outputs.insert("kubectl config current-context".into(), k8s.clone());
        }

        MockEnvironment {
            env_vars,
            cwd: PathBuf::from("/mock/workspace"),
            command_outputs,
            ..Default::default()
        }
    }
}

fn parse_challenge(s: &str) -> Challenge {
    match s {
        "Math" => Challenge::Math,
        "Enter" => Challenge::Enter,
        "Yes" => Challenge::Yes,
        other => panic!("Unknown challenge type: {}", other),
    }
}

fn parse_risk_level(s: &str) -> RiskLevel {
    match s {
        "Normal" => RiskLevel::Normal,
        "Elevated" => RiskLevel::Elevated,
        "Critical" => RiskLevel::Critical,
        other => panic!("Unknown risk level: {}", other),
    }
}

fn default_settings() -> Settings {
    Settings {
        challenge: Challenge::Math,
        enabled_groups: vec![
            "base".into(),
            "fs".into(),
            "git".into(),
            "kubernetes".into(),
            "docker".into(),
            "aws".into(),
            "gcp".into(),
            "azure".into(),
            "database".into(),
            "terraform".into(),
            "heroku".into(),
            "network".into(),
        ],
        disabled_groups: vec![],
        ignores_patterns_ids: vec![],
        deny_patterns_ids: vec![],
        context: ContextConfig::default(),
        audit_enabled: false,
        blast_radius: true,
        min_severity: None,
        agent: shellfirm::AgentConfig::default(),
        llm: shellfirm::LlmConfig::default(),
        wrappers: shellfirm::WrappersConfig::default(),
    }
}

fn scenario_to_project_policy(sp: &ScenarioPolicy) -> ProjectPolicy {
    let overrides = sp
        .overrides
        .iter()
        .map(|o| policy::Override {
            id: o.id.clone(),
            challenge: o.challenge.as_ref().map(|c| parse_challenge(c)),
            on_branches: None,
        })
        .collect();

    ProjectPolicy {
        version: 1,
        deny: sp.deny.clone(),
        overrides,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Test runner
// ---------------------------------------------------------------------------

#[test]
fn test_decision_matrix() {
    let yaml_content =
        std::fs::read_to_string("tests/decisions/matrix.yaml").expect("could not read matrix.yaml");
    let scenarios: Vec<Scenario> =
        serde_yaml::from_str(&yaml_content).expect("could not parse matrix.yaml");

    let settings = default_settings();
    let all_checks = settings.get_active_checks().unwrap();

    for scenario in &scenarios {
        let env = scenario.context.to_mock_environment();
        let prompter = MockPrompter::passing();

        // Split and check
        let parts = checks::split_command(&scenario.command);
        let matches: Vec<&checks::Check> = parts
            .iter()
            .flat_map(|c| checks::run_check_on_command_with_env(&all_checks, c, &env))
            .collect();

        let matched_ids: Vec<String> = matches.iter().map(|c| c.id.clone()).collect();

        // Assert matched IDs
        for expected_id in &scenario.expected.matched_ids {
            assert!(
                matched_ids.contains(expected_id),
                "FAILED [{}]: expected pattern '{}' in matches {:?}",
                scenario.name,
                expected_id,
                matched_ids
            );
        }

        // If no matches expected, verify
        if scenario.expected.matched_ids.is_empty() && matches.is_empty() {
            continue; // Safe command, no further checks needed
        }

        if matches.is_empty() {
            // Expected matches but got none — this is a failure
            if !scenario.expected.matched_ids.is_empty() {
                panic!(
                    "FAILED [{}]: expected matches {:?} but got none",
                    scenario.name, scenario.expected.matched_ids
                );
            }
            continue;
        }

        // Detect context
        let runtime_context = context::detect(&env, &settings.context);

        // Build policy
        let project_policy = scenario.policy.as_ref().map(scenario_to_project_policy);
        let merged_policy = if let Some(ref pp) = project_policy {
            policy::merge_into_settings(&settings, pp, runtime_context.git_branch.as_deref())
        } else {
            MergedPolicy::default()
        };

        // Run challenge
        let _result = checks::challenge_with_context(
            &settings.challenge,
            &matches,
            &settings.deny_patterns_ids,
            &runtime_context,
            &merged_policy,
            &settings.context.escalation,
            &prompter,
            &[],
        )
        .unwrap();

        let displays = prompter.captured_displays.borrow();
        assert_eq!(
            displays.len(),
            1,
            "FAILED [{}]: expected exactly one display",
            scenario.name
        );
        let display = &displays[0];

        // Assert risk level
        if let Some(ref expected_rl) = scenario.expected.risk_level {
            let expected = parse_risk_level(expected_rl);
            assert_eq!(
                runtime_context.risk_level, expected,
                "FAILED [{}]: wrong risk level (got {:?}, expected {:?})",
                scenario.name, runtime_context.risk_level, expected
            );
        }

        // Assert effective challenge
        if let Some(ref expected_ch) = scenario.expected.effective_challenge {
            let expected = parse_challenge(expected_ch);
            assert_eq!(
                display.effective_challenge, expected,
                "FAILED [{}]: wrong effective challenge (got {:?}, expected {:?})",
                scenario.name, display.effective_challenge, expected
            );
        }

        // Assert denied
        if let Some(expected_denied) = scenario.expected.is_denied {
            assert_eq!(
                display.is_denied, expected_denied,
                "FAILED [{}]: wrong is_denied (got {}, expected {})",
                scenario.name, display.is_denied, expected_denied
            );
        }

        // Assert alternative shown
        if let Some(ref expected_alt) = scenario.expected.alternative_shown {
            assert!(
                display
                    .alternatives
                    .iter()
                    .any(|a| a.suggestion.contains(expected_alt.as_str())),
                "FAILED [{}]: alternative '{}' not shown (got {:?})",
                scenario.name,
                expected_alt,
                display
                    .alternatives
                    .iter()
                    .map(|a| &a.suggestion)
                    .collect::<Vec<_>>()
            );
        }
    }
}
