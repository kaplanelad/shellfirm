//! Tier 2: Sandboxed integration tests — full pipeline with MockEnvironment + MockPrompter.
//!
//! These test the complete command processing pipeline end-to-end with
//! **zero real system access**. The mock environment provides virtual
//! filesystem, env vars, and command outputs.

use std::{collections::HashMap, path::PathBuf};

use serde_json;
use shellfirm::{
    checks,
    context::{self, ContextConfig},
    env::MockEnvironment,
    policy::{self, MergedPolicy, ProjectPolicy},
    prompt::{ChallengeResult, MockPrompter},
    Challenge, Settings,
};

// ---------------------------------------------------------------------------
// Test helpers — mock environment builders
// ---------------------------------------------------------------------------

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
    }
}

fn mock_env_production_ssh() -> MockEnvironment {
    let mut env_vars = HashMap::new();
    env_vars.insert("SSH_CONNECTION".into(), "10.0.0.1 22 10.0.0.2 54321".into());
    env_vars.insert("NODE_ENV".into(), "production".into());

    let mut command_outputs = HashMap::new();
    command_outputs.insert("git rev-parse --abbrev-ref HEAD".into(), "main".into());
    command_outputs.insert(
        "kubectl config current-context".into(),
        "prod-us-east-1".into(),
    );

    MockEnvironment {
        env_vars,
        cwd: PathBuf::from("/var/app/deploy"),
        existing_paths: Default::default(),
        command_outputs,
        files: Default::default(),
        home: Some(PathBuf::from("/home/deploy")),
    }
}

fn mock_env_local_dev() -> MockEnvironment {
    let mut env_vars = HashMap::new();
    env_vars.insert("NODE_ENV".into(), "development".into());

    let mut command_outputs = HashMap::new();
    command_outputs.insert(
        "git rev-parse --abbrev-ref HEAD".into(),
        "feature/my-thing".into(),
    );
    command_outputs.insert("kubectl config current-context".into(), "minikube".into());

    MockEnvironment {
        env_vars,
        cwd: PathBuf::from("/Users/dev/project"),
        existing_paths: Default::default(),
        command_outputs,
        files: Default::default(),
        home: Some(PathBuf::from("/Users/dev")),
    }
}

/// Run the full challenge pipeline and return the display context and result.
fn run_pipeline(
    command: &str,
    settings: &Settings,
    env: &MockEnvironment,
    prompter: &MockPrompter,
    project_policy: Option<&ProjectPolicy>,
) -> Option<ChallengeResult> {
    let all_checks = settings.get_active_checks().unwrap();

    // Split and check
    let parts = checks::split_command(command);
    let matches: Vec<&checks::Check> = parts
        .iter()
        .flat_map(|c| checks::run_check_on_command_with_env(&all_checks, c, env))
        .collect();

    if matches.is_empty() {
        return None; // No risky patterns found
    }

    // Detect context
    let runtime_context = context::detect(env, &settings.context);

    // Merge project policy
    let merged_policy = if let Some(pp) = project_policy {
        policy::merge_into_settings(settings, pp, runtime_context.git_branch.as_deref())
    } else {
        MergedPolicy::default()
    };

    // Run challenge
    let result = checks::challenge_with_context(
        &settings.challenge,
        &matches,
        &settings.deny_patterns_ids,
        &runtime_context,
        &merged_policy,
        &settings.context.escalation,
        prompter,
        &[],
    )
    .unwrap();

    Some(result)
}

// ---------------------------------------------------------------------------
// Context detection tests
// ---------------------------------------------------------------------------

#[test]
fn test_context_production_ssh_is_critical() {
    let env = mock_env_production_ssh();
    let ctx = context::detect(&env, &ContextConfig::default());

    assert!(ctx.is_ssh);
    assert_eq!(ctx.git_branch, Some("main".into()));
    assert_eq!(ctx.k8s_context, Some("prod-us-east-1".into()));
    assert_eq!(ctx.risk_level, context::RiskLevel::Critical);
    assert!(!ctx.labels.is_empty());
}

#[test]
fn test_context_local_dev_is_normal() {
    let env = mock_env_local_dev();
    let ctx = context::detect(&env, &ContextConfig::default());

    assert!(!ctx.is_ssh);
    assert_eq!(ctx.git_branch, Some("feature/my-thing".into()));
    assert_eq!(ctx.k8s_context, Some("minikube".into()));
    assert_eq!(ctx.risk_level, context::RiskLevel::Normal);
}

// ---------------------------------------------------------------------------
// Full pipeline tests
// ---------------------------------------------------------------------------

#[test]
fn test_pipeline_local_dev_force_push_passes() {
    let env = mock_env_local_dev();
    let prompter = MockPrompter::passing();
    let settings = default_settings();

    let result = run_pipeline(
        "git push -f origin feature/my-thing",
        &settings,
        &env,
        &prompter,
        None,
    );

    assert_eq!(result, Some(ChallengeResult::Passed));

    // Verify the display showed Math challenge (no escalation on feature branch)
    let displays = prompter.captured_displays.borrow();
    assert_eq!(displays.len(), 1);
    assert_eq!(displays[0].effective_challenge, Challenge::Math);
    assert!(!displays[0].is_denied);
}

#[test]
fn test_pipeline_production_ssh_force_push_escalates() {
    let env = mock_env_production_ssh();
    let prompter = MockPrompter::passing();
    let settings = default_settings();

    let result = run_pipeline("git push -f origin main", &settings, &env, &prompter, None);

    assert_eq!(result, Some(ChallengeResult::Passed));

    let displays = prompter.captured_displays.borrow();
    assert_eq!(displays.len(), 1);
    // Should be escalated from Math to Yes due to Critical context (main branch + prod k8s)
    assert_eq!(displays[0].effective_challenge, Challenge::Yes);
    assert!(!displays[0].context_labels.is_empty());
}

#[test]
fn test_pipeline_safe_command_no_challenge() {
    let env = mock_env_local_dev();
    let prompter = MockPrompter::passing();
    let settings = default_settings();

    let result = run_pipeline("git status", &settings, &env, &prompter, None);
    assert!(result.is_none()); // No risky patterns
    assert!(prompter.captured_displays.borrow().is_empty());
}

#[test]
fn test_pipeline_project_policy_denies_force_push() {
    let env = mock_env_local_dev();
    let prompter = MockPrompter::passing();
    let settings = default_settings();
    let policy = ProjectPolicy {
        version: 1,
        deny: vec!["git:force_push".into()],
        ..Default::default()
    };

    let result = run_pipeline(
        "git push -f origin feature/my-thing",
        &settings,
        &env,
        &prompter,
        Some(&policy),
    );

    // Should be denied because project policy denies git:force_push
    assert_eq!(result, Some(ChallengeResult::Denied));

    let displays = prompter.captured_displays.borrow();
    assert_eq!(displays.len(), 1);
    assert!(displays[0].is_denied);
}

#[test]
fn test_pipeline_global_deny_blocks() {
    let env = mock_env_local_dev();
    let prompter = MockPrompter::passing();
    let mut settings = default_settings();
    settings.deny_patterns_ids = vec!["git:force_push".into()];

    let result = run_pipeline(
        "git push -f origin feature/my-thing",
        &settings,
        &env,
        &prompter,
        None,
    );

    assert_eq!(result, Some(ChallengeResult::Denied));
}

#[test]
fn test_pipeline_alternative_shown_for_force_push() {
    let env = mock_env_local_dev();
    let prompter = MockPrompter::passing();
    let settings = default_settings();

    let result = run_pipeline("git push -f origin main", &settings, &env, &prompter, None);

    assert_eq!(result, Some(ChallengeResult::Passed));

    let displays = prompter.captured_displays.borrow();
    assert_eq!(displays.len(), 1);
    assert!(
        displays[0]
            .alternatives
            .iter()
            .any(|a| a.suggestion.contains("--force-with-lease")),
        "Expected --force-with-lease alternative, got: {:?}",
        displays[0].alternatives
    );
}

#[test]
fn test_pipeline_compound_command_detects_risky_part() {
    let env = mock_env_local_dev();
    let prompter = MockPrompter::passing();
    let settings = default_settings();

    // The risky command is after &&
    let result = run_pipeline(
        "cd /tmp && git push -f origin main",
        &settings,
        &env,
        &prompter,
        None,
    );

    assert_eq!(result, Some(ChallengeResult::Passed));
    let displays = prompter.captured_displays.borrow();
    assert_eq!(displays.len(), 1);
}

// ---------------------------------------------------------------------------
// Policy discovery in virtual filesystem
// ---------------------------------------------------------------------------

#[test]
fn test_policy_discovery_walks_up() {
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

    let p = policy::discover(&env, &env.cwd);
    assert!(p.is_some());
    assert!(p.unwrap().deny.contains(&"git:force_push".to_string()));
}

#[test]
fn test_policy_discovery_no_file() {
    let env = MockEnvironment {
        cwd: PathBuf::from("/home/user/project"),
        ..Default::default()
    };

    let p = policy::discover(&env, &env.cwd);
    assert!(p.is_none());
}

// ---------------------------------------------------------------------------
// Custom checks loading
// ---------------------------------------------------------------------------

#[test]
fn test_custom_checks_loaded_from_temp_dir() {
    let temp = tempfile::tempdir().unwrap();
    let checks_dir = temp.path().join("checks");
    std::fs::create_dir_all(&checks_dir).unwrap();
    std::fs::write(
        checks_dir.join("custom.yaml"),
        r#"
- from: custom
  test: my-dangerous-tool deploy
  description: "Custom deploy command is risky."
  id: custom:deploy
"#,
    )
    .unwrap();

    let custom = checks::load_custom_checks(&checks_dir).unwrap();
    assert_eq!(custom.len(), 1);
    assert_eq!(custom[0].id, "custom:deploy");

    let matches = checks::run_check_on_command(&custom, "my-dangerous-tool deploy prod");
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].id, "custom:deploy");
}

// ---------------------------------------------------------------------------
// Audit log tests
// ---------------------------------------------------------------------------

#[test]
fn test_audit_log_written_to_temp_dir() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("audit.log");

    let event = shellfirm::audit::AuditEvent {
        event_id: "test-integration-1".into(),
        timestamp: "2026-02-15T10:00:00Z".into(),
        command: "git push -f".into(),
        matched_ids: vec!["git:force_push".into()],
        challenge_type: "Math".into(),
        outcome: shellfirm::audit::AuditOutcome::Allowed,
        context_labels: vec!["branch=main".into()],
        severity: shellfirm::checks::Severity::High,
        agent_name: None,
        agent_session_id: None,
        blast_radius_scope: None,
        blast_radius_detail: None,
    };

    shellfirm::audit::log_event(&path, &event).unwrap();
    let content = shellfirm::audit::read_log(&path).unwrap();
    // JSON lines format — parse to verify structure
    let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
    assert_eq!(parsed["command"], "git push -f");
    assert_eq!(parsed["outcome"], "Allowed");
    assert_eq!(parsed["matched_ids"][0], "git:force_push");
    assert_eq!(parsed["context_labels"][0], "branch=main");
    assert_eq!(parsed["severity"], "High");
}

#[test]
fn test_audit_clear() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("audit.log");

    let event = shellfirm::audit::AuditEvent {
        event_id: "test-integration-2".into(),
        timestamp: "2026-02-15T10:00:00Z".into(),
        command: "rm -rf /".into(),
        matched_ids: vec!["fs:recursively_delete".into()],
        challenge_type: "Math".into(),
        outcome: shellfirm::audit::AuditOutcome::Denied,
        context_labels: vec![],
        severity: shellfirm::checks::Severity::Critical,
        agent_name: None,
        agent_session_id: None,
        blast_radius_scope: None,
        blast_radius_detail: None,
    };

    shellfirm::audit::log_event(&path, &event).unwrap();
    assert!(path.exists());

    shellfirm::audit::clear_log(&path).unwrap();
    assert!(!path.exists());
}

// ---------------------------------------------------------------------------
// Context-specific escalation scenarios
// ---------------------------------------------------------------------------

#[test]
fn test_ssh_only_elevates_to_enter() {
    let mut env_vars = HashMap::new();
    env_vars.insert("SSH_TTY".into(), "/dev/pts/0".into());
    let env = MockEnvironment {
        env_vars,
        cwd: "/home/user".into(),
        ..Default::default()
    };
    let ctx = context::detect(&env, &ContextConfig::default());
    assert_eq!(ctx.risk_level, context::RiskLevel::Elevated);
}

#[test]
fn test_root_escalates_to_critical() {
    let mut env_vars = HashMap::new();
    env_vars.insert("EUID".into(), "0".into());
    let env = MockEnvironment {
        env_vars,
        cwd: "/root".into(),
        ..Default::default()
    };
    let ctx = context::detect(&env, &ContextConfig::default());
    assert_eq!(ctx.risk_level, context::RiskLevel::Critical);
}

#[test]
fn test_multiple_critical_signals() {
    let mut env_vars = HashMap::new();
    env_vars.insert("SSH_CONNECTION".into(), "10.0.0.1 22".into());
    env_vars.insert("EUID".into(), "0".into());
    env_vars.insert("NODE_ENV".into(), "production".into());

    let mut cmd_outputs = HashMap::new();
    cmd_outputs.insert("git rev-parse --abbrev-ref HEAD".into(), "main".into());

    let env = MockEnvironment {
        env_vars,
        cwd: "/var/app".into(),
        command_outputs: cmd_outputs,
        ..Default::default()
    };
    let ctx = context::detect(&env, &ContextConfig::default());
    assert_eq!(ctx.risk_level, context::RiskLevel::Critical);
    assert!(ctx.is_ssh);
    assert!(ctx.is_root);
}
