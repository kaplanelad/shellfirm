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
        enabled_groups: vec![
            "base".into(),
            "fs".into(),
            "git".into(),
            "kubernetes".into(),
            "docker".into(),
            "aws".into(),
        ],
        audit_enabled: false,
        ..Settings::default()
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
        settings,
        &matches,
        &runtime_context,
        &merged_policy,
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

    // Verify the display showed Enter challenge (High severity → Enter, no context escalation)
    let displays = prompter.captured_displays.borrow();
    assert_eq!(displays.len(), 1);
    assert_eq!(displays[0].effective_challenge, Challenge::Enter);
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
    let temp = tree_fs::TreeBuilder::default()
        .add(
            "checks/custom.yaml",
            r#"
- from: custom
  test: my-dangerous-tool deploy
  description: "Custom deploy command is risky."
  id: custom:deploy
"#,
        )
        .create()
        .expect("create tree");

    let custom = checks::load_custom_checks(&temp.root.join("checks")).unwrap();
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
    let temp = tree_fs::TreeBuilder::default()
        .create()
        .expect("create tree");
    let path = temp.root.join("audit.log");

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
    let temp = tree_fs::TreeBuilder::default()
        .create()
        .expect("create tree");
    let path = temp.root.join("audit.log");

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

// ---------------------------------------------------------------------------
// Command-aware context filtering (relevant_context) tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Severity-based escalation tests
// ---------------------------------------------------------------------------

#[test]
fn test_pipeline_high_severity_escalates_to_enter() {
    // git push -f is High severity → Enter on a normal local dev environment
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
    let displays = prompter.captured_displays.borrow();
    assert_eq!(displays.len(), 1);
    assert_eq!(displays[0].effective_challenge, Challenge::Enter);
}

#[test]
fn test_pipeline_severity_disabled_stays_math() {
    // With severity escalation disabled, High severity stays at Math
    let env = mock_env_local_dev();
    let prompter = MockPrompter::passing();
    let mut settings = default_settings();
    settings.severity_escalation.enabled = false;

    let result = run_pipeline(
        "git push -f origin feature/my-thing",
        &settings,
        &env,
        &prompter,
        None,
    );

    assert_eq!(result, Some(ChallengeResult::Passed));
    let displays = prompter.captured_displays.borrow();
    assert_eq!(displays.len(), 1);
    assert_eq!(displays[0].effective_challenge, Challenge::Math);
}

#[test]
fn test_pipeline_group_escalation() {
    // Group escalation: git → Yes
    let env = mock_env_local_dev();
    let prompter = MockPrompter::passing();
    let mut settings = default_settings();
    settings.severity_escalation.enabled = false; // disable severity to isolate group
    settings
        .group_escalation
        .insert("git".into(), Challenge::Yes);

    let result = run_pipeline(
        "git push -f origin feature/my-thing",
        &settings,
        &env,
        &prompter,
        None,
    );

    assert_eq!(result, Some(ChallengeResult::Passed));
    let displays = prompter.captured_displays.borrow();
    assert_eq!(displays.len(), 1);
    assert_eq!(displays[0].effective_challenge, Challenge::Yes);
}

#[test]
fn test_pipeline_check_id_escalation() {
    // Check-ID escalation: git:force_push → Yes
    let env = mock_env_local_dev();
    let prompter = MockPrompter::passing();
    let mut settings = default_settings();
    settings.severity_escalation.enabled = false; // disable severity to isolate check-id
    settings
        .check_escalation
        .insert("git:force_push".into(), Challenge::Yes);

    let result = run_pipeline(
        "git push -f origin feature/my-thing",
        &settings,
        &env,
        &prompter,
        None,
    );

    assert_eq!(result, Some(ChallengeResult::Passed));
    let displays = prompter.captured_displays.borrow();
    assert_eq!(displays.len(), 1);
    assert_eq!(displays[0].effective_challenge, Challenge::Yes);
}

#[test]
fn test_pipeline_all_layers_compose() {
    // All layers composing: severity(Enter) + group(ignored, less than Enter) + context(Yes)
    let env = mock_env_production_ssh();
    let prompter = MockPrompter::passing();
    let mut settings = default_settings();
    settings
        .group_escalation
        .insert("git".into(), Challenge::Enter); // less than severity

    let result = run_pipeline("git push -f origin main", &settings, &env, &prompter, None);

    assert_eq!(result, Some(ChallengeResult::Passed));
    let displays = prompter.captured_displays.borrow();
    assert_eq!(displays.len(), 1);
    // max(Enter from severity, Enter from group, Yes from context) = Yes
    assert_eq!(displays[0].effective_challenge, Challenge::Yes);
}

fn strip_quotes_regex() -> regex::Regex {
    regex::Regex::new(r#"'[^']*'|"[^"]*""#).unwrap()
}

#[test]
fn test_relevant_context_rm_rf_hides_branch_and_k8s() {
    // Environment has branch=main + k8s=prod, but `rm -rf /` is an "fs" check
    // so relevant_context should NOT include branch or k8s labels.
    let mut env = mock_env_production_ssh();
    // PathExists filters need `/` to exist in the mock
    env.existing_paths.insert(PathBuf::from("/"));
    let settings = default_settings();
    let all_checks = settings.get_active_checks().unwrap();
    let re = strip_quotes_regex();

    let pipeline = checks::analyze_command("rm -rf /", &settings, &all_checks, &env, &re).unwrap();

    // Should have matched at least one fs check
    assert!(
        !pipeline.active_matches.is_empty(),
        "rm -rf / should match checks"
    );

    // Full context has branch and k8s
    assert!(pipeline.context.git_branch.is_some());
    assert!(pipeline.context.k8s_context.is_some());

    // Relevant context should NOT have branch or k8s (fs command)
    assert!(
        pipeline.relevant_context.git_branch.is_none(),
        "branch should be hidden for fs command"
    );
    assert!(
        pipeline.relevant_context.k8s_context.is_none(),
        "k8s should be hidden for fs command"
    );
    assert!(
        !pipeline
            .relevant_context
            .labels
            .iter()
            .any(|l| l.starts_with("branch=")),
        "branch label should be hidden"
    );
    assert!(
        !pipeline
            .relevant_context
            .labels
            .iter()
            .any(|l| l.starts_with("k8s=")),
        "k8s label should be hidden"
    );
    // Global signals (SSH, env_signals) still present
    assert!(pipeline.relevant_context.is_ssh);
}

#[test]
fn test_relevant_context_git_push_shows_branch_hides_k8s() {
    // `git push --force` is a "git" check — branch should be shown, k8s hidden.
    let env = mock_env_production_ssh();
    let settings = default_settings();
    let all_checks = settings.get_active_checks().unwrap();
    let re = strip_quotes_regex();

    let pipeline =
        checks::analyze_command("git push --force", &settings, &all_checks, &env, &re).unwrap();

    assert!(
        !pipeline.active_matches.is_empty(),
        "git push --force should match checks"
    );

    // Relevant context: branch shown, k8s hidden
    assert_eq!(
        pipeline.relevant_context.git_branch,
        Some("main".into()),
        "branch should be visible for git command"
    );
    assert!(
        pipeline.relevant_context.k8s_context.is_none(),
        "k8s should be hidden for git command"
    );
    assert!(pipeline
        .relevant_context
        .labels
        .iter()
        .any(|l| l.starts_with("branch=")));
    assert!(!pipeline
        .relevant_context
        .labels
        .iter()
        .any(|l| l.starts_with("k8s=")),);
}

#[test]
fn test_relevant_context_kubectl_shows_k8s_hides_branch() {
    // `kubectl delete ns kube-system` is a "kubernetes" check
    let env = mock_env_production_ssh();
    let settings = default_settings();
    let all_checks = settings.get_active_checks().unwrap();
    let re = strip_quotes_regex();

    let pipeline = checks::analyze_command(
        "kubectl delete ns kube-system",
        &settings,
        &all_checks,
        &env,
        &re,
    )
    .unwrap();

    assert!(
        !pipeline.active_matches.is_empty(),
        "kubectl delete ns should match checks"
    );

    // Relevant context: k8s shown, branch hidden
    assert!(
        pipeline.relevant_context.git_branch.is_none(),
        "branch should be hidden for kubernetes command"
    );
    assert_eq!(
        pipeline.relevant_context.k8s_context,
        Some("prod-us-east-1".into()),
        "k8s should be visible for kubernetes command"
    );
}
