//! Tier 1: Pure logic tests — no I/O, no traits needed.
//!
//! These test the computational core: pattern matching, challenge escalation,
//! policy merging, command splitting, and alternative formatting.

use shellfirm::{
    checks,
    context::{self, EscalationConfig, RiskLevel},
    policy::{self, Override, ProjectPolicy},
    Challenge,
};

// ---------------------------------------------------------------------------
// Pattern matching
// ---------------------------------------------------------------------------

#[test]
fn test_pattern_matching_git_force_push() {
    let checks = checks::get_all().unwrap();
    let matches = checks::run_check_on_command(&checks, "git push -f origin main");
    let ids: Vec<&str> = matches.iter().map(|c| c.id.as_str()).collect();
    assert!(
        ids.contains(&"git:force_push"),
        "Expected git:force_push in {:?}",
        ids
    );
}

#[test]
fn test_pattern_matching_git_reset() {
    let checks = checks::get_all().unwrap();
    let matches = checks::run_check_on_command(&checks, "git reset --hard HEAD~1");
    let ids: Vec<&str> = matches.iter().map(|c| c.id.as_str()).collect();
    assert!(
        ids.contains(&"git:reset"),
        "Expected git:reset in {:?}",
        ids
    );
}

#[test]
fn test_pattern_matching_safe_command() {
    let checks = checks::get_all().unwrap();
    let matches = checks::run_check_on_command(&checks, "git status");
    assert!(
        matches.is_empty(),
        "Expected no matches for 'git status', got: {:?}",
        matches.iter().map(|c| &c.id).collect::<Vec<_>>()
    );
}

#[test]
fn test_pattern_matching_kubectl_delete_ns() {
    let checks = checks::get_all().unwrap();
    let matches = checks::run_check_on_command(&checks, "kubectl delete namespace payments");
    let ids: Vec<&str> = matches.iter().map(|c| c.id.as_str()).collect();
    assert!(
        ids.contains(&"kubernetes:delete_namespace"),
        "Expected kubernetes:delete_namespace in {:?}",
        ids
    );
}

#[test]
fn test_pattern_matching_docker_prune() {
    let checks = checks::get_all().unwrap();
    let matches = checks::run_check_on_command(&checks, "docker system prune -a");
    let ids: Vec<&str> = matches.iter().map(|c| c.id.as_str()).collect();
    assert!(
        ids.contains(&"docker:system_prune_all"),
        "Expected docker:system_prune_all in {:?}",
        ids
    );
}

#[test]
fn test_pattern_matching_aws_s3_delete() {
    let checks = checks::get_all().unwrap();
    let matches = checks::run_check_on_command(&checks, "aws s3 rm s3://bucket/path --recursive");
    let ids: Vec<&str> = matches.iter().map(|c| c.id.as_str()).collect();
    assert!(
        ids.contains(&"aws:s3_recursive_delete"),
        "Expected aws:s3_recursive_delete in {:?}",
        ids
    );
}

#[test]
fn test_pattern_matching_terraform_auto_approve() {
    let checks = checks::get_all().unwrap();
    let matches = checks::run_check_on_command(&checks, "terraform apply -auto-approve");
    let ids: Vec<&str> = matches.iter().map(|c| c.id.as_str()).collect();
    assert!(ids.contains(&"terraform:apply_with_auto_approve"));
}

#[test]
fn test_pattern_matching_database_drop() {
    let checks = checks::get_all().unwrap();
    let matches = checks::run_check_on_command(&checks, "DROP DATABASE production");
    let ids: Vec<&str> = matches.iter().map(|c| c.id.as_str()).collect();
    assert!(ids.contains(&"database:drop_database"));
}

// ---------------------------------------------------------------------------
// Challenge escalation
// ---------------------------------------------------------------------------

#[test]
fn test_escalate_normal_does_not_change() {
    let esc = EscalationConfig::default();
    assert_eq!(
        context::escalate_challenge(&Challenge::Math, RiskLevel::Normal, &esc),
        Challenge::Math
    );
    assert_eq!(
        context::escalate_challenge(&Challenge::Enter, RiskLevel::Normal, &esc),
        Challenge::Enter
    );
    assert_eq!(
        context::escalate_challenge(&Challenge::Yes, RiskLevel::Normal, &esc),
        Challenge::Yes
    );
}

#[test]
fn test_escalate_elevated_raises_to_enter() {
    let esc = EscalationConfig::default();
    assert_eq!(
        context::escalate_challenge(&Challenge::Math, RiskLevel::Elevated, &esc),
        Challenge::Enter
    );
}

#[test]
fn test_escalate_critical_raises_to_yes() {
    let esc = EscalationConfig::default();
    assert_eq!(
        context::escalate_challenge(&Challenge::Math, RiskLevel::Critical, &esc),
        Challenge::Yes
    );
}

#[test]
fn test_escalate_cannot_lower() {
    let esc = EscalationConfig::default();
    // Yes is already stricter than Enter (elevated escalation)
    assert_eq!(
        context::escalate_challenge(&Challenge::Yes, RiskLevel::Elevated, &esc),
        Challenge::Yes
    );
    // Yes stays at Yes even with Critical
    assert_eq!(
        context::escalate_challenge(&Challenge::Yes, RiskLevel::Critical, &esc),
        Challenge::Yes
    );
}

// ---------------------------------------------------------------------------
// Policy merging (additive-only)
// ---------------------------------------------------------------------------

fn default_settings() -> shellfirm::Settings {
    shellfirm::Settings {
        challenge: Challenge::Math,
        enabled_groups: vec!["base".into(), "fs".into(), "git".into()],
        disabled_groups: vec![],
        ignores_patterns_ids: vec![],
        deny_patterns_ids: vec![],
        context: context::ContextConfig::default(),
        audit_enabled: false,
        blast_radius: true,
        min_severity: None,
        agent: shellfirm::AgentConfig::default(),
        llm: shellfirm::LlmConfig::default(),
        wrappers: shellfirm::WrappersConfig::default(),
    }
}

#[test]
fn test_policy_merge_adds_deny() {
    let settings = default_settings();
    let policy = ProjectPolicy {
        version: 1,
        deny: vec!["git:force_push".into()],
        ..Default::default()
    };
    let merged = policy::merge_into_settings(&settings, &policy, None);
    assert!(merged.is_denied("git:force_push"));
    assert!(!merged.is_denied("git:reset"));
}

#[test]
fn test_policy_merge_escalates_challenge() {
    let settings = default_settings();
    let policy = ProjectPolicy {
        version: 1,
        overrides: vec![Override {
            id: "git:force_push".into(),
            challenge: Some(Challenge::Yes),
            on_branches: None,
        }],
        ..Default::default()
    };
    let merged = policy::merge_into_settings(&settings, &policy, None);
    assert_eq!(
        merged.effective_challenge("git:force_push", &Challenge::Math),
        Challenge::Yes
    );
}

#[test]
fn test_policy_cannot_weaken() {
    let settings = default_settings();
    let policy = ProjectPolicy {
        version: 1,
        overrides: vec![Override {
            id: "git:reset".into(),
            challenge: Some(Challenge::Enter), // tries to weaken from Yes to Enter
            on_branches: None,
        }],
        ..Default::default()
    };
    let merged = policy::merge_into_settings(&settings, &policy, None);
    // Policy tried to lower: base=Yes, override=Enter → must stay Yes
    assert_eq!(
        merged.effective_challenge("git:reset", &Challenge::Yes),
        Challenge::Yes
    );
}

#[test]
fn test_policy_branch_specific_override() {
    let settings = default_settings();
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
    let merged = policy::merge_into_settings(&settings, &policy, Some("main"));
    assert_eq!(
        merged.effective_challenge("git:reset", &Challenge::Math),
        Challenge::Yes
    );

    // On feature branch → override does NOT apply
    let merged = policy::merge_into_settings(&settings, &policy, Some("feature/foo"));
    assert_eq!(
        merged.effective_challenge("git:reset", &Challenge::Math),
        Challenge::Math
    );
}

// ---------------------------------------------------------------------------
// Command splitting
// ---------------------------------------------------------------------------

#[test]
fn test_split_command_double_ampersand() {
    let parts = checks::split_command("ls && rm -rf /");
    assert_eq!(parts, vec!["ls ", " rm -rf /"]);
}

#[test]
fn test_split_command_pipe() {
    let parts = checks::split_command("cat foo | grep bar");
    assert_eq!(parts, vec!["cat foo ", " grep bar"]);
}

#[test]
fn test_split_command_mixed_operators() {
    let parts = checks::split_command("a && b || c; d");
    assert_eq!(parts, vec!["a ", " b ", " c", " d"]);
}

#[test]
fn test_split_command_single() {
    let parts = checks::split_command("git push -f");
    assert_eq!(parts, vec!["git push -f"]);
}

#[test]
fn test_split_command_semicolon() {
    let parts = checks::split_command("cd /tmp; rm -rf *");
    assert_eq!(parts, vec!["cd /tmp", " rm -rf *"]);
}

#[test]
fn test_split_command_respects_double_quotes() {
    let parts = checks::split_command(r#"echo "hello && world" && rm -rf /"#);
    assert_eq!(parts, vec![r#"echo "hello && world" "#, " rm -rf /"]);
}

#[test]
fn test_split_command_respects_single_quotes() {
    let parts = checks::split_command("echo 'a | b' | grep c");
    assert_eq!(parts, vec!["echo 'a | b' ", " grep c"]);
}

// ---------------------------------------------------------------------------
// Alternative formatting
// ---------------------------------------------------------------------------

#[test]
fn test_alternatives_present_in_force_push_check() {
    let checks = checks::get_all().unwrap();
    let force_push = checks.iter().find(|c| c.id == "git:force_push");
    assert!(force_push.is_some(), "git:force_push check should exist");
    let check = force_push.unwrap();
    assert!(
        check.alternative.is_some(),
        "git:force_push should have an alternative"
    );
    assert!(
        check
            .alternative
            .as_ref()
            .unwrap()
            .contains("--force-with-lease"),
        "Alternative should mention --force-with-lease"
    );
    assert!(
        check.alternative_info.is_some(),
        "Should have alternative_info"
    );
}

#[test]
fn test_alternatives_present_in_rm_check() {
    let checks = checks::get_all().unwrap();
    let rm_check = checks.iter().find(|c| c.id == "fs:recursively_delete");
    assert!(rm_check.is_some());
    let check = rm_check.unwrap();
    assert!(check.alternative.is_some());
    assert!(check.alternative.as_ref().unwrap().contains("trash"));
}

#[test]
fn test_safe_command_has_no_alternative() {
    // The base:bash_fork_bomb check has no alternative
    let checks = checks::get_all().unwrap();
    let bomb = checks.iter().find(|c| c.id == "base:bash_fork_bomb");
    assert!(bomb.is_some());
    assert!(bomb.unwrap().alternative.is_none());
}

// ---------------------------------------------------------------------------
// Policy validation
// ---------------------------------------------------------------------------

#[test]
fn test_validate_valid_policy() {
    let yaml = r#"
version: 1
checks:
  - id: "project:deploy"
    test: "deploy\\s+prod"
    from: project
    description: "Production deployment"
deny:
  - git:force_push
"#;
    let warnings = policy::validate_policy(yaml).unwrap();
    assert!(
        warnings.is_empty(),
        "Expected no warnings, got: {:?}",
        warnings
    );
}

#[test]
fn test_validate_policy_bad_version() {
    let yaml = "version: 99\n";
    let warnings = policy::validate_policy(yaml).unwrap();
    assert!(!warnings.is_empty());
    assert!(warnings[0].contains("version"));
}

#[test]
fn test_validate_policy_empty_id() {
    let yaml = r#"
version: 1
checks:
  - id: ""
    test: "test"
    from: project
    description: ""
"#;
    let warnings = policy::validate_policy(yaml).unwrap();
    assert!(warnings.iter().any(|w| w.contains("empty id")));
}
