//! A project policy is enforced: personal settings cannot weaken it.
//!
//! These tests mirror what `shellfirm` does at startup (load policy →
//! enforced active checks → apply policy context) and then run the shared
//! analysis pipeline against a mock environment.

use std::path::PathBuf;

use shellfirm::{
    checks::{self, Severity},
    env::MockEnvironment,
    policy, Mode, Settings,
};

fn strip_quotes_regex() -> regex::Regex {
    regex::Regex::new(r#"'[^']*'|"[^"]*""#).unwrap()
}

fn env_with_policy(policy_yaml: &str) -> MockEnvironment {
    MockEnvironment {
        cwd: PathBuf::from("/repo/src"),
        files: [(
            PathBuf::from("/repo/.shellfirm.yaml"),
            policy_yaml.to_string(),
        )]
        .into_iter()
        .collect(),
        existing_paths: [PathBuf::from("/repo/.git")].into_iter().collect(),
        ..Default::default()
    }
}

/// Run the pipeline the way the binary does and return (`is_denied`,
/// active match ids).
fn run(settings: &Settings, env: &MockEnvironment, command: &str) -> (bool, Vec<String>) {
    let discovery = policy::discover_all(env, &env.cwd);
    let mut settings = settings.clone();
    if let Some(p) = &discovery.policy {
        policy::apply_to_settings(&mut settings, p);
    }
    let active = settings
        .get_active_checks_enforced(&[], discovery.policy.as_ref())
        .unwrap();
    let resolved = settings.resolved_for(Mode::Shell);
    let re = strip_quotes_regex();
    let pipeline =
        checks::analyze_command(command, &settings, &resolved, &active, env, &re).unwrap();
    (
        pipeline.is_denied,
        pipeline
            .active_matches
            .iter()
            .map(|c| c.id.clone())
            .collect(),
    )
}

const DENY_FORCE_PUSH: &str = "version: 1\ndeny: [git:force_push]\n";

#[test]
fn policy_deny_survives_ignores_patterns_ids() {
    let env = env_with_policy(DENY_FORCE_PUSH);
    let s = Settings {
        ignores_patterns_ids: vec!["git:force_push".into()],
        ..Settings::default()
    };
    let (denied, ids) = run(&s, &env, "git push -f origin main");
    assert!(denied, "{ids:?}");
}

#[test]
fn policy_deny_survives_disabled_groups() {
    let env = env_with_policy(DENY_FORCE_PUSH);
    let s = Settings {
        disabled_groups: vec!["git".into()],
        ..Settings::default()
    };
    assert!(run(&s, &env, "git push -f origin main").0);
}

#[test]
fn policy_deny_survives_enabled_groups_whitelist() {
    let env = env_with_policy(DENY_FORCE_PUSH);
    let s = Settings {
        enabled_groups: vec!["fs".into()],
        ..Settings::default()
    };
    assert!(run(&s, &env, "git push -f origin main").0);
}

#[test]
fn policy_deny_survives_min_severity() {
    let env = env_with_policy(DENY_FORCE_PUSH);
    let s = Settings {
        min_severity: Some(Severity::Critical),
        ..Settings::default()
    };
    assert!(run(&s, &env, "git push -f origin main").0);
}

#[test]
fn policy_checks_survive_min_severity() {
    let env = env_with_policy(
        "version: 1\nchecks:\n  - id: team:deploy\n    from: team\n    test: 'deploy\\s+prod'\n    description: Deploys to prod\n    severity: Low\n",
    );
    let s = Settings {
        min_severity: Some(Severity::Critical),
        ..Settings::default()
    };
    let (_, ids) = run(&s, &env, "deploy prod");
    assert!(ids.contains(&"team:deploy".to_string()), "{ids:?}");
}

#[test]
fn without_policy_personal_ignore_still_works() {
    let env = MockEnvironment {
        cwd: PathBuf::from("/elsewhere"),
        ..Default::default()
    };
    let s = Settings {
        ignores_patterns_ids: vec!["git:force_push".into()],
        ..Settings::default()
    };
    let (_, ids) = run(&s, &env, "git push -f origin main");
    assert!(!ids.contains(&"git:force_push".to_string()));
}

#[test]
fn nested_policy_cannot_cancel_parent_deny() {
    let mut env = env_with_policy(DENY_FORCE_PUSH);
    env.cwd = PathBuf::from("/repo/svc/src");
    env.files.insert(
        PathBuf::from("/repo/svc/.shellfirm.yaml"),
        "version: 1\n".to_string(),
    );
    assert!(run(&Settings::default(), &env, "git push -f origin main").0);
}

#[test]
fn policy_context_adds_protected_branch() {
    let env = env_with_policy("version: 1\ncontext:\n  protected_branches: [develop]\n");
    let d = policy::discover_all(&env, &env.cwd);
    let mut s = Settings::default();
    policy::apply_to_settings(&mut s, d.policy.as_ref().unwrap());
    assert!(s
        .context
        .protected_branches
        .contains(&"develop".to_string()));
}

#[test]
fn invalid_policy_is_reported_not_silently_ignored() {
    let env = env_with_policy("deny: [git:force_push]\n");
    let d = policy::discover_all(&env, &env.cwd);
    assert!(d.policy.is_none());
    assert_eq!(d.errors.len(), 1);
    assert!(d.found_any());
}

#[test]
fn submodule_inherits_superproject_policy() {
    let mut env = env_with_policy(DENY_FORCE_PUSH);
    env.cwd = PathBuf::from("/repo/vendor/lib/src");
    // `.git` file of a submodule and an empty `.git` dir must not stop the walk.
    env.existing_paths
        .insert(PathBuf::from("/repo/vendor/lib/.git"));
    env.existing_paths
        .insert(PathBuf::from("/repo/vendor/.git"));
    assert!(run(&Settings::default(), &env, "git push -f origin main").0);
}

#[test]
fn typo_in_policy_is_reported_but_the_rest_still_applies() {
    let env = env_with_policy("version: 1\ndeny: [git:force_push, git:forse_push]\noverides: []\n");
    let d = policy::discover_all(&env, &env.cwd);
    assert_eq!(d.problems.len(), 2, "{:?}", d.problems);
    let load = d.to_load();
    assert!(!load.is_ok());
    assert!(load.summary().is_some());
    assert!(run(&Settings::default(), &env, "git push -f origin main").0);
}

#[test]
fn personal_deny_beats_personal_ignore() {
    let env = MockEnvironment {
        cwd: PathBuf::from("/elsewhere"),
        ..Default::default()
    };
    let s = Settings {
        ignores_patterns_ids: vec!["git:force_push".into()],
        deny_patterns_ids: vec!["git:force_push".into()],
        ..Settings::default()
    };
    assert!(run(&s, &env, "git push -f origin main").0);
}
