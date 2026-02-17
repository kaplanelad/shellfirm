use std::sync::OnceLock;

use anyhow::Result;
use clap::{Arg, ArgAction, ArgMatches, Command};
use regex::Regex;
use shellfirm::{
    audit,
    checks::{self, Check},
    env::{Environment, RealEnvironment},
    prompt::{ChallengeResult, Prompter, TerminalPrompter},
    Settings,
};

fn regex_string_command_replace() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"'[^']*'|"[^"]*""#).unwrap())
}

pub fn command() -> Command {
    Command::new("pre-command")
        .about("Check if a command matches a risky pattern (used by shell hooks)")
        .arg(
            Arg::new("command")
                .short('c')
                .long("command")
                .help("The command to check")
                .required(true),
        )
        .arg(
            Arg::new("test")
                .short('t')
                .long("test")
                .help("Check if the command is risky and exit")
                .action(ArgAction::SetTrue),
        )
}

pub fn run(
    arg_matches: &ArgMatches,
    settings: &Settings,
    checks: &[Check],
    config: &shellfirm::Config,
) -> Result<shellfirm::CmdExit> {
    let env = RealEnvironment;
    let prompter = TerminalPrompter;
    execute(
        arg_matches
            .get_one::<String>("command")
            .map_or("", String::as_str),
        settings,
        checks,
        arg_matches.get_flag("test"),
        &env,
        &prompter,
        config,
    )
}

#[allow(clippy::too_many_lines)]
fn execute(
    command: &str,
    settings: &Settings,
    checks: &[Check],
    dryrun: bool,
    env: &dyn Environment,
    prompter: &dyn Prompter,
    config: &shellfirm::Config,
) -> Result<shellfirm::CmdExit> {
    let pipeline = checks::analyze_command(
        command,
        settings,
        checks,
        env,
        regex_string_command_replace(),
    )?;

    log::debug!(
        "matches found: active={}, skipped={}",
        pipeline.active_matches.len(),
        pipeline.skipped_matches.len()
    );

    if dryrun {
        return Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: Some(serde_yaml::to_string(&pipeline.active_matches)?),
        });
    }

    if !pipeline.active_matches.is_empty() || !pipeline.skipped_matches.is_empty() {
        // Audit log skipped checks
        if settings.audit_enabled && !pipeline.skipped_matches.is_empty() {
            let event = audit::AuditEvent {
                event_id: uuid::Uuid::new_v4().to_string(),
                timestamp: audit::now_timestamp(),
                command: pipeline.stripped_command.clone(),
                matched_ids: pipeline
                    .skipped_matches
                    .iter()
                    .map(|c| c.id.clone())
                    .collect(),
                challenge_type: format!("{}", settings.challenge),
                outcome: audit::AuditOutcome::Skipped,
                context_labels: pipeline.context.labels.clone(),
                severity: pipeline
                    .skipped_matches
                    .iter()
                    .map(|c| c.severity)
                    .max()
                    .unwrap_or_default(),
                agent_name: None,
                agent_session_id: None,
                blast_radius_scope: None,
                blast_radius_detail: None,
            };
            if let Err(e) = audit::log_event(&config.audit_log_path(), &event) {
                log::warn!("Failed to write audit log: {e}");
            }
        }

        // Only run the challenge if there are active (non-skipped) matches
        if !pipeline.active_matches.is_empty() {
            let active_refs: Vec<&checks::Check> = pipeline.active_matches.iter().collect();

            // Compute blast radius audit fields from the highest-scope entry
            let br_scope = pipeline
                .blast_radii
                .iter()
                .max_by_key(|(_, br)| br.scope)
                .map(|(_, br)| format!("{}", br.scope));
            let br_detail = pipeline
                .blast_radii
                .iter()
                .max_by_key(|(_, br)| br.scope)
                .map(|(_, br)| br.description.clone());

            // Write a pre-challenge Cancelled entry so that if the process is
            // killed (Ctrl+C) during the prompt, we still have a record.
            let event_id = uuid::Uuid::new_v4().to_string();
            if settings.audit_enabled {
                let event = audit::AuditEvent {
                    event_id: event_id.clone(),
                    timestamp: audit::now_timestamp(),
                    command: pipeline.stripped_command.clone(),
                    matched_ids: pipeline
                        .active_matches
                        .iter()
                        .map(|c| c.id.clone())
                        .collect(),
                    challenge_type: format!("{}", settings.challenge),
                    outcome: audit::AuditOutcome::Cancelled,
                    context_labels: pipeline.context.labels.clone(),
                    severity: pipeline.max_severity,
                    agent_name: None,
                    agent_session_id: None,
                    blast_radius_scope: br_scope.clone(),
                    blast_radius_detail: br_detail.clone(),
                };
                if let Err(e) = audit::log_event(&config.audit_log_path(), &event) {
                    log::warn!("Failed to write audit log: {e}");
                }
            }

            // Run the context-aware challenge
            let result = checks::challenge_with_context(
                &settings.challenge,
                &active_refs,
                &settings.deny_patterns_ids,
                &pipeline.context,
                &pipeline.merged_policy,
                &settings.context.escalation,
                prompter,
                &pipeline.blast_radii,
            )?;

            // Post-challenge audit with the same event_id
            if settings.audit_enabled {
                let outcome = match result {
                    ChallengeResult::Passed => audit::AuditOutcome::Allowed,
                    ChallengeResult::Denied => audit::AuditOutcome::Denied,
                };
                let event = audit::AuditEvent {
                    event_id,
                    timestamp: audit::now_timestamp(),
                    command: pipeline.stripped_command,
                    matched_ids: pipeline
                        .active_matches
                        .iter()
                        .map(|c| c.id.clone())
                        .collect(),
                    challenge_type: format!("{}", settings.challenge),
                    outcome,
                    context_labels: pipeline.context.labels,
                    severity: pipeline.max_severity,
                    agent_name: None,
                    agent_session_id: None,
                    blast_radius_scope: br_scope,
                    blast_radius_detail: br_detail,
                };
                if let Err(e) = audit::log_event(&config.audit_log_path(), &event) {
                    log::warn!("Failed to write audit log: {e}");
                }
            }
        }
    }

    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: None,
    })
}

#[cfg(test)]
mod test_command_cli_command {

    use shellfirm::Config;
    use tempfile::TempDir;

    use super::*;

    fn initialize_config_folder(temp_dir: &TempDir) -> Config {
        let temp_dir = temp_dir.path().join("app");
        Config::new(Some(&temp_dir.display().to_string())).unwrap()
    }

    #[test]
    fn can_run_pre_command() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = initialize_config_folder(&temp_dir);
        let settings = config.get_settings_from_file().unwrap();
        let mut existing = std::collections::HashSet::new();
        existing.insert(std::path::PathBuf::from("/tmp/test/"));
        existing.insert(std::path::PathBuf::from("/"));
        let env = shellfirm::env::MockEnvironment {
            cwd: "/tmp/test".into(),
            existing_paths: existing,
            ..Default::default()
        };
        let prompter = shellfirm::prompt::MockPrompter::passing();

        let checks = settings.get_active_checks().unwrap();
        assert!(!checks.is_empty(), "Active checks must not be empty");

        let result = execute(
            "rm -rf /", &settings, &checks, true, &env, &prompter, &config,
        );
        assert!(result.is_ok());
        let cmd_exit = result.unwrap();
        let output = cmd_exit.message.unwrap_or_default();
        assert!(
            output.contains("fs:recursively_delete"),
            "Expected fs:recursively_delete in dryrun output, got: {output}"
        );
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_run_pre_command_without_match() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = initialize_config_folder(&temp_dir);
        let settings = config.get_settings_from_file().unwrap();
        let env = shellfirm::env::MockEnvironment {
            cwd: "/tmp/test".into(),
            ..Default::default()
        };
        let prompter = shellfirm::prompt::MockPrompter::passing();

        let result = execute(
            "command",
            &settings,
            &settings.get_active_checks().unwrap(),
            true,
            &env,
            &prompter,
            &config,
        );
        assert!(result.is_ok());
        let cmd_exit = result.unwrap();
        assert_eq!(cmd_exit.code, exitcode::OK);
        temp_dir.close().unwrap();
    }

    #[test]
    fn regex_strips_matching_double_quotes() {
        let re = regex_string_command_replace();
        let result = re.replace_all(r#"echo "hello world""#, "").to_string();
        assert_eq!(result, "echo ");
    }

    #[test]
    fn regex_strips_matching_single_quotes() {
        let re = regex_string_command_replace();
        let result = re.replace_all("echo 'hello world'", "").to_string();
        assert_eq!(result, "echo ");
    }

    #[test]
    fn regex_does_not_strip_mismatched_quotes() {
        let re = regex_string_command_replace();
        // Mismatched quotes should NOT be treated as a quoted string
        let result = re.replace_all("echo 'hello\"", "").to_string();
        assert_eq!(result, "echo 'hello\"");
    }

    #[test]
    fn regex_handles_multiple_quoted_segments() {
        let re = regex_string_command_replace();
        let result = re
            .replace_all(r#"cmd "arg1" --flag 'arg2'"#, "")
            .to_string();
        assert_eq!(result, "cmd  --flag ");
    }
}
