use std::sync::OnceLock;

use anyhow::Result;
use clap::{Arg, ArgAction, ArgMatches, Command};
use regex::Regex;
use shellfirm::{
    audit,
    checks::{self, Check},
    context,
    env::{Environment, RealEnvironment},
    policy,
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

fn execute(
    command: &str,
    settings: &Settings,
    checks: &[Check],
    dryrun: bool,
    env: &dyn Environment,
    prompter: &dyn Prompter,
    config: &shellfirm::Config,
) -> Result<shellfirm::CmdExit> {
    let command = regex_string_command_replace()
        .replace_all(command, "")
        .to_string();

    // Fixed: use proper command splitting instead of buggy char-based split
    let splitted_command = checks::split_command(&command);

    log::debug!("splitted_command {splitted_command:?}");
    let matches: Vec<&checks::Check> = splitted_command
        .iter()
        .flat_map(|c| checks::run_check_on_command_with_env(checks, c, env))
        .collect();

    log::debug!("matches found {}. {matches:?}", matches.len());

    if dryrun {
        return Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: Some(serde_yaml::to_string(&matches)?),
        });
    }

    if !matches.is_empty() {
        // Detect context
        let runtime_context = context::detect(env, &settings.context);

        // Discover project policy
        let cwd = env.current_dir().unwrap_or_default();
        let project_policy = policy::discover(env, &cwd);
        let merged_policy = if let Some(ref pp) = project_policy {
            policy::merge_into_settings(
                settings,
                pp,
                runtime_context.git_branch.as_deref(),
            )
        } else {
            policy::MergedPolicy::default()
        };

        // Merge extra checks from project policy
        let mut all_matches = matches.clone();
        if !merged_policy.extra_checks.is_empty() {
            let extra_matches: Vec<&Check> = splitted_command
                .iter()
                .flat_map(|c| checks::run_check_on_command_with_env(&merged_policy.extra_checks, c, env))
                .collect();
            all_matches.extend(extra_matches);
        }

        // Split matches by min_severity: active vs skipped
        let (active_matches, skipped_matches): (Vec<&Check>, Vec<&Check>) =
            if let Some(min_sev) = settings.min_severity {
                all_matches
                    .into_iter()
                    .partition(|c| c.severity >= min_sev)
            } else {
                (all_matches, Vec::new())
            };

        // Compute the highest severity across all original matches for audit
        let max_severity = active_matches
            .iter()
            .chain(skipped_matches.iter())
            .map(|c| c.severity)
            .max()
            .unwrap_or_default();

        // Audit log skipped checks
        if settings.audit_enabled && !skipped_matches.is_empty() {
            let event = audit::AuditEvent {
                timestamp: audit::now_timestamp(),
                command: command.clone(),
                matched_ids: skipped_matches.iter().map(|c| c.id.clone()).collect(),
                challenge_type: format!("{}", settings.challenge),
                outcome: audit::AuditOutcome::Skipped,
                context_labels: runtime_context.labels.clone(),
                severity: skipped_matches.iter().map(|c| c.severity).max().unwrap_or_default(),
            };
            if let Err(e) = audit::log_event(&config.audit_log_path(), &event) {
                log::warn!("Failed to write audit log: {e}");
            }
        }

        // Only run the challenge if there are active (non-skipped) matches
        if !active_matches.is_empty() {
            // Run the context-aware challenge
            let result = checks::challenge_with_context(
                &settings.challenge,
                &active_matches,
                &settings.deny_patterns_ids,
                &runtime_context,
                &merged_policy,
                &settings.context.escalation,
                prompter,
            )?;

            // Audit logging
            if settings.audit_enabled {
                let outcome = match result {
                    ChallengeResult::Passed => audit::AuditOutcome::Allowed,
                    ChallengeResult::Denied => audit::AuditOutcome::Denied,
                };
                let event = audit::AuditEvent {
                    timestamp: audit::now_timestamp(),
                    command,
                    matched_ids: active_matches.iter().map(|c| c.id.clone()).collect(),
                    challenge_type: format!("{}", settings.challenge),
                    outcome,
                    context_labels: runtime_context.labels,
                    severity: max_severity,
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
        let env = shellfirm::env::MockEnvironment {
            cwd: "/tmp/test".into(),
            existing_paths: existing,
            ..Default::default()
        };
        let prompter = shellfirm::prompt::MockPrompter::passing();

        let result = execute(
            "rm -rf /",
            &settings,
            &settings.get_active_checks().unwrap(),
            true,
            &env,
            &prompter,
            &config,
        );
        assert!(result.is_ok());
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
