use anyhow::{anyhow, Result};
use clap::{Arg, ArgMatches, Command};
use shellfirm::{checks::Severity, dialog, Challenge, Config, Settings};
use strum::IntoEnumIterator;

const ALL_GROUP_CHECKS: &[&str] = &include!(concat!(env!("OUT_DIR"), "/all_the_files.rs"));

pub fn command() -> Command {
    Command::new("config")
        .about("Manage shellfirm configuration")
        .arg_required_else_help(true)
        .subcommand(
            Command::new("update-groups")
                .about("Enable or disable check groups (fs, git, kubernetes, etc.)")
                .arg(Arg::new("check-group").help("Check group")),
        )
        .subcommand(Command::new("reset").about("Reset configuration"))
        .subcommand(
            Command::new("challenge")
                .about("Change the default challenge type (Math, Enter, Yes)")
                .arg(
                    Arg::new("type")
                        .help("Challenge type: Math, Enter, or Yes")
                        .value_parser(["Math", "Enter", "Yes"]),
                ),
        )
        .subcommand(
            Command::new("ignore")
                .about("Skip challenge for specific pattern IDs")
                .arg(
                    Arg::new("patterns")
                        .help("Pattern IDs to ignore (e.g. fs:recursively_delete git:force_push)")
                        .num_args(1..),
                ),
        )
        .subcommand(
            Command::new("deny")
                .about("Block commands matching specific pattern IDs (no challenge, always denied)")
                .arg(
                    Arg::new("patterns")
                        .help("Pattern IDs to deny (e.g. git:force_push)")
                        .num_args(1..),
                ),
        )
        .subcommand(
            Command::new("severity")
                .about("Set the minimum severity threshold (checks below this level are skipped)")
                .arg(
                    Arg::new("level")
                        .help("Minimum severity: Info, Low, Medium, High, Critical, or None to disable")
                        .value_parser(["Info", "Low", "Medium", "High", "Critical", "None"]),
                ),
        )
        .subcommand(Command::new("show").about("Display current shellfirm configuration"))
}

pub fn run(
    matches: &ArgMatches,
    config: &Config,
    settings: &Settings,
) -> Result<shellfirm::CmdExit> {
    match matches.subcommand() {
        None => Err(anyhow!("command not found")),
        Some(tup) => match tup {
            ("update-groups", _subcommand_matches) => {
                run_update_groups(config, &config.get_settings_from_file()?, None)
            }
            ("reset", _subcommand_matches) => Ok(run_reset(config, None)),
            ("challenge", subcommand_matches) => {
                let challenge = subcommand_matches
                    .get_one::<String>("type")
                    .map(|s| Challenge::from_string(s))
                    .transpose()?;
                run_challenge(config, challenge)
            }
            ("ignore", subcommand_matches) => {
                let patterns: Option<Vec<String>> = subcommand_matches
                    .get_many::<String>("patterns")
                    .map(|vals| vals.cloned().collect());
                run_ignore(config, settings, patterns)
            }
            ("deny", subcommand_matches) => {
                let patterns: Option<Vec<String>> = subcommand_matches
                    .get_many::<String>("patterns")
                    .map(|vals| vals.cloned().collect());
                run_deny(config, settings, patterns)
            }
            ("severity", subcommand_matches) => {
                let level = subcommand_matches
                    .get_one::<String>("level")
                    .map(String::as_str);
                run_severity(config, settings, level)
            }
            ("show", _subcommand_matches) => run_show(config, settings),
            _ => unreachable!(),
        },
    }
}

pub fn run_update_groups(
    config: &Config,
    settings: &Settings,
    groups: Option<Vec<String>>,
) -> Result<shellfirm::CmdExit> {
    let check_groups = if let Some(groups) = groups {
        groups
    } else {
        let all_groups = ALL_GROUP_CHECKS.iter().map(|f| (*f).to_string()).collect();
        dialog::multi_choice(
            "select checks",
            all_groups,
            settings.get_active_groups().clone(),
            100,
        )?
    };

    match config.update_check_groups(check_groups.clone()) {
        Ok(()) => Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: Some(format!(
                "Check groups updated successfully: {}",
                if check_groups.is_empty() {
                    "(none)".to_string()
                } else {
                    check_groups.join(", ")
                }
            )),
        }),
        Err(e) => Ok(shellfirm::CmdExit {
            code: exitcode::CONFIG,
            message: Some(format!("Could not update checks group. error: {e}")),
        }),
    }
}

pub fn run_reset(config: &Config, force_selection: Option<usize>) -> shellfirm::CmdExit {
    match config.reset_config(force_selection) {
        Ok(()) => shellfirm::CmdExit {
            code: exitcode::OK,
            message: Some("shellfirm configuration reset successfully".to_string()),
        },
        Err(e) => shellfirm::CmdExit {
            code: exitcode::CONFIG,
            message: Some(format!("reset settings error: {e:?}")),
        },
    }
}

pub fn run_challenge(config: &Config, challenge: Option<Challenge>) -> Result<shellfirm::CmdExit> {
    let selection_challenge = if let Some(c) = challenge {
        c
    } else {
        let challenges = Challenge::iter().map(|c| c.to_string()).collect::<Vec<_>>();
        Challenge::from_string(&dialog::select("change shellfirm challenge", &challenges)?)?
    };

    match config.update_challenge(selection_challenge) {
        Ok(()) => Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: Some(format!("Challenge type changed to {selection_challenge}.")),
        }),
        Err(e) => Ok(shellfirm::CmdExit {
            code: exitcode::CONFIG,
            message: Some(format!("change challenge error: {e:?}")),
        }),
    }
}

pub fn run_ignore(
    config: &Config,
    settings: &Settings,
    force_ignore: Option<Vec<String>>,
) -> Result<shellfirm::CmdExit> {
    let all_check_ids: Vec<String> = settings
        .get_active_checks()?
        .iter()
        .map(|c| c.id.clone())
        .collect();

    let selected = if let Some(force_ignore) = force_ignore {
        force_ignore
    } else {
        dialog::multi_choice(
            "select checks",
            all_check_ids,
            settings.ignores_patterns_ids.clone(),
            100,
        )?
    };

    let count = selected.len();
    match config.update_ignores_pattern_ids(selected) {
        Ok(()) => Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: Some(format!("Ignore list updated ({count} patterns).")),
        }),
        Err(e) => Ok(shellfirm::CmdExit {
            code: exitcode::CONFIG,
            message: Some(format!("update ignore patterns error: {e:?}")),
        }),
    }
}

pub fn run_deny(
    config: &Config,
    settings: &Settings,
    force_ignore: Option<Vec<String>>,
) -> Result<shellfirm::CmdExit> {
    let all_check_ids: Vec<String> = settings
        .get_active_checks()?
        .iter()
        .map(|c| c.id.clone())
        .collect();

    let selected = if let Some(force_ignore) = force_ignore {
        force_ignore
    } else {
        dialog::multi_choice(
            "select checks",
            all_check_ids,
            settings.deny_patterns_ids.clone(),
            100,
        )?
    };

    let count = selected.len();
    match config.update_deny_pattern_ids(selected) {
        Ok(()) => Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: Some(format!("Deny list updated ({count} patterns).")),
        }),
        Err(e) => Ok(shellfirm::CmdExit {
            code: exitcode::CONFIG,
            message: Some(format!("update deny patterns error: {e:?}")),
        }),
    }
}

fn parse_severity(s: &str) -> Option<Severity> {
    match s {
        "Info" => Some(Severity::Info),
        "Low" => Some(Severity::Low),
        "Medium" => Some(Severity::Medium),
        "High" => Some(Severity::High),
        "Critical" => Some(Severity::Critical),
        _ => None,
    }
}

pub fn run_severity(
    config: &Config,
    settings: &Settings,
    level: Option<&str>,
) -> Result<shellfirm::CmdExit> {
    let min_severity = if let Some(level_str) = level {
        if level_str == "None" {
            None
        } else {
            Some(parse_severity(level_str).ok_or_else(|| {
                anyhow!("Invalid severity level: {level_str}")
            })?)
        }
    } else {
        // Interactive selection
        let options = vec![
            "None (all checks trigger)".to_string(),
            "Info".to_string(),
            "Low".to_string(),
            "Medium".to_string(),
            "High".to_string(),
            "Critical".to_string(),
        ];
        let current = settings.min_severity.map_or_else(
            || "None (all checks trigger)".to_string(),
            |s| format!("{s}"),
        );
        let selected = dialog::select(
            &format!("Set minimum severity (current: {current})"),
            &options,
        )?;
        if selected.starts_with("None") {
            None
        } else {
            Some(parse_severity(&selected).ok_or_else(|| {
                anyhow!("Invalid severity level: {selected}")
            })?)
        }
    };

    match config.update_min_severity(min_severity) {
        Ok(()) => {
            let label = min_severity.map_or_else(
                || "disabled (all checks trigger)".to_string(),
                |s| format!("{s}"),
            );
            Ok(shellfirm::CmdExit {
                code: exitcode::OK,
                message: Some(format!("Minimum severity set to: {label}")),
            })
        }
        Err(e) => Ok(shellfirm::CmdExit {
            code: exitcode::CONFIG,
            message: Some(format!("Failed to update severity: {e:?}")),
        }),
    }
}

#[allow(clippy::unnecessary_wraps)]
fn run_show(config: &Config, settings: &Settings) -> Result<shellfirm::CmdExit> {
    let groups = if settings.includes.is_empty() {
        "(none)".to_string()
    } else {
        settings.includes.join(", ")
    };

    let ignored = if settings.ignores_patterns_ids.is_empty() {
        "(none)".to_string()
    } else {
        settings.ignores_patterns_ids.join(", ")
    };

    let denied = if settings.deny_patterns_ids.is_empty() {
        "(none)".to_string()
    } else {
        settings.deny_patterns_ids.join(", ")
    };

    let active_checks = settings
        .get_active_checks()
        .map(|c| c.len())
        .unwrap_or(0);

    let protected_branches = if settings.context.protected_branches.is_empty() {
        "(none)".to_string()
    } else {
        settings.context.protected_branches.join(", ")
    };

    let min_severity = settings.min_severity.map_or_else(
        || "disabled (all checks trigger)".to_string(),
        |s| format!("{s}"),
    );

    let config_path = config.setting_file_path.display();

    let output = format!(
        "\
Config path:         {config_path}
Challenge:           {challenge}
Active groups:       {groups}
Active checks:       {active_checks}
Ignored patterns:    {ignored}
Denied patterns:     {denied}
Min severity:        {min_severity}
Audit:               {audit}
Protected branches:  {protected_branches}
Escalation:          elevated={elevated}, critical={critical}",
        config_path = config_path,
        challenge = settings.challenge,
        audit = if settings.audit_enabled {
            "enabled"
        } else {
            "disabled"
        },
        elevated = settings.context.escalation.elevated,
        critical = settings.context.escalation.critical,
    );

    println!("{output}");
    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: None,
    })
}

#[cfg(test)]
mod test_config_cli_command {

    use std::fs;

    use insta::{assert_debug_snapshot, with_settings};
    use tempfile::TempDir;

    use super::*;

    fn initialize_config_folder(temp_dir: &TempDir) -> Config {
        let temp_dir = temp_dir.path().join("app");
        Config::new(Some(&temp_dir.display().to_string())).unwrap()
    }

    #[test]
    fn can_run_update_groups() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = initialize_config_folder(&temp_dir);
        assert_debug_snapshot!(run_update_groups(
            &config,
            &config.get_settings_from_file().unwrap(),
            Some(vec!["test-1".to_string()])
        ));
        assert_debug_snapshot!(config.get_settings_from_file());
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_run_update_groups_with_error() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = initialize_config_folder(&temp_dir);
        let settings = config.get_settings_from_file().unwrap();
        fs::remove_file(&config.setting_file_path).unwrap();
        with_settings!({filters => vec![
            (r"error:.+", "error message"),
        ]}, {
            assert_debug_snapshot!(run_update_groups(
            &config,
            &settings,
            Some(vec!["test-1".to_string()])
        ));
        });
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_run_reset() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = initialize_config_folder(&temp_dir);
        config.update_challenge(Challenge::Yes).unwrap();
        assert_debug_snapshot!(run_reset(&config, Some(1)));
        assert_debug_snapshot!(config.get_settings_from_file());
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_run_reset_with_error() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = initialize_config_folder(&temp_dir);
        fs::remove_file(&config.setting_file_path).unwrap();
        with_settings!({filters => vec![
            (r"error:.+", "error message"),
        ]}, {
            assert_debug_snapshot!(run_reset(&config, Some(1)));
        });
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_run_challenge() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = initialize_config_folder(&temp_dir);
        let settings = config.get_settings_from_file().unwrap();
        assert_debug_snapshot!(run_challenge(&config, Some(Challenge::Yes)));
        assert_debug_snapshot!(
            config.get_settings_from_file().unwrap().challenge != settings.challenge
        );
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_run_challenge_with_err() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = initialize_config_folder(&temp_dir);
        fs::remove_file(&config.setting_file_path).unwrap();

        with_settings!({filters => vec![
            (r"error:.+", "error message"),
        ]}, {
            assert_debug_snapshot!(run_challenge(&config, Some(Challenge::Yes)));
        });
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_run_ignore() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = initialize_config_folder(&temp_dir);
        let settings = config.get_settings_from_file().unwrap();
        assert_debug_snapshot!(run_ignore(
            &config,
            &settings,
            Some(vec!["id-1".to_string(), "id-2".to_string()])
        ));
        assert_debug_snapshot!(
            config
                .get_settings_from_file()
                .unwrap()
                .ignores_patterns_ids
        );
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_run_deny() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = initialize_config_folder(&temp_dir);
        let settings = config.get_settings_from_file().unwrap();
        assert_debug_snapshot!(run_deny(
            &config,
            &settings,
            Some(vec!["id-1".to_string(), "id-2".to_string()])
        ));
        assert_debug_snapshot!(config.get_settings_from_file().unwrap().deny_patterns_ids);
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_run_severity_set_high() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = initialize_config_folder(&temp_dir);
        let settings = config.get_settings_from_file().unwrap();
        assert!(settings.min_severity.is_none());

        let result = run_severity(&config, &settings, Some("High")).unwrap();
        assert_eq!(result.code, exitcode::OK);
        assert!(result.message.unwrap().contains("HIGH"));

        let updated = config.get_settings_from_file().unwrap();
        assert_eq!(updated.min_severity, Some(Severity::High));
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_run_severity_set_none() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = initialize_config_folder(&temp_dir);

        // First set to High
        let settings = config.get_settings_from_file().unwrap();
        run_severity(&config, &settings, Some("High")).unwrap();
        assert_eq!(
            config.get_settings_from_file().unwrap().min_severity,
            Some(Severity::High)
        );

        // Then clear it
        let settings = config.get_settings_from_file().unwrap();
        let result = run_severity(&config, &settings, Some("None")).unwrap();
        assert_eq!(result.code, exitcode::OK);
        assert!(result.message.unwrap().contains("disabled"));

        let updated = config.get_settings_from_file().unwrap();
        assert!(updated.min_severity.is_none());
        temp_dir.close().unwrap();
    }
}
