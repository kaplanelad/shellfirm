use anyhow::{anyhow, Result};
use clap::{Arg, ArgMatches, Command};
use shellfirm::{dialog, Challenge, Config, Settings};
use shellfirm_core::checks::Severity;
use std::process::Command as ProcessCommand;
use strum::IntoEnumIterator;

pub fn command() -> Command {
    Command::new("config")
        .about("Manage Shellfirm configuration")
        .arg_required_else_help(true)
        .subcommand(
            Command::new("update-severity")
                .about("Select which severities trigger checks (Low/Medium/High/Critical)")
                .arg(Arg::new("severity").help("Severity")),
        )
        .subcommand(
            Command::new("reset").about("Reset configuration file (optionally create a backup)"),
        )
        .subcommand(Command::new("challenge").about("Set the default interactive challenge type"))
        .subcommand(
            Command::new("ignore").about("Configure rule IDs to ignore (allow without prompts)"),
        )
        .subcommand(Command::new("deny").about("Configure rule IDs to deny (block immediately)"))
        .subcommand(Command::new("path").about("Show the absolute path to the configuration file"))
        .subcommand(Command::new("edit").about("Open the configuration file for editing"))
}

pub fn run(
    matches: &ArgMatches,
    config: &Config,
    settings: &Settings,
) -> Result<shellfirm::CmdExit> {
    match matches.subcommand() {
        None => Err(anyhow!("command not found")),
        Some(tup) => match tup {
            ("update-severity", _subcommand_matches) => {
                run_update_severity(config, &config.get_settings_from_file()?, None)
            }
            ("reset", _subcommand_matches) => Ok(run_reset(config, None)),
            ("challenge", _subcommand_matches) => run_challenge(config, None),
            ("ignore", _subcommand_matches) => run_ignore(config, settings, None),
            ("deny", _subcommand_matches) => run_deny(config, settings, None),
            ("path", _subcommand_matches) => Ok(run_show_config_path(config)),
            ("edit", _subcommand_matches) => Ok(run_open_config_for_edit(config)),
            _ => unreachable!(),
        },
    }
}

pub fn run_update_severity(
    config: &Config,
    settings: &Settings,
    severities: Option<Vec<String>>,
) -> Result<shellfirm::CmdExit> {
    let selected_severities = if let Some(severities) = severities {
        severities
    } else {
        let all_severities = Severity::iter().map(|s| s.to_string()).collect();
        dialog::multi_choice(
            "select severities",
            all_severities,
            settings
                .get_active_groups()
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
            100,
        )?
    };

    match config.update_check_groups(selected_severities) {
        Ok(()) => Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: None,
        }),
        Err(e) => Ok(shellfirm::CmdExit {
            code: exitcode::CONFIG,
            message: Some(format!("Could not update severities. error: {e}")),
        }),
    }
}

pub fn run_show_config_path(config: &Config) -> shellfirm::CmdExit {
    shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some(config.setting_file_path.clone()),
    }
}

pub fn run_open_config_for_edit(config: &Config) -> shellfirm::CmdExit {
    let file_path = &config.setting_file_path;

    let editor = std::env::var("EDITOR")
        .ok()
        .or_else(|| std::env::var("VISUAL").ok());

    let status = editor.map_or_else(
        || {
            if cfg!(target_os = "macos") {
                ProcessCommand::new("open").arg(file_path).status()
            } else if cfg!(target_family = "windows") {
                ProcessCommand::new("cmd")
                    .args(["/C", "start", file_path])
                    .status()
            } else {
                ProcessCommand::new("xdg-open").arg(file_path).status()
            }
        },
        |ed| ProcessCommand::new(ed).arg(file_path).status(),
    );

    match status {
        Ok(s) if s.success() => shellfirm::CmdExit {
            code: exitcode::OK,
            message: None,
        },
        Ok(_s) => shellfirm::CmdExit {
            code: exitcode::USAGE,
            message: Some("Failed to open editor for configuration".to_string()),
        },
        Err(e) => shellfirm::CmdExit {
            code: exitcode::USAGE,
            message: Some(format!(
                "Could not launch editor. Set $EDITOR or install a default opener. error: {e}"
            )),
        },
    }
}

pub fn run_reset(config: &Config, force_selection: Option<usize>) -> shellfirm::CmdExit {
    match config.reset_config(force_selection) {
        Ok(()) => shellfirm::CmdExit {
            code: exitcode::OK,
            message: Some("Shellfirm configuration reset successfully".to_string()),
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
        Challenge::from_string(&dialog::select("change Shellfirm challenge", &challenges)?)?
    };

    match config.update_challenge(selection_challenge) {
        Ok(()) => Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: None,
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
        .map(|c| c.id.to_string())
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

    match config.update_ignores_pattern_ids(selected) {
        Ok(()) => Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: None,
        }),
        Err(e) => Ok(shellfirm::CmdExit {
            code: exitcode::CONFIG,
            message: Some(format!("update pattern ignore errors: {e:?}")),
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
        .map(|c| c.id.to_string())
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

    match config.update_deny_pattern_ids(selected) {
        Ok(()) => Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: None,
        }),
        Err(e) => Ok(shellfirm::CmdExit {
            code: exitcode::CONFIG,
            message: Some(format!("update pattern ignore errors: {e:?}")),
        }),
    }
}

#[cfg(test)]
mod test_config_cli_command {

    use super::*;
    use insta::{assert_debug_snapshot, with_settings};
    use std::fs;
    use std::path::Path;

    fn initialize_config_folder(temp_dir: &Path) -> Config {
        let temp_dir = temp_dir.join("app");
        Config::new(Some(&temp_dir.display().to_string())).expect("Failed to create new config")
    }

    #[test]
    fn can_run_update_severity() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("Failed to create temp directory");
        let config = initialize_config_folder(temp_dir.root.as_path());
        assert_debug_snapshot!(run_update_severity(
            &config,
            &config
                .get_settings_from_file()
                .expect("Failed to get settings from file"),
            Some(vec!["high".to_string(), "critical".to_string()])
        ));
        assert_debug_snapshot!(config.get_settings_from_file());
    }

    #[test]
    fn can_run_update_severity_with_error() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("Failed to create temp directory");
        let config = initialize_config_folder(temp_dir.root.as_path());
        let settings = config
            .get_settings_from_file()
            .expect("Failed to get settings from file");
        fs::remove_file(&config.setting_file_path).expect("Failed to remove setting file");
        with_settings!({filters => vec![
            (r"error:.+", "error message"),
        ]}, {
            assert_debug_snapshot!(run_update_severity(
            &config,
            &settings,
            Some(vec!["high".to_string()])
        ));
        });
    }

    #[test]
    fn can_run_reset() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("Failed to create temp directory");
        let config = initialize_config_folder(temp_dir.root.as_path());
        config
            .update_challenge(Challenge::Yes)
            .expect("Failed to update challenge");
        assert_debug_snapshot!(run_reset(&config, Some(1)));
        assert_debug_snapshot!(config.get_settings_from_file());
    }

    #[test]
    fn can_run_reset_with_error() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("Failed to create temp directory");
        let config = initialize_config_folder(temp_dir.root.as_path());
        fs::remove_file(&config.setting_file_path).expect("Failed to remove setting file");
        with_settings!({filters => vec![
            (r"error:.+", "error message"),
        ]}, {
            assert_debug_snapshot!(run_reset(&config, Some(1)));
        });
    }

    #[test]
    fn can_run_challenge() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("Failed to create temp directory");
        let config = initialize_config_folder(temp_dir.root.as_path());
        let settings = config
            .get_settings_from_file()
            .expect("Failed to get settings from file");
        assert_debug_snapshot!(run_challenge(&config, Some(Challenge::Yes)));
        assert_debug_snapshot!(
            config
                .get_settings_from_file()
                .expect("Failed to get settings from file")
                .challenge
                != settings.challenge
        );
    }

    #[test]
    fn can_run_challenge_with_err() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("Failed to create temp directory");
        let config = initialize_config_folder(temp_dir.root.as_path());
        fs::remove_file(&config.setting_file_path).expect("Failed to remove setting file");

        with_settings!({filters => vec![
            (r"error:.+", "error message"),
        ]}, {
            assert_debug_snapshot!(run_challenge(&config, Some(Challenge::Yes)));
        });
    }

    #[test]
    fn can_run_ignore() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("Failed to create temp directory");
        let config = initialize_config_folder(temp_dir.root.as_path());
        let settings = config
            .get_settings_from_file()
            .expect("Failed to get settings from file");
        assert_debug_snapshot!(run_ignore(
            &config,
            &settings,
            Some(vec!["id-1".to_string(), "id-2".to_string()])
        ));
        assert_debug_snapshot!(
            config
                .get_settings_from_file()
                .expect("Failed to get settings from file")
                .ignores_patterns_ids
        );
    }

    #[test]
    fn can_run_deny() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("Failed to create temp directory");
        let config = initialize_config_folder(temp_dir.root.as_path());
        let settings = config
            .get_settings_from_file()
            .expect("Failed to get settings from file");
        assert_debug_snapshot!(run_deny(
            &config,
            &settings,
            Some(vec!["id-1".to_string(), "id-2".to_string()])
        ));
        assert_debug_snapshot!(
            config
                .get_settings_from_file()
                .expect("Failed to get settings from file")
                .deny_patterns_ids
        );
    }
}
