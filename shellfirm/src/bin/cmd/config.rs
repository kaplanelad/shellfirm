use anyhow::{anyhow, Result};
use clap::{App, AppSettings::ArgRequiredElseHelp, Arg, ArgMatches, Command};
use shellfirm::{dialog, Challenge, Config, Settings};
use strum::IntoEnumIterator;

const ALL_GROUP_CHECKS: &[&str] = &include!(concat!(env!("OUT_DIR"), "/all_the_files.rs"));

pub fn command() -> Command<'static> {
    Command::new("config")
        .about("Manage app config")
        .setting(ArgRequiredElseHelp)
        .subcommand(
            App::new("update-groups")
                .about("enable check group")
                .arg(Arg::new("check-group").help("Check group")),
        )
        .subcommand(App::new("reset").about("Reset configuration"))
        .subcommand(App::new("challenge").about("Reset configuration"))
        .subcommand(App::new("ignore").about("Ignore command pattern"))
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
            ("challenge", _subcommand_matches) => run_challenge(config, None),
            ("ignore", _subcommand_matches) => run_ignore(config, settings, None),
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

    match config.update_check_groups(check_groups) {
        Ok(()) => Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: None,
        }),
        Err(e) => Ok(shellfirm::CmdExit {
            code: exitcode::CONFIG,
            message: Some(format!("Could not update checks group. error: {}", e)),
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
            message: Some(format!("reset settings error: {:?}", e)),
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
            message: None,
        }),
        Err(e) => Ok(shellfirm::CmdExit {
            code: exitcode::CONFIG,
            message: Some(format!("change challenge error: {:?}", e)),
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
            settings.ignores.clone(),
            100,
        )?
    };

    match config.update_ignores(selected) {
        Ok(()) => Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: None,
        }),
        Err(e) => Ok(shellfirm::CmdExit {
            code: exitcode::CONFIG,
            message: Some(format!("update pattern ignore errors: {:?}", e)),
        }),
    }
}

#[cfg(test)]
mod test_config_cli_command {

    use std::fs;

    use insta::{assert_debug_snapshot, with_settings};
    use tempdir::TempDir;

    use super::*;

    fn initialize_config_folder(temp_dir: &TempDir) -> Config {
        let temp_dir = temp_dir.path().join("app");
        Config::new(Some(&temp_dir.display().to_string())).unwrap()
    }

    #[test]
    fn can_run_update_groups() {
        let temp_dir = TempDir::new("config-app").unwrap();
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
        let temp_dir = TempDir::new("config-app").unwrap();
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
        let temp_dir = TempDir::new("config-app").unwrap();
        let config = initialize_config_folder(&temp_dir);
        config.update_challenge(Challenge::Yes).unwrap();
        assert_debug_snapshot!(run_reset(&config, Some(1)));
        assert_debug_snapshot!(config.get_settings_from_file());
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_run_reset_with_error() {
        let temp_dir = TempDir::new("config-app").unwrap();
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
        let temp_dir = TempDir::new("config-app").unwrap();
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
        let temp_dir = TempDir::new("config-app").unwrap();
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
        let temp_dir = TempDir::new("config-app").unwrap();
        let config = initialize_config_folder(&temp_dir);
        let settings = config.get_settings_from_file().unwrap();
        assert_debug_snapshot!(run_ignore(
            &config,
            &settings,
            Some(vec!["id-1".to_string(), "id-2".to_string()])
        ));
        assert_debug_snapshot!(config.get_settings_from_file().unwrap().ignores);
        temp_dir.close().unwrap();
    }
}
