use anyhow::{anyhow, Result};
use clap::{App, Arg, ArgMatches, Command};
use shellfirm::{dialog, Challenge, Config};
use strum::IntoEnumIterator;

const ALL_GROUP_CHECKS: &[&str] = &include!(concat!(env!("OUT_DIR"), "/all_the_files.rs"));

pub fn command() -> Command<'static> {
    Command::new("config")
        .about("Manage app config")
        .subcommand(
            App::new("update-groups")
                .about("enable check group")
                .arg(Arg::new("check-group").help("Check group")),
        )
        .subcommand(App::new("reset").about("Reset configuration"))
        .subcommand(App::new("challenge").about("Reset configuration"))
}

pub fn run(matches: &ArgMatches, config: &Config) -> Result<shellfirm::CmdExit> {
    match matches.subcommand() {
        None => Err(anyhow!("command not found")),
        Some(tup) => match tup {
            ("update-groups", _subcommand_matches) => run_update_groups(config, None),
            ("reset", _subcommand_matches) => run_reset(config, None),
            ("challenge", _subcommand_matches) => run_challenge(config, None),
            _ => unreachable!(),
        },
    }
}

pub fn run_update_groups(
    config: &Config,
    groups: Option<Vec<String>>,
) -> Result<shellfirm::CmdExit> {
    let settings = config.get_settings_from_file()?;

    let check_groups = match groups {
        Some(g) => g,
        None => {
            let all_groups = ALL_GROUP_CHECKS.iter().map(|f| f.to_string()).collect();
            dialog::multi_choice(
                "select checks",
                all_groups,
                settings.get_active_groups().to_vec(),
                100,
            )?
        }
    };

    match config.update_check_groups(check_groups) {
        Ok(()) => Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: None,
        }),
        Err(e) => Ok(shellfirm::CmdExit {
            code: exitcode::CONFIG,
            message: Some(format!("Could not update checks group. err: {}", e)),
        }),
    }
}

pub fn run_reset(config: &Config, force_selection: Option<usize>) -> Result<shellfirm::CmdExit> {
    match config.reset_config(force_selection) {
        Ok(()) => Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: Some("shellfirm configuration reset successfully".to_string()),
        }),
        Err(e) => Ok(shellfirm::CmdExit {
            code: exitcode::CONFIG,
            message: Some(format!("reset settings error: {:?}", e)),
        }),
    }
}

pub fn run_challenge(config: &Config, challenge: Option<Challenge>) -> Result<shellfirm::CmdExit> {
    let selection_challenge = match challenge {
        Some(c) => c,
        None => {
            let challenges = Challenge::iter().map(|c| c.to_string()).collect::<Vec<_>>();
            Challenge::from_string(&dialog::select("change shellfirm challenge", &challenges)?)?
        }
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
        assert_debug_snapshot!(run_update_groups(&config, Some(vec!["test-1".to_string()])));
        assert_debug_snapshot!(config.get_settings_from_file());
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
}
