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
            ("update-groups", _subcommand_matches) => run_update_groups(config),
            ("reset", _subcommand_matches) => run_reset(config),
            ("challenge", _subcommand_matches) => run_challenge(config),
            _ => unreachable!(),
        },
    }
}

pub fn run_update_groups(config: &Config) -> Result<shellfirm::CmdExit> {
    let all_groups = ALL_GROUP_CHECKS.iter().map(|f| f.to_string()).collect();
    let settings = config.get_settings_from_file()?;

    let check_groups = dialog::multi_choice(
        "select checks",
        all_groups,
        settings.get_active_groups().to_vec(),
        100,
    )?;

    let res: Vec<String> = check_groups
        .iter()
        .map(std::string::ToString::to_string)
        .collect();

    match config.update_check_groups(res) {
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

pub fn run_reset(settings: &Config) -> Result<shellfirm::CmdExit> {
    settings.reset_config(None)?;

    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some("shellfirm configuration reset successfully".to_string()),
    })
}

pub fn run_challenge(settings: &Config) -> Result<shellfirm::CmdExit> {
    let challenges = Challenge::iter().map(|c| c.to_string()).collect::<Vec<_>>();
    let selection_challenge =
        Challenge::from_string(&dialog::select("change shellfirm challenge", &challenges)?)?;

    settings.update_challenge(selection_challenge)?;
    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: None,
    })
}
