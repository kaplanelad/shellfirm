use anyhow::{anyhow, Result};
use clap::{App, Arg, ArgMatches, Command};
use shellfirm::{Challenge, Config};

const ALL_GROUP_CHECKS: &[&str] = &include!(concat!(env!("OUT_DIR"), "/all_the_files.rs"));

pub fn command() -> Command<'static> {
    Command::new("config")
        .about("Manage app config")
        .subcommand(
            App::new("update")
                .about("add/remove check group")
                .arg(
                    Arg::new("check-group")
                        .help("Check group")
                        .possible_values(ALL_GROUP_CHECKS)
                        .multiple_values(true)
                        .required(true)
                        .min_values(1),
                )
                .arg(
                    Arg::new("remove")
                        .long("remove")
                        .help("remove the given checks")
                        .possible_values(ALL_GROUP_CHECKS)
                        .takes_value(false),
                ),
        )
        .subcommand(App::new("reset").about("Reset configuration"))
        .subcommand(
            App::new("challenge").about("Reset configuration").arg(
                Arg::new("challenge")
                    .possible_values(&["Math", "Enter", "Yes"])
                    .required(true)
                    .takes_value(true),
            ),
        )
}

pub fn run(matches: &ArgMatches, settings: &Config) -> Result<shellfirm::CmdExit> {
    match matches.subcommand() {
        None => Err(anyhow!("command not found")),
        Some(tup) => match tup {
            ("update", subcommand_matches) => run_update(subcommand_matches, settings),
            ("reset", _subcommand_matches) => run_reset(settings),
            ("challenge", subcommand_matches) => run_challenge(subcommand_matches, settings),
            _ => unreachable!(),
        },
    }
}

pub fn run_update(matches: &ArgMatches, settings: &Config) -> Result<shellfirm::CmdExit> {
    let check_groups: Vec<&str> = match matches.values_of("check-group") {
        Some(g) => g.collect(),
        None => return Err(anyhow!("check-group not found")),
    };

    let res: Vec<String> = check_groups
        .iter()
        .map(std::string::ToString::to_string)
        .collect();

    match settings.update_config_content(matches.is_present("remove"), &res) {
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

pub fn run_challenge(matches: &ArgMatches, settings: &Config) -> Result<shellfirm::CmdExit> {
    let challenge = match matches.value_of("challenge").unwrap() {
        "Enter" => Challenge::Enter,
        "Yes" => Challenge::Yes,
        _ => Challenge::Math,
    };

    settings.update_challenge(challenge)?;

    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: None,
    })
}
