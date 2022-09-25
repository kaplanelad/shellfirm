use anyhow::Result;
use clap::{Arg, ArgMatches, Command};
use lazy_static::lazy_static;
use regex::Regex;
use shellfirm::{checks, checks::Check, Settings};

lazy_static! {
    static ref REGEX_STRING_COMMAND_REPLACE: Regex = Regex::new(r#"('|")([\s\S]*?)('|")"#).unwrap();
}

pub fn command() -> Command<'static> {
    Command::new("pre-command")
        .about("Check if given command marked as sensitive command that need your extra approval.")
        .arg(
            Arg::new("command")
                .short('c')
                .long("command")
                .help("get the user command that should run.")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::new("test")
                .short('t')
                .long("test")
                .help("Check if the command is risky and exit")
                .takes_value(false),
        )
}

pub fn run(
    arg_matches: &ArgMatches,
    settings: &Settings,
    checks: &[Check],
) -> Result<shellfirm::CmdExit> {
    let command = arg_matches.value_of("command").unwrap_or(""); // todo:: wrap me

    let command = REGEX_STRING_COMMAND_REPLACE
        .replace_all(command, "")
        .to_string();

    let splitted_command: Vec<&str> = command
        .split(|c| c == '&' || c == '|' || c == "&&".chars().next().unwrap())
        .collect();

    log::debug!("splitted_command {:?}", splitted_command);
    let matches: Vec<checks::Check> = splitted_command
        .iter()
        .flat_map(|c| checks::run_check_on_command(checks, c))
        .collect();

    log::debug!("matches found {}. {:?}", matches.len(), matches);
    if !matches.is_empty() {
        checks::challenge(
            &settings.challenge,
            &matches,
            arg_matches.is_present("test"),
        )?;
    }

    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: None,
    })
}
