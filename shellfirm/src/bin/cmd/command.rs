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
    run_pre_command(
        arg_matches.value_of("command").unwrap_or(""),
        settings,
        checks,
        arg_matches.is_present("test"),
    )
}

pub fn run_pre_command(
    command: &str,
    settings: &Settings,
    checks: &[Check],
    dryrun: bool,
) -> Result<shellfirm::CmdExit> {
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

    if dryrun {
        return Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: Some(serde_yaml::to_string(&matches)?),
        });
    }

    if !matches.is_empty() {
        checks::challenge(&settings.challenge, &matches, &settings.deny_patterns_ids)?;
    }

    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: None,
    })
}

#[cfg(test)]
mod test_command_cli_command {

    use insta::assert_debug_snapshot;
    use shellfirm::Config;
    use tempdir::TempDir;

    use super::*;

    fn initialize_config_folder(temp_dir: &TempDir) -> Config {
        let temp_dir = temp_dir.path().join("app");
        Config::new(Some(&temp_dir.display().to_string())).unwrap()
    }

    #[test]
    fn can_run_pre_command() {
        let temp_dir = TempDir::new("config-app").unwrap();
        let settings = initialize_config_folder(&temp_dir)
            .get_settings_from_file()
            .unwrap();

        assert_debug_snapshot!(run_pre_command(
            "rm -rf /",
            &settings,
            &settings.get_active_checks().unwrap(),
            true
        ));
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_run_pre_command_without_match() {
        let temp_dir = TempDir::new("config-app").unwrap();
        let settings = initialize_config_folder(&temp_dir)
            .get_settings_from_file()
            .unwrap();

        assert_debug_snapshot!(run_pre_command(
            "command",
            &settings,
            &settings.get_active_checks().unwrap(),
            true
        ));
        temp_dir.close().unwrap();
    }
}
