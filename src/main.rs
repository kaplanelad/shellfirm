//! `shellfirm` will intercept any risky patterns (default or defined by you) and prompt you a small challenge for double verification, kinda like a captcha for your terminal.
//!
//! Protect yourself from yourself!
//! * `rm -rf *`
//! * `git reset --hard` before saving?
//! * `kubectl delete ns` which going to delete all resources under this namespace?
//! * And more!
//!
mod checks;
mod cli;
mod config;
mod prompt;
use colored::Colorize;
use config::Challenge;
use log::debug;
use regex::Regex;
use std::process::exit;

fn main() {
    env_logger::builder().format_timestamp(None).init();

    let mut app = cli::get_app();
    let matches = app.to_owned().get_matches();

    let config_dir = match config::get_config_folder() {
        Ok(config_dir) => config_dir,
        Err(err) => {
            eprintln!("Loading config error: {}", err.to_string());
            exit(1)
        }
    };

    // make sure that the application and configuration file ins exists and updated with the current version
    if let Err(err) = config_dir.manage_config_file() {
        eprintln!("{}", err.to_string());
        exit(1);
    }

    if let Some(validate_matches) = matches.subcommand_matches("pre-command") {
        let command = validate_matches.value_of("command").unwrap();

        let command = Regex::new(r#"('|")([\s\S]*?)('|")"#)
            .unwrap()
            .replace_all(command, "")
            .to_string();

        let conf = match config_dir.load_config_from_file() {
            Ok(conf) => conf,
            Err(e) => {
                eprintln!(
                    "Could not load config from file. Try resolving by running `{}`\nError: {}",
                    "shellfirm config reset".bold().italic().underline(),
                    e.to_string()
                );
                exit(1)
            }
        };

        // to be able push changes when releasing new version,
        // we can check if the config file is different then app version.
        // if yes we should do the following steps:
        // 1. update the config version
        // 2. adding/remove checks the changed from the baseline code
        if conf.version != env!("CARGO_PKG_VERSION") {
            config_dir.update_config_version(conf).unwrap();
            return;
        }

        let matches = checks::run_check_on_command(&conf.checks, &command);

        debug!("matches found {}. {:?}", matches.len(), matches);
        let mut success = true;
        if !matches.is_empty() {
            success = checks::challenge(
                &conf.challenge,
                &matches,
                validate_matches.is_present("test"),
            );
        }

        exit(!success as i32);
    } else if let Some(validate_matches) = matches.subcommand_matches("config") {
        if let Some(update_matches) = validate_matches.subcommand_matches("update") {
            let check_groups: Vec<&str> =
                update_matches.values_of("check-group").unwrap().collect();

            let res: Vec<String> = check_groups.iter().map(|s| s.to_string()).collect();

            if let Err(err) =
                config_dir.update_config_content(update_matches.is_present("remove"), &res)
            {
                eprintln!("Could not update checks group{}", err.to_string());
                exit(1)
            }

            exit(0);
        } else if validate_matches.subcommand_matches("reset").is_some() {
            if let Err(err) = config_dir.reset_config() {
                eprintln!("Could not reset settings {}", err.to_string());
                exit(1)
            }

            exit(0);
        } else if let Some(challenge_matches) = validate_matches.subcommand_matches("challenge") {
            let challenge = match challenge_matches.value_of("challenge").unwrap() {
                "Math" => Challenge::Math,
                "Enter" => Challenge::Enter,
                "Yes" => Challenge::Yes,
                _ => Challenge::Math,
            };

            if let Err(err) = config_dir.update_challenge(challenge) {
                eprintln!("Could not update challenge: {}", err.to_string());
                exit(1)
            }

            exit(0);
        }
    }

    app.print_long_help().unwrap();
}
