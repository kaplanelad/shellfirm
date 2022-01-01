mod checks;
mod cli;
mod config;
use std::process::exit;

use config::Challenge;

fn main() {
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

        let conf = match config_dir.load_config_from_file() {
            Ok(conf) => conf,
            Err(e) => {
                eprintln!("Could not load config from file: {}", e.to_string());
                exit(1)
            }
        };

        let matches = checks::run_check_on_command(&conf.checks, command);

        let mut should_continue = 0;
        for m in matches {
            if !m.show(&conf.challenge, validate_matches.is_present("test")) {
                should_continue = 2;
                break;
            }
        }

        exit(should_continue);
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
                eprintln!("Could not reset settings{}", err.to_string());
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
