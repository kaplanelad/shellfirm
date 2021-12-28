mod checks;
mod cli;
mod config;
use std::process::exit;

fn main() {
    let mut app = cli::get_app();
    let matches = app.to_owned().get_matches();

    // TODO:: get config from environment variable
    let config_dir = match config::get_config_folder(matches.value_of("config").unwrap_or_default())
    {
        Ok(config_dir) => config_dir,
        Err(err) => {
            eprintln!("Error: {}", err.to_string());
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
                eprintln!("Error: {}", e.to_string());
                exit(1)
            }
        };

        let matches = checks::run_check_on_command(&conf.checks, command);

        let mut should_continue = 0;
        for m in matches {
            if !m.show(&conf.challenge) {
                should_continue = 2;
                break;
            }
        }

        exit(should_continue);
    }
    if let Some(validate_matches) = matches.subcommand_matches("update-configuration") {
        let behaver = validate_matches.value_of("behaver").unwrap();
        if let Err(err) = config_dir.update_config_content(behaver) {
            eprintln!(
                "Error while trying to update configuration. Error: {}",
                err.to_string()
            );
            exit(1)
        }
    } else {
        app.print_long_help().unwrap();
    }
}
