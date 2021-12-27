mod checks;
mod cli;
mod config;
use std::process::exit;

fn main() {
    let app = cli::get_app();
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

    let matches = match config_dir.load_config_from_file() {
        Ok(conf) => checks::run_check_on_command(&conf.checks, "git reset"),
        Err(e) => {
            eprintln!("Error: {}", e.to_string());
            exit(1)
        }
    };

    println!("matches found: {}", matches.len());

    for m in matches {
        m.show()
    }
}
