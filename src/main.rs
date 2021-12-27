mod cli;
mod config;
use std::fs;
use std::process::exit;

fn main() {
    let app = cli::get_app();
    let matches = app.to_owned().get_matches();

    let config_dir = match config::get_config_folder(matches.value_of("config").unwrap_or_default())
    {
        Ok(config_dir) => config_dir,
        Err(err) => {
            eprintln!("Error: {}", err.to_string());
            exit(1)
        }
    };

    if let Err(err) = fs::create_dir(&config_dir.path) {
        if err.kind() != std::io::ErrorKind::AlreadyExists {
            eprintln!("could not create folder: {}", err.to_string());
            exit(1)
        }
    }

    if let Err(err) = config::manage_config_file(&config_dir) {
        eprintln!("could not get config file: {}", err.to_string());
        exit(1);
    }

    let app_config = config_dir.load_config_from_file();
    println!("{:?}", app_config);
}
