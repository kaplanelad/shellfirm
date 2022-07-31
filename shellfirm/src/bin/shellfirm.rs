mod cmd;
use anyhow::anyhow;
use console::style;
use console::Style;
use shellfirm::get_config_folder;
use std::process::exit;

const DEFAULT_ERR_EXIT_CODE: i32 = 1;

fn main() {
    let app = cmd::default::command()
        .subcommand(cmd::command::command())
        .subcommand(cmd::config::command());

    let matches = app.clone().get_matches();

    let env = env_logger::Env::default().filter_or(
        "LOG",
        matches.value_of("log").unwrap_or(log::Level::Info.as_str()),
    );
    env_logger::init_from_env(env);

    // load configuration
    let config = match get_config_folder() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("Loading config error: {}", err);
            exit(1)
        }
    };

    let context = match config.load_config_from_file() {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "Could not load config from file. Try resolving by running `{}`\nError: {}",
                style("shellfirm config reset").bold().italic().underlined(),
                e
            );
            exit(1)
        }
    };

    // to be able push changes when releasing new version,
    // we can check if the config file is different then app version.
    // if yes we should do the following steps:
    // 1. update the config version
    // 2. adding/remove checks the changed from the baseline code
    if context.version != env!("CARGO_PKG_VERSION") {
        if let Err(err) = config.update_config_version(&context) {
            log::debug!("could not update version configuration. err: {}", err);
            exit(1)
        }
    }

    let res = match matches.subcommand() {
        None => Err(anyhow!("command not found")),
        Some(tup) => match tup {
            ("pre-command", subcommand_matches) => cmd::command::run(subcommand_matches, &context),
            ("config", subcommand_matches) => cmd::config::run(subcommand_matches, &config),
            _ => unreachable!(),
        },
    };

    let exit_with = match res {
        Ok(cmd) => {
            if let Some(message) = cmd.message {
                let style = if exitcode::is_success(cmd.code) {
                    Style::new().green()
                } else {
                    Style::new().red()
                };
                eprintln!("{}", style.apply_to(message));
            }
            cmd.code
        }
        Err(e) => {
            log::debug!("{:?}", e);
            DEFAULT_ERR_EXIT_CODE
        }
    };
    exit(exit_with)
}
