mod cmd;
use std::process::exit;

use anyhow::{anyhow, Result};
use console::{style, Style};
use shellfirm::{CmdExit, Config};

const DEFAULT_ERR_EXIT_CODE: i32 = 1;

fn main() {
    let mut app = cmd::default::command()
        .subcommand(cmd::command::command())
        .subcommand(cmd::config::command())
        .subcommand(cmd::init::command())
        .subcommand(cmd::audit_cmd::command())
        .subcommand(cmd::policy_cmd::command())
        .subcommand(cmd::check_cmd::command())
        .subcommand(cmd::completions_cmd::command())
        .subcommand(cmd::status_cmd::command());

    let matches = app.clone().get_matches();

    // Handle completions command early (doesn't need config)
    if let Some(("completions", sub_matches)) = matches.subcommand() {
        shellfirm_exit(Ok(cmd::completions_cmd::run(sub_matches, &mut app)));
    }

    let env = env_logger::Env::default().filter_or(
        "LOG",
        matches
            .get_one::<String>("log")
            .map_or(log::Level::Info.as_str(), String::as_str),
    );
    env_logger::init_from_env(env);

    // Handle init command early (doesn't need config)
    if let Some(("init", sub_matches)) = matches.subcommand() {
        shellfirm_exit(cmd::init::run(sub_matches));
    }

    // Handle policy command early (doesn't need full config)
    if let Some(("policy", sub_matches)) = matches.subcommand() {
        shellfirm_exit(cmd::policy_cmd::run(sub_matches));
    }

    // load configuration
    let config = match Config::new(None) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("Loading config error: {err}");
            exit(1)
        }
    };

    if let Some((command_name, subcommand_matches)) = matches.subcommand() {
        if command_name == "config" && subcommand_matches.subcommand_name() == Some("reset") {
            let c = cmd::config::run_reset(&config, None);
            shellfirm_exit(Ok(c));
        }
    }

    let settings = match config.get_settings_from_file() {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "Could not load setting from file. Try resolving by running `{}`\nError: {}",
                style("shellfirm config reset").bold().italic().underlined(),
                e
            );
            exit(1)
        }
    };

    // Load built-in checks
    let mut checks = match settings.get_active_checks() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Could not load checks: {e}");
            exit(1)
        }
    };

    // Load custom checks from ~/.shellfirm/checks/
    let custom_checks_dir = config.custom_checks_dir();
    match shellfirm::checks::load_custom_checks(&custom_checks_dir) {
        Ok(custom) => {
            if !custom.is_empty() {
                log::info!("Loaded {} custom check(s)", custom.len());
                checks.extend(custom);
            }
        }
        Err(e) => {
            log::warn!("Could not load custom checks: {e}");
        }
    }

    let res = matches.subcommand().map_or_else(
        || Err(anyhow!("command not found")),
        |tup| match tup {
            ("pre-command", subcommand_matches) => {
                cmd::command::run(subcommand_matches, &settings, &checks, &config)
            }
            ("config", subcommand_matches) => {
                cmd::config::run(subcommand_matches, &config, &settings)
            }
            ("audit", subcommand_matches) => {
                cmd::audit_cmd::run(subcommand_matches, &config)
            }
            ("check", subcommand_matches) => {
                cmd::check_cmd::run(subcommand_matches, &settings, &checks)
            }
            ("status", subcommand_matches) => {
                Ok(cmd::status_cmd::run(subcommand_matches, &config, &settings, &checks))
            }
            _ => unreachable!(),
        },
    );

    shellfirm_exit(res);
}

fn shellfirm_exit(res: Result<CmdExit>) {
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
            log::debug!("{e:?}");
            DEFAULT_ERR_EXIT_CODE
        }
    };
    exit(exit_with);
}
