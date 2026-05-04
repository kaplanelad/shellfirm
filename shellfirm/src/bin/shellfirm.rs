mod cmd;
use std::process::exit;

use console::{style, Style};
use shellfirm::error::{Error, Result};
use shellfirm::{CmdExit, Config};

const DEFAULT_ERR_EXIT_CODE: i32 = 1;

#[allow(clippy::too_many_lines)]
fn main() {
    let mut app = cmd::default::command()
        .subcommand(cmd::command::command())
        .subcommand(cmd::config::command())
        .subcommand(cmd::init::command())
        .subcommand(cmd::connect_cmd::command())
        .subcommand(cmd::audit_cmd::command())
        .subcommand(cmd::policy_cmd::command())
        .subcommand(cmd::check_cmd::command())
        .subcommand(cmd::completions_cmd::command())
        .subcommand(cmd::status_cmd::command());

    #[cfg(feature = "mcp")]
    {
        app = app.subcommand(cmd::mcp_cmd::command());
    }

    #[cfg(feature = "wrap")]
    {
        app = app.subcommand(cmd::wrap_cmd::command());
    }

    let matches = app.clone().get_matches();

    // Handle completions command early (doesn't need config)
    if let Some(("completions", sub_matches)) = matches.subcommand() {
        shellfirm_exit(Ok(cmd::completions_cmd::run(sub_matches, &mut app)));
    }

    let filter = tracing_subscriber::EnvFilter::try_from_env("SHELLFIRM_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("error"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    // Handle init command early (doesn't need config)
    if let Some(("init", sub_matches)) = matches.subcommand() {
        shellfirm_exit(cmd::init::run(sub_matches));
    }

    // Handle connect command early (doesn't need config)
    if let Some(("connect", sub_matches)) = matches.subcommand() {
        shellfirm_exit(cmd::connect_cmd::run(sub_matches));
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

    // Handle config commands early — some subcommands (like reset, show, challenge, etc.)
    // don't need loaded checks, and `config` (no subcommand) should show the interactive menu.
    if let Some(("config", subcommand_matches)) = matches.subcommand() {
        shellfirm_exit(cmd::config::run(subcommand_matches, &config));
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

    // Load custom checks from ~/.shellfirm/checks/
    let custom_checks_dir = config.custom_checks_dir();
    let custom = match shellfirm::checks::load_custom_checks(&custom_checks_dir) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Could not load custom checks: {e}");
            Vec::new()
        }
    };
    if !custom.is_empty() {
        tracing::info!("Loaded {} custom check(s)", custom.len());
    }

    // One-shot migration: ensure custom-check group names appear in enabled_groups
    // so the new filter logic doesn't silently disable them after upgrade.
    let mut settings = settings;
    let added = settings.migrate_custom_groups_into_enabled_groups(&custom);
    if !added.is_empty() {
        tracing::info!(
            "shellfirm: added new custom-check groups to enabled_groups: {}",
            added.join(", ")
        );
        if let Err(e) = config.save_settings_file_from_struct(&settings) {
            tracing::warn!("could not persist migration: {e}");
        }
    }

    let checks = match settings.get_active_checks_with_custom(&custom) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Could not load checks: {e}");
            exit(1)
        }
    };

    let res = matches.subcommand().map_or_else(
        || Err(Error::Other("command not found".into())),
        |tup| match tup {
            ("pre-command", subcommand_matches) => {
                cmd::command::run(subcommand_matches, &settings, &checks, &config)
            }
            ("audit", subcommand_matches) => cmd::audit_cmd::run(subcommand_matches, &config),
            ("check", subcommand_matches) => {
                cmd::check_cmd::run(subcommand_matches, &settings, &checks)
            }
            ("status", subcommand_matches) => Ok(cmd::status_cmd::run(
                subcommand_matches,
                &config,
                &settings,
                &checks,
            )),
            #[cfg(feature = "mcp")]
            ("mcp", subcommand_matches) => {
                cmd::mcp_cmd::run(subcommand_matches, &settings, &checks, &config)
            }
            #[cfg(feature = "wrap")]
            ("wrap", subcommand_matches) => {
                cmd::wrap_cmd::run(subcommand_matches, &settings, &checks, &config)
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
            tracing::debug!("{e:?}");
            DEFAULT_ERR_EXIT_CODE
        }
    };
    exit(exit_with);
}
