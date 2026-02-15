use anyhow::Result;
use clap::{ArgMatches, Command};
use shellfirm::{audit, Config};

pub fn command() -> Command {
    Command::new("audit")
        .about("View and manage the audit trail")
        .arg_required_else_help(true)
        .subcommand(Command::new("show").about("Show the audit log"))
        .subcommand(Command::new("clear").about("Clear the audit log"))
}

pub fn run(matches: &ArgMatches, config: &Config) -> Result<shellfirm::CmdExit> {
    match matches.subcommand() {
        Some(("show", _)) => {
            let log_path = config.audit_log_path();
            let content = audit::read_log(&log_path)?;
            println!("{content}");
            Ok(shellfirm::CmdExit {
                code: exitcode::OK,
                message: None,
            })
        }
        Some(("clear", _)) => {
            let log_path = config.audit_log_path();
            audit::clear_log(&log_path)?;
            Ok(shellfirm::CmdExit {
                code: exitcode::OK,
                message: Some("Audit log cleared.".to_string()),
            })
        }
        _ => Ok(shellfirm::CmdExit {
            code: exitcode::USAGE,
            message: Some("Unknown audit subcommand.".to_string()),
        }),
    }
}
