use std::path::PathBuf;

use clap::{Arg, ArgMatches, Command};
use shellfirm::error::Result;
use shellfirm::policy;

pub fn command() -> Command {
    Command::new("policy")
        .about("Manage project-level .shellfirm.yaml policies")
        .arg_required_else_help(true)
        .subcommand(
            Command::new("init")
                .about("Create a .shellfirm.yaml template in the current directory"),
        )
        .subcommand(
            Command::new("validate")
                .about("Validate a .shellfirm.yaml file")
                .arg(Arg::new("file").help("Path to the policy file (default: .shellfirm.yaml)")),
        )
}

pub fn run(matches: &ArgMatches) -> Result<shellfirm::CmdExit> {
    match matches.subcommand() {
        Some(("init", _)) => {
            let path = PathBuf::from(".shellfirm.yaml");
            if path.exists() {
                return Ok(shellfirm::CmdExit {
                    code: exitcode::USAGE,
                    message: Some(".shellfirm.yaml already exists in this directory.".to_string()),
                });
            }
            std::fs::write(&path, policy::scaffold_policy())?;
            Ok(shellfirm::CmdExit {
                code: exitcode::OK,
                message: Some("Created .shellfirm.yaml template.".to_string()),
            })
        }
        Some(("validate", sub_matches)) => {
            let file = sub_matches
                .get_one::<String>("file")
                .map_or(".shellfirm.yaml", String::as_str);
            let content = std::fs::read_to_string(file)?;
            match policy::validate_policy(&content) {
                Ok(warnings) => {
                    if warnings.is_empty() {
                        Ok(shellfirm::CmdExit {
                            code: exitcode::OK,
                            message: Some(format!("{file}: valid")),
                        })
                    } else {
                        let msg = warnings
                            .iter()
                            .map(|w| format!("  - {w}"))
                            .collect::<Vec<_>>()
                            .join("\n");
                        Ok(shellfirm::CmdExit {
                            code: exitcode::DATAERR,
                            message: Some(format!("{file}: warnings:\n{msg}")),
                        })
                    }
                }
                Err(e) => Ok(shellfirm::CmdExit {
                    code: exitcode::DATAERR,
                    message: Some(format!("{file}: invalid — {e}")),
                }),
            }
        }
        _ => Ok(shellfirm::CmdExit {
            code: exitcode::USAGE,
            message: Some("Unknown policy subcommand.".to_string()),
        }),
    }
}
