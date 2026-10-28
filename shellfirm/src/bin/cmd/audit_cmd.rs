use std::io::IsTerminal;

use clap::{Arg, ArgAction, ArgMatches, Command};
use shellfirm::checks::Severity;
use shellfirm::error::{Error, Result};
use shellfirm::{audit, Config};

pub fn command() -> Command {
    Command::new("audit")
        .about("View and manage the audit trail")
        .arg(super::config_dir_arg())
        .arg_required_else_help(true)
        .subcommand(
            Command::new("show")
                .about("Show the audit log")
                .long_about(
                    "Show the audit log. Every rotated generation (audit.log.N … audit.log.1) is \
                     read as well as the current file. By default the pre-challenge record and \
                     the final outcome of the same prompt are collapsed into one row.\n\n\
                     Outcomes: allowed, denied, skipped (below min_severity), cancelled (declined \
                     or aborted by a human), asked (handed to an AI agent's own prompt), \
                     no-terminal (blocked because nobody could answer the challenge).\n\n\
                     Examples:\n  shellfirm audit show --since 7d --outcome denied\n  \
                     shellfirm audit show --severity high --limit 20 --format json",
                )
                .arg(
                    Arg::new("format")
                        .long("format")
                        .value_parser(["text", "json", "jsonl"])
                        .default_value("text")
                        .help("Output format: text (table), json (array) or jsonl (one record per line)"),
                )
                .arg(
                    Arg::new("since")
                        .long("since")
                        .value_name("WHEN")
                        .help("Only records since a duration ago (30m, 12h, 7d, 2w) or a date/timestamp"),
                )
                .arg(
                    Arg::new("outcome")
                        .long("outcome")
                        .value_name("OUTCOME")
                        .help(format!("Only records with this outcome: {}", audit::OUTCOME_VALUES)),
                )
                .arg(
                    Arg::new("severity")
                        .long("severity")
                        .value_name("LEVEL")
                        .help("Only records at or above this severity: info, low, medium, high, critical"),
                )
                .arg(
                    Arg::new("limit")
                        .long("limit")
                        .short('n')
                        .value_name("N")
                        .value_parser(clap::value_parser!(usize))
                        .help("Show only the last N records"),
                )
                .arg(
                    Arg::new("all-records")
                        .long("all-records")
                        .action(ArgAction::SetTrue)
                        .help("Do not collapse pre-challenge and final records of the same prompt"),
                ),
        )
        .subcommand(
            Command::new("clear")
                .about("Delete the audit log and its rotated files (asks for confirmation)")
                .arg(
                    Arg::new("yes")
                        .long("yes")
                        .short('y')
                        .action(ArgAction::SetTrue)
                        .help("Do not ask for confirmation (for scripts)"),
                ),
        )
}

fn parse_severity(s: &str) -> Result<Severity> {
    match s.to_lowercase().as_str() {
        "info" => Ok(Severity::Info),
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        _ => Err(Error::Config(format!(
            "invalid severity '{s}'. Valid values: info, low, medium, high, critical"
        ))),
    }
}

pub fn run(matches: &ArgMatches, config: &Config) -> Result<shellfirm::CmdExit> {
    match matches.subcommand() {
        Some(("show", sub)) => run_show(config, sub),
        Some(("clear", sub)) => run_clear(config, sub.get_flag("yes")),
        _ => Ok(shellfirm::CmdExit {
            code: exitcode::USAGE,
            message: Some("Unknown audit subcommand.".to_string()),
        }),
    }
}

fn run_show(config: &Config, sub: &ArgMatches) -> Result<shellfirm::CmdExit> {
    let filter = audit::AuditFilter {
        since: sub
            .get_one::<String>("since")
            .map(|s| audit::parse_since(s))
            .transpose()?,
        outcome: sub
            .get_one::<String>("outcome")
            .map(|s| audit::AuditOutcome::parse(s))
            .transpose()?,
        min_severity: sub
            .get_one::<String>("severity")
            .map(|s| parse_severity(s))
            .transpose()?,
        limit: sub.get_one::<usize>("limit").copied(),
    };
    let format = sub
        .get_one::<String>("format")
        .map_or("text", String::as_str);

    let log_path = config.audit_log_path();
    let read = audit::read_entries(&log_path)?;
    let entries = if sub.get_flag("all-records") {
        read.entries
    } else {
        audit::collapse_events(read.entries)
    };
    let total = entries.len();
    let filtered = filter.since.is_some()
        || filter.outcome.is_some()
        || filter.min_severity.is_some()
        || filter.limit.is_some();
    let entries = audit::filter_entries(entries, &filter);

    let files_label = if read.files.len() > 1 {
        format!(
            "{} and {} rotated file(s)",
            log_path.display(),
            read.files.len() - 1
        )
    } else {
        log_path.display().to_string()
    };
    let text = match format {
        "json" => serde_json::to_string_pretty(&entries)?,
        "jsonl" => entries
            .iter()
            .map(serde_json::to_string)
            .collect::<std::result::Result<Vec<_>, _>>()?
            .join("\n"),
        _ => {
            if entries.is_empty() && total > 0 && filtered {
                format!("No audit events match the filter ({total} event(s) in {files_label}).")
            } else if entries.is_empty() {
                format!(
                    "No audit events recorded yet (log: {}).",
                    log_path.display()
                )
            } else {
                shellfirm::config::ascii_fallback(
                    audit::format_table(&entries).trim_end_matches('\n'),
                )
            }
        }
    };
    if !(format == "jsonl" && entries.is_empty()) {
        let out = crate::print_stdout(&text);
        if out.code != exitcode::OK {
            return Ok(out);
        }
    }
    if read.malformed > 0 {
        eprintln!(
            "shellfirm: warning: skipped {} malformed line(s) (invalid UTF-8, not JSON, or missing \
             timestamp/outcome) in {}",
            read.malformed,
            read.files
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: None,
    })
}

fn run_clear(config: &Config, yes: bool) -> Result<shellfirm::CmdExit> {
    let log_path = config.audit_log_path();
    if !log_path.exists() {
        return Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: Some("Audit log is already empty.".to_string()),
        });
    }
    if !yes {
        if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
            return Ok(shellfirm::CmdExit {
                code: exitcode::USAGE,
                message: Some(
                    "Refusing to delete the audit log without confirmation. \
                     Re-run in a terminal, or pass --yes."
                        .to_string(),
                ),
            });
        }
        let confirmed = shellfirm::prompt::confirm(
            &format!(
                "Permanently delete the audit log at {}?",
                log_path.display()
            ),
            false,
        )
        .map_err(|e| Error::Prompt(e.to_string()))?;
        if !confirmed {
            return Ok(shellfirm::CmdExit {
                code: exitcode::OK,
                message: Some("Audit log kept.".to_string()),
            });
        }
    }
    audit::clear_log(&log_path)?;
    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some("Audit log cleared.".to_string()),
    })
}
