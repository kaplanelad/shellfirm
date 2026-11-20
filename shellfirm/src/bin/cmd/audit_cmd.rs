use std::fmt::Write as _;
use std::io::IsTerminal;
use std::path::Path;

use clap::{Arg, ArgAction, ArgMatches, Command};
use shellfirm::agent::Decision;
use shellfirm::checks::Severity;
use shellfirm::env::{Environment, RealEnvironment};
use shellfirm::error::{Error, Result};
use shellfirm::replay::{self, AgentKind};
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
                        .help(
                            "Only records since a duration ago (30m, 12h, 7d, 2w), a date or \
                             timestamp (2026-01-31, 2026-01-31T10:00:00Z, +02:00 offsets; none \
                             = UTC), or `all`",
                        ),
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
        .subcommand(replay_command())
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

/// Default `--since` for `audit replay`.
const REPLAY_DEFAULT_SINCE: &str = "7d";
/// Default `--limit` for the `audit replay` text output.
const REPLAY_DEFAULT_LIMIT: usize = 25;

fn replay_command() -> Command {
    Command::new("replay")
        .about("Judge the commands past AI-agent sessions ran, as the hook would have")
        .long_about(
            "Read the session transcripts coding agents keep on disk (Claude Code: \
             ~/.claude/projects; Codex CLI: ~/.codex/sessions) and judge every shell command \
             and file operation the agent ran exactly as that agent's hook (`shellfirm check \
             --hook claude-code` / `--hook codex`) would have: with the recorded working \
             directory, your agent settings and the project policies that apply there (Codex \
             cannot ask, so an ask is a deny there, as in its hook). Then report what \
             shellfirm would have blocked (deny) or asked about (ask), worst first, identical \
             calls grouped (×N). Secrets in commands are shown as ***.\n\n\
             Local and read-only: nothing from a transcript is executed, no external program \
             is started for context (git, kubectl, ...), the LLM review is off, nothing leaves \
             the machine and nothing is written (not even shellfirm's audit log). Decisions \
             use today's settings, policies and files: a path deleted since then no longer \
             matches checks that need it to exist.\n\n\
             Exit status: 0, or with --fail-on: 11 when a deny was found, 10 when an ask was \
             found (--fail-on ask), counted after --min-severity and before --limit; otherwise \
             66 when a transcript file or directory could not be read or a compressed rollout \
             was skipped (the replay is incomplete; stderr says so whatever the exit status). \
             2 for a bad option value (an invalid or future --since, an empty --project or one \
             that is not a directory).\n\n\
             Examples:\n  shellfirm audit replay\n  \
             shellfirm audit replay --since 30d --agent codex --min-severity high\n  \
             shellfirm audit replay --project . --redact\n  \
             shellfirm audit replay --since all --json | jq 'select(.type == \"finding\")'\n  \
             shellfirm audit replay --since 24h --fail-on deny",
        )
        .arg(
            Arg::new("since")
                .long("since")
                .value_name("WHEN")
                .default_value(REPLAY_DEFAULT_SINCE)
                .help(
                    "Only calls since a duration ago (24h, 7d, 30d, 2w), a date or timestamp \
                     (as `audit show`), or `all`",
                ),
        )
        .arg(
            Arg::new("agent")
                .long("agent")
                .value_name("AGENT")
                .ignore_case(true)
                .value_parser(["claude-code", "codex", "all"])
                .default_value("all")
                .help("Which agent's sessions to read"),
        )
        .arg(
            Arg::new("project")
                .long("project")
                .value_name("PATH")
                .help("Only calls made in PATH or a directory below it"),
        )
        .arg(
            Arg::new("min-severity")
                .long("min-severity")
                .value_name("LEVEL")
                .ignore_case(true)
                .value_parser(["info", "low", "medium", "high", "critical"])
                .help("Only list findings at or above this severity (totals count every call)"),
        )
        .arg(
            Arg::new("limit")
                .long("limit")
                .short('n')
                .value_name("N")
                .value_parser(clap::value_parser!(usize))
                .help(format!(
                    "List at most N findings (default {REPLAY_DEFAULT_LIMIT} in text, all with \
                     --json; 0 = all)"
                )),
        )
        .arg(
            Arg::new("json")
                .long("json")
                .action(ArgAction::SetTrue)
                .help("JSON lines: one object per finding, then a summary object"),
        )
        .arg(
            Arg::new("redact")
                .long("redact")
                .action(ArgAction::SetTrue)
                .help(
                    "Show rule ids and reasons but no command text, file paths or session \
                     ids (projects by name only), for sharing. Lists the same findings",
                ),
        )
        .arg(
            Arg::new("fail-on")
                .long("fail-on")
                .value_name("DECISION")
                .ignore_case(true)
                .value_parser(["deny", "ask"])
                .help(
                    "Exit 11 when a deny was found (and, with `ask`, 10 when an ask was); 66 \
                     when a transcript could not be read or was compressed",
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
        Some(("replay", sub)) => run_replay(config, sub),
        _ => Ok(shellfirm::CmdExit {
            code: exitcode::USAGE,
            message: Some("Unknown audit subcommand.".to_string()),
        }),
    }
}

/// `--since WHEN` as a timestamp (`None` for `all`). An invalid or future
/// value is a usage error (exit 2, like any other bad flag value).
fn parse_since_arg(value: &str) -> Result<Option<String>> {
    if value.trim().eq_ignore_ascii_case("all") {
        return Ok(None);
    }
    let since = audit::parse_since(value).map_err(|e| match e {
        Error::Config(m) => Error::Usage(m),
        e => e,
    })?;
    if since > audit::now_timestamp() {
        return Err(Error::Usage(format!(
            "--since {value} is in the future ({since}): nothing can match"
        )));
    }
    Ok(Some(since))
}

fn run_show(config: &Config, sub: &ArgMatches) -> Result<shellfirm::CmdExit> {
    let filter = audit::AuditFilter {
        since: sub
            .get_one::<String>("since")
            .map(|s| parse_since_arg(s))
            .transpose()?
            .flatten(),
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

/// The exit code for `--fail-on` (`EXIT_DENY` / `EXIT_ASK` as for `check`;
/// otherwise `EXIT_INCOMPLETE` when some transcripts were not read, so an
/// unreadable source never passes silently).
fn replay_exit_code(findings: &[&replay::Finding], incomplete: bool, fail_on: Option<&str>) -> i32 {
    let deny = findings.iter().any(|f| f.decision == Decision::Deny);
    let ask = findings.iter().any(|f| f.decision == Decision::Ask);
    match fail_on {
        Some("deny" | "ask") if deny => super::check_cmd::EXIT_DENY,
        Some("ask") if ask => super::check_cmd::EXIT_ASK,
        Some(_) if incomplete => REPLAY_EXIT_INCOMPLETE,
        _ => exitcode::OK,
    }
}

/// The stderr line for a replay that did not read every transcript.
fn incomplete_message(report: &replay::ReplayReport, code: i32) -> String {
    let mut parts = Vec::new();
    let unreadable = report.unreadable();
    if unreadable > 0 {
        parts.push(if unreadable == 1 {
            "1 transcript file or directory could not be read".to_string()
        } else {
            format!("{unreadable} transcript files or directories could not be read")
        });
    }
    let compressed = report.compressed();
    if compressed > 0 {
        parts.push(if compressed == 1 {
            "1 compressed rollout was not read".to_string()
        } else {
            format!("{compressed} compressed rollouts were not read")
        });
    }
    let exit = if code == REPLAY_EXIT_INCOMPLETE {
        format!(" (exit {REPLAY_EXIT_INCOMPLETE})")
    } else {
        String::new()
    };
    format!(
        "shellfirm: {}: the replay is incomplete{exit}.",
        parts.join(", ")
    )
}

/// `audit replay --fail-on` exit code when some transcripts could not be
/// read (`EX_NOINPUT`).
const REPLAY_EXIT_INCOMPLETE: i32 = exitcode::NOINPUT;

/// The closing hint: how to have shellfirm decide these calls live.
fn replay_next_step(report: &replay::ReplayReport, home: Option<&Path>) -> String {
    let agents: Vec<AgentKind> = report
        .stats
        .iter()
        .filter(|s| s.commands + s.file_operations > 0)
        .filter_map(|s| s.agent)
        .collect();
    // The user-scope hook only: it covers every project replay reads (a
    // project-scope hook in the current directory does not).
    let status = home.map(|h| super::connect_cmd::integration_status(h, h));
    let connected = |tool: &str| {
        status
            .as_ref()
            .is_some_and(|s| s.iter().any(|s| s.tool == tool && s.hook_installed))
    };
    let mut wanted: Vec<(&str, &str)> = Vec::new();
    if agents.contains(&AgentKind::ClaudeCode) || agents.is_empty() {
        wanted.push(("claude-code", "Claude Code"));
    }
    if agents.contains(&AgentKind::Codex) {
        wanted.push(("codex", "Codex CLI"));
    }
    let steps: Vec<String> = wanted
        .into_iter()
        .map(|(tool, name)| {
            if connected(tool) {
                format!(
                    "{name}'s hook is connected (user scope): new sessions get these decisions \
                     before each call runs (`shellfirm audit show` lists them)."
                )
            } else {
                format!(
                    "Next: `shellfirm connect {tool}` has shellfirm decide these before they run."
                )
            }
        })
        .collect();
    steps.join("\n")
}

/// `--project PATH` as an absolute directory (relative to the current one).
fn project_dir(value: &str) -> Result<std::path::PathBuf> {
    if value.trim().is_empty() {
        return Err(Error::Usage(
            "--project needs a directory (the value is empty)".to_string(),
        ));
    }
    let p = Path::new(value);
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| Error::Other(format!("could not read the current directory: {e}")))?
            .join(p)
    };
    if !abs.is_dir() {
        let why = if abs.exists() {
            "not a directory"
        } else {
            "no such directory"
        };
        return Err(Error::Usage(format!(
            "--project {}: {why}",
            shellfirm::context::escape_invisible(value)
        )));
    }
    Ok(abs)
}

/// The same warnings as `check` (an invalid settings file is replaced by
/// the defaults, so the decisions are not the ones you configured).
fn warn_about_settings(config: &Config, env: &RealEnvironment) {
    let no_exec = shellfirm::agent::NoExecEnvironment::new(env);
    let cwd = env.current_dir().unwrap_or_default();
    match shellfirm::agent::load_agent_inputs(config, &no_exec, &cwd) {
        Ok(l) => l
            .warnings
            .iter()
            .for_each(|w| eprintln!("shellfirm: warning: {w}")),
        Err(e) => eprintln!("shellfirm: warning: {e}"),
    }
}

fn run_replay(config: &Config, sub: &ArgMatches) -> Result<shellfirm::CmdExit> {
    let since_arg = sub
        .get_one::<String>("since")
        .map_or(REPLAY_DEFAULT_SINCE, String::as_str);
    let since = parse_since_arg(since_arg)?;
    let agents = match sub
        .get_one::<String>("agent")
        .map(|s| s.to_ascii_lowercase())
    {
        Some(a) if a != "all" => AgentKind::parse(&a).into_iter().collect(),
        _ => Vec::new(),
    };
    let project = sub
        .get_one::<String>("project")
        .map(|p| project_dir(p))
        .transpose()?;
    let json = sub.get_flag("json");
    let redact = sub.get_flag("redact");
    let limit = match sub.get_one::<usize>("limit").copied() {
        Some(0) => None,
        Some(n) => Some(n),
        None if json => None,
        None => Some(REPLAY_DEFAULT_LIMIT),
    };
    let min_severity = sub
        .get_one::<String>("min-severity")
        .map(|s| parse_severity(s))
        .transpose()?;
    let fail_on = sub
        .get_one::<String>("fail-on")
        .map(|s| s.to_ascii_lowercase());

    let env = RealEnvironment;
    warn_about_settings(config, &env);
    let opts = replay::ReplayOptions {
        since,
        agents,
        project,
    };
    let report = replay::replay(config, &env, &replay::sources(), &opts);
    let home = env.home_dir();
    let out_opts = replay::OutputOptions {
        redact,
        min_severity,
        limit,
        home: home.clone(),
    };
    let text = if json {
        let mut lines: Vec<String> = replay::select(&report.findings, min_severity, limit)
            .into_iter()
            .map(|f| replay::finding_json(f, &out_opts).to_string())
            .collect();
        lines.push(replay::summary_json(&report, &out_opts).to_string());
        lines.join("\n")
    } else {
        let window = replay::window_label(report.since.as_deref(), since_arg);
        let mut t = replay::format_text(&report, &window, &out_opts);
        let _ = write!(
            t,
            "\n{}\n{}",
            console::style(
                "Read-only: nothing was run, sent or written (shellfirm's audit log included)."
            )
            .dim(),
            replay_next_step(&report, home.as_deref())
        );
        shellfirm::config::ascii_fallback(&t)
    };
    let out = crate::print_stdout(&text);
    if out.code != exitcode::OK {
        return Ok(out);
    }
    let failing = replay::select(&report.findings, min_severity, None);
    let code = replay_exit_code(&failing, report.incomplete(), fail_on.as_deref());
    if report.incomplete() {
        eprintln!(
            "{}",
            console::style(incomplete_message(&report, code))
                .for_stderr()
                .yellow()
        );
    }
    Ok(shellfirm::CmdExit {
        code,
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
