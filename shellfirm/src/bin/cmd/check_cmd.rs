use std::fmt::Write;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use clap::{Arg, ArgAction, ArgMatches, Command};
use shellfirm::agent::{self, AgentAuditInfo, Decision, RiskAssessment};
use shellfirm::error::Result;
use shellfirm::{
    checks::{self, Check, Severity},
    env::{Environment, RealEnvironment},
    Config, Settings,
};

// ---------------------------------------------------------------------------
// Exit-code contract (documented in `shellfirm check --help`)
// ---------------------------------------------------------------------------

/// Command allowed / nothing risky (or `--exit-code` not given).
pub const EXIT_OK: i32 = 0;
/// Internal error or unreadable input.
pub const EXIT_ERROR: i32 = 1;
/// Usage error (same as clap's).
pub const EXIT_USAGE: i32 = 2;
/// Risky: a human should confirm (`decision: ask`).
pub const EXIT_ASK: i32 = 10;
/// Blocked (`decision: deny`).
pub const EXIT_DENY: i32 = 11;

/// Maximum hook/stdin payload we accept (anything larger fails closed).
const MAX_STDIN_BYTES: u64 = 16 * 1024 * 1024;

/// The command line `shellfirm connect claude-code` installed up to v0.3.10.
/// It must keep producing Claude Code hook output.
#[cfg_attr(not(test), allow(dead_code))]
pub const LEGACY_CLAUDE_HOOK_ARGS: &str = "check --stdin --format json --exit-code";

const AFTER_HELP: &str = "\
Output: the text report goes to stdout (warnings and errors to stderr). It
names each matched check with its severity, what the shell hook would do
(\"Shell (you, in a terminal)\") and what an AI agent hook would do. Checks
that matched but do not apply are listed under \"Not applied\": ignored by
your settings, below your min_severity, or the path does not exist.

Exit codes (with --exit-code or --fail-on; otherwise always 0 on success):
  0   allowed: nothing risky matched (or below --fail-on)
  1   error (empty, unreadable or malformed input, internal failure)
  2   usage error (also an unknown group in --list -g)
  10  risky: needs human confirmation (decision \"ask\")
  11  blocked (decision \"deny\")
  74  the result could not be written to stdout (e.g. disk full)
  78  --strict: the settings, custom checks or an applicable policy have errors
      or warnings (printed as `shellfirm: strict: ...`); the output is unchanged,
      and 78 replaces the decision's 10 / 11
--fail-on <severity> exits non-zero only when the matched severity is at least
<severity>; deny-listed commands always exit 11.

JSON (--format json): a versioned RiskAssessment (\"schema_version\": 2,
\"version\": the shellfirm version, \"decision\": allow | ask | deny,
\"matched_rules\", \"alternatives\" with their \"rule_id\"), plus:
  \"shell\"                  what the shell hook would do: {decision: allow |
                           challenge | deny, challenge, escalated_from,
                           escalation_reasons, context}
  \"not_applied\"            [{id, reason: ignored | below_min_severity |
                           path_missing, undo | severity, min_severity | path}]
  \"skipped_missing_paths\"  [{id, path}], one entry per check and path (each
                           path one argument, from every part of the line);
                           [] when none
  \"exit_code\", \"exit_reason\"  only when --fail-on (\"below_fail_on\") or
                           --strict (\"strict\") changed the exit code
  \"decision_reason\"        why the decision is ask or deny (human-readable)
  \"denial_reason\"          deny only: the same text as decision_reason (kept
                           for older consumers)
  \"deny_reason\", \"policy_sources\"  for a deny (policy_deny | user_deny |
                           agent_auto_deny)

Hook modes (--hook claude-code | cursor, or --format claude-hook |
cursor-hook) read the agent's hook payload from stdin, always exit 0 and
answer in the agent's JSON protocol; they fail closed (deny), and exit 2 when
the answer cannot be written. The hook line installed by older shellfirm
versions (`check --stdin --format json --exit-code`) still works.

--no-context (or SHELLFIRM_NO_CONTEXT=1) runs no external programs (git,
kubectl, du, find, ...). --config-dir DIR (or SHELLFIRM_CONFIG_DIR) reads the
settings, custom checks and audit log from DIR; it must exist (exit 2; hook
modes fall back to the default location).

Full reference (agent decisions, --stdin encodings, hook details):
https://github.com/kaplanelad/shellfirm/blob/main/docs/check.md";

/// `--strict`: the settings, custom checks or a policy have problems
/// (`EX_CONFIG`).
pub const EXIT_STRICT: i32 = 78;
/// Output could not be written (`EX_IOERR`).
pub const EXIT_IO: i32 = 74;
/// Hook mode: the decision could not be written. Exit code 2 blocks the tool
/// call in both Claude Code and Cursor.
const EXIT_HOOK_BLOCK: i32 = 2;

pub fn command() -> Command {
    Command::new("check")
        .about("Test commands against shellfirm checks or list available checks")
        .after_long_help(AFTER_HELP)
        .arg_required_else_help(true)
        .arg(
            Arg::new("command")
                .short('c')
                .long("command")
                .help("Command to test (dry-run, no challenge prompted)")
                .conflicts_with_all(["list", "stdin"]),
        )
        .arg(
            Arg::new("stdin")
                .long("stdin")
                .help("Read the command from stdin: plain text, {\"command\": \"...\"} or an agent hook payload")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["command", "list"]),
        )
        .arg(
            Arg::new("format")
                .long("format")
                .help("Output format")
                .value_parser(["text", "json", "claude-hook", "cursor-hook"])
                .default_value("text"),
        )
        .arg(
            Arg::new("hook")
                .long("hook")
                .help("Run as an AI-agent hook (reads the hook payload from stdin)")
                .value_parser(["claude-code", "cursor"])
                .conflicts_with_all(["list", "command"]),
        )
        .arg(
            Arg::new("exit-code")
                .long("exit-code")
                .help("Exit 10 when risky (ask), 11 when blocked (deny); see --help")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("fail-on")
                .long("fail-on")
                .help("Exit non-zero only when a matched rule is at least this severity (implies --exit-code; deny-listed commands always exit 11)")
                .value_parser(["info", "low", "medium", "high", "critical"])
                .ignore_case(true),
        )
        .arg(
            Arg::new("config-dir")
                .long("config-dir")
                .value_name("DIR")
                .help("Use the shellfirm configuration in DIR (settings, custom checks, audit log)"),
        )
        .arg(
            Arg::new("strict")
                .long("strict")
                .help("Exit 78 when the settings, custom checks or an applicable policy have errors or warnings (after the normal output; not with --list or --hook, whose protocols fix the exit code)")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["list", "hook"]),
        )
        .arg(
            Arg::new("no-context")
                .long("no-context")
                .help("Do not run external programs (git, kubectl, du, ...): no blast radius; context only from the uid, the environment, .git/HEAD and the kubeconfig file")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("list")
                .short('l')
                .long("list")
                .help("List all active checks")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["command", "stdin"]),
        )
        .arg(
            Arg::new("group")
                .short('g')
                .long("group")
                .help("Filter checks by group (used with --list)")
                .requires("list"),
        )
        .arg(
            Arg::new("all")
                .short('a')
                .long("all")
                .help("Include checks from disabled groups (used with --list)")
                .action(ArgAction::SetTrue)
                .requires("list"),
        )
}

/// Which hook protocol to speak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HookKind {
    ClaudeCode,
    Cursor,
}

impl HookKind {
    const fn agent_name(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Cursor => "cursor",
        }
    }
}

fn parse_severity(s: &str) -> Option<Severity> {
    match s.to_ascii_lowercase().as_str() {
        "info" => Some(Severity::Info),
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

/// Hook mode requested explicitly (`--hook` or a hook `--format`).
fn hook_kind(matches: &ArgMatches, format: &str) -> Option<HookKind> {
    match matches.get_one::<String>("hook").map(String::as_str) {
        Some("claude-code") => return Some(HookKind::ClaudeCode),
        Some("cursor") => return Some(HookKind::Cursor),
        _ => {}
    }
    match format {
        "claude-hook" => Some(HookKind::ClaudeCode),
        "cursor-hook" => Some(HookKind::Cursor),
        _ => None,
    }
}

/// `check --stdin --format json --exit-code` exactly (the hook command line
/// installed by <= 0.3.10). It only means hook mode when stdin also carries a
/// hook payload (see [`looks_like_hook_payload`]).
fn is_legacy_invocation(matches: &ArgMatches, format: &str) -> bool {
    format == "json"
        && matches.get_flag("stdin")
        && matches.get_flag("exit-code")
        && matches.get_one::<String>("fail-on").is_none()
        && matches.get_one::<String>("hook").is_none()
}

/// How `--stdin` text should be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StdinShape {
    /// Valid JSON.
    Json,
    /// Looks like a JSON object (`{"...` or `{}`) but does not parse.
    BrokenJson,
    /// A shell command (including `{ ...; }` brace groups and `[ ... ]`
    /// tests).
    Shell,
}

/// Classify `--stdin` input. Only text that parses as JSON, or that starts
/// like a JSON object (`{` followed by `"` or `}`), is JSON: a brace group
/// `{ rm -rf /; }` or a test `[ -d x ] && ...` is a shell command.
fn stdin_shape(raw: &str) -> StdinShape {
    let trimmed = strip_bom(raw).trim();
    if !(trimmed.starts_with('{') || trimmed.starts_with('[')) {
        return StdinShape::Shell;
    }
    if serde_json::from_str::<serde_json::Value>(trimmed).is_ok() {
        return StdinShape::Json;
    }
    // A brace group needs whitespace after `{` (`{ cmd; }`); `{word` or a
    // pretty-printed object (`{` newline `"key"`) is broken JSON.
    let Some(rest) = trimmed.strip_prefix('{') else {
        return StdinShape::Shell;
    };
    match rest.chars().next() {
        Some(c) if c.is_whitespace() => match rest.trim_start().chars().next() {
            None | Some('"' | '}') => StdinShape::BrokenJson,
            Some(_) => StdinShape::Shell,
        },
        _ => StdinShape::BrokenJson,
    }
}

/// `true` for input that is an agent hook payload rather than a command for
/// `check`: a JSON object with hook fields, or something that starts like a
/// JSON object but doesn't parse (which must fail closed in hook mode).
fn looks_like_hook_payload(raw: &str) -> bool {
    match stdin_shape(raw) {
        StdinShape::Shell => false,
        StdinShape::BrokenJson => true,
        StdinShape::Json => {
            match serde_json::from_str::<serde_json::Value>(strip_bom(raw).trim()) {
                Ok(serde_json::Value::Object(obj)) => [
                    "tool_input",
                    "tool_name",
                    "hook_event_name",
                    "session_id",
                    "conversation_id",
                ]
                .iter()
                .any(|k| obj.contains_key(*k)),
                _ => false,
            }
        }
    }
}

/// `true` only for a well-formed JSON object with agent hook fields (the
/// legacy `--stdin --format json --exit-code` hook line switches to the
/// hook protocol for these and nothing else).
fn is_hook_payload_json(raw: &str) -> bool {
    stdin_shape(raw) == StdinShape::Json && looks_like_hook_payload(raw)
}

/// Options shared by the hook and the plain `check` paths.
struct RunCtx<'a> {
    settings: &'a Settings,
    checks: &'a [Check],
    config_dir: Option<PathBuf>,
    no_context: bool,
}

fn usage(msg: impl Into<String>) -> shellfirm::CmdExit {
    shellfirm::CmdExit {
        code: EXIT_USAGE,
        message: Some(format!("shellfirm: error: {}", msg.into())),
    }
}

/// An input error (exit 1) with the standard `shellfirm: error:` prefix.
fn input_error(msg: impl std::fmt::Display) -> shellfirm::CmdExit {
    shellfirm::CmdExit {
        code: EXIT_ERROR,
        message: Some(format!("shellfirm: error: {msg}")),
    }
}

#[allow(clippy::too_many_lines)]
pub fn run(
    matches: &ArgMatches,
    settings: &Settings,
    checks: &[Check],
) -> Result<shellfirm::CmdExit> {
    let format = matches
        .get_one::<String>("format")
        .map_or("text", String::as_str);

    if matches.get_flag("list") {
        let group_filter = matches.get_one::<String>("group").map(String::as_str);
        let show_all = matches.get_flag("all");
        // `--list --config-dir DIR` lists what DIR's settings make active.
        if let Some(dir) = matches.get_one::<String>("config-dir") {
            if !Path::new(dir).is_dir() {
                return Ok(usage(format!("--config-dir {dir}: no such directory")));
            }
            let env = RealEnvironment;
            let cwd = env.current_dir().unwrap_or_default();
            let l = agent::load_agent_inputs(&Config::new(Some(dir))?, &env, &cwd)?;
            for w in &l.warnings {
                eprintln!("shellfirm: warning: {w}");
            }
            return run_list(
                &l.settings,
                &l.checks,
                group_filter,
                show_all,
                format == "json",
            );
        }
        return run_list(settings, checks, group_filter, show_all, format == "json");
    }

    let ctx = RunCtx {
        settings,
        checks,
        config_dir: matches.get_one::<String>("config-dir").map(PathBuf::from),
        no_context: matches.get_flag("no-context")
            || shellfirm::env::no_context_requested(&RealEnvironment),
    };

    if let Some(kind) = hook_kind(matches, format) {
        if matches.get_flag("exit-code") || matches.get_one::<String>("fail-on").is_some() {
            return Ok(usage(
                "--exit-code/--fail-on cannot be used with --hook or a hook --format: hook modes \
                 always exit 0 and report the decision in the agent's JSON protocol",
            ));
        }
        let input = matches.get_one::<String>("command").map_or_else(
            || read_stdin_lossy().map(HookInput::Raw),
            |c| Ok(HookInput::Command(c.clone())),
        );
        return Ok(run_hook(kind, input, &ctx));
    }

    // An explicit --config-dir that is not a directory is a mistake (a typo
    // would silently drop the team's deny list). Hook mode keeps the
    // recorded-directory fallback (see `hook_config`).
    if let Some(dir) = ctx.config_dir.as_deref() {
        if !dir.is_dir() {
            return Ok(usage(format!(
                "--config-dir {}: {}",
                dir.display(),
                if dir.exists() {
                    "not a directory"
                } else {
                    "no such directory"
                }
            )));
        }
    }

    let fail_on = matches
        .get_one::<String>("fail-on")
        .and_then(|s| parse_severity(s));
    let exit_code_mode = matches.get_flag("exit-code") || fail_on.is_some();

    // Resolve the command string: --command or --stdin
    // `broken_json`: the input starts like a JSON object but does not parse
    // (NDJSON, truncated JSON, `{}; rm -rf /`). It is analysed as a shell
    // command; if nothing matches it is still an input error (exit 1).
    let mut broken_json: Option<String> = None;
    // The exact hook line installed by shellfirm <= 0.3.10 may still be run
    // by Claude Code, where only exit 2 blocks a tool call: input it cannot
    // use exits 2 there (never 0, never a non-blocking 1).
    let legacy = is_legacy_invocation(matches, format);
    let bad_input = |msg: String| {
        let mut e = input_error(msg);
        if legacy {
            e.code = EXIT_HOOK_BLOCK;
        }
        e
    };
    let command_str = if matches.get_flag("stdin") {
        let raw = match read_stdin_lossy() {
            Ok(raw) => raw,
            Err(msg) => return Ok(bad_input(msg)),
        };
        // Only a well-formed JSON hook payload switches the legacy line to
        // the hook protocol (anything else keeps the documented exit codes).
        if legacy && is_hook_payload_json(&raw) {
            return Ok(run_hook(
                HookKind::ClaudeCode,
                Ok(HookInput::Raw(raw)),
                &ctx,
            ));
        }
        if stdin_shape(&raw) == StdinShape::BrokenJson {
            let text = strip_bom(&raw).trim().to_string();
            broken_json = Some(format!(
                "stdin starts like a JSON object but is not valid JSON; expected {{\"command\": \"...\"}}, \
                 {{\"tool_input\": {{\"command\": \"...\"}}}} or a plain command{}",
                serde_json::from_str::<serde_json::Value>(&text)
                    .err()
                    .map_or_else(String::new, |e| format!(" ({e})"))
            ));
            text
        } else {
            match parse_command_input(&raw) {
                Ok(cmd) => cmd,
                Err(msg) => return Ok(bad_input(msg)),
            }
        }
    } else if let Some(cmd) = matches.get_one::<String>("command") {
        cmd.clone()
    } else {
        return Ok(usage(
            "Provide --command, --stdin, --hook or --list. See: shellfirm check --help",
        ));
    };

    let real = RealEnvironment;
    let no_exec = agent::NoExecEnvironment::new(&real);
    let env: &dyn Environment = if ctx.no_context { &no_exec } else { &real };

    // An explicit --config-dir replaces the settings loaded by main().
    let cwd = env.current_dir().unwrap_or_default();
    let config = match ctx.config_dir.as_deref() {
        Some(dir) => Some(Config::new(Some(&dir.display().to_string()))?),
        None => Config::new(None).ok(),
    };
    let loaded = match (ctx.config_dir.as_deref(), config.as_ref()) {
        (Some(_), Some(config)) => Some(agent::load_agent_inputs(config, env, &cwd)?),
        _ => None,
    };
    // The settings and custom checks of --config-dir get the same warnings
    // as the default location (main() only reports the default one).
    // Under --strict each problem is printed once, as a `strict:` line.
    if let Some(l) = loaded.as_ref().filter(|_| !matches.get_flag("strict")) {
        for w in &l.warnings {
            eprintln!("shellfirm: warning: {w}");
        }
    }
    let (settings, checks) = loaded
        .as_ref()
        .map_or((settings, checks), |l| (&l.settings, l.checks.as_slice()));

    // One time budget for the whole report (the agent view, the target
    // repository's policy and the shell view), from the settings in use
    // (`--config-dir DIR` included): later views reuse the first answers.
    let _scope = settings.command_scope();
    let mut assessment =
        agent::assess_command(&command_str, settings, checks, env, &settings.agent)?;
    // `cd /other/repo && ...`: that repository's policy applies too.
    if let Some(config) = config.as_ref() {
        let files = shellfirm::policy::policy_files(env, &cwd).0;
        assessment =
            agent::apply_target_repo_policies(assessment, &command_str, config, env, &cwd, &files);
    }

    let mut code = if exit_code_mode {
        exit_code_for(&assessment, fail_on)
    } else {
        EXIT_OK
    };
    // Why the exit code is not the decision's own (JSON `exit_reason`).
    let mut exit_reason: Option<&str> =
        (fail_on.is_some() && assessment.decision != Decision::Allow && code == EXIT_OK)
            .then_some("below_fail_on");
    // --strict: a configuration problem fails the check (CI gates), even
    // when the command itself is fine.
    if matches.get_flag("strict") {
        let mut problems: Vec<String> = match (loaded.as_ref(), config.as_ref()) {
            (Some(l), _) => l.warnings.clone(),
            (None, Some(c)) => agent::load_agent_inputs(c, env, &cwd)
                .map(|l| l.warnings)
                .unwrap_or_default(),
            (None, None) => Vec::new(),
        };
        let dirs = agent::command_target_dirs(&command_str, &cwd, env.home_dir().as_deref());
        let d = shellfirm::policy::with_extra_target_dirs(&dirs, || {
            shellfirm::policy::discover_for(
                env,
                &cwd,
                &shellfirm::context::command_target_dirs(&command_str),
            )
        });
        problems.extend(shellfirm::policy::problem_lines(&d));
        for w in &d.warnings {
            let line = format!("policy {}: {}", w.path.display(), w.message);
            if !w.message.starts_with("ignored: ") && !problems.contains(&line) {
                problems.push(line);
            }
        }
        if !problems.is_empty() {
            for p in &problems {
                eprintln!("shellfirm: strict: {p}");
            }
            code = EXIT_STRICT;
            exit_reason = Some("strict");
        }
    }
    if let Some(msg) = broken_json {
        if assessment.decision == Decision::Allow {
            return Ok(bad_input(msg));
        }
        eprintln!("shellfirm: warning: {msg}; it was analysed as a shell command");
        if legacy {
            code = EXIT_HOOK_BLOCK;
        }
    }

    // What the shell hook would do, and why matched checks do not apply
    // (ignored / below min_severity / missing path), for text and JSON.
    let shell = shell_view(&command_str, settings, checks, env, &cwd);
    let ignored: Vec<String> = checks::ignored_matches(settings, &command_str, env)
        .into_iter()
        .map(|c| c.id)
        .filter(|id| !assessment.matched_rules.iter().any(|m| &m.id == id))
        .collect();

    let text =
        if format == "json" {
            let mut value = serde_json::to_value(&assessment)?;
            if let Some(obj) = value.as_object_mut() {
                obj.insert(
                    "version".into(),
                    serde_json::Value::String(env!("CARGO_PKG_VERSION").into()),
                );
                // Always present (`[]` when nothing was skipped).
                obj.entry("skipped_missing_paths")
                    .or_insert_with(|| serde_json::json!([]));
                obj.insert(
                    "not_applied".into(),
                    serde_json::Value::Array(
                        not_applied(&assessment, &shell, &ignored)
                            .iter()
                            .map(NotApplied::json)
                            .collect(),
                    ),
                );
                obj.insert("shell".into(), shell.json());
                // Only when --fail-on / --strict changed the exit code.
                if let Some(reason) = exit_reason {
                    obj.insert("exit_code".into(), serde_json::json!(code));
                    obj.insert("exit_reason".into(), serde_json::json!(reason));
                }
            }
            serde_json::to_string_pretty(&value)?
        } else {
            // The report is the command's output: stdout (`| less`, `> file`);
            // warnings stay on stderr. ASCII when the terminal is not UTF-8, and
            // wrapped between words to the width of a terminal.
            shellfirm::prompt::wrap_for_stdout(&shellfirm::config::ascii_fallback(
                &format_text_output(&assessment, &shell, &ignored),
            ))
        };
    if let Err(e) = write_stdout(&text) {
        // A reader that stopped early (`| head`) still gets the decision
        // as the exit code.
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            return Ok(shellfirm::CmdExit {
                code,
                message: None,
            });
        }
        return Ok(output_error(&e));
    }
    Ok(shellfirm::CmdExit {
        code,
        message: None,
    })
}

/// Write one line to stdout without panicking (disk full, closed pipe, ...).
fn write_stdout(text: &str) -> std::io::Result<()> {
    let mut out = std::io::stdout().lock();
    writeln!(out, "{text}")?;
    out.flush()
}

/// A failed write to stdout: a closed pipe (`check --list | head -1`) exits
/// 0 quietly, any other error (a full disk) exits 74 with a message.
fn output_error(e: &std::io::Error) -> shellfirm::CmdExit {
    if e.kind() == std::io::ErrorKind::BrokenPipe {
        return shellfirm::CmdExit {
            code: EXIT_OK,
            message: None,
        };
    }
    shellfirm::CmdExit {
        code: EXIT_IO,
        message: Some(format!("shellfirm: error: writing output: {e}")),
    }
}

/// Map an assessment to the documented exit code.
fn exit_code_for(assessment: &RiskAssessment, fail_on: Option<Severity>) -> i32 {
    let decision_code = match assessment.decision {
        Decision::Allow => return EXIT_OK,
        Decision::Ask => EXIT_ASK,
        Decision::Deny => EXIT_DENY,
    };
    let Some(min) = fail_on else {
        return decision_code;
    };
    let deny_listed = assessment.decision == Decision::Deny
        && matches!(
            assessment.deny_reason.as_deref(),
            Some("policy_deny" | "user_deny" | "deny")
        );
    let sev = assessment.effective_severity.or(assessment.severity);
    if deny_listed || sev.is_some_and(|s| s >= min) {
        decision_code
    } else {
        EXIT_OK
    }
}

// ---------------------------------------------------------------------------
// Hook mode
// ---------------------------------------------------------------------------

enum HookInput {
    /// Raw stdin payload (JSON expected).
    Raw(String),
    /// Command given with `-c` (testing a hook decision by hand).
    Command(String),
}

/// What the agent is about to do.
#[derive(Debug, Default, PartialEq, Eq)]
enum HookAction {
    /// Run a shell command.
    Command(String),
    /// Write a file with a file-editing tool (`Write`, `Edit`, ...).
    FileWrite { tool: String, path: String },
    /// A tool shellfirm has no opinion about.
    #[default]
    NotApplicable,
}

/// A parsed agent hook payload.
#[derive(Debug, Default, PartialEq, Eq)]
struct HookPayload {
    action: HookAction,
    cwd: Option<String>,
    /// Cursor: first `workspace_roots` entry (used when `cwd` is missing).
    workspace_root: Option<String>,
    session_id: Option<String>,
    tool_use_id: Option<String>,
}

#[cfg(test)]
impl HookPayload {
    fn command(&self) -> Option<&str> {
        match &self.action {
            HookAction::Command(c) => Some(c),
            _ => None,
        }
    }
}

/// Tools (besides [`agent::SHELL_TOOLS`]) whose `tool_input.command` is a
/// shell command: Cursor's `preToolUse` calls its shell tool `Shell`.
const OTHER_SHELL_TOOLS: &[&str] = &["Shell", "Terminal"];

/// Cursor `preToolUse` file tools. Cursor does not document their
/// `tool_input` fields, so the path is looked up under several names.
const CURSOR_FILE_TOOLS: &[&str] = &["Write", "Edit", "Delete", "MultiEdit", "StrReplace"];
const PATH_KEYS: &[&str] = &[
    "file_path",
    "notebook_path",
    "path",
    "target_file",
    "filePath",
    "file",
    "target",
    "relative_workspace_path",
];

/// Parse a Claude Code `PreToolUse` or Cursor `beforeShellExecution` /
/// `preToolUse` payload.
///
/// Fails (→ the caller denies) on anything that isn't a well-formed payload.
#[allow(clippy::too_many_lines)]
fn parse_hook_payload(input: &str, kind: HookKind) -> std::result::Result<HookPayload, String> {
    let trimmed = strip_bom(input).trim();
    if trimmed.is_empty() {
        return Err("empty hook input on stdin".into());
    }
    let value: serde_json::Value =
        serde_json::from_str(trimmed).map_err(|e| format!("malformed JSON hook input ({e})"))?;
    let obj = value
        .as_object()
        .ok_or_else(|| "hook input must be a JSON object".to_string())?;

    let str_field = |v: Option<&serde_json::Value>,
                     name: &str|
     -> std::result::Result<Option<String>, String> {
        match v {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(serde_json::Value::String(s)) => Ok(Some(s.clone())),
            Some(_) => Err(format!("hook input field '{name}' must be a string")),
        }
    };

    // An empty `cwd` (Cursor sends `""` at times) means "not given".
    let cwd = str_field(obj.get("cwd"), "cwd")?.filter(|c| !c.trim().is_empty());
    let workspace_root = obj
        .get("workspace_roots")
        .and_then(serde_json::Value::as_array)
        .and_then(|a| {
            a.iter()
                .filter_map(serde_json::Value::as_str)
                .find(|r| !r.trim().is_empty())
        })
        .map(ToString::to_string);
    let session_id = str_field(obj.get("session_id"), "session_id")?
        .or(str_field(obj.get("conversation_id"), "conversation_id")?);
    let tool_use_id = str_field(obj.get("tool_use_id"), "tool_use_id")?;
    let base = |action| HookPayload {
        action,
        cwd: cwd.clone(),
        workspace_root: workspace_root.clone(),
        session_id: session_id.clone(),
        tool_use_id: tool_use_id.clone(),
    };

    let tool_input = match obj.get("tool_input") {
        None => None,
        Some(ti) => Some(
            ti.as_object()
                .ok_or_else(|| "hook input field 'tool_input' must be an object".to_string())?,
        ),
    };

    if let Some(tool) = str_field(obj.get("tool_name"), "tool_name")? {
        let cursor_file_tool =
            kind == HookKind::Cursor && CURSOR_FILE_TOOLS.contains(&tool.as_str());
        if cursor_file_tool {
            // Undocumented input shape: look for a path under several names.
            // No path at all (`tool_input: {}`, `"file_path": 5`) is
            // malformed and denied, like Claude Code's file tools.
            let path = tool_input.and_then(|ti| {
                PATH_KEYS
                    .iter()
                    .find_map(|k| ti.get(*k).and_then(serde_json::Value::as_str))
                    .or_else(|| {
                        ti.iter()
                            .filter(|(k, _)| {
                                let k = k.to_ascii_lowercase();
                                k.contains("path") || k.contains("file")
                            })
                            .find_map(|(_, v)| v.as_str())
                    })
                    .map(ToString::to_string)
            });
            let path = path
                .filter(|p| !p.trim().is_empty())
                .ok_or_else(|| format!("{tool} hook input has no file path in tool_input"))?;
            return Ok(base(HookAction::FileWrite { tool, path }));
        }
        if agent::FILE_WRITE_TOOLS.contains(&tool.as_str()) {
            let ti =
                tool_input.ok_or_else(|| format!("{tool} hook input has no tool_input object"))?;
            let path = str_field(ti.get("file_path"), "tool_input.file_path")?
                .or(str_field(
                    ti.get("notebook_path"),
                    "tool_input.notebook_path",
                )?)
                .ok_or_else(|| {
                    format!("{tool} hook input has no tool_input.file_path / notebook_path")
                })?;
            return Ok(base(HookAction::FileWrite { tool, path }));
        }
        let shell_tool = agent::SHELL_TOOLS.contains(&tool.as_str())
            || OTHER_SHELL_TOOLS.contains(&tool.as_str());
        if !shell_tool {
            // Any other tool that carries a shell command string is
            // analysed the same way (e.g. an MCP "run" tool matched by `*`).
            return Ok(base(match tool_input.and_then(|ti| ti.get("command")) {
                Some(serde_json::Value::String(c)) => HookAction::Command(c.clone()),
                _ => HookAction::NotApplicable,
            }));
        }
        // Monitor can watch a WebSocket (`ws`) instead of running a command.
        if tool == "Monitor"
            && tool_input.is_some_and(|ti| !ti.contains_key("command") && ti.contains_key("ws"))
        {
            return Ok(base(HookAction::NotApplicable));
        }
    }

    let command = if let Some(ti) = tool_input {
        str_field(ti.get("command"), "tool_input.command")?
    } else {
        str_field(obj.get("command"), "command")?
    };
    let command =
        command.ok_or_else(|| "hook input has no command (tool_input.command)".to_string())?;
    let cwd_override = tool_input
        .and_then(|ti| ti.get("working_directory"))
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string);
    let mut p = base(HookAction::Command(command));
    if p.cwd.is_none() {
        p.cwd = cwd_override;
    }
    Ok(p)
}

/// Pick the configuration directory for a hook run.
///
/// `--config-dir` (recorded by `shellfirm connect`) wins over the location
/// derived from `HOME`/`XDG_CONFIG_HOME`, so a redirected environment cannot
/// swap in a weaker configuration or move the audit log. If the recorded
/// directory no longer exists the default location is used.
fn hook_config(config_dir: Option<&Path>) -> Option<Config> {
    // A stale SHELLFIRM_CONFIG_DIR never leaves the hook without a decision:
    // the recorded directory (or the default location) is used instead.
    let default = Config::new(None)
        .or_else(|_| Config::default_location())
        .ok();
    if let Some(dir) = config_dir {
        if dir.is_dir() {
            if let Some(d) = default.as_ref().filter(|d| d.root_folder != dir) {
                tracing::debug!(
                    "hook: the environment points at {} but the hook was installed for {}; using the recorded directory",
                    d.root_folder.display(),
                    dir.display()
                );
            }
            return Config::new(Some(&dir.display().to_string())).ok();
        }
        tracing::warn!(
            "hook: recorded configuration directory {} does not exist; using the default location",
            dir.display()
        );
    }
    default
}

/// `true` when a raw hook payload names a file-editing tool (whatever
/// else is wrong with it).
fn raw_names_file_tool(raw: &str, kind: HookKind) -> bool {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(strip_bom(raw).trim()) else {
        return false;
    };
    v.get("tool_name")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|t| {
            agent::FILE_WRITE_TOOLS.contains(&t)
                || (kind == HookKind::Cursor && CURSOR_FILE_TOOLS.contains(&t))
        })
}

struct HookOutcome {
    assessment: RiskAssessment,
    allow_safe: bool,
    /// What the decision is about: `command` or `file edit`.
    subject: &'static str,
}

fn run_hook(
    kind: HookKind,
    input: std::result::Result<HookInput, String>,
    ctx: &RunCtx<'_>,
) -> shellfirm::CmdExit {
    // Never exit without a decision: a panic anywhere in the evaluation
    // becomes a deny.
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        evaluate_hook(kind, input, ctx)
    }))
    .unwrap_or_else(|_| HookOutcome {
        assessment: RiskAssessment::fail_closed(
            Decision::Deny,
            "shellfirm crashed while evaluating this command. Failing closed.",
        ),
        allow_safe: false,
        subject: "command",
    });
    emit_hook(kind, &outcome)
}

#[allow(clippy::too_many_lines)]
fn evaluate_hook(
    kind: HookKind,
    input: std::result::Result<HookInput, String>,
    ctx: &RunCtx<'_>,
) -> HookOutcome {
    // A malformed file-tool payload is reported as a file edit, not a
    // command.
    let file_tool_input =
        matches!(&input, Ok(HookInput::Raw(raw)) if raw_names_file_tool(raw, kind));
    let payload = match input {
        Ok(HookInput::Command(c)) => Ok(HookPayload {
            action: HookAction::Command(c),
            ..HookPayload::default()
        }),
        Ok(HookInput::Raw(raw)) => parse_hook_payload(&raw, kind),
        Err(e) => Err(e),
    };

    let config = hook_config(ctx.config_dir.as_deref());
    let real = RealEnvironment;
    let no_exec = agent::NoExecEnvironment::new(&real);
    let env: &dyn Environment = if ctx.no_context { &no_exec } else { &real };

    let payload = match payload {
        Ok(p) => p,
        Err(reason) => {
            let assessment = RiskAssessment::fail_closed(
                Decision::Deny,
                format!(
                    "shellfirm could not evaluate this {}: {reason}. Failing closed.",
                    if file_tool_input {
                        "file edit"
                    } else {
                        "command"
                    }
                ),
            );
            let mut to_log = assessment.clone();
            to_log.matched_rules.push(agent::MatchedRule {
                id: "shellfirm:invalid_hook_input".into(),
                description: assessment.decision_reason.clone().unwrap_or_default(),
                severity: Severity::High,
                group: agent::SELF_PROTECTION_GROUP.into(),
                origin: "self-protection".into(),
                blast_radius_scope: None,
                blast_radius_detail: None,
            });
            audit_hook(
                kind,
                ctx.settings,
                config.as_ref(),
                "<unparseable hook input>",
                &to_log,
                &HookPayload::default(),
                true,
            );
            return HookOutcome {
                assessment,
                allow_safe: false,
                subject: if file_tool_input {
                    "file edit"
                } else {
                    "command"
                },
            };
        }
    };

    if payload.action == HookAction::NotApplicable {
        // Not a shell command or a file write (e.g. Read): no opinion.
        return HookOutcome {
            assessment: RiskAssessment::no_objection(),
            allow_safe: false,
            subject: "command",
        };
    }

    // Evaluate relative paths, git context and project policy where the
    // agent will actually run the command. Cursor payloads may carry only
    // `workspace_roots` (the hook process runs in ~/.cursor).
    let payload_dir = payload
        .cwd
        .as_deref()
        .into_iter()
        .chain(payload.workspace_root.as_deref())
        .map(Path::new)
        .find(|d| d.is_dir());
    if let Some(dir) = payload_dir {
        if let Err(e) = std::env::set_current_dir(dir) {
            tracing::debug!("could not switch to payload cwd {}: {e}", dir.display());
        }
    }
    let cwd = env.current_dir().unwrap_or_default();

    // Settings, custom checks and policy are (re)loaded for the payload cwd
    // and the recorded configuration directory, so personal ignores vs.
    // policy enforcement follow the agent's directory, not the hook's.
    let loaded = config
        .as_ref()
        .map(|c| agent::load_agent_inputs(c, env, &cwd));
    let (settings, checks, policy_errors) = match &loaded {
        Some(Ok(l)) => (&l.settings, l.checks.as_slice(), l.policy.errors.as_slice()),
        Some(Err(e)) => {
            let assessment = RiskAssessment::fail_closed(
                Decision::Deny,
                format!("shellfirm could not load its checks ({e}). Failing closed."),
            );
            return HookOutcome {
                assessment,
                allow_safe: false,
                subject: "command",
            };
        }
        None => (ctx.settings, ctx.checks, &[][..]),
    };

    let (audit_text, assessment) = match &payload.action {
        HookAction::FileWrite { tool, path } => {
            let mut a = agent::assess_file_tool_for(
                tool,
                path,
                Some(&cwd),
                config.as_ref().map(|c| c.root_folder.as_path()),
                settings,
                env.home_dir().as_deref(),
            );
            // An agent-instruction edit (AGENTS.md, CLAUDE.md, Cursor rules) is
            // an everyday task: it stays `ask` even in Cursor, where `ask` may
            // not be enforced for preToolUse (the edit then goes ahead). Turn
            // it off with `shellfirm config ignore shellfirm-self:agent_instructions_edit`.
            if kind == HookKind::Cursor
                && a.decision == Decision::Ask
                && !agent::only_instruction_edits(&a)
            {
                // Cursor does not enforce `ask` for preToolUse: deny, and
                // tell the user to make the change themselves.
                a.decision = Decision::Deny;
                let r = format!(
                    "{} (Cursor cannot ask for file edits, so shellfirm blocks it; make this \
                     change yourself if it is intended)",
                    a.decision_reason.take().unwrap_or_default()
                );
                a.denial_reason = Some(r.clone());
                a.decision_reason = Some(r);
                a.requires_human_approval = false;
            }
            (format!("{tool} {path}"), a)
        }
        HookAction::Command(command) => {
            // One time budget for both evaluations (this one and the
            // target repository's policy), from the settings used here.
            let _scope = settings.command_scope();
            let mut assessment =
                agent::assess_command(command, settings, checks, env, &settings.agent)
                    .unwrap_or_else(|e| {
                        RiskAssessment::fail_closed(
                            Decision::Deny,
                            format!(
                                "shellfirm failed to analyze this command ({e}). Failing closed."
                            ),
                        )
                    });
            agent::apply_policy_errors(&mut assessment, policy_errors);
            // `cd /other/repo && ...` from outside the repository: that
            // repository's policy applies too.
            if let Some(c) = config.as_ref() {
                let files = match &loaded {
                    Some(Ok(l)) => l.policy.files.clone(),
                    _ => Vec::new(),
                };
                assessment =
                    agent::apply_target_repo_policies(assessment, command, c, env, &cwd, &files);
            }
            (command.clone(), assessment)
        }
        HookAction::NotApplicable => unreachable!("handled above"),
    };

    audit_hook(
        kind,
        settings,
        config.as_ref(),
        &audit_text,
        &assessment,
        &payload,
        false,
    );
    let subject = if matches!(payload.action, HookAction::FileWrite { .. }) {
        "file edit"
    } else {
        "command"
    };
    HookOutcome {
        assessment,
        allow_safe: settings.agent.allow_safe,
        subject,
    }
}

fn audit_hook(
    kind: HookKind,
    settings: &Settings,
    config: Option<&Config>,
    command: &str,
    assessment: &RiskAssessment,
    payload: &HookPayload,
    fail_closed: bool,
) {
    let Some(config) = config else {
        return;
    };
    let info = AgentAuditInfo {
        agent_name: kind.agent_name(),
        session_id: payload.session_id.as_deref(),
        tool_use_id: payload.tool_use_id.as_deref(),
        fail_closed,
    };
    if let Err(e) = agent::audit_decision(
        settings,
        &config.audit_log_path(),
        command,
        assessment,
        &info,
    ) {
        tracing::warn!("could not write audit log: {e}");
    }
}

/// Build the hook-protocol JSON for an assessment. `None` = print nothing.
#[cfg(test)]
fn build_hook_output(
    kind: HookKind,
    assessment: &RiskAssessment,
    allow_safe: bool,
) -> Option<serde_json::Value> {
    build_hook_output_for(kind, assessment, allow_safe, "command")
}

/// [`build_hook_output`] for a decision about `subject` (`command` /
/// `file edit`).
fn build_hook_output_for(
    kind: HookKind,
    assessment: &RiskAssessment,
    allow_safe: bool,
    subject: &str,
) -> Option<serde_json::Value> {
    if assessment.decision == Decision::Allow && !allow_safe {
        // No decision. Claude Code: "exit code 0 with no output" means the
        // normal permission flow applies. Cursor documents no neutral value
        // and an explicit `allow` may skip its own approval, so shellfirm
        // stays silent there too (`agent.allow_safe` opts in to `allow`).
        return None;
    }
    match kind {
        HookKind::ClaudeCode => {
            let reason = if assessment.decision == Decision::Allow {
                "shellfirm found no risky patterns".to_string()
            } else {
                agent::format_reason_for(assessment, subject)
            };
            Some(serde_json::json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": assessment.decision.as_str(),
                    "permissionDecisionReason": reason,
                }
            }))
        }
        HookKind::Cursor => {
            if assessment.decision == Decision::Allow {
                return Some(serde_json::json!({ "permission": "allow" }));
            }
            let reason = agent::format_reason_for(assessment, subject);
            let short = reason.lines().next().unwrap_or_default().to_string();
            let user_message = assessment
                .decision_reason
                .as_deref()
                .map_or_else(|| short.clone(), |r| format!("{short} {r}"));
            Some(serde_json::json!({
                "permission": assessment.decision.as_str(),
                "user_message": user_message,
                "agent_message": reason,
            }))
        }
    }
}

fn emit_hook(kind: HookKind, outcome: &HookOutcome) -> shellfirm::CmdExit {
    if let Some(out) = build_hook_output_for(
        kind,
        &outcome.assessment,
        outcome.allow_safe,
        outcome.subject,
    ) {
        if let Err(e) = write_stdout(&out.to_string()) {
            // Without a decision on stdout, exit 2 is the only way left to
            // block the tool call.
            return shellfirm::CmdExit {
                code: EXIT_HOOK_BLOCK,
                message: Some(format!(
                    "shellfirm: could not write the hook decision ({e}); blocking the tool call"
                )),
            };
        }
    }
    shellfirm::CmdExit {
        code: EXIT_OK,
        message: None,
    }
}

// ---------------------------------------------------------------------------
// Input helpers
// ---------------------------------------------------------------------------

/// Drop leading UTF-8 byte-order marks: a BOM before `{` must not turn a JSON
/// payload into a plain-text "command" that matches nothing (fail open).
fn strip_bom(input: &str) -> &str {
    input.trim_start_matches('\u{feff}')
}

/// Read stdin as bytes and decode lossily (invalid UTF-8 never aborts).
fn read_stdin_lossy() -> std::result::Result<String, String> {
    let mut buf = Vec::new();
    std::io::stdin()
        .take(MAX_STDIN_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("Failed to read stdin: {e}"))?;
    if buf.len() as u64 > MAX_STDIN_BYTES {
        return Err(format!(
            "stdin input exceeds the {} MiB limit",
            MAX_STDIN_BYTES / 1024 / 1024
        ));
    }
    decode_input(&buf)
}

/// Decode stdin bytes.
///
/// - UTF-32 with a BOM (`FF FE 00 00` / `00 00 FE FF`) or with the NUL
///   pattern of ASCII text in UTF-32;
/// - UTF-16 with a BOM (`FF FE` / `FE FF`) or with the NUL pattern of ASCII
///   text in UTF-16 (Windows PowerShell 5.1 `>` writes UTF-16LE). A BOM is
///   only trusted when the rest really is UTF-16: a stray `FF FE` in front
///   of UTF-8 text (no NUL bytes) is dropped and the text is read as UTF-8,
///   because that is how a shell would run it;
/// - otherwise UTF-8 (lossy; invalid bytes never abort).
///
/// Input that still contains NUL bytes, or is not valid in the encoding it
/// claims, is rejected: it would otherwise match nothing and fail open.
fn decode_input(buf: &[u8]) -> std::result::Result<String, String> {
    const REFUSE: &str = "stdin contains NUL bytes and is not valid UTF-16 or UTF-32 text; \
                          refusing to check it";
    let units16 = |bytes: &[u8], le: bool| -> Option<String> {
        if !bytes.len().is_multiple_of(2) {
            return None;
        }
        let unit = if le {
            u16::from_le_bytes
        } else {
            u16::from_be_bytes
        };
        let units: Vec<u16> = bytes.as_chunks::<2>().0.iter().map(|&c| unit(c)).collect();
        String::from_utf16(&units)
            .ok()
            .filter(|t| !t.contains('\0'))
    };
    let units32 = |bytes: &[u8], le: bool| -> Option<String> {
        if !bytes.len().is_multiple_of(4) {
            return None;
        }
        let unit = if le {
            u32::from_le_bytes
        } else {
            u32::from_be_bytes
        };
        bytes
            .as_chunks::<4>()
            .0
            .iter()
            .map(|&c| char::from_u32(unit(c)).filter(|ch| *ch != '\0'))
            .collect()
    };
    let has_nul = |bytes: &[u8]| bytes.contains(&0);
    match buf {
        [0xFF, 0xFE, 0, 0, rest @ ..] => return units32(rest, true).ok_or_else(|| REFUSE.into()),
        [0, 0, 0xFE, 0xFF, rest @ ..] => return units32(rest, false).ok_or_else(|| REFUSE.into()),
        [0xFF, 0xFE, rest @ ..] | [0xFE, 0xFF, rest @ ..] => {
            let le = buf[0] == 0xFF;
            if !has_nul(rest) {
                // UTF-8 text behind a stray BOM-like prefix.
                return Ok(String::from_utf8_lossy(rest).into_owned());
            }
            return units16(rest, le).ok_or_else(|| REFUSE.into());
        }
        _ => {}
    }
    if !has_nul(buf) {
        return Ok(String::from_utf8_lossy(buf).into_owned());
    }
    let sample = &buf[..buf.len().min(4096) & !3];
    let zero_at = |pred: &dyn Fn(usize) -> bool| {
        sample
            .iter()
            .enumerate()
            .filter(|(i, _)| pred(*i))
            .all(|(_, b)| *b == 0)
    };
    if sample.len() >= 4 && zero_at(&|i| i % 4 != 0) {
        return units32(buf, true).ok_or_else(|| REFUSE.into());
    }
    if sample.len() >= 4 && zero_at(&|i| i % 4 != 3) {
        return units32(buf, false).ok_or_else(|| REFUSE.into());
    }
    // UTF-16 without a BOM: ASCII characters put their NUL byte on one
    // side (odd offsets for little endian), other characters (`日本語`,
    // `é`) usually have none. The side with the NULs decides the byte
    // order; the text must then decode cleanly (no NUL characters).
    let sample = &buf[..buf.len().min(4096) & !1];
    let odd_nuls = sample
        .iter()
        .skip(1)
        .step_by(2)
        .filter(|b| **b == 0)
        .count();
    let even_nuls = sample.iter().step_by(2).filter(|b| **b == 0).count();
    // A handful of NULs in otherwise plain text is not UTF-16: it is UTF-8
    // with stray NUL bytes, which bash runs after dropping them. Real UTF-16
    // shell text is mostly ASCII, so at least 30% of its code units carry a
    // NUL on the same side.
    let units = sample.len() / 2;
    let enough = |n: usize| n > 0 && n * 10 >= units * 3;
    let decoded = if enough(odd_nuls) && even_nuls == 0 {
        units16(buf, true)
    } else if enough(even_nuls) && odd_nuls == 0 {
        units16(buf, false)
    } else {
        None
    };
    // Without a BOM the byte order is only a guess. When the same bytes with
    // the NULs dropped (what a shell runs) read differently, both readings
    // are checked, so padding a UTF-8 script with NULs cannot hide it.
    let decoded = decoded.map(|text| {
        let stripped: Vec<u8> = buf.iter().copied().filter(|b| *b != 0).collect();
        let as_shell = String::from_utf8_lossy(&stripped);
        if as_shell == text {
            text
        } else {
            format!("{text}\n{as_shell}")
        }
    });
    decoded.ok_or_else(|| {
        "stdin contains NUL bytes and could not be decoded as UTF-16 or UTF-32 text \
         (without a byte-order mark the byte order is guessed from the NUL bytes of \
         ASCII characters; add a BOM, or send UTF-8); refusing to check it"
            .into()
    })
}

/// Parse a command from `--stdin` input (non-hook mode).
///
/// JSON formats:
/// - `{"command": "..."}` — simple format
/// - `{"tool_name": "Bash", "tool_input": {"command": "..."}}` — Claude Code hooks format
///
/// Anything that is not JSON (see [`stdin_shape`]) is a plain-text command,
/// including brace groups and `[ ... ]` tests. Input that starts like a
/// JSON object but does not parse is an error (it is never re-interpreted
/// as plain text).
fn parse_command_input(input: &str) -> std::result::Result<String, String> {
    let trimmed = strip_bom(input).trim();
    if trimmed.is_empty() {
        return Err("no input received on stdin (empty or only whitespace)".to_string());
    }

    if stdin_shape(trimmed) != StdinShape::Shell {
        return match parse_hook_payload(trimmed, HookKind::ClaudeCode) {
            Ok(HookPayload {
                action: HookAction::Command(c),
                ..
            }) => Ok(c),
            Ok(_) => Err("JSON input is for a non-Bash tool; nothing to check".to_string()),
            Err(e) => Err(format!(
                "Invalid JSON input: {e}. Expected {{\"command\": \"...\"}} or {{\"tool_input\": {{\"command\": \"...\"}}}}"
            )),
        };
    }

    Ok(trimmed.to_string())
}

/// What the interactive shell hook would do with a command (the human
/// view, next to the agent decision), computed like `pre-command`.
#[derive(Debug, Default)]
struct ShellView {
    /// `None` when no active check matches in the shell.
    verdict: Option<ShellVerdict>,
    /// Matches below the shell's `min_severity` (no challenge for them).
    below_min: Vec<(String, Severity)>,
    /// The shell's `min_severity`.
    min_severity: Option<Severity>,
    /// The context the shell hook sees (with the target repository's
    /// policy `context:` applied, e.g. for `sudo rm -rf repo/f`).
    risk_level: String,
    labels: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ShellVerdict {
    /// Deny list or project policy: blocked, no challenge.
    Denied,
    /// A challenge (`effective`), raised from `base` when they differ.
    Challenge {
        effective: shellfirm::config::Challenge,
        base: shellfirm::config::Challenge,
        reasons: Vec<String>,
    },
}

impl ShellView {
    fn line(&self) -> Option<String> {
        match self.verdict.as_ref()? {
            ShellVerdict::Denied => {
                Some("blocked (deny list or project policy; no challenge)".to_string())
            }
            ShellVerdict::Challenge {
                effective,
                base,
                reasons,
            } => Some(if effective.is_stricter_than(*base) {
                if reasons.is_empty() {
                    format!("would challenge ({effective}, escalated from {base})")
                } else {
                    format!(
                        "would challenge ({effective}, escalated from {base}: {})",
                        reasons.join(", ")
                    )
                }
            } else {
                format!("would challenge ({effective})")
            }),
        }
    }

    fn json(&self) -> serde_json::Value {
        let (decision, challenge, escalated_from, reasons) = match &self.verdict {
            None => ("allow", None, None, Vec::new()),
            Some(ShellVerdict::Denied) => ("deny", None, None, Vec::new()),
            Some(ShellVerdict::Challenge {
                effective,
                base,
                reasons,
            }) => (
                "challenge",
                Some(effective.to_string()),
                effective.is_stricter_than(*base).then(|| base.to_string()),
                reasons.clone(),
            ),
        };
        serde_json::json!({
            "decision": decision,
            "challenge": challenge,
            "escalated_from": escalated_from,
            "escalation_reasons": reasons,
            "context": {"risk_level": self.risk_level, "labels": self.labels},
        })
    }
}

/// Compute the [`ShellView`] the way `pre-command` does: the policies of
/// the directories the command targets (`cd repo &&`, `git -C`, path
/// arguments, `bash -c`, `sudo`) are discovered and their `context:` is
/// applied to the settings, so `check` predicts the same challenge.
fn shell_view(
    command: &str,
    settings: &Settings,
    checks: &[Check],
    env: &dyn Environment,
    cwd: &Path,
) -> ShellView {
    static NO_RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let dirs = agent::command_target_dirs(command, cwd, env.home_dir().as_deref());
    let discovery = shellfirm::policy::with_extra_target_dirs(&dirs, || {
        shellfirm::policy::discover_for(env, cwd, &shellfirm::context::command_target_dirs(command))
    });
    let mut settings = settings.clone();
    let owned_checks: Option<Vec<Check>> = discovery.policy.as_ref().and_then(|p| {
        let _ = shellfirm::policy::apply_to_settings(&mut settings, p);
        // The target policy's own checks and the ids it enforces over a
        // personal ignore (as `pre-command` loads them).
        let all = checks::get_all().unwrap_or_default();
        let builtin: std::collections::HashSet<&str> = all.iter().map(|c| c.id.as_str()).collect();
        let custom: Vec<Check> = checks
            .iter()
            .filter(|c| !builtin.contains(c.id.as_str()) && !p.checks.iter().any(|x| x.id == c.id))
            .cloned()
            .collect();
        settings.get_active_checks_enforced(&custom, Some(p)).ok()
    });
    let checks = owned_checks.as_deref().unwrap_or(checks);
    let resolved = settings.resolved_for(shellfirm::config::Mode::Shell);
    let Ok(pipeline) = shellfirm::policy::with_extra_target_dirs(&dirs, || {
        checks::analyze_command(
            command,
            &settings,
            &resolved,
            checks,
            env,
            NO_RE.get_or_init(|| regex::Regex::new("$^").expect("valid regex")),
        )
    }) else {
        return ShellView::default();
    };
    let mut view = ShellView {
        verdict: None,
        below_min: pipeline
            .skipped_matches
            .iter()
            .map(|c| (c.id.clone(), c.severity))
            .collect(),
        min_severity: resolved.min_severity,
        risk_level: format!("{:?}", pipeline.relevant_context.risk_level),
        labels: pipeline.relevant_context.labels.clone(),
    };
    if pipeline.active_matches.is_empty() {
        return view;
    }
    let refs: Vec<&Check> = pipeline.active_matches.iter().collect();
    let d = checks::build_challenge_display(
        &settings,
        &resolved,
        &refs,
        &pipeline.relevant_context,
        &pipeline.merged_policy,
        &pipeline.blast_radii,
    );
    view.verdict = Some(if d.is_denied {
        ShellVerdict::Denied
    } else {
        ShellVerdict::Challenge {
            effective: d.effective_challenge,
            base: d.base_challenge,
            reasons: d.escalation_reasons,
        }
    });
    view
}

/// Why a check that matched the command does not apply (`check -c` and
/// the JSON `not_applied` list): ignored, below `min_severity`, or the path
/// it acts on does not exist.
#[derive(Debug, Clone, PartialEq, Eq)]
enum NotApplied {
    Ignored {
        id: String,
    },
    BelowMinSeverity {
        id: String,
        severity: Severity,
        min: Severity,
    },
    PathMissing {
        id: String,
        path: String,
    },
}

impl NotApplied {
    fn text(&self) -> String {
        match self {
            Self::Ignored { id } => format!(
                "{id}: ignored by your settings (undo: shellfirm config ignore --remove {id})"
            ),
            Self::BelowMinSeverity { id, severity, min } => format!(
                "{id} [{}]: below your min_severity ({min}), so the shell does not challenge it \
                 (change: shellfirm config severity)",
                severity_label(*severity)
            ),
            Self::PathMissing { id, path } => format!("{id}: skipped, {path} does not exist"),
        }
    }

    fn json(&self) -> serde_json::Value {
        match self {
            Self::Ignored { id } => serde_json::json!({
                "id": id, "reason": "ignored",
                "undo": format!("shellfirm config ignore --remove {id}"),
            }),
            Self::BelowMinSeverity { id, severity, min } => serde_json::json!({
                "id": id, "reason": "below_min_severity", "severity": severity, "min_severity": min,
            }),
            Self::PathMissing { id, path } => serde_json::json!({
                "id": id, "reason": "path_missing", "path": path,
            }),
        }
    }
}

/// Every [`NotApplied`] entry for one command, ignored first.
fn not_applied(
    assessment: &RiskAssessment,
    shell: &ShellView,
    ignored: &[String],
) -> Vec<NotApplied> {
    let mut out: Vec<NotApplied> = ignored
        .iter()
        .map(|id| NotApplied::Ignored { id: id.clone() })
        .collect();
    if let Some(min) = shell.min_severity {
        for (id, severity) in &shell.below_min {
            if !out
                .iter()
                .any(|n| matches!(n, NotApplied::Ignored { id: i } if i == id))
            {
                out.push(NotApplied::BelowMinSeverity {
                    id: id.clone(),
                    severity: *severity,
                    min,
                });
            }
        }
    }
    for s in &assessment.skipped_missing_paths {
        out.push(NotApplied::PathMissing {
            id: s.id.clone(),
            path: s.path.clone(),
        });
    }
    out
}

/// `CRITICAL`, `HIGH`, ... as in the challenge banner.
fn severity_label(s: Severity) -> String {
    s.to_string()
}

/// The severity label coloured by severity (red for High/Critical, yellow
/// for Medium; the word is always there, colour is only a cue). Colour
/// follows stdout (`NO_COLOR`, monochrome terminals, pipes: none).
fn styled_severity(s: Severity) -> String {
    let label = format!("[{}]", severity_label(s));
    let st = match s {
        Severity::Critical => console::style(label).red().bold(),
        Severity::High => console::style(label).red(),
        Severity::Medium => console::style(label).yellow(),
        Severity::Low | Severity::Info => console::style(label).cyan(),
    };
    st.to_string()
}

fn risk_rank(level: &str) -> u8 {
    match level {
        "Critical" => 2,
        "Elevated" => 1,
        _ => 0,
    }
}

/// Format a `RiskAssessment` as human-readable text for stdout. `shell` is
/// what the interactive shell hook would do (see [`shell_view`]). Dynamic
/// text (ids, paths, descriptions) is escaped before any colour is added.
#[allow(clippy::too_many_lines)]
fn format_text_output(
    assessment: &RiskAssessment,
    shell: &ShellView,
    ignored: &[String],
) -> String {
    let e = |t: &str| shellfirm::context::escape_invisible(t);
    // Free text keeps its joiners (Persian, Indic, emoji), as the banner does.
    let et = |t: &str| shellfirm::context::escape_invisible_text(t);
    let not_applied = not_applied(assessment, shell, ignored);
    let not_applied_lines = |output: &mut String| {
        for n in &not_applied {
            let _ = write!(output, "\n  - {}", e(&n.text()));
        }
    };
    let shell_line = shell.line();
    if assessment.matched_rules.is_empty()
        && assessment.decision == Decision::Allow
        && shell_line.is_none()
    {
        if not_applied.is_empty() {
            return console::style("No risky patterns matched.")
                .green()
                .to_string();
        }
        let mut out = format!(
            "{} matched, but none applies here:",
            if not_applied.len() == 1 {
                "1 check".to_string()
            } else {
                format!("{} checks", not_applied.len())
            }
        );
        not_applied_lines(&mut out);
        out.push_str("\n\n  Shell (you, in a terminal): runs without a challenge");
        out.push_str("\n  AI agent (hooks, MCP): allow");
        return out;
    }

    let mut output = String::new();
    if !assessment.matched_rules.is_empty() {
        let _ = writeln!(
            output,
            "{} risky pattern(s) matched:",
            assessment.matched_rules.len()
        );
    }
    let write_alt = |output: &mut String, alt: &agent::Alternative| {
        let _ = write!(output, "    > Safe alternative: {}", e(&alt.command));
        if let Some(info) = alt.explanation.as_deref().filter(|i| !i.trim().is_empty()) {
            let _ = write!(output, " ({})", et(info));
        }
        output.push('\n');
    };
    for m in &assessment.matched_rules {
        let _ = write!(
            output,
            "\n  [{}] {} {}\n",
            e(&m.id),
            styled_severity(m.severity),
            et(&m.description)
        );
        if let Some(ref scope) = m.blast_radius_scope {
            let detail = m.blast_radius_detail.as_deref().unwrap_or("");
            let _ = writeln!(output, "    Blast radius: [{scope}] — {}", e(detail));
        }
        // Each alternative under the rule it belongs to.
        for alt in assessment
            .alternatives
            .iter()
            .filter(|a| a.rule_id.as_deref() == Some(m.id.as_str()))
        {
            write_alt(&mut output, alt);
        }
    }
    let unowned: Vec<&agent::Alternative> = assessment
        .alternatives
        .iter()
        .filter(|a| {
            !a.rule_id
                .as_deref()
                .is_some_and(|id| assessment.matched_rules.iter().any(|m| m.id == id))
        })
        .collect();
    if !unowned.is_empty() {
        output.push('\n');
        for alt in unowned {
            write_alt(&mut output, alt);
        }
    }
    // The context: the agent's, plus the labels only the shell view has
    // (the target repository's policy context, e.g. under `sudo`).
    let mut labels = assessment.context.labels.clone();
    for l in &shell.labels {
        if !labels.contains(l) {
            labels.push(l.clone());
        }
    }
    let risk = if risk_rank(&shell.risk_level) > risk_rank(&assessment.context.risk_level) {
        shell.risk_level.as_str()
    } else {
        assessment.context.risk_level.as_str()
    };
    if !labels.is_empty() {
        let _ = writeln!(output, "\n  Context: {risk} ({})", e(&labels.join(", ")));
    }
    if !not_applied.is_empty() {
        output.push_str("\n  Not applied:");
        not_applied_lines(&mut output);
        output.push('\n');
    }
    let reason = e(assessment.decision_reason.as_deref().unwrap_or(""));
    output.push('\n');
    let _ = writeln!(
        output,
        "  Shell (you, in a terminal): {}",
        shell_line.map_or_else(|| "runs without a challenge".to_string(), |l| e(&l))
    );
    match assessment.decision {
        Decision::Deny => {
            let _ = writeln!(
                output,
                "  AI agent (hooks, MCP): {}\n    why: {reason}",
                console::style("deny (blocked)").red().bold()
            );
        }
        Decision::Ask => {
            let _ = writeln!(
                output,
                "  AI agent (hooks, MCP): {} — {reason}",
                console::style("ask").yellow()
            );
        }
        Decision::Allow => {
            let _ = writeln!(output, "  AI agent (hooks, MCP): allow");
        }
    }
    output.trim_end().to_string()
}

// ---------------------------------------------------------------------------
// --list
// ---------------------------------------------------------------------------

/// One `check --list` row. Ids and groups are escaped strictly; the
/// description keeps its joiners (Persian, Indic, emoji) as the banner does.
fn list_row(marker: &str, c: &Check) -> String {
    format!(
        "  {marker}{id:<45} {group:<18} {sev:<10} {desc}",
        id = shellfirm::context::escape_invisible(&c.id),
        group = shellfirm::context::escape_invisible(&c.from),
        sev = format!("{}", c.severity),
        desc = shellfirm::context::escape_invisible_text(&c.description)
    )
}

#[allow(clippy::too_many_lines)]
fn run_list(
    settings: &Settings,
    active_checks: &[Check],
    group_filter: Option<&str>,
    show_all: bool,
    json: bool,
) -> Result<shellfirm::CmdExit> {
    let all = checks::get_all()?;
    // Checks defined by the project / org policy that applies here: they are
    // active (policies cannot be ignored) and listed with a marker.
    let env = RealEnvironment;
    let policy_checks: Vec<Check> = env
        .current_dir()
        .ok()
        .and_then(|cwd| shellfirm::policy::discover_all(&env, &cwd).policy)
        .map(|p| p.checks)
        .unwrap_or_default();
    let mut active_owned: Vec<Check> = active_checks.to_vec();
    for c in &policy_checks {
        if !active_owned.iter().any(|a| a.id == c.id) {
            active_owned.push(c.clone());
        }
    }
    let active_checks: &[Check] = &active_owned;
    let is_policy = |c: &Check| policy_checks.iter().any(|p| p.id == c.id);

    if let Some(group) = group_filter {
        let known = all
            .iter()
            .chain(active_checks.iter())
            .any(|c| c.from == group);
        if !known {
            // The same wording and exit code (2) as `config groups`.
            return Ok(usage(shellfirm::config::unknown_group_message(
                group,
                all.iter()
                    .chain(active_checks.iter())
                    .map(|c| c.from.as_str())
                    .chain(shellfirm::config::DEFAULT_ENABLED_GROUPS),
            )));
        }
    }

    let source: Vec<Check> = if show_all {
        let mut v = all;
        for c in active_checks {
            if !v.iter().any(|x| x.id == c.id) {
                v.push(c.clone());
            }
        }
        v
    } else {
        active_checks.to_vec()
    };
    let filtered: Vec<&Check> = source
        .iter()
        .filter(|c| group_filter.is_none_or(|g| c.from == g))
        .collect();
    // `-g nomad` for a group that is not enabled (an opt-in group, or one
    // the user disabled): say how to enable it instead of an empty list.
    let inactive_group_note = group_filter
        .filter(|_| !show_all && filtered.is_empty())
        .map(|g| {
            format!(
                "group `{g}` is not enabled (it is opt-in, or disabled in your settings); \
                 enable it with `shellfirm config groups --enable {g}`, or add --all to list \
                 its checks"
            )
        });

    if json {
        let items: Vec<serde_json::Value> = filtered
            .iter()
            .map(|c| {
                serde_json::json!({
                    "id": c.id,
                    "group": c.from,
                    "severity": c.severity,
                    "description": c.description,
                    "active": active_checks.iter().any(|ac| ac.id == c.id),
                    "alternative": c.alternative,
                    "origin": if is_policy(c) { "project-policy" } else { "builtin" },
                })
            })
            .collect();
        let enabled_groups: Vec<&String> = settings
            .enabled_groups
            .iter()
            .filter(|g| group_filter.is_none_or(|f| f == g.as_str()))
            .collect();
        let mut out = serde_json::json!({
            "schema_version": agent::ASSESSMENT_SCHEMA_VERSION,
            "version": env!("CARGO_PKG_VERSION"),
            "enabled_groups": enabled_groups,
            "checks": items,
        });
        if let Some(note) = &inactive_group_note {
            out["note"] = serde_json::Value::String(note.clone());
        }
        if let Err(e) = write_stdout(&serde_json::to_string_pretty(&out)?) {
            return Ok(output_error(&e));
        }
        return Ok(shellfirm::CmdExit {
            code: EXIT_OK,
            message: None,
        });
    }

    let mut output = if show_all {
        format!("{} check(s) available:\n\n", filtered.len())
    } else {
        format!(
            "{} active check(s) (groups: {}):\n\n",
            filtered.len(),
            group_filter.map_or_else(|| settings.enabled_groups.join(", "), ToString::to_string)
        )
    };
    if let Some(note) = &inactive_group_note {
        let _ = writeln!(output, "  note: {note}");
    }
    let any_policy = filtered.iter().any(|c| is_policy(c));
    for c in &filtered {
        let marker = if !show_all {
            String::new()
        } else if active_checks.iter().any(|ac| ac.id == c.id) {
            "[+] ".into()
        } else {
            "[-] ".into()
        };
        let marker = if is_policy(c) {
            format!("{marker}[policy] ")
        } else {
            marker
        };
        let _ = writeln!(output, "{}", list_row(&marker, c));
    }
    if show_all {
        output.push_str("\n  [+] = active, [-] = inactive\n");
    }
    if any_policy {
        output.push_str("  [policy] = defined by the project/org policy that applies here\n");
    }
    // Descriptions come from the YAML catalogue (em dashes, ellipses):
    // plain ASCII when the terminal is not UTF-8 (`LC_ALL=C`).
    if let Err(e) = write_stdout(&shellfirm::config::ascii_fallback(&output)) {
        return Ok(output_error(&e));
    }
    Ok(shellfirm::CmdExit {
        code: EXIT_OK,
        message: None,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use shellfirm::AgentConfig;

    fn php(input: &str) -> std::result::Result<HookPayload, String> {
        parse_hook_payload(input, HookKind::ClaudeCode)
    }

    fn test_settings() -> Settings {
        Settings {
            challenge: shellfirm::Challenge::Math,
            enabled_groups: vec!["base".into(), "fs".into(), "git".into()],
            audit_enabled: false,
            ..Settings::default()
        }
    }

    fn assess(cmd: &str, mut agent: AgentConfig) -> RiskAssessment {
        // These tests use the real environment (which may be root, on `main`,
        // ...), so keep runtime context out of the decision; context
        // escalation is covered with a mock environment in agent.rs.
        agent.context_escalation = false;
        let settings = Settings {
            agent: agent.clone(),
            ..test_settings()
        };
        let checks = settings.get_active_checks().unwrap();
        agent::assess_command(cmd, &settings, &checks, &RealEnvironment, &agent).unwrap()
    }

    // -- CLI wiring --

    #[test]
    fn cli_definition_is_valid() {
        command().debug_assert();
    }

    fn kind_for(args: &[&str]) -> Option<HookKind> {
        let m = command().try_get_matches_from(args).unwrap();
        let format = m.get_one::<String>("format").unwrap().clone();
        hook_kind(&m, &format)
    }

    fn legacy_for(args: &[&str]) -> bool {
        let m = command().try_get_matches_from(args).unwrap();
        let format = m.get_one::<String>("format").unwrap().clone();
        is_legacy_invocation(&m, &format)
    }

    #[test]
    fn legacy_hook_command_line_is_recognised_exactly() {
        let mut args = vec!["check"];
        args.extend(LEGACY_CLAUDE_HOOK_ARGS.split_whitespace().skip(1));
        assert!(legacy_for(&args));
        assert_eq!(kind_for(&args), None, "only with a hook payload on stdin");
        assert!(!legacy_for(&[
            "check",
            "--stdin",
            "--format",
            "json",
            "--exit-code",
            "--fail-on",
            "high"
        ]));
        assert!(!legacy_for(&["check", "--stdin", "--format", "json"]));
    }

    #[test]
    fn hook_payload_detection_for_legacy_line() {
        assert!(looks_like_hook_payload(
            r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#
        ));
        assert!(looks_like_hook_payload(
            r#"{"hook_event_name":"PreToolUse"}"#
        ));
        assert!(looks_like_hook_payload("\u{feff}{not json"));
        assert!(looks_like_hook_payload(r#"{"tool_input":{"command":"x"}"#));
        assert!(!looks_like_hook_payload("git push -f"));
        assert!(!looks_like_hook_payload(r#"{"command":"git push -f"}"#));
        assert!(!looks_like_hook_payload("   "));
    }

    #[test]
    fn hook_flag_conflicts_with_command() {
        assert!(command()
            .try_get_matches_from(["check", "--hook", "claude-code", "-c", "ls"])
            .is_err());
    }

    #[test]
    fn hook_selection() {
        assert_eq!(
            kind_for(&["check", "--hook", "claude-code"]),
            Some(HookKind::ClaudeCode)
        );
        assert_eq!(
            kind_for(&["check", "--hook", "cursor"]),
            Some(HookKind::Cursor)
        );
        assert_eq!(
            kind_for(&["check", "--stdin", "--format", "claude-hook"]),
            Some(HookKind::ClaudeCode)
        );
        // `-c ... --format json --exit-code` is NOT hook mode any more.
        assert_eq!(
            kind_for(&["check", "-c", "ls", "--format", "json", "--exit-code"]),
            None
        );
        assert_eq!(kind_for(&["check", "--stdin", "--format", "json"]), None);
    }

    #[test]
    fn fail_on_parses_case_insensitively() {
        let m = command()
            .try_get_matches_from(["check", "-c", "ls", "--fail-on", "HIGH"])
            .unwrap();
        assert_eq!(
            m.get_one::<String>("fail-on")
                .and_then(|s| parse_severity(s)),
            Some(Severity::High)
        );
    }

    // -- hook payload parsing --

    #[test]
    fn parse_claude_payload_full_envelope() {
        let input = r#"{"session_id":"abc","transcript_path":"/t","cwd":"/home/u/p","permission_mode":"default","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push -f","description":"push"},"tool_use_id":"toolu_1"}"#;
        let p = php(input).unwrap();
        assert_eq!(p.command(), Some("git push -f"));
        assert_eq!(p.cwd.as_deref(), Some("/home/u/p"));
        assert_eq!(p.session_id.as_deref(), Some("abc"));
    }

    #[test]
    fn parse_cursor_payload() {
        let input = r#"{"conversation_id":"c1","hook_event_name":"beforeShellExecution","command":"rm -rf /","cwd":"/w"}"#;
        let p = php(input).unwrap();
        assert_eq!(p.command(), Some("rm -rf /"));
        assert_eq!(p.session_id.as_deref(), Some("c1"));
    }

    #[test]
    fn parse_file_tools_and_other_tools() {
        let input = r#"{"tool_name":"Write","tool_input":{"file_path":"/x","content":"rm -rf /"},"tool_use_id":"toolu_9"}"#;
        let p = php(input).unwrap();
        assert_eq!(
            p.action,
            HookAction::FileWrite {
                tool: "Write".into(),
                path: "/x".into()
            }
        );
        assert_eq!(p.tool_use_id.as_deref(), Some("toolu_9"));
        let nb = r#"{"tool_name":"NotebookEdit","tool_input":{"notebook_path":"/n.ipynb","new_source":"x"}}"#;
        assert!(matches!(
            php(nb).unwrap().action,
            HookAction::FileWrite { ref path, .. } if path == "/n.ipynb"
        ));
        for other in [
            r#"{"tool_name":"Read","tool_input":{"file_path":"/home/u/.config/shellfirm/settings.yaml"}}"#,
            r#"{"tool_name":"mcp__x__y","tool_input":{}}"#,
        ] {
            assert_eq!(php(other).unwrap().action, HookAction::NotApplicable);
        }
        // a file tool without a path fails closed
        assert!(php(r#"{"tool_name":"Edit","tool_input":{}}"#).is_err());
        assert!(php(r#"{"tool_name":"Edit","tool_input":{"file_path":3}}"#).is_err());
    }

    #[test]
    fn parse_bad_payloads_fail() {
        for bad in [
            "",
            "   ",
            "{not json",
            r#"{"tool_input":{"command":"git push -f origin main"}"#,
            r#"{"tool_input":{"command":"git push -f","x":1,}}"#,
            "[1,2,3]",
            r#""just a string""#,
            r#"{"tool_name":"Bash","tool_input":{"command":["rm","-rf","/"]}}"#,
            r#"{"tool_name":"Bash","tool_input":{}}"#,
            r#"{"tool_name":"Bash","tool_input":"rm -rf /"}"#,
            r#"{"command":42}"#,
            r#"{"foo":"bar"}"#,
            "git push -f",
        ] {
            assert!(php(bad).is_err(), "should fail: {bad:?}");
        }
        let deep = format!(
            "{{\"tool_input\":{{\"command\":\"git push -f\",\"x\":{}{}}}}}",
            "[".repeat(200),
            "]".repeat(200)
        );
        assert!(php(&deep).is_err());
    }

    // -- non-hook stdin parsing --

    #[test]
    fn parse_json_with_leading_bom() {
        assert_eq!(
            parse_command_input("\u{feff}{\"command\": \"rm -rf /\"}").unwrap(),
            "rm -rf /"
        );
        let payload = php(
            "\u{feff}\u{feff} {\"tool_name\": \"Bash\", \"tool_input\": {\"command\": \"ls\"}}",
        )
        .unwrap();
        assert_eq!(payload.command(), Some("ls"));
    }

    #[test]
    fn parse_simple_json_command() {
        assert_eq!(
            parse_command_input(r#"{"command": "rm -rf /"}"#).unwrap(),
            "rm -rf /"
        );
    }

    #[test]
    fn parse_claude_code_hooks_format() {
        let input = r#"{"tool_name": "Bash", "tool_input": {"command": "git push --force"}}"#;
        assert_eq!(parse_command_input(input).unwrap(), "git push --force");
    }

    #[test]
    fn parse_plain_text_fallback() {
        assert_eq!(parse_command_input("ls -la /tmp").unwrap(), "ls -la /tmp");
        assert_eq!(
            parse_command_input("  echo hello  \n").unwrap(),
            "echo hello"
        );
    }

    #[test]
    fn parse_empty_input_returns_error() {
        assert!(parse_command_input("").is_err());
        assert!(parse_command_input("   \n  ").is_err());
    }

    #[test]
    fn parse_malformed_json_is_not_plain_text() {
        assert!(parse_command_input(r#"{"command":"git push -f""#).is_err());
        assert!(parse_command_input(r#"{"foo": "bar"}"#)
            .unwrap_err()
            .contains("command"));
    }

    #[test]
    fn parse_tool_input_takes_precedence_over_command() {
        let input = r#"{"command": "echo fallback", "tool_input": {"command": "echo preferred"}}"#;
        assert_eq!(parse_command_input(input).unwrap(), "echo preferred");
    }

    // -- hook output golden tests --

    #[test]
    fn claude_hook_safe_command_emits_nothing() {
        let a = assess("echo hello", AgentConfig::default());
        assert_eq!(a.decision, Decision::Allow);
        assert_eq!(build_hook_output(HookKind::ClaudeCode, &a, false), None);
    }

    #[test]
    fn claude_hook_allow_safe_opt_in_emits_allow() {
        let a = assess("echo hello", AgentConfig::default());
        let out = build_hook_output(HookKind::ClaudeCode, &a, true).unwrap();
        assert_eq!(out["hookSpecificOutput"]["permissionDecision"], "allow");
    }

    #[test]
    fn claude_hook_below_threshold_is_ask_golden() {
        let a = assess(
            "git push --force",
            AgentConfig {
                auto_deny_severity: Severity::Critical,
                ..AgentConfig::default()
            },
        );
        let out = build_hook_output(HookKind::ClaudeCode, &a, false).unwrap();
        let obj = out.as_object().unwrap();
        assert_eq!(obj.len(), 1);
        let h = out["hookSpecificOutput"].as_object().unwrap();
        let keys: Vec<&str> = h.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "hookEventName",
                "permissionDecision",
                "permissionDecisionReason"
            ]
        );
        assert_eq!(h["hookEventName"], "PreToolUse");
        assert_eq!(h["permissionDecision"], "ask");
        let reason = h["permissionDecisionReason"].as_str().unwrap();
        assert!(reason.contains("git:force_push"), "{reason}");
        assert!(reason.contains("confirm"), "{reason}");
    }

    #[test]
    fn claude_hook_deny_golden() {
        let a = assess("git push --force", AgentConfig::default());
        let out = build_hook_output(HookKind::ClaudeCode, &a, false).unwrap();
        let h = &out["hookSpecificOutput"];
        assert_eq!(h["permissionDecision"], "deny");
        let reason = h["permissionDecisionReason"].as_str().unwrap();
        assert!(reason.starts_with("shellfirm BLOCKED this command."));
        assert!(reason.contains("BLOCKED: Severity HIGH"));
        assert!(reason.contains("Safe alternative: "));
    }

    #[test]
    fn claude_hook_require_human_approval_is_ask() {
        let a = assess(
            "git push --force",
            AgentConfig {
                require_human_approval: true,
                ..AgentConfig::default()
            },
        );
        let out = build_hook_output(HookKind::ClaudeCode, &a, false).unwrap();
        assert_eq!(out["hookSpecificOutput"]["permissionDecision"], "ask");
    }

    #[test]
    fn claude_hook_fail_closed_is_deny() {
        let a = RiskAssessment::fail_closed(Decision::Deny, "malformed JSON hook input");
        let out = build_hook_output(HookKind::ClaudeCode, &a, true).unwrap();
        assert_eq!(out["hookSpecificOutput"]["permissionDecision"], "deny");
        assert!(out["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("malformed JSON"));
    }

    #[test]
    fn cursor_hook_golden() {
        let safe = assess("ls", AgentConfig::default());
        assert_eq!(build_hook_output(HookKind::Cursor, &safe, false), None);
        assert_eq!(
            build_hook_output(HookKind::Cursor, &safe, true).unwrap(),
            serde_json::json!({"permission": "allow"})
        );
        let deny = assess("git push --force", AgentConfig::default());
        let out = build_hook_output(HookKind::Cursor, &deny, false).unwrap();
        assert_eq!(out["permission"], "deny");
        assert!(out["agent_message"]
            .as_str()
            .unwrap()
            .contains("git:force_push"));
        let user = out["user_message"].as_str().unwrap();
        assert!(!user.contains('\n'), "{user}");
    }

    #[test]
    fn self_protection_through_hook_is_ask() {
        let a = assess(
            "shellfirm config ignore git:force_push",
            AgentConfig::default(),
        );
        let out = build_hook_output(HookKind::ClaudeCode, &a, false).unwrap();
        assert_eq!(out["hookSpecificOutput"]["permissionDecision"], "ask");
    }

    // -- hook evaluation (file tools, config dir) --

    fn hook_ctx(settings: &Settings, dir: &Path) -> RunCtx<'static> {
        let settings: &'static Settings = Box::leak(Box::new(settings.clone()));
        RunCtx {
            settings,
            checks: &[],
            config_dir: Some(dir.to_path_buf()),
            no_context: true,
        }
    }

    #[test]
    fn hook_file_tools_on_protected_files_ask() {
        let tree = tree_fs::TreeBuilder::default()
            .add("cfg/settings.yaml", "audit_enabled: false\n")
            .create()
            .unwrap();
        let cfg = tree.root.join("cfg");
        let ctx = hook_ctx(&test_settings(), &cfg);
        let write_to = |path: &str, tool: &str| {
            let payload = serde_json::json!({
                "tool_name": tool,
                "tool_input": {"file_path": path, "content": "x"},
            })
            .to_string();
            evaluate_hook(HookKind::ClaudeCode, Ok(HookInput::Raw(payload)), &ctx).assessment
        };
        let pinned = cfg.join("settings.yaml").display().to_string();
        for (path, tool) in [
            (pinned.as_str(), "Write"),
            ("/home/dev/projects/webapp/.shellfirm.yaml", "Edit"),
            ("/home/dev/.claude/settings.local.json", "MultiEdit"),
        ] {
            let a = write_to(path, tool);
            assert_eq!(a.decision, Decision::Ask, "{path}");
            let out = build_hook_output(HookKind::ClaudeCode, &a, false).unwrap();
            assert_eq!(out["hookSpecificOutput"]["permissionDecision"], "ask");
        }
        let a = write_to("/home/dev/projects/webapp/src/app.ts", "Write");
        assert_eq!(build_hook_output(HookKind::ClaudeCode, &a, false), None);
        let nb = serde_json::json!({
            "tool_name": "NotebookEdit",
            "tool_input": {"notebook_path": "/home/dev/.zshrc", "new_source": "x"},
        })
        .to_string();
        let a = evaluate_hook(HookKind::ClaudeCode, Ok(HookInput::Raw(nb)), &ctx).assessment;
        assert_eq!(a.decision, Decision::Ask);
    }

    #[test]
    fn hook_uses_recorded_config_dir_settings() {
        let tree = tree_fs::TreeBuilder::default()
            .add(
                "cfg/settings.yaml",
                "audit_enabled: false\ndeny_patterns_ids: [git:force_push]\nagent:\n  require_human_approval: true\n",
            )
            .create()
            .unwrap();
        let ctx = hook_ctx(&test_settings(), &tree.root.join("cfg"));
        let payload = r#"{"tool_name":"Bash","tool_input":{"command":"git push --force"}}"#;
        let a = evaluate_hook(
            HookKind::ClaudeCode,
            Ok(HookInput::Raw(payload.into())),
            &ctx,
        )
        .assessment;
        assert_eq!(a.decision, Decision::Deny, "deny list from the pinned dir");
        assert!(a
            .denial_reason
            .as_deref()
            .is_some_and(|r| r.starts_with(agent::DENY_LIST_REASON)));
        assert_eq!(a.deny_reason.as_deref(), Some("user_deny"));
    }

    #[test]
    fn hook_and_exit_code_flags_are_a_usage_error() {
        let s = test_settings();
        for args in [
            vec!["check", "--hook", "claude-code", "--exit-code"],
            vec!["check", "--hook", "cursor", "--fail-on", "low"],
            vec![
                "check",
                "-c",
                "ls",
                "--format",
                "claude-hook",
                "--exit-code",
            ],
        ] {
            let m = command().try_get_matches_from(&args).unwrap();
            let r = run(&m, &s, &[]).unwrap();
            assert_eq!(r.code, EXIT_USAGE, "{args:?}");
        }
    }

    #[test]
    fn ask_is_not_allowed_in_json() {
        let ask = assess(
            "git push --force",
            AgentConfig {
                auto_deny_severity: Severity::Critical,
                ..AgentConfig::default()
            },
        );
        let v = serde_json::to_value(&ask).unwrap();
        assert_eq!(v["decision"], "ask");
        assert_eq!(v["allowed"], false);
    }

    // -- exit codes --

    #[test]
    fn exit_codes_follow_decision() {
        let safe = assess("echo hi", AgentConfig::default());
        assert_eq!(exit_code_for(&safe, None), EXIT_OK);
        let deny = assess("git push --force", AgentConfig::default());
        assert_eq!(exit_code_for(&deny, None), EXIT_DENY);
        let ask = assess(
            "git push --force",
            AgentConfig {
                auto_deny_severity: Severity::Critical,
                ..AgentConfig::default()
            },
        );
        assert_eq!(exit_code_for(&ask, None), EXIT_ASK);
    }

    #[test]
    fn fail_on_threshold() {
        let deny = assess("git push --force", AgentConfig::default());
        assert_eq!(deny.severity, Some(Severity::High));
        assert_eq!(exit_code_for(&deny, Some(Severity::Medium)), EXIT_DENY);
        assert_eq!(exit_code_for(&deny, Some(Severity::High)), EXIT_DENY);
        assert_eq!(exit_code_for(&deny, Some(Severity::Critical)), EXIT_OK);
    }

    #[test]
    fn exit_code_constants_are_distinct_from_clap_usage() {
        let codes = [EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_ASK, EXIT_DENY];
        let unique: std::collections::HashSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), codes.len());
        assert_eq!(EXIT_USAGE, 2);
    }

    /// `echo $($(…x…))` nested `depth` times.
    fn nested_substitutions(depth: usize) -> String {
        format!("echo {}x{}", "$(".repeat(depth), ")".repeat(depth))
    }

    #[test]
    fn deep_substitution_nesting_is_bounded_in_check_and_agent_hooks() {
        // Every depth is answered (no stack overflow, even on a 2 MB test
        // thread) with the nesting check, as text, JSON and both hooks.
        let settings = Settings {
            enabled_groups: vec!["base".into(), "fs".into(), "git".into(), "shell".into()],
            audit_enabled: false,
            ..Settings::default()
        };
        let checks = settings.get_active_checks().unwrap();
        let agent = AgentConfig {
            context_escalation: false,
            ..AgentConfig::default()
        };
        for depth in [5_000, 15_000, 50_000] {
            let cmd = nested_substitutions(depth);
            let started = std::time::Instant::now();
            let a =
                agent::assess_command(&cmd, &settings, &checks, &RealEnvironment, &agent).unwrap();
            assert!(
                a.matched_rules
                    .iter()
                    .any(|m| m.id == "shell:nesting_too_deep"),
                "{depth}: {:?}",
                a.matched_rules
            );
            assert_ne!(a.decision, Decision::Allow, "{depth}");
            let text = format_text_output(&a, &ShellView::default(), &[]);
            assert!(text.contains("shell:nesting_too_deep"), "{depth}");
            assert!(serde_json::to_string(&a)
                .unwrap()
                .contains("nesting_too_deep"));
            for kind in [HookKind::ClaudeCode, HookKind::Cursor] {
                let payload = serde_json::json!({
                    "tool_name": "Bash",
                    "tool_input": {"command": cmd},
                    "cwd": "/tmp"
                })
                .to_string();
                let parsed = parse_hook_payload(&payload, kind).unwrap();
                assert_eq!(parsed.command(), Some(cmd.as_str()));
                let out = build_hook_output(kind, &a, false).unwrap().to_string();
                assert!(out.contains("deny") || out.contains("ask"), "{out}");
            }
            // Linear: far below the 30 s agent-hook timeout even unoptimised.
            assert!(
                started.elapsed().as_secs() < 30,
                "{depth}: {:?}",
                started.elapsed()
            );
        }
    }

    // -- text / json output --

    #[test]
    fn text_output_and_list_keep_joiners_but_escape_bidi() {
        // U+200C (Persian), U+200D + U+FE0F (emoji sequences) are text; a
        // right-to-left override is still shown escaped.
        let desc = "\u{645}\u{6cc}\u{200c}\u{6a9}\u{646}\u{62f} \u{1F469}\u{200d}\u{1F4BB} \u{1F3F3}\u{fe0f}\u{200d}\u{1F308} x\u{202e}y";
        let mut a = assess("git reset --hard", AgentConfig::default());
        assert!(!a.matched_rules.is_empty());
        a.matched_rules[0].description = desc.into();
        let text = format_text_output(&a, &ShellView::default(), &[]);
        for c in ['\u{200c}', '\u{200d}', '\u{fe0f}'] {
            assert!(text.contains(c), "{c:?} missing: {text}");
        }
        assert!(
            !text.contains("\\u{200c}") && !text.contains("\\u{200d}"),
            "{text}"
        );
        assert!(text.contains("x\\u{202e}y"), "{text}");
        let check = Check {
            id: "mine:fa".into(),
            from: "mine".into(),
            description: desc.into(),
            ..checks::get_all().unwrap()[0].clone()
        };
        let row = list_row("[+] ", &check);
        assert!(
            row.contains('\u{200c}') && row.contains('\u{200d}'),
            "{row}"
        );
        assert!(row.contains("x\\u{202e}y"), "{row}");
        // A joiner in an id is still shown (it could disguise the id).
        let check = Check {
            id: "mine:a\u{200d}b".into(),
            ..check
        };
        assert!(list_row("", &check).contains("a\\u{200d}b"));
    }

    #[test]
    fn text_output_escapes_bidi_in_blast_radius() {
        // A right-to-left override in a path is shown escaped.
        let mut a = assess("git push -f", AgentConfig::default());
        assert!(!a.matched_rules.is_empty());
        a.matched_rules[0].blast_radius_scope = Some("RESOURCE".into());
        a.matched_rules[0].blast_radius_detail =
            Some("Deletes 2 paths (src\u{202e}.txt, build2 \u{200b})".into());
        let text = format_text_output(&a, &ShellView::default(), &[]);
        assert!(
            !text.contains('\u{202e}') && !text.contains('\u{200b}'),
            "{text}"
        );
        assert!(text.contains("src\\u{202e}.txt"), "{text}");
    }

    #[test]
    fn text_output_safe_command() {
        let a = assess("echo hi", AgentConfig::default());
        assert_eq!(
            format_text_output(&a, &ShellView::default(), &[]),
            "No risky patterns matched."
        );
    }

    #[test]
    fn text_output_says_an_ignored_check_is_ignored() {
        // Not "No risky patterns matched." for an ignored match.
        let a = assess("echo hi", AgentConfig::default());
        let text = format_text_output(&a, &ShellView::default(), &["git:force_push".to_string()]);
        assert!(!text.contains("No risky patterns matched"), "{text}");
        assert!(
            text.starts_with("1 check matched, but none applies here:"),
            "{text}"
        );
        assert!(
            text.contains(
                "git:force_push: ignored by your settings (undo: shellfirm config ignore \
                 --remove git:force_push)"
            ),
            "{text}"
        );
    }

    #[test]
    fn text_output_explains_all_three_not_applied_reasons() {
        // Ignored, below min_severity, missing path.
        let mut a = assess("echo hi", AgentConfig::default());
        a.skipped_missing_paths.push(agent::SkippedMissingPath {
            id: "fs:recursively_delete".into(),
            path: "/opt/app".into(),
        });
        let shell = ShellView {
            below_min: vec![("fs-strict:recursive_deletion".into(), Severity::Medium)],
            min_severity: Some(Severity::High),
            ..ShellView::default()
        };
        let text = format_text_output(&a, &shell, &["git:reset".to_string()]);
        assert!(
            text.starts_with("3 checks matched, but none applies here:"),
            "{text}"
        );
        assert!(
            text.contains("git:reset: ignored by your settings"),
            "{text}"
        );
        assert!(
            text.contains("fs-strict:recursive_deletion [MEDIUM]: below your min_severity (HIGH)"),
            "{text}"
        );
        assert!(
            text.contains("fs:recursively_delete: skipped, /opt/app does not exist"),
            "{text}"
        );
        assert!(text.contains("Shell (you, in a terminal): runs without a challenge"));
        let json = serde_json::to_value(&a).unwrap();
        assert_eq!(
            json["skipped_missing_paths"],
            serde_json::json!([{"id": "fs:recursively_delete", "path": "/opt/app"}])
        );
        let na: Vec<serde_json::Value> = not_applied(&a, &shell, &["git:reset".to_string()])
            .iter()
            .map(NotApplied::json)
            .collect();
        assert_eq!(na[0]["reason"], "ignored");
        assert_eq!(na[0]["undo"], "shellfirm config ignore --remove git:reset");
        assert_eq!(na[1]["reason"], "below_min_severity");
        assert_eq!(na[2]["reason"], "path_missing");
    }

    #[test]
    fn text_output_deny_and_ask() {
        let deny = assess("git push --force", AgentConfig::default());
        let shell = ShellView {
            verdict: Some(ShellVerdict::Challenge {
                effective: shellfirm::config::Challenge::Math,
                base: shellfirm::config::Challenge::Math,
                reasons: Vec::new(),
            }),
            ..ShellView::default()
        };
        let text = format_text_output(&deny, &shell, &[]);
        assert!(text.contains("risky pattern(s) matched:"));
        assert!(
            text.contains("[HIGH]") || text.contains("[CRITICAL]"),
            "{text}"
        );
        assert!(text.contains("Shell (you, in a terminal): would challenge (Math)"));
        assert!(
            text.contains("AI agent (hooks, MCP): deny (blocked)"),
            "{text}"
        );
        let ask = assess(
            "git push --force",
            AgentConfig {
                auto_deny_severity: Severity::Critical,
                ..AgentConfig::default()
            },
        );
        let text = format_text_output(&ask, &ShellView::default(), &[]);
        assert!(text.contains("AI agent (hooks, MCP): ask"));
        assert!(!text.contains("blocked"));
    }

    #[test]
    fn shell_view_line_names_escalation_reasons() {
        let v = ShellView {
            verdict: Some(ShellVerdict::Challenge {
                effective: shellfirm::config::Challenge::Yes,
                base: shellfirm::config::Challenge::Math,
                reasons: vec!["protected branch `develop`".into()],
            }),
            ..ShellView::default()
        };
        assert_eq!(
            v.line().unwrap(),
            "would challenge (Yes, escalated from Math: protected branch `develop`)"
        );
        assert_eq!(v.json()["decision"], "challenge");
        assert_eq!(v.json()["escalated_from"], "Math");
        assert_eq!(ShellView::default().json()["decision"], "allow");
    }

    #[test]
    fn json_output_has_schema_version_and_decision() {
        let a = assess("git push --force", AgentConfig::default());
        let v = serde_json::to_value(&a).unwrap();
        assert_eq!(v["schema_version"], 2);
        assert_eq!(v["decision"], "deny");
        assert_eq!(v["allowed"], false);
        assert_eq!(v["matched_rules"][0]["id"], "git:force_push");
        assert!(v["denial_reason"].is_string());
    }

    #[test]
    fn stdin_shell_lines_starting_with_brackets_are_commands() {
        for c in [
            "{ rm -rf /; }",
            "[ -d x ] && rm -rf /",
            "[[ -n x ]] && git push -f",
            "{\n rm -rf /\n}",
            "[ \"$X\" = y ] && ls",
        ] {
            assert_eq!(stdin_shape(c), StdinShape::Shell, "{c}");
            assert!(!looks_like_hook_payload(c), "{c}");
            assert_eq!(parse_command_input(c).unwrap(), c.trim(), "{c}");
        }
        assert_eq!(
            stdin_shape(r#"{"tool_input":{"command":"x"}"#),
            StdinShape::BrokenJson
        );
        assert_eq!(stdin_shape("{}"), StdinShape::Json);
        assert_eq!(stdin_shape("{\n  \"command\": 1,"), StdinShape::BrokenJson);
        assert_eq!(stdin_shape("[1,2]"), StdinShape::Json);
        assert!(parse_command_input("[1,2]").is_err());
        assert!(looks_like_hook_payload("{\"tool_input\":"));
    }

    #[test]
    fn utf16_stdin_is_decoded() {
        let text = "rm -rf /";
        let le: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let be: Vec<u8> = text.encode_utf16().flat_map(u16::to_be_bytes).collect();
        let with_bom = |bom: [u8; 2], body: &[u8]| [bom.as_slice(), body].concat();
        assert_eq!(decode_input(&with_bom([0xFF, 0xFE], &le)).unwrap(), text);
        assert_eq!(decode_input(&with_bom([0xFE, 0xFF], &be)).unwrap(), text);
        assert_eq!(decode_input(&le).unwrap(), text);
        assert_eq!(decode_input(&be).unwrap(), text);
        assert!(decode_input(b"rm\0\0\0 -rf").is_err());
        assert_eq!(decode_input("ls \u{e9}".as_bytes()).unwrap(), "ls \u{e9}");
        // Without a BOM, non-ASCII characters (no NUL byte) do not hide the
        // byte order the ASCII ones give away.
        let mixed = "echo \u{65e5}\u{672c}\u{8a9e}; rm -rf /";
        let le: Vec<u8> = mixed.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let be: Vec<u8> = mixed.encode_utf16().flat_map(u16::to_be_bytes).collect();
        let both = decode_input(&le).unwrap();
        assert!(both.starts_with(&format!("{mixed}\n")), "{both:?}");
        assert!(both.ends_with("; rm -rf /"), "{both:?}");
        assert!(decode_input(&be)
            .unwrap()
            .starts_with(&format!("{mixed}\n")));
    }

    #[test]
    fn utf8_with_stray_nul_is_never_read_as_utf16() {
        // UTF-8 scripts with a stray NUL and an even length
        // were decoded as UTF-16 garbage and allowed. They are refused.
        for raw in [
            b"#!/bin/bash\necho deploying\n# \x00\ngit push -f\n ".as_slice(),
            b"rm -rf / \x00",
            b"echo \x00; rm -rf /",
            b"\xe6\x97\xa5\x00rm -rf /",
            b"ls\x00\x01\x00\x01\nrm -rf /",
            b"ls\x00\x01\x00\x01\nrm -rf /x",
        ] {
            assert!(decode_input(raw).is_err(), "{raw:?}");
        }
        // Padding with enough NULs to look like UTF-16 still exposes the
        // text a shell would run.
        let mut padded = b"git push -f\n".to_vec();
        padded.extend(b"a\0".repeat(40));
        let text = decode_input(&padded).unwrap();
        assert!(text.contains("git push -f"), "{text:?}");
        // Pure-ASCII UTF-16 decodes to exactly one reading.
        let le: Vec<u8> = "git push -f"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(decode_input(&le).unwrap(), "git push -f");
    }

    #[test]
    fn stray_bom_before_utf8_is_read_as_utf8() {
        // `FF FE` / `FE FF` in front of UTF-8 text (no NUL bytes) is not
        // UTF-16: the shell runs the text, so that is what is checked.
        for bom in [[0xFF, 0xFE], [0xFE, 0xFF]] {
            for body in [
                "\ngit push -f origin main\nrm -rf /\n",
                "rm -rf /",
                "rm -rf /x",
            ] {
                let input = [bom.as_slice(), body.as_bytes()].concat();
                assert_eq!(decode_input(&input).unwrap(), body, "{bom:?} {body:?}");
            }
        }
        // A UTF-16 BOM with an odd-length or invalid body that has NULs is
        // refused, never decoded as garbage.
        assert!(decode_input(&[0xFF, 0xFE, b'r', 0, b'm']).is_err());
        assert!(decode_input(&[0xFF, 0xFE, 0x00, 0xD8, b'a', 0]).is_err());
    }

    #[test]
    fn utf32_stdin_is_decoded_or_refused() {
        let text = "git push -f";
        let le: Vec<u8> = text
            .chars()
            .flat_map(|c| (c as u32).to_le_bytes())
            .collect();
        let be: Vec<u8> = text
            .chars()
            .flat_map(|c| (c as u32).to_be_bytes())
            .collect();
        assert_eq!(
            decode_input(&[[0xFF, 0xFE, 0, 0].as_slice(), &le].concat()).unwrap(),
            text
        );
        assert_eq!(
            decode_input(&[[0, 0, 0xFE, 0xFF].as_slice(), &be].concat()).unwrap(),
            text
        );
        assert_eq!(decode_input(&le).unwrap(), text);
        assert_eq!(decode_input(&be).unwrap(), text);
        // Truncated UTF-32 is refused.
        assert!(decode_input(&[[0xFF, 0xFE, 0, 0].as_slice(), &le[..5]].concat()).is_err());
    }

    #[test]
    fn broken_json_stdin_is_not_a_hook_payload() {
        for raw in [
            "{\"command\":\"rm -rf /\"}\n{\"command\":\"ls\"}\n",
            "{\"command\":",
            "{}; rm -rf /",
            "{\"command\":\"ls\"}; rm -rf /",
        ] {
            assert!(!is_hook_payload_json(raw), "{raw:?}");
            assert_eq!(stdin_shape(raw), StdinShape::BrokenJson, "{raw:?}");
        }
        assert!(is_hook_payload_json(
            r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#
        ));
        assert!(!is_hook_payload_json(r#"{"command":"ls"}"#));
    }

    #[test]
    fn shell_tools_beyond_bash_are_commands() {
        for tool in ["PowerShell", "Monitor", "Shell"] {
            let p = php(&format!(
                r#"{{"tool_name":"{tool}","tool_input":{{"command":"rm -rf /","description":"x","timeout_ms":1}}}}"#
            ))
            .unwrap();
            assert_eq!(p.command(), Some("rm -rf /"), "{tool}");
        }
        let ws = php(r#"{"tool_name":"Monitor","tool_input":{"ws":{"url":"wss://x"}}}"#).unwrap();
        assert_eq!(ws.action, HookAction::NotApplicable);
        let mcp = php(r#"{"tool_name":"mcp__shell__run","tool_input":{"command":"git push -f"}}"#)
            .unwrap();
        assert_eq!(mcp.command(), Some("git push -f"));
        assert!(php(r#"{"tool_name":"PowerShell","tool_input":{}}"#).is_err());
    }

    #[test]
    fn cursor_payloads_file_tools_and_workspace_root() {
        let p = parse_hook_payload(
            r#"{"hook_event_name":"preToolUse","tool_name":"Write","tool_input":{"path":"/w/.shellfirm.yaml","contents":"x"},"workspace_roots":["/w"]}"#,
            HookKind::Cursor,
        )
        .unwrap();
        assert_eq!(
            p.action,
            HookAction::FileWrite {
                tool: "Write".into(),
                path: "/w/.shellfirm.yaml".into()
            }
        );
        assert_eq!(p.workspace_root.as_deref(), Some("/w"));
        // No usable path: malformed, denied by the caller (fail closed).
        for bad in [
            r#"{"tool_name":"Write","tool_input":{"weird":1}}"#,
            r#"{"tool_name":"Write","tool_input":{}}"#,
            r#"{"tool_name":"Write","tool_input":{"file_path":5}}"#,
            r#"{"tool_name":"Write"}"#,
        ] {
            assert!(parse_hook_payload(bad, HookKind::Cursor).is_err(), "{bad}");
        }
        // An empty `cwd` is treated as missing.
        let p = parse_hook_payload(
            r#"{"command":"rm -rf ./src","cwd":"","workspace_roots":["","/w"]}"#,
            HookKind::Cursor,
        )
        .unwrap();
        assert_eq!(p.cwd, None);
        assert_eq!(p.workspace_root.as_deref(), Some("/w"));
    }

    #[test]
    fn cursor_protected_file_edit_is_denied_and_worded_as_file_edit() {
        let tree = tree_fs::TreeBuilder::default()
            .add("cfg/settings.yaml", "audit_enabled: false\n")
            .create()
            .unwrap();
        let ctx = hook_ctx(&test_settings(), &tree.root.join("cfg"));
        let payload = r#"{"tool_name":"Write","tool_input":{"file_path":"/home/dev/projects/webapp/.shellfirm.yaml"}}"#;
        let o = evaluate_hook(HookKind::Cursor, Ok(HookInput::Raw(payload.into())), &ctx);
        assert_eq!(o.assessment.decision, Decision::Deny);
        let out = build_hook_output_for(HookKind::Cursor, &o.assessment, false, o.subject).unwrap();
        assert_eq!(out["permission"], "deny");
        assert!(out["agent_message"]
            .as_str()
            .unwrap()
            .contains("this file edit"));
        let cc = evaluate_hook(
            HookKind::ClaudeCode,
            Ok(HookInput::Raw(payload.into())),
            &ctx,
        );
        assert_eq!(cc.assessment.decision, Decision::Ask);
        let out =
            build_hook_output_for(HookKind::ClaudeCode, &cc.assessment, false, cc.subject).unwrap();
        assert!(out["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .starts_with("shellfirm flagged this file edit"));
    }

    #[test]
    fn config_dir_must_be_a_directory() {
        let tree = tree_fs::TreeBuilder::default()
            .add("afile", "x")
            .create()
            .unwrap();
        let s = test_settings();
        for dir in [tree.root.join("afile"), tree.root.join("missing")] {
            let d = dir.display().to_string();
            let m = command()
                .try_get_matches_from(["check", "-c", "ls", "--config-dir", d.as_str()])
                .unwrap();
            let r = run(&m, &s, &[]).unwrap();
            assert_eq!(r.code, EXIT_USAGE, "{d}");
        }
    }
}
