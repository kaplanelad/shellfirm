mod cmd;
use std::io::{IsTerminal, Write};
use std::process::exit;

use console::Style;
use shellfirm::error::{Error, Result};
use shellfirm::{
    config,
    env::{Environment, RealEnvironment},
    policy, CmdExit, Config,
};

const DEFAULT_ERR_EXIT_CODE: i32 = 1;

/// Everything `status` needs to report problems instead of hiding them.
pub struct LoadReport {
    /// Error from the settings file (the in-memory settings fell back to
    /// defaults for the invalid values).
    pub settings_error: Option<String>,
    /// Non-fatal settings problems (unknown keys, ignore/deny conflicts).
    pub settings_warnings: Vec<String>,
    /// Warnings from loading custom checks (one per skipped file / check).
    pub custom_warnings: Vec<String>,
    /// Number of custom checks that loaded.
    pub custom_count: usize,
    /// Project policy discovery result.
    pub policy: policy::PolicyDiscovery,
}

const LOG_LEVELS: [&str; 6] = ["off", "error", "warn", "info", "debug", "trace"];

/// Validate a `SHELLFIRM_LOG` value. `EnvFilter` accepts almost anything (a
/// bare word is a *target* name), so a typo such as `debgu` would silently
/// turn logging off. Accept levels and `target=level` directives only.
fn check_log_directives(v: &str) -> std::result::Result<(), String> {
    for d in v.split(',').map(str::trim).filter(|d| !d.is_empty()) {
        let level = d.rsplit_once('=').map_or(d, |(_, l)| l);
        if !LOG_LEVELS.iter().any(|l| l.eq_ignore_ascii_case(level)) {
            let hint = config::suggest_similar(level, LOG_LEVELS, 1)
                .into_iter()
                .next()
                .map_or_else(String::new, |s| format!(" (did you mean `{s}`?)"));
            return Err(format!(
                "`{d}` is not a log level{hint}; valid levels: {}",
                LOG_LEVELS.join(", ")
            ));
        }
    }
    Ok(())
}

/// Configure tracing. Precedence: `--log` > `SHELLFIRM_LOG` > `error`.
/// ANSI colours are only used when stderr is a terminal and `NO_COLOR` is
/// not set.
fn init_logging(matches: &clap::ArgMatches) {
    let filter = matches.get_one::<String>("log").map_or_else(
        || match std::env::var("SHELLFIRM_LOG") {
            Ok(v) if !v.trim().is_empty() => check_log_directives(&v)
                .and_then(|()| {
                    tracing_subscriber::EnvFilter::try_new(v.to_lowercase())
                        .map_err(|e| e.to_string())
                })
                .unwrap_or_else(|e| {
                    eprintln!(
                        "shellfirm: warning: ignoring invalid SHELLFIRM_LOG value '{v}': {e}"
                    );
                    tracing_subscriber::EnvFilter::new("error")
                }),
            _ => tracing_subscriber::EnvFilter::new("error"),
        },
        |level| tracing_subscriber::EnvFilter::new(level.to_lowercase()),
    );
    let ansi = console::colors_enabled_stderr();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(ansi)
        .try_init();
}

/// Decide once whether stdout / stderr get colour, with one rule for the
/// whole tool (CLI output, the challenge banner, logs): see
/// [`config::color_preference`]. An empty `NO_COLOR=` keeps colour, and
/// monochrome terminals (`TERM=vt100`, `xterm-mono`, `dumb`) get none.
fn init_colors() {
    let pref = config::color_preference(|k| std::env::var(k).ok());
    console::set_colors_enabled(pref.unwrap_or_else(|| std::io::stdout().is_terminal()));
    console::set_colors_enabled_stderr(pref.unwrap_or_else(|| std::io::stderr().is_terminal()));
}

/// The exit code for a failed write to stdout: `0` for a closed pipe
/// (`shellfirm status | head -1`), otherwise `EX_IOERR` (74) with a message.
fn write_failure_exit(e: &std::io::Error) -> i32 {
    if e.kind() == std::io::ErrorKind::BrokenPipe {
        exitcode::OK
    } else {
        let _ = writeln!(std::io::stderr(), "shellfirm: error: writing output: {e}");
        exitcode::IOERR
    }
}

/// Write `text` (plus a newline) to stdout and turn a write failure into a
/// clean exit instead of a panic: a closed pipe exits 0 quietly, any other
/// error (a full disk) exits 74 with a message.
#[must_use]
pub fn print_stdout(text: &str) -> CmdExit {
    let mut out = std::io::stdout().lock();
    let res = out
        .write_all(text.as_bytes())
        .and_then(|()| out.write_all(b"\n"))
        .and_then(|()| out.flush());
    CmdExit {
        code: res.map_or_else(|e| write_failure_exit(&e), |()| exitcode::OK),
        message: None,
    }
}

/// Safety net for `println!` calls that hit a closed or full stdout
/// (`failed printing to stdout: Broken pipe`): exit 0 on a broken pipe and
/// 74 on any other write error, never a panic with exit 101.
fn install_output_panic_hook() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let msg = info
            .payload()
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| info.payload().downcast_ref::<&str>().copied())
            .unwrap_or("");
        if msg.starts_with("failed printing to std") || msg.starts_with("failed to write") {
            if msg.contains("Broken pipe") || msg.contains("os error 32") {
                exit(exitcode::OK);
            }
            let detail = msg.split_once(": ").map_or(msg, |(_, d)| d);
            let _ = writeln!(
                std::io::stderr(),
                "shellfirm: error: writing output: {detail}"
            );
            exit(exitcode::IOERR);
        }
        default(info);
    }));
}

#[allow(clippy::too_many_lines)]
fn main() {
    install_output_panic_hook();
    init_colors();
    let mut app = cmd::default::command()
        .subcommand(cmd::config::command())
        .subcommand(cmd::init::command())
        .subcommand(cmd::connect_cmd::command())
        .subcommand(cmd::audit_cmd::command())
        .subcommand(cmd::policy_cmd::command())
        .subcommand(cmd::check_cmd::command())
        .subcommand(cmd::completions_cmd::command())
        .subcommand(cmd::status_cmd::command())
        .subcommand(cmd::doctor_cmd::command());

    #[cfg(feature = "mcp")]
    {
        app = app.subcommand(cmd::mcp_cmd::command());
    }

    #[cfg(feature = "wrap")]
    {
        app = app.subcommand(cmd::wrap_cmd::command());
    }

    // Used by the shell hooks, not typed by people: listed last.
    app = app.subcommand(cmd::command::command());

    let matches = match app.clone().try_get_matches() {
        Ok(m) => m,
        // `--help` / `--version` are output like any other: a full disk is
        // EX_IOERR (74), a closed pipe exits 0 quietly.
        Err(e) => {
            let code = e.exit_code();
            let printed = e.print().and_then(|()| std::io::stdout().flush());
            match printed {
                Err(io) if code == 0 => exit(write_failure_exit(&io)),
                _ => exit(code),
            }
        }
    };

    // Handle completions command early (doesn't need config)
    if let Some(("completions", sub_matches)) = matches.subcommand() {
        shellfirm_exit(Ok(cmd::completions_cmd::run(sub_matches, &mut app)));
    }

    init_logging(&matches);

    // Handle init command early (doesn't need config)
    if let Some(("init", sub_matches)) = matches.subcommand() {
        shellfirm_exit(cmd::init::run(sub_matches));
    }

    // Handle doctor command early (it loads the config itself)
    if let Some(("doctor", sub_matches)) = matches.subcommand() {
        shellfirm_exit(Ok(cmd::doctor_cmd::run(sub_matches)));
    }

    // Handle connect command early (doesn't need config)
    if let Some(("connect", sub_matches)) = matches.subcommand() {
        shellfirm_exit(cmd::connect_cmd::run(sub_matches));
    }

    // `status`, `config` and `audit` take `--config-dir DIR` like `check`:
    // DIR must exist (a typo would silently show or change another setup).
    let explicit_dir = match matches.subcommand() {
        Some(("status" | "config" | "audit", m)) => m.get_one::<String>("config-dir").cloned(),
        _ => None,
    };
    if let Some(dir) = explicit_dir.as_deref() {
        if !std::path::Path::new(dir).is_dir() {
            eprintln!("shellfirm: error: --config-dir {dir}: no such directory");
            exit(2);
        }
    }

    // load configuration
    let config = match Config::new(explicit_dir.as_deref()) {
        Ok(config) => config,
        // An explicit --config-dir wins over SHELLFIRM_CONFIG_DIR, and the
        // agent hooks and the MCP server never stop without a decision
        // because of a stale variable: they fall back to the default
        // location (like a missing --config-dir in hook mode).
        Err(err) if env_config_dir_is_lenient(&matches) => {
            let pinned = matches
                .subcommand()
                .and_then(|(_, m)| m.try_get_one::<String>("config-dir").ok().flatten())
                .is_some();
            if !pinned {
                // The shell hook shows this once per session (and again
                // when the variable changes); say how to get rid of it.
                let fix = if matches!(matches.subcommand(), Some(("pre-command", _))) {
                    format!(
                        " (fix: `unset {}`, or create that directory)",
                        config::CONFIG_DIR_ENV
                    )
                } else {
                    String::new()
                };
                eprintln!(
                    "shellfirm: warning: {err}; using the default configuration directory{fix}"
                );
            }
            match Config::default_location() {
                Ok(config) => config,
                Err(err) => {
                    eprintln!(
                        "shellfirm: error: could not determine the configuration directory: {err}"
                    );
                    exit(1)
                }
            }
        }
        Err(err) => {
            eprintln!("shellfirm: error: could not determine the configuration directory: {err}");
            // A bad SHELLFIRM_CONFIG_DIR is a usage error, like a bad
            // --config-dir.
            let from_env =
                config::config_dir_from_env(std::env::var(config::CONFIG_DIR_ENV).ok().as_deref())
                    .is_err();
            exit(if from_env { 2 } else { 1 })
        }
    };

    // Handle policy command early (doesn't need settings)
    if let Some(("policy", sub_matches)) = matches.subcommand() {
        shellfirm_exit(cmd::policy_cmd::run(sub_matches, &config));
    }

    // Handle config commands early — they read and validate the settings
    // file themselves (and refuse to overwrite an invalid one).
    if let Some(("config", subcommand_matches)) = matches.subcommand() {
        shellfirm_exit(cmd::config::run(subcommand_matches, &config));
    }

    // The audit log does not depend on settings.
    if let Some(("audit", subcommand_matches)) = matches.subcommand() {
        shellfirm_exit(cmd::audit_cmd::run(subcommand_matches, &config));
    }

    let is_status = matches!(matches.subcommand(), Some(("status", _)));
    // `check --config-dir DIR` (and the hook modes, which pick their own
    // directory) report the problems of the directory they really use;
    // warnings about the default location would only confuse.
    let own_config_dir = matches!(
        matches.subcommand(),
        Some(("check", m)) if m.get_one::<String>("config-dir").is_some()
    );
    // `check --strict` prints each problem once, as a `strict:` line.
    let strict_check = matches!(
        matches.subcommand(),
        Some(("check", m)) if m.get_flag("strict")
    );
    let quiet_settings = is_status || own_config_dir || strict_check;
    if strict_check {
        policy::suppress_policy_warnings();
    }

    // Settings: never lock the shell. An invalid file produces a warning and
    // safe in-memory defaults for the invalid values; it is never rewritten.
    let (mut settings, settings_error) = config.load_settings_lenient();
    if let Some(err) = &settings_error {
        if !quiet_settings {
            eprintln!(
                "shellfirm: warning: {err}\nshellfirm: using built-in defaults for the invalid \
                 values (the file was not modified). Fix it with `shellfirm config edit`."
            );
        }
    }
    // The interactive shell hook gets a transient "checking impact…" line
    // while a slow blast radius is computed. The time budget itself comes
    // from the settings each command really uses (see `command_scope`).
    if let Some(("pre-command", m)) = matches.subcommand() {
        shellfirm::blast_radius::set_progress_notice(!m.get_flag("test"));
    }
    let mut settings_warnings = config.settings_warnings();
    for id in settings.ignore_deny_conflicts() {
        settings_warnings.push(format!(
            "`{id}` is in both ignores_patterns_ids and deny_patterns_ids; the deny wins \
             (remove one with `shellfirm config ignore --remove {id}` or `shellfirm config deny --remove {id}`)"
        ));
    }

    // Load custom checks: one broken file is skipped with a warning, the
    // others still load.
    let custom = config::load_custom_checks_report(&config.custom_checks_dir());

    // Project policy: discovered once here so it can be enforced against the
    // user's personal filters and its `context` merged in.
    let env = RealEnvironment;
    let cwd = env.current_dir().unwrap_or_default();
    // `pre-command`: a command aimed at another repository (`cd repo && …`,
    // `rm -rf repo/src`, `git -C repo …`) gets that repository's policy too,
    // with the same target walk as the agent hooks, so a personal ignore
    // never removes a check one of those policies enforces.
    let pre_command = match matches.subcommand() {
        Some(("pre-command", m)) => m.get_one::<String>("command").cloned(),
        _ => None,
    };
    let extra_policy_dirs = pre_command.as_deref().map_or_else(Vec::new, |c| {
        shellfirm::agent::command_target_dirs(c, &cwd, env.home_dir().as_deref())
    });
    let discovery = pre_command.as_deref().map_or_else(
        || policy::discover_all(&env, &cwd),
        |c| {
            policy::with_extra_target_dirs(&extra_policy_dirs, || {
                policy::discover_for(&env, &cwd, &shellfirm::context::command_target_dirs(c))
            })
        },
    );

    // Unknown ids / groups in a hand-edited settings file (the setters
    // reject them; a typo here would silently protect nobody).
    if config.setting_file_path.exists() {
        let policy_ids: Vec<String> = discovery
            .policy
            .as_ref()
            .map(|p| p.checks.iter().map(|c| c.id.clone()).collect())
            .unwrap_or_default();
        settings_warnings.extend(config::unknown_reference_warnings(
            &settings,
            &custom.checks,
            &policy_ids,
        ));
    }
    if !quiet_settings {
        for w in &settings_warnings {
            eprintln!(
                "shellfirm: warning: {}: {w}",
                config.setting_file_path.display()
            );
        }
    }
    if !quiet_settings {
        for w in &custom.warnings {
            eprintln!("shellfirm: warning: custom checks: {w}");
        }
    }
    if !custom.checks.is_empty() {
        tracing::info!("Loaded {} custom check(s)", custom.checks.len());
    }

    // Custom-check groups that are neither enabled nor disabled are active
    // (in memory only — the settings file is never rewritten here).
    let added = settings.migrate_custom_groups_into_enabled_groups(&custom.checks);
    if !added.is_empty() {
        tracing::debug!(
            "custom-check groups treated as enabled: {}",
            added.join(", ")
        );
    }
    // Honour per-check `challenge:` in custom checks (as a floor).
    settings.apply_custom_check_challenges(&custom.explicit_challenges);

    if !is_status && !strict_check {
        policy::warn_policy_problems(&discovery);
    }
    if let Some(p) = &discovery.policy {
        for note in policy::apply_to_settings(&mut settings, p) {
            tracing::warn!("{note}");
        }
    }

    let checks =
        match settings.get_active_checks_enforced(&custom.checks, discovery.policy.as_ref()) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("shellfirm: error: could not load checks: {e}");
                exit(1)
            }
        };

    let report = LoadReport {
        settings_error,
        settings_warnings,
        custom_warnings: custom.warnings,
        custom_count: custom.checks.len(),
        policy: discovery,
    };

    let res = matches.subcommand().map_or_else(
        || Err(Error::Other("command not found".into())),
        |tup| match tup {
            ("pre-command", subcommand_matches) => {
                // One time budget for everything this command needs.
                let _scope = settings.command_scope();
                policy::with_extra_target_dirs(&extra_policy_dirs, || {
                    cmd::command::run(subcommand_matches, &settings, &checks, &config)
                })
            }
            ("check", subcommand_matches) => {
                cmd::check_cmd::run(subcommand_matches, &settings, &checks)
            }
            ("status", subcommand_matches) => Ok(cmd::status_cmd::run(
                subcommand_matches,
                &config,
                &settings,
                &checks,
                &report,
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

/// `true` when an invalid `SHELLFIRM_CONFIG_DIR` must not stop the command:
/// `check` / `mcp` with an explicit `--config-dir` (the flag wins), the
/// agent hook modes and the MCP server (they answer with defaults), and the
/// shell hooks' `pre-command` (a stale variable must never lock the shell,
/// not even the `unset` that fixes it).
fn env_config_dir_is_lenient(matches: &clap::ArgMatches) -> bool {
    match matches.subcommand() {
        Some(("pre-command", _)) => true,
        Some(("check", m)) => {
            m.get_one::<String>("config-dir").is_some()
                || m.get_one::<String>("hook").is_some()
                || matches!(
                    m.get_one::<String>("format").map(String::as_str),
                    Some("claude-hook" | "cursor-hook")
                )
        }
        #[cfg(feature = "mcp")]
        Some(("mcp", _)) => true,
        _ => false,
    }
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
                let message = config::ascii_fallback(&message);
                eprintln!("{}", style.for_stderr().apply_to(message));
            }
            cmd.code
        }
        Err(e) => {
            tracing::debug!("{e:?}");
            eprintln!(
                "{}",
                Style::new()
                    .for_stderr()
                    .red()
                    .apply_to(config::ascii_fallback(&format!("shellfirm: error: {e}")))
            );
            match e {
                Error::Config(_) => exitcode::CONFIG,
                Error::Usage(_) => config::EXIT_USAGE,
                _ => DEFAULT_ERR_EXIT_CODE,
            }
        }
    };
    exit(exit_with);
}
