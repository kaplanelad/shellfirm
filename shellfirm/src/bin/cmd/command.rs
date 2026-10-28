use std::sync::OnceLock;

use clap::{Arg, ArgAction, ArgMatches, Command};
use regex::Regex;
use shellfirm::error::Result;
use shellfirm::{
    audit,
    checks::{self, Check},
    env::{Environment, RealEnvironment},
    prompt::{ChallengeResult, DisplayContext, Prompter},
    Settings,
};

fn regex_string_command_replace() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"'[^']*'|"[^"]*""#).unwrap())
}

#[cfg(not(unix))]
use shellfirm::prompt::TerminalPrompter;

/// Exit code: the command may run (no risky match, or the challenge passed).
pub const EXIT_ALLOWED: i32 = exitcode::OK;
/// Exit code: the challenge was passed, when the caller asked to be told
/// (`SHELLFIRM_SIGNAL_PROMPTED=1`, set by the bash hook so it keeps the
/// reprinted line, the challenge and the approved line on screen).
/// Without that variable a passed challenge exits [`EXIT_ALLOWED`].
pub const EXIT_ALLOWED_AFTER_PROMPT: i32 = 3;
/// Environment variable asking for [`EXIT_ALLOWED_AFTER_PROMPT`].
pub const SIGNAL_PROMPTED_ENV: &str = "SHELLFIRM_SIGNAL_PROMPTED";
/// Environment variable (`1`) set by a hook that prints the "approved,
/// running" line itself, later (zsh: from preexec, after a transient prompt
/// has redrawn the line): a passed challenge then prints nothing and exits
/// [`EXIT_ALLOWED_AFTER_PROMPT`] when the line is wanted (the
/// `approved_notice` setting), [`EXIT_ALLOWED`] when it is not. The hook
/// prints it with `pre-command --approved-notice`.
pub const DEFER_APPROVED_ENV: &str = "SHELLFIRM_DEFER_APPROVED";
/// Environment variable (`1`) set by the zsh and bash hooks when the shell
/// does not treat `#` as a comment in interactive lines (zsh without
/// `interactivecomments`, its default; bash without `interactive_comments`):
/// `rm -rf a # b` is then checked with `#` and `b` as arguments.
pub const NO_COMMENTS_ENV: &str = "SHELLFIRM_NO_COMMENTS";
/// Exit code: the challenge was cancelled or failed (`EX_DATAERR`, 65).
/// With `--test`: the command would require a challenge.
pub const EXIT_CHALLENGE_NOT_PASSED: i32 = exitcode::DATAERR;
/// Exit code: a challenge was required but there is no terminal to ask on
/// (`EX_IOERR`, 74). The command is blocked (fail closed).
pub const EXIT_NO_TERMINAL: i32 = exitcode::IOERR;
/// Exit code: the command is denied by the deny list or project policy
/// (`EX_NOPERM`, 77). Returned immediately; shellfirm never waits for ^C.
/// With `--test`: the command would be denied.
pub const EXIT_DENIED: i32 = exitcode::NOPERM;

const EXIT_CODES_HELP: &str = "\
Exit codes:
  0   allowed (no risky pattern, or the challenge was passed)
  3   allowed after a passed challenge (only with SHELLFIRM_SIGNAL_PROMPTED=1
      or SHELLFIRM_DEFER_APPROVED=1)
  65  challenge cancelled/failed      (--test: would require a challenge)
  74  no terminal to prompt on; blocked (fail closed)
  77  denied by deny list / policy    (--test: would be denied)
Shell hooks treat any other non-zero exit code as \"do not run the command\".";

pub fn command() -> Command {
    Command::new("pre-command")
        .about("Check if a command matches a risky pattern (used by shell hooks)")
        .after_help(EXIT_CODES_HELP)
        .arg(
            Arg::new("command")
                .short('c')
                .long("command")
                .help("The command to check")
                .allow_hyphen_values(true)
                .required(true),
        )
        .arg(
            Arg::new("test")
                .short('t')
                .long("test")
                .help(
                    "Dry run: report the decision (matches, deny status, context, effective \
                     challenge) on stdout without prompting, and exit with the code a real \
                     run would use if nobody confirmed (0 = would run)",
                )
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("no-context")
                .long("no-context")
                .help(
                    "Do not run any external command (git, kubectl, docker, du, find) to \
                     detect context or compute the blast radius; context that can be read \
                     from files (git HEAD, kubeconfig) is still used. Same as SHELLFIRM_NO_CONTEXT=1",
                )
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("line")
                .long("line")
                .help(
                    "The line as the user typed it (aliases and re-runs resolved), shown in the \
                     banner and stored in the audit log; --command is what is checked (with \
                     the bodies of the functions the line calls)",
                )
                .allow_hyphen_values(true)
                .hide(true),
        )
        .arg(
            Arg::new("approved-notice")
                .long("approved-notice")
                .help(
                    "Only print the \"approved, running\" line for --line (else --command) on the \
                     terminal, when the approved_notice setting is on (used by the hooks)",
                )
                .hide(true)
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("direct-tty")
                .long("direct-tty")
                .help("Read prompts directly from /dev/tty (always the case on unix)")
                .hide(true)
                .action(ArgAction::SetTrue),
        )
}

pub fn run(
    arg_matches: &ArgMatches,
    settings: &Settings,
    checks: &[Check],
    config: &shellfirm::Config,
) -> Result<shellfirm::CmdExit> {
    let real_env = RealEnvironment;
    let no_context_env = shellfirm::env::NoContextEnvironment::new(&real_env);
    let env: &dyn Environment =
        if arg_matches.get_flag("no-context") || shellfirm::env::no_context_requested(&real_env) {
            &no_context_env
        } else {
            &real_env
        };
    let command = arg_matches
        .get_one::<String>("command")
        .map_or("", String::as_str);
    let dryrun = arg_matches.get_flag("test");
    // What the user typed, when the hook checks more than that (function
    // bodies, markers): the banner and the audit log show the typed line.
    let line = arg_matches
        .get_one::<String>("line")
        .map(String::as_str)
        .filter(|l| !l.trim().is_empty());

    if arg_matches.get_flag("approved-notice") {
        if settings.approved_notice {
            shellfirm::prompt::announce_approved(line.unwrap_or(command));
        }
        return Ok(shellfirm::CmdExit {
            code: EXIT_ALLOWED,
            message: None,
        });
    }
    if real_env.var(NO_COMMENTS_ENV).as_deref() == Some("1") {
        shellfirm::parser::set_hash_comments(false);
    }
    // A dumb terminal (Emacs `M-x shell`) cannot erase a line: no transient
    // "checking impact…" line there.
    if real_env.var("TERM").as_deref() == Some("dumb") {
        shellfirm::blast_radius::set_progress_notice(false);
    }

    // On unix every hook prompts through /dev/tty directly. crossterm's
    // raw-mode event system hangs inside zsh zle widgets on macOS
    // (https://github.com/kaplanelad/shellfirm/issues/160), and a single
    // prompter gives the same keys (Esc / Ctrl-C to cancel) in every shell.
    #[cfg(unix)]
    {
        let _ = arg_matches.get_flag("direct-tty");
        let prompter = shellfirm::prompt::DirectTtyPrompter;
        execute(
            command, line, settings, checks, dryrun, env, &prompter, config,
        )
    }

    #[cfg(not(unix))]
    {
        let prompter = TerminalPrompter;
        execute(
            command, line, settings, checks, dryrun, env, &prompter, config,
        )
    }
}

/// The `shellfirm:input_too_large` match of the shell hook (agents get the
/// same rule from [`shellfirm::agent`]).
fn input_too_large_check(len: usize) -> Option<Check> {
    Some(Check {
        id: shellfirm::agent::INPUT_TOO_LARGE_RULE.to_string(),
        test: checks::CheckRegex::new(r"\A").ok()?,
        description: format!(
            "The command is {len} bytes, more than the {} MiB shellfirm analyses completely; \
             review it before it runs.",
            shellfirm::agent::MAX_ANALYZED_COMMAND_BYTES / 1024 / 1024
        ),
        from: "shellfirm".to_string(),
        challenge: shellfirm::Challenge::default(),
        filters: Vec::new(),
        alternative: None,
        alternative_info: None,
        severity: checks::Severity::Medium,
    })
}

fn audit_event(
    command: &str,
    matches: &[Check],
    challenge_type: String,
    outcome: audit::AuditOutcome,
    context_labels: Vec<String>,
    severity: checks::Severity,
    blast: Option<(String, String)>,
) -> audit::AuditEvent {
    let (blast_radius_scope, blast_radius_detail) = blast.unzip();
    audit::AuditEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        timestamp: audit::now_timestamp(),
        command: command.to_string(),
        matched_ids: matches.iter().map(|c| c.id.clone()).collect(),
        challenge_type,
        outcome,
        context_labels,
        severity,
        agent_name: None,
        agent_session_id: None,
        blast_radius_scope,
        blast_radius_detail,
        attempts: None,
    }
}

fn write_audit(
    settings: &Settings,
    config: &shellfirm::Config,
    event: &audit::AuditEvent,
    extra: &audit::AuditExtra,
) {
    if !settings.audit_enabled {
        return;
    }
    if let Err(e) = audit::log_event_with(&config.audit_log_path(), event, extra) {
        tracing::warn!("Failed to write audit log: {e}");
    }
}

/// Human-readable dry-run report for `pre-command --test`.
fn dry_run_report(
    command: &str,
    pipeline: &checks::PipelineResult,
    display: Option<&DisplayContext>,
    ignored: &[Check],
) -> (String, i32) {
    use std::fmt::Write as _;
    let mut out = String::new();
    // Escaped: bidi / zero-width characters would hide what is checked.
    let _ = writeln!(
        out,
        "command: {}",
        shellfirm::context::escape_invisible(command)
    );

    let (decision, code) = match display {
        None => ("allow", EXIT_ALLOWED),
        Some(d) if d.is_denied => ("deny", EXIT_DENIED),
        Some(_) => ("challenge", EXIT_CHALLENGE_NOT_PASSED),
    };
    let _ = writeln!(out, "decision: {decision}");

    // "none" only when nothing matched at all; a match that was ignored,
    // below min_severity or dropped for a missing path is explained below.
    let nothing_matched = ignored.is_empty()
        && pipeline.skipped_matches.is_empty()
        && pipeline.skipped_missing_paths.is_empty();
    if pipeline.active_matches.is_empty() && nothing_matched {
        let _ = writeln!(out, "matched: none");
    } else if pipeline.active_matches.is_empty() {
        let _ = writeln!(out, "matched: none active");
    } else {
        let _ = writeln!(out, "matched:");
        for c in &pipeline.active_matches {
            let _ = writeln!(out, "  - {} [{}] {}", c.id, c.severity, c.description);
        }
    }
    for c in ignored {
        let _ = writeln!(
            out,
            "ignored: {} [{}] matched (ignored by your settings; `shellfirm config ignore --remove {}` to check it again)",
            c.id, c.severity, c.id
        );
    }
    if !pipeline.skipped_matches.is_empty() {
        let _ = writeln!(out, "skipped (below min_severity):");
        for c in &pipeline.skipped_matches {
            let _ = writeln!(out, "  - {} [{}]", c.id, c.severity);
        }
    }
    for (id, path) in &pipeline.skipped_missing_paths {
        let _ = writeln!(
            out,
            "skipped (path does not exist): {id}: {}",
            shellfirm::context::escape_invisible(path)
        );
    }

    if let Some(d) = display {
        if d.is_denied {
            let _ = writeln!(out, "denied: yes ({})", d.deny_reasons.join("; "));
        } else {
            let _ = writeln!(out, "denied: no");
            let challenge = if d.effective_challenge.is_stricter_than(d.base_challenge) {
                format!(
                    "{} (escalated from {}: {})",
                    d.effective_challenge,
                    d.base_challenge,
                    d.escalation_reasons.join(", ")
                )
            } else {
                format!("{}", d.effective_challenge)
            };
            let _ = writeln!(out, "challenge: {challenge}");
        }
        for note in &d.notes {
            let _ = writeln!(out, "note: {note}");
        }
        let risk = pipeline.relevant_context.risk_level;
        if d.context_labels.is_empty() && risk == shellfirm::context::RiskLevel::Normal {
            let _ = writeln!(out, "context: normal (no risk signals)");
        } else {
            let labels = if d.context_labels.is_empty() {
                "no labels".to_string()
            } else {
                d.context_labels.join(", ")
            };
            let _ = writeln!(out, "context: risk={risk:?}; {labels}");
        }
        if let Some(ref br) = d.blast_radius_label {
            let _ = writeln!(out, "blast radius: {br}");
        }
    }
    (out, code)
}

#[allow(clippy::too_many_lines)]
#[allow(clippy::too_many_arguments)]
fn execute(
    command: &str,
    line: Option<&str>,
    settings: &Settings,
    checks: &[Check],
    dryrun: bool,
    env: &dyn Environment,
    prompter: &dyn Prompter,
    config: &shellfirm::Config,
) -> Result<shellfirm::CmdExit> {
    let resolved = settings.resolved_for(shellfirm::Mode::Shell);
    // Ctrl-C while the impact is measured ("checking impact…") cancels the
    // command like a cancelled challenge: the measurement stops, the
    // transient line is erased, and the hook keeps the line for editing.
    let interrupt = (!dryrun && std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .then(interrupt::Guard::install);
    let mut pipeline = checks::analyze_command(
        command,
        settings,
        &resolved,
        checks,
        env,
        regex_string_command_replace(),
    )?;
    let interrupted = interrupt.is_some_and(interrupt::Guard::finish);
    // A command too large to analyze completely is never run unasked.
    if command.len() > shellfirm::agent::MAX_ANALYZED_COMMAND_BYTES {
        if let Some(c) = input_too_large_check(command.len()) {
            pipeline.max_severity = pipeline.max_severity.max(c.severity);
            pipeline.active_matches.push(c);
        }
    }

    tracing::debug!(
        "matches found: active={}, skipped={}",
        pipeline.active_matches.len(),
        pipeline.skipped_matches.len()
    );

    let active_refs: Vec<&checks::Check> = pipeline.active_matches.iter().collect();
    let display = if active_refs.is_empty() {
        None
    } else {
        let mut d = checks::build_challenge_display(
            settings,
            &resolved,
            &active_refs,
            &pipeline.relevant_context,
            &pipeline.merged_policy,
            &pipeline.blast_radii,
        );
        d.command = Some(line.unwrap_or(command).to_string());
        // Alternatives with the user's own arguments filled in.
        d.alternatives.clone_from(&pipeline.alternatives);
        Some(d)
    };

    if dryrun {
        let active: std::collections::HashSet<&str> = pipeline
            .active_matches
            .iter()
            .map(|c| c.id.as_str())
            .collect();
        let ignored: Vec<Check> = checks::ignored_matches(settings, command, env)
            .into_iter()
            .filter(|c| !active.contains(c.id.as_str()))
            .collect();
        let (report, code) = dry_run_report(command, &pipeline, display.as_ref(), &ignored);
        // Catalogue descriptions (em dashes): ASCII when the terminal is not
        // UTF-8, like every other report.
        print!("{}", shellfirm::config::ascii_fallback(&report));
        return Ok(shellfirm::CmdExit {
            code,
            message: None,
        });
    }

    // Audit log skipped checks
    if !pipeline.skipped_matches.is_empty() {
        let severity = pipeline
            .skipped_matches
            .iter()
            .map(|c| c.severity)
            .max()
            .unwrap_or_default();
        let event = audit_event(
            line.unwrap_or(&pipeline.stripped_command),
            &pipeline.skipped_matches,
            format!("{}", resolved.challenge),
            audit::AuditOutcome::Skipped,
            pipeline.relevant_context.labels.clone(),
            severity,
            None,
        );
        write_audit(settings, config, &event, &audit::AuditExtra::default());
    }

    if interrupted {
        eprintln!("\nshellfirm: cancelled, command not run.");
        if let Some(display) = &display {
            let ids: Vec<String> = pipeline
                .active_matches
                .iter()
                .map(|c| c.id.clone())
                .collect();
            let event = audit_event(
                line.unwrap_or(&pipeline.stripped_command),
                &pipeline.active_matches,
                format!("{}", display.effective_challenge),
                audit::AuditOutcome::Cancelled,
                pipeline.relevant_context.labels.clone(),
                pipeline.max_severity,
                None,
            );
            let mut extra = audit::AuditExtra::for_decision(
                &pipeline.merged_policy,
                &settings.deny_patterns_ids,
                &ids,
                display.is_denied,
                Some(format!("{}", display.effective_challenge)),
                display.escalation_reasons.clone(),
            );
            extra.deny_reason = Some(audit::deny_reason::CANCELLED.to_string());
            write_audit(settings, config, &event, &extra);
        }
        return Ok(shellfirm::CmdExit {
            code: EXIT_CHALLENGE_NOT_PASSED,
            message: None,
        });
    }

    // Only run the challenge if there are active (non-skipped) matches
    let Some(display) = display else {
        return Ok(shellfirm::CmdExit {
            code: EXIT_ALLOWED,
            message: None,
        });
    };

    // Blast radius audit fields from the highest-scope entry
    let blast = pipeline
        .blast_radii
        .iter()
        .max_by_key(|(_, br)| br.scope)
        .map(|(_, br)| (format!("{}", br.scope), br.description.clone()));

    let (outcome, challenge_type, code) = if display.is_denied {
        // Deny is absolute: show why and return immediately (never block).
        let _ = prompter.run_challenge(&display);
        (audit::AuditOutcome::Denied, "Deny".to_string(), EXIT_DENIED)
    } else if !prompter.can_prompt() {
        // Fail closed with a clear reason when nobody can answer.
        shellfirm::prompt::display_banner(&display);
        eprintln!("{}", shellfirm::prompt::no_terminal_message(&display));
        (
            audit::AuditOutcome::NoTerminal,
            format!("{}", display.effective_challenge),
            EXIT_NO_TERMINAL,
        )
    } else {
        match prompter.run_challenge(&display) {
            ChallengeResult::Passed => {
                // Say it is running, so a slow command does not look hung
                // (terminal only, `approved_notice`). It names what was
                // typed, not the function definitions checked with it.
                let defer = env.var(DEFER_APPROVED_ENV).as_deref() == Some("1");
                if settings.approved_notice && !defer {
                    prompter.announce_approved(line.unwrap_or(command));
                }
                let code = if env.var(SIGNAL_PROMPTED_ENV).as_deref() == Some("1")
                    || (defer && settings.approved_notice)
                {
                    EXIT_ALLOWED_AFTER_PROMPT
                } else {
                    EXIT_ALLOWED
                };
                (
                    audit::AuditOutcome::Allowed,
                    format!("{}", display.effective_challenge),
                    code,
                )
            }
            ChallengeResult::Denied => (
                audit::AuditOutcome::Cancelled,
                format!("{}", display.effective_challenge),
                EXIT_CHALLENGE_NOT_PASSED,
            ),
        }
    };

    // One audit row per prompt, written once the outcome is known.
    let event = audit_event(
        line.unwrap_or(&pipeline.stripped_command),
        &pipeline.active_matches,
        challenge_type,
        outcome.clone(),
        pipeline.relevant_context.labels.clone(),
        pipeline.max_severity,
        blast,
    );
    // Policy attribution, effective challenge and escalation reasons.
    let ids: Vec<String> = pipeline
        .active_matches
        .iter()
        .map(|c| c.id.clone())
        .collect();
    let mut extra = audit::AuditExtra::for_decision(
        &pipeline.merged_policy,
        &settings.deny_patterns_ids,
        &ids,
        display.is_denied,
        Some(format!("{}", display.effective_challenge)),
        display.escalation_reasons,
    );
    match outcome {
        audit::AuditOutcome::NoTerminal => {
            extra.deny_reason = Some(audit::deny_reason::NO_TTY.to_string());
        }
        audit::AuditOutcome::Cancelled => {
            // The prompters return `Denied` when the user declines or aborts
            // (Esc, Ctrl-C); a wrong answer re-asks.
            extra.deny_reason = Some(audit::deny_reason::CANCELLED.to_string());
        }
        _ => {}
    }
    write_audit(settings, config, &event, &extra);

    Ok(shellfirm::CmdExit {
        code,
        message: None,
    })
}

/// SIGINT while the command is analyzed (the blast radius can take up to
/// its time budget): remembered instead of ending the process, so the
/// cancel is reported, audited and the transient line erased.
mod interrupt {
    use std::sync::atomic::{AtomicBool, Ordering};

    static HIT: AtomicBool = AtomicBool::new(false);

    #[cfg(unix)]
    extern "C" fn on_sigint(_: libc::c_int) {
        HIT.store(true, Ordering::SeqCst);
        // Stop the running `find` / `du` / `git` now, not at the end of
        // the budget (an atomic store: async-signal-safe).
        shellfirm::env::request_cancel();
    }

    /// Restores the previous SIGINT disposition when finished or dropped.
    pub struct Guard {
        #[cfg(unix)]
        previous: Option<libc::sighandler_t>,
    }

    impl Guard {
        /// Catch SIGINT from now on (only when it is not ignored: a
        /// background job keeps ignoring it).
        #[must_use]
        pub fn install() -> Self {
            HIT.store(false, Ordering::SeqCst);
            shellfirm::env::reset_cancel();
            #[cfg(unix)]
            {
                let handler = on_sigint as extern "C" fn(libc::c_int) as libc::sighandler_t;
                // SAFETY: the handler only stores to an atomic.
                let previous = unsafe { libc::signal(libc::SIGINT, handler) };
                if previous == libc::SIG_IGN {
                    // SAFETY: restoring the disposition that was there.
                    unsafe { libc::signal(libc::SIGINT, libc::SIG_IGN) };
                    return Self { previous: None };
                }
                Self {
                    previous: Some(previous),
                }
            }
            #[cfg(not(unix))]
            Self {}
        }

        /// Stop catching SIGINT; `true` when it arrived.
        #[must_use]
        pub fn finish(self) -> bool {
            drop(self);
            HIT.load(Ordering::SeqCst)
        }
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            // The measurement is over: later subprocesses run normally.
            shellfirm::env::reset_cancel();
            #[cfg(unix)]
            if let Some(previous) = self.previous.take() {
                // SAFETY: restoring the disposition that was there.
                unsafe { libc::signal(libc::SIGINT, previous) };
            }
        }
    }

    #[cfg(all(test, unix))]
    mod tests {
        #[test]
        fn sigint_is_caught_while_installed() {
            let g = super::Guard::install();
            // SAFETY: the handler installed above only stores to an atomic.
            unsafe { libc::raise(libc::SIGINT) };
            // The measurement is told to stop at once.
            assert!(shellfirm::env::cancel_requested());
            assert!(g.finish());
            let g = super::Guard::install();
            assert!(!shellfirm::env::cancel_requested());
            assert!(!g.finish());
        }
    }
}

#[cfg(test)]
mod test_command_cli_command {

    use shellfirm::{config::Challenge, prompt::MockPrompter, Config};
    use tree_fs::Tree;

    use super::*;

    fn initialize_config_folder(temp_dir: &Tree) -> Config {
        let temp_dir = temp_dir.root.join("app");
        Config::new(Some(&temp_dir.display().to_string())).unwrap()
    }

    fn setup() -> (Tree, Config, Settings) {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        let settings = config.get_settings_from_file().unwrap();
        (temp_dir, config, settings)
    }

    fn env_on_branch(branch: &str) -> shellfirm::env::MockEnvironment {
        let mut command_outputs = std::collections::HashMap::new();
        command_outputs.insert("git rev-parse --abbrev-ref HEAD".into(), branch.into());
        shellfirm::env::MockEnvironment {
            cwd: "/tmp/test".into(),
            command_outputs,
            ..Default::default()
        }
    }

    /// A prompter with no terminal, like `docker exec` without `-t` or CI.
    struct NoTtyPrompter {
        calls: std::cell::Cell<usize>,
    }
    impl Prompter for NoTtyPrompter {
        fn run_challenge(&self, _display: &DisplayContext) -> ChallengeResult {
            self.calls.set(self.calls.get() + 1);
            ChallengeResult::Denied
        }
        fn can_prompt(&self) -> bool {
            false
        }
    }

    fn read_audit(config: &Config) -> Vec<serde_json::Value> {
        std::fs::read_to_string(config.audit_log_path())
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn can_run_pre_command() {
        let (_t, config, settings) = setup();
        let mut existing = std::collections::HashSet::new();
        existing.insert(std::path::PathBuf::from("/tmp/test/"));
        existing.insert(std::path::PathBuf::from("/"));
        let env = shellfirm::env::MockEnvironment {
            cwd: "/tmp/test".into(),
            existing_paths: existing,
            ..Default::default()
        };
        let prompter = MockPrompter::passing();

        let checks = settings.get_active_checks().unwrap();
        assert!(!checks.is_empty(), "Active checks must not be empty");

        let (report, code) = {
            let resolved = settings.resolved_for(shellfirm::Mode::Shell);
            let pipeline = checks::analyze_command(
                "rm -rf /",
                &settings,
                &resolved,
                &checks,
                &env,
                regex_string_command_replace(),
            )
            .unwrap();
            let refs: Vec<&Check> = pipeline.active_matches.iter().collect();
            let display = checks::build_challenge_display(
                &settings,
                &resolved,
                &refs,
                &pipeline.relevant_context,
                &pipeline.merged_policy,
                &pipeline.blast_radii,
            );
            dry_run_report("rm -rf /", &pipeline, Some(&display), &[])
        };
        assert!(
            report.contains("fs:recursively_delete"),
            "Expected fs:recursively_delete in dryrun output, got: {report}"
        );
        assert!(report.contains("decision: challenge"), "{report}");
        assert!(
            report.contains("challenge: Yes (escalated from Math: severity CRITICAL)"),
            "{report}"
        );
        assert_eq!(code, EXIT_CHALLENGE_NOT_PASSED);

        let result = execute(
            "rm -rf /", None, &settings, &checks, true, &env, &prompter, &config,
        )
        .unwrap();
        assert_eq!(result.code, EXIT_CHALLENGE_NOT_PASSED);
        assert!(
            prompter.captured_displays.borrow().is_empty(),
            "dry run never prompts"
        );
    }

    #[test]
    fn deep_substitution_nesting_is_bounded_in_pre_command() {
        // 5k / 15k / 50k nested `$(`: answered with the nesting check, no
        // stack overflow, no quadratic time.
        let (_t, config, mut settings) = setup();
        if !settings.enabled_groups.iter().any(|g| g == "shell") {
            settings.enabled_groups.push("shell".into());
        }
        let checks = settings.get_active_checks().unwrap();
        let env = shellfirm::env::MockEnvironment {
            cwd: "/tmp/test".into(),
            ..Default::default()
        };
        for depth in [5_000, 15_000, 50_000] {
            let cmd = format!("echo {}x{}", "$(".repeat(depth), ")".repeat(depth));
            let started = std::time::Instant::now();
            let resolved = settings.resolved_for(shellfirm::Mode::Shell);
            let pipeline = checks::analyze_command(
                &cmd,
                &settings,
                &resolved,
                &checks,
                &env,
                regex_string_command_replace(),
            )
            .unwrap();
            assert!(
                pipeline
                    .active_matches
                    .iter()
                    .any(|c| c.id == "shell:nesting_too_deep"),
                "{depth}"
            );
            let prompter = MockPrompter::passing();
            let result = execute(
                &cmd, None, &settings, &checks, true, &env, &prompter, &config,
            )
            .unwrap();
            assert_eq!(result.code, EXIT_CHALLENGE_NOT_PASSED, "{depth}");
            assert!(
                started.elapsed().as_secs() < 30,
                "{depth}: {:?}",
                started.elapsed()
            );
        }
    }

    #[test]
    fn can_run_pre_command_without_match() {
        let (_t, config, settings) = setup();
        let env = shellfirm::env::MockEnvironment {
            cwd: "/tmp/test".into(),
            ..Default::default()
        };
        let prompter = MockPrompter::passing();

        let result = execute(
            "command",
            None,
            &settings,
            &settings.get_active_checks().unwrap(),
            true,
            &env,
            &prompter,
            &config,
        );
        assert!(result.is_ok());
        let cmd_exit = result.unwrap();
        assert_eq!(cmd_exit.code, exitcode::OK);
    }

    #[test]
    fn dry_run_explains_missing_path_instead_of_matched_none() {
        let (_t, _config, settings) = setup();
        let env = shellfirm::env::MockEnvironment {
            cwd: "/tmp/test".into(),
            ..Default::default()
        };
        let checks = settings.get_active_checks().unwrap();
        let resolved = settings.resolved_for(shellfirm::Mode::Shell);
        let cmd = "rm -rf /tmp/test/missing-dir";
        let pipeline = checks::analyze_command(
            cmd,
            &settings,
            &resolved,
            &checks,
            &env,
            regex_string_command_replace(),
        )
        .unwrap();
        assert!(
            !pipeline.skipped_missing_paths.is_empty(),
            "{:?}",
            pipeline.skipped_missing_paths
        );
        let (report, code) = dry_run_report(cmd, &pipeline, None, &[]);
        assert_eq!(code, EXIT_ALLOWED);
        assert!(!report.contains("matched: none\n"), "{report}");
        assert!(
            report.contains("skipped (path does not exist): ")
                && report.contains("/tmp/test/missing-dir"),
            "{report}"
        );
    }

    #[test]
    fn passed_challenge_exits_3_only_when_the_hook_asks() {
        let (_t, config, settings) = setup();
        let checks = settings.get_active_checks().unwrap();
        let prompter = MockPrompter::passing();
        let mut env = env_on_branch("feature/login");
        let run = |env: &shellfirm::env::MockEnvironment| {
            execute(
                "git push -f origin feature/login",
                None,
                &settings,
                &checks,
                false,
                env,
                &prompter,
                &config,
            )
            .unwrap()
            .code
        };
        assert_eq!(run(&env), EXIT_ALLOWED);
        env.env_vars
            .insert(SIGNAL_PROMPTED_ENV.to_string(), "1".to_string());
        assert_eq!(run(&env), EXIT_ALLOWED_AFTER_PROMPT);
        // No prompt, no signal: a safe command still exits 0.
        let safe = execute(
            "ls", None, &settings, &checks, false, &env, &prompter, &config,
        )
        .unwrap();
        assert_eq!(safe.code, EXIT_ALLOWED);
    }

    #[test]
    fn dry_run_reports_deny_and_escalation() {
        let (_t, config, mut settings) = setup();
        let env = env_on_branch("feature/login");
        let checks = settings.get_active_checks().unwrap();
        let prompter = MockPrompter::passing();

        // Escalated by push target, not current branch.
        let r = execute(
            "git push -f origin main",
            None,
            &settings,
            &checks,
            true,
            &env,
            &prompter,
            &config,
        )
        .unwrap();
        assert_eq!(r.code, EXIT_CHALLENGE_NOT_PASSED);

        settings.deny_patterns_ids.push("git:force_push".into());
        let r = execute(
            "git push -f origin main",
            None,
            &settings,
            &checks,
            true,
            &env,
            &prompter,
            &config,
        )
        .unwrap();
        assert_eq!(r.code, EXIT_DENIED);
    }

    #[test]
    fn denied_command_exits_immediately_with_denied_code_and_logs_denied() {
        let (_t, config, mut settings) = setup();
        settings.audit_enabled = true;
        settings.deny_patterns_ids.push("git:force_push".into());
        let env = env_on_branch("feature/login");
        let checks = settings.get_active_checks().unwrap();
        // No terminal at all: deny must still return immediately.
        let prompter = NoTtyPrompter {
            calls: std::cell::Cell::new(0),
        };
        let r = execute(
            "git push -f origin main",
            None,
            &settings,
            &checks,
            false,
            &env,
            &prompter,
            &config,
        )
        .unwrap();
        assert_eq!(r.code, EXIT_DENIED);
        let rows = read_audit(&config);
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0]["outcome"], "Denied");
        assert_eq!(rows[0]["challenge_type"], "Deny");
    }

    #[test]
    fn no_tty_challenge_fails_closed() {
        let (_t, config, mut settings) = setup();
        settings.audit_enabled = true;
        let env = env_on_branch("feature/login");
        let checks = settings.get_active_checks().unwrap();
        let prompter = NoTtyPrompter {
            calls: std::cell::Cell::new(0),
        };
        let r = execute(
            "git push -f origin feature/login",
            None,
            &settings,
            &checks,
            false,
            &env,
            &prompter,
            &config,
        )
        .unwrap();
        assert_eq!(r.code, EXIT_NO_TERMINAL);
        assert_eq!(prompter.calls.get(), 0, "must not try to prompt");
        let rows = read_audit(&config);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["outcome"], "NoTerminal");
        assert_eq!(rows[0]["deny_reason"], "no_tty");
        assert_eq!(rows[0]["effective_challenge"], "Math");
    }

    #[test]
    fn passed_challenge_logs_one_allowed_row_with_effective_challenge() {
        let (_t, config, mut settings) = setup();
        settings.audit_enabled = true;
        settings.challenge = Challenge::Math;
        let env = env_on_branch("main");
        let checks = settings.get_active_checks().unwrap();
        let prompter = MockPrompter::passing();
        let r = execute(
            "git push -f",
            None,
            &settings,
            &checks,
            false,
            &env,
            &prompter,
            &config,
        )
        .unwrap();
        assert_eq!(r.code, EXIT_ALLOWED);
        let rows = read_audit(&config);
        assert_eq!(rows.len(), 1, "exactly one row per prompt: {rows:?}");
        assert_eq!(rows[0]["outcome"], "Allowed");
        assert_eq!(rows[0]["challenge_type"], "Yes");
        assert_eq!(rows[0]["effective_challenge"], "Yes");
        assert!(
            rows[0]["escalation_reasons"]
                .to_string()
                .contains("protected branch"),
            "{rows:?}"
        );

        let displays = prompter.captured_displays.borrow();
        assert_eq!(displays[0].effective_challenge, Challenge::Yes);
        assert_eq!(displays[0].check_ids, vec!["git:force_push".to_string()]);
        assert!(displays[0]
            .escalation_note
            .as_deref()
            .unwrap()
            .contains("protected branch `main`"));
    }

    #[test]
    fn approved_line_only_after_a_pass_with_the_setting_on() {
        let (_t, config, mut settings) = setup();
        let env = env_on_branch("feature/login");
        let checks = settings.get_active_checks().unwrap();
        let cmd = "git push -f origin feature/login";
        let run = |s: &Settings, response: ChallengeResult| {
            let p = MockPrompter {
                response,
                captured_displays: std::cell::RefCell::new(Vec::new()),
            };
            let _ = MockPrompter::take_announced();
            execute(cmd, None, s, &checks, false, &env, &p, &config).unwrap();
            MockPrompter::take_announced()
        };
        assert_eq!(run(&settings, ChallengeResult::Passed), vec![cmd]);
        assert!(run(&settings, ChallengeResult::Denied).is_empty());
        settings.approved_notice = false;
        assert!(run(&settings, ChallengeResult::Passed).is_empty());
    }

    #[test]
    fn cancelled_challenge_exits_65_and_logs_cancelled() {
        let (_t, config, mut settings) = setup();
        settings.audit_enabled = true;
        let env = env_on_branch("feature/login");
        let checks = settings.get_active_checks().unwrap();
        let prompter = MockPrompter {
            response: ChallengeResult::Denied,
            captured_displays: std::cell::RefCell::new(Vec::new()),
        };
        let r = execute(
            "git push -f origin feature/login",
            None,
            &settings,
            &checks,
            false,
            &env,
            &prompter,
            &config,
        )
        .unwrap();
        assert_eq!(r.code, EXIT_CHALLENGE_NOT_PASSED);
        let rows = read_audit(&config);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["outcome"], "Cancelled");
        assert_eq!(rows[0]["challenge_type"], "Math");
        // A user cancel (Esc / Ctrl-C) is recorded as such.
        assert_eq!(rows[0]["deny_reason"], "cancelled", "{:?}", rows[0]);
    }

    #[test]
    fn typed_line_is_shown_and_audited_instead_of_the_expansion() {
        let (_t, config, mut settings) = setup();
        settings.audit_enabled = true;
        let env = env_on_branch("feature/login");
        let checks = settings.get_active_checks().unwrap();
        let prompter = MockPrompter {
            response: ChallengeResult::Denied,
            captured_displays: std::cell::RefCell::new(Vec::new()),
        };
        let r = execute(
            "pf x\n git push -f origin x",
            Some("pf x"),
            &settings,
            &checks,
            false,
            &env,
            &prompter,
            &config,
        )
        .unwrap();
        assert_eq!(r.code, EXIT_CHALLENGE_NOT_PASSED);
        let shown = prompter.captured_displays.borrow();
        assert_eq!(shown[0].command.as_deref(), Some("pf x"));
        let rows = read_audit(&config);
        assert_eq!(rows[0]["command"], "pf x", "{:?}", rows[0]);
        assert!(rows[0]["matched_ids"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "git:force_push"));
    }

    #[test]
    fn command_flag_accepts_leading_hyphen() {
        let m = command()
            .try_get_matches_from(["pre-command", "-c", "-f origin main"])
            .unwrap();
        assert_eq!(m.get_one::<String>("command").unwrap(), "-f origin main");
    }

    #[test]
    fn regex_strips_matching_double_quotes() {
        let re = regex_string_command_replace();
        let result = re.replace_all(r#"echo "hello world""#, "").to_string();
        assert_eq!(result, "echo ");
    }

    #[test]
    fn regex_strips_matching_single_quotes() {
        let re = regex_string_command_replace();
        let result = re.replace_all("echo 'hello world'", "").to_string();
        assert_eq!(result, "echo ");
    }

    #[test]
    fn regex_does_not_strip_mismatched_quotes() {
        let re = regex_string_command_replace();
        // Mismatched quotes should NOT be treated as a quoted string
        let result = re.replace_all("echo 'hello\"", "").to_string();
        assert_eq!(result, "echo 'hello\"");
    }

    #[test]
    fn regex_handles_multiple_quoted_segments() {
        let re = regex_string_command_replace();
        let result = re
            .replace_all(r#"cmd "arg1" --flag 'arg2'"#, "")
            .to_string();
        assert_eq!(result, "cmd  --flag ");
    }
}
