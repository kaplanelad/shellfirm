//! `shellfirm doctor`: is the current shell really protected?
//!
//! Static checks (binary, rc file, configuration) run in this process. The
//! live state of the shell hook (does Enter go through shellfirm, which
//! widgets/bindings are wrapped, known plugins) can only be seen from inside
//! the shell: `doctor` starts a fresh interactive shell that runs the
//! hook's probe function (`__shellfirm_doctor_probe`, the same name in
//! bash, zsh and fish). To check the shell you are typing in
//! (including bindings changed after startup) pipe the probe in:
//! `__shellfirm_doctor_probe | shellfirm doctor --stdin`.
//!
//! Whether the shell `doctor` was started from has loaded the hook at all is
//! told by `SHELLFIRM_HOOK_PID`, which every hook exports with its own pid.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command as Process, Stdio};
use std::time::{Duration, Instant};

use clap::{crate_version, Arg, ArgAction, ArgMatches, Command};
use serde_json::json;
use shellfirm::config::ascii_fallback;
use shellfirm::Config;

use super::init::{self, Shell, ShellSource, HOOK_VERSION};

/// How long a probe shell may take to start (rc files can be slow).
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);

/// Version of the `--format json` output. Bumped when a field changes
/// meaning or is removed (new fields may be added without a bump).
const SCHEMA_VERSION: u32 = 1;

/// Exported by every hook with the pid of the shell that loaded it.
const HOOK_PID_ENV: &str = "SHELLFIRM_HOOK_PID";
/// Set by the hook to a new value every time it loads: after `exec`, a value
/// other than the one the shell started with means this shell loaded it.
const HOOK_LOAD_ENV: &str = "SHELLFIRM_HOOK_LOAD";

/// Exit code when a check failed (commands may run unchecked).
const EXIT_FAILED: i32 = 1;

pub fn command() -> Command {
    Command::new("doctor")
        .about("Check that the current shell really routes commands through shellfirm")
        .long_about(
            "Check the shell integration: which shell you use, whether this shell session \
             has loaded the hook, which shellfirm binary the hook runs, whether the rc file \
             loads the hook (once), whether Enter (and the other keys that run a command) go \
             through shellfirm in a new interactive shell, known plugin conflicts, and \
             whether the configuration is valid.\n\n\
             The live check starts a new interactive shell, so it sees what your rc files \
             set up, not key bindings you changed by hand in this session. To check this \
             session, pipe the hook's probe in (bash, zsh and fish):\n\
             \x20 __shellfirm_doctor_probe | shellfirm doctor --stdin\n\n\
             Exit codes:\n\
             \x20 0   nothing is wrong (warnings may still be listed)\n\
             \x20 1   a check failed: commands typed in this shell may run unchecked\n\
             \x20 64  usage error (for example, the shell could not be detected)\n\n\
             `--format json` prints one object with `schema_version`, `ok`, \
             `session_hooked`, `enter_routes_through_shellfirm` and the findings.",
        )
        .arg(
            Arg::new("shell")
                .long("shell")
                .help("Shell to check (default: the shell that started shellfirm, then $SHELL)")
                .value_parser(clap::builder::PossibleValuesParser::new([
                    "bash", "zsh", "fish", "nushell", "nu", "powershell", "pwsh", "elvish",
                    "xonsh", "oils", "osh", "ysh",
                ]))
                .ignore_case(true),
        )
        .arg(
            Arg::new("stdin")
                .long("stdin")
                .help("Read the probe output of the live shell from stdin instead of starting a new shell")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("format")
                .long("format")
                .value_parser(["text", "json"])
                .default_value("text")
                .help("Output format"),
        )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde_derive::Serialize)]
#[serde(rename_all = "lowercase")]
enum Status {
    Ok,
    Info,
    Warn,
    Fail,
}

impl Status {
    const fn symbol(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Info => "--",
            Self::Warn => "!!",
            Self::Fail => "XX",
        }
    }
}

#[derive(Debug, Clone, serde_derive::Serialize)]
struct Finding {
    id: &'static str,
    status: Status,
    message: String,
}

#[derive(Default)]
struct Report {
    findings: Vec<Finding>,
}

impl Report {
    fn add(&mut self, id: &'static str, status: Status, message: impl Into<String>) {
        self.findings.push(Finding {
            id,
            status,
            message: message.into(),
        });
    }

    fn failed(&self) -> bool {
        self.findings.iter().any(|f| f.status == Status::Fail)
    }
}

/// Parse `key=value` lines printed by a hook's probe function.
fn parse_probe(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .filter(|(k, _)| !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
        .collect()
}

/// The probe command for shells that have one.
const fn probe_invocation(shell: Shell) -> Option<(&'static str, &'static [&'static str])> {
    match shell {
        Shell::Bash => Some(("bash", &["-i", "-c", "__shellfirm_doctor_probe"])),
        // Hooks before version 7 named the zsh probe `_shellfirm_doctor_probe`.
        Shell::Zsh => Some((
            "zsh",
            &[
                "-i",
                "-c",
                "if (( $+functions[__shellfirm_doctor_probe] )); then __shellfirm_doctor_probe; \
                 else _shellfirm_doctor_probe; fi",
            ],
        )),
        Shell::Fish => Some(("fish", &["-i", "-c", "__shellfirm_doctor_probe"])),
        _ => None,
    }
}

/// The probe function every hook defines (zsh also keeps the pre-7 name
/// `_shellfirm_doctor_probe`).
const fn probe_function(_shell: Shell) -> &'static str {
    "__shellfirm_doctor_probe"
}

/// Start a new interactive shell and run the hook's probe function.
fn run_probe(shell: Shell) -> Result<String, String> {
    let Some((bin, args)) = probe_invocation(shell) else {
        return Err(format!("no live probe for {shell}"));
    };
    let mut child = Process::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("could not start {bin}: {e}"))?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() > PROBE_TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "{bin} did not finish starting within {}s",
                    PROBE_TIMEOUT.as_secs()
                ));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => return Err(format!("waiting for {bin}: {e}")),
        }
    }
    let mut out = String::new();
    if let Some(mut stdout) = child.stdout.take() {
        let _ = stdout.read_to_string(&mut out);
    }
    Ok(out)
}

/// First `shellfirm` on PATH (what the hooks run).
fn shellfirm_on_path() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| {
            d.join(if cfg!(windows) {
                "shellfirm.exe"
            } else {
                "shellfirm"
            })
        })
        .find(|p| p.is_file())
}

/// Whether the shell binary on PATH actually starts (a wrapper with a
/// missing interpreter, or a binary for another libc, is a file but exits
/// 126/127 before shellfirm runs).
fn binary_starts(path: &PathBuf) -> Result<(), String> {
    match Process::new(path)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(s
            .code()
            .map_or_else(|| "killed by a signal".to_string(), |c| format!("exit {c}"))),
        Err(e) => Err(e.to_string()),
    }
}

fn check_binary(report: &mut Report) -> serde_json::Value {
    let exe = std::env::current_exe().ok();
    let on_path = shellfirm_on_path();
    let mut starts = None;
    match &on_path {
        None => report.add(
            "binary",
            Status::Fail,
            "shellfirm is not on PATH: the shell hooks fail open (commands are NOT checked)",
        ),
        Some(p) => {
            let same = exe
                .as_ref()
                .zip(Some(p))
                .is_some_and(|(a, b)| a.canonicalize().ok() == b.canonicalize().ok());
            if same || exe.is_none() {
                starts = Some(true);
                report.add(
                    "binary",
                    Status::Ok,
                    format!("{} (v{})", p.display(), crate_version!()),
                );
            } else if let Err(e) = binary_starts(p) {
                starts = Some(false);
                report.add(
                    "binary",
                    Status::Fail,
                    format!(
                        "the hooks run {} but it does not start ({e}): commands are NOT checked \
                         (the hooks warn on every command)",
                        p.display()
                    ),
                );
            } else {
                starts = Some(true);
                report.add(
                    "binary",
                    Status::Warn,
                    format!(
                        "the hooks run {} but this is {}; they may be different versions",
                        p.display(),
                        exe.as_ref()
                            .map(|e| e.display().to_string())
                            .unwrap_or_default()
                    ),
                );
            }
        }
    }
    json!({
        "path_lookup": on_path,
        "current_exe": exe,
        "starts": starts,
        "version": crate_version!(),
    })
}

/// Whether the shell `doctor` runs in has loaded the hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Session {
    /// `SHELLFIRM_HOOK_PID` is the pid of this shell.
    Hooked,
    /// The marker is missing, or belongs to another (outer) shell.
    NotHooked { outer: Option<u32> },
    /// The marker is this shell's pid but it was already in the environment
    /// the shell started with: the shell replaced a hooked one with `exec`
    /// (same pid, same environment), so the marker says nothing about it.
    Inherited,
    /// Not known: doctor was not started from the shell it checks.
    Unknown,
}

/// `marker` is the value of `SHELLFIRM_HOOK_PID`, `parent` the pid of the
/// shell doctor was started from. A marker of another pid comes from an
/// outer shell (`zsh -f` started from a protected shell inherits it).
fn session_state(marker: Option<&str>, parent: Option<u32>) -> Session {
    let Some(parent) = parent else {
        return Session::Unknown;
    };
    match marker.and_then(|m| m.trim().parse::<u32>().ok()) {
        Some(m) if m == parent => Session::Hooked,
        other => Session::NotHooked { outer: other },
    }
}

fn detect_session() -> Session {
    #[cfg(unix)]
    let parent = Some(std::os::unix::process::parent_id());
    #[cfg(not(unix))]
    let parent = None;
    let session = session_state(std::env::var(HOOK_PID_ENV).ok().as_deref(), parent);
    if session == Session::Hooked && parent.is_some_and(started_with_marker) {
        // Restarted with `exec`: the hook loaded again when its load marker
        // is not the one the shell started with.
        let now = std::env::var(HOOK_LOAD_ENV).ok();
        let at_start = parent.and_then(|p| {
            std::fs::read(format!("/proc/{p}/environ"))
                .ok()
                .and_then(|env| environ_value(&env, HOOK_LOAD_ENV))
        });
        return inherited_or_reloaded(now.as_deref(), at_start.as_deref());
    }
    session
}

/// A shell started (by `exec`) with the marker of a hooked shell: `Hooked`
/// when its hook load marker changed since it started (it loaded the hook
/// itself), else `Inherited` (not known).
fn inherited_or_reloaded(now: Option<&str>, at_start: Option<&str>) -> Session {
    match now {
        Some(n) if !n.is_empty() && Some(n) != at_start => Session::Hooked,
        _ => Session::Inherited,
    }
}

/// The value of `name` in a `/proc/<pid>/environ` buffer.
fn environ_value(environ: &[u8], name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    environ
        .split(|b| *b == 0)
        .find_map(|kv| kv.strip_prefix(prefix.as_bytes()))
        .map(|v| String::from_utf8_lossy(v).into_owned())
}

/// Whether the marker was already in the environment process `pid` started
/// with (Linux: `/proc/<pid>/environ`). A shell sets the marker after it
/// starts, so finding its own pid there means it came from `exec`.
fn started_with_marker(pid: u32) -> bool {
    std::fs::read(format!("/proc/{pid}/environ")).is_ok_and(|env| environ_has_marker(&env, pid))
}

fn environ_has_marker(environ: &[u8], pid: u32) -> bool {
    let want = format!("{HOOK_PID_ENV}={pid}");
    environ.split(|b| *b == 0).any(|kv| kv == want.as_bytes())
}

fn check_session(report: &mut Report, shell: Shell, session: Session) {
    match session {
        Session::Hooked => report.add(
            "session",
            Status::Ok,
            format!("this {shell} session has loaded the shellfirm hook"),
        ),
        Session::NotHooked { outer } => {
            let outer = outer
                .map(|p| {
                    format!(" (the hook is active in an outer shell, pid {p}, not in this one)")
                })
                .unwrap_or_default();
            report.add(
                "session",
                Status::Fail,
                format!(
                    "this {shell} session has NOT loaded the shellfirm hook{outer}: commands typed \
                     here are not checked. It was started before `shellfirm init`, or without \
                     its rc files ({}); start a new one: `{}`",
                    match shell {
                        Shell::Zsh => "`zsh -f`",
                        Shell::Bash => "`bash --norc`",
                        Shell::Fish => "`fish --no-config`",
                        _ => "no rc file",
                    },
                    shell.activate_hint()
                ),
            );
        }
        Session::Inherited => report.add(
            "session",
            Status::Warn,
            format!(
                "this {shell} was restarted with `exec` from a shell that had the hook; the \
                 marker it inherited cannot tell whether this one loaded the hook. Check it \
                 directly: `{} | shellfirm doctor --stdin`",
                probe_function(shell)
            ),
        ),
        Session::Unknown => {}
    }
}

/// A session restarted with `exec` from a hooked shell: judged by whether
/// a new interactive shell loads the hook (`exec` runs the same rc files).
fn check_inherited_session(report: &mut Report, shell: Shell, new_shell_hooked: bool) {
    if new_shell_hooked {
        report.add(
            "session",
            Status::Info,
            format!(
                "this {shell} was restarted with `exec`; a new {shell} loads the hook, so this \
                 one most likely did too (to be sure: `{} | shellfirm doctor --stdin`)",
                probe_function(shell)
            ),
        );
    } else {
        report.add(
            "session",
            Status::Fail,
            format!(
                "this {shell} was restarted with `exec` and a new {shell} does not load the hook: \
                 this session is most likely NOT protected (the inherited marker \
                 SHELLFIRM_HOOK_PID is stale)"
            ),
        );
    }
}

/// The rc file finding; `live_hooked` = a new shell (or this one) has the
/// hook, so a missing loader line means it is loaded from another file.
fn check_rc(
    report: &mut Report,
    shell: Shell,
    rc: &init::RcReport,
    live_hooked: bool,
    session_hooked: bool,
) {
    let path = rc
        .path
        .as_ref()
        .map_or_else(|| "?".to_string(), |p| p.display().to_string());
    if let Some(other) = &rc.loaded_from {
        report.add(
            "rc_file",
            Status::Ok,
            format!("{} loads the hook", other.display()),
        );
    } else if !rc.installed && live_hooked {
        report.add(
            "rc_file",
            Status::Info,
            format!(
                "{path} does not load the hook itself; a new {shell} loads it from another file \
                 (a sourced file or plugin manager), which is fine"
            ),
        );
    } else if !rc.installed && session_hooked {
        // Right after `init --uninstall`: the hook loaded in this shell keeps
        // working until the shell is restarted.
        report.add(
            "rc_file",
            Status::Fail,
            format!(
                "{path} does not load the shellfirm hook: this session still has the hook loaded \
                 and stays protected until you restart the shell, but new shells will not load \
                 it. Run `shellfirm init {shell}` to protect them"
            ),
        );
    } else if !rc.installed {
        report.add(
            "rc_file",
            Status::Fail,
            format!("{path} does not load the shellfirm hook: run `shellfirm init {shell}`"),
        );
    } else if rc.load_count > 1 {
        report.add(
            "rc_file",
            Status::Warn,
            format!(
                "{path} loads the hook {} times; keep one (double hooks prompt twice)",
                rc.load_count
            ),
        );
    } else {
        report.add("rc_file", Status::Ok, format!("{path} loads the hook"));
    }
    if let Some(line) = rc.legacy_hook_line {
        report.add(
            "legacy_hook",
            Status::Warn,
            format!("{path} line {line} has a hook from shellfirm 0.3.x; remove it"),
        );
    }
}

fn check_config(report: &mut Report) -> serde_json::Value {
    let config = match Config::new(None) {
        Ok(c) => c,
        Err(e) => {
            report.add(
                "config",
                Status::Fail,
                format!("could not determine the configuration directory: {e}"),
            );
            return json!({ "error": e.to_string() });
        }
    };
    let (_, settings_error) = config.load_settings_lenient();
    let path = config.setting_file_path.display().to_string();
    match &settings_error {
        Some(e) => report.add(
            "settings",
            Status::Fail,
            format!("{path} is invalid (built-in defaults are used for the bad values): {e}"),
        ),
        None if config.setting_file_path.exists() => {
            report.add("settings", Status::Ok, format!("{path} is valid"));
        }
        None => report.add(
            "settings",
            Status::Info,
            format!("{path} does not exist yet (built-in defaults)"),
        ),
    }
    let custom = shellfirm::config::load_custom_checks_report(&config.custom_checks_dir());
    if custom.warnings.is_empty() {
        report.add(
            "custom_checks",
            Status::Ok,
            format!("{} custom check(s) loaded", custom.checks.len()),
        );
    } else {
        report.add(
            "custom_checks",
            Status::Warn,
            format!(
                "{} custom check(s) loaded, {} problem(s): {}",
                custom.checks.len(),
                custom.warnings.len(),
                custom.warnings.join("; ")
            ),
        );
    }
    json!({
        "settings_file": path,
        "settings_valid": settings_error.is_none(),
        "settings_error": settings_error,
        "custom_checks": custom.checks.len(),
        "custom_check_warnings": custom.warnings,
    })
}

/// Where the probe output came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeSource {
    NewShell,
    Stdin,
}

impl ProbeSource {
    const fn describe(self) -> &'static str {
        match self {
            Self::NewShell => "a new interactive shell",
            Self::Stdin => "this shell (stdin)",
        }
    }
}

/// Marker the bash new-shell probe appends to `enter=` when a
/// `PROMPT_COMMAND` entry rebinds Enter at the first prompt.
const BASH_FIRST_PROMPT_REBIND: &str = "(rebound at the first prompt";

/// The `enter` finding. Returns whether Enter goes through shellfirm.
/// `gate`: zsh checks the line again when the line editor finishes
/// (zle-line-finish), whatever widget Enter runs.
fn check_enter(report: &mut Report, shell: Shell, value: Option<&str>, gate: bool) -> bool {
    match value {
        Some(v)
            if gate
                && shell == Shell::Zsh
                && (v.starts_with("bypass:") || v.starts_with("unknown:")) =>
        {
            let w = v.split_once(':').map_or(v, |(_, w)| w);
            report.add(
                "enter",
                Status::Ok,
                format!(
                    "Enter runs the `{w}` widget, which may call zsh's built-in `.accept-line`; \
                     shellfirm checks the line when zsh finishes reading it (zle-line-finish), \
                     so it is still checked"
                ),
            );
            true
        }
        Some("ok") => {
            report.add("enter", Status::Ok, "Enter runs commands through shellfirm");
            true
        }
        Some("n/a") => {
            report.add(
                "enter",
                Status::Warn,
                "line editing is off: the fallback DEBUG-trap hook is used (commands hidden from history are not checked)",
            );
            true
        }
        // zsh: a widget bound to Enter that calls the (checked) accept-line.
        Some(v) if v.starts_with("chained:") => {
            let w = &v["chained:".len()..];
            report.add(
                "enter",
                Status::Ok,
                if shell == Shell::Fish {
                    format!("Enter runs `{w}`, which calls the checked `commandline -f execute`")
                } else {
                    format!("Enter runs the `{w}` widget, which calls the checked accept-line")
                },
            );
            true
        }
        Some(v) if v.starts_with("bypass:") => {
            report.add(
                "enter",
                Status::Fail,
                format!(
                    "Enter runs `{}`, which calls zsh's built-in `.accept-line`: commands are NOT checked",
                    &v["bypass:".len()..]
                ),
            );
            false
        }
        Some(v)
            if shell == Shell::Zsh && (v.starts_with("unknown:") || v.starts_with("rebound:")) =>
        {
            let w = v.split_once(':').map_or(v, |(_, w)| w);
            report.add(
                "enter",
                Status::Warn,
                format!(
                    "Enter runs the `{w}` widget; shellfirm cannot tell whether it calls the \
                     checked accept-line (`zle accept-line`) or bypasses it (`zle .accept-line`)"
                ),
            );
            true
        }
        // bash, new-shell probe: a PROMPT_COMMAND entry that runs after
        // shellfirm's rebinds Enter with `builtin bind` (a plain `bind` is
        // wrapped again at once), so the first command is not checked.
        Some(v) if shell == Shell::Bash && v.contains(BASH_FIRST_PROMPT_REBIND) => {
            let keys = v.split(" (").next().unwrap_or(v).trim();
            report.add(
                "enter",
                Status::Fail,
                format!(
                    "a PROMPT_COMMAND entry that runs after shellfirm's rebinds Enter ({keys}) with \
                     `builtin bind` at the first prompt: the first command of a new shell is NOT \
                     checked (shellfirm warns after it and checks the commands that follow). \
                     Have the plugin use `bind` instead of `builtin bind`; shellfirm wraps a \
                     `bind` that changes Enter again at once"
                ),
            );
            false
        }
        Some(other) => {
            report.add(
                "enter",
                Status::Fail,
                format!(
                    "Enter is bound to something else ({}): commands are NOT checked",
                    other.trim()
                ),
            );
            false
        }
        None => true,
    }
}

/// Turn the probe output into findings. Returns whether Enter goes through
/// shellfirm.
#[allow(clippy::too_many_lines)]
fn check_probe(
    report: &mut Report,
    shell: Shell,
    probe: &BTreeMap<String, String>,
    source: ProbeSource,
) -> bool {
    let get = |k: &str| probe.get(k).map(String::as_str);
    let Some(version) = get("hook_version").filter(|v| !v.is_empty()) else {
        let msg = match source {
            ProbeSource::NewShell => format!("a new interactive {shell} does not load the shellfirm hook"),
            ProbeSource::Stdin => format!(
                "the probe output on stdin has no hook version: the shellfirm hook is not loaded in this {shell}"
            ),
        };
        report.add("hook_loaded", Status::Fail, msg);
        return false;
    };
    if let Some(probed) = get("shell").and_then(Shell::from_name) {
        if probed != shell {
            report.add(
                "hook_loaded",
                Status::Warn,
                format!("the probe output is from {probed}, not {shell}"),
            );
        }
    }
    if version == HOOK_VERSION {
        report.add(
            "hook_loaded",
            Status::Ok,
            format!("hook loaded (version {version})"),
        );
    } else {
        report.add(
            "hook_loaded",
            Status::Warn,
            format!(
                "the hook in this shell is version {version}, this shellfirm ships {HOOK_VERSION}: \
                 restart the shell (`{}`)",
                shell.activate_hint()
            ),
        );
    }

    let gate = shell == Shell::Zsh && get("line_finish") == Some("ok");
    let mut enter_ok = check_enter(report, shell, get("enter"), gate);
    if let Some(chain) = get("enter_chain").filter(|c| !c.is_empty()) {
        report.add(
            "enter",
            Status::Info,
            format!("the Enter binding that was there before shellfirm (`{chain}`) runs after the check"),
        );
    }

    match shell {
        Shell::Bash => {
            if get("ctrl_o") == Some("unchecked") {
                enter_ok = false;
                report.add(
                    "ctrl_o",
                    Status::Fail,
                    "Ctrl-O (operate-and-get-next) is bound directly: commands run with it are NOT checked",
                );
            }
            match (get("fc"), get("fc_builtin")) {
                (Some("ok"), Some("on")) => report.add(
                    "fc",
                    Status::Warn,
                    "fc typed on the line (also as `command fc` / `builtin fc` or inside `eval`) \
                     and Ctrl-X Ctrl-E / vi `v` are checked, but the fc builtin is turned on again \
                     (`enable fc`): a `command fc -s` / `builtin fc -s` run from a function, a \
                     variable, PROMPT_COMMAND or a trap re-runs history unchecked",
                ),
                (Some("ok"), Some("off-no-handler")) => report.add(
                    "fc",
                    Status::Warn,
                    "fc typed on the line is checked, but command_not_found_handle was replaced \
                     after shellfirm loaded: `command fc` run from a function, a variable, \
                     PROMPT_COMMAND or a trap fails instead of running the checked fc",
                ),
                (Some("ok"), _) => report.add(
                    "fc",
                    Status::Ok,
                    "fc (editor and `fc -s` re-runs, also as `command fc`, `builtin fc`, inside \
                     `eval` or in a function) and Ctrl-X Ctrl-E / vi `v` are checked; a \
                     `command fc` that runs from a function, a variable, PROMPT_COMMAND or a \
                     trap goes to the checked fc (the fc builtin is turned off; `builtin fc` \
                     works only on a line typed at the prompt)",
                ),
                (Some(_), _) => report.add(
                    "fc",
                    Status::Warn,
                    "a user-defined `fc` replaces shellfirm's: Ctrl-X Ctrl-E / vi `v` / fc run edited or re-run commands unchecked",
                ),
                (None, _) => {}
            }
            if let Some(k) = get("rewrapped").filter(|k| !k.is_empty()) {
                report.add(
                    "enter",
                    Status::Info,
                    format!(
                        "Enter was rebound after shellfirm loaded ({k}); shellfirm wrapped it at \
                         the prompt, so the line is checked first and then that binding runs"
                    ),
                );
            }
            if get("precmd") == Some("missing") {
                report.add(
                    "precmd",
                    Status::Warn,
                    "__shellfirm_precmd is not in PROMPT_COMMAND",
                );
            }
        }
        Shell::Zsh => {
            match get("widgets") {
                Some("ok") | None => {}
                Some(bad) => {
                    enter_ok = false;
                    report.add(
                        "widgets",
                        Status::Fail,
                        format!("accept-line widgets are not wrapped by shellfirm: {bad}"),
                    );
                }
            }
            if let Some(v) = get("isearch").filter(|v| *v != "ok") {
                report.add(
                    "isearch",
                    Status::Warn,
                    format!(
                        "Ctrl-R (incremental search) + Enter is not routed through shellfirm ({v})"
                    ),
                );
            }
            if let Some(w) = get("rewrapped").filter(|w| !w.is_empty()) {
                report.add(
                    "widgets",
                    Status::Info,
                    format!(
                        "`{w}` was replaced or bound to Enter after shellfirm loaded (a plugin); \
                         shellfirm wrapped it at the prompt, so the line is still checked first"
                    ),
                );
            }
            if get("line_finish") == Some("missing") {
                report.add(
                    "line_finish",
                    Status::Warn,
                    "the zle-line-finish check is not in place (zsh older than 5.3, or a plugin \
                     replaced the zle-line-finish widget): a plugin that binds Enter after the \
                     first prompt (zinit turbo, zsh-defer, `sched`) can run one command unchecked",
                );
            }
            if get("correct") == Some("checked") {
                report.add(
                    "correct",
                    Status::Info,
                    "CORRECT is on: a mistyped command name is also checked as each command \
                     zsh could correct it to",
                );
            }
            match get("fc") {
                Some("ok") => report.add(
                    "fc",
                    Status::Ok,
                    "fc and r (editor and re-runs, also as `builtin fc`/`builtin r` or inside \
                     `eval`) are checked",
                ),
                Some(_) => report.add(
                    "fc",
                    Status::Warn,
                    "`fc` / `r` are your own alias or function: commands they edit or re-run are only checked when typed as `r ...` / `fc -e - ...`",
                ),
                None => {}
            }
        }
        Shell::Fish if get("execute_wrapper") == Some("missing") => {
            report.add(
                "execute_wrapper",
                Status::Warn,
                "`commandline -f execute` (atuin enter_accept, transient prompts) is not checked",
            );
        }
        _ => {}
    }
    if get("legacy_hook") == Some("active") {
        report.add(
            "legacy_hook",
            Status::Fail,
            "an old (0.3.x) shellfirm hook is active in this shell: it prompts twice; remove it from the rc file",
        );
    }
    if get("bypass_seen") == Some("yes") {
        enter_ok = false;
        report.add(
            "bypass",
            Status::Fail,
            "a command in this session ran without passing through shellfirm (Enter was rebound)",
        );
    }
    let plugins: Vec<&str> = get("plugins")
        .unwrap_or_default()
        .split_whitespace()
        .collect();
    for p in &plugins {
        let (name, state) = p.split_once(':').unwrap_or((p, ""));
        let (status, msg) = match (shell, name, state) {
            (Shell::Bash, "atuin", "checked") => (Status::Ok, "atuin enter_accept is checked".to_string()),
            (Shell::Bash, "atuin", _) => (
                Status::Warn,
                "atuin enter_accept runs commands unchecked (set `enter_accept = false` in atuin's config)".to_string(),
            ),
            (Shell::Bash, "ble.sh", _) => (
                Status::Warn,
                "ble.sh replaces readline: the shellfirm key bindings are not used".to_string(),
            ),
            (Shell::Fish, "transient", "chained") => (
                Status::Ok,
                "transient prompt: its Enter binding runs after the check".to_string(),
            ),
            (Shell::Fish, "transient", _) => (
                Status::Info,
                "transient prompt: its `commandline -f execute` is checked".to_string(),
            ),
            _ => (Status::Info, format!("{name} detected")),
        };
        report.add("plugin", status, msg);
    }
    enter_ok
}

fn print_text(shell: Shell, source: &str, report: &Report) {
    // Wrapped between words to the terminal width (unchanged when piped).
    let wrap = shellfirm::prompt::wrap_for_stdout;
    println!(
        "{}\n",
        wrap(&ascii_fallback(&format!(
            "shellfirm doctor — {shell} (from {source})"
        )))
    );
    for f in &report.findings {
        println!(
            "{}",
            wrap(&ascii_fallback(&format!(
                "  [{}] {:<16} {}",
                f.status.symbol(),
                f.id,
                f.message
            )))
        );
    }
    println!();
}

#[allow(clippy::too_many_lines)]
pub fn run(matches: &ArgMatches) -> shellfirm::CmdExit {
    let format = matches
        .get_one::<String>("format")
        .map_or("text", String::as_str);
    let detected = Shell::detect_current();
    let explicit = matches
        .get_one::<String>("shell")
        .and_then(|s| Shell::from_name(s));
    let (shell, source) = explicit.map_or_else(
        || detected.map_or((None, "unknown"), |(s, src)| (Some(s), src.describe())),
        |s| (Some(s), "--shell"),
    );
    let Some(shell) = shell else {
        return shellfirm::CmdExit {
            code: exitcode::USAGE,
            message: Some(
                "Could not detect your shell (parent process or $SHELL). Use: shellfirm doctor --shell <shell>"
                    .into(),
            ),
        };
    };
    // Only the shell doctor was started from can be asked whether it loaded
    // the hook.
    let from_this_shell =
        detected.is_some_and(|(s, src)| s == shell && src == ShellSource::ParentProcess);
    let session = if from_this_shell {
        detect_session()
    } else {
        Session::Unknown
    };
    let use_stdin = matches.get_flag("stdin");

    let mut report = Report::default();
    report.add(
        "shell",
        Status::Info,
        format!("{shell} (detected from {source})"),
    );
    if session != Session::Inherited {
        check_session(&mut report, shell, session);
    }
    let binary = check_binary(&mut report);
    let rc = init::rc_report(shell);

    let probe_source = if use_stdin {
        ProbeSource::Stdin
    } else {
        ProbeSource::NewShell
    };
    let probe_text = if use_stdin {
        let mut s = String::new();
        let _ = std::io::stdin().take(1024 * 1024).read_to_string(&mut s);
        if s.trim().is_empty() {
            Err(format!(
                "no probe output on stdin: the shellfirm hook is not loaded in this shell (`{}` \
                 does not exist). Load it with `{}` (after `shellfirm init {shell}`)",
                probe_function(shell),
                shell.activate_hint()
            ))
        } else {
            Ok(s)
        }
    } else {
        run_probe(shell)
    };
    let probe = probe_text
        .as_ref()
        .map_or_else(|_| BTreeMap::new(), |t| parse_probe(t));
    let mut probe_report = Report::default();
    let enter = match (&probe_text, shell) {
        (Ok(_), _) => Some(check_probe(&mut probe_report, shell, &probe, probe_source)),
        (Err(e), _) if use_stdin => {
            probe_report.add("hook_loaded", Status::Fail, e.clone());
            Some(false)
        }
        (Err(e), Shell::Bash | Shell::Zsh | Shell::Fish) => {
            probe_report.add(
                "hook_loaded",
                Status::Warn,
                format!("live check skipped: {e}"),
            );
            None
        }
        (Err(_), _) => {
            probe_report.add(
                "key_bindings",
                Status::Info,
                format!(
                    "doctor cannot inspect {shell}'s key bindings from outside; the session and \
                     rc file checks above are all it can verify"
                ),
            );
            None
        }
    };
    // The rc file is judged by what a new shell does: the probe of a new
    // shell, or (no new-shell probe) this session. A probe read from stdin
    // describes this session, which may have loaded the hook by hand.
    let probe_hooked = probe.get("hook_version").is_some_and(|v| !v.is_empty());
    let live_hooked = match probe_source {
        ProbeSource::NewShell if probe_text.is_ok() => probe_hooked,
        _ => probe_hooked || session == Session::Hooked,
    };
    if session == Session::Inherited {
        // After `exec`, only a new shell tells what this one most likely did.
        let mut s = Report::default();
        if matches!(probe_source, ProbeSource::NewShell) && probe_text.is_ok() {
            check_inherited_session(&mut s, shell, probe_hooked);
        } else {
            check_session(&mut s, shell, session);
        }
        report.findings.splice(1..1, s.findings);
    }
    check_rc(
        &mut report,
        shell,
        &rc,
        live_hooked,
        session == Session::Hooked,
    );
    report.findings.extend(probe_report.findings);
    if let Some(l) = shell.limitation() {
        report.add("limitation", Status::Warn, l);
    }
    if let Some(var) = match shell {
        Shell::Bash | Shell::Zsh => Some("$?"),
        Shell::Fish => Some("$status"),
        _ => None,
    } {
        report.add(
            "exit_status",
            Status::Info,
            format!(
                "after a line shellfirm blocked, `{var}` still holds the status of the command \
                 before it: the blocked line never ran, and {shell} gives a key binding no way \
                 to set it"
            ),
        );
    }
    let config = check_config(&mut report);
    let failed = report.failed();

    if format == "json" {
        let out = json!({
            "schema_version": SCHEMA_VERSION,
            "version": crate_version!(),
            "shell": shell.name(),
            "detected_from": source,
            "ok": !failed,
            "session_hooked": match session {
                Session::Hooked => Some(true),
                Session::NotHooked { .. } => Some(false),
                Session::Inherited | Session::Unknown => None,
            },
            "enter_routes_through_shellfirm": enter,
            "hook_version_expected": HOOK_VERSION,
            "hook_version": probe.get("hook_version"),
            "probe_source": probe_source.describe(),
            "probe": probe,
            "binary": binary,
            "rc_file": rc,
            "config": config,
            "findings": report.findings,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
    } else {
        print_text(shell, source, &report);
        if !use_stdin && probe_invocation(shell).is_some() {
            if matches!(session, Session::NotHooked { .. }) {
                println!(
                    "{}\n",
                    shellfirm::prompt::wrap_for_stdout(&format!(
                        "This session is not protected; the live check ran in {}. Start a new shell: {}",
                        probe_source.describe(),
                        shell.activate_hint()
                    ))
                );
            } else if live_hooked {
                // Only useful when the probe function exists.
                println!(
                    "{}\n",
                    shellfirm::prompt::wrap_for_stdout(&format!(
                        "Live check ran in {}. To check this session (bindings changed after startup):\n  {} | shellfirm doctor --stdin",
                        probe_source.describe(),
                        probe_function(shell)
                    ))
                );
            }
        }
    }

    shellfirm::CmdExit {
        code: if failed { EXIT_FAILED } else { exitcode::OK },
        message: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(text: &str) -> BTreeMap<String, String> {
        parse_probe(&text.replace("{V}", HOOK_VERSION))
    }

    #[test]
    fn parses_probe_lines() {
        let p =
            parse_probe("shell=bash\nhook_version=4\nenter=ok\nnoise line\nplugins=atuin fzf\n");
        assert_eq!(p.get("shell").map(String::as_str), Some("bash"));
        assert_eq!(p.get("plugins").map(String::as_str), Some("atuin fzf"));
        assert!(!p.contains_key("noise line"));
    }

    #[test]
    fn missing_hook_fails() {
        let mut r = Report::default();
        assert!(!check_probe(
            &mut r,
            Shell::Bash,
            &BTreeMap::new(),
            ProbeSource::NewShell
        ));
        assert!(r.failed());
        let mut r = Report::default();
        check_probe(&mut r, Shell::Zsh, &BTreeMap::new(), ProbeSource::Stdin);
        assert!(r.findings[0].message.contains("not loaded in this zsh"));
    }

    #[test]
    fn rebound_enter_fails_in_bash() {
        let mut r = Report::default();
        let p = probe("shell=bash\nhook_version={V}\nenter= emacs:\\C-m\nfc=ok\n");
        assert!(!check_probe(&mut r, Shell::Bash, &p, ProbeSource::Stdin));
        assert!(r.failed());
    }

    #[test]
    fn first_prompt_rebind_has_its_own_message_in_bash() {
        let mut r = Report::default();
        let p = probe(
            "shell=bash\nhook_version={V}\nenter=emacs:\\C-m (rebound at the first prompt by a \
             PROMPT_COMMAND entry that runs after shellfirm looks: the first command of a new \
             shell is not checked)\nfc=ok\n",
        );
        assert!(!check_probe(&mut r, Shell::Bash, &p, ProbeSource::NewShell));
        let msg = &r.findings.iter().find(|f| f.id == "enter").unwrap().message;
        assert!(msg.contains("builtin bind"), "{msg}");
        assert!(
            msg.contains("first command of a new shell is NOT checked"),
            "{msg}"
        );
        assert!(msg.contains("(emacs:\\C-m)"), "{msg}");
        assert!(!msg.contains("something else"), "{msg}");
    }

    #[test]
    fn rebound_ctrl_o_fails_in_bash() {
        let mut r = Report::default();
        let p = probe("shell=bash\nhook_version={V}\nenter=ok\nctrl_o=unchecked\nfc=ok\n");
        assert!(!check_probe(&mut r, Shell::Bash, &p, ProbeSource::Stdin));
        assert!(r.failed());
    }

    #[test]
    fn healthy_probe_passes() {
        let mut r = Report::default();
        let p = probe(
            "shell=zsh\nhook_version={V}\nwidgets=ok\nenter=ok\nisearch=ok\nprecmd=ok\nfc=ok\nplugins=atuin\n",
        );
        assert!(check_probe(&mut r, Shell::Zsh, &p, ProbeSource::NewShell));
        assert!(!r.failed());
    }

    #[test]
    fn zsh_enter_widgets_are_classified() {
        // zsh-abbr / magic-enter style: calls `zle accept-line` (checked).
        let mut r = Report::default();
        let p = probe("shell=zsh\nhook_version={V}\nwidgets=ok\nenter=chained:magic-enter\n");
        assert!(check_probe(&mut r, Shell::Zsh, &p, ProbeSource::Stdin));
        assert!(r
            .findings
            .iter()
            .all(|f| f.status != Status::Warn && f.status != Status::Fail));
        // `zle .accept-line`: a bypass.
        let mut r = Report::default();
        let p = probe("shell=zsh\nhook_version={V}\nwidgets=ok\nenter=bypass:my-enter\n");
        assert!(!check_probe(&mut r, Shell::Zsh, &p, ProbeSource::Stdin));
        assert!(r.failed());
        // Can't tell: a warning, not a failure.
        let mut r = Report::default();
        let p = probe("shell=zsh\nhook_version={V}\nwidgets=ok\nenter=unknown:odd\n");
        assert!(check_probe(&mut r, Shell::Zsh, &p, ProbeSource::Stdin));
        assert!(!r.failed());
        assert!(r
            .findings
            .iter()
            .any(|f| f.id == "enter" && f.status == Status::Warn));
    }

    #[test]
    fn zsh_line_finish_check_covers_an_enter_widget_that_bypasses() {
        // `zle .accept-line` in the Enter widget, but zle-line-finish checks
        // the line anyway: ok.
        let mut r = Report::default();
        let p = probe(
            "shell=zsh\nhook_version={V}\nwidgets=ok\nenter=bypass:my-enter\nline_finish=ok\n",
        );
        assert!(check_probe(&mut r, Shell::Zsh, &p, ProbeSource::Stdin));
        assert!(!r.failed());
        assert!(r.findings.iter().any(|f| f.id == "enter"
            && f.status == Status::Ok
            && f.message.contains("zle-line-finish")));
        // Without it, a plugin that binds Enter later is a gap: a warning.
        let mut r = Report::default();
        let p = probe("shell=zsh\nhook_version={V}\nwidgets=ok\nenter=ok\nline_finish=missing\n");
        assert!(check_probe(&mut r, Shell::Zsh, &p, ProbeSource::Stdin));
        assert!(r
            .findings
            .iter()
            .any(|f| f.id == "line_finish" && f.status == Status::Warn));
        // A bypass seen in the session still fails.
        let mut r = Report::default();
        let p = probe("shell=zsh\nhook_version={V}\nenter=ok\nline_finish=ok\nbypass_seen=yes\n");
        assert!(!check_probe(&mut r, Shell::Zsh, &p, ProbeSource::Stdin));
    }

    #[test]
    fn every_shell_uses_the_same_probe_name() {
        for shell in [Shell::Bash, Shell::Zsh, Shell::Fish] {
            assert_eq!(probe_function(shell), "__shellfirm_doctor_probe");
            let (_, args) = probe_invocation(shell).expect("probe");
            assert!(args.iter().any(|a| a.contains("__shellfirm_doctor_probe")));
        }
    }

    #[test]
    fn fish_rebound_enter_fails() {
        let mut r = Report::default();
        let p =
            probe("shell=fish\nhook_version={V}\nenter=default:\\r=execute\nexecute_wrapper=ok\n");
        assert!(!check_probe(&mut r, Shell::Fish, &p, ProbeSource::Stdin));
        assert!(r.failed());
    }

    #[test]
    fn old_hook_version_warns() {
        let mut r = Report::default();
        let p = parse_probe("shell=fish\nhook_version=1\nenter=ok\n");
        check_probe(&mut r, Shell::Fish, &p, ProbeSource::NewShell);
        assert!(r
            .findings
            .iter()
            .any(|f| f.id == "hook_loaded" && f.status == Status::Warn));
    }

    #[test]
    fn session_is_told_by_the_hook_pid() {
        assert_eq!(session_state(Some("42"), Some(42)), Session::Hooked);
        assert_eq!(
            session_state(None, Some(42)),
            Session::NotHooked { outer: None }
        );
        // `zsh -f` started from a protected bash: the marker is bash's.
        assert_eq!(
            session_state(Some("9"), Some(42)),
            Session::NotHooked { outer: Some(9) }
        );
        assert_eq!(session_state(Some("x"), None), Session::Unknown);
    }

    #[test]
    fn exec_then_reloaded_hook_is_hooked() {
        // `exec bash` that loaded the hook again: a new load marker.
        assert_eq!(
            inherited_or_reloaded(Some("42.1"), Some("42.7")),
            Session::Hooked
        );
        // The marker it started with: not known.
        assert_eq!(
            inherited_or_reloaded(Some("42.7"), Some("42.7")),
            Session::Inherited
        );
        assert_eq!(inherited_or_reloaded(None, None), Session::Inherited);
        assert_eq!(
            environ_value(b"A=1\0SHELLFIRM_HOOK_LOAD=42.7\0", HOOK_LOAD_ENV).as_deref(),
            Some("42.7")
        );
        // Right after `init --uninstall`: still protected until a restart.
        let rc = init::RcReport::default();
        let mut r = Report::default();
        check_rc(&mut r, Shell::Bash, &rc, false, true);
        assert!(r.findings[0]
            .message
            .contains("stays protected until you restart"));
    }

    #[test]
    fn exec_inherited_marker_is_detected() {
        let env = b"PATH=/bin\0SHELLFIRM_HOOK_PID=42\0HOME=/h\0";
        assert!(environ_has_marker(env, 42));
        assert!(!environ_has_marker(env, 4));
        assert!(!environ_has_marker(b"SHELLFIRM_HOOK_PID=420\0", 42));
        let mut r = Report::default();
        check_inherited_session(&mut r, Shell::Bash, false);
        assert!(r.failed());
        let mut r = Report::default();
        check_inherited_session(&mut r, Shell::Bash, true);
        assert!(!r.failed());
        let mut r = Report::default();
        check_session(&mut r, Shell::Bash, Session::Inherited);
        assert!(r.findings[0].message.contains("exec"));
        assert_eq!(r.findings[0].status, Status::Warn);
    }

    #[test]
    fn fish_enter_chain_is_ok() {
        let mut r = Report::default();
        let p = probe(
            "shell=fish\nhook_version={V}\nenter=chained:transient_execute\nexecute_wrapper=ok\n",
        );
        assert!(check_probe(&mut r, Shell::Fish, &p, ProbeSource::Stdin));
        assert!(!r.failed());
        assert!(r
            .findings
            .iter()
            .any(|f| f.message.contains("commandline -f execute")));
    }

    #[test]
    fn zsh_rewrapped_widget_is_reported() {
        let mut r = Report::default();
        let p = probe("shell=zsh\nhook_version={V}\nwidgets=ok\nenter=ok\nrewrapped=accept-line\n");
        assert!(check_probe(&mut r, Shell::Zsh, &p, ProbeSource::Stdin));
        assert!(r
            .findings
            .iter()
            .any(|f| f.id == "widgets" && f.status == Status::Info));
    }

    #[test]
    fn unprotected_session_fails() {
        let mut r = Report::default();
        check_session(&mut r, Shell::Zsh, Session::NotHooked { outer: None });
        assert!(r.failed());
        assert!(r.findings[0].message.contains("exec zsh"));
        let mut r = Report::default();
        check_session(&mut r, Shell::Zsh, Session::Hooked);
        assert!(!r.failed());
    }

    #[test]
    fn rc_loaded_elsewhere_is_not_an_error() {
        let rc = init::RcReport {
            path: Some(PathBuf::from("/h/.zshrc")),
            exists: true,
            installed: false,
            load_count: 0,
            legacy_hook_line: None,
            loaded_from: None,
        };
        let mut r = Report::default();
        check_rc(&mut r, Shell::Zsh, &rc, true, false);
        assert!(!r.failed());
        assert!(!r.findings[0].message.contains("run `shellfirm init"));
        let mut r = Report::default();
        check_rc(&mut r, Shell::Zsh, &rc, false, false);
        assert!(r.failed());
        let rc = init::RcReport {
            loaded_from: Some(PathBuf::from("/h/.config/fish/conf.d/shellfirm.fish")),
            ..rc
        };
        let mut r = Report::default();
        check_rc(&mut r, Shell::Fish, &rc, false, false);
        assert!(!r.failed());
    }
}
