//! Platform-agnostic types and logic for the PTY proxy.

use std::{
    cell::RefCell,
    io::{BufRead, Read},
    path::{Component, Path, PathBuf},
    sync::OnceLock,
    time::SystemTime,
};

use regex::Regex;
use tracing::{debug, warn};

use crate::{
    audit,
    checks::{self, Check},
    config::{Challenge, Config, Mode, Settings, WrappersConfig},
    env::Environment,
    prompt::{ChallengeResult, DisplayContext, Prompter},
};

use super::{
    lexer::{normalize_ws, statement_candidates, Dialect, MetaCommand, MetaKind},
    line::{ScriptReader, StatementMode, Submission},
};

// ---------------------------------------------------------------------------
// Delimiter
// ---------------------------------------------------------------------------

/// Statement delimiter for the wrapped program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delimiter {
    /// A specific character (e.g. `;`).
    Char(char),
    /// Every line (Enter) is a statement.
    Newline,
}

impl Delimiter {
    /// Parse a delimiter from a config string.
    ///
    /// `\n`, `\r`, `newline`, `enter` and `line` mean [`Delimiter::Newline`].
    /// Falls back to `;` for other multi-character strings.
    #[must_use]
    pub fn from_str_config(s: &str) -> Self {
        match s {
            "\\n" | "\n" | "\\r" | "\r" | "\r\n" | "\\r\\n" | "newline" | "enter" | "line" => {
                Self::Newline
            }
            _ => s
                .chars()
                .next()
                .filter(|_| s.chars().count() == 1)
                .map_or(Self::Char(';'), Self::Char),
        }
    }
}

// ---------------------------------------------------------------------------
// Tool profiles
// ---------------------------------------------------------------------------

/// What to send to the child to throw away a statement the user declined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelKind {
    /// Ctrl-C: psql/mysql/mongosh clear their whole query buffer (also the
    /// earlier lines of a multi-line statement) and stay open.
    Interrupt,
    /// Ctrl-E Ctrl-U: move to end of line and kill it. Used for tools that
    /// exit on Ctrl-C (redis-cli/linenoise) and generic programs.
    KillLine,
}

impl CancelKind {
    /// Bytes written to the child to discard the current input.
    #[must_use]
    pub const fn bytes(self) -> &'static [u8] {
        match self {
            Self::Interrupt => &[0x03],
            Self::KillLine => &[0x05, 0x15],
        }
    }
}

/// Built-in knowledge about an interactive client.
#[derive(Debug, Clone, Copy)]
struct ToolProfile {
    names: &'static [&'static str],
    delimiter: Delimiter,
    groups: &'static [&'static str],
    /// The client's lexer rules.
    dialect: Dialect,
    /// A bracket-balanced line runs on Enter even without the delimiter.
    enter_completes: bool,
    cancel: CancelKind,
}

const TOOL_PROFILES: &[ToolProfile] = &[
    ToolProfile {
        names: &["psql", "pgcli"],
        delimiter: Delimiter::Char(';'),
        groups: &["database", "psql"],
        dialect: Dialect::Postgres,
        enter_completes: false,
        cancel: CancelKind::Interrupt,
    },
    ToolProfile {
        names: &["mysql", "mariadb", "mycli"],
        delimiter: Delimiter::Char(';'),
        groups: &["database", "mysql"],
        dialect: Dialect::MySql,
        enter_completes: false,
        cancel: CancelKind::Interrupt,
    },
    ToolProfile {
        names: &["sqlite3", "sqlite", "duckdb", "litecli"],
        delimiter: Delimiter::Char(';'),
        groups: &["database"],
        dialect: Dialect::Sqlite,
        enter_completes: false,
        cancel: CancelKind::Interrupt,
    },
    ToolProfile {
        names: &["clickhouse-client", "clickhouse", "cqlsh", "sqlplus"],
        delimiter: Delimiter::Char(';'),
        groups: &["database"],
        dialect: Dialect::Generic,
        enter_completes: false,
        cancel: CancelKind::Interrupt,
    },
    ToolProfile {
        names: &["sqlcmd"],
        delimiter: Delimiter::Char(';'),
        groups: &["database"],
        dialect: Dialect::SqlServer,
        enter_completes: false,
        cancel: CancelKind::Interrupt,
    },
    ToolProfile {
        names: &["redis-cli", "valkey-cli", "keydb-cli", "iredis"],
        delimiter: Delimiter::Newline,
        groups: &["redis"],
        dialect: Dialect::Generic,
        enter_completes: false,
        cancel: CancelKind::KillLine,
    },
    ToolProfile {
        names: &["mongosh", "mongo"],
        delimiter: Delimiter::Char(';'),
        groups: &["mongodb"],
        dialect: Dialect::JavaScript,
        enter_completes: true,
        cancel: CancelKind::Interrupt,
    },
];

fn profile_for(tool: &str) -> Option<&'static ToolProfile> {
    TOOL_PROFILES.iter().find(|p| p.names.contains(&tool))
}

fn basename(program: &str) -> &str {
    std::path::Path::new(program)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(program)
}

/// Skip options; returns the index of the first positional argument.
///
/// `short_with_arg` / `long_with_arg` list options that consume the next
/// argument (`-u postgres`, `--user postgres`).
fn skip_opts(args: &[String], short_with_arg: &str, long_with_arg: &[&str]) -> usize {
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            return i + 1;
        }
        if let Some(long) = a.strip_prefix("--") {
            if !long.contains('=') && long_with_arg.contains(&long) {
                i += 1;
            }
        } else if a.len() > 1 && a.starts_with('-') {
            // Short cluster: `-it`, `-u` + arg, `-upostgres`.
            let flags: Vec<char> = a[1..].chars().collect();
            for (j, f) in flags.iter().enumerate() {
                if short_with_arg.contains(*f) {
                    if j == flags.len() - 1 {
                        i += 1; // argument is the next word
                    }
                    break; // rest of the cluster is the argument
                }
            }
        } else {
            return i;
        }
        i += 1;
    }
    args.len()
}

/// Strip `VAR=value` assignments.
fn skip_assignments(args: &[String], from: usize) -> usize {
    let mut i = from;
    while i < args.len() && args[i].contains('=') && !args[i].starts_with('-') {
        i += 1;
    }
    i
}

/// Wrappers whose inner command runs on another machine / in a container.
const REMOTE_WRAPPERS: &[&str] = &[
    "docker", "podman", "nerdctl", "finch", "kubectl", "oc", "ssh",
];

/// The command a wrapper (sudo, docker exec, kubectl exec, ssh, ...) runs,
/// or `None` if `argv[0]` is not a known wrapper.
#[allow(clippy::too_many_lines)]
fn unwrap_once(argv: &[String]) -> Option<Vec<String>> {
    let name = basename(argv.first()?);
    let rest = &argv[1..];
    let start = match name {
        "sudo" => skip_opts(
            rest,
            "ugpCrtUDRTh",
            &[
                "user",
                "group",
                "prompt",
                "close-from",
                "role",
                "type",
                "other-user",
                "chdir",
                "chroot",
                "host",
                "command-timeout",
            ],
        ),
        "doas" => skip_opts(rest, "uC", &[]),
        "env" => {
            let i = skip_opts(rest, "uCS", &["unset", "chdir", "split-string"]);
            skip_assignments(rest, i)
        }
        "nice" | "ionice" | "chrt" | "taskset" | "stdbuf" => {
            skip_opts(rest, "ncpioeO", &["adjustment", "class", "classdata"])
        }
        "nohup" | "exec" | "command" | "time" | "builtin" | "rlwrap" | "unbuffer" => {
            skip_opts(rest, "", &[])
        }
        "timeout" => {
            let i = skip_opts(rest, "sk", &["signal", "kill-after"]);
            i + 1 // the duration
        }
        "su" | "runuser" => {
            // `su - postgres -c psql`
            let pos = rest.iter().position(|a| a == "-c" || a == "--command")?;
            let cmd = rest.get(pos + 1)?;
            return Some(cmd.split_whitespace().map(str::to_string).collect());
        }
        "docker" | "podman" | "nerdctl" | "finch" => {
            let mut i = skip_opts(
                rest,
                "cHl",
                &["context", "host", "config", "log-level", "tlscacert"],
            );
            // `docker container exec`, `docker compose exec`
            if matches!(
                rest.get(i).map(String::as_str),
                Some("container" | "compose")
            ) {
                i += 1;
                if rest[i - 1] == "compose" {
                    i += skip_opts(
                        &rest[i..],
                        "fp",
                        &["file", "project-name", "profile", "env-file"],
                    );
                }
            }
            match rest.get(i).map(String::as_str) {
                Some("exec") => {
                    i += 1;
                    i += skip_opts(
                        &rest[i..],
                        "euw",
                        &["env", "user", "workdir", "env-file", "detach-keys", "index"],
                    );
                }
                Some("run") => {
                    i += 1;
                    i += skip_opts(
                        &rest[i..],
                        "euwvpmhlc",
                        &[
                            "env",
                            "user",
                            "workdir",
                            "volume",
                            "publish",
                            "name",
                            "network",
                            "memory",
                            "hostname",
                            "label",
                            "entrypoint",
                            "env-file",
                            "mount",
                            "platform",
                            "pull",
                            "cpus",
                            "add-host",
                            "restart",
                        ],
                    );
                }
                _ => return None,
            }
            i + 1 // container / service / image
        }
        "kubectl" | "oc" => {
            if !rest.iter().any(|a| a == "exec") {
                return None;
            }
            rest.iter().position(|a| a == "--")? + 1
        }
        "ssh" => {
            let i = skip_opts(rest, "BbcDEeFIiJLlmOoPpQRSWw", &[]);
            i + 1 // the host
        }
        _ => return None,
    };
    let inner: Vec<String> = rest.get(start..)?.to_vec();
    if inner.is_empty() {
        return None;
    }
    // `ssh host 'psql -d prod'`, `bash -c` is not unwrapped.
    if inner.len() == 1 && inner[0].contains(char::is_whitespace) {
        return Some(inner[0].split_whitespace().map(str::to_string).collect());
    }
    Some(inner)
}

/// Determine the real interactive tool behind wrapper commands.
///
/// `sudo -u postgres psql` → `psql`, `docker exec -it db psql` → `psql`,
/// `kubectl exec -it pg-0 -- psql` → `psql`. Returns the basename of the
/// program itself when it is not a recognised wrapper.
#[must_use]
pub fn detect_tool(program: &str, args: &[String]) -> String {
    detect_tool_and_location(program, args).0
}

/// Like [`detect_tool`], also reporting whether the tool runs remotely
/// (through docker/kubectl exec or ssh), where local files are not the
/// files it reads.
#[must_use]
pub fn detect_tool_and_location(program: &str, args: &[String]) -> (String, bool) {
    let (words, remote) = innermost_command(program, args);
    (basename(&words[0]).to_string(), remote)
}

/// The command behind any wrappers (`sudo`, `docker exec`, `kubectl exec`,
/// `ssh`, ...) and whether it runs remotely. Never empty.
fn innermost_command(program: &str, args: &[String]) -> (Vec<String>, bool) {
    let mut words: Vec<String> = std::iter::once(program.to_string())
        .chain(args.iter().cloned())
        .collect();
    let mut remote = false;
    for _ in 0..8 {
        match unwrap_once(&words) {
            Some(inner) if !inner.is_empty() => {
                remote |= REMOTE_WRAPPERS.contains(&basename(&words[0]));
                words = inner;
            }
            _ => break,
        }
    }
    (words, remote)
}

// ---------------------------------------------------------------------------
// WrapperConfig (resolved per-invocation)
// ---------------------------------------------------------------------------

/// Resolved configuration for a single `shellfirm wrap` invocation.
#[derive(Debug, Clone)]
pub struct WrapperConfig {
    /// The program actually executed.
    pub program: String,
    /// The detected interactive tool (looks through sudo/docker/kubectl/ssh).
    pub tool: String,
    pub delimiter: Delimiter,
    /// Check groups to apply; empty = all active groups.
    pub check_groups: Vec<String>,
    pub display_name: String,
    /// How lines are grouped into statements.
    pub mode: StatementMode,
    /// How a declined statement is discarded in the child.
    pub cancel: CancelKind,
    /// Apply shell-style quote stripping before matching. Off for database
    /// clients, where quotes are SQL identifiers / JS strings.
    pub strip_quotes: bool,
    /// Whether `tool` has a built-in profile.
    pub known_tool: bool,
    /// The tool runs in a container / on another host (its files are not
    /// local files).
    pub remote: bool,
}

impl WrapperConfig {
    /// Resolve the wrapper config for a given program and its arguments.
    ///
    /// Priority: CLI `--delimiter` flag > user config (`wrappers.tools.<tool>`,
    /// looked up by detected tool name, then by program basename) > built-in
    /// tool profile > generic fallback (newline, all groups).
    #[must_use]
    #[allow(clippy::option_if_let_else)]
    pub fn resolve(
        program: &str,
        args: &[String],
        cli_delimiter: Option<&str>,
        user_config: &WrappersConfig,
    ) -> Self {
        let (tool, remote) = detect_tool_and_location(program, args);
        let base = basename(program).to_string();
        let profile = profile_for(&tool);
        let user_tool = user_config
            .tools
            .get(&tool)
            .or_else(|| user_config.tools.get(&base));

        let builtin_delim = profile.map(|p| p.delimiter);
        let delimiter = if let Some(d) = cli_delimiter {
            Delimiter::from_str_config(d)
        } else if let Some(d) = user_tool.and_then(|t| t.delimiter.as_deref()) {
            Delimiter::from_str_config(d)
        } else {
            builtin_delim.unwrap_or(Delimiter::Newline)
        };

        let check_groups = if let Some(t) = user_tool.filter(|t| !t.check_groups.is_empty()) {
            t.check_groups.clone()
        } else if let Some(p) = profile {
            p.groups.iter().map(|s| (*s).to_string()).collect()
        } else {
            vec![]
        };

        let mode = match delimiter {
            Delimiter::Newline => StatementMode::Line,
            Delimiter::Char(c) => StatementMode::Delimited {
                delimiter: c,
                dialect: profile.map_or(Dialect::Generic, |p| p.dialect),
                enter_completes: profile.is_some_and(|p| p.enter_completes),
            },
        };

        let cancel = profile.map_or(CancelKind::KillLine, |p| p.cancel);

        Self {
            program: program.to_string(),
            display_name: tool.clone(),
            tool,
            delimiter,
            check_groups,
            mode,
            cancel,
            strip_quotes: profile.is_none(),
            known_tool: profile.is_some(),
            remote,
        }
    }

    /// Filter `checks` down to this tool's groups (all when none configured).
    /// The lexer dialect used to mask string literals before matching
    /// (`None` for line-mode tools: redis-cli, shells).
    #[must_use]
    pub const fn dialect(&self) -> Option<Dialect> {
        match self.mode {
            StatementMode::Delimited { dialect, .. } => Some(dialect),
            StatementMode::Line => None,
        }
    }

    #[must_use]
    pub fn filter_checks(&self, checks: &[Check]) -> Vec<Check> {
        if self.check_groups.is_empty() {
            checks.to_vec()
        } else {
            checks
                .iter()
                .filter(|c| self.check_groups.contains(&c.from))
                .cloned()
                .collect()
        }
    }
}

// ---------------------------------------------------------------------------
// Statement handling (reuses the existing analysis pipeline)
// ---------------------------------------------------------------------------

/// Outcome after analyzing a statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementAction {
    /// Nothing risky matched — forward.
    Forward,
    /// A challenge was shown and the user passed it — forward.
    Approved,
    /// The user cancelled the challenge or a deny rule matched — discard.
    Block,
}

impl StatementAction {
    /// Whether the statement may be sent to the program.
    #[must_use]
    pub const fn allows(self) -> bool {
        matches!(self, Self::Forward | Self::Approved)
    }
}

fn strip_quotes_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"'[^']*'|"[^"]*""#).unwrap())
}

fn no_strip_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Matches nothing: quotes are kept.
    RE.get_or_init(|| Regex::new(r"[^\s\S]").unwrap())
}

/// Records what the inner prompter was asked to show.
struct RecordingPrompter<'a> {
    inner: &'a dyn Prompter,
    display: RefCell<Option<DisplayContext>>,
}

impl Prompter for RecordingPrompter<'_> {
    fn run_challenge(&self, display: &DisplayContext) -> ChallengeResult {
        *self.display.borrow_mut() = Some(display.clone());
        self.inner.run_challenge(display)
    }
}

/// Everything needed to analyze a statement.
pub struct StatementContext<'a> {
    pub settings: &'a Settings,
    /// Checks for this tool's groups.
    pub checks: &'a [Check],
    /// Every active check (used for shell escapes such as `\!`).
    pub all_checks: &'a [Check],
    pub env: &'a dyn Environment,
    pub prompter: &'a dyn Prompter,
    pub config: &'a Config,
    pub tool_name: &'a str,
    pub strip_quotes: bool,
    /// Client lexer, used to mask string literals before matching.
    pub dialect: Option<Dialect>,
    /// The client runs remotely: files named in `\i` / `source` are not
    /// read from this machine.
    pub remote: bool,
    /// Read included files from disk line by line (a live session). When
    /// false they are read through [`Environment::read_file`] (tests).
    pub stream_files: bool,
    /// The temporary tables the session created so far (`None`: every
    /// line is checked on its own).
    pub session: Option<&'a SessionTables>,
}

impl<'a> StatementContext<'a> {
    /// A context with no dialect, no shell-escape checks and local files.
    #[must_use]
    pub fn basic(
        settings: &'a Settings,
        checks: &'a [Check],
        env: &'a dyn Environment,
        prompter: &'a dyn Prompter,
        config: &'a Config,
        tool_name: &'a str,
    ) -> Self {
        Self {
            settings,
            checks,
            all_checks: checks,
            env,
            prompter,
            config,
            tool_name,
            strip_quotes: false,
            dialect: None,
            remote: false,
            stream_files: false,
            session: None,
        }
    }
}

/// The temporary tables a wrapped session created.
///
/// `CREATE TEMP TABLE t` typed earlier in the session, then `DROP TABLE t`,
/// only drops that temporary table (it hides a real table of the same
/// name), so it is not a Critical drop. A reconnect, `ROLLBACK` or
/// `DISCARD` forgets them.
#[derive(Default)]
pub struct SessionTables(RefCell<ScriptTables>);

impl std::fmt::Debug for SessionTables {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SessionTables")
            .field(&self.0.borrow().tables.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Live settings
// ---------------------------------------------------------------------------

/// Re-reads the settings and every active check (`None` = keep the old ones).
pub type ReloadFn<'a> = dyn Fn() -> Option<(Settings, Vec<Check>)> + 'a;

/// Size and modification time of a watched file.
type Stamp = Option<(SystemTime, u64)>;

fn stamp(path: &Path) -> Stamp {
    let m = std::fs::metadata(path).ok()?;
    Some((m.modified().ok()?, m.len()))
}

/// The settings and checks of a running wrap session.
///
/// Sessions last for hours: when the settings file (or the custom checks
/// directory) changes, they are re-read on the next Enter, so
/// `shellfirm config deny ...` in another terminal applies to a session that
/// is already open.
pub struct LiveRules<'a> {
    pub settings: Settings,
    /// Checks for the wrapped tool's groups.
    pub checks: Vec<Check>,
    /// Every active check (shell escapes).
    pub all_checks: Vec<Check>,
    wrapper: WrapperConfig,
    watch: Vec<PathBuf>,
    stamps: Vec<Stamp>,
    reload: Option<&'a ReloadFn<'a>>,
    tables: SessionTables,
}

impl<'a> LiveRules<'a> {
    #[must_use]
    pub fn new(
        settings: &Settings,
        checks: &[Check],
        all_checks: &[Check],
        wrapper: &WrapperConfig,
    ) -> Self {
        Self {
            settings: settings.clone(),
            checks: checks.to_vec(),
            all_checks: all_checks.to_vec(),
            wrapper: wrapper.clone(),
            watch: Vec::new(),
            stamps: Vec::new(),
            reload: None,
            tables: SessionTables::default(),
        }
    }

    /// Re-read through `reload` when one of `paths` changes.
    #[must_use]
    pub fn watching(mut self, paths: Vec<PathBuf>, reload: Option<&'a ReloadFn<'a>>) -> Self {
        self.stamps = paths.iter().map(|p| stamp(p)).collect();
        self.watch = paths;
        self.reload = reload;
        self
    }

    /// Re-read the settings if a watched file changed. Returns true when
    /// new settings were loaded.
    pub fn refresh(&mut self) -> bool {
        let Some(reload) = self.reload else {
            return false;
        };
        let now: Vec<Stamp> = self.watch.iter().map(|p| stamp(p)).collect();
        if now == self.stamps {
            return false;
        }
        self.stamps = now;
        let Some((settings, all_checks)) = reload() else {
            warn!("[wrap] settings changed but could not be re-read; keeping the old ones");
            return false;
        };
        debug!("[wrap] settings changed: reloaded");
        self.checks = self.wrapper.filter_checks(&all_checks);
        self.settings = settings;
        self.all_checks = all_checks;
        true
    }

    /// A statement context over the current rules.
    #[must_use]
    pub fn context<'b>(
        &'b self,
        env: &'b dyn Environment,
        prompter: &'b dyn Prompter,
        config: &'b Config,
    ) -> StatementContext<'b> {
        StatementContext {
            settings: &self.settings,
            checks: &self.checks,
            all_checks: &self.all_checks,
            env,
            prompter,
            config,
            tool_name: &self.wrapper.display_name,
            strip_quotes: self.wrapper.strip_quotes,
            dialect: self.wrapper.dialect(),
            remote: self.wrapper.remote,
            stream_files: true,
            session: Some(&self.tables),
        }
    }
}

fn audit_statement(
    ctx: &StatementContext<'_>,
    statement: &str,
    pipeline: &checks::PipelineResult,
    matched: &[Check],
    challenge: Option<Challenge>,
    outcome: audit::AuditOutcome,
    extra: &audit::AuditExtra,
) {
    if !ctx.settings.audit_enabled {
        return;
    }
    let top_br = pipeline.blast_radii.iter().max_by_key(|(_, br)| br.scope);
    let event = audit::AuditEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        timestamp: audit::now_timestamp(),
        command: format!("[wrap:{}] {statement}", ctx.tool_name),
        matched_ids: matched.iter().map(|c| c.id.clone()).collect(),
        challenge_type: challenge.map_or_else(|| "None".to_string(), |c| c.to_string()),
        outcome,
        context_labels: pipeline.context.labels.clone(),
        severity: pipeline.max_severity,
        agent_name: None,
        agent_session_id: None,
        blast_radius_scope: top_br.map(|(_, br)| br.scope.to_string()),
        blast_radius_detail: top_br.map(|(_, br)| br.description.clone()),
        attempts: None,
    };
    if let Err(e) = audit::log_event_with(&ctx.config.audit_log_path(), &event, extra) {
        warn!("Failed to write audit log: {e}");
    }
}

/// Run the analysis pipeline on one text (fail-open: `None` on error).
fn run_pipeline(
    text: &str,
    checks: &[Check],
    strip_quotes: bool,
    ctx: &StatementContext<'_>,
) -> Option<checks::PipelineResult> {
    let resolved = ctx.settings.resolved_for(Mode::Wrap);
    let strip = if strip_quotes {
        strip_quotes_regex()
    } else {
        no_strip_regex()
    };
    match checks::analyze_command(text, ctx.settings, &resolved, checks, ctx.env, strip) {
        Ok(p) => Some(p),
        Err(e) => {
            warn!("[wrap:{}] analysis failed (fail-open): {e}", ctx.tool_name);
            None
        }
    }
}

/// `check`, already matched against a statement, as a check that matches
/// any text (so the shell parser in the pipeline cannot lose it).
fn matched_check(check: &Check) -> Check {
    Check {
        test: Regex::new(r"(?s).").expect("valid regex").into(),
        filters: Vec::new(),
        ..check.clone()
    }
}

/// Pipeline for one reading of a SQL / JavaScript statement.
///
/// A statement is not a shell command: it is matched as a whole, so the
/// shell parser cannot cut it at `(` / `)` (`SET a = now() WHERE id = 42`
/// would otherwise lose its WHERE, and `(SELECT ...)` would become a
/// "subshell"). The checks that matched then go through the full pipeline
/// (context, policy, deny lists, severity) on the same text.
///
/// `require_match`: skip the pipeline when no check matched (file scans,
/// when the project policy defines no checks of its own).
///
/// Every matched check is passed through `adjust` first (`None` drops
/// it).
fn statement_pipeline_adjusted(
    text: &str,
    ctx: &StatementContext<'_>,
    require_match: bool,
    adjust: &dyn Fn(Check) -> Option<Check>,
) -> Option<checks::PipelineResult> {
    if ctx.strip_quotes || ctx.dialect.is_none() {
        // Line-mode tools and unknown programs: shell-like input.
        return run_pipeline(text, ctx.checks, ctx.strip_quotes, ctx);
    }
    let matched: Vec<Check> = checks::match_text(ctx.checks, text, ctx.env)
        .into_iter()
        .map(matched_check)
        .filter_map(adjust)
        .collect();
    if matched.is_empty() && require_match {
        return None;
    }
    run_pipeline(text, &matched, false, ctx)
}

/// Merge the matches of several pipelines (one per candidate reading of a
/// statement) into the first one that matched.
fn combine(pipelines: Vec<checks::PipelineResult>) -> Option<checks::PipelineResult> {
    let mut iter = pipelines.into_iter();
    let mut base = iter.next()?;
    for p in iter {
        if base.active_matches.is_empty() && base.skipped_matches.is_empty() {
            let mut p = p;
            std::mem::swap(&mut base, &mut p);
            merge_into(&mut base, p);
        } else {
            merge_into(&mut base, p);
        }
    }
    Some(base)
}

fn merge_into(base: &mut checks::PipelineResult, other: checks::PipelineResult) {
    for c in other.active_matches {
        if !base.active_matches.iter().any(|x| x.id == c.id) {
            base.active_matches.push(c);
        }
    }
    for c in other.skipped_matches {
        if !base.skipped_matches.iter().any(|x| x.id == c.id)
            && !base.active_matches.iter().any(|x| x.id == c.id)
        {
            base.skipped_matches.push(c);
        }
    }
    for alt in other.alternatives {
        if !base
            .alternatives
            .iter()
            .any(|a| a.suggestion == alt.suggestion)
        {
            base.alternatives.push(alt);
        }
    }
    base.blast_radii.extend(other.blast_radii);
    base.is_denied |= other.is_denied;
    base.max_severity = base.max_severity.max(other.max_severity);
}

/// Show the challenge for `pipeline` (if anything matched) and audit it.
fn challenge_pipeline(
    shown_statement: &str,
    pipeline: &checks::PipelineResult,
    ctx: &StatementContext<'_>,
) -> StatementAction {
    let tool_name = ctx.tool_name;
    if pipeline.active_matches.is_empty() {
        if !pipeline.skipped_matches.is_empty() {
            audit_statement(
                ctx,
                shown_statement,
                pipeline,
                &pipeline.skipped_matches,
                None,
                audit::AuditOutcome::Skipped,
                &audit::AuditExtra::default(),
            );
        }
        return StatementAction::Forward;
    }
    let resolved = ctx.settings.resolved_for(Mode::Wrap);
    let active_refs: Vec<&Check> = pipeline.active_matches.iter().collect();
    let recorder = RecordingPrompter {
        inner: ctx.prompter,
        display: RefCell::new(None),
    };
    let result = match checks::challenge_with_context(
        ctx.settings,
        &resolved,
        &active_refs,
        &pipeline.relevant_context,
        &pipeline.merged_policy,
        &recorder,
        &pipeline.blast_radii,
    ) {
        Ok(r) => r,
        Err(e) => {
            warn!("[wrap:{tool_name}] challenge failed (fail-open): {e}");
            return StatementAction::Forward;
        }
    };

    let shown = recorder.display.into_inner();
    let is_denied = shown.as_ref().is_some_and(|d| d.is_denied) || pipeline.is_denied;
    let challenge = shown.as_ref().map(|d| d.effective_challenge);
    let (outcome, action) = match result {
        ChallengeResult::Passed => (audit::AuditOutcome::Allowed, StatementAction::Approved),
        ChallengeResult::Denied if is_denied => {
            (audit::AuditOutcome::Denied, StatementAction::Block)
        }
        ChallengeResult::Denied => (audit::AuditOutcome::Cancelled, StatementAction::Block),
    };
    // The same attribution as the shell hook: policy files, effective
    // challenge, escalation reasons, and why it did not run
    // (`reason=cancelled`).
    let ids: Vec<String> = pipeline
        .active_matches
        .iter()
        .map(|c| c.id.clone())
        .collect();
    let mut extra = audit::AuditExtra::for_decision(
        &pipeline.merged_policy,
        &ctx.settings.deny_patterns_ids,
        &ids,
        is_denied,
        challenge.map(|c| c.to_string()),
        shown.map(|d| d.escalation_reasons).unwrap_or_default(),
    );
    if let Some(reason) = audit::deny_reason::for_outcome(&outcome) {
        extra.deny_reason = Some(reason.to_string());
    }
    audit_statement(
        ctx,
        shown_statement,
        pipeline,
        &pipeline.active_matches,
        challenge,
        outcome,
        &extra,
    );
    action
}

/// Analyze one statement and challenge the user if it is risky.
///
/// SQL/JS string literals are masked before matching (so data such as
/// `INSERT ... VALUES ('DELETE FROM users')` never matches), and statements
/// the statement really executes are checked too (`EXPLAIN ANALYZE <stmt>`,
/// `PREPARE x AS <stmt>`, SQL inside `DO` blocks / `EXECUTE '...'`).
///
/// Writes exactly one audit entry per risky statement, after the
/// challenge, with the effective challenge and the real outcome
/// (`Allowed`, `Denied` for deny rules, `Cancelled` when the user declined).
///
/// Fail-open: if analysis errors out, the statement is forwarded so the
/// interactive session keeps working.
#[must_use]
pub fn analyze_statement(statement: &str, ctx: &StatementContext<'_>) -> StatementAction {
    analyze_statement_impl(statement, ctx, false, None)
}

/// `tables`: the temporary tables created so far (updated with what this
/// statement creates or drops).
fn analyze_statement_impl(
    statement: &str,
    ctx: &StatementContext<'_>,
    redact: bool,
    tables: Option<&mut ScriptTables>,
) -> StatementAction {
    let trimmed = statement.trim();
    if trimmed.is_empty() {
        return StatementAction::Forward;
    }
    let tool_name = ctx.tool_name;
    let candidates = ctx.dialect.map_or_else(
        || vec![trimmed.to_string()],
        |d| statement_candidates(trimmed, d),
    );
    if redact {
        // Possibly a secret typed at a prompt that does not echo: only go
        // through the (logging) pipeline when a check really matches.
        let any = candidates.iter().any(|c| {
            if ctx.dialect.is_some() && !ctx.strip_quotes {
                !checks::match_text(ctx.checks, c, ctx.env).is_empty()
            } else {
                !checks::run_check_on_command_with_env(ctx.checks, c, ctx.env).is_empty()
            }
        });
        if !any {
            debug!(
                "[wrap:{tool_name}] unconfirmed input <{} chars>: no match",
                trimmed.chars().count()
            );
            return StatementAction::Forward;
        }
    }
    debug!("[wrap:{tool_name}] analyzing: {trimmed:?} (candidates: {candidates:?})");
    let script_drop = tables.and_then(|t| candidates.first().and_then(|m| t.observe(m, true)));
    let adjust = |c: Check| adjust_script_drop(c, script_drop);
    let pipelines: Vec<checks::PipelineResult> = candidates
        .iter()
        .filter_map(|c| statement_pipeline_adjusted(c, ctx, false, &adjust))
        .collect();
    let Some(pipeline) = combine(pipelines) else {
        return StatementAction::Forward;
    };
    challenge_pipeline(trimmed, &pipeline, ctx)
}

/// A check built at runtime for a client meta-command.
fn meta_check(id: &str, description: String, severity: checks::Severity) -> Check {
    Check {
        id: id.to_string(),
        test: Regex::new(r"(?s).").expect("valid regex").into(),
        description,
        from: "wrap".to_string(),
        challenge: Challenge::default(),
        filters: Vec::new(),
        alternative: None,
        alternative_info: None,
        severity,
    }
}

/// Pipeline for a synthetic meta-command check (context, policy, deny lists
/// and `min_severity` all apply as for built-in checks).
fn meta_pipeline(check: Check, ctx: &StatementContext<'_>) -> Option<checks::PipelineResult> {
    if ctx.settings.ignores_patterns_ids.contains(&check.id) {
        return None;
    }
    run_pipeline("shellfirm-wrap-meta", &[check], false, ctx)
}

fn resolve_path(path: &str, env: &dyn Environment) -> PathBuf {
    let home = path
        .strip_prefix("~/")
        .and_then(|rest| env.home_dir().map(|h| h.join(rest)));
    let p = home.unwrap_or_else(|| PathBuf::from(path));
    if p.is_absolute() {
        return p;
    }
    match env.current_dir() {
        Ok(cwd) => cwd.join(&p),
        Err(_) => p,
    }
}

/// Max bytes of an included file that are scanned. The file is read line by
/// line (any size works); beyond this the rest is reported as not checked.
const MAX_SCAN_BYTES: u64 = 256 << 20;

/// How deep nested includes (`\i` inside an `\i` file) are followed.
const MAX_INCLUDE_DEPTH: usize = 8;

/// Max number of files read for one meta-command.
const MAX_INCLUDE_FILES: usize = 64;

/// Risky statements of a file scan that get their own pipeline (context,
/// policy); the matches of the others are only counted.
const MAX_LISTED_RISKY: usize = 20;

/// Lexically normalise `.` / `..` components (cycle detection; the file
/// itself may not exist).
fn normalize_path(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push(c);
                }
            }
            _ => out.push(c),
        }
    }
    out
}

fn display_name(p: &Path) -> String {
    p.file_name().map_or_else(
        || p.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    )
}

const fn mib(bytes: u64) -> u64 {
    bytes >> 20
}

/// Everything found while scanning a file and the files it includes.
#[derive(Default)]
struct FileScan {
    /// Statements and meta-commands seen, over every file.
    items: usize,
    /// Files read (the top-level one included).
    files: usize,
    /// Risky items: (what is shown in the challenge, matches).
    risky: Vec<(String, checks::PipelineResult)>,
    /// Risky statements beyond [`MAX_LISTED_RISKY`] and the checks they
    /// matched.
    more: usize,
    more_checks: Vec<Check>,
    /// Files already being scanned (include cycles).
    seen: Vec<PathBuf>,
    /// The project policy defines its own checks: every statement goes
    /// through the pipeline.
    policy_checks: bool,
    /// Max bytes read per file.
    cap: u64,
    /// Tables the script creates itself, in the order seen.
    created: ScriptTables,
}

/// The time a file scan may take before the transient "checking" line is
/// shown (the same delay as the shell hook's).
const SCAN_NOTICE_AFTER_MS: u64 = 200;

/// The transient `shellfirm: checking <file>…` line shown on the terminal
/// while a large file is scanned, erased when the scan ends
/// (before the challenge is drawn).
struct ScanNotice {
    done: Option<std::sync::mpsc::Sender<()>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl ScanNotice {
    /// The text of the line for `name` (`size`: the file size, when known).
    fn text(name: &str, size: Option<u64>) -> String {
        let size = size
            .filter(|s| *s >= 1 << 20)
            .map_or_else(String::new, |s| format!(" ({} MiB)", mib(s)));
        format!(
            "shellfirm: checking {name}{size}{}",
            crate::config::glyph("…", "...")
        )
    }

    /// Start the line for `path` (nothing outside a live session or
    /// without a terminal).
    fn start(path: &Path, ctx: &StatementContext<'_>) -> Self {
        use std::io::{IsTerminal as _, Write as _};
        let idle = Self {
            done: None,
            handle: None,
        };
        if !ctx.stream_files || !cfg!(unix) || !std::io::stderr().is_terminal() {
            return idle;
        }
        let text = Self::text(
            &display_name(path),
            std::fs::metadata(path).ok().map(|m| m.len()),
        );
        let color = console::colors_enabled_stderr();
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let handle = std::thread::spawn(move || {
            if rx.recv_timeout(std::time::Duration::from_millis(SCAN_NOTICE_AFTER_MS))
                != Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            {
                return;
            }
            let Ok(mut tty) = std::fs::OpenOptions::new().write(true).open("/dev/tty") else {
                return;
            };
            let text = if color {
                format!("\x1b[2m{text}\x1b[0m")
            } else {
                text
            };
            let _ = write!(tty, "\r\n{text}");
            let _ = tty.flush();
            let _ = rx.recv();
            // Erase it and go back up: the banner (or the client's own
            // output) lands where it would have without the line.
            let _ = write!(tty, "\r\x1b[2K\x1b[1A");
            let _ = tty.flush();
        });
        Self {
            done: Some(tx),
            handle: Some(handle),
        }
    }
}

impl Drop for ScanNotice {
    fn drop(&mut self) {
        if let Some(tx) = self.done.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// How a table dropped by a script was created earlier in the same script.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScriptTable {
    /// `CREATE TEMP TABLE t`: lives only in this session.
    Temporary,
    /// `CREATE TABLE t` (no `IF NOT EXISTS` / `OR REPLACE`).
    Created,
}

/// Tables a script (or a wrapped session) creates: normalised name, how.
#[derive(Default)]
struct ScriptTables {
    tables: Vec<(String, ScriptTable)>,
}

fn create_table_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)^\s*CREATE\s+(?P<orr>OR\s+REPLACE\s+)?(?:(?:GLOBAL|LOCAL)\s+)?(?:(?P<temp>TEMPORARY|TEMP)\s+)?(?:UNLOGGED\s+)?TABLE\s+(?P<ine>IF\s+NOT\s+EXISTS\s+)?(?P<name>[\w."`\[\]$#]+)"#,
        )
        .expect("valid regex")
    })
}

fn drop_table_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)^\s*DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?P<names>[\w."`\[\]$#]+(?:\s*,\s*[\w."`\[\]$#]+)*)(?:\s+(?:CASCADE|RESTRICT))?\s*;?\s*$"#,
        )
        .expect("valid regex")
    })
}

/// Statements after which the temporary tables created so far may be gone:
/// a rollback (it undoes the CREATE) or `DISCARD TEMP` / `DISCARD ALL`.
fn tables_gone_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)^\s*(?:ROLLBACK|ABORT|DISCARD\s+(?:TEMP|TEMPORARY|ALL))\b")
            .expect("valid regex")
    })
}

fn on_commit_drop_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\bON\s+COMMIT\s+DROP\b").expect("valid regex"))
}

/// A name that can only be a temporary table: `pg_temp.t` (Postgres) or
/// `#t` / `##t` (SQL Server).
fn always_temporary(name: &str) -> bool {
    let n = name.trim().trim_start_matches(['"', '[']);
    n.starts_with('#') || n.to_ascii_lowercase().starts_with("pg_temp.")
}

/// A table name as written in a statement, for comparing names: quotes
/// removed, lower case, `pg_temp.` dropped.
fn table_key(name: &str) -> String {
    let n = name
        .chars()
        .filter(|c| !matches!(c, '"' | '`' | '[' | ']'))
        .collect::<String>()
        .to_lowercase();
    n.strip_prefix("pg_temp.")
        .map_or_else(|| n.clone(), str::to_string)
}

impl ScriptTables {
    /// Follow one statement (`masked`: literals masked). The table it
    /// creates is remembered (only temporary ones when `temp_only`). When
    /// it is a `DROP TABLE` of tables only this script / session created,
    /// returns how they were created (any `Created` makes it `Created`) and
    /// forgets them: the name then means the table it hid, if any.
    fn observe(&mut self, masked: &str, temp_only: bool) -> Option<ScriptTable> {
        if tables_gone_re().is_match(masked) {
            self.tables.clear();
            return None;
        }
        if let Some(c) = create_table_re().captures(masked) {
            let how = if c.name("temp").is_some() || always_temporary(&c["name"]) {
                ScriptTable::Temporary
            } else if c.name("orr").is_some() || c.name("ine").is_some() {
                // It may have existed before the script ran.
                return None;
            } else {
                ScriptTable::Created
            };
            // `ON COMMIT DROP`: gone after the transaction, so a later
            // DROP of the name is the real table's.
            if (temp_only && how == ScriptTable::Created) || on_commit_drop_re().is_match(masked) {
                return None;
            }
            self.tables.push((table_key(&c["name"]), how));
            return None;
        }
        let c = drop_table_re().captures(masked)?;
        let mut out = ScriptTable::Temporary;
        let mut known = Vec::new();
        for name in c["names"].split(',') {
            if always_temporary(name) {
                continue;
            }
            let key = table_key(name.trim());
            let how = self
                .tables
                .iter()
                .rev()
                .find(|(n, _)| *n == key)
                .map(|(_, h)| *h)?;
            if how == ScriptTable::Created {
                out = ScriptTable::Created;
            }
            known.push(key);
        }
        for key in known {
            if let Some(pos) = self.tables.iter().rposition(|(n, _)| *n == key) {
                self.tables.remove(pos);
            }
        }
        Some(out)
    }
}

/// A matched check on a `DROP TABLE` of tables the script created itself:
/// dropping a temporary table the script made is not risky;
/// a table created earlier in the script gets a Low finding (it may have
/// existed already when its CREATE failed and the script went on).
fn adjust_script_drop(check: Check, how: Option<ScriptTable>) -> Option<Check> {
    let Some(how) = how else {
        return Some(check);
    };
    if !matches!(
        check.id.as_str(),
        "database:drop_table" | "database:drop_cascade"
    ) {
        return Some(check);
    }
    match how {
        ScriptTable::Temporary => None,
        ScriptTable::Created => Some(Check {
            severity: checks::Severity::Low,
            description: format!(
                "{} The table is created earlier in this file, so this normally only drops \
                 what the script itself built (unless its CREATE failed because the table \
                 already existed).",
                check.description
            ),
            ..check
        }),
    }
}

impl FileScan {
    fn push(&mut self, shown: String, p: checks::PipelineResult) {
        if !p.active_matches.is_empty() && !self.risky.iter().any(|(r, _)| *r == shown) {
            self.risky.push((shown, p));
        }
    }

    /// Too many risky statements already listed: only count this one.
    const fn full(&self) -> bool {
        self.risky.len() >= MAX_LISTED_RISKY
    }
}

/// How reading a script ended.
#[derive(Debug, PartialEq, Eq)]
enum ReadEnd {
    Complete,
    /// Stopped after `cap` bytes; `size` is the file size when known.
    Truncated {
        size: Option<u64>,
    },
    Unreadable,
    /// Not a regular file (FIFO, character device such as `/dev/tty`,
    /// socket): never opened, since opening or reading it could block or
    /// never end.
    NotRegular,
}

/// Whether `path` exists and is neither a regular file nor a directory
/// (a FIFO, `/dev/tty`, `/dev/zero`, a socket; symlinks are followed).
/// `/dev/null` is read (it is empty).
fn is_special_file(path: &Path) -> bool {
    path != Path::new("/dev/null")
        && std::fs::metadata(path).is_ok_and(|m| !m.is_file() && !m.is_dir())
}

/// Call `f` with every line of `path` (line ending removed, invalid UTF-8
/// replaced), reading at most `cap` bytes. Files are streamed from disk in
/// a live session, so a large dump never has to fit in memory.
fn for_each_line(
    path: &Path,
    ctx: &StatementContext<'_>,
    cap: u64,
    f: &mut dyn FnMut(&str),
) -> ReadEnd {
    let mut total = 0u64;
    let mut first = true;
    let mut emit = |line: &str, total: u64| -> bool {
        if total > cap {
            return false;
        }
        let mut l = line.strip_suffix('\n').unwrap_or(line);
        l = l.strip_suffix('\r').unwrap_or(l);
        if first {
            l = l.strip_prefix('\u{feff}').unwrap_or(l);
            first = false;
        }
        f(l);
        true
    };
    // Like the shell hook: a FIFO or a device is never opened (a FIFO's
    // open blocks until a writer appears, `/dev/tty` would read the
    // keyboard).
    if is_special_file(path) {
        return ReadEnd::NotRegular;
    }
    if !ctx.stream_files {
        let Ok(content) = ctx.env.read_file(path) else {
            return ReadEnd::Unreadable;
        };
        for line in content.split_inclusive('\n') {
            total += line.len() as u64;
            if !emit(line, total) {
                return ReadEnd::Truncated {
                    size: Some(content.len() as u64),
                };
            }
        }
        return ReadEnd::Complete;
    }
    let Ok(file) = std::fs::File::open(path) else {
        return ReadEnd::Unreadable;
    };
    let size = file.metadata().ok().map(|m| m.len());
    let mut reader = std::io::BufReader::new(file);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        // Never hold more than the remaining budget (a file without
        // newlines is one huge line).
        let budget = cap.saturating_sub(total).saturating_add(1);
        match (&mut reader).take(budget).read_until(b'\n', &mut buf) {
            Ok(0) => return ReadEnd::Complete,
            Ok(n) => {
                total += n as u64;
                if !emit(&String::from_utf8_lossy(&buf), total) {
                    return ReadEnd::Truncated { size };
                }
            }
            // A directory opens but cannot be read.
            Err(_) if total == 0 => return ReadEnd::Unreadable,
            Err(_) => return ReadEnd::Truncated { size },
        }
    }
}

/// How a statement or meta-command found in `path` is shown.
fn scan_label(shown: &str, path: &Path, depth: usize) -> String {
    if depth == 0 {
        format!("`{}`", short(shown, 60))
    } else {
        format!("`{}` in {}", short(shown, 60), display_name(path))
    }
}

/// A Medium `wrap:run_file` finding: part of what a file runs is not
/// checked.
fn push_not_checked(desc: String, shown: String, ctx: &StatementContext<'_>, scan: &mut FileScan) {
    if let Some(p) = meta_pipeline(
        meta_check("wrap:run_file", desc, checks::Severity::Medium),
        ctx,
    ) {
        scan.push(shown, p);
    }
}

/// Scan a file a meta-command runs, through the same client model as typed
/// input ([`ScriptReader`]): statements, `DELIMITER`, shell escapes (`\!`,
/// `system`, `.shell`, `\o |cmd`), opaque commands (`\gexec`, `\e`) and
/// nested includes, which are followed up to [`MAX_INCLUDE_DEPTH`] levels
/// (cycle-safe). The file is read line by line; a file larger than the
/// scan cap gets a Medium "not fully checked" finding. Returns false when
/// the file could not be read.
fn scan_file(
    path: &Path,
    depth: usize,
    ctx: &StatementContext<'_>,
    scan: &mut FileScan,
) -> Result<(), &'static str> {
    let dialect = ctx.dialect.unwrap_or(Dialect::Generic);
    scan.files += 1;
    scan.seen.push(normalize_path(path));
    let mut reader = ScriptReader::new(dialect);
    let mut sub = Submission::default();
    let cap = scan.cap;
    let end = for_each_line(path, ctx, cap, &mut |line| {
        reader.push_line(line, &mut sub);
        if dialect == Dialect::JavaScript {
            // mongosh scripts often omit `;` (and a mis-lexed line must
            // not hide the rest): also scan line by line.
            let l = normalize_ws(line);
            if !l.is_empty() && !sub.statements.contains(&l) {
                sub.statements.push(l);
            }
        }
        scan_items(&mut sub, path, depth, ctx, scan);
    });
    if matches!(end, ReadEnd::Unreadable | ReadEnd::NotRegular) {
        scan.files -= 1;
        scan.seen.pop();
        return Err(if end == ReadEnd::NotRegular {
            NOT_REGULAR
        } else {
            NOT_READABLE
        });
    }
    if let ReadEnd::Truncated { size } = end {
        let size = size.map_or_else(String::new, |s| format!(" ({} MiB)", mib(s)));
        let why = format!(
            "file too large to check{size}; only its first {} MiB were checked",
            mib(cap)
        );
        push_not_checked(
            format!(
                "{} is not fully checked: file too large to check{size}. Only its first {} MiB \
                 were checked; the statements after that are not.",
                path.display(),
                mib(cap)
            ),
            format!("{} — NOT fully checked: {why}", display_name(path)),
            ctx,
            scan,
        );
    } else {
        reader.finish(&mut sub);
        scan_items(&mut sub, path, depth, ctx, scan);
    }
    Ok(())
}

/// Why a file was not scanned: it could not be read.
const NOT_READABLE: &str = "the file could not be read here";
/// Why a file was not scanned: a FIFO / device is never opened.
const NOT_REGULAR: &str = "not a regular file (a FIFO or device); it is not read";

/// Check (and remove) the statements and meta-commands collected in `sub`.
fn scan_items(
    sub: &mut Submission,
    path: &Path,
    depth: usize,
    ctx: &StatementContext<'_>,
    scan: &mut FileScan,
) {
    let dialect = ctx.dialect.unwrap_or(Dialect::Generic);
    scan.items += sub.statements.len() + sub.metas.len();
    for s in std::mem::take(&mut sub.statements) {
        let candidates = statement_candidates(&s, dialect);
        let script_drop = candidates
            .first()
            .and_then(|m| scan.created.observe(m, false));
        if scan.full() {
            // Enough listed: only record what else matched.
            let mut hit = false;
            for c in &candidates {
                for check in checks::match_text(ctx.checks, c, ctx.env) {
                    let Some(check) = adjust_script_drop(matched_check(check), script_drop) else {
                        continue;
                    };
                    hit = true;
                    if !scan.more_checks.iter().any(|x| x.id == check.id) {
                        scan.more_checks.push(check);
                    }
                }
            }
            scan.more += usize::from(hit);
            continue;
        }
        let adjust = |c: Check| adjust_script_drop(c, script_drop);
        let pipelines: Vec<_> = candidates
            .iter()
            .filter_map(|c| statement_pipeline_adjusted(c, ctx, !scan.policy_checks, &adjust))
            .collect();
        if let Some(p) = combine(pipelines) {
            scan.push(scan_label(&s, path, depth), p);
        }
    }
    for meta in std::mem::take(&mut sub.metas) {
        let label = scan_label(&meta.raw, path, depth);
        match &meta.kind {
            MetaKind::Shell { command } => {
                if let Some(p) = run_pipeline(command, ctx.all_checks, true, ctx) {
                    scan.push(label, p);
                }
            }
            MetaKind::ShellToSql { command } => {
                if let Some(p) = shell_to_sql_pipeline(command, ctx) {
                    scan.push(label, p);
                }
            }
            MetaKind::Opaque { id, what } => {
                if let Some(p) =
                    meta_pipeline(meta_check(id, what.clone(), checks::Severity::Medium), ctx)
                {
                    scan.push(label, p);
                }
            }
            MetaKind::UnknownTarget { what } => {
                if let Some(p) = unknown_target_pipeline(what, ctx) {
                    scan.push(label, p);
                }
            }
            MetaKind::RunFile {
                path: nested,
                relative,
            } => {
                scan_nested(nested, *relative, path, &meta.raw, depth + 1, ctx, scan);
            }
        }
    }
    sub.fallbacks.clear();
    sub.unconfirmed.clear();
}

/// Where a nested include is read from.
///
/// * `\ir` / `\include_relative`: the including file's directory (psql).
/// * `\i`, `source`, `\.`, `.read`: the client's working directory.
/// * mongosh `load()`: the including file's directory, then the working
///   directory.
fn include_candidates(
    nested: &str,
    relative: bool,
    parent: &Path,
    ctx: &StatementContext<'_>,
) -> Vec<PathBuf> {
    let from_cwd = resolve_path(nested, ctx.env);
    if !Path::new(nested).is_relative() || nested.starts_with("~/") {
        return vec![from_cwd];
    }
    let from_file = parent.parent().map(|d| d.join(nested));
    if relative {
        return from_file.into_iter().collect();
    }
    if ctx.dialect == Some(Dialect::JavaScript) {
        let mut out: Vec<PathBuf> = from_file.into_iter().collect();
        if !out.contains(&from_cwd) {
            out.push(from_cwd);
        }
        return out;
    }
    vec![from_cwd]
}

/// Follow a nested include found in `parent`.
fn scan_nested(
    nested: &str,
    relative: bool,
    parent: &Path,
    raw: &str,
    depth: usize,
    ctx: &StatementContext<'_>,
    scan: &mut FileScan,
) {
    let tool = ctx.tool_name;
    let not_checked = |why: &str, scan: &mut FileScan| {
        let desc = format!(
            "{} (in {}) runs SQL from {nested} — its contents are not checked ({why}).",
            short(raw, 60),
            display_name(parent)
        );
        let shown = format!(
            "`{}` in {} — NOT checked: {why}",
            short(raw, 60),
            display_name(parent)
        );
        push_not_checked(desc, shown, ctx, scan);
    };
    if depth > MAX_INCLUDE_DEPTH {
        not_checked(
            &format!("includes nested deeper than {MAX_INCLUDE_DEPTH} levels"),
            scan,
        );
        return;
    }
    if scan.files >= MAX_INCLUDE_FILES {
        not_checked(
            &format!("more than {MAX_INCLUDE_FILES} files included"),
            scan,
        );
        return;
    }
    let candidates = include_candidates(nested, relative, parent, ctx);
    let mut why = NOT_READABLE;
    for c in &candidates {
        if scan.seen.contains(&normalize_path(c)) {
            debug!("[wrap:{tool}] include cycle at {nested}: not followed again");
            return;
        }
        match scan_file(c, depth, ctx, scan) {
            Ok(()) => return,
            Err(w) => why = w,
        }
    }
    not_checked(why, scan);
}

fn short(s: &str, max: usize) -> String {
    if s.chars().count() > max {
        format!("{}...", s.chars().take(max).collect::<String>())
    } else {
        s.to_string()
    }
}

/// Pipeline for sqlite3 `.read '|cmd'`: the command is checked as a shell
/// command, and its output runs as SQL that is not checked (Medium).
fn shell_to_sql_pipeline(
    command: &str,
    ctx: &StatementContext<'_>,
) -> Option<checks::PipelineResult> {
    let what = format!(
        "This runs the shell command `{}` and then runs its output as SQL; that SQL is not \
         checked.",
        short(command, 80)
    );
    let pipelines: Vec<_> = run_pipeline(command, ctx.all_checks, true, ctx)
        .into_iter()
        .chain(meta_pipeline(
            meta_check("wrap:run_command_output", what, checks::Severity::Medium),
            ctx,
        ))
        .collect();
    combine(pipelines)
}

/// High `wrap:sql_variable_target`: a TRUNCATE / DROP / DELETE whose
/// target is a psql variable the wrap does not know.
fn unknown_target_pipeline(
    what: &str,
    ctx: &StatementContext<'_>,
) -> Option<checks::PipelineResult> {
    meta_pipeline(
        meta_check(
            "wrap:sql_variable_target",
            what.to_string(),
            checks::Severity::High,
        ),
        ctx,
    )
}

/// Analyze a client meta-command (`\i file`, `source`, `.read`, `load()`,
/// `\!`, `.shell`, `\e`, `\gexec`, ...) and challenge if needed.
///
/// * Files are read (when local) and every statement is checked; a clean
///   file passes, risky statements are listed in the challenge. A file that
///   cannot be read gets a Medium challenge ("contents not checked").
/// * Shell escapes are checked as shell commands with every active check.
/// * Commands that run SQL the wrap cannot see get a Medium challenge.
#[must_use]
pub fn analyze_meta(meta: &MetaCommand, ctx: &StatementContext<'_>) -> StatementAction {
    let tool = ctx.tool_name;
    debug!("[wrap:{tool}] meta-command: {:?}", meta.raw);
    let pipeline = match &meta.kind {
        MetaKind::Shell { command } => run_pipeline(command, ctx.all_checks, true, ctx),
        MetaKind::ShellToSql { command } => shell_to_sql_pipeline(command, ctx),
        MetaKind::Opaque { id, what } => {
            meta_pipeline(meta_check(id, what.clone(), checks::Severity::Medium), ctx)
        }
        MetaKind::UnknownTarget { what } => unknown_target_pipeline(what, ctx),
        MetaKind::RunFile { path, .. } => run_file_pipeline(path, ctx),
    };
    pipeline.map_or(StatementAction::Forward, |p| {
        challenge_pipeline(&meta.raw, &p, ctx)
    })
}

/// Pipeline for a meta-command that runs a file (`None` = nothing to ask).
fn run_file_pipeline(path: &str, ctx: &StatementContext<'_>) -> Option<checks::PipelineResult> {
    run_file_pipeline_capped(path, ctx, MAX_SCAN_BYTES)
}

fn run_file_pipeline_capped(
    path: &str,
    ctx: &StatementContext<'_>,
    cap: u64,
) -> Option<checks::PipelineResult> {
    let tool = ctx.tool_name;
    let shown_path = if path.is_empty() {
        "(no file name)"
    } else {
        path
    };
    let not_read = |why: &str| {
        let desc =
            format!("This runs SQL from file {shown_path} — its contents are not checked ({why}).");
        meta_pipeline(
            meta_check("wrap:run_file", desc, checks::Severity::Medium),
            ctx,
        )
    };
    if ctx.remote {
        return not_read("the file is on the remote host / container");
    }
    let full = resolve_path(path, ctx.env);
    let cwd = ctx.env.current_dir().unwrap_or_default();
    let mut scan = FileScan {
        cap,
        policy_checks: crate::policy::discover_all(ctx.env, &cwd)
            .policy
            .is_some_and(|p| !p.checks.is_empty()),
        ..FileScan::default()
    };
    if path.is_empty() {
        return not_read(NOT_READABLE);
    }
    let notice = ScanNotice::start(&full, ctx);
    let scanned = scan_file(&full, 0, ctx, &mut scan);
    drop(notice);
    if let Err(why) = scanned {
        return not_read(why);
    }
    let n = scan.items;
    if scan.risky.is_empty() && scan.more == 0 {
        debug!(
            "[wrap:{tool}] {}: {n} statement(s) in {} file(s), nothing risky",
            full.display(),
            scan.files
        );
        return None;
    }
    let risky = scan.risky;
    let total = risky.len() + scan.more;
    let list = risky
        .iter()
        .take(3)
        .map(|(s, p)| {
            let ids: Vec<&str> = p.active_matches.iter().map(|c| c.id.as_str()).collect();
            format!("{s} ({})", ids.join(", "))
        })
        .collect::<Vec<_>>()
        .join("; ");
    let more = if total > 3 {
        format!(" and {} more", total - 3)
    } else {
        String::new()
    };
    let nested = match scan.files {
        0 | 1 => String::new(),
        2 => " and 1 file it includes".to_string(),
        k => format!(" and {} files it includes", k - 1),
    };
    let desc = format!(
        "This runs {n} statement(s) from {}{nested}; risky ({total}): {list}{more}.",
        full.display(),
    );
    let mut pipelines: Vec<_> = meta_pipeline(
        meta_check("wrap:run_file", desc, checks::Severity::Medium),
        ctx,
    )
    .into_iter()
    .collect();
    pipelines.extend(risky.into_iter().map(|(_, p)| p));
    if !scan.more_checks.is_empty() {
        pipelines.extend(run_pipeline(
            "shellfirm-wrap-meta",
            &scan.more_checks,
            false,
            ctx,
        ));
    }
    combine(pipelines)
}

fn shell_quote(s: &str) -> String {
    let plain = !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_./:@%+=,-".contains(c));
    if plain {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

/// What `program args` runs from its own command line.
///
/// That is what runs before any input is typed (`psql -c ...`, `psql -f
/// file`, `mysql -e ...`, `mongosh --eval ...`, `sqlite3 db "SQL"`, a
/// redis-cli command), read the way the session reads typed input. `wc.tool`
/// decides how the arguments are read
/// (`--tool psql ./my-wrapper -c ...` reads the wrapper's arguments as
/// psql's).
#[must_use]
pub fn startup_submission(wc: &WrapperConfig, program: &str, args: &[String]) -> Submission {
    let (inner, _) = innermost_command(program, args);
    let payloads = super::startup::payloads(&wc.tool, &inner[1..]);
    super::startup::submission(&payloads, wc.dialect())
}

/// Check what the wrapped client runs from its own command line.
///
/// This runs before the client is started (see [`startup_submission`]), so
/// that
/// `alias psql='shellfirm wrap psql'` protects `psql -c 'DROP TABLE users'`
/// with or without a shell hook. A program without a client profile is
/// checked as a shell command line with every active check.
///
/// Returns whether the client may be started (`forward`) and whether a
/// challenge was shown.
pub fn check_startup(
    wc: &WrapperConfig,
    program: &str,
    args: &[String],
    ctx: &StatementContext<'_>,
    before_each: &dyn Fn(&str),
) -> EnterDecision {
    if !wc.known_tool {
        let line = std::iter::once(program)
            .chain(args.iter().map(String::as_str))
            .map(shell_quote)
            .collect::<Vec<_>>()
            .join(" ");
        before_each(&line);
        let action = run_pipeline(&line, ctx.all_checks, false, ctx)
            .map_or(StatementAction::Forward, |p| {
                challenge_pipeline(&line, &p, ctx)
            });
        return EnterDecision {
            forward: action.allows(),
            challenged: action != StatementAction::Forward,
        };
    }
    let sub = startup_submission(wc, program, args);
    if sub.is_empty() {
        return EnterDecision {
            forward: true,
            challenged: false,
        };
    }
    debug!("[wrap:{}] command line: {}", wc.tool, sub.log_summary());
    decide_submission(&sub, ctx, before_each)
}

/// Backwards-compatible wrapper around [`analyze_statement`].
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn handle_statement(
    statement: &str,
    settings: &Settings,
    checks: &[Check],
    env: &dyn Environment,
    prompter: &dyn Prompter,
    config: &Config,
    tool_name: &str,
) -> StatementAction {
    analyze_statement(
        statement,
        &StatementContext::basic(settings, checks, env, prompter, config, tool_name),
    )
}

/// Decision for a held Enter key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnterDecision {
    /// Forward the Enter byte (true) or discard the statement (false).
    pub forward: bool,
    /// A challenge was shown (pending type-ahead should be dropped).
    pub challenged: bool,
}

/// The line printed after a passed challenge in a wrapped session.
///
/// `✓ approved — sending to psql`, or for a line of several statements
/// `✓ approved — sending 3 statements to psql`; in plain ASCII `ok:
/// approved, sending to psql` (same shape as the shell hook's approved
/// line).
#[must_use]
pub fn approved_sending_line(client: &str, statements: usize) -> String {
    let what = if statements > 1 {
        format!("{statements} statements to ")
    } else {
        "to ".to_string()
    };
    format!(
        "{}{what}{client}",
        crate::config::glyph("✓ approved — sending ", "ok: approved, sending "),
    )
}

/// Check every statement and meta-command of a submission.
///
/// When nothing was challenged, the fallback readings are checked too. One
/// cancelled/denied item discards the whole line (the program receives the
/// line as a unit).
pub fn decide_submission(
    sub: &Submission,
    ctx: &StatementContext<'_>,
    before_each: &dyn Fn(&str),
) -> EnterDecision {
    let blocked = EnterDecision {
        forward: false,
        challenged: true,
    };
    let mut challenged = false;
    // The session's temporary tables, plus what this line creates; kept
    // only when the line is sent.
    let mut tables = ScriptTables {
        tables: ctx
            .session
            .map(|s| s.0.borrow().tables.clone())
            .unwrap_or_default(),
    };
    for stmt in &sub.statements {
        before_each(stmt);
        match analyze_statement_impl(stmt, ctx, false, Some(&mut tables)) {
            StatementAction::Forward => {}
            StatementAction::Approved => challenged = true,
            StatementAction::Block => return blocked,
        }
    }
    for meta in &sub.metas {
        before_each(&meta.raw);
        match analyze_meta(meta, ctx) {
            StatementAction::Forward => {}
            StatementAction::Approved => challenged = true,
            StatementAction::Block => return blocked,
        }
    }
    if !challenged {
        let rest = sub
            .fallbacks
            .iter()
            .map(|f| (f, false))
            .chain(sub.unconfirmed.iter().map(|u| (u, true)));
        for (text, redact) in rest {
            before_each(text);
            match analyze_statement_impl(text, ctx, redact, None) {
                StatementAction::Forward => {}
                StatementAction::Approved => {
                    challenged = true;
                    break;
                }
                StatementAction::Block => return blocked,
            }
        }
    }
    if let Some(session) = ctx.session {
        if sub.reconnect {
            tables.tables.clear();
        }
        *session.0.borrow_mut() = tables;
    }
    EnterDecision {
        forward: true,
        challenged,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::WrapperToolConfig,
        prompt::MockPrompter,
        wrap::line::{Interceptor, KeyEvent},
    };
    use std::collections::HashMap;

    fn argv(s: &str) -> (String, Vec<String>) {
        let mut parts: Vec<String> = s.split_whitespace().map(str::to_string).collect();
        let p = parts.remove(0);
        (p, parts)
    }

    fn resolve(s: &str) -> WrapperConfig {
        let (p, a) = argv(s);
        WrapperConfig::resolve(&p, &a, None, &WrappersConfig::default())
    }

    // -- Delimiter tests --

    #[test]
    fn delimiter_parsing() {
        assert_eq!(Delimiter::from_str_config(";"), Delimiter::Char(';'));
        assert_eq!(Delimiter::from_str_config("\\n"), Delimiter::Newline);
        assert_eq!(Delimiter::from_str_config("\n"), Delimiter::Newline);
        assert_eq!(Delimiter::from_str_config("\r"), Delimiter::Newline);
        assert_eq!(Delimiter::from_str_config("\\r"), Delimiter::Newline);
        assert_eq!(Delimiter::from_str_config("go"), Delimiter::Char(';'));
    }

    // -- Tool detection --

    #[test]
    fn detect_tool_through_wrappers() {
        for (cmd, tool) in [
            ("psql -d prod", "psql"),
            ("/usr/bin/psql", "psql"),
            ("sudo -u postgres psql", "psql"),
            ("sudo -E -u postgres -- psql -d x", "psql"),
            ("doas -u postgres psql", "psql"),
            ("docker exec -it db psql -U postgres", "psql"),
            (
                "docker exec -it -e PGPASSWORD=x -u postgres db psql",
                "psql",
            ),
            ("docker compose exec db psql", "psql"),
            (
                "docker run --rm -it --network host postgres:16 psql -h db",
                "psql",
            ),
            ("podman exec -it cache redis-cli", "redis-cli"),
            ("kubectl exec -it pg-0 -n prod -- psql", "psql"),
            (
                "kubectl --context prod exec -it mongo-0 -- mongosh",
                "mongosh",
            ),
            ("ssh -p 2222 db1 psql -d prod", "psql"),
            ("env PGHOST=prod psql", "psql"),
            ("sudo docker exec -it db mysql", "mysql"),
            ("su - postgres -c psql", "psql"),
            ("timeout 600 redis-cli", "redis-cli"),
            ("pgcli", "pgcli"),
            ("bash --norc", "bash"),
            ("kubectl get pods", "kubectl"),
            ("docker ps", "docker"),
        ] {
            let (p, a) = argv(cmd);
            assert_eq!(detect_tool(&p, &a), tool, "{cmd}");
        }
        // `ssh db1 'mysql -u root'` — the remote command is one argument.
        assert_eq!(
            detect_tool("ssh", &["db1".into(), "mysql -u root".into()]),
            "mysql"
        );
    }

    // -- WrapperConfig resolution tests --

    #[test]
    fn builtin_groups_per_tool() {
        let cfg = resolve("psql");
        assert_eq!(cfg.delimiter, Delimiter::Char(';'));
        assert_eq!(cfg.check_groups, vec!["database", "psql"]);
        assert_eq!(cfg.cancel, CancelKind::Interrupt);
        assert!(!cfg.strip_quotes);

        assert_eq!(resolve("mysql").check_groups, vec!["database", "mysql"]);
        assert_eq!(resolve("mariadb").check_groups, vec!["database", "mysql"]);
        assert_eq!(resolve("sqlite3").check_groups, vec!["database"]);

        let redis = resolve("redis-cli -h prod");
        assert_eq!(redis.delimiter, Delimiter::Newline);
        assert_eq!(redis.mode, StatementMode::Line);
        assert_eq!(redis.check_groups, vec!["redis"]);
        assert_eq!(redis.cancel, CancelKind::KillLine);

        let mongo = resolve("mongosh");
        assert_eq!(mongo.check_groups, vec!["mongodb"]);
        assert!(matches!(
            mongo.mode,
            StatementMode::Delimited {
                enter_completes: true,
                ..
            }
        ));
    }

    #[test]
    fn wrapped_tool_gets_its_profile() {
        let cfg = resolve("sudo -u postgres psql");
        assert_eq!(cfg.tool, "psql");
        assert_eq!(cfg.display_name, "psql");
        assert_eq!(cfg.program, "sudo");
        assert_eq!(cfg.check_groups, vec!["database", "psql"]);
        assert!(cfg.known_tool);
    }

    #[test]
    fn user_override_takes_precedence() {
        let mut tools = HashMap::new();
        tools.insert(
            "psql".to_string(),
            WrapperToolConfig {
                delimiter: Some("\\n".to_string()),
                check_groups: vec!["custom".to_string()],
            },
        );
        let user_cfg = WrappersConfig {
            tools,
            ..Default::default()
        };
        let cfg = WrapperConfig::resolve("psql", &[], None, &user_cfg);
        assert_eq!(cfg.delimiter, Delimiter::Newline);
        assert_eq!(cfg.check_groups, vec!["custom"]);
        // Also applies through a wrapper.
        let (p, a) = argv("docker exec -it db psql");
        let cfg = WrapperConfig::resolve(&p, &a, None, &user_cfg);
        assert_eq!(cfg.check_groups, vec!["custom"]);
    }

    #[test]
    fn default_semicolon_does_not_break_redis() {
        let mut tools = HashMap::new();
        tools.insert(
            "redis-cli".to_string(),
            WrapperToolConfig {
                delimiter: None, // user only set check_groups
                check_groups: vec!["redis".to_string(), "database".to_string()],
            },
        );
        let user_cfg = WrappersConfig {
            tools,
            ..Default::default()
        };
        let cfg = WrapperConfig::resolve("redis-cli", &[], None, &user_cfg);
        assert_eq!(cfg.delimiter, Delimiter::Newline);
        assert_eq!(cfg.check_groups, vec!["redis", "database"]);
    }

    #[test]
    fn cli_delimiter_overrides_all() {
        let cfg = WrapperConfig::resolve("psql", &[], Some("\\n"), &WrappersConfig::default());
        assert_eq!(cfg.delimiter, Delimiter::Newline);
    }

    #[test]
    fn unknown_tool_gets_generic_fallback() {
        let cfg = resolve("some-tool");
        assert_eq!(cfg.delimiter, Delimiter::Newline);
        assert!(cfg.check_groups.is_empty());
        assert!(cfg.strip_quotes);
        assert!(!cfg.known_tool);
    }

    #[test]
    fn filter_checks_by_group() {
        let settings = Settings::default();
        let all = settings.get_active_checks().unwrap();
        let redis = resolve("redis-cli").filter_checks(&all);
        assert!(!redis.is_empty());
        assert!(redis.iter().all(|c| c.from == "redis"));
        assert_eq!(resolve("bash").filter_checks(&all).len(), all.len());
    }

    // -- analyze_statement tests --

    struct Fixture {
        settings: Settings,
        checks: Vec<Check>,
        env: crate::env::MockEnvironment,
        config: Config,
        _temp: tree_fs::Tree,
    }

    fn fixture(groups: Option<&[&str]>) -> Fixture {
        let settings = Settings::default();
        let mut checks = settings.get_active_checks().unwrap();
        if let Some(g) = groups {
            checks.retain(|c| g.contains(&c.from.as_str()));
        }
        let env = crate::env::MockEnvironment {
            cwd: "/tmp".into(),
            ..Default::default()
        };
        let temp = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = Config::new(Some(&temp.root.join("app").display().to_string())).unwrap();
        Fixture {
            settings,
            checks,
            env,
            config,
            _temp: temp,
        }
    }

    fn ctx<'a>(f: &'a Fixture, prompter: &'a dyn Prompter, tool: &'a str) -> StatementContext<'a> {
        let dialect = resolve(tool).dialect();
        StatementContext {
            dialect,
            ..StatementContext::basic(&f.settings, &f.checks, &f.env, prompter, &f.config, tool)
        }
    }

    #[test]
    fn safe_statement_forwards() {
        let f = fixture(None);
        let p = MockPrompter::passing();
        assert_eq!(
            analyze_statement("SELECT 1", &ctx(&f, &p, "psql")),
            StatementAction::Forward
        );
        assert_eq!(
            analyze_statement("   ", &ctx(&f, &p, "psql")),
            StatementAction::Forward
        );
        assert!(p.captured_displays.borrow().is_empty());
    }

    #[test]
    fn drop_table_triggers_challenge() {
        let f = fixture(None);
        let p = MockPrompter::passing();
        let action = handle_statement(
            "DROP TABLE users",
            &f.settings,
            &f.checks,
            &f.env,
            &p,
            &f.config,
            "psql",
        );
        assert_eq!(action, StatementAction::Approved);
        let displays = p.captured_displays.borrow();
        assert_eq!(displays.len(), 1);
        assert!(displays[0]
            .descriptions
            .iter()
            .any(|d| d.contains("Dropping a table")));
    }

    #[test]
    fn interactive_flushall_triggers_challenge() {
        let f = fixture(Some(&["redis"]));
        let p = MockPrompter::passing();
        assert_eq!(
            analyze_statement("FLUSHALL", &ctx(&f, &p, "redis-cli")),
            StatementAction::Approved
        );
        assert!(p.captured_displays.borrow()[0]
            .descriptions
            .iter()
            .any(|d| d.contains("FLUSHALL")));
    }

    #[test]
    fn cancelled_challenge_blocks_and_audits_once() {
        let f = fixture(None);
        let p = MockPrompter {
            response: ChallengeResult::Denied,
            captured_displays: RefCell::new(Vec::new()),
        };
        assert_eq!(
            analyze_statement("DROP TABLE users", &ctx(&f, &p, "psql")),
            StatementAction::Block
        );
        let log = audit::read_log(&f.config.audit_log_path()).unwrap();
        let lines: Vec<&str> = log.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(lines.len(), 1, "exactly one audit entry: {log}");
        let ev: audit::AuditEvent = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(ev.outcome, audit::AuditOutcome::Cancelled);
        // The same `reason=cancelled` as a shell cancel.
        assert!(lines[0].contains("\"deny_reason\":\"cancelled\""), "{log}");
        assert_eq!(ev.command, "[wrap:psql] DROP TABLE users");
        let shown = p.captured_displays.borrow()[0].effective_challenge;
        assert_eq!(ev.challenge_type, shown.to_string());
    }

    #[test]
    fn deny_rule_audited_as_denied() {
        let mut f = fixture(None);
        f.settings.deny_patterns_ids = vec!["database:drop_table".into()];
        let p = MockPrompter::passing();
        assert_eq!(
            analyze_statement("DROP TABLE users", &ctx(&f, &p, "psql")),
            StatementAction::Block
        );
        let log = audit::read_log(&f.config.audit_log_path()).unwrap();
        let ev: audit::AuditEvent = serde_json::from_str(log.lines().next().unwrap()).unwrap();
        assert_eq!(ev.outcome, audit::AuditOutcome::Denied);
    }

    #[test]
    fn approved_sending_line_names_the_client() {
        // No trailing `…`: the line is complete.
        for (n, unicode, ascii) in [
            (
                1,
                "✓ approved — sending to psql",
                "ok: approved, sending to psql",
            ),
            (
                0,
                "✓ approved — sending to psql",
                "ok: approved, sending to psql",
            ),
            (
                3,
                "✓ approved — sending 3 statements to psql",
                "ok: approved, sending 3 statements to psql",
            ),
        ] {
            let line = approved_sending_line("psql", n);
            assert!(line == unicode || line == ascii, "{line}");
        }
    }

    #[test]
    fn submission_counts_the_statements_a_line_sends() {
        let mut ic = Interceptor::new(resolve("psql").mode);
        for &b in b"DELETE FROM a; DELETE FROM b; SELECT 1;\r" {
            if ic.feed_key(b) == KeyEvent::Enter {
                let sub = ic.take_submission();
                assert_eq!(sub.count, 3, "{}", sub.log_summary());
            }
        }
        let mut ic = Interceptor::new(resolve("psql").mode);
        for &b in b"\\set t users\rDROP TABLE :t;\r" {
            if ic.feed_key(b) == KeyEvent::Enter {
                let sub = ic.take_submission();
                assert!(sub.count <= 1, "{}", sub.log_summary());
            }
        }
    }

    #[test]
    fn approved_statement_audited_as_allowed() {
        let f = fixture(None);
        let p = MockPrompter::passing();
        let _ = analyze_statement("DROP TABLE users", &ctx(&f, &p, "psql"));
        let log = audit::read_log(&f.config.audit_log_path()).unwrap();
        assert_eq!(log.lines().count(), 1);
        let ev: audit::AuditEvent = serde_json::from_str(log.lines().next().unwrap()).unwrap();
        assert_eq!(ev.outcome, audit::AuditOutcome::Allowed);
    }

    #[test]
    fn submission_with_fallback_is_checked() {
        let f = fixture(Some(&["redis"]));
        let p = MockPrompter::passing();
        let sub = Submission {
            statements: vec!["get key".into()],
            fallbacks: vec!["FLUSHALL".into()],
            from_echo: true,
            ..Default::default()
        };
        let d = decide_submission(&sub, &ctx(&f, &p, "redis-cli"), &|_| {});
        assert!(d.forward);
        assert!(d.challenged);
    }

    /// End-to-end through the keystroke model: the known bypasses
    /// (from a DBA's review) must all reach the challenge.
    #[test]
    fn keystroke_bypasses_are_challenged() {
        let f = fixture(None);
        let psql = resolve("psql");
        let cases: &[&[u8]] = &[
            b"UPDATE users\rSET admin = true;\r",
            b"DROP\rTABLE users;\r",
            b"DROP TABLX\x7fE users;\r",
            b"SELECT 1\x15DROP TABLE users;\r",
            b"TRUNCATE TABLE orders \\g\r",
            b"DROP /* x */ TABLE users;\r",
        ];
        for input in cases {
            let p = MockPrompter::passing();
            let mut ic = Interceptor::new(psql.mode);
            let mut challenged = false;
            for &b in *input {
                if ic.feed_key(b) == KeyEvent::Enter {
                    let sub = ic.take_submission();
                    challenged |= decide_submission(&sub, &ctx(&f, &p, "psql"), &|_| {}).challenged;
                }
            }
            assert!(
                challenged,
                "not challenged: {:?}",
                String::from_utf8_lossy(input)
            );
        }

        let redis = resolve("redis-cli");
        let p = MockPrompter::passing();
        let mut ic = Interceptor::new(redis.mode);
        let rf = fixture(Some(&["redis"]));
        let mut challenged = false;
        for &b in b"FLUSHALL\r" {
            if ic.feed_key(b) == KeyEvent::Enter {
                challenged |=
                    decide_submission(&ic.take_submission(), &ctx(&rf, &p, "redis-cli"), &|_| {})
                        .challenged;
            }
        }
        assert!(challenged);

        let mongo = resolve("mongosh");
        let mf = fixture(Some(&["mongodb"]));
        for input in [&b"db.dropDatabase()\r"[..], b"db.users.drop();\r"] {
            let p = MockPrompter::passing();
            let mut ic = Interceptor::new(mongo.mode);
            let mut challenged = false;
            for &b in input {
                if ic.feed_key(b) == KeyEvent::Enter {
                    challenged |=
                        decide_submission(&ic.take_submission(), &ctx(&mf, &p, "mongosh"), &|_| {})
                            .challenged;
                }
            }
            assert!(challenged, "{:?}", String::from_utf8_lossy(input));
        }
    }

    // -- literals, executed sub-statements, meta-commands --

    fn ids_shown(p: &MockPrompter) -> Vec<String> {
        p.captured_displays
            .borrow()
            .iter()
            .flat_map(|d| d.descriptions.clone())
            .collect()
    }

    #[test]
    fn string_literals_are_not_statements() {
        let f = fixture(None);
        let p = MockPrompter::passing();
        for stmt in [
            "INSERT INTO audit VALUES ('DELETE FROM users')",
            "COMMENT ON TABLE users IS 'never DROP TABLE users'",
            "SELECT * FROM t WHERE note = $$TRUNCATE orders$$",
        ] {
            assert_eq!(
                analyze_statement(stmt, &ctx(&f, &p, "psql")),
                StatementAction::Forward,
                "{stmt}"
            );
        }
        assert!(p.captured_displays.borrow().is_empty());
    }

    #[test]
    fn executed_sub_statements_are_checked() {
        let f = fixture(None);
        for stmt in [
            "EXPLAIN ANALYZE DELETE FROM users",
            "PREPARE wipe AS DELETE FROM users",
            "DO $$ BEGIN EXECUTE 'DROP TABLE users'; END $$",
        ] {
            let p = MockPrompter::passing();
            assert_eq!(
                analyze_statement(stmt, &ctx(&f, &p, "psql")),
                StatementAction::Approved,
                "{stmt}"
            );
            let shown = p.captured_displays.borrow();
            assert!(
                shown[0]
                    .severity_label
                    .as_deref()
                    .is_some_and(|s| s.contains("CRITICAL")),
                "{stmt}: {:?}",
                shown[0].severity_label
            );
        }
    }

    fn meta(raw: &str, kind: MetaKind) -> MetaCommand {
        MetaCommand {
            raw: raw.to_string(),
            kind,
        }
    }

    #[test]
    fn include_file_is_scanned() {
        let mut f = fixture(None);
        f.env.files.insert(
            "/tmp/cleanup.sql".into(),
            "SELECT 1;\nDROP TABLE users;\nDELETE FROM orders;\n".into(),
        );
        f.env
            .files
            .insert("/tmp/ok.sql".into(), "SELECT 1;\n".into());
        let risky = meta(
            "\\i cleanup.sql",
            MetaKind::RunFile {
                path: "cleanup.sql".into(),
                relative: false,
            },
        );
        let p = MockPrompter::passing();
        assert_eq!(
            analyze_meta(&risky, &ctx(&f, &p, "psql")),
            StatementAction::Approved
        );
        let desc = ids_shown(&p).join("\n");
        assert!(desc.contains("risky (2)"), "{desc}");
        assert!(desc.contains("database:drop_table"), "{desc}");

        let clean = meta(
            "\\i ok.sql",
            MetaKind::RunFile {
                path: "ok.sql".into(),
                relative: false,
            },
        );
        let p = MockPrompter::passing();
        assert_eq!(
            analyze_meta(&clean, &ctx(&f, &p, "psql")),
            StatementAction::Forward
        );

        let missing = meta(
            "\\i nope.sql",
            MetaKind::RunFile {
                path: "nope.sql".into(),
                relative: false,
            },
        );
        let p = MockPrompter::passing();
        assert_eq!(
            analyze_meta(&missing, &ctx(&f, &p, "psql")),
            StatementAction::Approved
        );
        assert!(ids_shown(&p)[0].contains("contents are not checked"));

        // remote client: the local file is not the file it reads
        let p = MockPrompter::passing();
        let c = StatementContext {
            remote: true,
            ..ctx(&f, &p, "psql")
        };
        assert_eq!(analyze_meta(&clean, &c), StatementAction::Approved);

        // the meta id can be ignored like any check
        let mut f2 = fixture(None);
        f2.settings.ignores_patterns_ids = vec!["wrap:run_file".into()];
        let p = MockPrompter::passing();
        assert_eq!(
            analyze_meta(&missing, &ctx(&f2, &p, "psql")),
            StatementAction::Forward
        );
    }

    /// Run `\i <path>` (or the tool's equivalent) and return the action and
    /// everything the challenge showed (descriptions + check ids).
    fn run_include(f: &Fixture, tool: &str, path: &str) -> (StatementAction, String) {
        let p = MockPrompter::passing();
        let m = meta(
            &format!("\\i {path}"),
            MetaKind::RunFile {
                path: path.into(),
                relative: false,
            },
        );
        let action = analyze_meta(&m, &ctx(f, &p, tool));
        let shown = p
            .captured_displays
            .borrow()
            .iter()
            .flat_map(|d| d.descriptions.iter().chain(d.check_ids.iter()).cloned())
            .collect::<Vec<_>>()
            .join("\n");
        (action, shown)
    }

    #[test]
    fn nested_includes_and_client_commands_in_files_are_scanned() {
        // One level deep only, client commands ignored.
        let mut f = fixture(None);
        f.env.existing_paths.insert("/home/dev/data".into());
        let files: &[(&str, &str)] = &[
            (
                "/tmp/cleanup.sql",
                "DROP TABLE users;\nDELETE FROM orders;\n",
            ),
            ("/tmp/outer.sql", "\\i /tmp/cleanup.sql\n"),
            ("/tmp/nest.sql", "SELECT 1; \\i /tmp/cleanup.sql\n"),
            ("/tmp/shesc.sql", "SELECT 1; \\! rm -rf /home/dev/data\n"),
            ("/tmp/gx.sql", "SELECT 'DROP TABLE users' \\gexec\n"),
            ("/tmp/wpipe.sql", "SELECT 1\n\\w |rm -rf /home/dev/data\n"),
            ("/tmp/sub/a.sql", "\\ir b.sql\n"),
            ("/tmp/sub/b.sql", "TRUNCATE orders;\n"),
            ("/tmp/c1.sql", "\\i /tmp/c2.sql\nSELECT 1;\n"),
            ("/tmp/c2.sql", "\\i /tmp/c1.sql\nSELECT 2;\n"),
            ("/tmp/missing.sql", "SELECT 1;\n\\i /tmp/nope.sql\n"),
            ("/tmp/multi.sql", "DELETE FROM users\nWHERE id = 1;\n"),
            ("/tmp/tail.sql", "SELECT 1;\nTRUNCATE orders\n"),
            ("/tmp/vars.sql", "\\set t users\nDROP TABLE :t;\n"),
            ("/tmp/msrc.sql", "source /tmp/cleanup.sql\n"),
            (
                "/tmp/mdelim.sql",
                "DELIMITER //\nDROP TABLE users//\nDELIMITER ;\nSELECT 1;\n",
            ),
            (
                "/tmp/md2.sql",
                "DELIMITER $$\nTRUNCATE orders$$\nDELIMITER ;\n",
            ),
            ("/tmp/mdok.sql", "DELIMITER //\nSELECT 1//\nDELIMITER ;\n"),
            ("/tmp/ms3.sql", "SELECT 1; \\! rm -rf /home/dev/data\n"),
            ("/tmp/msys.sql", "system rm -rf /home/dev/data\n"),
            ("/tmp/lite.sql", ".read /tmp/cleanup.sql\n"),
            ("/tmp/load1.js", "load('/tmp/load2.js')\n"),
            ("/tmp/load2.js", "db.users.drop()\n"),
            ("/tmp/strdrop.js", "db.users.find({name: \"drop()\"})\n"),
        ];
        for (path, content) in files {
            f.env.files.insert((*path).into(), (*content).into());
        }
        // chain deeper than the cap
        for i in 0..=MAX_INCLUDE_DEPTH + 1 {
            f.env.files.insert(
                format!("/tmp/d{i}.sql").into(),
                format!("\\i /tmp/d{}.sql\n", i + 1),
            );
        }

        let challenged: &[(&str, &str, &str)] = &[
            ("psql", "/tmp/outer.sql", "database:drop_table"),
            ("psql", "/tmp/outer.sql", "in cleanup.sql"),
            ("psql", "/tmp/outer.sql", "1 file it includes"),
            ("psql", "/tmp/nest.sql", "database:delete_all_rows"),
            ("psql", "/tmp/shesc.sql", "fs:"),
            ("psql", "/tmp/gx.sql", "wrap:psql_gexec"),
            ("psql", "/tmp/wpipe.sql", "fs:"),
            ("psql", "/tmp/sub/a.sql", "database:truncate_table"),
            (
                "psql",
                "/tmp/missing.sql",
                "NOT checked: the file could not be read",
            ),
            ("psql", "/tmp/tail.sql", "database:truncate_table"),
            ("psql", "/tmp/vars.sql", "database:drop_table"),
            ("psql", "/tmp/d0.sql", "deeper than"),
            ("mysql", "/tmp/msrc.sql", "database:drop_table"),
            ("mysql", "/tmp/mdelim.sql", "database:drop_table"),
            ("mysql", "/tmp/md2.sql", "database:truncate_table"),
            ("mysql", "/tmp/ms3.sql", "fs:"),
            ("mysql", "/tmp/msys.sql", "fs:"),
            ("sqlite3", "/tmp/lite.sql", "database:drop_table"),
            (
                "mongosh",
                "/tmp/load1.js",
                "mongodb:interactive_drop_collection",
            ),
        ];
        for (tool, path, want) in challenged {
            let (action, shown) = run_include(&f, tool, path);
            assert_eq!(action, StatementAction::Approved, "{tool} {path}: {shown}");
            assert!(
                shown.contains(want),
                "{tool} {path}: want {want:?} in {shown}"
            );
        }

        let clean: &[(&str, &str)] = &[
            ("psql", "/tmp/c1.sql"), // include cycle: terminates, nothing risky
            ("psql", "/tmp/multi.sql"),
            ("mysql", "/tmp/mdok.sql"),
            ("mongosh", "/tmp/strdrop.js"),
        ];
        for (tool, path) in clean {
            let (action, shown) = run_include(&f, tool, path);
            assert_eq!(action, StatementAction::Forward, "{tool} {path}: {shown}");
        }
    }

    #[test]
    fn catalog_checks_apply_in_wrap() {
        // The catalog cases as typed in a wrap session.
        let f = fixture(None);
        let risky: &[(&str, &str, &str)] = &[
            (
                "mysql",
                "ALTER TABLE users DROP INDEX idx_email",
                "database:alter_drop_index",
            ),
            (
                "mysql",
                "ALTER TABLE orders DROP FOREIGN KEY fk_user",
                "database:alter_drop_key",
            ),
            (
                "mysql",
                "PURGE BINARY LOGS BEFORE NOW()",
                "mysql:purge_binary_logs",
            ),
            ("redis-cli", "REPLICAOF 10.0.0.5 6379", "redis:replicaof"),
            ("redis-cli", "SWAPDB 0 1", "redis:swapdb"),
            ("mongosh", "db.users.dropIndexes()", "mongodb:drop_indexes"),
        ];
        for (tool, stmt, id) in risky {
            let p = MockPrompter::passing();
            assert_eq!(
                analyze_statement(stmt, &ctx(&f, &p, tool)),
                StatementAction::Approved,
                "{tool}: {stmt}"
            );
            let ids: Vec<String> = p
                .captured_displays
                .borrow()
                .iter()
                .flat_map(|d| d.check_ids.clone())
                .collect();
            assert!(ids.iter().any(|i| i == id), "{tool}: {stmt}: {ids:?}");
        }
        let clean: &[(&str, &str)] = &[
            ("redis-cli", "REPLICAOF NO ONE"),
            ("mongosh", "db.users.find({name: \"drop()\"})"),
        ];
        for (tool, stmt) in clean {
            let p = MockPrompter::passing();
            assert_eq!(
                analyze_statement(stmt, &ctx(&f, &p, tool)),
                StatementAction::Forward,
                "{tool}: {stmt}"
            );
        }
    }

    #[test]
    fn shell_escape_is_checked_as_shell_command() {
        let mut f = fixture(None);
        f.env.existing_paths.insert("/".into());
        let p = MockPrompter::passing();
        let m = meta(
            "\\! rm -rf /",
            MetaKind::Shell {
                command: "rm -rf /".into(),
            },
        );
        assert_eq!(
            analyze_meta(&m, &ctx(&f, &p, "psql")),
            StatementAction::Approved
        );
        let p = MockPrompter::passing();
        let m = meta(
            "\\! ls",
            MetaKind::Shell {
                command: "ls".into(),
            },
        );
        assert_eq!(
            analyze_meta(&m, &ctx(&f, &p, "psql")),
            StatementAction::Forward
        );
    }

    #[test]
    fn opaque_meta_gets_medium_challenge() {
        let f = fixture(None);
        let p = MockPrompter::passing();
        let m = meta(
            "\\e",
            MetaKind::Opaque {
                id: "wrap:editor",
                what: "editor".into(),
            },
        );
        assert_eq!(
            analyze_meta(&m, &ctx(&f, &p, "psql")),
            StatementAction::Approved
        );
    }

    #[test]
    fn wrap_bypasses_are_challenged() {
        // Earlier bypass repros, end to end through the interceptor (no echo).
        let f = fixture(None);
        let cases: &[(&str, &[u8])] = &[
            (
                "psql",
                b"COMMENT ON TABLE users IS $$Don't touch$$;\rDROP TABLE users;\r",
            ),
            (
                "psql",
                b"UPDATE settings SET path = 'C:\\backups\\' WHERE id = 1;\rDROP TABLE users;\r",
            ),
            ("mysql", b"SELECT 1 # it's fine\r;\rDROP TABLE users;\r"),
            ("mysql", b"use billing\rTRUNCATE invoices;\r"),
            ("mysql", b"delimiter //\rDROP TABLE users//\r"),
            ("sqlite3", b".tables\rDELETE FROM users;\r"),
            ("psql", b"\\set c 'DROP TABLE users'\r:c;\r"),
            ("psql", b"EXPLAIN ANALYZE DELETE FROM users;\r"),
        ];
        for (tool, input) in cases {
            let wc = resolve(tool);
            let p = MockPrompter::passing();
            let mut ic = Interceptor::new(wc.mode);
            let mut challenged = false;
            for &b in *input {
                if ic.feed_key(b) == KeyEvent::Enter {
                    let sub = ic.take_submission();
                    challenged |= decide_submission(&sub, &ctx(&f, &p, tool), &|_| {}).challenged;
                }
            }
            assert!(
                challenged,
                "{tool}: not challenged: {:?}",
                String::from_utf8_lossy(input)
            );
        }
    }

    fn shown_ids(p: &MockPrompter) -> Vec<String> {
        p.captured_displays
            .borrow()
            .iter()
            .flat_map(|d| d.check_ids.clone())
            .collect()
    }

    #[test]
    fn update_with_where_and_parentheses_is_not_update_all_rows() {
        // `now()` / `(SELECT ...)` hid the WHERE clause.
        let f = fixture(None);
        for (tool, stmt) in [
            ("psql", "UPDATE users SET last_login = now() WHERE id = 42"),
            ("mysql", "UPDATE users SET a = NOW() WHERE id = 42"),
            ("psql", "UPDATE users SET a = (SELECT 1) WHERE id = 42"),
            (
                "psql",
                "UPDATE users SET id = gen_random_uuid() WHERE id = 42",
            ),
            (
                "psql",
                "UPDATE t SET a = (SELECT max(b) FROM c WHERE c.x = t.x) WHERE t.id = 7",
            ),
        ] {
            let p = MockPrompter::passing();
            assert_eq!(
                analyze_statement(stmt, &ctx(&f, &p, tool)),
                StatementAction::Forward,
                "{tool}: {stmt}: {:?}",
                shown_ids(&p)
            );
        }
        for stmt in [
            "UPDATE users SET last_login = now()",
            "UPDATE users SET a = (SELECT 1)",
            "UPDATE users SET a = 1 WHERE 'a' = 'a'",
            "WITH d AS (DELETE FROM users RETURNING *) SELECT count(*) FROM d",
        ] {
            let p = MockPrompter::passing();
            assert_eq!(
                analyze_statement(stmt, &ctx(&f, &p, "psql")),
                StatementAction::Approved,
                "{stmt}"
            );
        }
    }

    #[test]
    fn mongosh_other_database_handles_are_checked() {
        let f = fixture(Some(&["mongodb"]));
        for (stmt, id) in [
            (
                "db.getSiblingDB(\"prod\").dropDatabase()",
                "mongodb:interactive_drop_database",
            ),
            (
                "db.getSiblingDB('prod').dropDatabase()",
                "mongodb:interactive_drop_database",
            ),
            (
                "db.getMongo().getDB(\"prod\").dropDatabase()",
                "mongodb:interactive_drop_database",
            ),
            (
                "db.getSiblingDB(\"prod\").users.drop()",
                "mongodb:interactive_drop_collection_indirect",
            ),
            (
                "db.getSiblingDB(\"prod\").getCollection(\"users\").drop()",
                "mongodb:interactive_drop_collection_indirect",
            ),
            (
                "db.getMongo().getDB('prod').users.drop()",
                "mongodb:interactive_drop_collection_indirect",
            ),
        ] {
            let p = MockPrompter::passing();
            assert_eq!(
                analyze_statement(stmt, &ctx(&f, &p, "mongosh")),
                StatementAction::Approved,
                "{stmt}"
            );
            assert!(
                shown_ids(&p).iter().any(|i| i == id),
                "{stmt}: {:?}",
                shown_ids(&p)
            );
        }
        for stmt in [
            "db.getSiblingDB(\"prod\").users.find({name: \"drop()\"})",
            "db.users.find({q: \"db.users.deleteMany({})\"})",
        ] {
            let p = MockPrompter::passing();
            assert_eq!(
                analyze_statement(stmt, &ctx(&f, &p, "mongosh")),
                StatementAction::Forward,
                "{stmt}"
            );
        }
    }

    #[test]
    fn do_blocks_run_their_bodies() {
        // Single-quoted dynamic SQL and `DO '...'`.
        let f = fixture(None);
        for stmt in [
            "DO $$ BEGIN EXECUTE 'DROP TABLE users'; END $$",
            "DO 'BEGIN DROP TABLE users; END'",
            "DO LANGUAGE plpgsql 'BEGIN EXECUTE ''TRUNCATE orders''; END'",
        ] {
            let p = MockPrompter::passing();
            assert_eq!(
                analyze_statement(stmt, &ctx(&f, &p, "psql")),
                StatementAction::Approved,
                "{stmt}"
            );
        }
        let p = MockPrompter::passing();
        assert_eq!(
            analyze_statement("SELECT 'DO nothing'", &ctx(&f, &p, "psql")),
            StatementAction::Forward
        );
    }

    #[test]
    fn do_blocks_with_dynamic_sql_loops_are_checked() {
        // Nested dollar quotes, `format()` placeholders and
        // `||` concatenation inside a `DO` body are code, not data.
        let f = fixture(None);
        for (stmt, id) in [
            (
                "DO $$ BEGIN EXECUTE $q$DROP TABLE users$q$; END $$",
                "database:drop_table",
            ),
            (
                "DO $$ DECLARE r record; BEGIN FOR r IN SELECT tablename FROM pg_tables \
                 WHERE schemaname = $s$public$s$ LOOP EXECUTE format($f$DROP TABLE %I \
                 CASCADE$f$, r.tablename); END LOOP; END $$",
                "database:drop_table",
            ),
            (
                "DO $$ DECLARE r record; BEGIN FOR r IN SELECT tablename FROM pg_tables \
                 WHERE schemaname = 'public' LOOP EXECUTE 'DROP TABLE IF EXISTS ' || \
                 quote_ident(r.tablename) || ' CASCADE'; END LOOP; END $$",
                "database:drop_table",
            ),
            (
                "DO $$ DECLARE t text; BEGIN FOR t IN SELECT tablename FROM pg_tables LOOP \
                 EXECUTE 'TRUNCATE ' || quote_ident(t) || ' CASCADE'; END LOOP; END $$",
                "database:truncate_table",
            ),
            (
                "DO $body$ BEGIN EXECUTE format('TRUNCATE %I', 'orders'); END $body$",
                "database:truncate_table",
            ),
            (
                "DO $$ BEGIN EXECUTE format('DELETE FROM %I.%I', 'public', 'users'); END $$",
                "database:delete_all_rows",
            ),
            (
                "DO $$ BEGIN EXECUTE 'DELETE FROM ' || quote_ident('users'); END $$",
                "database:delete_all_rows",
            ),
            (
                "DO $$ BEGIN EXECUTE 'DROP TABLE users'; END $$",
                "database:drop_table",
            ),
            ("DO 'BEGIN DROP TABLE users; END'", "database:drop_table"),
            (
                "DO LANGUAGE plpgsql $$ BEGIN EXECUTE $x$DROP SCHEMA app CASCADE$x$; END $$",
                "database:drop_schema_cascade",
            ),
        ] {
            let p = MockPrompter::passing();
            assert_eq!(
                analyze_statement(stmt, &ctx(&f, &p, "psql")),
                StatementAction::Approved,
                "{stmt}"
            );
            assert!(
                shown_ids(&p).iter().any(|i| i == id),
                "{stmt}: {:?}",
                shown_ids(&p)
            );
        }
        for stmt in [
            "SELECT $$DROP TABLE users$$",
            "DO $$ BEGIN RAISE NOTICE 'DROP TABLE is not run here'; END $$",
            "DO $$ BEGIN EXECUTE 'DELETE FROM ' || quote_ident(t) || ' WHERE id = ' || \
             quote_literal(i); END $$",
            "DO $$ BEGIN EXECUTE format('DELETE FROM %I WHERE id = %L', t, i); END $$",
            "DO $$ BEGIN EXECUTE format('ANALYZE %I', t); END $$",
        ] {
            let p = MockPrompter::passing();
            assert_eq!(
                analyze_statement(stmt, &ctx(&f, &p, "psql")),
                StatementAction::Forward,
                "{stmt}: {:?}",
                shown_ids(&p)
            );
        }
    }

    #[test]
    fn mongosh_command_documents_are_checked() {
        let f = fixture(Some(&["mongodb"]));
        for (stmt, id) in [
            (
                "db.runCommand({dropDatabase: 1})",
                "mongodb:run_command_drop",
            ),
            (
                "db.getSiblingDB(\"prod\").runCommand({dropDatabase: 1})",
                "mongodb:run_command_drop",
            ),
            (
                "db.runCommand({\"dropDatabase\": 1})",
                "mongodb:run_command_drop",
            ),
            (
                "db.adminCommand({ 'dropDatabase': 1 })",
                "mongodb:run_command_drop",
            ),
            (
                "db.runCommand({drop: \"users\"})",
                "mongodb:run_command_drop",
            ),
            (
                "db.runCommand({delete: \"users\", deletes: [{q: {}, limit: 0}]})",
                "mongodb:run_command_delete_all",
            ),
            (
                "db.users.renameCollection(\"archive\", true)",
                "mongodb:rename_drop_target",
            ),
            (
                "db.adminCommand({renameCollection: \"app.a\", to: \"app.b\", dropTarget: true})",
                "mongodb:rename_drop_target",
            ),
        ] {
            let p = MockPrompter::passing();
            assert_eq!(
                analyze_statement(stmt, &ctx(&f, &p, "mongosh")),
                StatementAction::Approved,
                "{stmt}"
            );
            assert!(
                shown_ids(&p).iter().any(|i| i == id),
                "{stmt}: {:?}",
                shown_ids(&p)
            );
        }
        for stmt in [
            "db.runCommand({ping: 1})",
            "db.runCommand({dropIndexes: \"users\", index: \"email_1\"})",
            "db.runCommand({delete: \"users\", deletes: [{q: {old: true}, limit: 0}]})",
            "db.users.renameCollection(\"archive\")",
            "db.users.find({\"name\": \"db.users.drop()\"})",
            "db.notes.insertOne({text: \"db.runCommand({dropDatabase: 1})\"})",
        ] {
            let p = MockPrompter::passing();
            assert_eq!(
                analyze_statement(stmt, &ctx(&f, &p, "mongosh")),
                StatementAction::Forward,
                "{stmt}: {:?}",
                shown_ids(&p)
            );
        }
    }

    fn startup(f: &Fixture, line: &str) -> (EnterDecision, Vec<String>) {
        let (program, args) = argv(line);
        startup_with(f, &program, &args, None)
    }

    fn startup_with(
        f: &Fixture,
        program: &str,
        args: &[String],
        tool: Option<&str>,
    ) -> (EnterDecision, Vec<String>) {
        let wc = tool.map_or_else(
            || WrapperConfig::resolve(program, args, None, &WrappersConfig::default()),
            |t| {
                let mut wc = WrapperConfig::resolve(t, &[], None, &WrappersConfig::default());
                wc.program = program.to_string();
                wc
            },
        );
        let checks = wc.filter_checks(&f.checks);
        let p = MockPrompter::passing();
        let ctx = StatementContext {
            all_checks: &f.checks,
            dialect: wc.dialect(),
            strip_quotes: wc.strip_quotes,
            remote: wc.remote,
            ..StatementContext::basic(&f.settings, &checks, &f.env, &p, &f.config, &wc.tool)
        };
        let d = check_startup(&wc, program, args, &ctx, &|_| {});
        (d, shown_ids(&p))
    }

    fn words(s: &[&str]) -> Vec<String> {
        s.iter().map(|w| (*w).to_string()).collect()
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn client_command_line_is_checked_before_start() {
        // `shellfirm wrap psql -c ...` never checked its argv.
        let mut f = fixture(None);
        f.env.files.insert(
            "/tmp/cleanup.sql".into(),
            "SELECT 1;\nDROP TABLE users;\n".into(),
        );
        f.env
            .files
            .insert("/tmp/safe.sql".into(), "SELECT 1;\n".into());
        f.env.existing_paths.insert("/home/dev/data".into());
        let cases: Vec<(Vec<String>, Option<&str>, &str)> = vec![
            (
                words(&["psql", "-h", "db", "-c", "DROP TABLE users"]),
                None,
                "database:drop_table",
            ),
            (
                words(&["psql", "--command=TRUNCATE orders"]),
                None,
                "database:truncate_table",
            ),
            (
                words(&["psql", "-f", "cleanup.sql", "prod"]),
                None,
                "database:drop_table",
            ),
            (
                words(&["psql", "-c", "\\! rm -rf /home/dev/data"]),
                None,
                "fs:recursively_delete",
            ),
            (
                words(&[
                    "mysql",
                    "-uroot",
                    "-p",
                    "-e",
                    "DELETE FROM users # WHERE id=1",
                ]),
                None,
                "database:delete_all_rows",
            ),
            (
                words(&[
                    "mongosh",
                    "prod",
                    "--eval",
                    "db.runCommand({dropDatabase: 1})",
                ]),
                None,
                "mongodb:run_command_drop",
            ),
            (
                words(&["sqlite3", "app.db", "DROP TABLE t"]),
                None,
                "database:drop_table",
            ),
            (
                words(&["redis-cli", "-n", "2", "FLUSHDB"]),
                None,
                "redis:interactive_flushdb",
            ),
            (
                words(&["sudo", "-u", "postgres", "psql", "-c", "DROP DATABASE prod"]),
                None,
                "database:drop_database",
            ),
            (
                words(&["./pgw", "-c", "DROP TABLE users"]),
                Some("psql"),
                "database:drop_table",
            ),
            (
                words(&["sqlcmd", "-S", "prod", "-Q", "DROP DATABASE prod"]),
                None,
                "database:drop_database",
            ),
            (
                words(&[
                    "psql",
                    "-c",
                    "DO $$ BEGIN EXECUTE $q$DROP TABLE users$q$; END $$",
                ]),
                None,
                "database:drop_table",
            ),
        ];
        for (line, tool, id) in &cases {
            let (d, ids) = startup_with(&f, &line[0], &line[1..], *tool);
            assert!(d.challenged && d.forward, "{line:?}: {d:?}");
            assert!(ids.iter().any(|i| i.starts_with(id)), "{line:?}: {ids:?}");
        }
        let (d, ids) = startup_with(&f, "psql", &words(&["-c", "SELECT 1"]), None);
        assert!(!d.challenged && d.forward, "{ids:?}");
        for line in [
            "psql -h db -U postgres prod",
            "psql -f safe.sql",
            "mysql -u root -p app",
            "mongosh prod",
            "sqlite3 app.db",
            "redis-cli -h cache",
        ] {
            let (d, ids) = startup(&f, line);
            assert!(!d.challenged && d.forward, "{line}: {ids:?}");
        }
        // A remote client: its `-f` file is not a local file.
        let (d, ids) = startup(&f, "docker exec -it db psql -f safe.sql");
        assert!(d.challenged, "{ids:?}");
        assert!(ids.iter().any(|i| i == "wrap:run_file"), "{ids:?}");
        // An unknown program: its command line is checked as a shell command.
        let (d, ids) = startup_with(&f, "bash", &words(&["-c", "rm -rf /home/dev/data"]), None);
        assert!(d.challenged, "{ids:?}");
        let (d, ids) = startup_with(&f, "bash", &words(&["-l"]), None);
        assert!(!d.challenged, "{ids:?}");
    }

    #[test]
    fn declined_command_line_is_not_started() {
        let f = fixture(None);
        let wc = resolve("psql -c x");
        let checks = wc.filter_checks(&f.checks);
        let p = MockPrompter {
            response: ChallengeResult::Denied,
            captured_displays: RefCell::new(Vec::new()),
        };
        let ctx = StatementContext {
            dialect: wc.dialect(),
            ..StatementContext::basic(&f.settings, &checks, &f.env, &p, &f.config, "psql")
        };
        let args = words(&["-c", "DROP TABLE users"]);
        let d = check_startup(&wc, "psql", &args, &ctx, &|_| {});
        assert!(!d.forward);
    }

    #[test]
    fn include_relative_resolves_from_the_including_file() {
        // `\ir b.sql` inside sub/a.sql is sub/b.sql, even when
        // the working directory has a b.sql too.
        let mut f = fixture(None);
        f.env
            .files
            .insert("/tmp/sub/a.sql".into(), "\\ir b.sql\n".into());
        f.env
            .files
            .insert("/tmp/sub/b.sql".into(), "DROP TABLE users;\n".into());
        f.env
            .files
            .insert("/tmp/b.sql".into(), "SELECT 1;\n".into());
        let (action, shown) = run_include(&f, "psql", "sub/a.sql");
        assert_eq!(action, StatementAction::Approved, "{shown}");
        assert!(shown.contains("database:drop_table"), "{shown}");

        // reversed: the cwd file is risky, the one psql runs is not
        f.env
            .files
            .insert("/tmp/sub/b.sql".into(), "SELECT 1;\n".into());
        f.env
            .files
            .insert("/tmp/b.sql".into(), "TRUNCATE orders;\n".into());
        let (action, shown) = run_include(&f, "psql", "sub/a.sql");
        assert_eq!(action, StatementAction::Forward, "{shown}");

        // `\i` inside a file resolves against the working directory
        f.env
            .files
            .insert("/tmp/sub/c.sql".into(), "\\i b.sql\n".into());
        let (action, shown) = run_include(&f, "psql", "sub/c.sql");
        assert_eq!(action, StatementAction::Approved, "{shown}");
        assert!(shown.contains("database:truncate_table"), "{shown}");
    }

    #[test]
    fn include_path_variables_and_sqlite_pipes() {
        // `\i :d/x.sql` and sqlite3 pipes inside files.
        let mut f = fixture(None);
        f.env.existing_paths.insert("/home/dev/data".into());
        f.env.files.insert(
            "/tmp/vars2.sql".into(),
            "\\set d /tmp/lib\n\\i :d/cleanup.sql\n".into(),
        );
        f.env
            .files
            .insert("/tmp/lib/cleanup.sql".into(), "TRUNCATE orders;\n".into());
        f.env.files.insert(
            "/tmp/lpipe.sql".into(),
            ".once '|rm -rf /home/dev/data'\nSELECT 1;\n".into(),
        );
        f.env.files.insert(
            "/tmp/lread.sql".into(),
            ".read '|rm -rf /home/dev/data'\n".into(),
        );
        for (tool, path, want) in [
            ("psql", "/tmp/vars2.sql", "database:truncate_table"),
            ("sqlite3", "/tmp/lpipe.sql", "fs:"),
            ("sqlite3", "/tmp/lread.sql", "wrap:run_command_output"),
            ("sqlite3", "/tmp/lread.sql", "fs:"),
        ] {
            let (action, shown) = run_include(&f, tool, path);
            assert_eq!(action, StatementAction::Approved, "{path}: {shown}");
            assert!(shown.contains(want), "{path}: want {want} in {shown}");
        }

        // typed: `.read '|cmd'` checks the command and says its output runs
        let p = MockPrompter::passing();
        let m = meta(
            ".read '|rm -rf /home/dev/data'",
            MetaKind::ShellToSql {
                command: "rm -rf /home/dev/data".into(),
            },
        );
        assert_eq!(
            analyze_meta(&m, &ctx(&f, &p, "sqlite3")),
            StatementAction::Approved
        );
        let ids = shown_ids(&p);
        assert!(
            ids.iter().any(|i| i == "wrap:run_command_output"),
            "{ids:?}"
        );
        assert!(ids.iter().any(|i| i.starts_with("fs:")), "{ids:?}");
    }

    #[test]
    fn large_files_are_fully_scanned_or_reported() {
        // The tail of a file over 1 MiB was silently skipped.
        let mut f = fixture(None);
        let mut big = String::new();
        while big.len() < (3 << 20) {
            big.push_str("INSERT INTO t VALUES (1, 'padding padding padding padding');\n");
        }
        big.push_str("TRUNCATE orders;\n");
        f.env.files.insert("/tmp/big.sql".into(), big);
        let (action, shown) = run_include(&f, "psql", "/tmp/big.sql");
        assert_eq!(action, StatementAction::Approved, "{shown}");
        assert!(shown.contains("database:truncate_table"), "{shown}");

        // over the cap: a Medium "not fully checked" finding, even when the
        // part that was read is clean
        let mut f2 = fixture(None);
        let mut clean = String::new();
        while clean.len() < 4096 {
            clean.push_str("SELECT 1;\n");
        }
        clean.push_str("DROP TABLE users;\n");
        f2.env.files.insert("/tmp/cap.sql".into(), clean);
        let p = MockPrompter::passing();
        let c = ctx(&f2, &p, "psql");
        let pipeline = run_file_pipeline_capped("/tmp/cap.sql", &c, 1024).expect("finding");
        let desc: Vec<&str> = pipeline
            .active_matches
            .iter()
            .map(|m| m.description.as_str())
            .collect();
        assert!(
            desc.iter().any(|d| d.contains("file too large to check (")),
            "{desc:?}"
        );
        assert!(pipeline
            .active_matches
            .iter()
            .all(|m| m.id == "wrap:run_file"));
    }

    #[test]
    fn files_are_streamed_from_disk() {
        // A live session reads included files line by line from disk
        // (also files that are not valid UTF-8).
        let tree = tree_fs::TreeBuilder::default().create().expect("tree");
        let path = tree.root.join("latin1.sql");
        let mut bytes = b"INSERT INTO t VALUES ('caf\xe9');\n".to_vec();
        bytes.extend_from_slice(b"DELETE FROM users;\n");
        std::fs::write(&path, bytes).unwrap();
        let f = fixture(None);
        let p = MockPrompter::passing();
        let c = StatementContext {
            stream_files: true,
            ..ctx(&f, &p, "psql")
        };
        let pipeline = run_file_pipeline_capped(&path.display().to_string(), &c, MAX_SCAN_BYTES)
            .expect("risky");
        assert!(pipeline
            .active_matches
            .iter()
            .any(|m| m.id == "database:delete_all_rows"));
        let pipeline =
            run_file_pipeline_capped(&path.display().to_string(), &c, 10).expect("truncated");
        assert!(pipeline
            .active_matches
            .iter()
            .any(|m| m.description.contains("file too large to check (")));
    }

    #[cfg(unix)]
    #[test]
    fn fifos_and_devices_are_never_opened() {
        // `wrap psql -f /tmp/fifo` hung, `-f /dev/tty` read
        // the keyboard. Like the hook: an immediate Medium, nothing opened.
        let tree = tree_fs::TreeBuilder::default().create().expect("tree");
        let fifo = tree.root.join("fifo");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRWXU).unwrap();
        let inc = tree.root.join("inc.sql");
        std::fs::write(&inc, format!("SELECT 1;\n\\i {}\n", fifo.display())).unwrap();
        let f = fixture(None);
        let p = MockPrompter::passing();
        let c = StatementContext {
            stream_files: true,
            ..ctx(&f, &p, "psql")
        };
        for path in [
            fifo.display().to_string(),
            "/dev/tty".to_string(),
            "/dev/zero".to_string(),
            inc.display().to_string(),
        ] {
            let pipeline = run_file_pipeline_capped(&path, &c, MAX_SCAN_BYTES).expect("finding");
            assert!(
                pipeline.active_matches.iter().any(
                    |m| m.id == "wrap:run_file" && m.description.contains("not a regular file")
                ),
                "{path}: {:?}",
                pipeline.active_matches
            );
            assert_eq!(pipeline.max_severity, checks::Severity::Medium, "{path}");
        }
        assert!(run_file_pipeline_capped("/dev/null", &c, MAX_SCAN_BYTES).is_none());
    }

    #[test]
    fn live_rules_reload_when_the_settings_file_changes() {
        // `config deny` in another terminal applies to an open
        // session.
        let tree = tree_fs::TreeBuilder::default().create().expect("tree");
        let file = tree.root.join("settings.yaml");
        std::fs::write(&file, "a").unwrap();
        let settings = Settings::default();
        let all = settings.get_active_checks().unwrap();
        let wc = resolve("psql");
        let checks = wc.filter_checks(&all);
        let reload = || {
            let mut s = Settings::default();
            s.deny_patterns_ids = vec!["database:drop_table".into()];
            let c = s.get_active_checks().ok()?;
            Some((s, c))
        };
        let mut rules = LiveRules::new(&settings, &checks, &all, &wc)
            .watching(vec![file.clone()], Some(&reload));
        assert!(!rules.refresh(), "unchanged file: no reload");
        assert!(rules.settings.deny_patterns_ids.is_empty());
        std::fs::write(&file, "changed: true\n").unwrap();
        assert!(rules.refresh());
        assert_eq!(
            rules.settings.deny_patterns_ids,
            vec!["database:drop_table"]
        );
        assert!(rules
            .checks
            .iter()
            .all(|c| wc.check_groups.contains(&c.from)));

        let f = fixture(None);
        let p = MockPrompter::passing();
        let c = StatementContext {
            stream_files: false,
            ..rules.context(&f.env, &p, &f.config)
        };
        assert_eq!(
            analyze_statement("DROP TABLE users", &c),
            StatementAction::Block
        );
    }

    #[test]
    fn statements_after_a_with_clause_are_checked() {
        // `WITH x AS (...) DELETE FROM users` ran unchecked.
        let mut f = fixture(None);
        for tool in ["psql", "mysql"] {
            for (stmt, id) in [
                (
                    "WITH x AS (SELECT 1) DELETE FROM users",
                    "database:delete_all_rows",
                ),
                (
                    "WITH old AS (SELECT id FROM users WHERE id < 5) DELETE FROM users",
                    "database:delete_all_rows",
                ),
                (
                    "with x as (select 1) delete from users",
                    "database:delete_all_rows",
                ),
                (
                    "WITH x AS (SELECT 1) UPDATE users SET a = 1",
                    "database:update_all_rows",
                ),
                (
                    "WITH RECURSIVE t(n) AS (SELECT 1), u AS (SELECT 2) DELETE FROM users",
                    "database:delete_all_rows",
                ),
            ] {
                let p = MockPrompter::passing();
                assert_eq!(
                    analyze_statement(stmt, &ctx(&f, &p, tool)),
                    StatementAction::Approved,
                    "{tool}: {stmt}"
                );
                assert!(shown_ids(&p).iter().any(|i| i == id), "{tool}: {stmt}");
            }
            // The outer statement's own WHERE / USING ... WHERE counts.
            for stmt in [
                "WITH old AS (SELECT id FROM users WHERE id < 5) \
                 DELETE FROM users WHERE id IN (SELECT id FROM old)",
                "WITH s AS (SELECT id FROM t) DELETE FROM users USING s WHERE users.id = s.id",
                "WITH x AS (SELECT 1) UPDATE users SET a = 1 WHERE id = 7",
                "WITH x AS (DELETE FROM users WHERE id = 1 RETURNING *) SELECT * FROM x",
                "WITH x AS (SELECT 1) SELECT * FROM x",
            ] {
                let p = MockPrompter::passing();
                assert_eq!(
                    analyze_statement(stmt, &ctx(&f, &p, tool)),
                    StatementAction::Forward,
                    "{tool}: {stmt}: {:?}",
                    shown_ids(&p)
                );
            }
        }
        // ... also inside an included file.
        f.env.files.insert(
            "/tmp/w.sql".into(),
            "WITH x AS (SELECT 1) DELETE FROM users;\n".into(),
        );
        let (action, shown) = run_include(&f, "psql", "w.sql");
        assert_eq!(action, StatementAction::Approved);
        assert!(shown.contains("database:delete_all_rows"), "{shown}");
    }

    #[test]
    fn dropping_a_table_the_script_created_is_not_critical() {
        let mut f = fixture(None);
        f.env.files.insert(
            "/tmp/import.sql".into(),
            "CREATE TEMP TABLE t_import (id int, name text);\n\
             INSERT INTO users SELECT * FROM t_import;\n\
             DROP TABLE t_import;\n\
             CREATE TEMPORARY TABLE \"T2\" AS SELECT 1;\n\
             DROP TABLE IF EXISTS t2, pg_temp.t_import CASCADE;\n"
                .into(),
        );
        let (action, shown) = run_include(&f, "psql", "import.sql");
        assert_eq!(action, StatementAction::Forward, "{shown}");

        f.env.files.insert(
            "/tmp/staging.sql".into(),
            "CREATE TABLE staging_x (id int);\nDROP TABLE staging_x;\n".into(),
        );
        let p = MockPrompter::passing();
        let m = meta(
            "\\i staging.sql",
            MetaKind::RunFile {
                path: "staging.sql".into(),
                relative: false,
            },
        );
        assert_eq!(
            analyze_meta(&m, &ctx(&f, &p, "psql")),
            StatementAction::Approved
        );
        {
            let shown = p.captured_displays.borrow();
            let d = shown.last().expect("challenged");
            assert!(
                d.matched.iter().any(|m| m.id == "database:drop_table"
                    && m.severity == checks::Severity::Low.to_string()),
                "{:?}",
                d.matched
            );
            assert!(
                !d.matched
                    .iter()
                    .any(|m| m.severity == checks::Severity::Critical.to_string()),
                "{:?}",
                d.matched
            );
        }

        // A table that was not created by the script (or may have existed:
        // IF NOT EXISTS) keeps its Critical drop.
        for (name, text) in [
            (
                "/tmp/other.sql",
                "CREATE TEMP TABLE t_import (id int);\nDROP TABLE users, t_import;\n",
            ),
            (
                "/tmp/ine.sql",
                "CREATE TABLE IF NOT EXISTS users (id int);\nDROP TABLE users;\n",
            ),
            (
                "/tmp/before.sql",
                "DROP TABLE t;\nCREATE TEMP TABLE t (id int);\n",
            ),
        ] {
            f.env.files.insert(name.into(), text.into());
            let p = MockPrompter::passing();
            let m = meta(
                &format!("\\i {name}"),
                MetaKind::RunFile {
                    path: name.into(),
                    relative: false,
                },
            );
            assert_eq!(
                analyze_meta(&m, &ctx(&f, &p, "psql")),
                StatementAction::Approved,
                "{name}"
            );
            let d = p.captured_displays.borrow();
            let d = d.last().expect("challenged");
            assert!(
                d.matched.iter().any(|m| m.id == "database:drop_table"
                    && m.severity == checks::Severity::Critical.to_string()),
                "{name}: {:?}",
                d.matched
            );
        }
    }

    #[test]
    fn init_command_and_sqlcmd_input_files_are_checked_before_start() {
        let mut f = fixture(None);
        f.env.files.insert(
            "/tmp/cleanup.sql".into(),
            "SELECT 1;\nDROP TABLE users;\n".into(),
        );
        f.env
            .files
            .insert("/tmp/safe.sql".into(), "SELECT 1;\n".into());
        for (line, id) in [
            (
                words(&["mysql", "--init-command=DROP TABLE users", "prod"]),
                "database:drop_table",
            ),
            (
                words(&["mysql", "--init-command", "DELETE FROM users", "prod"]),
                "database:delete_all_rows",
            ),
            (
                words(&[
                    "sqlcmd",
                    "-S",
                    "prod",
                    "-U",
                    "sa",
                    "-P",
                    "pw",
                    "-i",
                    "cleanup.sql",
                ]),
                "database:drop_table",
            ),
            (
                words(&["sqlcmd", "-S", "prod", "-i", "safe.sql,cleanup.sql"]),
                "database:drop_table",
            ),
            (
                words(&["psql", "-c", "WITH x AS (SELECT 1) DELETE FROM users"]),
                "database:delete_all_rows",
            ),
        ] {
            let (d, ids) = startup_with(&f, &line[0], &line[1..], None);
            assert!(d.challenged && d.forward, "{line:?}: {d:?}");
            assert!(ids.iter().any(|i| i == id), "{line:?}: {ids:?}");
        }
        for line in [
            words(&["mysql", "--init-command=SET NAMES utf8mb4", "prod"]),
            words(&["sqlcmd", "-S", "prod", "-i", "safe.sql"]),
        ] {
            let (d, ids) = startup_with(&f, &line[0], &line[1..], None);
            assert!(!d.challenged && d.forward, "{line:?}: {ids:?}");
        }
    }

    // -- client commands, session state and input files --

    /// Type `input` into one session of `tool` (one [`SessionTables`] for
    /// every line); returns, per Enter, the decision and the check ids
    /// shown.
    fn type_session(
        f: &Fixture,
        tool: &str,
        input: &[u8],
        session: Option<&SessionTables>,
    ) -> Vec<(EnterDecision, Vec<String>)> {
        let wc = resolve(tool);
        let mut ic = Interceptor::new(wc.mode);
        let mut out = Vec::new();
        for &b in input {
            if ic.feed_key(b) == KeyEvent::Enter {
                let sub = ic.take_submission();
                let p = MockPrompter::passing();
                let c = StatementContext {
                    session,
                    ..ctx(f, &p, tool)
                };
                let d = decide_submission(&sub, &c, &|_| {});
                out.push((d, shown_ids(&p)));
            }
        }
        out
    }

    #[test]
    fn sqlcmd_client_commands_are_checked() {
        // `!!cmd`, `:!! cmd` and `:r file` run commands and files: checked.
        let mut f = fixture(None);
        f.env.existing_paths.insert("/home/dev/data".into());
        f.env.files.insert(
            "/tmp/cleanup.sql".into(),
            "SELECT 1\nGO\nDROP TABLE users\nGO\n".into(),
        );
        f.env
            .files
            .insert("/tmp/safe.sql".into(), "SELECT 1\nGO\n".into());
        for (input, id) in [
            (&b"!!rm -rf /home/dev/data\r"[..], "fs:"),
            (b":!! rm -rf /home/dev/data\r", "fs:"),
            (b"  :!!rm -rf /home/dev/data\r", "fs:"),
            (b":r /tmp/cleanup.sql\r", "database:drop_table"),
            (b":R cleanup.sql\r", "database:drop_table"),
            (b":r \"/tmp/missing.sql\"\r", "wrap:run_file"),
            (b":ed\r", "wrap:editor"),
            // A command line inside a batch is still a command.
            (b"SELECT 1\r!!rm -rf /home/dev/data\r", "fs:"),
            // `GO` ends the batch: a statement without `;` is checked.
            (b"DELETE FROM users\rGO\r", "database:delete_all_rows"),
            (b"DROP TABLE users\rgo 2\r", "database:drop_table"),
            (
                b"SELECT 1\r:exit(DROP TABLE users)\r",
                "database:drop_table",
            ),
        ] {
            let results = type_session(&f, "sqlcmd", input, None);
            let ids: Vec<String> = results.iter().flat_map(|(_, i)| i.clone()).collect();
            assert!(
                results.iter().any(|(d, _)| d.challenged),
                "{:?}: {results:?}",
                String::from_utf8_lossy(input)
            );
            assert!(
                ids.iter().any(|i| i.starts_with(id)),
                "{:?}: {ids:?}",
                String::from_utf8_lossy(input)
            );
        }
        for input in [
            &b"SELECT name FROM sys.databases\rGO\r"[..],
            b":r /tmp/safe.sql\r",
            b":setvar db app\r:out /tmp/x.txt\r!!\r",
            b"SELECT 'it''s' AS a, [my table].x FROM [my table]\rGO\r",
            b"DELETE FROM users WHERE id = 7\rGO\r",
        ] {
            let results = type_session(&f, "sqlcmd", input, None);
            assert!(
                results.iter().all(|(d, _)| d.forward && !d.challenged),
                "{:?}: {results:?}",
                String::from_utf8_lossy(input)
            );
        }

        // ... and in input files (`sqlcmd -i`) and `:r` files.
        f.env.files.insert(
            "/tmp/bang.sql".into(),
            "SELECT 1;\n!!rm -rf /home/dev/data\n".into(),
        );
        f.env.files.insert(
            "/tmp/inc.sql".into(),
            "SELECT 1\nGO\n:r cleanup.sql\n".into(),
        );
        for (line, id) in [
            (
                words(&["sqlcmd", "-S", "prod", "-i", "/tmp/bang.sql"]),
                "fs:",
            ),
            (
                words(&["sqlcmd", "-S", "prod", "-i", "inc.sql"]),
                "database:drop_table",
            ),
            (
                words(&["sqlcmd", "-S", "prod", "-Q", "DELETE FROM users"]),
                "database:delete_all_rows",
            ),
        ] {
            let (d, ids) = startup_with(&f, &line[0], &line[1..], None);
            assert!(d.challenged && d.forward, "{line:?}: {d:?}");
            assert!(ids.iter().any(|i| i.starts_with(id)), "{line:?}: {ids:?}");
        }
    }

    #[test]
    fn temp_tables_created_in_the_session_are_not_critical_to_drop() {
        // Wrap's file scan, the hook and the interactive
        // session must agree: a temp table the session created is not a
        // Critical drop; a real table is.
        let f = fixture(None);
        let critical = |r: &[(EnterDecision, Vec<String>)]| {
            r.iter()
                .any(|(_, ids)| ids.iter().any(|i| i == "database:drop_table"))
        };
        for (tool, input) in [
            (
                "psql",
                &b"CREATE TEMP TABLE t_import (id int);\rDROP TABLE t_import;\r"[..],
            ),
            ("psql", b"CREATE TEMP TABLE t (id int); DROP TABLE t;\r"),
            (
                "mysql",
                b"CREATE TEMPORARY TABLE t_import (id int);\rDROP TABLE t_import;\r",
            ),
            (
                "sqlcmd",
                b"CREATE TABLE #t (id int)\rGO\rDROP TABLE #t\rGO\r",
            ),
        ] {
            let session = SessionTables::default();
            let r = type_session(&f, tool, input, Some(&session));
            assert!(!critical(&r), "{tool}: {r:?}");
            assert!(r.iter().all(|(d, _)| d.forward && !d.challenged), "{r:?}");
        }
        for (tool, input) in [
            // A real table.
            ("psql", &b"DROP TABLE users;\r"[..]),
            // Dropped twice: the second DROP is the real table's.
            (
                "psql",
                b"CREATE TEMP TABLE users (id int);\rDROP TABLE users;\rDROP TABLE users;\r",
            ),
            // A rollback undoes the CREATE.
            (
                "psql",
                b"BEGIN;\rCREATE TEMP TABLE users (id int);\rROLLBACK;\rDROP TABLE users;\r",
            ),
            // A new connection has none of the old temp tables.
            (
                "psql",
                b"CREATE TEMP TABLE users (id int);\r\\c other\rDROP TABLE users;\r",
            ),
            // `ON COMMIT DROP`: gone after the transaction.
            (
                "psql",
                b"CREATE TEMP TABLE users (id int) ON COMMIT DROP;\rDROP TABLE users;\r",
            ),
            // A permanent table created in the session keeps its Critical.
            (
                "psql",
                b"CREATE TABLE staging (id int);\rDROP TABLE staging;\r",
            ),
            // One temp and one real table.
            (
                "psql",
                b"CREATE TEMP TABLE t (id int);\rDROP TABLE t, users;\r",
            ),
        ] {
            let session = SessionTables::default();
            let r = type_session(&f, tool, input, Some(&session));
            assert!(
                critical(&r),
                "{tool}: {:?}: {r:?}",
                String::from_utf8_lossy(input)
            );
        }
        // A CREATE on a line that was not sent is not remembered.
        let session = SessionTables::default();
        let f2 = fixture(None);
        let wc = resolve("psql");
        let mut ic = Interceptor::new(wc.mode);
        for &b in b"CREATE TEMP TABLE users (id int); DROP TABLE accounts;\r" {
            if ic.feed_key(b) == KeyEvent::Enter {
                let p = MockPrompter {
                    response: ChallengeResult::Denied,
                    captured_displays: RefCell::new(Vec::new()),
                };
                let c = StatementContext {
                    session: Some(&session),
                    ..ctx(&f2, &p, "psql")
                };
                assert!(!decide_submission(&ic.take_submission(), &c, &|_| {}).forward);
            }
        }
        let r = type_session(&f2, "psql", b"DROP TABLE users;\r", Some(&session));
        assert!(critical(&r), "{r:?}");

        // The command line (`wrap psql -c "..."`) agrees with `-f`.
        let (d, ids) = startup_with(
            &f,
            "psql",
            &words(&["-c", "CREATE TEMP TABLE t (id int); DROP TABLE t"]),
            None,
        );
        assert!(!d.challenged && d.forward, "{ids:?}");
    }

    #[test]
    fn psql_variable_as_destructive_target_is_high() {
        // `SELECT 'users' AS t \gset` then `TRUNCATE :"t";`: the target is
        // not known.
        let f = fixture(None);
        for input in [
            &b"SELECT 'users' AS t \\gset\rTRUNCATE :\"t\";\r"[..],
            b"TRUNCATE TABLE :t;\r",
            b"TRUNCATE ONLY public.:\"t\";\r",
            b"DROP VIEW IF EXISTS :v;\r",
        ] {
            let r = type_session(&f, "psql", input, None);
            let ids: Vec<String> = r.iter().flat_map(|(_, i)| i.clone()).collect();
            assert!(
                ids.iter().any(|i| i == "wrap:sql_variable_target"),
                "{:?}: {r:?}",
                String::from_utf8_lossy(input)
            );
        }
        // The value is known (`\set`): the real table is checked instead;
        // and a variable in a WHERE / a value is not a target.
        for input in [
            &b"\\set t users\rTRUNCATE :\"t\";\r"[..],
            b"SELECT * FROM users WHERE id = :id;\r",
            b"DELETE FROM users WHERE id = :id;\r",
            b"SELECT now()::date;\r",
        ] {
            let r = type_session(&f, "psql", input, None);
            let ids: Vec<String> = r.iter().flat_map(|(_, i)| i.clone()).collect();
            assert!(
                !ids.iter().any(|i| i == "wrap:sql_variable_target"),
                "{:?}: {r:?}",
                String::from_utf8_lossy(input)
            );
        }
        // Its severity is High.
        let p = MockPrompter::passing();
        let m = meta(
            "TRUNCATE :\"t\"",
            MetaKind::UnknownTarget { what: "x".into() },
        );
        assert_eq!(
            analyze_meta(&m, &ctx(&f, &p, "psql")),
            StatementAction::Approved
        );
        let d = p.captured_displays.borrow();
        assert!(d[0]
            .matched
            .iter()
            .any(|m| m.severity == checks::Severity::High.to_string()));
    }

    #[test]
    fn scan_notice_names_the_file_and_its_size() {
        let t = ScanNotice::text("s500k.sql", Some(15 << 20));
        assert!(
            t == "shellfirm: checking s500k.sql (15 MiB)…"
                || t == "shellfirm: checking s500k.sql (15 MiB)...",
            "{t}"
        );
        let t = ScanNotice::text("up.sql", Some(10));
        assert!(t.starts_with("shellfirm: checking up.sql"), "{t}");
        assert!(!t.contains("MiB"), "{t}");
        // Outside a live session (tests, `stream_files: false`) nothing is
        // started.
        let f = fixture(None);
        let p = MockPrompter::passing();
        let n = ScanNotice::start(Path::new("/tmp/x.sql"), &ctx(&f, &p, "psql"));
        assert!(n.handle.is_none());
    }
}
