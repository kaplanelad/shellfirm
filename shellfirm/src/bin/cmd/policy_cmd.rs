use std::path::{Path, PathBuf};

use clap::{Arg, ArgAction, ArgMatches, Command};
use shellfirm::error::Result;
use shellfirm::{
    config,
    env::{Environment, RealEnvironment},
    policy, Config,
};

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
                .about("Validate .shellfirm.yaml policy files")
                .long_about(
                    "Validate a policy file. Without FILE, every policy that applies to the \
                     current directory is validated (the org policy, then nested files up to the \
                     outermost repository root).\n\n\
                     Detects YAML/syntax errors, unknown keys, unknown, wildcard or duplicate check \
                     ids, checks that shadow built-in ids, invalid regexes, invalid values and \
                     control characters in descriptions. Ids are checked against the built-in \
                     catalog and the policy's own checks only (never your personal custom \
                     checks), so the result is the same on every machine and in CI. Runtime and \
                     `shellfirm status` report exactly the same errors.\n\n\
                     A file is reported in one of three states, here and in `shellfirm status` / \
                     `policy show`:\n  \
                     invalid, NOT applied   fatal problem (bad YAML, missing or unsupported \
                     `version`, unreadable): nothing from the file is enforced\n  \
                     applied, with errors   the valid parts are enforced, the invalid entries \
                     are left out (a policy only adds rules, so this is the safe choice)\n  \
                     valid with warnings    everything is enforced; `--strict` treats the \
                     warnings as errors\n\n\
                     Exit codes: 0 = valid, 65 = invalid or applied with errors (or warnings \
                     with --strict; FILE is a directory), 66 = no policy file found (or FILE \
                     does not exist), 2 = usage error (a bad flag or --format), 74 = the result \
                     could not be written. Use `--strict` in CI.\n\n\
                     The warnings include an org policy file, or its directory, that you can \
                     write (like `shellfirm status`).\n\n\
                     The report is printed on stdout.\n\n\
                     `--format json` prints one document (same exit codes): \
                     {\"schema_version\": 1, \"version\": \"<shellfirm version>\", \"valid\": \
                     bool, \"strict\": bool, \"files\": [{\"path\", \"valid\", \"applied\", \
                     \"errors\": [..], \"warnings\": [..], \"notes\": [..]}], \"warnings\": [..]} \
                     (\"valid\" is the verdict after --strict; \"applied\" is false only for a \
                     file that is not applied at all; when no policy is found, every key is \
                     still present and \"error\" explains why: {\"schema_version\": 1, \
                     \"version\": \"...\", \"valid\": false, \"strict\": bool, \"files\": [], \
                     \"warnings\": [], \"error\": \"...\"}).",
                )
                .arg(Arg::new("file").help("Path to the policy file"))
                .arg(
                    Arg::new("strict")
                        .long("strict")
                        .help("Treat warnings as errors (for CI)")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("format")
                        .long("format")
                        .value_parser(["text", "json"])
                        .default_value("text")
                        .help("Output format"),
                ),
        )
        .subcommand(
            Command::new("show")
                .about("Show the effective (merged) policy for the current directory and where it comes from")
                .arg(
                    Arg::new("format")
                        .long("format")
                        .value_parser(["text", "json"])
                        .default_value("text")
                        .help("Output format"),
                ),
        )
}

fn exit(code: i32, message: impl Into<String>) -> shellfirm::CmdExit {
    shellfirm::CmdExit {
        code,
        message: Some(message.into()),
    }
}

pub fn run(matches: &ArgMatches, config: &Config) -> Result<shellfirm::CmdExit> {
    match matches.subcommand() {
        Some(("init", _)) => Ok(run_init()),
        Some(("validate", sub)) => Ok(run_validate(
            config,
            sub.get_one::<String>("file").map(String::as_str),
            sub.get_flag("strict"),
            sub.get_one::<String>("format").map(String::as_str) == Some("json"),
        )),
        Some(("show", sub)) => run_show(
            config,
            sub.get_one::<String>("format")
                .map_or("text", String::as_str),
        ),
        _ => Ok(exit(exitcode::USAGE, "Unknown policy subcommand.")),
    }
}

fn run_init() -> shellfirm::CmdExit {
    let path = PathBuf::from(policy::POLICY_FILENAME);
    if path.exists() {
        return exit(
            exitcode::USAGE,
            ".shellfirm.yaml already exists in this directory.",
        );
    }
    if let Err(e) = std::fs::write(&path, policy::scaffold_policy()) {
        return exit(
            exitcode::CANTCREAT,
            format!("could not create .shellfirm.yaml: {e}"),
        );
    }
    let env = RealEnvironment;
    let cwd = env.current_dir().unwrap_or_default();
    let parents: Vec<PathBuf> = policy::policy_files(&env, &cwd)
        .0
        .into_iter()
        .filter(|p| p.parent() != Some(cwd.as_path()))
        .collect();
    let mut msg = "Created .shellfirm.yaml template.".to_string();
    if !parents.is_empty() {
        msg.push_str("\nNote: parent policies also apply here: ");
        msg.push_str(
            &parents
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
        );
        msg.push_str("\n      This file adds to them; it cannot remove their rules.");
    }
    exit(exitcode::OK, msg)
}

/// The user's personal custom check ids (only used to improve messages).
fn personal_ids(config: &Config) -> std::collections::HashSet<String> {
    config::load_custom_checks_report(&config.custom_checks_dir())
        .checks
        .into_iter()
        .map(|c| c.id)
        .collect()
}

/// One validated policy file.
struct FileReport {
    path: PathBuf,
    /// `false` when the file has errors (or could not be read).
    valid: bool,
    errors: Vec<String>,
    warnings: Vec<String>,
    notes: Vec<String>,
    /// The file could be read (a read error is reported on one line).
    read: bool,
    /// The file is applied at runtime (the valid parts of a file with
    /// errors are); `false` for a fatal problem (not applied at all).
    applied: bool,
}

impl FileReport {
    fn text(&self) -> String {
        let mut lines = Vec::new();
        let path = self.path.display();
        if self.errors.is_empty() && self.warnings.is_empty() {
            lines.push(format!("{path}: valid"));
        } else if !self.read {
            lines.push(format!("{path}: invalid, NOT applied — {}", self.errors[0]));
        } else {
            // The same three states as `status` and `policy show`.
            let status = if self.errors.is_empty() {
                "valid with warnings".to_string()
            } else if self.applied {
                format!(
                    "applied, with {} error(s) — the invalid parts are ignored",
                    self.errors.len()
                )
            } else {
                "invalid, NOT applied".to_string()
            };
            lines.push(format!("{path}: {status}"));
            for e in &self.errors {
                lines.push(format!("  error:   {e}"));
            }
            for w in &self.warnings {
                lines.push(format!("  warning: {w}"));
            }
        }
        for n in &self.notes {
            lines.push(format!("  note:    {n}"));
        }
        lines.join("\n")
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "path": self.path,
            "valid": self.valid,
            "applied": self.applied,
            "errors": self.errors,
            "warnings": self.warnings,
            "notes": self.notes,
        })
    }
}

fn validate_file(path: &Path, known: &std::collections::HashSet<String>) -> FileReport {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            let reason = if e.kind() == std::io::ErrorKind::NotFound {
                "file not found".to_string()
            } else {
                format!("could not read file: {e}")
            };
            return FileReport {
                path: path.to_path_buf(),
                valid: false,
                errors: vec![reason],
                warnings: Vec::new(),
                notes: Vec::new(),
                read: false,
                applied: false,
            };
        }
    };
    let loaded = policy::load_policy_text(&content, known);
    let report = loaded.report;
    FileReport {
        path: path.to_path_buf(),
        valid: report.errors.is_empty(),
        errors: report.errors,
        warnings: report.warnings,
        notes: report.notes,
        read: true,
        applied: loaded.policy.is_some(),
    }
}

/// Discovery warnings `validate_policy_report` cannot see: a `.shellfirm.yml`
/// shadowed by `.shellfirm.yaml`, and an org policy file (or its directory)
/// that the current user can write. The same warnings `status` and
/// `policy show` print.
fn discovery_warnings(d: &policy::PolicyDiscovery) -> Vec<(PathBuf, String)> {
    d.warnings
        .iter()
        .filter(|w| {
            w.message.starts_with("ignored: ")
                || (d.org_files.contains(&w.path) && w.message.contains("writable by you"))
        })
        .map(|w| (w.path.clone(), w.message.clone()))
        .collect()
}

/// Schema version of `policy validate --format json`.
const POLICY_VALIDATE_SCHEMA_VERSION: u32 = 1;

#[allow(clippy::too_many_lines)]
fn run_validate(
    config: &Config,
    file: Option<&str>,
    strict: bool,
    json: bool,
) -> shellfirm::CmdExit {
    let env = RealEnvironment;
    let cwd = env.current_dir().unwrap_or_default();
    let d = policy::discover_all(&env, &cwd);
    let fail = |code: i32, message: String| -> shellfirm::CmdExit {
        if json {
            let doc = serde_json::json!({
                "schema_version": POLICY_VALIDATE_SCHEMA_VERSION,
                "version": env!("CARGO_PKG_VERSION"),
                "valid": false,
                "strict": strict,
                "files": [],
                "warnings": [],
                "error": message,
            });
            let mut out =
                crate::print_stdout(&serde_json::to_string_pretty(&doc).unwrap_or_default());
            if out.code == exitcode::OK {
                out.code = code;
            }
            out
        } else {
            exit(code, message)
        }
    };
    let mut reports: Vec<FileReport> = Vec::new();
    let files: Vec<PathBuf> = if let Some(f) = file {
        let p = PathBuf::from(f);
        if !p.exists() {
            return fail(
                exitcode::NOINPUT,
                format!("{}: file not found", p.display()),
            );
        }
        vec![p]
    } else {
        // Files discovery refuses before reading them (a relative
        // SHELLFIRM_ORG_POLICY) are invalid without being validated.
        for e in d.errors.iter().filter(|e| e.path.is_relative()) {
            reports.push(FileReport {
                path: e.path.clone(),
                valid: false,
                errors: vec![e.message.clone()],
                warnings: Vec::new(),
                notes: Vec::new(),
                read: false,
                applied: false,
            });
        }
        let files: Vec<PathBuf> = d
            .files
            .iter()
            .filter(|f| !f.is_relative())
            .cloned()
            .collect();
        if files.is_empty() && !reports.is_empty() {
            let text = reports
                .iter()
                .map(FileReport::text)
                .collect::<Vec<_>>()
                .join("\n");
            if !json {
                return report_stdout(exitcode::DATAERR, &text);
            }
        } else if files.is_empty() {
            return fail(
                exitcode::NOINPUT,
                "No policy found: no org policy, and no .shellfirm.yaml in this directory or its \
                 parents (up to the outermost repository root, or / outside a repository).\n\
                 Create one with `shellfirm policy init`, or pass a path: `shellfirm policy validate <FILE>`."
                    .to_string(),
            );
        }
        files
    };

    let known = personal_ids(config);
    for f in &files {
        reports.push(validate_file(f, &known));
    }
    // Discovery warnings (writable org policy file / directory, shadowed
    // `.shellfirm.yml`) belong to the file they are about. For an explicit
    // FILE only the warnings about that file are reported.
    let mut orphan: Vec<String> = Vec::new();
    for (path, message) in discovery_warnings(&d) {
        let canonical = std::fs::canonicalize(&path).ok();
        let same = |r: &&mut FileReport| {
            r.path == path
                || (canonical.is_some() && std::fs::canonicalize(&r.path).ok() == canonical)
        };
        if let Some(r) = reports.iter_mut().find(|r| same(r)) {
            if !r.warnings.contains(&message) {
                r.warnings.push(message);
            }
        } else if file.is_none() {
            orphan.push(format!("{}: warning: {message}", path.display()));
        }
    }
    let all_ok = reports.iter().all(|r| r.valid);
    let any_warning = !orphan.is_empty() || reports.iter().any(|r| !r.warnings.is_empty());
    let failed = !all_ok || (strict && any_warning);
    let code = if failed {
        exitcode::DATAERR
    } else {
        exitcode::OK
    };
    if json {
        let doc = serde_json::json!({
            "schema_version": POLICY_VALIDATE_SCHEMA_VERSION,
            "version": env!("CARGO_PKG_VERSION"),
            "valid": !failed,
            "strict": strict,
            "files": reports.iter().map(FileReport::json).collect::<Vec<_>>(),
            "warnings": orphan,
        });
        let mut out = crate::print_stdout(&serde_json::to_string_pretty(&doc).unwrap_or_default());
        if out.code == exitcode::OK {
            out.code = code;
        }
        return out;
    }
    let mut out: Vec<String> = reports.iter().map(FileReport::text).collect();
    out.extend(orphan);
    if strict && all_ok && any_warning {
        out.push("strict mode: warnings are treated as errors".into());
    }
    report_stdout(code, &out.join("\n"))
}

/// The validation report is the command's output: stdout (`| grep`,
/// `> file`), escaped and ASCII on a non-UTF-8 terminal, with `code` as the
/// exit code (74 when stdout cannot be written).
fn report_stdout(code: i32, text: &str) -> shellfirm::CmdExit {
    let mut out = crate::print_stdout(&config::ascii_fallback(
        &shellfirm::context::escape_invisible(text),
    ));
    if out.code == exitcode::OK {
        out.code = code;
    }
    out
}

/// The `policy show` report: lines of free text (`text_lines`, check
/// descriptions) keep their joiners (Persian, Indic, emoji), every other line
/// is escaped strictly (ids, paths, branch names).
fn escape_show_lines(lines: &[String], text_lines: &std::collections::HashSet<usize>) -> String {
    lines
        .iter()
        .enumerate()
        .map(|(i, l)| {
            if text_lines.contains(&i) {
                shellfirm::context::escape_invisible_text(l)
            } else {
                shellfirm::context::escape_invisible(l)
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Schema version of `policy show --format json`.
const POLICY_SHOW_SCHEMA_VERSION: u32 = 1;

#[allow(clippy::too_many_lines)]
fn run_show(config: &Config, format: &str) -> Result<shellfirm::CmdExit> {
    let env = RealEnvironment;
    let cwd = env.current_dir().unwrap_or_default();
    let d = policy::discover_all(&env, &cwd);
    let (settings, settings_error) = config.load_settings_lenient();
    let conflicts = d
        .policy
        .as_ref()
        .map_or_else(Vec::new, |p| policy::conflicts_with_settings(&settings, p));
    let status_of = |path: &Path| -> &'static str {
        if d.errors.iter().any(|e| e.path == path) {
            "invalid"
        } else if !d.errors_for(path).is_empty() {
            "applied_with_errors"
        } else {
            "valid"
        }
    };

    if format == "json" {
        let json = serde_json::json!({
            "schema_version": POLICY_SHOW_SCHEMA_VERSION,
            "version": env!("CARGO_PKG_VERSION"),
            "sources": d.sources,
            "files": d.files.iter().map(|f| serde_json::json!({
                "path": f,
                "org": d.org_files.contains(f),
                "status": status_of(f),
                "errors": d.errors_for(f),
                "warnings": d.warnings_for(f),
            })).collect::<Vec<_>>(),
            "repo_root": d.repo_root,
            "invalid": d.errors.iter().map(|e| serde_json::json!({
                "path": e.path, "error": e.message
            })).collect::<Vec<_>>(),
            "problems": d.problems.iter().map(|e| serde_json::json!({
                "path": e.path, "error": e.message
            })).collect::<Vec<_>>(),
            "warnings": d.warnings.iter().map(|e| serde_json::json!({
                "path": e.path, "warning": e.message
            })).collect::<Vec<_>>(),
            "notes": d.notes,
            "policy": d.policy.as_ref().map(|p| serde_json::json!({
                "deny": p.deny,
                "overrides": p.overrides,
                "effective_overrides": p.strictest_overrides(),
                "checks": p.checks.iter().map(|c| serde_json::json!({
                    "id": c.id, "from": c.from, "severity": c.severity,
                    "description": c.description, "test": c.test.as_str(),
                })).collect::<Vec<_>>(),
                "context": p.context.as_ref().map(shellfirm::policy::PolicyContext::effective),
                "context_without_effect": p.context.as_ref().map_or_else(Vec::new, shellfirm::policy::PolicyContext::no_effect_notes),
            })),
            "conflicts_with_your_settings": conflicts,
            "settings_error": settings_error,
        });
        return Ok(crate::print_stdout(&serde_json::to_string_pretty(&json)?));
    }

    let mut lines = Vec::new();
    // Lines of free text (check descriptions): escaped with the text rule,
    // which keeps joiners (Persian, Indic, emoji); everything else with the
    // strict one.
    let mut text_lines = std::collections::HashSet::new();
    if !d.found_any() {
        lines.push(format!(
            "No project policy applies to {} (no .shellfirm.yaml found{}, no org policy).",
            cwd.display(),
            d.repo_root.as_ref().map_or_else(String::new, |r| format!(
                " up to the outermost repository root {}",
                r.display()
            ))
        ));
        return Ok(crate::print_stdout(&lines.join("\n")));
    }
    lines.push("Policy sources (outermost first):".into());
    for f in &d.files {
        let org = if d.org_files.contains(f) {
            " [org]"
        } else {
            ""
        };
        let errs = d.errors_for(f);
        match status_of(f) {
            "invalid" => lines.push(format!(
                "  {}{org}  (INVALID, not applied: {})",
                f.display(),
                errs.first().copied().unwrap_or("invalid")
            )),
            "applied_with_errors" => {
                lines.push(format!(
                    "  {}{org}  (applied, with {} error(s) — the invalid parts are ignored)",
                    f.display(),
                    errs.len()
                ));
                for e in errs {
                    lines.push(format!("      error: {e}"));
                }
            }
            _ => lines.push(format!("  {}{org}  (valid)", f.display())),
        }
        for w in d.warnings_for(f) {
            lines.push(format!("      warning: {w}"));
        }
    }
    for w in d.warnings.iter().filter(|w| !d.files.contains(&w.path)) {
        lines.push(format!("  {}  ({})", w.path.display(), w.message));
    }
    if let Some(p) = &d.policy {
        // Ids that match no check (reported as errors above) are left out
        // of the effective policy: they enforce nothing.
        let known: std::collections::HashSet<String> = config::known_check_ids(&p.checks)
            .into_iter()
            .chain(config::BUILTIN_RULE_IDS.iter().map(ToString::to_string))
            .collect();
        let (deny, dropped): (Vec<&String>, Vec<&String>) =
            p.deny.iter().partition(|id| known.contains(*id));
        lines.push(String::new());
        lines.push("Effective policy:".into());
        lines.push(format!(
            "  deny:      {}",
            if deny.is_empty() {
                "(none)".into()
            } else {
                deny.iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        ));
        if !dropped.is_empty() {
            lines.push(format!(
                "  (left out, unknown ids: {})",
                dropped
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if p.overrides.iter().any(|o| known.contains(&o.id)) {
            lines.push("  overrides (strictest wins):".into());
            let mut shown = std::collections::HashSet::new();
            let strictest = p.strictest_overrides();
            for o in p.overrides.iter().filter(|o| known.contains(&o.id)) {
                let br = o
                    .on_branches
                    .as_ref()
                    .map_or_else(String::new, |b| format!(" on branches [{}]", b.join(", ")));
                let ch = if o.on_branches.is_none() {
                    if !shown.insert(o.id.clone()) {
                        continue;
                    }
                    strictest
                        .get(&o.id)
                        .map_or_else(|| "(no challenge)".to_string(), ToString::to_string)
                } else {
                    o.challenge
                        .map_or_else(|| "(no challenge)".to_string(), |c| c.to_string())
                };
                lines.push(format!("    {} -> at least {ch}{br}", o.id));
            }
        } else {
            lines.push("  overrides: (none)".into());
        }
        if p.checks.is_empty() {
            lines.push("  checks:    (none)".into());
        } else {
            lines.push("  checks:".into());
            for c in &p.checks {
                text_lines.insert(lines.len());
                lines.push(format!(
                    "    {} [{}] {}",
                    shellfirm::context::escape_invisible(&c.id),
                    c.severity,
                    c.description
                ));
            }
        }
        if let Some(ctx) = &p.context {
            // Only what has an effect is "effective"; an escalation at or
            // below the built-in default is named in a note instead.
            let effective = ctx.effective();
            if effective.has_effect() {
                lines.push("  context:".into());
                let yaml = serde_yaml::to_string(&effective).unwrap_or_default();
                for l in yaml.lines() {
                    lines.push(format!("    {l}"));
                }
            }
            for n in ctx.no_effect_notes() {
                lines.push(format!("note: {n}"));
            }
        }
    }
    for n in &d.notes {
        lines.push(format!("note: {n}"));
    }
    if !conflicts.is_empty() {
        lines.push(String::new());
        lines.push("Your personal settings that the policy overrides (the policy wins):".into());
        for c in &conflicts {
            lines.push(format!("  - {c}"));
        }
    }
    if let Some(e) = settings_error {
        lines.push(String::new());
        lines.push(format!("warning: {e}"));
    }
    Ok(crate::print_stdout(&shellfirm::config::ascii_fallback(
        &escape_show_lines(&lines, &text_lines),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn show_keeps_joiners_in_descriptions_only() {
        let lines = vec![
            "  deny:      team:a\u{200d}b".to_string(),
            "    team:x [HIGH] \u{6af}\u{644}\u{200c}\u{647}\u{627} \u{1F469}\u{200d}\u{1F4BB} x\u{202e}y"
                .to_string(),
        ];
        let text_lines: std::collections::HashSet<usize> = [1].into_iter().collect();
        let out = escape_show_lines(&lines, &text_lines);
        assert!(out.contains("team:a\\u{200d}b"), "{out}");
        assert!(
            out.contains('\u{200c}') && out.contains('\u{200d}'),
            "{out}"
        );
        assert!(out.contains("x\\u{202e}y"), "{out}");
    }
}
