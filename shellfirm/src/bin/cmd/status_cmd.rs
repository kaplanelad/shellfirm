use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use clap::{crate_version, Arg, ArgMatches, Command};
use serde_json::json;
use shellfirm::{
    checks::Check,
    config, context,
    env::{Environment, RealEnvironment},
    Config, Mode, Settings,
};

use crate::LoadReport;

pub fn command() -> Command {
    Command::new("status")
        .about("Show shellfirm installation status and current configuration overview")
        .arg(super::config_dir_arg())
        .arg(
            Arg::new("format")
                .long("format")
                .value_parser(["text", "json"])
                .default_value("text")
                .help("Output format"),
        )
}

/// Hook installation state for one shell.
#[derive(Debug, Clone, serde_derive::Serialize)]
pub struct HookStatus {
    pub shell: &'static str,
    pub rc_file: Option<PathBuf>,
    pub installed: bool,
    pub rc_exists: bool,
    /// The rc file does not load the hook, but this other startup file
    /// does (fish `conf.d/*.fish`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loaded_from: Option<PathBuf>,
}

/// The rc files `shellfirm init` writes to, per shell.
fn rc_files(env: &dyn Environment) -> Vec<(&'static str, Option<PathBuf>)> {
    let home = env.home_dir();
    let xdg = env
        .var("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| home.as_ref().map(|h| h.join(".config")));
    let zdot = env
        .var("ZDOTDIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| home.clone());
    let nu = dirs::config_dir().map(|d| d.join("nushell/config.nu"));
    vec![
        ("bash", home.as_ref().map(|h| h.join(".bashrc"))),
        ("zsh", zdot.map(|z| z.join(".zshrc"))),
        ("fish", xdg.as_ref().map(|x| x.join("fish/config.fish"))),
        ("nushell", nu),
        (
            "powershell",
            xdg.as_ref()
                .map(|x| x.join("powershell/Microsoft.PowerShell_profile.ps1")),
        ),
        ("elvish", xdg.as_ref().map(|x| x.join("elvish/rc.elv"))),
        ("xonsh", home.as_ref().map(|h| h.join(".xonshrc"))),
        ("oils", xdg.as_ref().map(|x| x.join("oils/oshrc"))),
    ]
}

fn has_hook(content: &str) -> bool {
    content.lines().any(|l| {
        let l = l.trim_start();
        !l.starts_with('#')
            && l.contains("shellfirm")
            && (l.contains("init") || l.contains("pre-command"))
    }) || content.contains("# Added by shellfirm init")
}

#[must_use]
pub fn detect_hooks(env: &dyn Environment) -> Vec<HookStatus> {
    rc_files(env)
        .into_iter()
        .map(|(shell, rc)| {
            let content = rc.as_ref().and_then(|p| std::fs::read_to_string(p).ok());
            let in_rc = content.as_deref().is_some_and(has_hook);
            // fish also loads every `conf.d/*.fish` next to config.fish.
            let loaded_from = if shell == "fish" && !in_rc {
                rc.as_ref()
                    .and_then(|p| p.parent())
                    .and_then(|d| std::fs::read_dir(d.join("conf.d")).ok())
                    .and_then(|entries| {
                        let mut found: Vec<PathBuf> = entries
                            .flatten()
                            .map(|e| e.path())
                            .filter(|p| {
                                p.extension().is_some_and(|x| x == "fish")
                                    && std::fs::read_to_string(p).is_ok_and(|c| has_hook(&c))
                            })
                            .collect();
                        found.sort();
                        found.into_iter().next()
                    })
            } else {
                None
            };
            HookStatus {
                shell,
                rc_exists: content.is_some(),
                installed: in_rc || loaded_from.is_some(),
                rc_file: rc,
                loaded_from,
            }
        })
        .collect()
}

/// Schema version of `status --format json`.
const STATUS_SCHEMA_VERSION: u32 = 1;

/// State of the settings file: `(state, human message, unknown keys)` where
/// `state` is one of `valid`, `invalid`, `missing`.
fn settings_file_state(
    config: &Config,
    report: &LoadReport,
) -> (&'static str, String, Vec<String>) {
    let path = &config.setting_file_path;
    if !path.exists() {
        return (
            "missing",
            "not created yet (using built-in defaults)".into(),
            vec![],
        );
    }
    if let Some(e) = &report.settings_error {
        // The error already names the file; don't repeat it.
        let prefix = format!("invalid settings file {}: ", path.display());
        let msg = e.strip_prefix(&prefix).unwrap_or(e);
        return ("invalid", format!("INVALID: {msg}"), vec![]);
    }
    let unknown = config
        .read_config_file()
        .map(|c| config::unknown_settings_keys(&c))
        .unwrap_or_default();
    let n = report.settings_warnings.len();
    if n == 0 {
        ("valid", "valid".into(), unknown)
    } else {
        // Still applied (it parses), but something in it has no effect.
        (
            "valid",
            format!("valid, with {n} warning(s) (see below)"),
            unknown,
        )
    }
}

/// The context risk outside of protected-branch escalation, and the reasons
/// for the full level. A protected branch only raises the risk of commands
/// that push to, rewrite or delete that branch, so `status` must not call
/// every command on `main` critical.
fn risk_summary(ctx: &context::RuntimeContext, cfg: &context::ContextConfig) -> (String, bool) {
    let mut without_branch = ctx.clone();
    without_branch.git_ignore_current_branch = true;
    without_branch.refresh(cfg);
    let protected = ctx
        .git_branch
        .as_deref()
        .is_some_and(|b| context::branch_matches_any(b, &cfg.protected_branches));
    let reasons: Vec<String> = without_branch
        .risk_reasons(cfg)
        .into_iter()
        .filter(|(l, _)| *l == without_branch.risk_level)
        .map(|(_, r)| r)
        .collect();
    let mut line = format!("{:?}", without_branch.risk_level);
    if !reasons.is_empty() {
        let _ = write!(line, " ({})", reasons.join(", "));
    }
    if protected {
        let branch = context::escape_invisible(ctx.git_branch.as_deref().unwrap_or_default());
        let _ = write!(
            line,
            "; Critical for commands that push to, rewrite or delete the protected branch `{branch}`"
        );
    }
    (line, protected)
}

/// One human-readable line for an integration row, e.g.
/// `claude-code (user): hook yes, file tools yes, fail-closed yes, MCP yes`.
fn integration_line(row: &serde_json::Value) -> String {
    let flag = |k: &str| {
        if row[k].as_bool().unwrap_or(false) {
            "yes"
        } else {
            "no"
        }
    };
    let mut line = format!(
        "{} ({}): hook {}, file tools {}, fail-closed {}, MCP {}",
        row["tool"].as_str().unwrap_or("?"),
        row["scope"].as_str().unwrap_or("?"),
        flag("hook_installed"),
        flag("file_tools_covered"),
        flag("fail_closed"),
        flag("mcp_registered"),
    );
    if row["hook_present"].as_bool().unwrap_or(false)
        && !row["hook_installed"].as_bool().unwrap_or(false)
    {
        line.push_str(" (hook present but Bash not covered)");
    }
    if let Some(missing) = row["shell_tools_missing"]
        .as_array()
        .filter(|m| !m.is_empty())
    {
        let names: Vec<&str> = missing
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect();
        let _ = write!(line, " (not covered: {})", names.join(", "));
    }
    if row["legacy_hook"].as_bool().unwrap_or(false) {
        line.push_str(" (legacy hook: re-run `shellfirm connect` to upgrade)");
    }
    if let Some(err) = row["error"].as_str() {
        let _ = write!(line, " (error: {err})");
    }
    line
}

const fn on_off(b: bool) -> &'static str {
    if b {
        "on"
    } else {
        "off"
    }
}

/// AI-agent integrations installed by `shellfirm connect`, as JSON rows.
/// Rows with neither a hook nor an MCP registration are omitted.
fn agent_integrations() -> Vec<serde_json::Value> {
    let home = dirs::home_dir().unwrap_or_default();
    let cwd = std::env::current_dir().unwrap_or_default();
    super::connect_cmd::integration_status(&home, &cwd)
        .into_iter()
        .filter(|s| s.hook_installed || s.hook_present || s.mcp_registered || s.error.is_some())
        .filter_map(|s| serde_json::to_value(s).ok())
        .collect()
}

/// `(id prefix, group)` pairs where a check id prefix differs from its
/// group (e.g. `fs-strict:` ids belong to the `fs` group).
fn id_prefix_groups(checks: &[Check]) -> Vec<(String, String)> {
    let mut out: std::collections::BTreeSet<(String, String)> = std::collections::BTreeSet::new();
    for c in shellfirm::checks::get_all()
        .unwrap_or_default()
        .iter()
        .chain(checks)
    {
        if let Some((prefix, _)) = c.id.split_once(':') {
            if prefix != c.from {
                out.insert((prefix.to_string(), c.from.clone()));
            }
        }
    }
    out.into_iter().collect()
}

fn display_path(p: &Path) -> String {
    p.display().to_string()
}

#[allow(clippy::too_many_lines)]
pub fn run(
    matches: &ArgMatches,
    config: &Config,
    settings: &Settings,
    checks: &[Check],
    report: &LoadReport,
) -> shellfirm::CmdExit {
    let env = RealEnvironment;
    let format = matches
        .get_one::<String>("format")
        .map_or("text", String::as_str);

    let version = crate_version!();
    let (settings_state, settings_message, unknown_keys) = settings_file_state(config, report);
    let prefixes = id_prefix_groups(checks);
    let integrations = Some(agent_integrations());
    let agent_summary = shellfirm::agent::agent_settings_summary(settings, &env);
    let resolved = settings.resolved_for(Mode::Shell);
    let hooks = detect_hooks(&env);
    // The shell in use: the parent process when it is a shell (a zsh started
    // from a bash login shell is zsh), else `$SHELL` — the same detection as
    // `init` and `doctor`.
    let current_shell: Option<String> =
        super::init::Shell::detect_current().map(|(s, _)| s.name().to_string());

    let runtime_ctx = context::detect(&env, &settings.context);
    let (risk_line, on_protected_branch) = risk_summary(&runtime_ctx, &settings.context);
    let shown_branch = runtime_ctx
        .git_branch
        .as_deref()
        .map(context::escape_invisible);
    let audit_path = config.audit_log_path();
    let pol = &report.policy;
    let min_sev = resolved
        .min_severity
        .map_or_else(|| "(all)".to_string(), |s| s.to_string());
    let esc = &resolved.severity_escalation;
    let llm_configured = settings.llm.is_some();

    if format == "json" {
        let out = json!({
            "schema_version": STATUS_SCHEMA_VERSION,
            "version": version,
            "settings": {
                "path": config.setting_file_path,
                "exists": config.setting_file_path.exists(),
                "state": settings_state,
                "message": settings_message,
                "error": report.settings_error,
                "unknown_keys": unknown_keys,
                "warnings": report.settings_warnings,
                "warning_count": report.settings_warnings.len(),
            },
            "challenge": resolved.challenge.to_string(),
            "min_severity": resolved.min_severity,
            "blast_radius_budget_ms": if settings.blast_radius_on() {
                settings.blast_radius_budget()
            } else {
                0
            },
            "approved_notice": settings.approved_notice,
            "severity_escalation": {
                "enabled": esc.enabled,
                "critical": esc.critical.to_string(),
                "high": esc.high.to_string(),
                "medium": esc.medium.to_string(),
                "low": esc.low.to_string(),
                "info": esc.info.to_string(),
            },
            "context_escalation": {
                "elevated": settings.context.escalation.elevated.to_string(),
                "critical": settings.context.escalation.critical.to_string(),
            },
            "enabled_groups": settings.enabled_groups,
            "disabled_groups": settings.disabled_groups,
            "id_prefix_groups": prefixes.iter().map(|(p, g)| json!({"prefix": p, "group": g})).collect::<Vec<_>>(),
            "active_checks": checks.len(),
            "custom_checks": {
                "loaded": report.custom_count,
                "dir": config.custom_checks_dir(),
                "warnings": report.custom_warnings,
            },
            "deny_patterns_ids": settings.deny_patterns_ids,
            "ignores_patterns_ids": settings.ignores_patterns_ids,
            "audit": {
                "enabled": settings.audit_enabled,
                "path": audit_path,
                "exists": audit_path.exists(),
                "max_files": shellfirm::audit::max_files(settings.audit_max_files),
                "rotate_at_bytes": shellfirm::audit::DEFAULT_MAX_AUDIT_BYTES,
            },
            "hooks": hooks,
            "current_shell": current_shell,
            "context": {
                "ssh": runtime_ctx.is_ssh,
                "root": runtime_ctx.is_root,
                // JSON carries the real value (serde escapes control
                // characters); only the text output shows `\u{200b}`.
                "git_branch": runtime_ctx.git_branch,
                "k8s_context": runtime_ctx.k8s_context,
                "risk_level": format!("{:?}", runtime_ctx.risk_level),
                "risk_summary": risk_line,
                "protected_branch": on_protected_branch,
            },
            "policy": {
                "sources": pol.sources,
                "org_files": pol.org_files,
                "invalid": pol.errors.iter().map(|e| json!({"path": e.path, "error": e.message})).collect::<Vec<_>>(),
                "problems": pol.problems.iter().map(|e| json!({"path": e.path, "error": e.message})).collect::<Vec<_>>(),
                "warnings": pol.warnings.iter().map(|e| json!({"path": e.path, "warning": e.message})).collect::<Vec<_>>(),
                "deny": pol.policy.as_ref().map(|p| p.deny.clone()),
                "overrides": pol.policy.as_ref().map_or(0, |p| p.overrides.len()),
                "checks": pol.policy.as_ref().map_or(0, |p| p.checks.len()),
            },
            "agent": {
                "auto_deny_severity": settings.agent.auto_deny_severity,
                "settings": agent_summary,
                "integrations": integrations,
            },
            "mcp_available": cfg!(feature = "mcp"),
            "llm": {
                "compiled": cfg!(feature = "llm"),
                "configured": llm_configured,
                "note": "used only for AI-agent review when agent.llm_review is enabled",
            },
        });
        return crate::print_stdout(
            &serde_json::to_string_pretty(&out).unwrap_or_else(|_| "{}".into()),
        );
    }

    let mut lines: Vec<String> = Vec::new();
    lines.push(format!("shellfirm v{version}"));
    lines.push(String::new());

    lines.push("Shell hooks:".into());
    for h in &hooks {
        let state = if h.installed {
            "installed"
        } else if h.rc_exists {
            "not installed"
        } else {
            "not installed (no rc file)"
        };
        let marker = if current_shell.as_deref() == Some(h.shell) {
            " <- current shell"
        } else {
            ""
        };
        let rc = h
            .loaded_from
            .as_deref()
            .or(h.rc_file.as_deref())
            .map_or_else(|| "(unknown path)".to_string(), display_path);
        lines.push(format!("  {:<11} {:<27} {rc}{marker}", h.shell, state));
    }
    if !hooks.iter().any(|h| h.installed) {
        lines.push(
            "  No shell hook found in your rc files. Run `shellfirm init` to protect new shells.\n  \
             (A shell that already loaded the hook stays protected until you restart it; \
             `shellfirm doctor` checks it.)"
                .into(),
        );
    }
    lines.push(String::new());

    lines.push("Configuration:".into());
    lines.push(format!(
        "  Settings file:       {} — {settings_message}",
        config.setting_file_path.display()
    ));
    for w in &report.settings_warnings {
        lines.push(format!("    warning: {w}"));
    }
    lines.push(format!("  Challenge:           {}", resolved.challenge));
    lines.push(format!("  Min severity:        {min_sev}"));
    if esc.enabled {
        lines.push(format!(
            "  Severity escalation: minimum challenge per severity — Critical: at least {}, \
             High: at least {}, Medium: at least {}, Low: at least {}, Info: at least {}",
            esc.critical, esc.high, esc.medium, esc.low, esc.info
        ));
    } else {
        lines.push("  Severity escalation: disabled".into());
    }
    lines.push(format!(
        "  Context escalation:  at least {} in an elevated context ({}), at least {} in a \
         critical one ({})",
        settings.context.escalation.elevated,
        shellfirm::config::ELEVATED_CONTEXTS,
        settings.context.escalation.critical,
        shellfirm::config::CRITICAL_CONTEXTS
    ));
    lines.push(
        "                       (\"at least\": a challenge is only ever raised, never lowered; \
         Enter < Math < Yes)"
            .into(),
    );
    lines.push(if settings.blast_radius_on() {
        format!(
            "  Impact budget:       at most {} ms per command before the prompt \
             (`shellfirm config impact-budget <ms>`)",
            settings.blast_radius_budget()
        )
    } else {
        "  Impact budget:       off, the impact is not measured (`shellfirm config \
         impact-budget 400` turns it on)"
            .to_string()
    });
    lines.push(format!(
        "  Approved line:       {} (`shellfirm config approved-notice on|off`)",
        if settings.approved_notice {
            "on, a line after a passed challenge"
        } else {
            "off"
        }
    ));
    // Unknown groups (a typo in a hand-edited file) match nothing: they are
    // not counted as active (the settings warnings name them).
    let known: std::collections::BTreeSet<String> = shellfirm::config::known_groups(checks);
    let (active_groups, unknown_groups): (Vec<&str>, Vec<&str>) = settings
        .enabled_groups
        .iter()
        .filter(|g| !settings.disabled_groups.contains(g))
        .map(String::as_str)
        .partition(|g| known.contains(*g));
    let groups = if active_groups.is_empty() {
        "(none)".to_string()
    } else {
        format!("{} ({})", active_groups.join(", "), active_groups.len())
    };
    lines.push(format!("  Active groups:       {groups}"));
    if !unknown_groups.is_empty() {
        lines.push(format!(
            "  Unknown groups:      {} (no such group; ignored)",
            unknown_groups.join(", ")
        ));
    }
    if !prefixes.is_empty() {
        lines.push(format!(
            "  Id prefixes:         {} (stricter checks inside those groups)",
            prefixes
                .iter()
                .map(|(p, g)| format!("{p}:* → {g}"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !settings.disabled_groups.is_empty() {
        lines.push(format!(
            "  Disabled groups:     {}",
            settings.disabled_groups.join(", ")
        ));
    }
    let not_enabled = settings.default_groups_not_enabled();
    if !not_enabled.is_empty() {
        lines.push(format!(
            "  Not enabled:         {} (default groups; enable: `{}`)",
            not_enabled.join(", "),
            shellfirm::config::enable_groups_command(&not_enabled)
        ));
    }
    lines.push(format!("  Active checks:       {}", checks.len()));
    let custom_dir = config.custom_checks_dir();
    if custom_dir.is_dir() {
        lines.push(format!(
            "  Custom checks:       {} (from {})",
            report.custom_count,
            custom_dir.display()
        ));
    } else {
        lines.push("  Custom checks:       0".into());
    }
    for w in &report.custom_warnings {
        lines.push(format!("    warning: {w}"));
    }
    if !settings.deny_patterns_ids.is_empty() {
        lines.push(format!(
            "  Denied (personal):   {}",
            settings.deny_patterns_ids.join(", ")
        ));
    }
    if !settings.ignores_patterns_ids.is_empty() {
        lines.push(format!(
            "  Ignored (personal):  {}",
            settings.ignores_patterns_ids.join(", ")
        ));
    }
    let retention = format!(
        "keeps {} rotated file(s) of 10 MiB",
        shellfirm::audit::max_files(settings.audit_max_files)
    );
    let audit_state = if !settings.audit_enabled {
        "disabled".to_string()
    } else if audit_path.exists() {
        format!("enabled ({}; {retention})", audit_path.display())
    } else {
        format!(
            "enabled (no events yet; will write {}; {retention})",
            audit_path.display()
        )
    };
    lines.push(format!("  Audit:               {audit_state}"));
    lines.push(String::new());

    lines.push("Context (current environment):".into());
    lines.push(format!(
        "  SSH session:         {}",
        if runtime_ctx.is_ssh { "yes" } else { "no" }
    ));
    lines.push(format!(
        "  Root user:           {}",
        if runtime_ctx.is_root { "yes" } else { "no" }
    ));
    lines.push(format!(
        "  Git branch:          {}{}",
        shown_branch.as_deref().unwrap_or("(not in a git repo)"),
        if on_protected_branch {
            " (protected)"
        } else {
            ""
        }
    ));
    lines.push(format!(
        "  Kubernetes context:  {}",
        runtime_ctx
            .k8s_context
            .as_deref()
            .unwrap_or("(not detected)")
    ));
    lines.push(format!("  Risk level:          {risk_line}"));
    lines.push(String::new());

    lines.push("Project policy:".into());
    if !pol.found_any() {
        lines.push("  .shellfirm.yaml:     not found".into());
    }
    for s in &pol.sources {
        let org = if pol.org_files.contains(s) {
            " [org]"
        } else {
            ""
        };
        let errs = pol.errors_for(s);
        if errs.is_empty() {
            lines.push(format!("  {}{org}: valid", s.display()));
        } else {
            lines.push(format!(
                "  {}{org}: applied, with {} error(s) (the invalid parts are ignored):",
                s.display(),
                errs.len()
            ));
            for e in errs {
                lines.push(format!("    error: {e}"));
            }
        }
        for w in pol.warnings_for(s) {
            lines.push(format!("    warning: {w}"));
        }
    }
    for w in pol.warnings.iter().filter(|w| !pol.files.contains(&w.path)) {
        lines.push(format!("  {}: {}", w.path.display(), w.message));
    }
    for e in &pol.errors {
        lines.push(format!(
            "  {}: INVALID (not applied): {}",
            e.path.display(),
            e.message
        ));
    }
    if let Some(p) = &pol.policy {
        lines.push(format!(
            "  Enforced:            {} deny, {} override(s), {} check(s){}",
            p.deny.len(),
            p.overrides.len(),
            p.checks.len(),
            if p.context.is_some() { ", context" } else { "" }
        ));
        lines.push("  Details:             shellfirm policy show".into());
    }
    lines.push(String::new());

    lines.push("AI features:".into());
    lines.push(format!(
        "  Agent guardrails:    auto-deny >= {}, human approval {}, context escalation {}, self-protection {}",
        settings.agent.auto_deny_severity,
        on_off(agent_summary.require_human_approval),
        on_off(agent_summary.context_escalation),
        on_off(agent_summary.self_protection),
    ));
    if agent_summary.llm_review {
        lines.push(format!(
            "  LLM review:          {}",
            agent_summary.llm_review_note.as_deref().unwrap_or("on")
        ));
    }
    match &integrations {
        Some(list) if !list.is_empty() => {
            lines.push("  Agent integrations:".into());
            for i in list {
                lines.push(format!("    {}", integration_line(i)));
            }
        }
        Some(_) => lines
            .push("  Agent integrations:  none installed (see `shellfirm connect --help`)".into()),
        None => lines.push(
            "  Agent integrations:  not reported by this build (see `shellfirm connect --help`)"
                .into(),
        ),
    }
    lines.push(format!(
        "  MCP server:          {}",
        if cfg!(feature = "mcp") {
            "available (run `shellfirm mcp` to start)"
        } else {
            "not compiled (build with --features mcp)"
        }
    ));
    lines.push(format!(
        "  LLM analysis:        {}",
        if !cfg!(feature = "llm") {
            "not compiled"
        } else if llm_configured {
            "configured (experimental — used only for AI-agent review when `agent.llm_review` is enabled)"
        } else {
            "not configured (experimental; see `shellfirm config llm`)"
        }
    ));

    // Wrapped between words to the terminal width (unchanged when piped).
    crate::print_stdout(&shellfirm::prompt::wrap_for_stdout(
        &config::ascii_fallback(&lines.join("\n")),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hook_detection_ignores_comments_and_finds_eval_lines() {
        assert!(has_hook("eval \"$(shellfirm init zsh)\"\n"));
        assert!(has_hook("# Added by shellfirm init\nsource x\n"));
        assert!(!has_hook("# eval \"$(shellfirm init zsh)\"\n"));
        assert!(!has_hook("alias ll='ls -l'\n"));
    }

    #[test]
    fn fish_hook_in_conf_d_is_reported_with_its_path() {
        let tree = tree_fs::TreeBuilder::default()
            .add("home/.config/fish/config.fish", "set -g x 1\n")
            .add(
                "home/.config/fish/conf.d/shellfirm.fish",
                "shellfirm init fish | source\n",
            )
            .create()
            .unwrap();
        let env = shellfirm::env::MockEnvironment {
            home: Some(tree.root.join("home")),
            ..Default::default()
        };
        let fish = detect_hooks(&env)
            .into_iter()
            .find(|h| h.shell == "fish")
            .unwrap();
        assert!(fish.installed);
        assert_eq!(
            fish.loaded_from,
            Some(tree.root.join("home/.config/fish/conf.d/shellfirm.fish"))
        );
    }
}
