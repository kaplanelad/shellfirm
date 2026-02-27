use clap::{Arg, ArgAction, ArgMatches, Command};
use shellfirm::checks::Severity;
use shellfirm::error::{Error, Result};
use shellfirm::{Challenge, Config, Settings, DEFAULT_ENABLED_GROUPS};

#[allow(clippy::too_many_lines)]
pub fn command() -> Command {
    Command::new("config")
        .about("Manage shellfirm configuration")
        .subcommand(Command::new("show").about("Show current configuration"))
        .subcommand(Command::new("reset").about("Reset configuration to defaults"))
        .subcommand(
            Command::new("edit").about("Open settings.yaml in $EDITOR with post-save validation"),
        )
        .subcommand(
            Command::new("challenge")
                .about("Set the challenge type (Math, Enter, Yes)")
                .arg(Arg::new("value").help("Challenge type: Math, Enter, or Yes")),
        )
        .subcommand(
            Command::new("severity")
                .about("Set the minimum severity threshold")
                .arg(
                    Arg::new("level")
                        .help("Severity level: all, Info, Low, Medium, High, or Critical"),
                ),
        )
        .subcommand(
            Command::new("groups")
                .about("Manage enabled check groups")
                .arg(
                    Arg::new("enable")
                        .long("enable")
                        .action(ArgAction::Append)
                        .help("Enable a check group"),
                )
                .arg(
                    Arg::new("disable")
                        .long("disable")
                        .action(ArgAction::Append)
                        .help("Disable a check group"),
                ),
        )
        .subcommand(
            Command::new("ignore")
                .about("Manage ignored pattern IDs")
                .arg(Arg::new("pattern").help("Pattern ID to add to ignore list"))
                .arg(
                    Arg::new("remove")
                        .long("remove")
                        .help("Pattern ID to remove from ignore list")
                        .num_args(1),
                )
                .arg(
                    Arg::new("list")
                        .long("list")
                        .help("List currently ignored patterns")
                        .action(ArgAction::SetTrue),
                ),
        )
        .subcommand(
            Command::new("deny")
                .about("Manage denied pattern IDs")
                .arg(Arg::new("pattern").help("Pattern ID to add to deny list"))
                .arg(
                    Arg::new("remove")
                        .long("remove")
                        .help("Pattern ID to remove from deny list")
                        .num_args(1),
                )
                .arg(
                    Arg::new("list")
                        .long("list")
                        .help("List currently denied patterns")
                        .action(ArgAction::SetTrue),
                ),
        )
        .subcommand(
            Command::new("llm")
                .about("Configure LLM analysis settings")
                .arg(
                    Arg::new("provider")
                        .long("provider")
                        .help("LLM provider (e.g. anthropic)"),
                )
                .arg(
                    Arg::new("model")
                        .long("model")
                        .help("Model ID (e.g. claude-sonnet-4-20250514)"),
                )
                .arg(
                    Arg::new("timeout")
                        .long("timeout")
                        .help("Request timeout in milliseconds"),
                )
                .arg(
                    Arg::new("base-url")
                        .long("base-url")
                        .help("Custom base URL for openai-compatible providers"),
                ),
        )
        .subcommand(
            Command::new("context")
                .about("Configure context-aware protection settings")
                .subcommand(
                    Command::new("branches")
                        .about("Manage protected branches")
                        .arg(Arg::new("add").long("add").help("Add a protected branch"))
                        .arg(
                            Arg::new("remove")
                                .long("remove")
                                .help("Remove a protected branch"),
                        ),
                )
                .subcommand(
                    Command::new("k8s")
                        .about("Manage production Kubernetes patterns")
                        .arg(Arg::new("add").long("add").help("Add a k8s pattern"))
                        .arg(
                            Arg::new("remove")
                                .long("remove")
                                .help("Remove a k8s pattern"),
                        ),
                )
                .subcommand(
                    Command::new("escalation")
                        .about("Configure escalation challenge levels")
                        .arg(
                            Arg::new("elevated")
                                .long("elevated")
                                .help("Challenge for elevated risk (Math, Enter, Yes)"),
                        )
                        .arg(
                            Arg::new("critical")
                                .long("critical")
                                .help("Challenge for critical risk (Math, Enter, Yes)"),
                        ),
                )
                .subcommand(
                    Command::new("paths")
                        .about("Manage sensitive paths")
                        .arg(Arg::new("add").long("add").help("Add a sensitive path"))
                        .arg(
                            Arg::new("remove")
                                .long("remove")
                                .help("Remove a sensitive path"),
                        ),
                ),
        )
        .subcommand(
            Command::new("escalation")
                .about("Manage challenge escalation settings")
                .subcommand(
                    Command::new("severity")
                        .about("Configure severity-based challenge escalation")
                        .arg(
                            Arg::new("enabled")
                                .long("enabled")
                                .help("Enable/disable severity escalation (true/false)"),
                        )
                        .arg(
                            Arg::new("critical")
                                .long("critical")
                                .help("Challenge for Critical severity (Math, Enter, Yes)"),
                        )
                        .arg(
                            Arg::new("high")
                                .long("high")
                                .help("Challenge for High severity (Math, Enter, Yes)"),
                        )
                        .arg(
                            Arg::new("medium")
                                .long("medium")
                                .help("Challenge for Medium severity (Math, Enter, Yes)"),
                        )
                        .arg(
                            Arg::new("low")
                                .long("low")
                                .help("Challenge for Low severity (Math, Enter, Yes)"),
                        )
                        .arg(
                            Arg::new("info")
                                .long("info")
                                .help("Challenge for Info severity (Math, Enter, Yes)"),
                        ),
                )
                .subcommand(
                    Command::new("group")
                        .about("Manage per-group challenge overrides")
                        .arg(Arg::new("name").help("Group name (e.g. fs, git, kubernetes)"))
                        .arg(Arg::new("challenge").help("Challenge type (Math, Enter, Yes)"))
                        .arg(
                            Arg::new("remove")
                                .long("remove")
                                .help("Remove override for a group")
                                .num_args(1),
                        )
                        .arg(
                            Arg::new("list")
                                .long("list")
                                .help("List group overrides")
                                .action(ArgAction::SetTrue),
                        ),
                )
                .subcommand(
                    Command::new("check")
                        .about("Manage per-check-ID challenge overrides")
                        .arg(Arg::new("id").help("Check ID (e.g. git:force_push)"))
                        .arg(Arg::new("challenge").help("Challenge type (Math, Enter, Yes)"))
                        .arg(
                            Arg::new("remove")
                                .long("remove")
                                .help("Remove override for a check ID")
                                .num_args(1),
                        )
                        .arg(
                            Arg::new("list")
                                .long("list")
                                .help("List check-ID overrides")
                                .action(ArgAction::SetTrue),
                        ),
                ),
        )
}

pub fn run(matches: &ArgMatches, config: &Config) -> Result<shellfirm::CmdExit> {
    matches.subcommand().map_or_else(
        || run_interactive_menu(config, None),
        |tup| match tup {
            ("show", _) => run_show(config),
            ("reset", _) => Ok(run_reset(config, None)),
            ("edit", _) => run_edit(config),
            ("challenge", sub) => {
                let value = sub.get_one::<String>("value");
                run_challenge_cmd(config, value.map(String::as_str), None)
            }
            ("severity", sub) => {
                let level = sub.get_one::<String>("level");
                run_severity_cmd(config, level.map(String::as_str), None)
            }
            ("groups", sub) => {
                let enables: Vec<&str> = sub
                    .get_many::<String>("enable")
                    .map_or_else(Vec::new, |v| v.map(String::as_str).collect());
                let disables: Vec<&str> = sub
                    .get_many::<String>("disable")
                    .map_or_else(Vec::new, |v| v.map(String::as_str).collect());
                if enables.is_empty() && disables.is_empty() {
                    run_groups_interactive(config, None)
                } else {
                    run_groups(config, &enables, &disables)
                }
            }
            ("ignore", sub) => run_pattern_list_cmd(config, sub, PatternListKind::Ignore),
            ("deny", sub) => run_pattern_list_cmd(config, sub, PatternListKind::Deny),
            ("llm", sub) => run_llm_cmd(config, sub),
            ("context", sub) => run_context_cmd(config, sub),
            ("escalation", sub) => run_escalation_cmd(config, sub),
            _ => unreachable!(),
        },
    )
}

// ---------------------------------------------------------------------------
// reset (kept as-is)
// ---------------------------------------------------------------------------

pub fn run_reset(config: &Config, force_selection: Option<usize>) -> shellfirm::CmdExit {
    match config.reset_config(force_selection) {
        Ok(()) => shellfirm::CmdExit {
            code: exitcode::OK,
            message: Some("shellfirm configuration reset successfully".to_string()),
        },
        Err(e) => shellfirm::CmdExit {
            code: exitcode::CONFIG,
            message: Some(format!("reset settings error: {e:?}")),
        },
    }
}

// ---------------------------------------------------------------------------
// edit (kept as-is)
// ---------------------------------------------------------------------------

pub fn run_edit(config: &Config) -> Result<shellfirm::CmdExit> {
    if !config.setting_file_path.exists() {
        config.reset_config(Some(0))?;
    }
    let original = config.read_config_file()?;
    let editor = std::env::var("EDITOR")
        .or_else(|_| std::env::var("VISUAL"))
        .unwrap_or_else(|_| "vi".to_string());

    let status = std::process::Command::new(&editor)
        .arg(&config.setting_file_path)
        .status()
        .map_err(|e| Error::Config(format!("failed to launch editor '{editor}': {e}")))?;

    if !status.success() {
        return Ok(shellfirm::CmdExit {
            code: exitcode::CONFIG,
            message: Some(format!("editor exited with status: {status}")),
        });
    }

    match config.get_settings_from_file() {
        Ok(_) => Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: Some("Configuration updated successfully.".to_string()),
        }),
        Err(e) => {
            let mut file = std::fs::File::create(&config.setting_file_path)?;
            std::io::Write::write_all(&mut file, original.as_bytes())?;
            Ok(shellfirm::CmdExit {
                code: exitcode::CONFIG,
                message: Some(format!(
                    "Invalid configuration, changes discarded: {e}\n\nRun 'config edit' to try again."
                )),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// show
// ---------------------------------------------------------------------------

pub fn run_show(config: &Config) -> Result<shellfirm::CmdExit> {
    let settings = config.get_settings_from_file()?;
    let output = format_settings_display(&settings, &config.setting_file_path);
    println!("{output}");
    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: None,
    })
}

#[allow(clippy::too_many_lines)]
fn format_settings_display(settings: &Settings, config_path: &std::path::Path) -> String {
    let mut lines = Vec::new();

    lines.push(format!("config:         {}", config_path.display()));
    lines.push(String::new());

    let severity_str = settings
        .min_severity
        .as_ref()
        .map_or_else(|| "(all)".to_string(), ToString::to_string);

    lines.push(format!("challenge:      {}", settings.challenge));
    lines.push(format!("min_severity:   {severity_str}"));
    lines.push(format!(
        "audit:          {}",
        if settings.audit_enabled {
            "enabled"
        } else {
            "disabled"
        }
    ));
    lines.push(format!(
        "blast_radius:   {}",
        if settings.blast_radius {
            "enabled"
        } else {
            "disabled"
        }
    ));

    // Groups
    let enabled_count = settings.enabled_groups.len();
    let disabled_count = settings.disabled_groups.len();
    lines.push(String::new());
    lines.push(format!(
        "groups ({enabled_count} enabled, {disabled_count} disabled):"
    ));
    let groups_str = settings.enabled_groups.join(", ");
    lines.push(format!("  {groups_str}"));
    if !settings.disabled_groups.is_empty() {
        let disabled_str = settings.disabled_groups.join(", ");
        lines.push(format!("  disabled: {disabled_str}"));
    }

    // Context
    lines.push(String::new());
    lines.push("context:".to_string());
    lines.push(format!(
        "  protected branches: {}",
        settings.context.protected_branches.join(", ")
    ));
    lines.push(format!(
        "  production k8s:     {}",
        settings.context.production_k8s_patterns.join(", ")
    ));
    lines.push(format!(
        "  escalation:         elevated={}, critical={}",
        settings.context.escalation.elevated, settings.context.escalation.critical
    ));
    if !settings.context.sensitive_paths.is_empty() {
        lines.push(format!(
            "  sensitive paths:    {}",
            settings.context.sensitive_paths.join(", ")
        ));
    }

    // Severity escalation
    lines.push(String::new());
    lines.push("escalation:".to_string());
    if settings.severity_escalation.enabled {
        lines.push(format!(
            "  severity:  Critical={}, High={}, Medium={}, Low={}, Info={}",
            settings.severity_escalation.critical,
            settings.severity_escalation.high,
            settings.severity_escalation.medium,
            settings.severity_escalation.low,
            settings.severity_escalation.info,
        ));
    } else {
        lines.push("  severity:  (disabled)".to_string());
    }
    if !settings.group_escalation.is_empty() {
        let mut entries: Vec<String> = settings
            .group_escalation
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        entries.sort();
        lines.push(format!("  groups:    {}", entries.join(", ")));
    }
    if !settings.check_escalation.is_empty() {
        let mut entries: Vec<String> = settings
            .check_escalation
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        entries.sort();
        lines.push(format!("  checks:    {}", entries.join(", ")));
    }

    // LLM
    lines.push(String::new());
    if let Some(ref llm) = settings.llm {
        let base_url_str = llm.base_url.as_deref().unwrap_or("(default)");
        lines.push(format!(
            "llm:     {} / {} (timeout: {}ms, base_url: {})",
            llm.provider, llm.model, llm.timeout_ms, base_url_str
        ));
    } else {
        lines.push("llm:     (not configured)".to_string());
    }

    // Agent
    lines.push(format!(
        "agent:   auto-deny severity: {}",
        settings.agent.auto_deny_severity
    ));

    // Ignore / Deny
    if !settings.ignores_patterns_ids.is_empty() {
        lines.push(String::new());
        lines.push(format!(
            "ignored patterns: {}",
            settings.ignores_patterns_ids.join(", ")
        ));
    }
    if !settings.deny_patterns_ids.is_empty() {
        lines.push(String::new());
        lines.push(format!(
            "denied patterns:  {}",
            settings.deny_patterns_ids.join(", ")
        ));
    }

    lines.join("\n")
}

// ---------------------------------------------------------------------------
// challenge
// ---------------------------------------------------------------------------

pub fn run_challenge(config: &Config, value: &str) -> Result<shellfirm::CmdExit> {
    let challenge = Challenge::from_string(value).map_err(|_| {
        Error::Config(format!(
            "invalid challenge type: '{value}'\n\nValid values: Math, Enter, Yes"
        ))
    })?;
    let mut settings = config.get_settings_from_file()?;
    settings.challenge = challenge;
    config.save_settings_file_from_struct(&settings)?;
    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some(format!("challenge = {challenge}")),
    })
}

fn run_challenge_cmd(
    config: &Config,
    arg: Option<&str>,
    force_selection: Option<usize>,
) -> Result<shellfirm::CmdExit> {
    if let Some(value) = arg {
        return run_challenge(config, value);
    }
    let items = &["Math", "Enter", "Yes"];
    let current = config.get_settings_from_file()?.challenge;
    let default_idx = items
        .iter()
        .position(|&i| i.eq_ignore_ascii_case(&current.to_string()))
        .unwrap_or(0);
    let idx = force_selection.map_or_else(
        || shellfirm::prompt::select_with_default("Select challenge type:", items, default_idx),
        Ok,
    )?;
    let value = items
        .get(idx)
        .ok_or_else(|| Error::Config("invalid selection".into()))?;
    run_challenge(config, value)
}

// ---------------------------------------------------------------------------
// severity
// ---------------------------------------------------------------------------

fn parse_severity(value: &str) -> std::result::Result<Option<Severity>, String> {
    match value.to_lowercase().as_str() {
        "all" | "null" | "" => Ok(None),
        "info" => Ok(Some(Severity::Info)),
        "low" => Ok(Some(Severity::Low)),
        "medium" => Ok(Some(Severity::Medium)),
        "high" => Ok(Some(Severity::High)),
        "critical" => Ok(Some(Severity::Critical)),
        _ => Err(format!(
            "invalid severity: '{value}'\n\nValid values: all, Info, Low, Medium, High, Critical"
        )),
    }
}

pub fn run_severity(config: &Config, value: &str) -> Result<shellfirm::CmdExit> {
    let severity = parse_severity(value).map_err(Error::Config)?;
    let mut settings = config.get_settings_from_file()?;
    settings.min_severity = severity;
    config.save_settings_file_from_struct(&settings)?;
    let display = severity.map_or_else(|| "(all)".to_string(), |s| s.to_string());
    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some(format!("min_severity = {display}")),
    })
}

fn run_severity_cmd(
    config: &Config,
    arg: Option<&str>,
    force_selection: Option<usize>,
) -> Result<shellfirm::CmdExit> {
    if let Some(value) = arg {
        return run_severity(config, value);
    }
    let items = &["(all)", "Info", "Low", "Medium", "High", "Critical"];
    let current = config.get_settings_from_file()?.min_severity;
    let default_idx = match current {
        None => 0,
        Some(Severity::Info) => 1,
        Some(Severity::Low) => 2,
        Some(Severity::Medium) => 3,
        Some(Severity::High) => 4,
        Some(Severity::Critical) => 5,
    };
    let idx = force_selection.map_or_else(
        || shellfirm::prompt::select_with_default("Select minimum severity:", items, default_idx),
        Ok,
    )?;
    let value = items
        .get(idx)
        .ok_or_else(|| Error::Config("invalid selection".into()))?;
    let mapped = if *value == "(all)" { "all" } else { value };
    run_severity(config, mapped)
}

// ---------------------------------------------------------------------------
// groups
// ---------------------------------------------------------------------------

pub fn run_groups(
    config: &Config,
    enables: &[&str],
    disables: &[&str],
) -> Result<shellfirm::CmdExit> {
    // Validate group names
    for &name in enables.iter().chain(disables.iter()) {
        if !DEFAULT_ENABLED_GROUPS.contains(&name) {
            return Ok(shellfirm::CmdExit {
                code: exitcode::CONFIG,
                message: Some(format!(
                    "unknown group: '{name}'\n\nAvailable groups: {}",
                    DEFAULT_ENABLED_GROUPS.join(", ")
                )),
            });
        }
    }

    let mut settings = config.get_settings_from_file()?;

    for &name in enables {
        if !settings.enabled_groups.iter().any(|g| g == name) {
            settings.enabled_groups.push(name.to_string());
        }
        settings.disabled_groups.retain(|g| g != name);
    }
    for &name in disables {
        if !settings.disabled_groups.iter().any(|g| g == name) {
            settings.disabled_groups.push(name.to_string());
        }
        settings.enabled_groups.retain(|g| g != name);
    }

    config.save_settings_file_from_struct(&settings)?;

    let mut parts = Vec::new();
    if !enables.is_empty() {
        parts.push(format!("enabled: {}", enables.join(", ")));
    }
    if !disables.is_empty() {
        parts.push(format!("disabled: {}", disables.join(", ")));
    }
    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some(format!("groups updated ({})", parts.join("; "))),
    })
}

fn run_groups_interactive(
    config: &Config,
    force_selections: Option<&[usize]>,
) -> Result<shellfirm::CmdExit> {
    let settings = config.get_settings_from_file()?;
    let items: Vec<&str> = DEFAULT_ENABLED_GROUPS.to_vec();
    let defaults: Vec<bool> = items
        .iter()
        .map(|&group| {
            settings.enabled_groups.iter().any(|g| g == group)
                && !settings.disabled_groups.iter().any(|g| g == group)
        })
        .collect();

    let selected_indices = if let Some(forced) = force_selections {
        forced.to_vec()
    } else {
        shellfirm::prompt::multi_select("Select check groups to enable:", &items, &defaults)?
    };

    let mut enables = Vec::new();
    let mut disables = Vec::new();
    for (i, &group) in items.iter().enumerate() {
        if selected_indices.contains(&i) {
            enables.push(group);
        } else {
            disables.push(group);
        }
    }

    run_groups(config, &enables, &disables)
}

// ---------------------------------------------------------------------------
// ignore / deny (shared pattern list logic)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub enum PatternListKind {
    Ignore,
    Deny,
}

impl PatternListKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Ignore => "ignore",
            Self::Deny => "deny",
        }
    }
}

fn run_pattern_list_cmd(
    config: &Config,
    matches: &ArgMatches,
    kind: PatternListKind,
) -> Result<shellfirm::CmdExit> {
    let list_flag = matches.get_flag("list");
    let remove_value = matches.get_one::<String>("remove");
    let add_value = matches.get_one::<String>("pattern");

    if list_flag {
        return run_pattern_list_show(config, kind);
    }
    if let Some(id) = remove_value {
        return run_pattern_list_remove(config, kind, id);
    }
    if let Some(id) = add_value {
        return run_pattern_list_add(config, kind, id);
    }

    // No args — show current list
    run_pattern_list_show(config, kind)
}

pub fn run_pattern_list_add(
    config: &Config,
    kind: PatternListKind,
    id: &str,
) -> Result<shellfirm::CmdExit> {
    let mut settings = config.get_settings_from_file()?;
    let list = match kind {
        PatternListKind::Ignore => &mut settings.ignores_patterns_ids,
        PatternListKind::Deny => &mut settings.deny_patterns_ids,
    };
    if !list.iter().any(|existing| existing == id) {
        list.push(id.to_string());
    }
    config.save_settings_file_from_struct(&settings)?;
    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some(format!("{} list: added '{id}'", kind.label())),
    })
}

pub fn run_pattern_list_remove(
    config: &Config,
    kind: PatternListKind,
    id: &str,
) -> Result<shellfirm::CmdExit> {
    let mut settings = config.get_settings_from_file()?;
    let list = match kind {
        PatternListKind::Ignore => &mut settings.ignores_patterns_ids,
        PatternListKind::Deny => &mut settings.deny_patterns_ids,
    };
    list.retain(|existing| existing != id);
    config.save_settings_file_from_struct(&settings)?;
    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some(format!("{} list: removed '{id}'", kind.label())),
    })
}

fn run_pattern_list_show(config: &Config, kind: PatternListKind) -> Result<shellfirm::CmdExit> {
    let settings = config.get_settings_from_file()?;
    let list = match kind {
        PatternListKind::Ignore => &settings.ignores_patterns_ids,
        PatternListKind::Deny => &settings.deny_patterns_ids,
    };
    if list.is_empty() {
        println!("{} list: (empty)", kind.label());
    } else {
        println!("{} list:", kind.label());
        for id in list {
            println!("  {id}");
        }
    }
    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: None,
    })
}

// ---------------------------------------------------------------------------
// llm
// ---------------------------------------------------------------------------

fn run_llm_cmd(config: &Config, matches: &ArgMatches) -> Result<shellfirm::CmdExit> {
    let provider = matches.get_one::<String>("provider");
    let model = matches.get_one::<String>("model");
    let timeout = matches.get_one::<String>("timeout");
    let base_url = matches.get_one::<String>("base-url");

    let has_flags =
        provider.is_some() || model.is_some() || timeout.is_some() || base_url.is_some();

    if has_flags {
        return run_llm(
            config,
            provider.map(String::as_str),
            model.map(String::as_str),
            timeout.map(String::as_str),
            base_url.map(String::as_str),
        );
    }

    // Interactive: prompt for each field
    run_llm_interactive(config, None)
}

pub fn run_llm(
    config: &Config,
    provider: Option<&str>,
    model: Option<&str>,
    timeout: Option<&str>,
    base_url: Option<&str>,
) -> Result<shellfirm::CmdExit> {
    let mut settings = config.get_settings_from_file()?;
    let mut llm = settings.llm.unwrap_or_default();
    let mut changes = Vec::new();

    if let Some(p) = provider {
        llm.provider = p.to_string();
        changes.push(format!("provider = {p}"));
    }
    if let Some(m) = model {
        llm.model = m.to_string();
        changes.push(format!("model = {m}"));
    }
    if let Some(t) = timeout {
        let ms: u64 = t.parse().map_err(|_| {
            Error::Config(format!("invalid timeout: '{t}' (expected milliseconds)"))
        })?;
        llm.timeout_ms = ms;
        changes.push(format!("timeout = {ms}ms"));
    }
    if let Some(url) = base_url {
        let url_value = if url.is_empty() || url == "none" {
            None
        } else {
            Some(url.to_string())
        };
        changes.push(format!(
            "base_url = {}",
            url_value.as_deref().unwrap_or("(none)")
        ));
        llm.base_url = url_value;
    }

    settings.llm = Some(llm);
    config.save_settings_file_from_struct(&settings)?;
    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some(format!("llm updated: {}", changes.join(", "))),
    })
}

fn run_llm_interactive(
    config: &Config,
    force_values: Option<(&str, &str)>,
) -> Result<shellfirm::CmdExit> {
    let settings = config.get_settings_from_file()?;
    let llm = settings.llm.unwrap_or_default();

    let (provider, model) = if let Some((p, m)) = force_values {
        (p.to_string(), m.to_string())
    } else {
        let p = shellfirm::prompt::input_with_default("LLM provider:", &llm.provider)?;
        let m = shellfirm::prompt::input_with_default("Model ID:", &llm.model)?;
        (p, m)
    };

    run_llm(config, Some(&provider), Some(&model), None, None)
}

// ---------------------------------------------------------------------------
// context
// ---------------------------------------------------------------------------

fn run_context_cmd(config: &Config, matches: &ArgMatches) -> Result<shellfirm::CmdExit> {
    match matches.subcommand() {
        Some(("branches", sub)) => {
            let add = sub.get_one::<String>("add");
            let remove = sub.get_one::<String>("remove");
            run_context_list(
                config,
                &ContextListField::Branches,
                add.map(String::as_str),
                remove.map(String::as_str),
            )
        }
        Some(("k8s", sub)) => {
            let add = sub.get_one::<String>("add");
            let remove = sub.get_one::<String>("remove");
            run_context_list(
                config,
                &ContextListField::K8s,
                add.map(String::as_str),
                remove.map(String::as_str),
            )
        }
        Some(("escalation", sub)) => {
            let elevated = sub.get_one::<String>("elevated");
            let critical = sub.get_one::<String>("critical");
            run_context_escalation(
                config,
                elevated.map(String::as_str),
                critical.map(String::as_str),
            )
        }
        Some(("paths", sub)) => {
            let add = sub.get_one::<String>("add");
            let remove = sub.get_one::<String>("remove");
            run_context_list(
                config,
                &ContextListField::Paths,
                add.map(String::as_str),
                remove.map(String::as_str),
            )
        }
        _ => run_context_interactive(config, None),
    }
}

pub enum ContextListField {
    Branches,
    K8s,
    Paths,
}

impl ContextListField {
    const fn label(&self) -> &'static str {
        match self {
            Self::Branches => "protected branches",
            Self::K8s => "production k8s patterns",
            Self::Paths => "sensitive paths",
        }
    }
}

const fn get_context_list_mut<'a>(
    settings: &'a mut Settings,
    field: &ContextListField,
) -> &'a mut Vec<String> {
    match field {
        ContextListField::Branches => &mut settings.context.protected_branches,
        ContextListField::K8s => &mut settings.context.production_k8s_patterns,
        ContextListField::Paths => &mut settings.context.sensitive_paths,
    }
}

const fn get_context_list<'a>(settings: &'a Settings, field: &ContextListField) -> &'a Vec<String> {
    match field {
        ContextListField::Branches => &settings.context.protected_branches,
        ContextListField::K8s => &settings.context.production_k8s_patterns,
        ContextListField::Paths => &settings.context.sensitive_paths,
    }
}

pub fn run_context_list(
    config: &Config,
    field: &ContextListField,
    add: Option<&str>,
    remove: Option<&str>,
) -> Result<shellfirm::CmdExit> {
    if add.is_none() && remove.is_none() {
        let settings = config.get_settings_from_file()?;
        let list = get_context_list(&settings, field);
        if list.is_empty() {
            println!("{}: (empty)", field.label());
        } else {
            println!("{}:", field.label());
            for item in list {
                println!("  {item}");
            }
        }
        return Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: None,
        });
    }

    let mut settings = config.get_settings_from_file()?;

    if let Some(value) = add {
        let list = get_context_list_mut(&mut settings, field);
        if !list.iter().any(|v| v == value) {
            list.push(value.to_string());
        }
    }
    if let Some(value) = remove {
        let list = get_context_list_mut(&mut settings, field);
        list.retain(|v| v != value);
    }

    config.save_settings_file_from_struct(&settings)?;

    let mut msg_parts = Vec::new();
    if let Some(value) = add {
        msg_parts.push(format!("added '{value}'"));
    }
    if let Some(value) = remove {
        msg_parts.push(format!("removed '{value}'"));
    }
    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some(format!("{}: {}", field.label(), msg_parts.join(", "))),
    })
}

pub fn run_context_escalation(
    config: &Config,
    elevated: Option<&str>,
    critical: Option<&str>,
) -> Result<shellfirm::CmdExit> {
    let mut settings = config.get_settings_from_file()?;
    let mut changes = Vec::new();

    if let Some(val) = elevated {
        let challenge = Challenge::from_string(val).map_err(|_| {
            Error::Config(format!(
                "invalid challenge for elevated: '{val}'\n\nValid values: Math, Enter, Yes"
            ))
        })?;
        settings.context.escalation.elevated = challenge;
        changes.push(format!("elevated = {challenge}"));
    }
    if let Some(val) = critical {
        let challenge = Challenge::from_string(val).map_err(|_| {
            Error::Config(format!(
                "invalid challenge for critical: '{val}'\n\nValid values: Math, Enter, Yes"
            ))
        })?;
        settings.context.escalation.critical = challenge;
        changes.push(format!("critical = {challenge}"));
    }

    if changes.is_empty() {
        // Show current escalation
        println!(
            "escalation: elevated={}, critical={}",
            settings.context.escalation.elevated, settings.context.escalation.critical
        );
        return Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: None,
        });
    }

    config.save_settings_file_from_struct(&settings)?;
    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some(format!("escalation updated: {}", changes.join(", "))),
    })
}

fn run_context_interactive(
    config: &Config,
    force_selection: Option<usize>,
) -> Result<shellfirm::CmdExit> {
    let items = &[
        "Protected branches",
        "Production k8s patterns",
        "Escalation settings",
        "Sensitive paths",
    ];
    let idx = force_selection.map_or_else(
        || shellfirm::prompt::select_with_default("What context setting to configure?", items, 0),
        Ok,
    )?;

    // Show the current values for the selected item
    match idx {
        0 => run_context_list(config, &ContextListField::Branches, None, None),
        1 => run_context_list(config, &ContextListField::K8s, None, None),
        2 => run_context_escalation(config, None, None),
        3 => run_context_list(config, &ContextListField::Paths, None, None),
        _ => Ok(shellfirm::CmdExit {
            code: exitcode::CONFIG,
            message: Some("invalid selection".to_string()),
        }),
    }
}

// ---------------------------------------------------------------------------
// escalation
// ---------------------------------------------------------------------------

fn run_escalation_cmd(config: &Config, matches: &ArgMatches) -> Result<shellfirm::CmdExit> {
    match matches.subcommand() {
        Some(("severity", sub)) => run_escalation_severity_from_matches(config, sub),
        Some(("group", sub)) => run_escalation_map_cmd(config, sub, EscalationMapKind::Group),
        Some(("check", sub)) => run_escalation_map_cmd(config, sub, EscalationMapKind::Check),
        _ => run_escalation_show(config),
    }
}

fn run_escalation_show(config: &Config) -> Result<shellfirm::CmdExit> {
    let settings = config.get_settings_from_file()?;
    if settings.severity_escalation.enabled {
        println!(
            "severity escalation: enabled\n  Critical={}, High={}, Medium={}, Low={}, Info={}",
            settings.severity_escalation.critical,
            settings.severity_escalation.high,
            settings.severity_escalation.medium,
            settings.severity_escalation.low,
            settings.severity_escalation.info,
        );
    } else {
        println!("severity escalation: disabled");
    }
    if settings.group_escalation.is_empty() {
        println!("group overrides: (none)");
    } else {
        println!("group overrides:");
        let mut entries: Vec<_> = settings.group_escalation.iter().collect();
        entries.sort_by(|(a, _), (b, _)| a.cmp(b));
        for (k, v) in entries {
            println!("  {k} = {v}");
        }
    }
    if settings.check_escalation.is_empty() {
        println!("check-id overrides: (none)");
    } else {
        println!("check-id overrides:");
        let mut entries: Vec<_> = settings.check_escalation.iter().collect();
        entries.sort_by(|(a, _), (b, _)| a.cmp(b));
        for (k, v) in entries {
            println!("  {k} = {v}");
        }
    }
    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: None,
    })
}

fn run_escalation_severity_from_matches(
    config: &Config,
    matches: &ArgMatches,
) -> Result<shellfirm::CmdExit> {
    let enabled_arg = matches.get_one::<String>("enabled").map(String::as_str);
    let critical = matches.get_one::<String>("critical").map(String::as_str);
    let high = matches.get_one::<String>("high").map(String::as_str);
    let medium = matches.get_one::<String>("medium").map(String::as_str);
    let low = matches.get_one::<String>("low").map(String::as_str);
    let info = matches.get_one::<String>("info").map(String::as_str);
    run_escalation_severity(config, enabled_arg, critical, high, medium, low, info)
}

pub fn run_escalation_severity(
    config: &Config,
    enabled_arg: Option<&str>,
    critical: Option<&str>,
    high: Option<&str>,
    medium: Option<&str>,
    low: Option<&str>,
    info: Option<&str>,
) -> Result<shellfirm::CmdExit> {
    let has_flags = enabled_arg.is_some()
        || critical.is_some()
        || high.is_some()
        || medium.is_some()
        || low.is_some()
        || info.is_some();

    if !has_flags {
        let settings = config.get_settings_from_file()?;
        if settings.severity_escalation.enabled {
            println!(
                "severity escalation: enabled\n  Critical={}, High={}, Medium={}, Low={}, Info={}",
                settings.severity_escalation.critical,
                settings.severity_escalation.high,
                settings.severity_escalation.medium,
                settings.severity_escalation.low,
                settings.severity_escalation.info,
            );
        } else {
            println!("severity escalation: disabled");
        }
        return Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: None,
        });
    }

    let mut settings = config.get_settings_from_file()?;
    let mut changes = Vec::new();

    if let Some(val) = enabled_arg {
        let enabled = match val.to_lowercase().as_str() {
            "true" | "1" | "yes" => true,
            "false" | "0" | "no" => false,
            _ => {
                return Err(Error::Config(format!(
                    "invalid value for --enabled: '{val}'\n\nValid values: true, false"
                )));
            }
        };
        settings.severity_escalation.enabled = enabled;
        changes.push(format!("enabled = {enabled}"));
    }

    for (name, arg_val) in [
        ("critical", critical),
        ("high", high),
        ("medium", medium),
        ("low", low),
        ("info", info),
    ] {
        if let Some(val) = arg_val {
            let challenge = Challenge::from_string(val).map_err(|_| {
                Error::Config(format!(
                    "invalid challenge for {name}: '{val}'\n\nValid values: Math, Enter, Yes"
                ))
            })?;
            match name {
                "critical" => settings.severity_escalation.critical = challenge,
                "high" => settings.severity_escalation.high = challenge,
                "medium" => settings.severity_escalation.medium = challenge,
                "low" => settings.severity_escalation.low = challenge,
                "info" => settings.severity_escalation.info = challenge,
                _ => unreachable!(),
            }
            changes.push(format!("{name} = {challenge}"));
        }
    }

    config.save_settings_file_from_struct(&settings)?;
    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some(format!(
            "severity escalation updated: {}",
            changes.join(", ")
        )),
    })
}

#[derive(Clone, Copy)]
pub enum EscalationMapKind {
    Group,
    Check,
}

impl EscalationMapKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Group => "group",
            Self::Check => "check-id",
        }
    }
}

fn run_escalation_map_cmd(
    config: &Config,
    matches: &ArgMatches,
    kind: EscalationMapKind,
) -> Result<shellfirm::CmdExit> {
    let list_flag = matches.get_flag("list");
    let remove_value = matches.get_one::<String>("remove");
    let key_arg = match kind {
        EscalationMapKind::Group => matches.get_one::<String>("name"),
        EscalationMapKind::Check => matches.get_one::<String>("id"),
    };
    let challenge_arg = matches.get_one::<String>("challenge");

    if list_flag {
        return run_escalation_map_show(config, kind);
    }
    if let Some(key) = remove_value {
        return run_escalation_map_remove(config, kind, key);
    }
    if let (Some(key), Some(challenge)) = (key_arg, challenge_arg) {
        return run_escalation_map_set(config, kind, key, challenge);
    }

    // No args or only key — show current
    run_escalation_map_show(config, kind)
}

fn run_escalation_map_show(config: &Config, kind: EscalationMapKind) -> Result<shellfirm::CmdExit> {
    let settings = config.get_settings_from_file()?;
    let map = match kind {
        EscalationMapKind::Group => &settings.group_escalation,
        EscalationMapKind::Check => &settings.check_escalation,
    };
    if map.is_empty() {
        println!("{} overrides: (none)", kind.label());
    } else {
        println!("{} overrides:", kind.label());
        let mut entries: Vec<_> = map.iter().collect();
        entries.sort_by(|(a, _), (b, _)| a.cmp(b));
        for (k, v) in entries {
            println!("  {k} = {v}");
        }
    }
    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: None,
    })
}

pub fn run_escalation_map_set(
    config: &Config,
    kind: EscalationMapKind,
    key: &str,
    challenge_str: &str,
) -> Result<shellfirm::CmdExit> {
    let challenge = Challenge::from_string(challenge_str).map_err(|_| {
        Error::Config(format!(
            "invalid challenge: '{challenge_str}'\n\nValid values: Math, Enter, Yes"
        ))
    })?;
    let mut settings = config.get_settings_from_file()?;
    let map = match kind {
        EscalationMapKind::Group => &mut settings.group_escalation,
        EscalationMapKind::Check => &mut settings.check_escalation,
    };
    map.insert(key.to_string(), challenge);
    config.save_settings_file_from_struct(&settings)?;
    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some(format!("{} override: {key} = {challenge}", kind.label())),
    })
}

pub fn run_escalation_map_remove(
    config: &Config,
    kind: EscalationMapKind,
    key: &str,
) -> Result<shellfirm::CmdExit> {
    let mut settings = config.get_settings_from_file()?;
    let map = match kind {
        EscalationMapKind::Group => &mut settings.group_escalation,
        EscalationMapKind::Check => &mut settings.check_escalation,
    };
    if map.remove(key).is_none() {
        return Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: Some(format!(
                "{} override: no override found for '{key}'",
                kind.label()
            )),
        });
    }
    config.save_settings_file_from_struct(&settings)?;
    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some(format!("{} override: removed '{key}'", kind.label())),
    })
}

// ---------------------------------------------------------------------------
// interactive menu (no subcommand)
// ---------------------------------------------------------------------------

fn run_interactive_menu(
    config: &Config,
    force_selection: Option<usize>,
) -> Result<shellfirm::CmdExit> {
    let settings = config.get_settings_from_file()?;
    let severity_str = settings
        .min_severity
        .as_ref()
        .map_or_else(|| "(all)".to_string(), ToString::to_string);
    let enabled_count = settings.enabled_groups.len();
    let disabled_count = settings.disabled_groups.len();

    let items: Vec<String> = vec![
        format!(
            "Challenge type          (currently: {})",
            settings.challenge
        ),
        format!("Minimum severity        (currently: {severity_str})"),
        format!("Check groups            ({enabled_count} enabled, {disabled_count} disabled)"),
        "Ignored patterns".to_string(),
        "Denied patterns".to_string(),
        settings.llm.as_ref().map_or_else(
            || "LLM settings            (not configured)".to_string(),
            |llm| format!("LLM settings            ({} / {})", llm.provider, llm.model),
        ),
        "Context settings".to_string(),
        "Escalation settings".to_string(),
        "Show full config".to_string(),
    ];
    let item_refs: Vec<&str> = items.iter().map(String::as_str).collect();

    let idx = force_selection.map_or_else(
        || {
            shellfirm::prompt::select_with_default(
                "What would you like to configure?",
                &item_refs,
                0,
            )
        },
        Ok,
    )?;

    match idx {
        0 => run_challenge_cmd(config, None, None),
        1 => run_severity_cmd(config, None, None),
        2 => run_groups_interactive(config, None),
        3 => run_pattern_list_show(config, PatternListKind::Ignore),
        4 => run_pattern_list_show(config, PatternListKind::Deny),
        5 => run_llm_interactive(config, None),
        6 => run_context_interactive(config, None),
        7 => run_escalation_show(config),
        8 => run_show(config),
        _ => Ok(shellfirm::CmdExit {
            code: exitcode::CONFIG,
            message: Some("invalid selection".to_string()),
        }),
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod test_config_cli_command {

    use std::fs;

    use insta::{assert_debug_snapshot, with_settings};
    use tree_fs::Tree;

    use super::*;

    fn initialize_config_folder(temp_dir: &Tree) -> Config {
        let temp_dir = temp_dir.root.join("app");
        let config = Config::new(Some(&temp_dir.display().to_string())).unwrap();
        config.reset_config(Some(0)).unwrap();
        config
    }

    fn fresh_config(temp_dir: &Tree) -> Config {
        let temp_dir = temp_dir.root.join("fresh");
        Config::new(Some(&temp_dir.display().to_string())).unwrap()
    }

    // -----------------------------------------------------------------------
    // reset (kept)
    // -----------------------------------------------------------------------

    #[test]
    fn can_run_reset() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        // Change challenge so reset has something to restore
        let mut settings = config.get_settings_from_file().unwrap();
        settings.challenge = Challenge::Yes;
        config.save_settings_file_from_struct(&settings).unwrap();
        assert_debug_snapshot!(run_reset(&config, Some(1)));
        assert_debug_snapshot!(config.get_settings_from_file());
    }

    #[test]
    fn can_run_reset_with_error() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        fs::remove_file(&config.setting_file_path).unwrap();
        with_settings!({filters => vec![
            (r"error:.+", "error message"),
        ]}, {
            assert_debug_snapshot!(run_reset(&config, Some(1)));
        });
    }

    // -----------------------------------------------------------------------
    // show
    // -----------------------------------------------------------------------

    #[test]
    fn show_default_config() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        let result = run_show(&config).unwrap();
        assert_eq!(result.code, exitcode::OK);
    }

    #[test]
    fn show_modified_config() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        let mut settings = config.get_settings_from_file().unwrap();
        settings.challenge = Challenge::Yes;
        settings.min_severity = Some(Severity::High);
        settings.ignores_patterns_ids = vec!["git:force_push".to_string()];
        config.save_settings_file_from_struct(&settings).unwrap();

        let settings = config.get_settings_from_file().unwrap();
        let output = format_settings_display(&settings, &config.setting_file_path);
        assert!(output.contains("challenge:      Yes"));
        assert!(output.contains("min_severity:   HIGH"));
        assert!(output.contains("git:force_push"));
    }

    #[test]
    fn show_on_fresh_install() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = fresh_config(&temp_dir);
        let result = run_show(&config).unwrap();
        assert_eq!(result.code, exitcode::OK);
    }

    // -----------------------------------------------------------------------
    // challenge
    // -----------------------------------------------------------------------

    #[test]
    fn challenge_set_valid() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        let result = run_challenge(&config, "Yes").unwrap();
        assert_eq!(result.code, exitcode::OK);
        assert_eq!(
            config.get_settings_from_file().unwrap().challenge,
            Challenge::Yes
        );
    }

    #[test]
    fn challenge_set_each_variant() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        for (input, expected) in [
            ("Math", Challenge::Math),
            ("Enter", Challenge::Enter),
            ("Yes", Challenge::Yes),
        ] {
            let result = run_challenge(&config, input).unwrap();
            assert_eq!(result.code, exitcode::OK);
            assert_eq!(config.get_settings_from_file().unwrap().challenge, expected);
        }
    }

    #[test]
    fn challenge_rejects_invalid() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        let result = run_challenge(&config, "Foo");
        assert!(result.is_err());
    }

    #[test]
    fn challenge_on_fresh_install() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = fresh_config(&temp_dir);
        let result = run_challenge(&config, "Yes").unwrap();
        assert_eq!(result.code, exitcode::OK);
        assert_eq!(
            config.get_settings_from_file().unwrap().challenge,
            Challenge::Yes
        );
    }

    // -----------------------------------------------------------------------
    // severity
    // -----------------------------------------------------------------------

    #[test]
    fn severity_set_valid() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        for (input, expected) in [
            ("Info", Some(Severity::Info)),
            ("Low", Some(Severity::Low)),
            ("Medium", Some(Severity::Medium)),
            ("High", Some(Severity::High)),
            ("Critical", Some(Severity::Critical)),
        ] {
            let result = run_severity(&config, input).unwrap();
            assert_eq!(result.code, exitcode::OK);
            assert_eq!(
                config.get_settings_from_file().unwrap().min_severity,
                expected
            );
        }
    }

    #[test]
    fn severity_set_null() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        // First set to something
        run_severity(&config, "High").unwrap();
        // Then clear
        let result = run_severity(&config, "all").unwrap();
        assert_eq!(result.code, exitcode::OK);
        assert_eq!(config.get_settings_from_file().unwrap().min_severity, None);
    }

    #[test]
    fn severity_rejects_invalid() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        let result = run_severity(&config, "Foo");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // groups
    // -----------------------------------------------------------------------

    #[test]
    fn groups_enable() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        // First disable aws, then re-enable
        run_groups(&config, &[], &["aws"]).unwrap();
        assert!(config
            .get_settings_from_file()
            .unwrap()
            .disabled_groups
            .contains(&"aws".to_string()));
        let result = run_groups(&config, &["aws"], &[]).unwrap();
        assert_eq!(result.code, exitcode::OK);
        let settings = config.get_settings_from_file().unwrap();
        assert!(settings.enabled_groups.contains(&"aws".to_string()));
        assert!(!settings.disabled_groups.contains(&"aws".to_string()));
    }

    #[test]
    fn groups_disable() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        let result = run_groups(&config, &[], &["docker"]).unwrap();
        assert_eq!(result.code, exitcode::OK);
        let settings = config.get_settings_from_file().unwrap();
        assert!(!settings.enabled_groups.contains(&"docker".to_string()));
        assert!(settings.disabled_groups.contains(&"docker".to_string()));
    }

    #[test]
    fn groups_enable_and_disable() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        let result = run_groups(&config, &["aws"], &["docker"]).unwrap();
        assert_eq!(result.code, exitcode::OK);
    }

    #[test]
    fn groups_rejects_unknown() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        let result = run_groups(&config, &["nonexistent"], &[]).unwrap();
        assert_eq!(result.code, exitcode::CONFIG);
        assert!(result.message.unwrap().contains("unknown group"));
    }

    #[test]
    fn groups_idempotent() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        let before = config.get_settings_from_file().unwrap();
        let result = run_groups(&config, &["aws"], &[]).unwrap();
        assert_eq!(result.code, exitcode::OK);
        let after = config.get_settings_from_file().unwrap();
        // aws should appear exactly once
        assert_eq!(
            before
                .enabled_groups
                .iter()
                .filter(|g| g.as_str() == "aws")
                .count(),
            after
                .enabled_groups
                .iter()
                .filter(|g| g.as_str() == "aws")
                .count()
        );
    }

    // -----------------------------------------------------------------------
    // ignore / deny
    // -----------------------------------------------------------------------

    #[test]
    fn ignore_add() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        let result =
            run_pattern_list_add(&config, PatternListKind::Ignore, "git:force_push").unwrap();
        assert_eq!(result.code, exitcode::OK);
        assert!(config
            .get_settings_from_file()
            .unwrap()
            .ignores_patterns_ids
            .contains(&"git:force_push".to_string()));
    }

    #[test]
    fn ignore_remove() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        run_pattern_list_add(&config, PatternListKind::Ignore, "git:force_push").unwrap();
        let result =
            run_pattern_list_remove(&config, PatternListKind::Ignore, "git:force_push").unwrap();
        assert_eq!(result.code, exitcode::OK);
        assert!(!config
            .get_settings_from_file()
            .unwrap()
            .ignores_patterns_ids
            .contains(&"git:force_push".to_string()));
    }

    #[test]
    fn ignore_add_duplicate() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        run_pattern_list_add(&config, PatternListKind::Ignore, "git:force_push").unwrap();
        run_pattern_list_add(&config, PatternListKind::Ignore, "git:force_push").unwrap();
        assert_eq!(
            config
                .get_settings_from_file()
                .unwrap()
                .ignores_patterns_ids
                .iter()
                .filter(|id| id.as_str() == "git:force_push")
                .count(),
            1
        );
    }

    #[test]
    fn deny_add() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        let result = run_pattern_list_add(&config, PatternListKind::Deny, "fs:rm_rf").unwrap();
        assert_eq!(result.code, exitcode::OK);
        assert!(config
            .get_settings_from_file()
            .unwrap()
            .deny_patterns_ids
            .contains(&"fs:rm_rf".to_string()));
    }

    #[test]
    fn deny_remove() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        run_pattern_list_add(&config, PatternListKind::Deny, "fs:rm_rf").unwrap();
        let result = run_pattern_list_remove(&config, PatternListKind::Deny, "fs:rm_rf").unwrap();
        assert_eq!(result.code, exitcode::OK);
        assert!(!config
            .get_settings_from_file()
            .unwrap()
            .deny_patterns_ids
            .contains(&"fs:rm_rf".to_string()));
    }

    // -----------------------------------------------------------------------
    // llm
    // -----------------------------------------------------------------------

    #[test]
    fn llm_set_model() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        let result = run_llm(&config, None, Some("gpt-4"), None, None).unwrap();
        assert_eq!(result.code, exitcode::OK);
        assert_eq!(
            config.get_settings_from_file().unwrap().llm.unwrap().model,
            "gpt-4"
        );
    }

    #[test]
    fn llm_set_provider() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        let result = run_llm(&config, Some("openai"), None, None, None).unwrap();
        assert_eq!(result.code, exitcode::OK);
        assert_eq!(
            config
                .get_settings_from_file()
                .unwrap()
                .llm
                .unwrap()
                .provider,
            "openai"
        );
    }

    #[test]
    fn llm_set_multiple() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        let result = run_llm(&config, Some("openai"), Some("gpt-4"), Some("10000"), None).unwrap();
        assert_eq!(result.code, exitcode::OK);
        let llm = config
            .get_settings_from_file()
            .unwrap()
            .llm
            .expect("llm should be Some after run_llm");
        assert_eq!(llm.provider, "openai");
        assert_eq!(llm.model, "gpt-4");
        assert_eq!(llm.timeout_ms, 10000);
    }

    #[test]
    fn llm_on_fresh_install() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = fresh_config(&temp_dir);
        let result = run_llm(&config, None, Some("gpt-4"), None, None).unwrap();
        assert_eq!(result.code, exitcode::OK);
        assert_eq!(
            config.get_settings_from_file().unwrap().llm.unwrap().model,
            "gpt-4"
        );
    }

    // -----------------------------------------------------------------------
    // context
    // -----------------------------------------------------------------------

    #[test]
    fn context_add_branch() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        let result =
            run_context_list(&config, &ContextListField::Branches, Some("develop"), None).unwrap();
        assert_eq!(result.code, exitcode::OK);
        assert!(config
            .get_settings_from_file()
            .unwrap()
            .context
            .protected_branches
            .contains(&"develop".to_string()));
    }

    #[test]
    fn context_remove_branch() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        let result =
            run_context_list(&config, &ContextListField::Branches, None, Some("main")).unwrap();
        assert_eq!(result.code, exitcode::OK);
        assert!(!config
            .get_settings_from_file()
            .unwrap()
            .context
            .protected_branches
            .contains(&"main".to_string()));
    }

    #[test]
    fn context_set_escalation() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        let result = run_context_escalation(&config, Some("Yes"), Some("Yes")).unwrap();
        assert_eq!(result.code, exitcode::OK);
        let settings = config.get_settings_from_file().unwrap();
        assert_eq!(settings.context.escalation.elevated, Challenge::Yes);
        assert_eq!(settings.context.escalation.critical, Challenge::Yes);
    }

    // -----------------------------------------------------------------------
    // escalation
    // -----------------------------------------------------------------------

    #[test]
    fn escalation_severity_set_high_and_disable() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        // Set high to Yes
        let result =
            run_escalation_severity(&config, None, None, Some("Yes"), None, None, None).unwrap();
        assert_eq!(result.code, exitcode::OK);
        let settings = config.get_settings_from_file().unwrap();
        assert_eq!(settings.severity_escalation.high, Challenge::Yes);
        // Other fields unchanged
        assert!(settings.severity_escalation.enabled);
        assert_eq!(settings.severity_escalation.critical, Challenge::Yes);

        // Disable severity escalation
        let result =
            run_escalation_severity(&config, Some("false"), None, None, None, None, None).unwrap();
        assert_eq!(result.code, exitcode::OK);
        let settings = config.get_settings_from_file().unwrap();
        assert!(!settings.severity_escalation.enabled);
        // high stays as previously set
        assert_eq!(settings.severity_escalation.high, Challenge::Yes);
    }

    #[test]
    fn escalation_group_set_fs() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        let result =
            run_escalation_map_set(&config, EscalationMapKind::Group, "fs", "Yes").unwrap();
        assert_eq!(result.code, exitcode::OK);
        let settings = config.get_settings_from_file().unwrap();
        assert_eq!(settings.group_escalation.get("fs"), Some(&Challenge::Yes));
    }

    #[test]
    fn escalation_check_set_and_remove() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        // Set
        let result =
            run_escalation_map_set(&config, EscalationMapKind::Check, "git:force_push", "Yes")
                .unwrap();
        assert_eq!(result.code, exitcode::OK);
        let settings = config.get_settings_from_file().unwrap();
        assert_eq!(
            settings.check_escalation.get("git:force_push"),
            Some(&Challenge::Yes)
        );
        // Remove
        let result =
            run_escalation_map_remove(&config, EscalationMapKind::Check, "git:force_push").unwrap();
        assert_eq!(result.code, exitcode::OK);
        let settings = config.get_settings_from_file().unwrap();
        assert!(settings.check_escalation.get("git:force_push").is_none());
    }

    #[test]
    fn escalation_group_on_fresh_install() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = fresh_config(&temp_dir);
        let result =
            run_escalation_map_set(&config, EscalationMapKind::Group, "database", "Yes").unwrap();
        assert_eq!(result.code, exitcode::OK);
        let settings = config.get_settings_from_file().unwrap();
        assert_eq!(
            settings.group_escalation.get("database"),
            Some(&Challenge::Yes)
        );
    }

    // -----------------------------------------------------------------------
    // interactive menu (force_selection)
    // -----------------------------------------------------------------------

    #[test]
    fn config_menu_delegates_to_show() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        // Selection 8 = "Show full config"
        let result = run_interactive_menu(&config, Some(8)).unwrap();
        assert_eq!(result.code, exitcode::OK);
    }
}
