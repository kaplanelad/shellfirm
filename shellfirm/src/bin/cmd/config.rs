use std::io::IsTerminal;

use clap::{Arg, ArgAction, ArgMatches, Command};
use console::style;
use shellfirm::checks::Severity;
use shellfirm::error::{Error, Result};
use shellfirm::{config as sf_config, Challenge, Config, Settings};

const VALID_CHALLENGES: &str = "Math, Enter, Yes";

fn is_interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

/// Load the user's custom checks (for id / group validation).
fn custom_checks(config: &Config) -> Vec<shellfirm::checks::Check> {
    sf_config::load_custom_checks_report(&config.custom_checks_dir()).checks
}

fn parse_challenge(value: &str, what: &str) -> Result<Challenge> {
    Challenge::from_string(value).map_err(|_| {
        Error::Usage(format!(
            "invalid {what}: '{value}'. Valid values: {VALID_CHALLENGES}"
        ))
    })
}

/// `text` ending in exactly one sentence mark (no `?.`).
fn sentence(text: &str) -> String {
    if text.ends_with(['.', '?', '!']) {
        text.to_string()
    } else {
        format!("{text}.")
    }
}

/// Ids similar to `id`, best match first, for "did you mean".
fn suggest_ids(id: &str, known: &std::collections::HashSet<String>) -> Vec<String> {
    sf_config::suggest_similar(id, known.iter().map(String::as_str), 5)
}

/// A typo'd group name: a usage error (exit 2, like `check --list -g`),
/// with the same "Did you mean" wording everywhere.
fn unknown_group_exit(name: &str, available: &[String]) -> shellfirm::CmdExit {
    shellfirm::CmdExit {
        code: sf_config::EXIT_USAGE,
        message: Some(format!(
            "shellfirm: error: {}",
            sf_config::unknown_group_message(name, available.iter().map(String::as_str))
        )),
    }
}

/// Validate that `id` is a known built-in or custom check id.
fn ensure_known_check_id(config: &Config, id: &str) -> Result<()> {
    if let Some(why) = sf_config::builtin_protection_refusal(id, "check_escalation") {
        return Err(Error::Usage(sentence(&why)));
    }
    let known = sf_config::known_check_ids(&custom_checks(config));
    if known.contains(id) {
        return Ok(());
    }
    let suggestions = suggest_ids(id, &known);
    let hint = if suggestions.is_empty() {
        String::new()
    } else {
        format!("\nDid you mean: {}", suggestions.join(", "))
    };
    // Ids may carry bidi / zero-width characters: shown escaped.
    Err(Error::Usage(shellfirm::context::escape_invisible(
        &format!(
            "unknown check id: '{id}'.{hint}\nList all ids with `shellfirm check --list --all`."
        ),
    )))
}

/// `--list` for the subcommands that list their values without arguments.
fn list_arg(help: &'static str) -> Arg {
    Arg::new("list")
        .long("list")
        .action(ArgAction::SetTrue)
        .help(help)
}

/// A select menu that can be left with Esc (or Ctrl-C): `Ok(None)`.
fn select_or_cancel(message: &str, items: &[&str], default: usize) -> Result<Option<usize>> {
    let question = requestty::Question::select("select")
        .message(format!("{message} (Enter to choose, Esc to cancel)"))
        .choices(items.iter().copied())
        .default(default)
        .on_esc(requestty::OnEsc::Terminate)
        .build();
    match requestty::prompt_one(question) {
        Ok(a) => Ok(a.as_list_item().map(|i| i.index)),
        Err(requestty::ErrorKind::Aborted | requestty::ErrorKind::Interrupted) => Ok(None),
        Err(e) => Err(Error::Prompt(e.to_string())),
    }
}

#[allow(clippy::too_many_lines)]
pub fn command() -> Command {
    Command::new("config")
        .about("Manage shellfirm configuration")
        .arg(super::config_dir_arg())
        .subcommand(Command::new("show").about("Show current configuration"))
        .subcommand(
            Command::new("reset")
                .about("Reset configuration to defaults (the old file is backed up first)")
                .arg(
                    Arg::new("yes")
                        .long("yes")
                        .short('y')
                        .action(ArgAction::SetTrue)
                        .help("Reset without prompting (no setup questions)"),
                ),
        )
        .subcommand(
            Command::new("edit").about("Open settings.yaml in $EDITOR; invalid edits are rejected and the file is left unchanged"),
        )
        .subcommand(
            Command::new("challenge")
                .about("Set the challenge type (Math, Enter, Yes)")
                .arg(Arg::new("value").help("Challenge type: Math, Enter, or Yes")),
        )
        .subcommand(
            Command::new("approved-notice")
                .about(
                    "Turn the `approved, running: <command>` line after a passed challenge \
                     on or off (shows the current value without an argument)",
                )
                .arg(Arg::new("value").help("on or off")),
        )
        .subcommand(
            Command::new("impact-budget")
                .about(
                    "Set the total time (ms) shellfirm may spend measuring a command's impact \
                     before the prompt (blast_radius_budget_ms; 0 = off, at most 5000; shows \
                     the current value without an argument)",
                )
                .arg(
                    Arg::new("ms")
                        .value_name("MS")
                        // `-1` reaches the friendly "from 0 (off) to 5000"
                        // message instead of clap's "unexpected argument".
                        .allow_hyphen_values(true)
                        .help("Milliseconds, 0 to 5000 (default 400)"),
                ),
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
                .about("Enable or disable check groups (lists them without arguments)")
                .long_about(
                    "Enable or disable check groups. Without arguments, lists every group and \
                     whether it is active (in a terminal you can also pick them interactively \
                     with `--pick`).\n\n\
                     Only the change is written: `--disable heroku` adds `heroku` to \
                     `disabled_groups` and leaves `enabled_groups` alone, so groups added by a \
                     later release are still enabled for you.",
                )
                .arg(
                    Arg::new("list")
                        .long("list")
                        .action(ArgAction::SetTrue)
                        .help("List every group and whether it is active (the default)"),
                )
                .arg(
                    Arg::new("pick")
                        .long("pick")
                        .action(ArgAction::SetTrue)
                        .help("Choose the active groups in an interactive checklist"),
                )
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
                .about("Manage ignored check ids (stop asking for these checks)")
                .long_about(
                    "Manage `ignores_patterns_ids`: check ids that never challenge you. Without \
                     arguments, lists them. A personal deny, and a project or org policy that \
                     enforces the check, always win over an ignore. List ids with \
                     `shellfirm check --list --all`.",
                )
                .arg(
                    Arg::new("pattern")
                        .value_name("CHECK_ID")
                        .help("Check id to add to the ignore list (e.g. git:reset)"),
                )
                .arg(
                    Arg::new("remove")
                        .long("remove")
                        .value_name("CHECK_ID")
                        .help("Check id to remove from the ignore list")
                        .num_args(1),
                )
                .arg(
                    Arg::new("list")
                        .long("list")
                        .help("List the ignored check ids (the default without arguments)")
                        .action(ArgAction::SetTrue),
                ),
        )
        .subcommand(
            Command::new("unignore")
                .hide(true)
                .arg(Arg::new("pattern").value_name("CHECK_ID")),
        )
        .subcommand(
            Command::new("undeny")
                .hide(true)
                .arg(Arg::new("pattern").value_name("CHECK_ID")),
        )
        .subcommand(
            Command::new("deny")
                .about("Manage denied check ids (always blocked, no challenge)")
                .long_about(
                    "Manage `deny_patterns_ids`: check ids whose commands are always blocked. \
                     Without arguments, lists them. A deny wins over an ignore of the same id.",
                )
                .arg(
                    Arg::new("pattern")
                        .value_name("CHECK_ID")
                        .help("Check id to add to the deny list (e.g. git:force_push)"),
                )
                .arg(
                    Arg::new("remove")
                        .long("remove")
                        .value_name("CHECK_ID")
                        .help("Check id to remove from the deny list")
                        .num_args(1),
                )
                .arg(
                    Arg::new("list")
                        .long("list")
                        .help("List the denied check ids (the default without arguments)")
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
                        .about("Manage protected branches (lists them without arguments)")
                        .arg(list_arg("List the protected branches (the default)"))
                        .arg(Arg::new("add").long("add").help("Add a protected branch"))
                        .arg(
                            Arg::new("remove")
                                .long("remove")
                                .help("Remove a protected branch"),
                        ),
                )
                .subcommand(
                    Command::new("k8s")
                        .about("Manage production Kubernetes patterns (lists them without arguments)")
                        .arg(list_arg("List the production k8s patterns (the default)"))
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
                        .about("Manage sensitive paths (the `context.sensitive_paths` setting)")
                        .long_about(
                            "Manage `context.sensitive_paths`: paths (globs allowed, `~` for your \
                             home) whose modification raises the risk context of a command.",
                        )
                        .arg(list_arg("List the sensitive paths (the default)"))
                        .arg(Arg::new("add").long("add").help("Add a sensitive path"))
                        .arg(
                            Arg::new("remove")
                                .long("remove")
                                .help("Remove a sensitive path"),
                        ),
                )
                .subcommand(
                    Command::new("env")
                        .about("Manage production environment variables (`context.production_env_vars`)")
                        .long_about(
                            "Manage `context.production_env_vars`: when an environment variable has \
                             the given value (e.g. APP_ENV=production) the context is critical.",
                        )
                        .arg(list_arg("List the production env vars (the default)"))
                        .arg(
                            Arg::new("add")
                                .long("add")
                                .value_name("NAME=VALUE")
                                .help("Add or change a production env var, e.g. APP_ENV=production"),
                        )
                        .arg(
                            Arg::new("remove")
                                .long("remove")
                                .value_name("NAME[=VALUE]")
                                .help("Remove a production env var, by name or as NAME=VALUE (as --list shows it)"),
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
        || {
            // The editor draws on stdout and reads stdin: both (and stderr,
            // for messages) must be the terminal, or it would run unseen
            // (`shellfirm config > file`) and still act on keys.
            if !is_interactive() || !std::io::stdout().is_terminal() {
                return Err(Error::Config(
                    "`shellfirm config` opens an interactive editor and needs a terminal \
                     (stdin, stdout and stderr).\n\
                     Use a subcommand instead, e.g. `shellfirm config show`, \
                     `shellfirm config edit` (opens settings.yaml in $EDITOR), \
                     `shellfirm config challenge Yes`, `shellfirm config --help`."
                        .into(),
                ));
            }
            #[cfg(feature = "tui")]
            {
                shellfirm::tui::run(config)
            }
            #[cfg(not(feature = "tui"))]
            {
                run_interactive_menu(config, None)
            }
        },
        |tup| match tup {
            ("show", _) => run_show(config),
            ("reset", sub) => Ok(run_reset_with(config, sub.get_flag("yes"))),
            ("edit", _) => run_edit(config),
            ("challenge", sub) => {
                let value = sub.get_one::<String>("value");
                run_challenge_cmd(config, value.map(String::as_str), None)
            }
            ("approved-notice", sub) => {
                run_approved_notice(config, sub.get_one::<String>("value").map(String::as_str))
            }
            ("impact-budget", sub) => {
                run_impact_budget(config, sub.get_one::<String>("ms").map(String::as_str))
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
                if !enables.is_empty() || !disables.is_empty() {
                    run_groups(config, &enables, &disables)
                } else if sub.get_flag("pick") {
                    run_groups_interactive(config, None)
                } else {
                    run_groups_list(config)
                }
            }
            ("ignore", sub) => run_pattern_list_cmd(config, sub, PatternListKind::Ignore),
            (verb @ ("unignore" | "undeny"), sub) => Ok(remove_hint(
                &verb[2..],
                sub.get_one::<String>("pattern").map(String::as_str),
            )),
            ("deny", sub) => run_pattern_list_cmd(config, sub, PatternListKind::Deny),
            ("llm", sub) => run_llm_cmd(config, sub),
            ("context", sub) => run_context_cmd(config, sub),
            ("escalation", sub) => run_escalation_cmd(config, sub),
            _ => unreachable!(),
        },
    )
}

/// `config unignore X` / `config undeny X` do not exist: point to the
/// `--remove` form instead of clap's "a similar subcommand exists: 'ignore'".
fn remove_hint(list: &str, id: Option<&str>) -> shellfirm::CmdExit {
    let id = id.map_or_else(
        || "<CHECK_ID>".to_string(),
        shellfirm::context::escape_invisible,
    );
    shellfirm::CmdExit {
        code: sf_config::EXIT_USAGE,
        message: Some(format!(
            "shellfirm: error: there is no `config un{list}`; use `shellfirm config {list} --remove {id}`"
        )),
    }
}

// ---------------------------------------------------------------------------
// reset
// ---------------------------------------------------------------------------

/// Reset the settings file.
///
/// The old file is always backed up first, nothing is written until every
/// question has been answered (aborting leaves the file untouched), and
/// without a terminal the command explains how to proceed instead of
/// failing with a raw prompt error.
pub fn run_reset_with(config: &Config, yes: bool) -> shellfirm::CmdExit {
    let fail = |msg: String| shellfirm::CmdExit {
        code: exitcode::CONFIG,
        message: Some(msg),
    };
    let mut root = serde_yaml::Value::Mapping(serde_yaml::Mapping::default());

    if !yes {
        if !is_interactive() {
            return shellfirm::CmdExit {
                code: exitcode::USAGE,
                message: Some(
                    "`shellfirm config reset` asks for confirmation and needs a terminal.\n\
                     Run `shellfirm config reset --yes` to reset to the defaults without prompting."
                        .to_string(),
                ),
            };
        }
        match shellfirm::prompt::confirm(
            "Reset shellfirm settings to the defaults? (your current file is backed up first)",
            false,
        ) {
            Ok(true) => {}
            Ok(false) => {
                return shellfirm::CmdExit {
                    code: exitcode::OK,
                    message: Some("Reset cancelled; your settings were not changed.".to_string()),
                };
            }
            Err(e) => {
                return fail(format!(
                    "reset aborted; your settings were not changed ({e})"
                ))
            }
        }
        if let Err(e) = collect_setup_choices(&mut root) {
            return fail(format!(
                "reset aborted; your settings were not changed ({e})"
            ));
        }
    }

    let _lock = match config.lock_settings() {
        Ok(l) => l,
        Err(e) => return fail(format!("reset aborted: {e}")),
    };
    let backup = match config.backup_settings_file() {
        Ok(b) => b,
        Err(e) => return fail(format!("reset aborted: {e}")),
    };
    let write = if root.as_mapping().is_some_and(serde_yaml::Mapping::is_empty) {
        config.reset_config()
    } else {
        config.save_config_from_value(&root)
    };
    if let Err(e) = write {
        return fail(format!("reset failed: {e}"));
    }

    let mut msg = format!(
        "shellfirm settings reset ({})",
        config.setting_file_path.display()
    );
    if let Some(b) = backup {
        msg.push_str("\nPrevious settings saved to ");
        msg.push_str(&b.display().to_string());
    }
    shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some(msg),
    }
}

// ---------------------------------------------------------------------------
// Shared interactive setup (used by both init and config reset)
// ---------------------------------------------------------------------------

/// Ask the setup questions (challenge type + protection level) and record
/// the answers in `root`. Returns `Ok(true)` when anything was chosen.
///
/// # Errors
///
/// Returns an error when a prompt is aborted (Esc / Ctrl-C) or fails.
fn collect_setup_choices(root: &mut serde_yaml::Value) -> Result<bool> {
    let idx = shellfirm::prompt::select_with_default(
        "Choose your challenge type:",
        &[
            "Math  — solve a quick math problem (e.g. 3 + 7 = ?)",
            "Enter — just press Enter to confirm",
            "Yes   — type \"yes\" to confirm",
        ],
        0,
    )?;
    let challenge = match idx {
        1 => Challenge::Enter,
        2 => Challenge::Yes,
        _ => Challenge::Math,
    };
    shellfirm::value_set(root, "challenge", serde_yaml::to_value(challenge)?)?;

    let idx = shellfirm::prompt::select_with_default(
        "Choose your protection level:",
        &[
            "Paranoid — catches everything, even low-risk commands",
            "Balanced — catches medium-risk and above (Recommended)",
            "Chill    — only high-risk and critical commands",
            "YOLO     — only critical, truly destructive commands",
        ],
        1,
    )?;
    let severity: Option<Severity> = match idx {
        0 => None,
        2 => Some(Severity::High),
        3 => Some(Severity::Critical),
        _ => Some(Severity::Medium),
    };
    shellfirm::value_set(root, "min_severity", serde_yaml::to_value(severity)?)?;
    Ok(true)
}

/// Prompt the user to choose a challenge type and protection level, then save.
///
/// Only the chosen keys are written (sparse), on top of the existing file.
/// When new questions are added here, both `init` and `config reset`
/// automatically pick them up.
///
/// Skipped when stderr is not a terminal (piped / non-interactive).
///
/// # Errors
///
/// Will return `Err` if the existing settings file is not valid YAML (it is
/// never overwritten in that case) or if settings cannot be saved.
pub fn run_interactive_setup(config: &Config) -> Result<()> {
    if !std::io::stderr().is_terminal() {
        return Ok(());
    }

    let mut root = config.read_config_as_value().map_err(|e| {
        Error::Config(format!(
            "not changing {} because it is not valid YAML: {e}",
            config.setting_file_path.display()
        ))
    })?;
    if !root.is_mapping() {
        root = serde_yaml::Value::Mapping(serde_yaml::Mapping::default());
    }

    // An aborted prompt leaves the file untouched.
    if collect_setup_choices(&mut root).unwrap_or(false) {
        config.save_config_from_value(&root)?;
        println!(
            "\n  {} saved to {}\n",
            style("Settings").green().bold(),
            style(config.setting_file_path.display().to_string()).cyan(),
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// edit
// ---------------------------------------------------------------------------

/// Validate settings text the way `config edit` does: it must parse, every
/// value must be valid and every top-level key must be known.
///
/// # Errors
///
/// Returns a message describing every problem found.
#[cfg(test)]
pub fn validate_settings_text(content: &str) -> Result<()> {
    validate_settings_text_with(content, &[])
}

/// [`validate_settings_text`], also rejecting unknown check ids and groups
/// (built-ins plus `custom` checks), exactly like the CLI setters do.
pub fn validate_settings_text_with(
    content: &str,
    custom: &[shellfirm::checks::Check],
) -> Result<()> {
    let settings = sf_config::parse_settings_strict(content)?;
    let unknown = sf_config::unknown_settings_key_warnings(content);
    if !unknown.is_empty() {
        return Err(Error::Config(format!(
            "{}. Valid top-level keys: {}",
            unknown.join("; "),
            sf_config::known_settings_keys().join(", ")
        )));
    }
    let refs = sf_config::unknown_reference_warnings(&settings, custom, &[]);
    if !refs.is_empty() {
        return Err(Error::Config(format!(
            "{}. List ids with `shellfirm check --list --all` and groups with \
             `shellfirm config groups`",
            refs.join("; ")
        )));
    }
    Ok(())
}

/// Split `$EDITOR` into program + arguments (`EDITOR="code -w"` works).
fn editor_command() -> (String, Vec<String>) {
    let raw = std::env::var("VISUAL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            std::env::var("EDITOR")
                .ok()
                .filter(|v| !v.trim().is_empty())
        })
        .unwrap_or_else(|| "vi".to_string());
    let mut parts = raw.split_whitespace().map(ToString::to_string);
    let program = parts.next().unwrap_or_else(|| "vi".to_string());
    (program, parts.collect())
}

pub fn run_edit(config: &Config) -> Result<shellfirm::CmdExit> {
    std::fs::create_dir_all(&config.root_folder)?;
    let original = if config.setting_file_path.exists() {
        config.read_config_file()?
    } else {
        String::from("# shellfirm settings. Keys that are not listed use the built-in defaults.\n")
    };

    // Edit a temporary copy: the real file is only replaced once the edit
    // is known to be valid.
    let tmp = config
        .root_folder
        .join(format!(".settings.edit-{}.yaml", std::process::id()));
    std::fs::write(&tmp, &original)?;

    let (program, args) = editor_command();
    let status = std::process::Command::new(&program)
        .args(&args)
        .arg(&tmp)
        .status();
    let status = match status {
        Ok(s) => s,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(Error::Config(format!(
                "failed to launch editor '{program}': {e} (set $EDITOR or $VISUAL)"
            )));
        }
    };
    if !status.success() {
        let _ = std::fs::remove_file(&tmp);
        return Ok(shellfirm::CmdExit {
            code: exitcode::CONFIG,
            message: Some(format!(
                "editor exited with {status}; settings were not changed"
            )),
        });
    }

    let edited = std::fs::read_to_string(&tmp)?;
    if edited == original {
        let _ = std::fs::remove_file(&tmp);
        return Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: Some("No changes.".to_string()),
        });
    }

    if let Err(e) = validate_settings_text_with(&edited, &custom_checks(config)) {
        // Keep only this rejected copy (older leftovers are removed).
        config.cleanup_edit_leftovers(Some(&tmp));
        return Ok(shellfirm::CmdExit {
            code: exitcode::CONFIG,
            message: Some(format!(
                "Invalid configuration — changes NOT applied: {e}\n\
                 {} was left unchanged. Your edits are kept in {}.\n\
                 Run `shellfirm config edit` to try again.",
                config.setting_file_path.display(),
                tmp.display()
            )),
        });
    }

    {
        let _lock = config.lock_settings()?;
        config.save_settings_text(&edited)?;
    }
    config.cleanup_edit_leftovers(None);
    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some("Configuration updated successfully.".to_string()),
    })
}

// ---------------------------------------------------------------------------
// show
// ---------------------------------------------------------------------------

/// Load settings for a `config` subcommand; on failure add a hint on how to
/// fix the file (it is never overwritten).
fn load_settings(config: &Config) -> Result<Settings> {
    config.get_settings_from_file().map_err(|e| {
        Error::Config(format!(
            "{e}\nThe file was not changed. Fix it with `shellfirm config edit`, or start over \
             with `shellfirm config reset` (the old file is backed up)."
        ))
    })
}

/// Add the "how to fix" hint to errors about an invalid settings file.
fn with_fix_hint(e: Error) -> Error {
    match e {
        Error::Config(m)
            if m.starts_with("invalid settings file")
                || m.starts_with("could not read settings") =>
        {
            Error::Config(format!(
                "{m}\nThe file was not changed. Fix it with `shellfirm config edit`, or start over \
                 with `shellfirm config reset` (the old file is backed up)."
            ))
        }
        other => other,
    }
}

/// Lock, re-read, modify and save the settings (see
/// [`Config::modify_settings`]). `f` returns its result and whether the
/// settings changed.
fn modify<T>(config: &Config, f: impl FnOnce(&mut Settings) -> Result<(T, bool)>) -> Result<T> {
    config.modify_settings(f).map_err(with_fix_hint)
}

/// Load, modify and save settings (sparse write; refuses invalid files).
fn update_settings(config: &Config, f: impl FnOnce(&mut Settings)) -> Result<()> {
    modify(config, |s| {
        f(s);
        Ok(((), true))
    })
}

pub fn run_show(config: &Config) -> Result<shellfirm::CmdExit> {
    let settings = load_settings(config)?;
    let custom = custom_checks(config);
    let mut output = format_settings_display(
        &settings,
        &config.setting_file_path,
        &sf_config::known_groups(&custom),
    );
    if !config.setting_file_path.exists() {
        output = output.replacen(
            &config.setting_file_path.display().to_string(),
            &format!(
                "{} (not created yet — showing defaults)",
                config.setting_file_path.display()
            ),
            1,
        );
    }
    if config.setting_file_path.exists() {
        let mut warnings = config.settings_warnings();
        warnings.extend(sf_config::unknown_reference_warnings(
            &settings,
            &custom,
            &[],
        ));
        if !warnings.is_empty() {
            output.push('\n');
        }
        for w in warnings {
            output.push_str("\nwarning: ");
            output.push_str(&w);
        }
    }
    let env = shellfirm::env::RealEnvironment;
    let cwd = std::env::current_dir().unwrap_or_default();
    let pol = shellfirm::policy::discover_all(&env, &cwd);
    if pol.found_any() {
        use std::fmt::Write as _;
        let _ = write!(
            output,
            "\n\npolicy:  {} policy file(s) apply here and can only make this stricter \
             (see `shellfirm policy show`)",
            pol.files.len()
        );
    }
    // Ids and names may carry bidi / zero-width characters: escaped.
    Ok(crate::print_stdout(&sf_config::ascii_fallback(
        &shellfirm::context::escape_invisible(&output),
    )))
}

#[allow(clippy::too_many_lines)]
fn format_settings_display(
    settings: &Settings,
    config_path: &std::path::Path,
    known_groups: &std::collections::BTreeSet<String>,
) -> String {
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
    let cap = shellfirm::audit::MAX_AUDIT_FILES_LIMIT;
    lines.push(if settings.audit_max_files > cap {
        format!(
            "audit_max_files: {cap} (your value {} is capped at {cap}; rotated audit.log.N \
             files kept; each up to 10 MiB)",
            settings.audit_max_files
        )
    } else {
        format!(
            "audit_max_files: {} (rotated audit.log.N files kept; each up to 10 MiB)",
            settings.audit_max_files
        )
    });
    lines.push(format!(
        "blast_radius:   {}",
        if !settings.blast_radius {
            "disabled (`blast_radius: false` in the settings file, an older switch; \
             `shellfirm config impact-budget 400` turns it on)"
                .to_string()
        } else if settings.blast_radius_budget_ms == 0 {
            "disabled (blast_radius_budget_ms: 0; `shellfirm config impact-budget 400` turns it on)"
                .to_string()
        } else if settings.blast_radius_budget_ms > sf_config::MAX_BLAST_RADIUS_BUDGET_MS {
            format!(
                "enabled (at most {} ms per command: your value {} is capped; \
                 `shellfirm config impact-budget <ms>`)",
                settings.blast_radius_budget(),
                settings.blast_radius_budget_ms
            )
        } else {
            format!(
                "enabled (at most {} ms per command; `shellfirm config impact-budget <ms>`)",
                settings.blast_radius_budget_ms
            )
        }
    ));
    lines.push(format!(
        "approved_notice: {} (`shellfirm config approved-notice on|off`)",
        if settings.approved_notice {
            "on, a line after a passed challenge"
        } else {
            "off"
        }
    ));

    // Groups (unknown names match nothing and are not counted as active)
    let (active, unknown): (Vec<&str>, Vec<&str>) = settings
        .enabled_groups
        .iter()
        .filter(|g| !settings.disabled_groups.contains(g))
        .map(String::as_str)
        .partition(|g| known_groups.contains(*g));
    let disabled_count = settings.disabled_groups.len();
    lines.push(String::new());
    lines.push(format!(
        "groups ({} active, {disabled_count} disabled):",
        active.len()
    ));
    let groups_str = active.join(", ");
    lines.push(format!("  {groups_str}"));
    if !unknown.is_empty() {
        lines.push(format!("  unknown (ignored): {}", unknown.join(", ")));
    }
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
        "  escalation:         at least {} in an elevated context ({}), at least {} in a \
         critical one ({})",
        settings.context.escalation.elevated,
        sf_config::ELEVATED_CONTEXTS,
        settings.context.escalation.critical,
        sf_config::CRITICAL_CONTEXTS
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
            "  severity:  minimum challenge per severity (a challenge is only ever raised; \
             Enter < Math < Yes)\n             Critical: at least {}, High: at least {}, \
             Medium: at least {}, Low: at least {}, Info: at least {}",
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
            .map(|(k, v)| format!("{k}: at least {v}"))
            .collect();
        entries.sort();
        lines.push(format!("  groups:    {}", entries.join(", ")));
    }
    if !settings.check_escalation.is_empty() {
        let mut entries: Vec<String> = settings
            .check_escalation
            .iter()
            .map(|(k, v)| format!("{k}: at least {v}"))
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
    let challenge = parse_challenge(value, "challenge type")?;
    update_settings(config, |s| s.challenge = challenge)?;
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
    if force_selection.is_none() && !is_interactive() {
        // Without a value (and no terminal to pick one): show the current one.
        let current = load_settings(config)?.challenge;
        return Ok(crate::print_stdout(&format!(
            "challenge = {current}\n(change it with `shellfirm config challenge <VALUE>`; valid values: {VALID_CHALLENGES})"
        )));
    }
    let items = &["Math", "Enter", "Yes"];
    let current = load_settings(config)?.challenge;
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
// approved-notice / impact-budget
// ---------------------------------------------------------------------------

const fn on_off(on: bool) -> &'static str {
    if on {
        "on"
    } else {
        "off"
    }
}

/// `config approved-notice [on|off]`: the `approved_notice` setting.
pub fn run_approved_notice(config: &Config, value: Option<&str>) -> Result<shellfirm::CmdExit> {
    let Some(value) = value else {
        let current = load_settings(config)?.approved_notice;
        return Ok(crate::print_stdout(&format!(
            "approved_notice = {}\n(change it with `shellfirm config approved-notice on|off`)",
            on_off(current)
        )));
    };
    let on = match value.trim().to_ascii_lowercase().as_str() {
        "on" | "true" | "yes" | "1" => true,
        "off" | "false" | "no" | "0" => false,
        _ => {
            return Err(Error::Usage(format!(
                "invalid value '{}' for approved-notice. Valid values: on, off",
                shellfirm::context::escape_invisible(value)
            )))
        }
    };
    update_settings(config, |s| s.approved_notice = on)?;
    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some(format!("approved_notice = {}", on_off(on))),
    })
}

/// `config impact-budget [<ms>]`: the `blast_radius_budget_ms` setting.
pub fn run_impact_budget(config: &Config, value: Option<&str>) -> Result<shellfirm::CmdExit> {
    let max = sf_config::MAX_BLAST_RADIUS_BUDGET_MS;
    let Some(value) = value else {
        let settings = load_settings(config)?;
        let current = settings.blast_radius_budget_ms;
        let note = if current > max {
            format!(" (more than {max}: {max} is used)")
        } else if !settings.blast_radius {
            " (but `blast_radius: false` keeps the measurement off; set a budget to turn it on)"
                .to_string()
        } else {
            String::new()
        };
        return Ok(crate::print_stdout(&format!(
            "blast_radius_budget_ms = {current}{note}\n(change it with `shellfirm config \
             impact-budget <ms>`; 0 turns the impact measurement off, at most {max}, default {})",
            sf_config::DEFAULT_BLAST_RADIUS_BUDGET_MS
        )));
    };
    let digits = value.trim().trim_end_matches("ms").trim();
    let ms = digits
        .parse::<u64>()
        .ok()
        .filter(|ms| *ms <= max)
        .ok_or_else(|| {
            Error::Usage(format!(
                "invalid impact budget '{}': give milliseconds from 0 (off) to {max}, e.g. \
                 `shellfirm config impact-budget 400`",
                shellfirm::context::escape_invisible(value)
            ))
        })?;
    // One switch: a budget above 0 also clears an older `blast_radius:
    // false` (the TUI toggle of earlier versions), which would silently
    // keep the measurement off.
    let was_off = load_settings(config).is_ok_and(|s| !s.blast_radius);
    update_settings(config, |s| {
        s.blast_radius_budget_ms = ms;
        if ms > 0 {
            s.blast_radius = true;
        }
    })?;
    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some(if ms == 0 {
            "blast_radius_budget_ms = 0 (impact not measured)".to_string()
        } else if was_off {
            format!(
                "blast_radius_budget_ms = {ms} (and the older `blast_radius: false` was \
                 removed, so the impact is measured again)"
            )
        } else {
            format!("blast_radius_budget_ms = {ms}")
        }),
    })
}

// ---------------------------------------------------------------------------
// severity
// ---------------------------------------------------------------------------

const VALID_SEVERITIES: &str = "all, Info, Low, Medium, High, Critical";

fn parse_severity(value: &str) -> std::result::Result<Option<Severity>, String> {
    match value.to_lowercase().as_str() {
        "all" | "null" | "" => Ok(None),
        "info" => Ok(Some(Severity::Info)),
        "low" => Ok(Some(Severity::Low)),
        "medium" => Ok(Some(Severity::Medium)),
        "high" => Ok(Some(Severity::High)),
        "critical" => Ok(Some(Severity::Critical)),
        _ => Err(format!(
            "invalid severity: '{value}'. Valid values: {VALID_SEVERITIES}"
        )),
    }
}

pub fn run_severity(config: &Config, value: &str) -> Result<shellfirm::CmdExit> {
    let severity = parse_severity(value).map_err(Error::Usage)?;
    update_settings(config, |s| s.min_severity = severity)?;
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
    if force_selection.is_none() && !is_interactive() {
        // Without a value (and no terminal to pick one): show the current one.
        let current = load_settings(config)?
            .min_severity
            .map_or_else(|| "(all)".to_string(), |s| s.to_string());
        return Ok(crate::print_stdout(&format!(
            "min_severity = {current}\n(change it with `shellfirm config severity <LEVEL>`; valid values: {VALID_SEVERITIES})"
        )));
    }
    let items = &["(all)", "Info", "Low", "Medium", "High", "Critical"];
    let current = load_settings(config)?.min_severity;
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

/// All group names that can be enabled/disabled: built-in groups (including
/// ones that are off by default, such as `shell`) plus custom-check groups.
fn available_groups(config: &Config) -> Vec<String> {
    sf_config::known_groups(&custom_checks(config))
        .into_iter()
        .collect()
}

pub fn run_groups(
    config: &Config,
    enables: &[&str],
    disables: &[&str],
) -> Result<shellfirm::CmdExit> {
    let available = available_groups(config);
    // Validate group names
    for &name in enables.iter().chain(disables.iter()) {
        if !available.iter().any(|g| g == name) {
            return Ok(unknown_group_exit(name, &available));
        }
    }
    if let Some(both) = enables.iter().find(|e| disables.contains(e)) {
        return Err(Error::Config(format!(
            "group '{both}' cannot be both enabled and disabled"
        )));
    }

    // Sparse: a group is active when it is in `enabled_groups` and not in
    // `disabled_groups`, so disabling only adds to `disabled_groups` and
    // never pins the full `enabled_groups` list (which would keep groups
    // added by a later release switched off).
    modify(config, |settings| {
        let before = (
            settings.enabled_groups.clone(),
            settings.disabled_groups.clone(),
        );
        apply_group_changes(settings, enables, disables);
        let changed = before
            != (
                settings.enabled_groups.clone(),
                settings.disabled_groups.clone(),
            );
        Ok(((), changed))
    })?;

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

/// Apply `--enable` / `--disable` to the group lists with the smallest
/// change (see [`run_groups`]).
fn apply_group_changes(settings: &mut Settings, enables: &[&str], disables: &[&str]) {
    for &name in enables {
        settings.disabled_groups.retain(|g| g != name);
        if !settings.enabled_groups.iter().any(|g| g == name) {
            settings.enabled_groups.push(name.to_string());
        }
    }
    for &name in disables {
        if !settings.disabled_groups.iter().any(|g| g == name) {
            settings.disabled_groups.push(name.to_string());
        }
    }
}

/// `config groups` without arguments: every group and whether it is active.
fn run_groups_list(config: &Config) -> Result<shellfirm::CmdExit> {
    let mut settings = load_settings(config)?;
    let custom = custom_checks(config);
    settings.migrate_custom_groups_into_enabled_groups(&custom);
    let mut lines = vec!["check groups:".to_string()];
    let mut active = 0;
    let all = available_groups(config);
    for g in &all {
        let on = settings.enabled_groups.contains(g) && !settings.disabled_groups.contains(g);
        if on {
            active += 1;
        }
        let state = if on {
            "active"
        } else if settings.disabled_groups.contains(g) {
            "disabled"
        } else {
            "not enabled"
        };
        lines.push(format!("  {g:<12} {state}"));
    }
    lines.push(format!(
        "{active} of {} active. Change with `shellfirm config groups --enable <GROUP>` / \
         `--disable <GROUP>`{}.",
        all.len(),
        if is_interactive() {
            ", or pick them with `--pick`"
        } else {
            ""
        }
    ));
    Ok(crate::print_stdout(&lines.join("\n")))
}

fn run_groups_interactive(
    config: &Config,
    force_selections: Option<&[usize]>,
) -> Result<shellfirm::CmdExit> {
    if force_selections.is_none() && !is_interactive() {
        return Err(Error::Config(
            "`--pick` needs a terminal. Use `shellfirm config groups --enable <GROUP>` / \
             `--disable <GROUP>`, or `shellfirm config groups` to list the groups."
                .into(),
        ));
    }
    let settings = load_settings(config)?;
    let custom = custom_checks(config);
    let mut effective = settings;
    effective.migrate_custom_groups_into_enabled_groups(&custom);
    let owned = available_groups(config);
    let items: Vec<&str> = owned.iter().map(String::as_str).collect();
    let defaults: Vec<bool> = items
        .iter()
        .map(|&group| {
            effective.enabled_groups.iter().any(|g| g == group)
                && !effective.disabled_groups.iter().any(|g| g == group)
        })
        .collect();

    let selected_indices = if let Some(forced) = force_selections {
        forced.to_vec()
    } else {
        shellfirm::prompt::multi_select("Select check groups to enable:", &items, &defaults)?
    };

    // Only the groups whose state changed are written.
    let mut enables = Vec::new();
    let mut disables = Vec::new();
    for (i, &group) in items.iter().enumerate() {
        let selected = selected_indices.contains(&i);
        if selected && !defaults[i] {
            enables.push(group);
        } else if !selected && defaults[i] {
            disables.push(group);
        }
    }
    if enables.is_empty() && disables.is_empty() {
        return Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: Some("groups: no change".to_string()),
        });
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
    let list_key = match kind {
        PatternListKind::Ignore => "ignores_patterns_ids",
        PatternListKind::Deny => "deny_patterns_ids",
    };
    if sf_config::is_builtin_protection_id(id) {
        if let Some(why) = sf_config::builtin_protection_refusal(id, list_key) {
            return Err(Error::Config(sentence(&why)));
        }
    } else {
        ensure_known_check_id(config, id)?;
    }
    let msg = modify(config, |settings| {
        let (list, other) = match kind {
            PatternListKind::Ignore => (
                &mut settings.ignores_patterns_ids,
                &settings.deny_patterns_ids,
            ),
            PatternListKind::Deny => (
                &mut settings.deny_patterns_ids,
                &settings.ignores_patterns_ids,
            ),
        };
        if list.iter().any(|existing| existing == id) {
            return Ok((
                format!(
                    "{} list: '{id}' is already present (no change)",
                    kind.label()
                ),
                false,
            ));
        }
        let also_other = other.iter().any(|x| x == id);
        list.push(id.to_string());
        let mut msg = format!("{} list: added '{id}'", kind.label());
        if also_other {
            let note = match kind {
                PatternListKind::Ignore => format!(
                    "\nwarning: '{id}' is also in your deny list. A deny always wins, so the \
                     command stays blocked; remove it with `shellfirm config deny --remove {id}` \
                     if you want to ignore it."
                ),
                PatternListKind::Deny => format!(
                    "\nwarning: '{id}' is also in your ignore list. The deny wins (it is always \
                     blocked); remove the ignore with `shellfirm config ignore --remove {id}`."
                ),
            };
            msg.push_str(&note);
        }
        Ok((msg, true))
    })?;
    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some(shellfirm::context::escape_invisible(&msg)),
    })
}

pub fn run_pattern_list_remove(
    config: &Config,
    kind: PatternListKind,
    id: &str,
) -> Result<shellfirm::CmdExit> {
    let msg = modify(config, |settings| {
        let list = match kind {
            PatternListKind::Ignore => &mut settings.ignores_patterns_ids,
            PatternListKind::Deny => &mut settings.deny_patterns_ids,
        };
        let before = list.len();
        list.retain(|existing| existing != id);
        if list.len() == before {
            return Ok((
                format!("{} list: '{id}' is not present (no change)", kind.label()),
                false,
            ));
        }
        Ok((format!("{} list: removed '{id}'", kind.label()), true))
    })?;
    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some(shellfirm::context::escape_invisible(&msg)),
    })
}

fn run_pattern_list_show(config: &Config, kind: PatternListKind) -> Result<shellfirm::CmdExit> {
    let settings = load_settings(config)?;
    let list = match kind {
        PatternListKind::Ignore => &settings.ignores_patterns_ids,
        PatternListKind::Deny => &settings.deny_patterns_ids,
    };
    if list.is_empty() {
        println!("{} list: (empty)", kind.label());
    } else {
        let known = sf_config::known_check_ids(&custom_checks(config));
        println!("{} list:", kind.label());
        for id in list {
            let shown = shellfirm::context::escape_invisible(id);
            if known.contains(id) {
                println!("  {shown}");
            } else {
                println!(
                    "{}",
                    sf_config::ascii_fallback(&format!(
                        "  {shown}   (unknown id — matches nothing)"
                    ))
                );
            }
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

    if !is_interactive() {
        return Err(Error::Config(
            "`shellfirm config llm` without options asks interactively and needs a terminal.\n\
             Use flags instead, e.g. `shellfirm config llm --provider anthropic --model <MODEL>` \
             (see `shellfirm config llm --help`)."
                .into(),
        ));
    }
    run_llm_interactive(config, None)
}

pub fn run_llm(
    config: &Config,
    provider: Option<&str>,
    model: Option<&str>,
    timeout: Option<&str>,
    base_url: Option<&str>,
) -> Result<shellfirm::CmdExit> {
    let timeout_ms = timeout
        .map(|t| {
            t.parse::<u64>().map_err(|_| {
                Error::Config(format!("invalid timeout: '{t}' (expected milliseconds)"))
            })
        })
        .transpose()?;
    let changes = modify(config, |settings| {
        let mut llm = settings.llm.clone().unwrap_or_default();
        let mut changes = Vec::new();

        if let Some(p) = provider {
            llm.provider = p.to_string();
            changes.push(format!("provider = {p}"));
        }
        if let Some(m) = model {
            llm.model = m.to_string();
            changes.push(format!("model = {m}"));
        }
        if let Some(ms) = timeout_ms {
            #[cfg(feature = "llm")]
            if let Some(warning) = shellfirm::llm::timeout_warning(ms) {
                eprintln!("shellfirm: warning: {warning}");
            }
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

        llm.validate()?;
        settings.llm = Some(llm);
        Ok((changes, true))
    })?;
    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some(format!("llm updated: {}", changes.join(", "))),
    })
}

fn run_llm_interactive(
    config: &Config,
    force_values: Option<(&str, &str)>,
) -> Result<shellfirm::CmdExit> {
    let settings = load_settings(config)?;
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
        Some(("env", sub)) => run_context_env(
            config,
            sub.get_one::<String>("add").map(String::as_str),
            sub.get_one::<String>("remove").map(String::as_str),
        ),
        _ => {
            if !is_interactive() {
                return Err(Error::Config(
                    "`shellfirm config context` opens an interactive menu and needs a terminal.\n\
                     Use a subcommand instead: `shellfirm config context branches|k8s|escalation|paths|env` \
                     (e.g. `shellfirm config context branches --add develop`)."
                        .into(),
                ));
            }
            run_context_interactive(config, None)
        }
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
        let settings = load_settings(config)?;
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

    if add.is_some_and(|v| v.trim().is_empty()) {
        return Err(Error::Config(format!(
            "{}: the value must not be empty",
            field.label()
        )));
    }
    let msg_parts = modify(config, |settings| {
        let mut parts = Vec::new();
        let mut changed = false;
        let list = get_context_list_mut(settings, field);
        if let Some(value) = add {
            if list.iter().any(|v| v == value) {
                parts.push(format!("'{value}' is already present (no change)"));
            } else {
                list.push(value.to_string());
                parts.push(format!("added '{value}'"));
                changed = true;
            }
        }
        if let Some(value) = remove {
            let before = list.len();
            list.retain(|v| v != value);
            if list.len() == before {
                parts.push(format!("'{value}' is not present (no change)"));
            } else {
                parts.push(format!("removed '{value}'"));
                changed = true;
            }
        }
        Ok((parts, changed))
    })?;
    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some(format!("{}: {}", field.label(), msg_parts.join(", "))),
    })
}

/// `config context env --add NAME=VALUE` / `--remove NAME[=VALUE]` (or list).
pub fn run_context_env(
    config: &Config,
    add: Option<&str>,
    remove: Option<&str>,
) -> Result<shellfirm::CmdExit> {
    if add.is_none() && remove.is_none() {
        let settings = load_settings(config)?;
        let vars = &settings.context.production_env_vars;
        if vars.is_empty() {
            println!("production env vars: (empty)");
        } else {
            println!("production env vars:");
            for (k, v) in vars {
                println!("  {k}={v}");
            }
        }
        return Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: None,
        });
    }
    let parsed = add
        .map(|a| {
            a.split_once('=')
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                .filter(|(k, v)| !k.is_empty() && !v.is_empty() && !k.contains(char::is_whitespace))
                .ok_or_else(|| {
                    Error::Config(format!(
                        "invalid value for --add: '{a}' (expected NAME=VALUE, e.g. APP_ENV=production)"
                    ))
                })
        })
        .transpose()?;
    let parts = modify(config, |settings| {
        let vars = &mut settings.context.production_env_vars;
        let mut parts = Vec::new();
        let mut changed = false;
        if let Some((k, v)) = &parsed {
            if vars.get(k) == Some(v) {
                parts.push(format!("'{k}={v}' is already present (no change)"));
            } else {
                vars.insert(k.clone(), v.clone());
                parts.push(format!("set '{k}={v}'"));
                changed = true;
            }
        }
        if let Some(entry) = remove {
            // `--remove NAME` or `--remove NAME=VALUE` (what `--add` takes
            // and the list prints).
            let (k, want) = entry
                .split_once('=')
                .map_or_else(|| (entry.trim(), None), |(k, v)| (k.trim(), Some(v.trim())));
            match (vars.get(k), want) {
                (Some(cur), Some(v)) if cur != v => {
                    parts.push(format!(
                        "'{k}' is set to '{cur}', not '{v}' (no change; remove it with --remove {k})"
                    ));
                }
                (Some(_), _) => {
                    let v = vars.remove(k).unwrap_or_default();
                    parts.push(format!("removed '{k}={v}'"));
                    changed = true;
                }
                (None, _) => parts.push(format!("'{k}' is not present (no change)")),
            }
        }
        Ok((parts, changed))
    })?;
    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some(format!("production env vars: {}", parts.join(", "))),
    })
}

pub fn run_context_escalation(
    config: &Config,
    elevated: Option<&str>,
    critical: Option<&str>,
) -> Result<shellfirm::CmdExit> {
    let parse = |name: &str, val: &str| {
        Challenge::from_string(val).map_err(|_| {
            Error::Config(format!(
                "invalid challenge for {name}: '{val}'\n\nValid values: Math, Enter, Yes"
            ))
        })
    };
    let elevated_c = elevated.map(|v| parse("elevated", v)).transpose()?;
    let critical_c = critical.map(|v| parse("critical", v)).transpose()?;

    if elevated_c.is_none() && critical_c.is_none() {
        let settings = load_settings(config)?;
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

    let changes = modify(config, |settings| {
        let mut changes = Vec::new();
        if let Some(c) = elevated_c {
            settings.context.escalation.elevated = c;
            changes.push(format!("elevated = {c}"));
        }
        if let Some(c) = critical_c {
            settings.context.escalation.critical = c;
            changes.push(format!("critical = {c}"));
        }
        Ok((changes, true))
    })?;
    let defaults = shellfirm::context::EscalationConfig::default();
    let mut message = format!("escalation updated: {}", changes.join(", "));
    for (name, set, default, what) in [
        (
            "elevated",
            elevated_c,
            defaults.elevated,
            "elevated contexts (SSH, or git / kubectl did not answer in time)",
        ),
        (
            "critical",
            critical_c,
            defaults.critical,
            "critical contexts (root, production k8s / env, sensitive paths, protected branches)",
        ),
    ] {
        if let Some(c) = set.filter(|c| *c < default) {
            message.push_str(&lowered_warning(&format!(
                "--{name} {c} is below the default ({default}): {what} now ask for at least \
                 {c} instead of {default}. This lowers protection; restore it with \
                 `shellfirm config context escalation --{name} {default}`."
            )));
        }
    }
    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some(message),
    })
}

/// A warning line appended to a setter's confirmation message.
fn lowered_warning(text: &str) -> String {
    format!("\nshellfirm: warning: {text}")
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
        "Production env vars",
        "Done",
    ];
    let done = items.len() - 1;
    let mut default = 0;
    // The menu comes back after each view until "Done" (or Esc), so "Done"
    // is a real choice. A forced selection (tests) shows one view.
    loop {
        let idx = match force_selection {
            Some(i) => Some(i),
            None => select_or_cancel("Which context setting do you want to see?", items, default)?,
        };
        let Some(idx) = idx.filter(|i| *i != done) else {
            if idx.is_none() {
                // The menu's last cursor move is still in stdout's buffer:
                // flush it first so the line lands below the menu.
                let _ = std::io::Write::flush(&mut std::io::stdout());
                eprintln!("shellfirm: closed the context menu (nothing was changed).");
            }
            return Ok(shellfirm::CmdExit {
                code: exitcode::OK,
                message: None,
            });
        };
        let shown = match idx {
            0 => run_context_list(config, &ContextListField::Branches, None, None),
            1 => run_context_list(config, &ContextListField::K8s, None, None),
            2 => run_context_escalation(config, None, None),
            3 => run_context_list(config, &ContextListField::Paths, None, None),
            4 => run_context_env(config, None, None),
            _ => Ok(shellfirm::CmdExit {
                code: exitcode::CONFIG,
                message: Some("invalid selection".to_string()),
            }),
        }?;
        if force_selection.is_some() || shown.code != exitcode::OK {
            return Ok(shown);
        }
        if let Some(m) = shown.message.as_deref() {
            eprintln!("{m}");
        }
        println!();
        default = idx;
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
    let settings = load_settings(config)?;
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
        entries.sort_by_key(|(k, _)| (*k).clone());
        for (k, v) in entries {
            println!("  {k} = {v}");
        }
    }
    if settings.check_escalation.is_empty() {
        println!("check-id overrides: (none)");
    } else {
        println!("check-id overrides:");
        let mut entries: Vec<_> = settings.check_escalation.iter().collect();
        entries.sort_by_key(|(k, _)| (*k).clone());
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
        let settings = load_settings(config)?;
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

    let enabled = enabled_arg
        .map(|val| match val.to_lowercase().as_str() {
            "true" | "1" | "yes" => Ok(true),
            "false" | "0" | "no" => Ok(false),
            _ => Err(Error::Config(format!(
                "invalid value for --enabled: '{val}'\n\nValid values: true, false"
            ))),
        })
        .transpose()?;
    let changes = modify(config, |settings| {
        let mut changes = Vec::new();

        if let Some(enabled) = enabled {
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
        Ok((changes, true))
    })?;
    let mut message = format!("severity escalation updated: {}", changes.join(", "));
    let defaults = shellfirm::config::SeverityEscalationConfig::default();
    for (name, arg_val, default) in [
        ("critical", critical, defaults.critical),
        ("high", high, defaults.high),
        ("medium", medium, defaults.medium),
        ("low", low, defaults.low),
        ("info", info, defaults.info),
    ] {
        let set = arg_val.and_then(|v| Challenge::from_string(v).ok());
        if let Some(c) = set.filter(|c| *c < default) {
            message.push_str(&lowered_warning(&format!(
                "--{name} {c} is below the default ({default}): {name}-severity checks now ask \
                 for at least {c} instead of {default}. This lowers protection."
            )));
        }
    }
    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some(message),
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
    let settings = load_settings(config)?;
    let map = match kind {
        EscalationMapKind::Group => &settings.group_escalation,
        EscalationMapKind::Check => &settings.check_escalation,
    };
    if map.is_empty() {
        println!("{} overrides: (none)", kind.label());
    } else {
        println!("{} overrides:", kind.label());
        let mut entries: Vec<_> = map.iter().collect();
        entries.sort_by_key(|(k, _)| (*k).clone());
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
    match kind {
        EscalationMapKind::Group => {
            let groups = available_groups(config);
            if !groups.iter().any(|g| g == key) {
                return Ok(unknown_group_exit(key, &groups));
            }
        }
        EscalationMapKind::Check => ensure_known_check_id(config, key)?,
    }
    modify(config, |settings| {
        let map = match kind {
            EscalationMapKind::Group => &mut settings.group_escalation,
            EscalationMapKind::Check => &mut settings.check_escalation,
        };
        map.insert(key.to_string(), challenge);
        Ok(((), true))
    })?;
    let mut message = format!("{} override: {key} = {challenge}", kind.label());
    if challenge == Challenge::Enter {
        message.push_str(&lowered_warning(&format!(
            "an override only ever raises the challenge, and Enter is the weakest one, so \
             `{key} = Enter` changes nothing (it cannot lower the severity or context \
             escalation for {key})."
        )));
    }
    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some(message),
    })
}

pub fn run_escalation_map_remove(
    config: &Config,
    kind: EscalationMapKind,
    key: &str,
) -> Result<shellfirm::CmdExit> {
    let msg = modify(config, |settings| {
        let map = match kind {
            EscalationMapKind::Group => &mut settings.group_escalation,
            EscalationMapKind::Check => &mut settings.check_escalation,
        };
        if map.remove(key).is_none() {
            return Ok((
                format!("{} override: no override found for '{key}'", kind.label()),
                false,
            ));
        }
        Ok((format!("{} override: removed '{key}'", kind.label()), true))
    })?;
    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some(msg),
    })
}

// ---------------------------------------------------------------------------
// interactive menu (no subcommand)
// ---------------------------------------------------------------------------

#[cfg_attr(feature = "tui", allow(dead_code))]
fn run_interactive_menu(
    config: &Config,
    force_selection: Option<usize>,
) -> Result<shellfirm::CmdExit> {
    let settings = load_settings(config)?;
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

    use insta::assert_debug_snapshot;
    use shellfirm::DEFAULT_ENABLED_GROUPS;
    use tree_fs::Tree;

    use super::*;

    fn initialize_config_folder(temp_dir: &Tree) -> Config {
        let temp_dir = temp_dir.root.join("app");
        let config = Config::new(Some(&temp_dir.display().to_string())).unwrap();
        config.reset_config().unwrap();
        config
    }

    fn fresh_config(temp_dir: &Tree) -> Config {
        let temp_dir = temp_dir.root.join("fresh");
        Config::new(Some(&temp_dir.display().to_string())).unwrap()
    }

    #[test]
    fn context_env_remove_accepts_name_or_name_value() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        let vars = |config: &Config| {
            config
                .get_settings_from_file()
                .unwrap()
                .context
                .production_env_vars
        };
        run_context_env(&config, Some("DATABASE_URL=*prod*"), None).unwrap();
        run_context_env(&config, Some("APP_ENV=production"), None).unwrap();
        // The NAME=VALUE form `--list` prints.
        let out = run_context_env(&config, None, Some("DATABASE_URL=*prod*")).unwrap();
        assert!(
            out.message
                .as_deref()
                .unwrap()
                .contains("removed 'DATABASE_URL=*prod*'"),
            "{:?}",
            out.message
        );
        assert!(!vars(&config).contains_key("DATABASE_URL"));
        // A different value is reported, not silently ignored.
        let out = run_context_env(&config, None, Some("APP_ENV=staging")).unwrap();
        assert!(
            out.message
                .as_deref()
                .unwrap()
                .contains("is set to 'production'"),
            "{:?}",
            out.message
        );
        assert!(vars(&config).contains_key("APP_ENV"));
        // The name alone.
        run_context_env(&config, None, Some("APP_ENV")).unwrap();
        assert!(!vars(&config).contains_key("APP_ENV"));
    }

    // -----------------------------------------------------------------------
    // reset
    // -----------------------------------------------------------------------

    #[test]
    fn reset_config_restores_defaults() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        // Change challenge so reset has something to restore
        let mut settings = config.get_settings_from_file().unwrap();
        settings.challenge = Challenge::Yes;
        config.save_settings_file_from_struct(&settings).unwrap();
        assert_eq!(
            config.get_settings_from_file().unwrap().challenge,
            Challenge::Yes
        );
        config.reset_config().unwrap();
        assert_debug_snapshot!(config.get_settings_from_file());
    }

    #[test]
    fn reset_then_sparse_setup_round_trip() {
        // Simulates the non-interactive part of run_interactive_setup after
        // reset: read empty config → value_set challenge → value_set
        // min_severity → save → verify sparse file → verify defaults fill in.
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);

        // After reset the file is empty — read_config_as_value returns empty mapping
        let mut root = config.read_config_as_value().unwrap();
        assert!(root.as_mapping().unwrap().is_empty());

        // Set only challenge and min_severity (what run_interactive_setup does)
        shellfirm::value_set(
            &mut root,
            "challenge",
            serde_yaml::to_value(Challenge::Enter).unwrap(),
        )
        .unwrap();
        shellfirm::value_set(
            &mut root,
            "min_severity",
            serde_yaml::to_value(Some(Severity::Medium)).unwrap(),
        )
        .unwrap();
        config.save_config_from_value(&root).unwrap();

        // The file should be sparse — only the two keys we set
        let content = config.read_config_file().unwrap();
        assert!(content.contains("challenge"));
        assert!(content.contains("min_severity"));
        assert!(!content.contains("enabled_groups"), "file should be sparse");

        // Loading via get_settings_from_file should fill in all defaults
        let settings = config.get_settings_from_file().unwrap();
        assert_eq!(settings.challenge, Challenge::Enter);
        assert_eq!(settings.min_severity, Some(Severity::Medium));
        let expected_groups: Vec<String> = DEFAULT_ENABLED_GROUPS
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        assert_eq!(settings.enabled_groups, expected_groups);
        assert!(settings.audit_enabled);
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
        let output = format_settings_display(
            &settings,
            &config.setting_file_path,
            &sf_config::known_groups(&[]),
        );
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
    fn approved_notice_setter_turns_the_line_on_and_off() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        let r = run_approved_notice(&config, Some("off")).unwrap();
        assert_eq!(r.message.as_deref(), Some("approved_notice = off"));
        assert!(!config.get_settings_from_file().unwrap().approved_notice);
        run_approved_notice(&config, Some("ON")).unwrap();
        assert!(config.get_settings_from_file().unwrap().approved_notice);
        assert!(run_approved_notice(&config, Some("maybe")).is_err());
        assert!(config.get_settings_from_file().unwrap().approved_notice);
    }

    #[test]
    fn impact_budget_setter_validates_the_range() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        let r = run_impact_budget(&config, Some("1500")).unwrap();
        assert_eq!(r.message.as_deref(), Some("blast_radius_budget_ms = 1500"));
        assert_eq!(
            config
                .get_settings_from_file()
                .unwrap()
                .blast_radius_budget_ms,
            1500
        );
        run_impact_budget(&config, Some("0")).unwrap();
        assert_eq!(
            config
                .get_settings_from_file()
                .unwrap()
                .blast_radius_budget_ms,
            0
        );
        for bad in ["5001", "-1", "abc", ""] {
            // A bad command-line value is a usage error (exit 2).
            assert!(
                matches!(run_impact_budget(&config, Some(bad)), Err(Error::Usage(_))),
                "{bad}"
            );
        }
        assert!(matches!(
            run_approved_notice(&config, Some("maybe")),
            Err(Error::Usage(_))
        ));
        assert!(matches!(
            run_severity(&config, "Huge"),
            Err(Error::Usage(_))
        ));
        run_impact_budget(&config, Some("250ms")).unwrap();
        assert_eq!(
            config
                .get_settings_from_file()
                .unwrap()
                .blast_radius_budget_ms,
            250
        );
    }

    #[test]
    fn impact_budget_default_is_not_written_and_one_switch_decides() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = fresh_config(&temp_dir);
        std::fs::create_dir_all(config.setting_file_path.parent().unwrap()).unwrap();
        // The older TUI toggle wrote `blast_radius: false`.
        std::fs::write(&config.setting_file_path, "blast_radius: false\n").unwrap();
        let r = run_impact_budget(&config, Some("800")).unwrap();
        assert!(
            r.message
                .as_deref()
                .unwrap_or_default()
                .contains("blast_radius: false"),
            "{r:?}"
        );
        let s = config.get_settings_from_file().unwrap();
        assert!(s.blast_radius_on() && s.blast_radius_budget_ms == 800);
        // Back to the default: the file says nothing about either key.
        run_impact_budget(&config, Some("400")).unwrap();
        let text = std::fs::read_to_string(&config.setting_file_path).unwrap();
        assert!(!text.contains("blast_radius"), "{text}");
        run_approved_notice(&config, Some("off")).unwrap();
        run_approved_notice(&config, Some("on")).unwrap();
        let text = std::fs::read_to_string(&config.setting_file_path).unwrap();
        assert!(!text.contains("approved_notice"), "{text}");
    }

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
        assert!(settings.disabled_groups.contains(&"docker".to_string()));
        assert!(!settings
            .get_active_checks()
            .unwrap()
            .iter()
            .any(|c| c.from == "docker"));
        // Sparse: only the delta is written, never the full enabled list.
        let content = std::fs::read_to_string(&config.setting_file_path).unwrap();
        assert!(!content.contains("enabled_groups"), "{content}");
        assert!(content.contains("disabled_groups"), "{content}");
        // Re-enabling removes the delta again.
        run_groups(&config, &["docker"], &[]).unwrap();
        let content = std::fs::read_to_string(&config.setting_file_path).unwrap();
        assert!(!content.contains("enabled_groups"), "{content}");
        assert!(!content.contains("docker"), "{content}");
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
        let out = run_groups(&config, &["nonexistent"], &[]).unwrap();
        assert_eq!(out.code, sf_config::EXIT_USAGE);
        assert!(out.message.unwrap().contains("unknown check group"));
        // A transposition gets a suggestion.
        let out = run_groups(&config, &[], &["gti"]).unwrap();
        assert_eq!(out.code, sf_config::EXIT_USAGE);
        assert!(
            out.message
                .as_deref()
                .unwrap()
                .contains("Did you mean: git?"),
            "{:?}",
            out.message
        );
        // built-in groups that are off by default are allowed
        assert!(run_groups(&config, &["shell"], &[]).is_ok());
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
        let result =
            run_pattern_list_add(&config, PatternListKind::Deny, "fs:recursively_delete").unwrap();
        assert_eq!(result.code, exitcode::OK);
        assert!(config
            .get_settings_from_file()
            .unwrap()
            .deny_patterns_ids
            .contains(&"fs:recursively_delete".to_string()));
    }

    #[test]
    fn deny_remove() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        run_pattern_list_add(&config, PatternListKind::Deny, "fs:recursively_delete").unwrap();
        let result =
            run_pattern_list_remove(&config, PatternListKind::Deny, "fs:recursively_delete")
                .unwrap();
        assert_eq!(result.code, exitcode::OK);
        assert!(!config
            .get_settings_from_file()
            .unwrap()
            .deny_patterns_ids
            .contains(&"fs:recursively_delete".to_string()));
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
        let result = run_llm(&config, Some("openai-compatible"), None, None, None).unwrap();
        assert_eq!(result.code, exitcode::OK);
        assert_eq!(
            config
                .get_settings_from_file()
                .unwrap()
                .llm
                .unwrap()
                .provider,
            "openai-compatible"
        );
    }

    #[test]
    fn llm_set_multiple() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        let result = run_llm(
            &config,
            Some("openai-compatible"),
            Some("gpt-4"),
            Some("10000"),
            None,
        )
        .unwrap();
        assert_eq!(result.code, exitcode::OK);
        let llm = config
            .get_settings_from_file()
            .unwrap()
            .llm
            .expect("llm should be Some after run_llm");
        assert_eq!(llm.provider, "openai-compatible");
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

    // -----------------------------------------------------------------------
    // fail loud, never overwrite, validate ids
    // -----------------------------------------------------------------------

    fn write_settings(config: &Config, content: &str) {
        std::fs::create_dir_all(&config.root_folder).unwrap();
        std::fs::write(&config.setting_file_path, content).unwrap();
    }

    #[test]
    fn invalid_values_produce_messages_with_valid_values() {
        let temp_dir = tree_fs::TreeBuilder::default().create().unwrap();
        let config = initialize_config_folder(&temp_dir);
        let e = run_challenge(&config, "Banana").unwrap_err().to_string();
        assert!(
            e.contains("Banana") && e.contains("Math, Enter, Yes"),
            "{e}"
        );
        let e = run_severity(&config, "extreme").unwrap_err().to_string();
        assert!(e.contains("extreme") && e.contains("Critical"), "{e}");
        let e = run_llm(&config, None, None, Some("abc"), None)
            .unwrap_err()
            .to_string();
        assert!(e.contains("abc"), "{e}");
        let e = run_llm(&config, Some("bogus"), None, None, None)
            .unwrap_err()
            .to_string();
        assert!(e.contains("anthropic"), "{e}");
        let e = run_escalation_map_set(&config, EscalationMapKind::Group, "nope", "Yes").unwrap();
        assert_eq!(e.code, sf_config::EXIT_USAGE);
        assert!(e.message.unwrap().contains("unknown check group"));
    }

    #[test]
    fn setter_on_corrupt_file_refuses_and_keeps_file() {
        let temp_dir = tree_fs::TreeBuilder::default().create().unwrap();
        let config = initialize_config_folder(&temp_dir);
        let original = "challenge: Banana\ndeny_patterns_ids: [git:force_push]\n";
        write_settings(&config, original);
        let e = run_severity(&config, "High").unwrap_err().to_string();
        assert!(e.contains("settings.yaml") && e.contains("line"), "{e}");
        assert!(run_show(&config).is_err());
        assert_eq!(
            std::fs::read_to_string(&config.setting_file_path).unwrap(),
            original
        );
    }

    #[test]
    fn ignore_and_deny_validate_ids() {
        let temp_dir = tree_fs::TreeBuilder::default().create().unwrap();
        let config = initialize_config_folder(&temp_dir);
        let e = run_pattern_list_add(&config, PatternListKind::Ignore, "does:not_exist")
            .unwrap_err()
            .to_string();
        assert!(e.contains("unknown check id"), "{e}");
        let e = run_pattern_list_add(&config, PatternListKind::Deny, "git:forse_push")
            .unwrap_err()
            .to_string();
        assert!(e.contains("unknown check id"), "{e}");
        let r = run_pattern_list_remove(&config, PatternListKind::Ignore, "never:there").unwrap();
        assert!(r.message.unwrap().contains("not present"));
        run_pattern_list_add(&config, PatternListKind::Ignore, "git:force_push").unwrap();
        let r = run_pattern_list_add(&config, PatternListKind::Ignore, "git:force_push").unwrap();
        assert!(r.message.unwrap().contains("already present"));
    }

    #[test]
    fn builtin_protection_ids_get_a_clear_answer() {
        let temp_dir = tree_fs::TreeBuilder::default().create().unwrap();
        let config = initialize_config_folder(&temp_dir);
        run_pattern_list_add(
            &config,
            PatternListKind::Ignore,
            "shellfirm-self:agent_instructions_edit",
        )
        .unwrap();
        let s = load_settings(&config).unwrap();
        assert!(s
            .ignores_patterns_ids
            .contains(&"shellfirm-self:agent_instructions_edit".to_string()));
        assert!(
            sf_config::unknown_reference_warnings(&s, &[], &[]).is_empty(),
            "{:?}",
            sf_config::unknown_reference_warnings(&s, &[], &[])
        );
        for (kind, id) in [
            (
                PatternListKind::Ignore,
                "shellfirm-self:protected_file_write",
            ),
            (PatternListKind::Ignore, "shellfirm:input_too_large"),
            (
                PatternListKind::Deny,
                "shellfirm-self:agent_instructions_edit",
            ),
            (PatternListKind::Deny, "shellfirm-self:protected_file_write"),
        ] {
            let e = run_pattern_list_add(&config, kind, id)
                .unwrap_err()
                .to_string();
            assert!(e.contains("built-in agent protection"), "{e}");
            assert!(e.contains("agent.self_protection"), "{e}");
            assert!(!e.contains("unknown check id"), "{e}");
        }
    }

    #[test]
    fn lowering_escalation_below_the_default_warns() {
        let temp_dir = tree_fs::TreeBuilder::default().create().unwrap();
        let config = initialize_config_folder(&temp_dir);
        let r = run_context_escalation(&config, None, Some("Enter")).unwrap();
        let m = r.message.unwrap();
        assert!(
            m.contains("warning") && m.contains("lowers protection"),
            "{m}"
        );
        assert_eq!(r.code, exitcode::OK);
        let r = run_context_escalation(&config, None, Some("Yes")).unwrap();
        assert!(!r.message.unwrap().contains("warning"));
        let r = run_escalation_map_set(&config, EscalationMapKind::Group, "git", "Enter").unwrap();
        assert!(r.message.unwrap().contains("changes nothing"));
        let r = run_escalation_map_set(&config, EscalationMapKind::Group, "git", "Yes").unwrap();
        assert!(!r.message.unwrap().contains("warning"));
    }

    #[test]
    fn custom_groups_and_ids_are_manageable() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .add(
                "app/checks/team.yaml",
                "- id: team:deploy\n  from: team\n  test: deploy\n  description: d\n",
            )
            .create()
            .unwrap();
        let config = initialize_config_folder(&temp_dir);
        run_groups(&config, &[], &["team"]).unwrap();
        assert!(config
            .get_settings_from_file()
            .unwrap()
            .disabled_groups
            .contains(&"team".to_string()));
        run_pattern_list_add(&config, PatternListKind::Deny, "team:deploy").unwrap();
    }

    #[test]
    fn setters_write_sparse_files() {
        let temp_dir = tree_fs::TreeBuilder::default().create().unwrap();
        let config = initialize_config_folder(&temp_dir);
        write_settings(
            &config,
            "# my team baseline\nchallenge: Yes\nmy_unknown: 1\n",
        );
        run_severity(&config, "High").unwrap();
        let content = std::fs::read_to_string(&config.setting_file_path).unwrap();
        assert!(content.contains("min_severity"));
        assert!(content.contains("challenge"));
        assert!(content.contains("my_unknown"), "unknown keys preserved");
        assert!(!content.contains("enabled_groups"), "sparse: {content}");
    }

    #[test]
    fn setters_leave_no_empty_defaults_and_llm_is_sparse() {
        let temp_dir = tree_fs::TreeBuilder::default().create().unwrap();
        let config = initialize_config_folder(&temp_dir);
        write_settings(&config, "challenge: Yes\n");
        run_groups(&config, &[], &["heroku"]).unwrap();
        run_groups(&config, &["heroku"], &[]).unwrap();
        run_pattern_list_add(&config, PatternListKind::Ignore, "git:reset").unwrap();
        run_pattern_list_remove(&config, PatternListKind::Ignore, "git:reset").unwrap();
        run_severity(&config, "High").unwrap();
        run_severity(&config, "all").unwrap();
        let content = std::fs::read_to_string(&config.setting_file_path).unwrap();
        for leftover in ["disabled_groups", "ignores_patterns_ids", "min_severity"] {
            assert!(!content.contains(leftover), "{leftover}: {content}");
        }
        // `config llm --timeout` writes only what differs from the LLM
        // defaults (the default model is not pinned).
        run_llm(&config, Some("anthropic"), None, Some("7000"), None).unwrap();
        let content = std::fs::read_to_string(&config.setting_file_path).unwrap();
        assert!(content.contains("llm:"), "{content}");
        assert!(content.contains("timeout_ms: 7000"), "{content}");
        assert!(!content.contains("model"), "{content}");
        assert!(!content.contains("max_tokens"), "{content}");
        let llm = config.get_settings_from_file().unwrap().llm.unwrap();
        assert_eq!(llm.timeout_ms, 7000);
        assert_eq!(llm.provider, "anthropic");
    }

    #[test]
    fn reset_yes_backs_up_and_never_leaves_empty_file() {
        let temp_dir = tree_fs::TreeBuilder::default().create().unwrap();
        let config = initialize_config_folder(&temp_dir);
        write_settings(&config, "deny_patterns_ids: [git:force_push]\n");
        let r = run_reset_with(&config, true);
        assert_eq!(r.code, exitcode::OK);
        assert!(r.message.unwrap().contains("Previous settings saved to"));
        let backups: Vec<_> = std::fs::read_dir(&config.root_folder)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("settings.yaml.bak")
            })
            .collect();
        assert_eq!(backups.len(), 1);
        let backup = std::fs::read_to_string(backups[0].path()).unwrap();
        assert!(backup.contains("git:force_push"));
        let now = std::fs::read_to_string(&config.setting_file_path).unwrap();
        assert!(!now.is_empty());
        assert!(config
            .get_settings_from_file()
            .unwrap()
            .deny_patterns_ids
            .is_empty());
    }

    #[test]
    fn edit_validation_rejects_bad_content() {
        assert!(validate_settings_text("challenge: Bogus\n").is_err());
        assert!(validate_settings_text("::: [").is_err());
        assert!(validate_settings_text("disabled_groups: git\n").is_err());
        assert!(validate_settings_text("deny_pattern_ids: [x]\n").is_err());
        assert!(validate_settings_text("challenge: Yes\n").is_ok());
        assert!(validate_settings_text("# only a comment\n").is_ok());
        // Unknown ids and groups are rejected like the CLI setters do.
        let e = validate_settings_text("deny_patterns_ids: [git:forse_push]\n").unwrap_err();
        assert!(e.to_string().contains("git:force_push"), "{e}");
        assert!(validate_settings_text("enabled_groups: [gti]\n").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn edit_with_invalid_result_leaves_file_unchanged() {
        use std::os::unix::fs::PermissionsExt;
        let temp_dir = tree_fs::TreeBuilder::default().create().unwrap();
        let config = initialize_config_folder(&temp_dir);
        write_settings(&config, "challenge: Yes\n");
        let script = temp_dir.root.join("ed.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\nfor last; do :; done\nprintf 'challenge: Bogus\\n' > \"$last\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::env::set_var("VISUAL", format!("{} --wait", script.display()));
        let r = run_edit(&config).unwrap();
        std::env::remove_var("VISUAL");
        assert_eq!(r.code, exitcode::CONFIG);
        assert_eq!(
            std::fs::read_to_string(&config.setting_file_path).unwrap(),
            "challenge: Yes\n"
        );
    }
}
