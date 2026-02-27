use std::fs;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;

use clap::{Arg, ArgAction, ArgMatches, Command};
use console::style;
use shellfirm::checks::Severity;
use shellfirm::error::Result;
use shellfirm::{Challenge, Config};

const MARKER: &str = "# Added by shellfirm init";

// ---------------------------------------------------------------------------
// Shell enum — replaces ALL_SHELLS + SHELL_BINARIES + free dispatch functions
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
enum Shell {
    Bash,
    Zsh,
    Fish,
    Nushell,
    PowerShell,
    Elvish,
    Xonsh,
    Oils,
}

impl Shell {
    const ALL: [Self; 8] = [
        Self::Bash,
        Self::Zsh,
        Self::Fish,
        Self::Nushell,
        Self::PowerShell,
        Self::Elvish,
        Self::Xonsh,
        Self::Oils,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Zsh => "zsh",
            Self::Fish => "fish",
            Self::Nushell => "nushell",
            Self::PowerShell => "powershell",
            Self::Elvish => "elvish",
            Self::Xonsh => "xonsh",
            Self::Oils => "oils",
        }
    }

    /// Detect the user's current shell from the `$SHELL` environment variable.
    fn current() -> Option<Self> {
        let shell_path = std::env::var("SHELL").ok()?;
        let binary = std::path::Path::new(&shell_path).file_name()?.to_str()?;
        Self::ALL
            .iter()
            .copied()
            .find(|s| s.binaries().contains(&binary))
    }

    fn from_name(name: &str) -> Option<Self> {
        match name {
            "bash" => Some(Self::Bash),
            "zsh" => Some(Self::Zsh),
            "fish" => Some(Self::Fish),
            "nushell" => Some(Self::Nushell),
            "powershell" => Some(Self::PowerShell),
            "elvish" => Some(Self::Elvish),
            "xonsh" => Some(Self::Xonsh),
            "oils" => Some(Self::Oils),
            _ => None,
        }
    }

    const fn binaries(self) -> &'static [&'static str] {
        match self {
            Self::Bash => &["bash"],
            Self::Zsh => &["zsh"],
            Self::Fish => &["fish"],
            Self::Nushell => &["nu"],
            Self::PowerShell => &["pwsh", "powershell"],
            Self::Elvish => &["elvish"],
            Self::Xonsh => &["xonsh"],
            Self::Oils => &["osh", "ysh"],
        }
    }

    fn rc_file_path(self) -> Option<PathBuf> {
        let home = dirs::home_dir()?;
        match self {
            Self::Zsh => Some(home.join(".zshrc")),
            Self::Bash => Some(home.join(".bashrc")),
            Self::Fish => Some(home.join(".config/fish/config.fish")),
            Self::Nushell => Some(dirs::config_dir()?.join("nushell/config.nu")),
            Self::PowerShell => {
                let config = dirs::config_dir()?;
                Some(config.join("powershell/Microsoft.PowerShell_profile.ps1"))
            }
            Self::Elvish => Some(home.join(".config/elvish/rc.elv")),
            Self::Xonsh => Some(home.join(".xonshrc")),
            Self::Oils => Some(home.join(".config/oils/oshrc")),
        }
    }

    /// For shells that support eval we write a one-liner that calls `shellfirm init <shell>`
    /// at startup. Other shells get the full hook code embedded directly.
    fn rc_snippet(self) -> String {
        match self {
            Self::Zsh => r#"eval "$(shellfirm init zsh)""#.to_string(),
            Self::Bash => r#"eval "$(shellfirm init bash)""#.to_string(),
            Self::Fish => "shellfirm init fish | source".to_string(),
            Self::Oils => r#"eval "$(shellfirm init oils)""#.to_string(),
            Self::Nushell | Self::PowerShell | Self::Elvish | Self::Xonsh => {
                self.hook().to_string()
            }
        }
    }

    const fn hook(self) -> &'static str {
        match self {
            Self::Bash => bash_hook(),
            Self::Zsh => zsh_hook(),
            Self::Fish => fish_hook(),
            Self::Nushell => nushell_hook(),
            Self::PowerShell => powershell_hook(),
            Self::Elvish => elvish_hook(),
            Self::Xonsh => xonsh_hook(),
            Self::Oils => oils_hook(),
        }
    }

    const fn activate_hint(self) -> &'static str {
        match self {
            Self::Bash => "exec bash",
            Self::Zsh => "exec zsh",
            Self::Fish => "exec fish",
            Self::Oils => "exec osh",
            Self::Nushell | Self::PowerShell | Self::Elvish | Self::Xonsh => "Restart your shell",
        }
    }
}

impl std::fmt::Display for Shell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

pub fn command() -> Command {
    Command::new("init")
        .about("Set up shell integration")
        .long_about(
            "Install shellfirm hooks so every shell is protected.\n\n\
             Without arguments, detects all shells on the system and installs \
             hooks for each one. Specify a shell name to install for that shell only.\n\
             Use --dry-run to preview changes without writing anything.\n\n\
             When piped (e.g. eval \"$(shellfirm init zsh)\"), prints the hook \
             to stdout instead of installing.",
        )
        .arg(
            Arg::new("shell")
                .help(
                    "Install for a specific shell only: bash, zsh, fish, nushell, \
                     powershell, elvish, xonsh, oils. If omitted, installs for ALL \
                     detected shells.",
                )
                .required(false),
        )
        .arg(
            Arg::new("dry-run")
                .long("dry-run")
                .help("Show what would be done without making any changes")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("uninstall")
                .long("uninstall")
                .help("Remove shellfirm hooks from shell rc files")
                .action(ArgAction::SetTrue),
        )
}

pub fn run(matches: &ArgMatches) -> Result<shellfirm::CmdExit> {
    let dry_run = matches.get_flag("dry-run");
    let uninstall = matches.get_flag("uninstall");
    let explicit_shell = matches.get_one::<String>("shell").map(String::as_str);

    // --- Uninstall mode ---
    if uninstall {
        return match explicit_shell {
            Some(name) => {
                let shell = match validate_shell_arg(Some(name)) {
                    Ok(s) => s,
                    Err(exit) => return Ok(exit),
                };
                uninstall_hook(shell)
            }
            None => Ok(run_uninstall_all()),
        };
    }

    // --- Install mode ---
    match explicit_shell {
        // `shellfirm init <shell>` — install for that shell only
        Some(name) => {
            let shell = match validate_shell_arg(Some(name)) {
                Ok(s) => s,
                Err(exit) => return Ok(exit),
            };

            // When piped (e.g. eval "$(shellfirm init zsh)"), print hook to stdout
            if !std::io::stdout().is_terminal() {
                let hook = shell.hook();
                print!("{hook}");
                return Ok(shellfirm::CmdExit {
                    code: exitcode::OK,
                    message: None,
                });
            }

            if dry_run {
                preview_shell(shell);
                Ok(shellfirm::CmdExit {
                    code: exitcode::OK,
                    message: Some("\nNo changes made. Run without --dry-run to apply.".to_string()),
                })
            } else {
                install_hook(shell)
            }
        }
        // `shellfirm init` — install for ALL detected shells
        None => {
            if dry_run {
                Ok(run_dry_run_all())
            } else {
                Ok(run_install_all())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

fn validate_shell_arg(shell: Option<&str>) -> std::result::Result<Shell, shellfirm::CmdExit> {
    shell.map_or_else(
        || {
            Err(shellfirm::CmdExit {
                code: exitcode::USAGE,
                message: Some(
                    "Could not detect shell. Please specify: shellfirm init <shell>".to_string(),
                ),
            })
        },
        |name| {
            Shell::from_name(name).ok_or_else(|| shellfirm::CmdExit {
                code: exitcode::USAGE,
                message: Some(format!(
                    "Unsupported shell: {name}. Supported: bash, zsh, fish, nushell, powershell, elvish, xonsh, oils"
                )),
            })
        },
    )
}

// ---------------------------------------------------------------------------
// --all: install hooks for every detected shell
// ---------------------------------------------------------------------------

fn run_install_all() -> shellfirm::CmdExit {
    let detected = detect_installed_shells();
    if detected.is_empty() {
        return shellfirm::CmdExit {
            code: exitcode::OK,
            message: Some("No supported shells detected on this system.".to_string()),
        };
    }

    println!(
        "\n{}",
        style("shellfirm — installing hooks for all detected shells").bold()
    );
    println!();

    let mut installed = 0u32;
    let mut already = 0u32;
    let mut errors = 0u32;

    for shell in &detected {
        match install_hook_quiet(*shell) {
            InstallOutcome::Installed(path) => {
                println!(
                    "  {} {:<12} → {}",
                    style("✓").green().bold(),
                    shell,
                    style(&path).cyan()
                );
                installed += 1;
            }
            InstallOutcome::AlreadyInstalled(path) => {
                println!(
                    "  {} {:<12} → {} (already set up)",
                    style("✓").dim(),
                    shell,
                    style(&path).dim()
                );
                already += 1;
            }
            InstallOutcome::Failed(msg) => {
                println!(
                    "  {} {:<12} → {}",
                    style("✗").red().bold(),
                    shell,
                    style(&msg).red()
                );
                errors += 1;
            }
        }
    }

    for shell in Shell::ALL {
        if !detected.contains(&shell) {
            println!(
                "  {} {:<12}   {}",
                style("—").dim(),
                shell,
                style("(not installed on system)").dim()
            );
        }
    }

    println!();

    let total_protected = installed + already;
    let counts = if errors > 0 {
        format!("{total_protected} shell(s) protected ({installed} new, {already} already set up, {errors} error(s)).")
    } else {
        format!("{total_protected} shell(s) protected ({installed} new, {already} already set up).")
    };

    // Run interactive setup (challenge + protection level)
    if let Err(e) = run_interactive_setup() {
        eprintln!("  {}: {e}", style("warning").yellow());
    }

    let activate_section = format_activate_hints(detected);

    shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some(format!("{counts}{activate_section}")),
    }
}

/// Format the "restart your shell" hints, with the current shell first and highlighted.
fn format_activate_hints(mut shells: Vec<Shell>) -> String {
    let current = Shell::current();
    if let Some(cur) = current {
        if let Some(pos) = shells.iter().position(|s| *s == cur) {
            shells.remove(pos);
            shells.insert(0, cur);
        }
    }
    let hints: Vec<String> = shells
        .iter()
        .map(|shell| {
            if current == Some(*shell) {
                format!(
                    "  {} {} {}",
                    style("▸").magenta().bold(),
                    style(shell.activate_hint()).magenta().bold(),
                    style("(current shell)").magenta()
                )
            } else {
                format!(
                    "    {} {}",
                    style(shell.activate_hint()).cyan(),
                    style(format!("({shell})")).dim()
                )
            }
        })
        .collect();

    format!(
        "\n  Restart your shell to activate protection:\n\n{}\n",
        hints.join("\n")
    )
}

// ---------------------------------------------------------------------------
// --dry-run --all: preview all shells
// ---------------------------------------------------------------------------

fn run_dry_run_all() -> shellfirm::CmdExit {
    let detected = detect_installed_shells();

    println!(
        "\n{}",
        style("shellfirm — dry run (no changes will be made)").bold()
    );
    println!();

    for shell in Shell::ALL {
        if detected.contains(&shell) {
            preview_shell(shell);
        } else {
            println!(
                "  {} {:<12}   {}",
                style("—").dim(),
                shell,
                style("(not installed on system)").dim()
            );
        }
    }

    shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some("\nNo changes made. Run without --dry-run to apply.".to_string()),
    }
}

// ---------------------------------------------------------------------------
// Preview a single shell (for --dry-run)
// ---------------------------------------------------------------------------

fn preview_shell(shell: Shell) {
    let rc = shell.rc_file_path();
    let already = rc
        .as_ref()
        .is_some_and(|p| p.exists() && is_already_installed(p));

    if already {
        println!(
            "  {} {:<12} → {} {}",
            style("✓").dim(),
            shell,
            rc.as_ref()
                .map(|p| style(p.display().to_string()).dim().to_string())
                .unwrap_or_default(),
            style("(already installed)").yellow()
        );
    } else if let Some(ref path) = rc {
        println!(
            "  {} {:<12} → {}",
            style("→").green().bold(),
            shell,
            style(format!("will add hook to {}", path.display())).green()
        );
    } else {
        println!(
            "  {} {:<12}   {}",
            style("?").red(),
            shell,
            style("could not determine rc file").red()
        );
    }
}

// ---------------------------------------------------------------------------
// Install hook into a single shell's rc file
// ---------------------------------------------------------------------------

enum InstallOutcome {
    Installed(String),
    AlreadyInstalled(String),
    Failed(String),
}

fn install_hook_quiet(shell: Shell) -> InstallOutcome {
    let Some(rc_path) = shell.rc_file_path() else {
        return InstallOutcome::Failed(format!("could not determine rc file for {shell}"));
    };

    let display = rc_path.display().to_string();

    if rc_path.exists() && is_already_installed(&rc_path) {
        return InstallOutcome::AlreadyInstalled(display);
    }

    if let Some(parent) = rc_path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            return InstallOutcome::Failed(format!("could not create directory: {e}"));
        }
    }

    let snippet = shell.rc_snippet();
    let block = format!("\n{MARKER}\n{snippet}\n");

    match fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&rc_path)
    {
        Ok(mut file) => match file.write_all(block.as_bytes()) {
            Ok(()) => InstallOutcome::Installed(display),
            Err(e) => InstallOutcome::Failed(format!("write error: {e}")),
        },
        Err(e) => InstallOutcome::Failed(format!("could not open {display}: {e}")),
    }
}

fn install_hook(shell: Shell) -> Result<shellfirm::CmdExit> {
    let hook = shell.hook();
    let Some(rc_path) = shell.rc_file_path() else {
        return Ok(shellfirm::CmdExit {
            code: exitcode::USAGE,
            message: Some(format!(
                "Could not determine rc file for {shell}. Add the following to your shell config manually:\n\n{hook}"
            )),
        });
    };

    if rc_path.exists() && is_already_installed(&rc_path) {
        return Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: Some(format!(
                "shellfirm is already set up in {}",
                rc_path.display()
            )),
        });
    }

    if let Some(parent) = rc_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let snippet = shell.rc_snippet();
    let block = format!("\n{MARKER}\n{snippet}\n");

    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&rc_path)?;
    file.write_all(block.as_bytes())?;

    // Run interactive setup (challenge + protection level)
    if let Err(e) = run_interactive_setup() {
        eprintln!("  {}: {e}", style("warning").yellow());
    }

    let is_current = Shell::current() == Some(shell);
    let hint = if is_current {
        format!(
            "  {} {} {}",
            style("▸").magenta().bold(),
            style(shell.activate_hint()).magenta().bold(),
            style("(current shell)").magenta()
        )
    } else {
        format!("    {}", style(shell.activate_hint()).cyan())
    };

    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some(format!(
            "\n  {} hook added to {}\n\n  Restart your shell to activate protection:\n\n{hint}\n",
            style("shellfirm").green().bold(),
            style(rc_path.display().to_string()).cyan(),
        )),
    })
}

// ---------------------------------------------------------------------------
// Interactive first-run setup
// ---------------------------------------------------------------------------

/// Prompt the user to choose a challenge type and protection level.
///
/// Skipped when:
/// - stderr is not a terminal (piped / non-interactive)
/// - both `challenge` and `min_severity` are already set in settings
fn run_interactive_setup() -> Result<()> {
    if !std::io::stderr().is_terminal() {
        return Ok(());
    }

    let config = Config::new(None)?;

    // Load the raw YAML tree so we only write the keys the user picks,
    // keeping the settings file sparse (no bloat from defaults).
    let mut root = config
        .read_config_as_value()
        .unwrap_or_else(|_| serde_yaml::Value::Mapping(serde_yaml::Mapping::default()));
    let has_challenge = root.get("challenge").is_some();
    let has_severity = root.get("min_severity").is_some();

    if has_challenge && has_severity {
        return Ok(());
    }

    let mut changed = false;

    if !has_challenge {
        if let Ok(idx) = shellfirm::prompt::select_with_default(
            "Choose your challenge type:",
            &[
                "Math  — solve a quick math problem (e.g. 3 + 7 = ?)",
                "Enter — just press Enter to confirm",
                "Yes   — type \"yes\" to confirm",
            ],
            0,
        ) {
            let challenge = match idx {
                1 => Challenge::Enter,
                2 => Challenge::Yes,
                _ => Challenge::Math,
            };
            shellfirm::value_set(&mut root, "challenge", serde_yaml::to_value(challenge)?)?;
            changed = true;
        }
    }

    if !has_severity {
        if let Ok(idx) = shellfirm::prompt::select_with_default(
            "Choose your protection level:",
            &[
                "Paranoid — catches everything, even low-risk commands",
                "Balanced — catches medium-risk and above (Recommended)",
                "Chill    — only high-risk and critical commands",
                "YOLO     — only critical, truly destructive commands",
            ],
            1,
        ) {
            let severity: Option<Severity> = match idx {
                0 => None,
                2 => Some(Severity::High),
                3 => Some(Severity::Critical),
                _ => Some(Severity::Medium),
            };
            shellfirm::value_set(&mut root, "min_severity", serde_yaml::to_value(severity)?)?;
            changed = true;
        }
    }

    if changed {
        config.save_config_from_value(&root)?;
        println!(
            "\n  {} saved to {}\n",
            style("Settings").green().bold(),
            style(config.setting_file_path.display().to_string()).cyan(),
        );
    }

    Ok(())
}

fn is_already_installed(rc_path: &std::path::Path) -> bool {
    let content = fs::read_to_string(rc_path).unwrap_or_default();
    content.contains("shellfirm init") || content.contains(MARKER)
}

// ---------------------------------------------------------------------------
// Uninstall: remove shellfirm hooks from rc files
// ---------------------------------------------------------------------------

fn run_uninstall_all() -> shellfirm::CmdExit {
    println!(
        "\n{}",
        style("shellfirm — removing hooks from all shells").bold()
    );
    println!();

    let mut removed = 0u32;
    let mut not_installed = 0u32;
    let mut errors = 0u32;

    for shell in Shell::ALL {
        match uninstall_hook_quiet(shell) {
            UninstallOutcome::Removed(path) => {
                println!(
                    "  {} {:<12} → {} (hook removed)",
                    style("✓").green().bold(),
                    shell,
                    style(&path).cyan()
                );
                removed += 1;
            }
            UninstallOutcome::NotInstalled => {
                not_installed += 1;
            }
            UninstallOutcome::Failed(msg) => {
                println!(
                    "  {} {:<12} → {}",
                    style("✗").red().bold(),
                    shell,
                    style(&msg).red()
                );
                errors += 1;
            }
        }
    }

    println!();

    if removed == 0 && errors == 0 {
        return shellfirm::CmdExit {
            code: exitcode::OK,
            message: Some("No shellfirm hooks found in any shell.".to_string()),
        };
    }

    let summary = if errors > 0 {
        format!("Removed hooks from {removed} shell(s) ({not_installed} had no hook, {errors} error(s)).\nRestart your shells to deactivate.")
    } else {
        format!("Removed hooks from {removed} shell(s).\nRestart your shells to deactivate.")
    };

    shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some(summary),
    }
}

enum UninstallOutcome {
    Removed(String),
    NotInstalled,
    Failed(String),
}

fn uninstall_hook_quiet(shell: Shell) -> UninstallOutcome {
    let Some(rc_path) = shell.rc_file_path() else {
        return UninstallOutcome::NotInstalled;
    };
    if !rc_path.exists() {
        return UninstallOutcome::NotInstalled;
    }

    let display = rc_path.display().to_string();
    let content = match fs::read_to_string(&rc_path) {
        Ok(c) => c,
        Err(e) => return UninstallOutcome::Failed(format!("could not read {display}: {e}")),
    };

    let (new_content, changed) = remove_shellfirm_block(&content, shell);
    if !changed {
        return UninstallOutcome::NotInstalled;
    }

    match fs::write(&rc_path, new_content) {
        Ok(()) => UninstallOutcome::Removed(display),
        Err(e) => UninstallOutcome::Failed(format!("could not write {display}: {e}")),
    }
}

fn uninstall_hook(shell: Shell) -> Result<shellfirm::CmdExit> {
    let Some(rc_path) = shell.rc_file_path() else {
        return Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: Some(format!("No rc file found for {shell} — nothing to remove.")),
        });
    };

    if !rc_path.exists() {
        return Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: Some(format!(
                "{} does not exist — nothing to remove.",
                rc_path.display()
            )),
        });
    }

    let content = fs::read_to_string(&rc_path)?;
    let (new_content, changed) = remove_shellfirm_block(&content, shell);

    if !changed {
        return Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: Some(format!("No shellfirm hook found in {}", rc_path.display())),
        });
    }

    fs::write(&rc_path, new_content)?;

    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some(format!(
            "{} hook removed from {}\nRestart your shell to deactivate.",
            style("shellfirm").green().bold(),
            style(rc_path.display().to_string()).cyan(),
        )),
    })
}

/// Remove the shellfirm block from rc file content.
fn remove_shellfirm_block(content: &str, shell: Shell) -> (String, bool) {
    let snippet = shell.rc_snippet();

    let blocks = [
        format!("\n{MARKER}\n{snippet}\n"),
        // Block at the very start of file (no leading newline)
        format!("{MARKER}\n{snippet}\n"),
    ];

    let mut result = content.to_string();
    let mut changed = false;

    for block in &blocks {
        if result.contains(block.as_str()) {
            result = result.replace(block.as_str(), "");
            changed = true;
        }
    }

    (result, changed)
}

// ---------------------------------------------------------------------------
// Shell detection
// ---------------------------------------------------------------------------

fn detect_installed_shells() -> Vec<Shell> {
    Shell::ALL
        .iter()
        .copied()
        .filter(|shell| {
            shell.binaries().iter().any(|bin| {
                std::process::Command::new("which")
                    .arg(bin)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false)
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Hook implementations
// ---------------------------------------------------------------------------

const fn zsh_hook() -> &'static str {
    r#"# shellfirm hook for zsh — intercepts Enter via the accept-line widget
shellfirm-pre-command() {
    if [[ -z "${BUFFER}" || "${BUFFER}" == *"shellfirm"* ]]; then
        zle .accept-line
        return
    fi
    shellfirm pre-command -c "${BUFFER}"
    if [[ $? -eq 0 ]]; then
        zle .accept-line
    else
        zle reset-prompt
    fi
}
zle -N accept-line shellfirm-pre-command"#
}

#[allow(clippy::literal_string_with_formatting_args)]
const fn bash_hook() -> &'static str {
    r#"# shellfirm hook for bash — intercepts risky commands via DEBUG trap.
# Fires once per command line using PROMPT_COMMAND flag + history number.
# Without functrace, the DEBUG trap only fires for function CALLS (not
# internal commands), so fzf/keybinding internals are never affected.
__shellfirm_ready=""
__shellfirm_histnum="__sf_none__"
__shellfirm_blocked=""

_shellfirm_prompt() {
    __shellfirm_ready="1"
    __shellfirm_blocked=""
}

_shellfirm_hook() {
    # Fast exit for sub-commands after the first check (no subshells)
    if [[ -z "$__shellfirm_ready" ]]; then
        [[ -n "$__shellfirm_blocked" ]] && return 1
        return 0
    fi
    [[ -n "${COMP_LINE:-}" ]] && return 0
    [[ "$BASH_COMMAND" == *"shellfirm"* ]] && return 0
    [[ "$BASH_COMMAND" == "_shellfirm_"* ]] && return 0
    command -v shellfirm &>/dev/null || return 0

    # Check history number to distinguish real commands from keybinding
    # functions (fzf, etc.). Keybinding functions don't create new history
    # entries, so the number stays the same — we skip without consuming
    # the ready flag, so the actual command will be checked later.
    local histnum
    histnum=$(HISTTIMEFORMAT='' builtin history 1 | awk '{print $1}')
    [[ "$histnum" == "$__shellfirm_histnum" ]] && return 0

    # New command line — consume the flag and check
    __shellfirm_ready=""
    __shellfirm_histnum="$histnum"

    local full_cmd
    full_cmd=$(HISTTIMEFORMAT='' builtin history 1 | sed 's/^[ ]*[0-9]*[ ]*//')
    [[ -z "$full_cmd" ]] && return 0

    local __sf_prev_int
    __sf_prev_int=$(trap -p INT)
    trap ':' INT
    shellfirm pre-command -c "$full_cmd"
    local __sf_rc=$?
    if [[ -n "$__sf_prev_int" ]]; then
        eval "$__sf_prev_int"
    else
        trap - INT
    fi
    if [[ $__sf_rc -ne 0 ]]; then
        __shellfirm_blocked="1"
        return 1
    fi
    return 0
}

PROMPT_COMMAND="_shellfirm_prompt${PROMPT_COMMAND:+;$PROMPT_COMMAND}"
shopt -s extdebug
trap '_shellfirm_hook' DEBUG"#
}

const fn fish_hook() -> &'static str {
    r#"# shellfirm hook for fish — intercepts Enter via key binding
function _shellfirm_check
    set -l cmd (commandline)
    if test -z "$cmd"; or string match -q '*shellfirm*' -- $cmd
        commandline -f execute
        return
    end
    stty sane
    shellfirm pre-command -c "$cmd"
    if test $status -eq 0
        commandline -f execute
    else
        commandline -f repaint
    end
end
bind \r _shellfirm_check
# Also bind in vi insert mode if active
bind -M insert \r _shellfirm_check 2>/dev/null"#
}

const fn nushell_hook() -> &'static str {
    r#"# shellfirm hook for nushell
$env.config.hooks.pre_execution = (
    $env.config.hooks.pre_execution | append {||
        let cmd = (commandline)
        if ($cmd | str trim | is-empty) {
            return
        }
        if ($cmd | str contains "shellfirm") {
            return
        }
        let result = (do { shellfirm pre-command -c $cmd } | complete)
        if $result.exit_code != 0 {
            commandline edit ""
        }
    }
)"#
}

const fn powershell_hook() -> &'static str {
    r#"# shellfirm hook for PowerShell
if (Get-Command shellfirm -ErrorAction SilentlyContinue) {
    Set-PSReadLineKeyHandler -Key Enter -ScriptBlock {
        $line = $null
        $cursor = $null
        [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]$line, [ref]$cursor)

        if ([string]::IsNullOrWhiteSpace($line)) {
            [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
            return
        }

        if ($line -match 'shellfirm') {
            [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
            return
        }

        Write-Host ""
        shellfirm pre-command -c $line 2>$null
        if ($LASTEXITCODE -eq 0) {
            [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
        } else {
            [Microsoft.PowerShell.PSConsoleReadLine]::InvokePrompt()
        }
    }
} else {
    Write-Warning "shellfirm binary not found. Install: https://github.com/kaplanelad/shellfirm#installation"
}"#
}

const fn elvish_hook() -> &'static str {
    r#"# shellfirm hook for elvish
if (not ?(which shellfirm &>/dev/null)) {
    echo "shellfirm binary not found. Install: https://github.com/kaplanelad/shellfirm#installation"
} else {
    set edit:insert:binding[Enter] = {
        var cmd = (edit:current-command)
        if (eq $cmd "") {
            edit:smart-enter
            return
        }
        if (str:contains $cmd "shellfirm") {
            edit:smart-enter
            return
        }
        try {
            echo ""
            shellfirm pre-command -c $cmd 2>/dev/null
            edit:smart-enter
        } catch {
            edit:redraw &full=$true
        }
    }
}"#
}

const fn xonsh_hook() -> &'static str {
    r#"# shellfirm hook for xonsh
import subprocess
import shutil

if shutil.which("shellfirm") is None:
    print("shellfirm binary not found. Install: https://github.com/kaplanelad/shellfirm#installation")
else:
    @events.on_precommand
    def _shellfirm_precommand(cmd, **kwargs):
        if not cmd or not cmd.strip():
            return
        if "shellfirm" in cmd:
            return
        result = subprocess.run(
            ["shellfirm", "pre-command", "-c", cmd],
            capture_output=True,
        )
        if result.returncode != 0:
            raise PermissionError("Command blocked by shellfirm")"#
}

#[allow(clippy::literal_string_with_formatting_args)]
const fn oils_hook() -> &'static str {
    r#"# shellfirm hook for Oils (OSH/YSH) — same approach as the bash hook.
__shellfirm_ready=""
__shellfirm_histnum="__sf_none__"
__shellfirm_blocked=""

_shellfirm_prompt() {
    __shellfirm_ready="1"
    __shellfirm_blocked=""
}

_shellfirm_hook() {
    if [[ -z "$__shellfirm_ready" ]]; then
        [[ -n "$__shellfirm_blocked" ]] && return 1
        return 0
    fi
    [[ -n "${COMP_LINE:-}" ]] && return 0
    [[ "$BASH_COMMAND" == *"shellfirm"* ]] && return 0
    [[ "$BASH_COMMAND" == "_shellfirm_"* ]] && return 0
    command -v shellfirm &>/dev/null || return 0

    local histnum
    histnum=$(HISTTIMEFORMAT='' builtin history 1 | awk '{print $1}')
    [[ "$histnum" == "$__shellfirm_histnum" ]] && return 0

    __shellfirm_ready=""
    __shellfirm_histnum="$histnum"

    local full_cmd
    full_cmd=$(HISTTIMEFORMAT='' builtin history 1 | sed 's/^[ ]*[0-9]*[ ]*//')
    [[ -z "$full_cmd" ]] && return 0

    shellfirm pre-command -c "$full_cmd"
    if [[ $? -ne 0 ]]; then
        __shellfirm_blocked="1"
        return 1
    fi
    return 0
}

PROMPT_COMMAND="_shellfirm_prompt${PROMPT_COMMAND:+;$PROMPT_COMMAND}"
shopt -s extdebug
trap '_shellfirm_hook' DEBUG"#
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_hooks_are_non_empty() {
        for shell in Shell::ALL {
            assert!(
                !shell.hook().is_empty(),
                "hook for {shell} should not be empty"
            );
        }
    }

    #[test]
    fn rc_paths_resolve_for_known_shells() {
        for shell in Shell::ALL {
            let _ = shell.rc_file_path();
        }
    }

    #[test]
    fn rc_snippet_returns_eval_for_eval_shells() {
        for shell in [Shell::Zsh, Shell::Bash, Shell::Fish, Shell::Oils] {
            let snippet = shell.rc_snippet();
            assert!(
                snippet.contains("shellfirm init"),
                "{shell} snippet should contain eval one-liner"
            );
        }
    }

    #[test]
    fn rc_snippet_returns_full_hook_for_other_shells() {
        for shell in [
            Shell::Nushell,
            Shell::PowerShell,
            Shell::Elvish,
            Shell::Xonsh,
        ] {
            let snippet = shell.rc_snippet();
            assert!(
                snippet.contains("shellfirm") && snippet.len() > 50,
                "{shell} snippet should contain full hook code"
            );
        }
    }

    #[test]
    fn install_to_temp_file() {
        let dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let rc = dir.root.join(".zshrc");

        let snippet = Shell::Zsh.rc_snippet();
        let block = format!("\n{MARKER}\n{snippet}\n");
        fs::write(&rc, block).unwrap();

        let content = fs::read_to_string(&rc).unwrap();
        assert!(content.contains(MARKER));
        assert!(content.contains("shellfirm init zsh"));
    }

    #[test]
    fn idempotent_install_detection() {
        let dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let rc = dir.root.join(".zshrc");

        let content = format!("# existing config\n{MARKER}\neval \"$(shellfirm init zsh)\"\n");
        fs::write(&rc, &content).unwrap();

        assert!(
            is_already_installed(&rc),
            "should detect existing installation"
        );
    }

    #[test]
    fn validate_shell_arg_accepts_known() {
        for shell in Shell::ALL {
            assert!(validate_shell_arg(Some(shell.name())).is_ok());
        }
    }

    #[test]
    fn validate_shell_arg_rejects_unknown() {
        assert!(validate_shell_arg(Some("csh")).is_err());
        assert!(validate_shell_arg(None).is_err());
    }

    #[test]
    fn detect_installed_shells_does_not_panic() {
        let _ = detect_installed_shells();
    }

    #[test]
    fn eval_shells_hook_contains_shellfirm_pre_command() {
        // These shells use `eval "$(shellfirm init <shell>)"` — the hook
        // printed to stdout must contain `shellfirm pre-command` to intercept commands.
        for shell in [Shell::Zsh, Shell::Bash, Shell::Fish, Shell::Oils] {
            let hook = shell.hook();
            assert!(
                hook.contains("shellfirm pre-command"),
                "{shell} hook must contain 'shellfirm pre-command' for interception"
            );
        }
    }

    #[test]
    fn uninstall_removes_block_with_current_marker() {
        let snippet = Shell::Zsh.rc_snippet();
        let content = format!("# my config\nPATH=/usr/bin\n\n{MARKER}\n{snippet}\n");

        let (result, changed) = remove_shellfirm_block(&content, Shell::Zsh);
        assert!(changed);
        assert!(!result.contains(MARKER));
        assert!(!result.contains("shellfirm init zsh"));
        assert!(result.contains("# my config"));
        assert!(result.contains("PATH=/usr/bin"));
    }

    #[test]
    fn uninstall_removes_embedded_hook() {
        let snippet = Shell::PowerShell.rc_snippet();
        let content = format!("# existing stuff\n\n{MARKER}\n{snippet}\n");

        let (result, changed) = remove_shellfirm_block(&content, Shell::PowerShell);
        assert!(changed);
        assert!(!result.contains("shellfirm"));
        assert!(result.contains("# existing stuff"));
    }

    #[test]
    fn uninstall_noop_when_not_installed() {
        let content = "# my config\nPATH=/usr/bin\n";

        let (result, changed) = remove_shellfirm_block(content, Shell::Zsh);
        assert!(!changed);
        assert_eq!(result, content);
    }

    #[test]
    fn activate_hint_returns_non_empty_for_all_shells() {
        for shell in Shell::ALL {
            let hint = shell.activate_hint();
            assert!(
                !hint.is_empty(),
                "activate_hint for {shell} should not be empty"
            );
        }
    }

    #[test]
    fn activate_hint_exec_for_posix_shells() {
        assert_eq!(Shell::Bash.activate_hint(), "exec bash");
        assert_eq!(Shell::Zsh.activate_hint(), "exec zsh");
        assert_eq!(Shell::Fish.activate_hint(), "exec fish");
        assert_eq!(Shell::Oils.activate_hint(), "exec osh");
    }

    #[test]
    fn activate_hint_restart_for_non_posix_shells() {
        for shell in [
            Shell::Nushell,
            Shell::PowerShell,
            Shell::Elvish,
            Shell::Xonsh,
        ] {
            assert_eq!(
                shell.activate_hint(),
                "Restart your shell",
                "{shell} should get restart hint"
            );
        }
    }

    #[test]
    fn uninstall_preserves_rest_of_file() {
        let snippet = Shell::Fish.rc_snippet();
        let content =
            format!("# before\nexport FOO=bar\n\n{MARKER}\n{snippet}\n\n# after\nexport BAZ=qux\n");

        let (result, changed) = remove_shellfirm_block(&content, Shell::Fish);
        assert!(changed);
        assert!(result.contains("# before"));
        assert!(result.contains("export FOO=bar"));
        assert!(result.contains("# after"));
        assert!(result.contains("export BAZ=qux"));
        assert!(!result.contains("shellfirm"));
    }

    #[test]
    fn from_name_round_trip() {
        for shell in Shell::ALL {
            let parsed = Shell::from_name(shell.name())
                .unwrap_or_else(|| panic!("from_name failed for {}", shell.name()));
            assert_eq!(parsed, shell);
        }
    }

    #[test]
    fn display_matches_name() {
        for shell in Shell::ALL {
            assert_eq!(shell.to_string(), shell.name());
        }
    }
}
