use std::fs;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;

use anyhow::Result;
use clap::{Arg, ArgAction, ArgMatches, Command};
use console::style;

const MARKER: &str = "# Added by shellfirm init";
const LEGACY_MARKER: &str = "# Added by shellfirm init --install";

const ALL_SHELLS: &[&str] = &[
    "bash",
    "zsh",
    "fish",
    "nushell",
    "powershell",
    "elvish",
    "xonsh",
    "oils",
];

const SHELL_BINARIES: &[(&str, &[&str])] = &[
    ("bash", &["bash"]),
    ("zsh", &["zsh"]),
    ("fish", &["fish"]),
    ("nushell", &["nu"]),
    ("powershell", &["pwsh", "powershell"]),
    ("elvish", &["elvish"]),
    ("xonsh", &["xonsh"]),
    ("oils", &["osh", "ysh"]),
];

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
    let explicit_shell = matches.get_one::<String>("shell").cloned();

    // When stdout is piped (e.g. eval "$(shellfirm init zsh)"), print the hook
    // to stdout for backward compatibility with existing rc files.
    if !dry_run && !uninstall && explicit_shell.is_some() && !std::io::stdout().is_terminal() {
        let shell = explicit_shell.clone().or_else(detect_shell);
        return match validate_shell_name(shell.as_deref()) {
            Ok(name) => {
                println!("{}", get_hook(name));
                Ok(shellfirm::CmdExit {
                    code: exitcode::OK,
                    message: None,
                })
            }
            Err(exit) => Ok(exit),
        };
    }

    // --- Uninstall mode ---
    if uninstall {
        return match explicit_shell {
            Some(ref shell) => {
                let shell_name = match validate_shell_name(Some(shell.as_str())) {
                    Ok(name) => name,
                    Err(exit) => return Ok(exit),
                };
                uninstall_hook(shell_name)
            }
            None => run_uninstall_all(),
        };
    }

    // --- Install mode ---
    match explicit_shell {
        // `shellfirm init <shell>` — install for that shell only
        Some(ref shell) => {
            let shell_name = match validate_shell_name(Some(shell.as_str())) {
                Ok(name) => name,
                Err(exit) => return Ok(exit),
            };

            if dry_run {
                preview_shell(shell_name);
                Ok(shellfirm::CmdExit {
                    code: exitcode::OK,
                    message: Some("\nNo changes made. Run without --dry-run to apply.".to_string()),
                })
            } else {
                install_hook(shell_name)
            }
        }
        // `shellfirm init` — install for ALL detected shells
        None => {
            if dry_run {
                run_dry_run_all()
            } else {
                run_install_all()
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

fn validate_shell_name(shell: Option<&str>) -> std::result::Result<&str, shellfirm::CmdExit> {
    match shell {
        Some(
            s @ ("bash" | "zsh" | "fish" | "nushell" | "powershell" | "elvish" | "xonsh" | "oils"),
        ) => Ok(s),
        Some(other) => Err(shellfirm::CmdExit {
            code: exitcode::USAGE,
            message: Some(format!(
                "Unsupported shell: {other}. Supported: bash, zsh, fish, nushell, powershell, elvish, xonsh, oils"
            )),
        }),
        None => Err(shellfirm::CmdExit {
            code: exitcode::USAGE,
            message: Some(
                "Could not detect shell. Please specify: shellfirm init <shell>".to_string(),
            ),
        }),
    }
}

// ---------------------------------------------------------------------------
// --all: install hooks for every detected shell
// ---------------------------------------------------------------------------

fn run_install_all() -> Result<shellfirm::CmdExit> {
    let detected = detect_installed_shells();
    if detected.is_empty() {
        return Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: Some("No supported shells detected on this system.".to_string()),
        });
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
        match install_hook_quiet(shell) {
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

    for shell in ALL_SHELLS {
        if !detected.contains(shell) {
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
    let summary = if errors > 0 {
        format!(
            "{total_protected} shell(s) protected ({installed} new, {already} already set up, {errors} error(s)).\nRestart your shells to activate."
        )
    } else {
        format!(
            "{total_protected} shell(s) protected ({installed} new, {already} already set up).\nRestart your shells to activate."
        )
    };

    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some(summary),
    })
}

// ---------------------------------------------------------------------------
// --dry-run --all: preview all shells
// ---------------------------------------------------------------------------

fn run_dry_run_all() -> Result<shellfirm::CmdExit> {
    let detected = detect_installed_shells();

    println!(
        "\n{}",
        style("shellfirm — dry run (no changes will be made)").bold()
    );
    println!();

    for shell in ALL_SHELLS {
        if detected.contains(shell) {
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

    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some("\nNo changes made. Run without --dry-run to apply.".to_string()),
    })
}

// ---------------------------------------------------------------------------
// Preview a single shell (for --dry-run)
// ---------------------------------------------------------------------------

fn preview_shell(shell: &str) {
    let rc = rc_file_path(shell);
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

fn install_hook_quiet(shell: &str) -> InstallOutcome {
    let Some(rc_path) = rc_file_path(shell) else {
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

    let snippet = rc_snippet(shell);
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

fn install_hook(shell: &str) -> Result<shellfirm::CmdExit> {
    let hook = get_hook(shell);
    let Some(rc_path) = rc_file_path(shell) else {
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

    let snippet = rc_snippet(shell);
    let block = format!("\n{MARKER}\n{snippet}\n");

    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&rc_path)?;
    file.write_all(block.as_bytes())?;

    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some(format!(
            "{} hook added to {}\nRestart your shell to activate, or run:  {}",
            style("shellfirm").green().bold(),
            style(rc_path.display().to_string()).cyan(),
            style(format!("source {}", rc_path.display())).bold(),
        )),
    })
}

fn is_already_installed(rc_path: &std::path::Path) -> bool {
    let content = fs::read_to_string(rc_path).unwrap_or_default();
    content.contains("shellfirm init")
        || content.contains(MARKER)
        || content.contains(LEGACY_MARKER)
}

// ---------------------------------------------------------------------------
// Uninstall: remove shellfirm hooks from rc files
// ---------------------------------------------------------------------------

fn run_uninstall_all() -> Result<shellfirm::CmdExit> {
    println!(
        "\n{}",
        style("shellfirm — removing hooks from all shells").bold()
    );
    println!();

    let mut removed = 0u32;
    let mut not_installed = 0u32;
    let mut errors = 0u32;

    for shell in ALL_SHELLS {
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
        return Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: Some("No shellfirm hooks found in any shell.".to_string()),
        });
    }

    let summary = if errors > 0 {
        format!("Removed hooks from {removed} shell(s) ({not_installed} had no hook, {errors} error(s)).\nRestart your shells to deactivate.")
    } else {
        format!("Removed hooks from {removed} shell(s).\nRestart your shells to deactivate.")
    };

    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some(summary),
    })
}

enum UninstallOutcome {
    Removed(String),
    NotInstalled,
    Failed(String),
}

fn uninstall_hook_quiet(shell: &str) -> UninstallOutcome {
    let Some(rc_path) = rc_file_path(shell) else {
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

fn uninstall_hook(shell: &str) -> Result<shellfirm::CmdExit> {
    let Some(rc_path) = rc_file_path(shell) else {
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

/// Remove the shellfirm block from rc file content. Handles both the current
/// and legacy marker formats.
fn remove_shellfirm_block(content: &str, shell: &str) -> (String, bool) {
    let snippet = rc_snippet(shell);

    let blocks = [
        format!("\n{MARKER}\n{snippet}\n"),
        format!("\n{LEGACY_MARKER}\n{snippet}\n"),
        // Block at the very start of file (no leading newline)
        format!("{MARKER}\n{snippet}\n"),
        format!("{LEGACY_MARKER}\n{snippet}\n"),
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

/// For shells that support eval we write a one-liner that calls `shellfirm init <shell>`
/// at startup. Other shells get the full hook code embedded directly.
fn rc_snippet(shell: &str) -> String {
    match shell {
        "zsh" => r#"eval "$(shellfirm init zsh)""#.to_string(),
        "bash" => r#"eval "$(shellfirm init bash)""#.to_string(),
        "fish" => "shellfirm init fish | source".to_string(),
        "oils" => r#"eval "$(shellfirm init oils)""#.to_string(),
        _ => get_hook(shell).to_string(),
    }
}

fn rc_file_path(shell: &str) -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    match shell {
        "zsh" => Some(home.join(".zshrc")),
        "bash" => Some(home.join(".bashrc")),
        "fish" => Some(home.join(".config/fish/config.fish")),
        "nushell" => Some(dirs::config_dir()?.join("nushell/config.nu")),
        "powershell" => {
            let config = dirs::config_dir()?;
            Some(config.join("powershell/Microsoft.PowerShell_profile.ps1"))
        }
        "elvish" => Some(home.join(".config/elvish/rc.elv")),
        "xonsh" => Some(home.join(".xonshrc")),
        "oils" => Some(home.join(".config/oils/oshrc")),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Shell detection
// ---------------------------------------------------------------------------

/// Detect the shell that is *currently running* (not just the login shell).
///
/// Strategy:
///   1. Check shell-specific env vars exported to child processes (e.g.
///      `FISH_VERSION` for fish, `XONSH_VERSION` for xonsh).
///   2. Inspect the parent process name via `ps` — this is the most reliable
///      way to identify the running shell on Unix.
///   3. Fall back to `$SHELL` (the login shell).
fn detect_shell() -> Option<String> {
    if let Some(s) = detect_from_env_vars() {
        return Some(s);
    }

    #[cfg(unix)]
    if let Some(s) = detect_from_parent_process() {
        return Some(s);
    }

    std::env::var("SHELL")
        .ok()
        .and_then(|s| shell_name_from_str(&s))
}

/// Some shells export a version variable that child processes can read.
fn detect_from_env_vars() -> Option<String> {
    if std::env::var("FISH_VERSION").is_ok() {
        return Some("fish".into());
    }
    if std::env::var("XONSH_VERSION").is_ok() {
        return Some("xonsh".into());
    }
    None
}

/// Ask the OS for the parent process name (the shell that launched us).
#[cfg(unix)]
fn detect_from_parent_process() -> Option<String> {
    let ppid = std::os::unix::process::parent_id();
    let output = std::process::Command::new("ps")
        .args(["-p", &ppid.to_string(), "-o", "comm="])
        .output()
        .ok()?;
    let comm = String::from_utf8_lossy(&output.stdout);
    let name = comm.trim().trim_start_matches('-');
    shell_name_from_str(name)
}

fn shell_name_from_str(s: &str) -> Option<String> {
    if s.contains("fish") {
        Some("fish".into())
    } else if s.contains("zsh") {
        Some("zsh".into())
    } else if s.contains("bash") {
        Some("bash".into())
    } else if s.contains("nu") {
        Some("nushell".into())
    } else if s.contains("pwsh") || s.contains("powershell") {
        Some("powershell".into())
    } else if s.contains("elvish") {
        Some("elvish".into())
    } else if s.contains("xonsh") {
        Some("xonsh".into())
    } else if s.contains("osh") || s.contains("ysh") {
        Some("oils".into())
    } else {
        None
    }
}

fn detect_installed_shells() -> Vec<&'static str> {
    SHELL_BINARIES
        .iter()
        .filter(|(_, bins)| {
            bins.iter().any(|bin| {
                std::process::Command::new("which")
                    .arg(bin)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false)
            })
        })
        .map(|(name, _)| *name)
        .collect()
}

// ---------------------------------------------------------------------------
// Hook selection
// ---------------------------------------------------------------------------

fn get_hook(shell: &str) -> &'static str {
    match shell {
        "bash" => bash_hook(),
        "zsh" => zsh_hook(),
        "fish" => fish_hook(),
        "nushell" => nushell_hook(),
        "powershell" => powershell_hook(),
        "elvish" => elvish_hook(),
        "xonsh" => xonsh_hook(),
        "oils" => oils_hook(),
        _ => "",
    }
}

// ---------------------------------------------------------------------------
// Hook implementations
// ---------------------------------------------------------------------------

const fn zsh_hook() -> &'static str {
    r#"# shellfirm hook for zsh — intercepts Enter via the accept-line widget
shellfirm-pre-command() {
    if [[ -z "${BUFFER}" || "${BUFFER}" == *"shellfirm pre-command"* ]]; then
        zle .accept-line
        return
    fi
    shellfirm pre-command -c "${BUFFER}"
    if [[ $? -eq 0 ]]; then
        zle .accept-line
    fi
}
zle -N accept-line shellfirm-pre-command"#
}

const fn bash_hook() -> &'static str {
    r#"# shellfirm hook for bash — intercepts commands before execution via DEBUG trap
_shellfirm_hook() {
    [[ -n "${COMP_LINE:-}" ]] && return 0
    [[ "$BASH_COMMAND" == *"shellfirm"* ]] && return 0
    [[ "$BASH_COMMAND" == "_shellfirm_hook" ]] && return 0
    command -v shellfirm &>/dev/null || return 0
    # Temporarily trap SIGINT with a no-op so Ctrl+C kills only the child
    # (shellfirm pre-command) without interrupting this handler.  Using ':'
    # rather than '' ensures child processes still receive SIGINT normally.
    local __sf_prev_int
    __sf_prev_int=$(trap -p INT)
    trap ':' INT
    shellfirm pre-command -c "$BASH_COMMAND"
    local __sf_rc=$?
    # Restore previous SIGINT handler
    if [[ -n "$__sf_prev_int" ]]; then
        eval "$__sf_prev_int"
    else
        trap - INT
    fi
    [[ $__sf_rc -ne 0 ]] && return 1
    return 0
}
shopt -s extdebug
trap '_shellfirm_hook' DEBUG"#
}

const fn fish_hook() -> &'static str {
    r#"# shellfirm hook for fish — intercepts Enter via key binding
function _shellfirm_check
    set -l cmd (commandline)
    if test -z "$cmd"; or string match -q '*shellfirm pre-command*' -- $cmd
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
        if ($cmd | str contains "shellfirm pre-command") {
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

        if ($line -match 'shellfirm pre-command') {
            [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
            return
        }

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
        if (str:contains $cmd "shellfirm pre-command") {
            edit:smart-enter
            return
        }
        try {
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
        if "shellfirm pre-command" in cmd:
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
    r#"# shellfirm hook for Oils (OSH/YSH) — bash-compatible, uses extdebug
shopt -s extdebug
_shellfirm_hook() {
    [[ -n "${COMP_LINE:-}" ]] && return 0
    [[ "$BASH_COMMAND" == *"shellfirm"* ]] && return 0
    command -v shellfirm &>/dev/null || return 0
    shellfirm pre-command -c "$BASH_COMMAND" || return 1
    return 0
}
trap '_shellfirm_hook' DEBUG"#
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_shell_from_env() {
        let _ = detect_shell();
    }

    #[test]
    fn all_hooks_are_non_empty() {
        for shell in ALL_SHELLS {
            assert!(
                !get_hook(shell).is_empty(),
                "hook for {shell} should not be empty"
            );
        }
    }

    #[test]
    fn rc_paths_resolve_for_known_shells() {
        for shell in ALL_SHELLS {
            let _ = rc_file_path(shell);
        }
    }

    #[test]
    fn rc_snippet_returns_eval_for_eval_shells() {
        for shell in &["zsh", "bash", "fish", "oils"] {
            let snippet = rc_snippet(shell);
            assert!(
                snippet.contains("shellfirm init"),
                "{shell} snippet should contain eval one-liner"
            );
        }
    }

    #[test]
    fn rc_snippet_returns_full_hook_for_other_shells() {
        for shell in &["nushell", "powershell", "elvish", "xonsh"] {
            let snippet = rc_snippet(shell);
            assert!(
                snippet.contains("shellfirm") && snippet.len() > 50,
                "{shell} snippet should contain full hook code"
            );
        }
    }

    #[test]
    fn install_to_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let rc = dir.path().join(".zshrc");

        let snippet = rc_snippet("zsh");
        let block = format!("\n{MARKER}\n{snippet}\n");
        fs::write(&rc, block).unwrap();

        let content = fs::read_to_string(&rc).unwrap();
        assert!(content.contains(MARKER));
        assert!(content.contains("shellfirm init zsh"));
    }

    #[test]
    fn idempotent_install_detection() {
        let dir = tempfile::tempdir().unwrap();
        let rc = dir.path().join(".zshrc");

        let content = format!("# existing config\n{MARKER}\neval \"$(shellfirm init zsh)\"\n");
        fs::write(&rc, &content).unwrap();

        assert!(
            is_already_installed(&rc),
            "should detect existing installation"
        );
    }

    #[test]
    fn legacy_marker_detected() {
        let dir = tempfile::tempdir().unwrap();
        let rc = dir.path().join(".zshrc");

        let content =
            format!("# existing config\n{LEGACY_MARKER}\neval \"$(shellfirm init zsh)\"\n");
        fs::write(&rc, &content).unwrap();

        assert!(
            is_already_installed(&rc),
            "should detect legacy marker from --install era"
        );
    }

    #[test]
    fn validate_shell_name_accepts_known() {
        for shell in ALL_SHELLS {
            assert!(validate_shell_name(Some(shell)).is_ok());
        }
    }

    #[test]
    fn validate_shell_name_rejects_unknown() {
        assert!(validate_shell_name(Some("csh")).is_err());
        assert!(validate_shell_name(None).is_err());
    }

    #[test]
    fn detect_installed_shells_does_not_panic() {
        let _ = detect_installed_shells();
    }

    #[test]
    fn uninstall_removes_block_with_current_marker() {
        let snippet = rc_snippet("zsh");
        let content = format!("# my config\nPATH=/usr/bin\n\n{MARKER}\n{snippet}\n");

        let (result, changed) = remove_shellfirm_block(&content, "zsh");
        assert!(changed);
        assert!(!result.contains(MARKER));
        assert!(!result.contains("shellfirm init zsh"));
        assert!(result.contains("# my config"));
        assert!(result.contains("PATH=/usr/bin"));
    }

    #[test]
    fn uninstall_removes_block_with_legacy_marker() {
        let snippet = rc_snippet("bash");
        let content = format!("# my config\n\n{LEGACY_MARKER}\n{snippet}\n");

        let (result, changed) = remove_shellfirm_block(&content, "bash");
        assert!(changed);
        assert!(!result.contains(LEGACY_MARKER));
        assert!(result.contains("# my config"));
    }

    #[test]
    fn uninstall_removes_embedded_hook() {
        let snippet = rc_snippet("powershell");
        let content = format!("# existing stuff\n\n{MARKER}\n{snippet}\n");

        let (result, changed) = remove_shellfirm_block(&content, "powershell");
        assert!(changed);
        assert!(!result.contains("shellfirm"));
        assert!(result.contains("# existing stuff"));
    }

    #[test]
    fn uninstall_noop_when_not_installed() {
        let content = "# my config\nPATH=/usr/bin\n";

        let (result, changed) = remove_shellfirm_block(content, "zsh");
        assert!(!changed);
        assert_eq!(result, content);
    }

    #[test]
    fn uninstall_preserves_rest_of_file() {
        let snippet = rc_snippet("fish");
        let content =
            format!("# before\nexport FOO=bar\n\n{MARKER}\n{snippet}\n\n# after\nexport BAZ=qux\n");

        let (result, changed) = remove_shellfirm_block(&content, "fish");
        assert!(changed);
        assert!(result.contains("# before"));
        assert!(result.contains("export FOO=bar"));
        assert!(result.contains("# after"));
        assert!(result.contains("export BAZ=qux"));
        assert!(!result.contains("shellfirm"));
    }
}
