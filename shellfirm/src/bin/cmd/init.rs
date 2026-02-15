use std::fs;
use std::io::Write;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Arg, ArgAction, ArgMatches, Command};
use console::style;

const MARKER: &str = "# Added by shellfirm init --install";

pub fn command() -> Command {
    Command::new("init")
        .about("Set up shell integration")
        .long_about(
            "Print the shell hook to stdout (for eval), or pass --install to \
             automatically add the hook to your shell's rc file.",
        )
        .arg(
            Arg::new("shell")
                .help("Shell type: bash, zsh, fish, nushell, powershell, elvish, xonsh, oils")
                .required(false),
        )
        .arg(
            Arg::new("install")
                .long("install")
                .help("Automatically add the hook to your shell's rc file")
                .action(ArgAction::SetTrue),
        )
}

pub fn run(matches: &ArgMatches) -> Result<shellfirm::CmdExit> {
    let shell = matches
        .get_one::<String>("shell")
        .cloned()
        .or_else(detect_shell);

    let install = matches.get_flag("install");

    let shell_name = match shell.as_deref() {
        Some(
            s @ ("bash" | "zsh" | "fish" | "nushell" | "powershell" | "elvish" | "xonsh" | "oils"),
        ) => s,
        Some(other) => {
            return Ok(shellfirm::CmdExit {
                code: exitcode::USAGE,
                message: Some(format!(
                    "Unsupported shell: {other}. Supported: bash, zsh, fish, nushell, powershell, elvish, xonsh, oils"
                )),
            })
        }
        None => {
            return Ok(shellfirm::CmdExit {
                code: exitcode::USAGE,
                message: Some(
                    "Could not detect shell. Please specify: shellfirm init <shell> [--install]"
                        .to_string(),
                ),
            })
        }
    };

    let hook = get_hook(shell_name);

    if install {
        install_hook(shell_name, hook)
    } else {
        println!("{hook}");
        Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: None,
        })
    }
}

// ---------------------------------------------------------------------------
// --install: append hook to rc file
// ---------------------------------------------------------------------------

fn install_hook(shell: &str, hook: &str) -> Result<shellfirm::CmdExit> {
    let Some(rc_path) = rc_file_path(shell) else {
        return Ok(shellfirm::CmdExit {
            code: exitcode::USAGE,
            message: Some(format!(
                "Could not determine rc file for {shell}. Add the following to your shell config manually:\n\n{hook}"
            )),
        });
    };

    // Already installed?
    if rc_path.exists() {
        let content = fs::read_to_string(&rc_path).unwrap_or_default();
        if content.contains("shellfirm init") || content.contains(MARKER) {
            return Ok(shellfirm::CmdExit {
                code: exitcode::OK,
                message: Some(format!(
                    "shellfirm is already set up in {}",
                    rc_path.display()
                )),
            });
        }
    }

    // Ensure parent directory exists
    if let Some(parent) = rc_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Build the content to append.
    // Eval-capable shells get a one-liner so that upgrades pick up new hooks
    // automatically. Other shells get the full hook code.
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

/// For shells that support eval we write a one-liner that calls `shellfirm init <shell>`
/// at startup.  Other shells get the full hook code embedded directly.
fn rc_snippet(shell: &str) -> String {
    match shell {
        "zsh" => r#"eval "$(shellfirm init zsh)""#.to_string(),
        "bash" => r#"eval "$(shellfirm init bash)""#.to_string(),
        "fish" => "shellfirm init fish | source".to_string(),
        "oils" => r#"eval "$(shellfirm init oils)""#.to_string(),
        // Shells without a clean eval — embed the full hook code
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

fn detect_shell() -> Option<String> {
    std::env::var("SHELL").ok().and_then(|s| {
        if s.contains("zsh") {
            Some("zsh".into())
        } else if s.contains("bash") {
            Some("bash".into())
        } else if s.contains("fish") {
            Some("fish".into())
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
    })
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
    r#"# shellfirm hook for bash — uses extdebug to intercept commands before execution
if [[ "${BASH_VERSINFO[0]}" -ge 4 ]]; then
    shopt -s extdebug
    _shellfirm_hook() {
        [[ -n "${COMP_LINE:-}" ]] && return 0
        [[ "$BASH_COMMAND" == *"shellfirm"* ]] && return 0
        command -v shellfirm &>/dev/null || return 0
        shellfirm pre-command -c "$BASH_COMMAND" || return 1
        return 0
    }
    trap '_shellfirm_hook' DEBUG
fi"#
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
        // Just verify the function doesn't panic
        let _ = detect_shell();
    }

    #[test]
    fn all_hooks_are_non_empty() {
        for shell in &[
            "bash",
            "zsh",
            "fish",
            "nushell",
            "powershell",
            "elvish",
            "xonsh",
            "oils",
        ] {
            assert!(
                !get_hook(shell).is_empty(),
                "hook for {shell} should not be empty"
            );
        }
    }

    #[test]
    fn rc_paths_resolve_for_known_shells() {
        // On CI or environments without a home dir this might be None,
        // but it should never panic.
        for shell in &[
            "bash",
            "zsh",
            "fish",
            "nushell",
            "powershell",
            "elvish",
            "xonsh",
            "oils",
        ] {
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
            // These should contain the actual hook code, not an eval wrapper
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

        // Simulate install by writing snippet
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

        // Write initial content with marker
        let content = format!("# existing config\n{MARKER}\neval \"$(shellfirm init zsh)\"\n");
        fs::write(&rc, &content).unwrap();

        // Check detection
        let existing = fs::read_to_string(&rc).unwrap();
        assert!(
            existing.contains("shellfirm init") || existing.contains(MARKER),
            "should detect existing installation"
        );
    }
}
