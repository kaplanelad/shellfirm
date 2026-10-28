use std::fmt::Write as _;
use std::fs;
use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use clap::builder::PossibleValuesParser;
use clap::{Arg, ArgAction, ArgMatches, Command};
use console::style;
use regex::Regex;
use shellfirm::config::{ascii_fallback, glyph};
use shellfirm::error::Result;
use shellfirm::Config;

const MARKER: &str = "# Added by shellfirm init";
/// Closes the block for shells whose hook is embedded in the rc file, so the
/// whole block can be found (and upgraded / removed) even after the hook text
/// changes between shellfirm versions.
const END_MARKER: &str = "# End of shellfirm init";
/// First line of an rc file that `shellfirm init` created. `--uninstall`
/// deletes such a file again when nothing else is left in it.
const CREATED_NOTE: &str =
    "# Created by `shellfirm init`; `shellfirm init --uninstall` deletes this file when it is otherwise empty.";
/// Follows [`CREATED_NOTE`] once per directory `shellfirm init` created for
/// the rc file (deepest first), so `--uninstall` removes them again when
/// they are empty.
const CREATED_DIR_NOTE: &str = "# shellfirm init also created the directory ";
/// Follows the directory notes once per (empty) file `shellfirm init`
/// created next to the rc file (nushell's `env.nu`), so `--uninstall`
/// removes it again with the rc file when it is still empty.
const CREATED_FILE_NOTE: &str = "# shellfirm init also created the file ";

/// A file the shell needs next to its rc file, created empty when it is
/// missing: nushell asks whether to create `env.nu` at its first start and
/// takes the first typed line as the answer.
fn companion_file(shell: Shell, rc_path: &Path) -> Option<PathBuf> {
    matches!(shell, Shell::Nushell).then(|| rc_path.with_file_name("env.nu"))
}

/// Creates the companion file of `rc_path` when it is missing. Returns it
/// when it was created.
fn create_companion(shell: Shell, rc_path: &Path) -> Option<PathBuf> {
    let file = companion_file(shell, rc_path)?;
    if file.exists() {
        return None;
    }
    fs::write(&file, "").ok().map(|()| file)
}

/// Version of the shell hook protocol. Every hook sets it (for example
/// `__shellfirm_hook_version=9` in bash) so `shellfirm doctor` can tell a
/// shell that still runs an older hook.
pub const HOOK_VERSION: &str = "13";

/// Every name `init` accepts (canonical names and binary names).
const SHELL_NAMES: [&str; 12] = [
    "bash",
    "zsh",
    "fish",
    "nushell",
    "nu",
    "powershell",
    "pwsh",
    "elvish",
    "xonsh",
    "oils",
    "osh",
    "ysh",
];

// ---------------------------------------------------------------------------
// Shell enum
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
    Nushell,
    PowerShell,
    Elvish,
    Xonsh,
    Oils,
}

/// How the current shell was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellSource {
    /// The process that started shellfirm is a known shell.
    ParentProcess,
    /// `$SHELL` (the login shell; may differ from the shell in use).
    ShellEnv,
}

impl ShellSource {
    pub const fn describe(self) -> &'static str {
        match self {
            Self::ParentProcess => "parent process",
            Self::ShellEnv => "$SHELL",
        }
    }
}

/// Where rc files live. Abstracted so path resolution is unit-testable.
struct RcEnv {
    home: Option<PathBuf>,
    /// `dirs::config_dir()` (platform config dir).
    platform_config: Option<PathBuf>,
    zdotdir: Option<PathBuf>,
    xdg_config_home: Option<PathBuf>,
}

impl RcEnv {
    fn from_process() -> Self {
        let abs_env = |name: &str| {
            std::env::var_os(name)
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
        };
        Self {
            home: dirs::home_dir(),
            platform_config: dirs::config_dir(),
            zdotdir: abs_env("ZDOTDIR"),
            xdg_config_home: abs_env("XDG_CONFIG_HOME"),
        }
    }

    /// `$XDG_CONFIG_HOME`, falling back to `~/.config` (what fish, elvish,
    /// Oils and PowerShell on Unix use on every platform).
    fn xdg_config(&self) -> Option<PathBuf> {
        self.xdg_config_home
            .clone()
            .or_else(|| self.home.as_ref().map(|h| h.join(".config")))
    }
}

/// Name of the process that started shellfirm (`zsh`, `-bash`, ...).
fn parent_process_name() -> Option<String> {
    #[cfg(unix)]
    {
        let ppid = std::os::unix::process::parent_id();
        if let Ok(comm) = fs::read_to_string(format!("/proc/{ppid}/comm")) {
            return Some(comm.trim().to_string());
        }
        let out = std::process::Command::new("ps")
            .args(["-o", "comm=", "-p", &ppid.to_string()])
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .ok()?;
        let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (!name.is_empty()).then_some(name)
    }
    #[cfg(not(unix))]
    {
        None
    }
}

impl Shell {
    pub const ALL: [Self; 8] = [
        Self::Bash,
        Self::Zsh,
        Self::Fish,
        Self::Nushell,
        Self::PowerShell,
        Self::Elvish,
        Self::Xonsh,
        Self::Oils,
    ];

    pub const fn name(self) -> &'static str {
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

    /// The shell in use: the parent process when it is a known shell (so a
    /// zsh started from a bash login shell is reported as zsh), else `$SHELL`.
    pub fn detect_current() -> Option<(Self, ShellSource)> {
        if let Some(shell) = parent_process_name().and_then(|n| {
            let n = n.trim_start_matches('-');
            Self::from_binary_path(n)
        }) {
            return Some((shell, ShellSource::ParentProcess));
        }
        let shell_path = std::env::var("SHELL").ok()?;
        Self::from_binary_path(&shell_path).map(|s| (s, ShellSource::ShellEnv))
    }

    fn current() -> Option<Self> {
        Self::detect_current().map(|(s, _)| s)
    }

    fn from_binary_path(path: &str) -> Option<Self> {
        let binary = Path::new(path).file_name()?.to_str()?;
        let binary = binary.strip_suffix(".exe").unwrap_or(binary);
        Self::ALL
            .iter()
            .copied()
            .find(|s| s.binaries().contains(&binary))
    }

    /// Accepts the canonical name and the binary names (`nu`, `pwsh`, `osh`, ...).
    pub fn from_name(name: &str) -> Option<Self> {
        let name = name.trim().to_ascii_lowercase();
        Self::ALL
            .iter()
            .copied()
            .find(|s| s.name() == name || s.binaries().contains(&name.as_str()))
    }

    pub const fn binaries(self) -> &'static [&'static str] {
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

    pub fn rc_file_path(self) -> Option<PathBuf> {
        self.rc_file_path_in(&RcEnv::from_process())
    }

    fn rc_file_path_in(self, env: &RcEnv) -> Option<PathBuf> {
        let home = env.home.as_ref();
        match self {
            Self::Zsh => env
                .zdotdir
                .clone()
                .or_else(|| home.cloned())
                .map(|d| d.join(".zshrc")),
            Self::Bash => home.map(|h| h.join(".bashrc")),
            Self::Fish => env.xdg_config().map(|c| c.join("fish/config.fish")),
            // nushell honours XDG_CONFIG_HOME, otherwise the platform dir.
            Self::Nushell => env
                .xdg_config_home
                .clone()
                .or_else(|| env.platform_config.clone())
                .map(|c| c.join("nushell/config.nu")),
            Self::PowerShell => {
                if cfg!(windows) {
                    dirs::document_dir()
                        .map(|d| d.join("PowerShell/Microsoft.PowerShell_profile.ps1"))
                } else {
                    env.xdg_config()
                        .map(|c| c.join("powershell/Microsoft.PowerShell_profile.ps1"))
                }
            }
            Self::Elvish => env.xdg_config().map(|c| c.join("elvish/rc.elv")),
            Self::Xonsh => home.map(|h| h.join(".xonshrc")),
            Self::Oils => env.xdg_config().map(|c| c.join("oils/oshrc")),
        }
    }

    /// Shells that can `eval` the output of `shellfirm init <shell>` at
    /// startup get a one-liner; the others get the hook embedded in the rc file.
    pub const fn uses_eval(self) -> bool {
        matches!(self, Self::Bash | Self::Zsh | Self::Fish | Self::Oils)
    }

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

    /// The exact block written to the rc file.
    fn rc_block(self) -> String {
        let snippet = self.rc_snippet();
        if self.uses_eval() {
            format!("\n{MARKER}\n{snippet}\n")
        } else {
            format!("\n{MARKER}\n{snippet}\n{END_MARKER}\n")
        }
    }

    pub const fn hook(self) -> &'static str {
        match self {
            Self::Bash => BASH_HOOK,
            Self::Zsh => ZSH_HOOK,
            Self::Fish => FISH_HOOK,
            Self::Nushell => NUSHELL_HOOK,
            Self::PowerShell => POWERSHELL_HOOK,
            Self::Elvish => ELVISH_HOOK,
            Self::Xonsh => XONSH_HOOK,
            Self::Oils => OILS_HOOK,
        }
    }

    /// Hook text written by earlier shellfirm versions, so `--uninstall` and
    /// upgrades can still find and remove it: embedded blocks, and hooks
    /// pasted by hand (`shellfirm init bash >> ~/.bashrc` in 0.3.x).
    const fn legacy_hooks(self) -> &'static [&'static str] {
        match self {
            Self::Nushell => &[legacy::NUSHELL_HOOK],
            Self::PowerShell => &[legacy::POWERSHELL_HOOK],
            Self::Elvish => &[legacy::ELVISH_HOOK],
            Self::Xonsh => &[legacy::XONSH_HOOK],
            Self::Bash => &[legacy::BASH_HOOK],
            Self::Zsh => &[legacy::ZSH_HOOK],
            Self::Fish => &[legacy::FISH_HOOK],
            Self::Oils => &[legacy::OILS_HOOK],
        }
    }

    /// A line that only an old (0.3.x) hook contains.
    const fn legacy_signatures(self) -> &'static [&'static str] {
        match self {
            Self::Bash | Self::Oils => &["trap '_shellfirm_hook' DEBUG", "_shellfirm_hook()"],
            Self::Zsh => &[
                "zle -N accept-line shellfirm-pre-command",
                "shellfirm-pre-command()",
            ],
            Self::Fish => &["function _shellfirm_check", "bind \\r _shellfirm_check"],
            Self::Nushell | Self::PowerShell | Self::Elvish | Self::Xonsh => &[],
        }
    }

    /// Command that reloads the shell so the hook becomes active.
    pub const fn activate_hint(self) -> &'static str {
        match self {
            Self::Bash => "exec bash",
            Self::Zsh => "exec zsh",
            Self::Fish => "exec fish",
            Self::Oils => "exec osh",
            Self::Nushell => "exec nu",
            Self::Elvish => "exec elvish",
            Self::Xonsh => "exec xonsh",
            Self::PowerShell => ". $PROFILE",
        }
    }

    /// Known protection gaps that the user must be told about at install time.
    pub const fn limitation(self) -> Option<&'static str> {
        match self {
            Self::Nushell => Some(
                "nushell cannot cancel a command from a hook. shellfirm can only stop external \
                 programs (by clearing PATH for the line); for lines that use nushell built-ins \
                 (rm, mv, cp, save, ...), custom commands or programs run by path it only warns, \
                 and they still run. Aliases are expanded and the source of small custom \
                 commands is checked with the call.",
            ),
            Self::Elvish => Some(
                "elvish functions (`fn`) are not expanded: calling one is checked as typed, not \
                 by what its body runs. Commands typed directly are checked.",
            ),
            Self::Xonsh => Some(
                "xonsh aliases (string, list and callable) are expanded; `![...]`, `$[...]`, \
                 `!(...)`, `$(...)`, `$VAR` as the command, literal `@([...])` lists and the \
                 strings given to os.system / subprocess / evalx are checked (one that is only \
                 known when it runs is challenged); other Python code that starts programs \
                 (computed lists) is not.",
            ),
            Self::Oils => Some(
                "the Oils hook uses a DEBUG trap and reads the command from history; commands \
                 hidden from history (HISTCONTROL/HISTIGNORE) are not checked.",
            ),
            _ => None,
        }
    }
}

impl std::fmt::Display for Shell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(self.name())
    }
}

pub fn command() -> Command {
    Command::new("init")
        .about("Set up shell integration")
        .long_about(
            "Install the shellfirm hook for your shell.\n\n\
             Without arguments, installs the hook for the shell you are using (asks first), \
             and offers the other shells found on the system. --all installs for every \
             shell found. Specify a shell name to install for that shell only.\n\
             Use --dry-run to preview changes (install or uninstall) without writing anything.\n\n\
             When stdout is not a terminal (e.g. eval \"$(shellfirm init zsh)\"), prints the \
             hook to stdout instead of installing, unless --yes is given (for rollout \
             scripts: `shellfirm init zsh --yes` installs without a terminal). Without a \
             shell name the shell is taken from the parent process, then $SHELL.",
        )
        .arg(
            Arg::new("shell")
                .help(
                    "Install for a specific shell only: bash, zsh, fish, nushell (nu), \
                     powershell (pwsh), elvish, xonsh, oils (osh, ysh). If omitted, installs \
                     for the current shell.",
                )
                .value_parser(PossibleValuesParser::new(SHELL_NAMES))
                .ignore_case(true)
                .required(false),
        )
        .arg(
            Arg::new("all")
                .long("all")
                .help("Install (or with --uninstall, remove) for every shell found on the system")
                .conflicts_with("shell")
                .action(ArgAction::SetTrue),
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
        .arg(
            Arg::new("yes")
                .short('y')
                .long("yes")
                .help(
                    "Do not ask: modify rc files without confirmation and skip the setup \
                     questions (a settings file without a protection level gets the recommended \
                     Balanced level, min_severity: Medium). Also installs when stdout is not a \
                     terminal.",
                )
                .action(ArgAction::SetTrue),
        )
}

// Returns `Result` like the other subcommands' `run` (see `shellfirm.rs`).
#[allow(clippy::unnecessary_wraps)]
pub fn run(matches: &ArgMatches) -> Result<shellfirm::CmdExit> {
    let dry_run = matches.get_flag("dry-run");
    let uninstall = matches.get_flag("uninstall");
    let assume_yes = matches.get_flag("yes");
    let all = matches.get_flag("all");
    let explicit_shell = matches.get_one::<String>("shell").map(String::as_str);

    let shell = match explicit_shell.map(|name| validate_shell_arg(Some(name))) {
        Some(Ok(s)) => Some(s),
        Some(Err(exit)) => return Ok(exit),
        None => None,
    };

    // --- Uninstall mode ---
    if uninstall {
        return Ok(shell.map_or_else(
            || run_uninstall_all(dry_run),
            |shell| uninstall_hook(shell, dry_run),
        ));
    }

    // --- Print mode: `eval "$(shellfirm init zsh)"` ---
    if !dry_run && !assume_yes && !std::io::stdout().is_terminal() {
        let Some(shell) = shell.or_else(Shell::current) else {
            return Ok(shellfirm::CmdExit {
                code: exitcode::USAGE,
                message: Some(
                    "Could not detect the shell (parent process or $SHELL). Use: shellfirm init <shell>"
                        .to_string(),
                ),
            });
        };
        let hook = shell.hook();
        if hook.ends_with('\n') {
            print!("{hook}");
        } else {
            println!("{hook}");
        }
        return Ok(ok_exit(None));
    }

    // --- Install mode ---
    Ok(match shell {
        Some(shell) if dry_run => {
            eprintln!(
                "{}",
                ascii_fallback(&format!(
                    "\n{}\n",
                    style("shellfirm — dry run (no changes will be made)").bold()
                ))
            );
            preview_shell(shell);
            ok_exit(Some(
                "\nNo changes made. Run without --dry-run to apply.".into(),
            ))
        }
        Some(shell) => install_hook(shell, assume_yes),
        None if dry_run => run_dry_run_all(all),
        None => run_install_all(assume_yes, all),
    })
}

const fn ok_exit(message: Option<String>) -> shellfirm::CmdExit {
    shellfirm::CmdExit {
        code: exitcode::OK,
        message,
    }
}

/// Ask a yes/no question on stderr and read the answer from stdin. EOF or
/// an unreadable answer counts as "no". Plain text, no terminal escape codes.
fn ask_yes_no(question: &str, default: bool) -> bool {
    let hint = if default { "[Y/n]" } else { "[y/N]" };
    eprint!("{question} {hint} ");
    let _ = std::io::stderr().flush();
    let mut answer = String::new();
    let read = std::io::stdin().lock().read_line(&mut answer);
    match read {
        Ok(0) | Err(_) => {
            eprintln!();
            false
        }
        Ok(_) => match answer.trim().to_ascii_lowercase().as_str() {
            "" => default,
            "y" | "yes" => true,
            _ => false,
        },
    }
}

fn is_interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
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
                    "Unsupported shell: {name}. Supported: bash, zsh, fish, nushell (nu), \
                     powershell (pwsh), elvish, xonsh, oils (osh)"
                )),
            })
        },
    )
}

// ---------------------------------------------------------------------------
// rc file planning (pure, unit-tested)
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
enum InstallPlan {
    /// Nothing to do.
    AlreadyInstalled,
    /// Append this block to the file (creating it if needed).
    Append(String),
    /// An older hook was found; replace the whole file content.
    Upgrade(String),
}

/// Decide what installing `shell`'s hook into a file with `existing` content does.
fn plan_install(shell: Shell, existing: Option<&str>) -> InstallPlan {
    let block = shell.rc_block();
    let Some(content) = existing else {
        return InstallPlan::Append(block);
    };
    if content.contains(block.trim_start_matches('\n')) {
        return InstallPlan::AlreadyInstalled;
    }
    let (without, changed) = remove_shellfirm_block(content, shell);
    if changed {
        let mut new_content = without;
        // An eval-style loader the user wrote by hand still loads the new hook.
        if shell.uses_eval() && has_manual_hook(&new_content, shell) {
            return InstallPlan::Upgrade(new_content);
        }
        if !new_content.is_empty() && !new_content.ends_with('\n') {
            new_content.push('\n');
        }
        new_content.push_str(&block);
        return InstallPlan::Upgrade(new_content);
    }
    if has_manual_hook(content, shell) {
        return InstallPlan::AlreadyInstalled;
    }
    InstallPlan::Append(block)
}

/// True when the rc file already loads shellfirm: our marker, or a
/// hand-written (non-comment) line such as
/// `command -v shellfirm && eval "$(shellfirm init zsh)"`, or a hook pasted
/// by hand (`shellfirm init nu >> config.nu`).
fn has_manual_hook(content: &str, shell: Shell) -> bool {
    if content.contains(MARKER) {
        return true;
    }
    let header = shell.hook().lines().next().unwrap_or_default();
    if !header.is_empty() && content.lines().any(|l| l.trim_end() == header) {
        return true;
    }
    content.lines().any(|line| {
        let line = line.trim_start();
        if line.starts_with('#') {
            return false;
        }
        let Some(idx) = line.find("shellfirm init") else {
            return false;
        };
        let rest = line[idx + "shellfirm init".len()..].trim_start();
        let word: String = rest
            .chars()
            .take_while(char::is_ascii_alphanumeric)
            .collect();
        Shell::from_name(&word) == Some(shell)
    })
}

/// 1-based line number of a hook from shellfirm 0.3.x that is still in the
/// file (one that could not be removed automatically).
fn legacy_hook_line(content: &str, shell: Shell) -> Option<usize> {
    let sigs = shell.legacy_signatures();
    content
        .lines()
        .position(|l| {
            let t = l.trim_start();
            !t.starts_with('#') && sigs.iter().any(|s| t.contains(s))
        })
        .map(|i| i + 1)
}

fn loader_line_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"^\s*(?:command -v shellfirm\s*(?:>\s*/dev/null)?\s*(?:2>&1)?\s*&&\s*)?(?:eval\s+"\$\(\s*(?:\S*/)?shellfirm init (\w+)\s*\)"|(?:\S*/)?shellfirm init (\w+)\s*\|\s*source)\s*;?\s*$"#,
        )
        .expect("valid regex")
    })
}

/// True when `line` is a stand-alone line that only loads the hook for
/// `shell` (`eval "$(shellfirm init bash)"`, `shellfirm init fish | source`).
fn is_loader_line(line: &str, shell: Shell) -> bool {
    loader_line_re().captures(line).is_some_and(|c| {
        c.get(1)
            .or_else(|| c.get(2))
            .and_then(|m| Shell::from_name(m.as_str()))
            == Some(shell)
    })
}

/// How many times the file loads the current hook (more than one means
/// double hooks). A 0.3.x hook is reported on its own
/// ([`legacy_hook_line`]), not counted here.
fn hook_load_count(content: &str, shell: Shell) -> usize {
    if shell.uses_eval() {
        // The marked block of an eval shell is itself a loader line.
        content.lines().filter(|l| is_loader_line(l, shell)).count()
    } else {
        content.matches(END_MARKER).count()
    }
}

#[cfg(test)]
fn is_already_installed(rc_path: &Path, shell: Shell) -> bool {
    fs::read_to_string(rc_path)
        .ok()
        .is_some_and(|c| plan_install(shell, Some(&c)) == InstallPlan::AlreadyInstalled)
}

/// Remove every shellfirm block from rc file content.
fn remove_shellfirm_block(content: &str, shell: Shell) -> (String, bool) {
    let mut result = content.to_string();
    let mut changed = false;

    // Marker .. end-marker blocks (embedded hooks from this version on).
    while let Some(end_idx) = result.find(END_MARKER) {
        // The closest MARKER before the end marker opens this block.
        let Some(start) = result[..end_idx].rfind(MARKER) else {
            break;
        };
        let mut end = end_idx + END_MARKER.len();
        if result[end..].starts_with('\n') {
            end += 1;
        }
        // The block was written with a leading newline (see `rc_block`).
        let begin = if result[..start].ends_with('\n') {
            start - 1
        } else {
            start
        };
        result.replace_range(begin..end, "");
        changed = true;
    }

    // One-liner blocks and legacy embedded hooks (marker + text, no end marker).
    let mut texts = vec![shell.rc_snippet()];
    texts.extend(shell.legacy_hooks().iter().map(|s| (*s).to_string()));
    for text in &texts {
        for block in [
            format!("\n{MARKER}\n{text}\n"),
            format!("{MARKER}\n{text}\n"),
        ] {
            if result.contains(block.as_str()) {
                result = result.replace(block.as_str(), "");
                changed = true;
            }
        }
    }

    // Old hooks pasted by hand, without a marker.
    for text in shell.legacy_hooks() {
        for pasted in [format!("{text}\n"), (*text).to_string()] {
            if result.contains(pasted.as_str()) {
                result = result.replace(pasted.as_str(), "");
                changed = true;
            }
        }
    }

    (result, changed)
}

/// Remove stand-alone loader lines (`eval "$(shellfirm init bash)"`) that
/// were written by hand. Lines inside a construct (`if ...; then` on the
/// line before) are kept so the file stays valid.
fn remove_loader_lines(content: &str, shell: Shell) -> (String, Vec<usize>) {
    let mut out = String::with_capacity(content.len());
    let mut removed = Vec::new();
    let mut prev = "";
    for (i, line) in content.split_inclusive('\n').enumerate() {
        let bare = line.trim_end_matches(['\n', '\r']);
        let top_level = !bare.starts_with([' ', '\t'])
            && !["then", "do", "else", "{", "&&", "||", "\\", "|"]
                .iter()
                .any(|t| prev.ends_with(t));
        if top_level && is_loader_line(bare, shell) {
            removed.push(i + 1);
        } else {
            out.push_str(line);
        }
        let t = bare.trim();
        if !t.is_empty() && !t.starts_with('#') {
            prev = t;
        }
    }
    (out, removed)
}

fn friendly_io_error(action: &str, path: &Path, e: &std::io::Error) -> String {
    let hint = if e.kind() == std::io::ErrorKind::PermissionDenied {
        " (permission denied: is the file read-only?)"
    } else {
        ""
    };
    format!("could not {action} {}: {e}{hint}", path.display())
}

// ---------------------------------------------------------------------------
// rc file report (used by `shellfirm doctor`)
// ---------------------------------------------------------------------------

/// What the rc file of a shell says about the hook.
#[derive(Debug, Clone, Default, serde_derive::Serialize)]
pub struct RcReport {
    pub path: Option<PathBuf>,
    pub exists: bool,
    /// The file loads the hook (marker block, loader line or pasted hook).
    pub installed: bool,
    /// How many times the hook is loaded (> 1: double hooks).
    pub load_count: usize,
    /// Line of a shellfirm 0.3.x hook that is still in the file.
    pub legacy_hook_line: Option<usize>,
    /// The rc file does not load the hook, but this other startup file does
    /// (fish `conf.d`, a login file).
    pub loaded_from: Option<PathBuf>,
}

/// Other startup files the shell reads, where a hand-written loader line
/// may live instead of the rc file.
fn other_startup_files(shell: Shell, env: &RcEnv) -> Vec<PathBuf> {
    let home = env.home.clone();
    let mut files = Vec::new();
    match shell {
        Shell::Fish => {
            if let Some(dir) = env.xdg_config().map(|c| c.join("fish/conf.d")) {
                if let Ok(entries) = fs::read_dir(&dir) {
                    let mut found: Vec<PathBuf> = entries
                        .filter_map(std::result::Result::ok)
                        .map(|e| e.path())
                        .filter(|p| p.extension().is_some_and(|e| e == "fish"))
                        .collect();
                    found.sort();
                    files.extend(found);
                }
            }
        }
        Shell::Bash => {
            if let Some(h) = home {
                for f in [".bash_profile", ".bash_login", ".profile", ".bash_aliases"] {
                    files.push(h.join(f));
                }
            }
        }
        Shell::Zsh => {
            if let Some(d) = env.zdotdir.clone().or(home) {
                for f in [".zshenv", ".zprofile", ".zlogin"] {
                    files.push(d.join(f));
                }
            }
        }
        _ => {}
    }
    files
}

pub fn rc_report(shell: Shell) -> RcReport {
    rc_report_in(shell, &RcEnv::from_process())
}

fn rc_report_in(shell: Shell, env: &RcEnv) -> RcReport {
    let path = shell.rc_file_path_in(env);
    let content = path.as_ref().and_then(|p| fs::read_to_string(p).ok());
    let installed = content
        .as_deref()
        .is_some_and(|c| has_manual_hook(c, shell));
    let loaded_from = if installed {
        None
    } else {
        other_startup_files(shell, env)
            .into_iter()
            .find(|f| fs::read_to_string(f).is_ok_and(|c| has_manual_hook(&c, shell)))
    };
    RcReport {
        exists: content.is_some(),
        installed,
        load_count: content.as_deref().map_or(0, |c| hook_load_count(c, shell)),
        legacy_hook_line: content.as_deref().and_then(|c| legacy_hook_line(c, shell)),
        loaded_from,
        path,
    }
}

// ---------------------------------------------------------------------------
// Install
// ---------------------------------------------------------------------------

enum InstallOutcome {
    Installed(String),
    Upgraded(String),
    AlreadyInstalled(String),
    Failed(String),
}

impl InstallOutcome {
    const fn changed(&self) -> bool {
        matches!(self, Self::Installed(_) | Self::Upgraded(_))
    }
}

fn install_hook_quiet(shell: Shell) -> InstallOutcome {
    let Some(rc_path) = shell.rc_file_path() else {
        return InstallOutcome::Failed(format!("could not determine rc file for {shell}"));
    };
    let display = rc_path.display().to_string();

    let existing = if rc_path.exists() {
        match fs::read_to_string(&rc_path) {
            Ok(c) => Some(c),
            Err(e) => return InstallOutcome::Failed(friendly_io_error("read", &rc_path, &e)),
        }
    } else {
        None
    };

    match plan_install(shell, existing.as_deref()) {
        InstallPlan::AlreadyInstalled => InstallOutcome::AlreadyInstalled(display),
        InstallPlan::Upgrade(new_content) => match fs::write(&rc_path, new_content) {
            Ok(()) => InstallOutcome::Upgraded(display),
            Err(e) => InstallOutcome::Failed(friendly_io_error("write", &rc_path, &e)),
        },
        InstallPlan::Append(block) => {
            // Directories that do not exist yet (deepest first).
            let mut new_dirs = Vec::new();
            let mut dir = rc_path.parent();
            while let Some(d) = dir.filter(|d| !d.as_os_str().is_empty() && !d.exists()) {
                new_dirs.push(d.to_path_buf());
                dir = d.parent();
            }
            if let Some(parent) = rc_path.parent() {
                if let Err(e) = fs::create_dir_all(parent) {
                    return InstallOutcome::Failed(friendly_io_error("create", parent, &e));
                }
            }
            let companion = create_companion(shell, &rc_path);
            let block = match existing.as_deref() {
                // A brand-new file: note that shellfirm created it (and its
                // directories and companion file), so `--uninstall` can
                // delete them again.
                None => {
                    let mut notes = new_dirs.iter().fold(String::new(), |mut acc, d| {
                        let _ = writeln!(acc, "{CREATED_DIR_NOTE}{}", d.display());
                        acc
                    });
                    if let Some(f) = &companion {
                        let _ = writeln!(notes, "{CREATED_FILE_NOTE}{}", f.display());
                    }
                    format!("{CREATED_NOTE}\n{notes}{}", block.trim_start_matches('\n'))
                }
                Some("") => block.trim_start_matches('\n').to_string(),
                Some(_) => block,
            };
            let result = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&rc_path)
                .and_then(|mut f| f.write_all(block.as_bytes()));
            match result {
                Ok(()) => InstallOutcome::Installed(display),
                Err(e) => InstallOutcome::Failed(friendly_io_error("write", &rc_path, &e)),
            }
        }
    }
}

/// A note about a 0.3.x hook that is still in the rc file after installing.
fn legacy_note(shell: Shell) -> Option<String> {
    let path = shell.rc_file_path()?;
    let content = fs::read_to_string(&path).ok()?;
    let line = legacy_hook_line(&content, shell)?;
    Some(format!(
        "{} {} line {line} still has a hook from an older shellfirm (0.3.x); remove it by hand \
         to avoid double prompts (the new hook disables it at startup where it can).",
        style("note:").yellow().bold(),
        path.display()
    ))
}

fn install_hook(shell: Shell, assume_yes: bool) -> shellfirm::CmdExit {
    let Some(rc_path) = shell.rc_file_path() else {
        return shellfirm::CmdExit {
            code: exitcode::USAGE,
            message: Some(format!(
                "Could not determine rc file for {shell}. Add the following to your shell config manually:\n\n{}",
                shell.hook()
            )),
        };
    };
    let rc_display = rc_path.display().to_string();

    // `shellfirm init zsh` asks the same question as `shellfirm init`.
    if is_interactive() && !assume_yes {
        eprintln!(
            "{}",
            ascii_fallback(&format!(
                "\n{}\n",
                style(format!("shellfirm — install the hook for {shell}")).bold()
            ))
        );
        if matches!(
            preview_shell(shell),
            Preview::WillAdd | Preview::WillUpgrade
        ) {
            eprintln!();
            if !ask_yes_no("Modify this file?", true) {
                return ok_exit(Some("No changes made.".into()));
            }
        }
    }

    // The same layout as `shellfirm init` (one line per shell, a count,
    // then how to activate it), whichever shell and however it is run.
    let (installed, already, errors, mut notes) = install_each(&[shell]);
    if already > 0 {
        if let Some(n) = legacy_note(shell) {
            notes.push(format!("  {n}"));
        }
    }
    let extra = if errors > 0 {
        format!(
            "\n\nAdd this line to your {shell} config ({rc_display}) manually instead:\n\n{}",
            shell.rc_snippet()
        )
    } else {
        String::new()
    };
    summary_exit(&installed, already, errors, &notes, assume_yes, &extra)
}

/// Install for each shell, printing one line per shell. Returns
/// (newly installed, already set up, errors, notes).
fn install_each(shells: &[Shell]) -> (Vec<Shell>, u32, u32, Vec<String>) {
    let mut installed = Vec::new();
    let mut already = 0u32;
    let mut errors = 0u32;
    let mut notes = Vec::new();
    for shell in shells {
        let outcome = install_hook_quiet(*shell);
        let changed = outcome.changed();
        match outcome {
            InstallOutcome::Installed(path) | InstallOutcome::Upgraded(path) => {
                eprintln!(
                    "{}",
                    ascii_fallback(&format!(
                        "  {} {:<12} → {}",
                        style("✓").green().bold(),
                        shell,
                        style(&path).cyan()
                    ))
                );
                installed.push(*shell);
                if let Some(l) = shell.limitation() {
                    notes.push(format!("  {} {shell}: {l}", style("note:").yellow().bold()));
                }
            }
            InstallOutcome::AlreadyInstalled(path) => {
                eprintln!(
                    "{}",
                    ascii_fallback(&format!(
                        "  {} {:<12} → {} (already set up)",
                        style("✓").dim(),
                        shell,
                        style(&path).dim()
                    ))
                );
                already += 1;
            }
            InstallOutcome::Failed(msg) => {
                eprintln!(
                    "{}",
                    ascii_fallback(&format!(
                        "  {} {:<12} → {}",
                        style("✗").red().bold(),
                        shell,
                        style(&msg).red()
                    ))
                );
                errors += 1;
            }
        }
        if changed {
            if let Some(n) = legacy_note(*shell) {
                notes.push(format!("  {n}"));
            }
        }
    }
    (installed, already, errors, notes)
}

/// Shells whose rc file would change.
fn pending_shells(shells: &[Shell]) -> Vec<Shell> {
    shells
        .iter()
        .copied()
        .filter(|s| {
            s.rc_file_path().is_some_and(|p| {
                let existing = fs::read_to_string(p).ok();
                plan_install(*s, existing.as_deref()) != InstallPlan::AlreadyInstalled
            })
        })
        .collect()
}

fn summary_exit(
    installed: &[Shell],
    already: u32,
    errors: u32,
    notes: &[String],
    assume_yes: bool,
    extra: &str,
) -> shellfirm::CmdExit {
    eprintln!();
    for note in notes {
        eprintln!("{note}");
    }
    if !notes.is_empty() {
        eprintln!();
    }
    let new = installed.len();
    let total_protected = new + already as usize;
    let shells = if total_protected == 1 {
        "shell"
    } else {
        "shells"
    };
    let counts = if errors > 0 {
        let errs = if errors == 1 { "error" } else { "errors" };
        format!("{total_protected} {shells} protected ({new} new, {already} already set up, {errors} {errs}).")
    } else {
        format!("{total_protected} {shells} protected ({new} new, {already} already set up).")
    };

    if !assume_yes && !installed.is_empty() {
        if let Err(e) = run_interactive_setup() {
            eprintln!("  {}: {e}", style("warning").yellow());
        }
    }
    // Questions skipped (`--yes`, no terminal, Esc): the recommended level,
    // not the catch-everything default.
    if !installed.is_empty() {
        match apply_recommended_level() {
            Ok(true) => eprintln!(
                "  Protection level: Balanced (Recommended: medium-risk and above). Change it with \
                 `shellfirm config severity`."
            ),
            Ok(false) => {}
            Err(e) => eprintln!("  {}: {e}", style("warning").yellow()),
        }
    }
    let hints = if installed.is_empty() {
        String::new()
    } else {
        format_activate_hints(installed.to_vec())
    };
    shellfirm::CmdExit {
        code: if errors > 0 {
            exitcode::CANTCREAT
        } else {
            exitcode::OK
        },
        message: Some(format!("{counts}{extra}{hints}")),
    }
}

fn run_install_all(assume_yes: bool, all: bool) -> shellfirm::CmdExit {
    let detected = detect_installed_shells();
    let current = if all { None } else { Shell::detect_current() };
    let Some((current, source)) = current else {
        if !all {
            eprintln!(
                "\n{}",
                style("Could not tell which shell you are using; offering every shell found.")
                    .yellow()
            );
        }
        return install_many(&detected, assume_yes);
    };

    eprintln!(
        "{}",
        ascii_fallback(&format!(
            "\n{}\n",
            style(format!(
                "shellfirm — install the hook for {current} (your shell, from the {})",
                source.describe()
            ))
            .bold()
        ))
    );
    let preview = preview_shell(current);
    eprintln!();
    let interactive = is_interactive();

    let mut installed = Vec::new();
    let mut already = 0u32;
    let mut errors = 0u32;
    let mut notes = Vec::new();
    match preview {
        Preview::AlreadyInstalled => already += 1,
        Preview::Unknown => errors += 1,
        Preview::WillAdd | Preview::WillUpgrade => {
            if interactive && !assume_yes && !ask_yes_no("Modify this file?", true) {
                return ok_exit(Some("No changes made.".into()));
            }
            let (i, a, e, n) = install_each(&[current]);
            installed.extend(i);
            already += a;
            errors += e;
            notes.extend(n);
        }
    }

    // Other shells found on the system: only with an explicit yes.
    let others: Vec<Shell> = detected.iter().copied().filter(|s| *s != current).collect();
    let others = pending_shells(&others);
    let mut extra = String::new();
    if !others.is_empty() {
        let names = others
            .iter()
            .map(|s| s.name())
            .collect::<Vec<_>>()
            .join(", ");
        if interactive && !assume_yes {
            eprintln!();
            if ask_yes_no(&format!("Also add the hook for: {names}?"), false) {
                let (i, a, e, n) = install_each(&others);
                installed.extend(i);
                already += a;
                errors += e;
                notes.extend(n);
            }
        } else {
            extra = format!(
                "\nOther shells found ({names}) were not changed: run `shellfirm init <shell>` \
                 or `shellfirm init --all`."
            );
        }
    }
    summary_exit(&installed, already, errors, &notes, assume_yes, &extra)
}

fn install_many(detected: &[Shell], assume_yes: bool) -> shellfirm::CmdExit {
    if detected.is_empty() {
        return ok_exit(Some("No supported shells detected on this system.".into()));
    }

    eprintln!(
        "{}",
        ascii_fallback(&format!(
            "\n{}\n",
            style("shellfirm — install hooks for detected shells").bold()
        ))
    );
    let mut pending = 0;
    for shell in detected {
        if !matches!(
            preview_shell(*shell),
            Preview::AlreadyInstalled | Preview::Unknown
        ) {
            pending += 1;
        }
    }
    print_not_installed(detected);
    eprintln!();

    if pending == 0 {
        return ok_exit(Some("All detected shells are already set up.".into()));
    }

    if is_interactive() && !assume_yes {
        if !ask_yes_no(&format!("Modify the {pending} file(s) listed above?"), true) {
            return ok_exit(Some("No changes made.".into()));
        }
        eprintln!();
    }

    let (installed, already, errors, notes) = install_each(detected);
    summary_exit(&installed, already, errors, &notes, assume_yes, "")
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
                    style(glyph("▸", ">")).magenta().bold(),
                    style(shell.activate_hint()).magenta().bold(),
                    style(format!("({shell}, your shell)")).magenta()
                )
            } else if shell.activate_hint().contains(shell.name()) {
                // `exec zsh (zsh)` would say it twice.
                format!("    {}", style(shell.activate_hint()).cyan())
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

fn print_not_installed(detected: &[Shell]) {
    for shell in Shell::ALL {
        if !detected.contains(&shell) {
            eprintln!(
                "{}",
                ascii_fallback(&format!(
                    "  {} {:<12}   {}",
                    style("—").dim(),
                    shell,
                    style("(not installed on system)").dim()
                ))
            );
        }
    }
}

// ---------------------------------------------------------------------------
// --dry-run
// ---------------------------------------------------------------------------

fn run_dry_run_all(all: bool) -> shellfirm::CmdExit {
    let detected = detect_installed_shells();
    eprintln!(
        "{}",
        ascii_fallback(&format!(
            "\n{}\n",
            style("shellfirm — dry run (no changes will be made)").bold()
        ))
    );
    let current = if all { None } else { Shell::current() };
    if let Some(current) = current {
        preview_shell(current);
        let others: Vec<Shell> = detected.iter().copied().filter(|s| *s != current).collect();
        let others = pending_shells(&others);
        if !others.is_empty() {
            let names = others
                .iter()
                .map(|s| s.name())
                .collect::<Vec<_>>()
                .join(", ");
            eprintln!(
                "\n  Other shells found ({names}) are only changed after you agree (or with --all)."
            );
        }
    } else {
        for shell in &detected {
            preview_shell(*shell);
        }
        print_not_installed(&detected);
    }
    ok_exit(Some(
        "\nNo changes made. Run without --dry-run to apply.".into(),
    ))
}

enum Preview {
    AlreadyInstalled,
    WillAdd,
    WillUpgrade,
    Unknown,
}

fn preview_shell(shell: Shell) -> Preview {
    let Some(path) = shell.rc_file_path() else {
        eprintln!(
            "  {} {:<12}   {}",
            style("?").red(),
            shell,
            style("could not determine rc file").red()
        );
        return Preview::Unknown;
    };
    let existing = fs::read_to_string(&path).ok();
    let display = path.display().to_string();
    match plan_install(shell, existing.as_deref()) {
        InstallPlan::AlreadyInstalled => {
            eprintln!(
                "{}",
                ascii_fallback(&format!(
                    "  {} {:<12} → {} {}",
                    style("✓").dim(),
                    shell,
                    style(&display).dim(),
                    style("(already installed)").yellow()
                ))
            );
            Preview::AlreadyInstalled
        }
        InstallPlan::Upgrade(_) => {
            eprintln!(
                "{}",
                ascii_fallback(&format!(
                    "  {} {:<12} → {}",
                    style("→").green().bold(),
                    shell,
                    style(format!("will update the hook in {display}")).green()
                ))
            );
            Preview::WillUpgrade
        }
        InstallPlan::Append(_) => {
            let verb = if existing.is_some() {
                "will add hook to"
            } else {
                "will create"
            };
            eprintln!(
                "{}",
                ascii_fallback(&format!(
                    "  {} {:<12} → {}",
                    style("→").green().bold(),
                    shell,
                    style(format!("{verb} {display}")).green()
                ))
            );
            if shell.uses_eval() {
                eprintln!(
                    "  {:<14}   {}",
                    "",
                    style(format!("+ {}", shell.rc_snippet())).dim()
                );
            } else {
                eprintln!(
                    "  {:<14}   {}",
                    "",
                    style(format!(
                        "+ embedded hook ({} lines)",
                        shell.hook().lines().count()
                    ))
                    .dim()
                );
            }
            Preview::WillAdd
        }
    }
}

// ---------------------------------------------------------------------------
// Interactive first-run setup
// ---------------------------------------------------------------------------

/// Prompt the user to choose a challenge type and protection level.
///
/// Skipped when:
/// - stdin or stderr is not a terminal (piped / non-interactive)
/// - the settings file already chooses a challenge or a protection level
///   (a file that only holds, say, an ignore list, written by `shellfirm
///   config ignore` before `init`, still gets the two questions; the
///   answers are added to it)
fn run_interactive_setup() -> Result<()> {
    if !is_interactive() {
        return Ok(());
    }

    let config = Config::new(None)?;
    if config.setting_file_path.exists() && settings_choose_protection(&config) {
        return Ok(());
    }

    super::config::run_interactive_setup(&config)
}

/// When the settings file does not choose a protection level (no
/// `min_severity`, e.g. `init --yes` or skipped setup questions), set the
/// recommended Balanced level (`min_severity: Medium`). Returns `true` when
/// it was set. A file that cannot be read is left alone.
fn apply_recommended_level() -> Result<bool> {
    let config = Config::new(None)?;
    let Ok(mut root) = config.read_config_as_value() else {
        return Ok(false);
    };
    if !root.is_mapping() {
        return Ok(false);
    }
    if root
        .as_mapping()
        .is_some_and(|m| m.contains_key(serde_yaml::Value::from("min_severity")))
    {
        return Ok(false);
    }
    shellfirm::value_set(
        &mut root,
        "min_severity",
        serde_yaml::to_value(Some(shellfirm::checks::Severity::Medium))?,
    )?;
    config.save_config_from_value(&root)?;
    Ok(true)
}

/// `true` when the settings file sets `challenge` or `min_severity` (or
/// cannot be read: then it is left alone).
fn settings_choose_protection(config: &Config) -> bool {
    config.read_config_as_value().map_or(true, |root| {
        root.as_mapping().is_some_and(|m| {
            ["challenge", "min_severity"]
                .iter()
                .any(|k| m.contains_key(serde_yaml::Value::from(*k)))
        })
    })
}

// ---------------------------------------------------------------------------
// Uninstall
// ---------------------------------------------------------------------------

enum UninstallOutcome {
    Removed(String),
    /// The hook was removed and the file, which `shellfirm init` had
    /// created, was left empty and deleted.
    Deleted(String),
    WouldRemove(String),
    NotInstalled,
    Failed(String),
}

/// Result of removing the hook from rc file content.
#[derive(Debug, PartialEq, Eq)]
struct Removal {
    content: String,
    changed: bool,
    /// The file was created by `shellfirm init` and nothing else is left.
    delete_file: bool,
    /// Directories `shellfirm init` created for the file (deepest first);
    /// removed with the file when they are empty.
    created_dirs: Vec<PathBuf>,
    /// Empty files `shellfirm init` created next to it (nushell `env.nu`);
    /// removed with the file when they are still empty.
    created_files: Vec<PathBuf>,
}

fn plan_uninstall(content: &str, shell: Shell) -> Removal {
    let (without_blocks, mut changed) = remove_shellfirm_block(content, shell);
    let (mut out, loader_lines) = remove_loader_lines(&without_blocks, shell);
    changed |= !loader_lines.is_empty();
    let mut delete_file = false;
    let mut created_dirs = Vec::new();
    let mut created_files = Vec::new();
    if changed {
        if let Some(rest) = out.strip_prefix(CREATED_NOTE) {
            let mut rest = rest.strip_prefix('\n').unwrap_or(rest);
            while let Some(after) = rest.strip_prefix(CREATED_DIR_NOTE) {
                let (dir, tail) = after.split_once('\n').unwrap_or((after, ""));
                created_dirs.push(PathBuf::from(dir));
                rest = tail;
            }
            while let Some(after) = rest.strip_prefix(CREATED_FILE_NOTE) {
                let (file, tail) = after.split_once('\n').unwrap_or((after, ""));
                created_files.push(PathBuf::from(file));
                rest = tail;
            }
            if rest.trim().is_empty() {
                delete_file = true;
            }
            out = rest.to_string();
        }
    }
    Removal {
        content: out,
        changed,
        delete_file,
        created_dirs,
        created_files,
    }
}

/// Remove the files `shellfirm init` created next to `rc_path` (only there,
/// and only while they are still empty).
fn remove_created_files(rc_path: &Path, files: &[PathBuf]) {
    for file in files {
        if file.parent() == rc_path.parent()
            && file != rc_path
            && fs::metadata(file).is_ok_and(|m| m.is_file() && m.len() == 0)
        {
            let _ = fs::remove_file(file);
        }
    }
}

/// Remove the (empty) directories `shellfirm init` created for `rc_path`.
/// Only ancestors of the rc file are touched, and never a non-empty one.
fn remove_created_dirs(rc_path: &Path, dirs: &[PathBuf]) {
    for dir in dirs {
        if rc_path.starts_with(dir) && dir != rc_path {
            // Fails (and is ignored) when the directory is not empty.
            let _ = fs::remove_dir(dir);
        }
    }
}

fn uninstall_hook_quiet(shell: Shell, dry_run: bool) -> UninstallOutcome {
    let Some(rc_path) = shell.rc_file_path() else {
        return UninstallOutcome::NotInstalled;
    };
    if !rc_path.exists() {
        return UninstallOutcome::NotInstalled;
    }

    let display = rc_path.display().to_string();
    let content = match fs::read_to_string(&rc_path) {
        Ok(c) => c,
        Err(e) => return UninstallOutcome::Failed(friendly_io_error("read", &rc_path, &e)),
    };

    let removal = plan_uninstall(&content, shell);
    if !removal.changed {
        return UninstallOutcome::NotInstalled;
    }
    if dry_run {
        return UninstallOutcome::WouldRemove(display);
    }

    if removal.delete_file {
        return match fs::remove_file(&rc_path) {
            Ok(()) => {
                remove_created_files(&rc_path, &removal.created_files);
                remove_created_dirs(&rc_path, &removal.created_dirs);
                UninstallOutcome::Deleted(display)
            }
            Err(e) => UninstallOutcome::Failed(friendly_io_error("delete", &rc_path, &e)),
        };
    }
    match fs::write(&rc_path, removal.content) {
        Ok(()) => UninstallOutcome::Removed(display),
        Err(e) => UninstallOutcome::Failed(friendly_io_error("write", &rc_path, &e)),
    }
}

/// Print one shell's line of `init --uninstall --all`. Returns
/// `Some(true)` for a hook removed (or that would be), `Some(false)` for an
/// error, `None` when the shell had no hook.
fn print_uninstall_outcome(shell: Shell, outcome: UninstallOutcome) -> Option<bool> {
    let (mark, path, what) = match outcome {
        UninstallOutcome::Removed(path) => (style("✓").green().bold(), path, "(hook removed)"),
        UninstallOutcome::Deleted(path) => (
            style("✓").green().bold(),
            path,
            "(hook removed; the file shellfirm created was empty and is deleted)",
        ),
        UninstallOutcome::WouldRemove(path) => {
            (style("→").yellow().bold(), path, "(would remove hook)")
        }
        UninstallOutcome::NotInstalled => return None,
        UninstallOutcome::Failed(msg) => {
            eprintln!(
                "{}",
                ascii_fallback(&format!(
                    "  {} {:<12} → {}",
                    style("✗").red().bold(),
                    shell,
                    style(&msg).red()
                ))
            );
            return Some(false);
        }
    };
    eprintln!(
        "{}",
        ascii_fallback(&format!(
            "  {mark} {shell:<12} → {} {what}",
            style(&path).cyan()
        ))
    );
    Some(true)
}

fn run_uninstall_all(dry_run: bool) -> shellfirm::CmdExit {
    let title = if dry_run {
        "shellfirm — dry run: hooks that would be removed (no changes will be made)"
    } else {
        "shellfirm — removing the shellfirm hooks"
    };
    eprintln!("\n{}\n", style(ascii_fallback(title)).bold());

    let mut removed = 0u32;
    let mut errors = 0u32;
    let mut leftovers = Vec::new();
    // Files shellfirm created, with the directories created for them
    // (`~/.config` can be shared by several of them).
    let mut created = Vec::new();
    for shell in Shell::ALL {
        if !dry_run {
            if let Some(path) = shell.rc_file_path() {
                if let Ok(content) = fs::read_to_string(&path) {
                    let plan = plan_uninstall(&content, shell);
                    if plan.delete_file && !plan.created_dirs.is_empty() {
                        created.push((path, plan.created_dirs));
                    }
                }
            }
        }
        match print_uninstall_outcome(shell, uninstall_hook_quiet(shell, dry_run)) {
            Some(true) => removed += 1,
            Some(false) => errors += 1,
            None => {}
        }
        if let Some(note) = manual_leftover(shell) {
            leftovers.push(note);
        }
    }
    if !dry_run && removed > 0 {
        remove_recommended_settings();
    }
    for (path, dirs) in &created {
        if !path.exists() {
            remove_created_dirs(path, dirs);
        }
    }
    eprintln!();
    for note in &leftovers {
        eprintln!("  {} {note}", style("note:").yellow().bold());
    }

    if removed == 0 && errors == 0 {
        if leftovers.is_empty() {
            return ok_exit(Some("No shellfirm hooks found in any shell.".into()));
        }
        return ok_exit(Some(
            "No hooks written by `shellfirm init` were found; remove the lines above by hand."
                .into(),
        ));
    }
    let summary = if dry_run {
        format!(
            "{removed} hook(s) would be removed. No changes made. Run without --dry-run to apply."
        )
    } else if errors > 0 {
        format!("Removed hooks from {removed} shell(s) ({errors} error(s)).\nRestart your shells to deactivate.")
    } else {
        format!("Removed hooks from {removed} shell(s).\nRestart your shells to deactivate.")
    };
    shellfirm::CmdExit {
        code: if errors > 0 {
            exitcode::CANTCREAT
        } else {
            exitcode::OK
        },
        message: Some(summary),
    }
}

/// A line that still loads shellfirm after uninstalling (written by hand
/// inside a construct, or an old hook), so the user can remove it. Looks at
/// the file as uninstalling leaves it, so `--dry-run` reports the same
/// leftovers as a real run.
fn manual_leftover(shell: Shell) -> Option<String> {
    let path = shell.rc_file_path()?;
    let raw = fs::read_to_string(&path).ok()?;
    let removal = plan_uninstall(&raw, shell);
    if removal.delete_file {
        return None;
    }
    let content = if removal.changed {
        removal.content
    } else {
        raw
    };
    if let Some(line) = legacy_hook_line(&content, shell) {
        return Some(format!(
            "{} line {line}: a hook from an older shellfirm is still there; remove it by hand.",
            path.display()
        ));
    }
    let line = content.lines().position(|l| {
        let t = l.trim_start();
        !t.starts_with('#') && has_manual_hook(t, shell) && t.contains("shellfirm")
    })?;
    Some(format!(
        "{} line {}: still loads shellfirm (`{}`); remove it by hand.",
        path.display(),
        line + 1,
        content.lines().nth(line).unwrap_or_default().trim()
    ))
}

/// The settings file `init` wrote when the setup questions were skipped
/// (only the recommended level, see [`apply_recommended_level`]): removed
/// with the last hook, with its directory when nothing else is in it.
fn remove_recommended_settings() {
    let Ok(config) = Config::new(None) else {
        return;
    };
    let path = &config.setting_file_path;
    if fs::read_to_string(path).is_ok_and(|c| c.trim() == RECOMMENDED_SETTINGS.trim()) {
        let _ = fs::remove_file(path);
        if let Some(dir) = path.parent() {
            let _ = fs::remove_dir(dir);
        }
    }
}

/// What [`apply_recommended_level`] writes into a new settings file.
const RECOMMENDED_SETTINGS: &str = "min_severity: Medium\n";

fn uninstall_hook(shell: Shell, dry_run: bool) -> shellfirm::CmdExit {
    let Some(rc_path) = shell.rc_file_path() else {
        return ok_exit(Some(ascii_fallback(&format!(
            "No rc file found for {shell} — nothing to remove."
        ))));
    };
    let display = rc_path.display().to_string();
    let leftover = || {
        manual_leftover(shell)
            .map(|n| format!("\n{} {n}", style("note:").yellow().bold()))
            .unwrap_or_default()
    };
    match uninstall_hook_quiet(shell, dry_run) {
        UninstallOutcome::NotInstalled => {
            if rc_path.exists() {
                if let Some(n) = manual_leftover(shell) {
                    return ok_exit(Some(format!(
                        "No hook written by `shellfirm init` was found, but {n}"
                    )));
                }
                ok_exit(Some(format!("No shellfirm hook found in {display}")))
            } else {
                ok_exit(Some(ascii_fallback(&format!("{display} does not exist — nothing to remove."))))
            }
        }
        UninstallOutcome::WouldRemove(path) => ok_exit(Some(format!(
            "Would remove the shellfirm hook from {path}\nNo changes made. Run without --dry-run to apply."
        ))),
        UninstallOutcome::Removed(path) => {
            // The last hook: also the settings `init --yes` wrote.
            if Shell::ALL.iter().all(|s| !rc_report(*s).installed) {
                remove_recommended_settings();
            }
            ok_exit(Some(format!(
            "{} hook removed from {}\nRestart your shell to deactivate.{}",
            style("shellfirm").green().bold(),
            style(path).cyan(),
            leftover(),
        )))
        }
        UninstallOutcome::Deleted(path) => ok_exit(Some(format!(
            "{} hook removed; {} was created by `shellfirm init` and is now empty, so it was deleted.\nRestart your shell to deactivate.",
            style("shellfirm").green().bold(),
            style(path).cyan(),
        ))),
        UninstallOutcome::Failed(msg) => shellfirm::CmdExit {
            code: exitcode::CANTCREAT,
            message: Some(msg),
        },
    }
}

// ---------------------------------------------------------------------------
// Shell detection
// ---------------------------------------------------------------------------

pub fn detect_installed_shells() -> Vec<Shell> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let dirs: Vec<PathBuf> = std::env::split_paths(&path).collect();
    Shell::ALL
        .iter()
        .copied()
        .filter(|shell| {
            shell.binaries().iter().any(|bin| {
                dirs.iter().any(|d| {
                    let p = d.join(bin);
                    p.is_file() || (cfg!(windows) && d.join(format!("{bin}.exe")).is_file())
                })
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Hook implementations
// ---------------------------------------------------------------------------
/// bash: Enter / Ctrl-J (and Ctrl-O) run a readline macro: first
/// `__shellfirm_accept` (via `bind -x`, which sees the exact text in
/// `READLINE_LINE`), then `accept-line`. On deny the second key is rebound
/// to a no-op so the line stays in the buffer. Aliases and small functions
/// are expanded in every command of the line, and history references line
/// by line. `fc` (also used by Ctrl-X Ctrl-E / vi `v`) checks the edited
/// text and re-runs (`fc -s`, also resolved on Enter however it is
/// spelled); atuin's `enter_accept` is wrapped. One shellfirm process per
/// Enter. No history or DEBUG trap involved (`extdebug` only inside a
/// subshell that looks up where a large function was defined). Shells
/// without readline (or bash < 4) fall back to a DEBUG trap.
const BASH_HOOK: &str = r#"# shellfirm hook for bash
if [[ $- == *i* && -z ${__shellfirm_hook_loaded:-} ]]; then
__shellfirm_hook_loaded=1
__shellfirm_hook_version=13
# Lets `shellfirm doctor` tell whether the shell it runs in loaded the hook
# (SHELLFIRM_HOOK_LOAD changes at every load, also after `exec bash`).
builtin export SHELLFIRM_HOOK_PID=$$ SHELLFIRM_HOOK_LOAD=$$.$RANDOM$RANDOM
__shellfirm_pending=""
__shellfirm_pending_x=""
__shellfirm_cont=""
__shellfirm_warned=""
__shellfirm_bypass_warned=""
__shellfirm_seen=""
__shellfirm_histcmd=""
__shellfirm_expanded=""
__shellfirm_line=""
__shellfirm_fc_ok=""
__shellfirm_block_msg=""
__shellfirm_notes=""
__shellfirm_rows=0
__shellfirm_traps=""
# Longer lines cannot be passed as one argument (Linux MAX_ARG_STRLEN is
# 128 KiB); they are checked through stdin instead and never prompt.
__shellfirm_max_arg=100000

__shellfirm_warn_missing() {
    if [[ -z $__shellfirm_warned ]]; then
        __shellfirm_warned=1
        builtin printf '%s\n' "shellfirm: binary not found in PATH; commands are NOT being checked" >&2
    fi
}

# shellfirm is on PATH but did not start (exit 127: a missing interpreter or
# library). The command runs unchecked, so say so every time.
__shellfirm_warn_broken() {
    builtin printf '%s\n' "shellfirm: warning: $(builtin type -P shellfirm) is installed but could not run (exit $1); this command was NOT checked. Run \`shellfirm doctor\`." >&2
}

# Byte length of $1 in __sf_len.
__shellfirm_len() { local LC_ALL=C; __sf_len=${#1}; }

# shellfirm prints settings, policy and custom-check problems on every call.
# Look once per session (and again when SHELLFIRM_CONFIG_DIR changes), show
# them once, and from then on keep them away from safe lines (they would
# otherwise be mixed into the line editor).
__shellfirm_probe_notes() {
    [[ -n $__shellfirm_notes && $__shellfirm_notes_key == "${SHELLFIRM_CONFIG_DIR-}" ]] && return
    __shellfirm_notes_key=${SHELLFIRM_CONFIG_DIR-}
    local __sf_w
    __sf_w=$(builtin command shellfirm pre-command --test --command=: 2>&1 >/dev/null)
    # Not runnable: the check itself reports it.
    (( $? >= 126 )) && return
    [[ -n $__sf_w ]] && builtin printf '%s\n' "$__sf_w" >&2
    # A SHELLFIRM_CONFIG_DIR that is not a directory: said once (above);
    # the checks then use the default directory, as shellfirm itself does,
    # without saying it again on every line.
    if [[ -n $__sf_w ]] && __shellfirm_stale_dir; then
        __sf_w=$(SHELLFIRM_CONFIG_DIR= builtin command shellfirm pre-command --test --command=: 2>&1 >/dev/null)
    fi
    if [[ -n $__sf_w ]]; then
        __shellfirm_notes=1
    else
        __shellfirm_notes=0
    fi
}
__shellfirm_stale_dir() { [[ -n ${SHELLFIRM_CONFIG_DIR//[[:space:]]/} && ! -d ${SHELLFIRM_CONFIG_DIR} ]]; }

# bash erases the edited line before running a `bind -x` function: put it
# back on the screen (it stays above a challenge). __shellfirm_rows is the
# number of screen rows it takes, so a safe line can be erased again.
# $1 = 1: a continuation line (PS2).
__shellfirm_show_line() {
    __shellfirm_rows=0 __shellfirm_line_rows=0
    # A dumb terminal (Emacs M-x shell) cannot move the cursor: plain text
    # only, so the line is not reprinted (the banner names it).
    [[ -t 2 && ${TERM-} != dumb ]] || return
    local __sf_p __sf_l __sf_w __sf_n=0 __sf_cols=${COLUMNS:-80} __sf_i
    if [[ ${1:-} == 1 ]]; then
        __sf_p=$PS2
    else
        __sf_p=$PS1
    fi
    # Expanding a prompt with $(...) would run its commands again.
    if [[ $__sf_p == *'$('* || $__sf_p == *'`'* ]]; then
        __sf_p=""
    else
        __sf_p=${__sf_p@P}
    fi
    __sf_p=${__sf_p//[$'\001\002']/}
    __sf_p=${__sf_p##*$'\n'}
    local __sf_t=$__sf_p${READLINE_LINE//[$'\001'-$'\010\013'-$'\037\177']/?}
    # A line that ends in a newline (pasted with it): readline leaves the
    # cursor on the row of its last text, not on a row of its own.
    __sf_t=${__sf_t%$'\n'}
    builtin printf '%s\n' "$__sf_t" >&2
    # Screen width of what was printed (colours and other escapes take none).
    local __sf_re=$'\e(\\[[0-9;?]*[ -/]*[@-~]|\\][^\a\e]*(\a|\e\\\\)|.)'
    for (( __sf_i = 0; __sf_i < 64; __sf_i++ )); do
        [[ $__sf_t =~ $__sf_re ]] || break
        __sf_t=${__sf_t/"${BASH_REMATCH[0]}"/}
    done
    (( __sf_cols > 0 )) || __sf_cols=80
    while IFS= builtin read -r __sf_l; do
        __shellfirm_width "$__sf_l"
        (( __sf_n += __sf_w > 0 ? (__sf_w + __sf_cols - 1) / __sf_cols : 1 ))
    done <<< "$__sf_t"
    __shellfirm_rows=$__sf_n __shellfirm_line_rows=$__sf_n
}
__shellfirm_line_rows=0
# Screen columns of $1 in __sf_w: double-width (CJK, emoji) characters take
# two, combining marks and zero-width characters none.
__shellfirm_width() {
    __sf_w=${#1}
    [[ $1 == *[!\ -~]* ]] || return 0
    local __sf_c __sf_i __sf_o __sf_s=$1
    (( ${#__sf_s} > 4000 )) && return 0
    __sf_w=0
    for (( __sf_i = 0; __sf_i < ${#__sf_s}; __sf_i++ )); do
        __sf_c=${__sf_s:__sf_i:1}
        if [[ $__sf_c == [\ -~] ]]; then
            (( __sf_w++ ))
            continue
        fi
        builtin printf -v __sf_o '%d' "'$__sf_c" 2>/dev/null || __sf_o=0
        if (( (__sf_o >= 0x300 && __sf_o <= 0x36F) || (__sf_o >= 0x200B && __sf_o <= 0x200F) \
            || (__sf_o >= 0xFE00 && __sf_o <= 0xFE0F) || __sf_o == 0x2060 || __sf_o == 0xFEFF )); then
            continue
        elif (( (__sf_o >= 0x1100 && __sf_o <= 0x115F) || (__sf_o >= 0x2E80 && __sf_o <= 0x303E) \
            || (__sf_o >= 0x3041 && __sf_o <= 0x33FF) || (__sf_o >= 0x3400 && __sf_o <= 0x4DBF) \
            || (__sf_o >= 0x4E00 && __sf_o <= 0x9FFF) || (__sf_o >= 0xA000 && __sf_o <= 0xA4CF) \
            || (__sf_o >= 0xAC00 && __sf_o <= 0xD7A3) || (__sf_o >= 0xF900 && __sf_o <= 0xFAFF) \
            || (__sf_o >= 0xFE30 && __sf_o <= 0xFE4F) || (__sf_o >= 0xFF00 && __sf_o <= 0xFF60) \
            || (__sf_o >= 0xFFE0 && __sf_o <= 0xFFE6) || (__sf_o >= 0x1F300 && __sf_o <= 0x1F64F) \
            || (__sf_o >= 0x1F900 && __sf_o <= 0x1F9FF) || (__sf_o >= 0x20000 && __sf_o <= 0x3FFFD) )); then
            (( __sf_w += 2 ))
        else
            (( __sf_w++ ))
        fi
    done
}
# Printed by bash before each command it runs (PS0, bash 4.4+): after a
# passed challenge, bash redraws the prompt and the line below the approved
# line; the first PS0 of that line erases this copy. Later commands of the
# same line (a pasted block, `a` newline `b`) get nothing: the subscript
# counts the expansions, so their output is never erased.
__shellfirm_ps0=()
__shellfirm_ps0n=0
__shellfirm_sync_ps0() {
    __shellfirm_ps0=() __shellfirm_ps0n=0
    local __sf_p='${__shellfirm_ps0[__shellfirm_ps0n++]-}'
    # Older hooks (a re-sourced rc file) put `${__shellfirm_ps0}` there.
    [[ ${PS0-} == *'${__shellfirm_ps0}'* ]] && PS0=${PS0//'${__shellfirm_ps0}'/}
    if builtin shopt -q promptvars; then
        [[ ${PS0-} == *"$__sf_p"* ]] || PS0=$__sf_p${PS0-}
    elif [[ ${PS0-} == *"$__sf_p"* ]]; then
        PS0=${PS0//"$__sf_p"/}
    fi
}

# A safe line: erase the reprinted line again (readline redraws it in the
# same place). Only called when pre-command showed nothing: after a
# challenge it exits 3 (SHELLFIRM_SIGNAL_PROMPTED), and the line, the
# challenge and the approved line stay on screen.
__shellfirm_unshow() {
    (( __shellfirm_rows > 0 )) || return
    builtin printf '\e[%dA\r\e[J' "$__shellfirm_rows" >&2
    __shellfirm_rows=0
}

# Reads the input waiting on the terminal into __shellfirm_rest (Enter as a
# newline; control characters and bracketed-paste marks left out).
__shellfirm_rest=""
__shellfirm_drain() {
    local __sf_c __sf_i
    __shellfirm_rest=""
    for (( __sf_i = 0; __sf_i < 64; __sf_i++ )); do
        builtin read -t 0 2>/dev/null || break
        __sf_c=""
        IFS= builtin read -r -s -d '' -t 0.02 __sf_c 2>/dev/null
        [[ -z $__sf_c ]] && break
        __shellfirm_rest+=$__sf_c
        (( ${#__shellfirm_rest} > 65536 )) && break
    done
    __shellfirm_rest=${__shellfirm_rest//$'\e[200~'/}
    __shellfirm_rest=${__shellfirm_rest//$'\e[201~'/}
    __shellfirm_rest=${__shellfirm_rest//$'\r'/$'\n'}
    __shellfirm_rest=${__shellfirm_rest//[$'\001'-$'\010\013'-$'\037\177']/}
    while [[ $__shellfirm_rest == *$'\n' ]]; do
        __shellfirm_rest=${__shellfirm_rest%$'\n'}
    done
    [[ -n ${__shellfirm_rest//[[:space:]]/} ]] || __shellfirm_rest=""
}
# "1 line" / "N lines" (in __sf_rn), "was" / "were" (in __sf_rv) and "it" /
# "them" (in __sf_rp) for __shellfirm_rest.
__shellfirm_rest_count() {
    local __sf_l __sf_k=0
    while IFS= builtin read -r __sf_l; do
        [[ -n ${__sf_l//[[:space:]]/} ]] && (( __sf_k++ ))
    done <<< "$__shellfirm_rest"
    (( __sf_k )) || __sf_k=1
    if (( __sf_k == 1 )); then
        __sf_rn="1 line" __sf_rv=was __sf_rp=it
    else
        __sf_rn="$__sf_k lines" __sf_rv=were __sf_rp=them
    fi
}

# Returns 0 to allow, 1 to block. A missing binary fails open; anything else
# that goes wrong (exit 126, a line too long to pass) fails closed.
# $2 = 1: called from the line editor (one shellfirm process per line: the
# line is reprinted first and erased again when nothing was shown);
# $3 = 1: the line is a continuation line.
__shellfirm_check() {
    if [[ -n ${BASH_CMDS[shellfirm]:-} && ! -x ${BASH_CMDS[shellfirm]} ]]; then
        builtin hash -d shellfirm 2>/dev/null
    fi
    if ! builtin type -P shellfirm >/dev/null 2>&1; then
        __shellfirm_warn_missing
        return 0
    fi
    local __sf_len __sf_rc __sf_out __sf_shown=""
    # Without interactive_comments `#` starts no comment: `rm -rf a # b`
    # removes b too.
    builtin shopt -q interactive_comments || local -x SHELLFIRM_NO_COMMENTS=1
    __shellfirm_rows=0
    __shellfirm_len "$1"
    (( __sf_len > __shellfirm_max_arg )) && __shellfirm_line=""
    if (( __sf_len > __shellfirm_max_arg )); then
        builtin printf '%s' "$1" | builtin command shellfirm check --stdin --exit-code >/dev/null 2>&1
        __sf_rc=$?
        (( __sf_rc == 0 )) && return 0
        if (( __sf_rc == 127 )); then
            __shellfirm_warn_broken 127
            return 0
        fi
        if (( __sf_rc == 10 || __sf_rc == 11 )); then
            builtin printf '\n%s\n' "shellfirm: blocked: this line is too long to confirm interactively ($__sf_len bytes) and it matches a risky pattern. Run it from a script file instead." >&2
        else
            builtin printf '\n%s\n' "shellfirm: blocked: this line ($__sf_len bytes) could not be checked (exit $__sf_rc). Run it from a script file instead." >&2
        fi
        return 1
    fi
    if [[ ${2:-} == 1 ]]; then
        __shellfirm_probe_notes
        # The stale SHELLFIRM_CONFIG_DIR was reported: not again (see above).
        if [[ -n $__shellfirm_notes && $__shellfirm_notes_key == "${SHELLFIRM_CONFIG_DIR-}" ]] && __shellfirm_stale_dir; then
            local -x SHELLFIRM_CONFIG_DIR=
        fi
        if [[ $__shellfirm_notes == 1 ]]; then
            # Dry run first, so warnings and the line only show for risky lines.
            __sf_out=$(builtin command shellfirm pre-command --test --command="$1" 2>/dev/null)
            __sf_rc=$?
            case $__sf_rc in
                0) [[ $__sf_out == *"skipped (below"* ]] || return 0 ;;
                65|77) __shellfirm_show_line "${3:-}"; __shellfirm_rows=0 ;;
            esac
        else
            __shellfirm_show_line "${3:-}"
            __sf_shown=1
        fi
        # Input typed or pasted after this line (not as one bracketed
        # paste) that bash has not read yet: a challenge discards it (it
        # could answer the challenge). Unless the line is plainly safe, it is
        # read first, so it can be named, and kept when the line is not run.
        if builtin read -t 0 2>/dev/null; then
            if [[ $__shellfirm_notes != 1 ]]; then
                builtin command shellfirm pre-command --test --command="$1" >/dev/null 2>&1
                __sf_rc=$?
            fi
            # 65: a challenge, 77: denied.
            (( __sf_rc == 65 || __sf_rc == 77 )) && __shellfirm_drain
        fi
    fi
    # The banner and the audit log show the line as typed, not the function
    # bodies checked with it.
    local -a __sf_la=()
    [[ -n $__shellfirm_line && $__shellfirm_line != "$1" ]] && __sf_la=(--line="$__shellfirm_line")
    __shellfirm_line=""
    SHELLFIRM_SIGNAL_PROMPTED=1 builtin command shellfirm pre-command --command="$1" "${__sf_la[@]}"
    __sf_rc=$?
    # The line runs: what was read ahead of it does not.
    if [[ -n $__shellfirm_rest ]] && (( __sf_rc == 0 || __sf_rc == 3 || __sf_rc == 127 )); then
        local __sf_rn __sf_rv __sf_rp
        __shellfirm_rest_count
        builtin printf '%s\n' "shellfirm: $__sf_rn typed or pasted after this command $__sf_rv not run (a challenge discards waiting input); run $__sf_rp again." >&2
        __shellfirm_rest=""
        __sf_shown=""
    fi
    case $__sf_rc in
        0) [[ -n $__sf_shown ]] && __shellfirm_unshow; return 0 ;;
        3)
            __shellfirm_rows=0
            [[ ${2:-} == 1 ]] && (( __shellfirm_line_rows > 0 )) && __shellfirm_ps0=($'\e['"$__shellfirm_line_rows"$'A\r\e[J') __shellfirm_ps0n=0
            return 0 ;;
        127) [[ -n $__sf_shown ]] && __shellfirm_unshow; __shellfirm_warn_broken 127; return 0 ;;
        126) builtin printf '%s\n' "shellfirm: could not run shellfirm (exit 126); command not run" >&2; return 1 ;;
        *) return 1 ;;
    esac
}

# A body (`declare -f` text without its header) as one line, which is how
# the check reads a definition. A here-document cannot be joined: that body
# stays as it is (its commands are then read as written, `$1` unknown).
# Sets __sf_ol.
__shellfirm_one_line() {
    local __sf_l __sf_o=""
    __sf_ol=$1
    [[ ${1//<<</} == *'<<'* ]] && return
    while IFS= builtin read -r __sf_l; do
        __sf_l=${__sf_l#"${__sf_l%%[![:space:]]*}"}
        __sf_l=${__sf_l%"${__sf_l##*[![:space:]]}"}
        [[ -z $__sf_l ]] && continue
        case $__sf_o in
            ''|*'{'|*'('|*';'|*'|'|*'&'|then|*[[:space:]]then|do|*[[:space:]]do|else|*[[:space:]]else|*[[:space:]]in) __sf_o+=" $__sf_l" ;;
            *) __sf_o+="; $__sf_l" ;;
        esac
    done <<< "$1"
    __sf_ol=${__sf_o# }
}

# What separates the words that can name a function: blanks, control
# characters and ASCII punctuation other than `_ : . @ + -`. Any other
# character (`nettoyé`, `日本`) can be part of a function name.
__shellfirm_nonname='[]!#"$%&'\''()*,/;<=>?[\\^`{|}~[:space:][:cntrl:]]'
# The same as an extended regular expression for one function name.
__shellfirm_namere='[^][:space:][:cntrl:]!#"$%&'\''()*,/;<=>?\^`{|}~0-9-][^][:space:][:cntrl:]!#"$%&'\''()*,/;<=>?\^`{|}~]*'

# The functions named in $1 (and those their bodies name, and so on), each
# once, are sent ahead of the line as definitions (`name() { body; }`): the
# check binds every call's arguments itself (`shift`, `"$@"`, any depth),
# so what it reads is what runs. A body that rewrites its arguments in a way
# the check does not follow (`set --`, `getopts`, `shift` in a loop) is
# also added as written, where its `$1` counts as unknown. Past the budget
# (64 functions, 64 KB, 16 KB for one body) the rest is not read: a marker
# says so (shell:function_depth_limit), so nothing is skipped silently. A
# function over 16 KB that was loaded from a file (nvm, sdkman, conda) is
# treated like a program on PATH: its arguments are checked, its body is not
# read (and gets no marker); one typed or pasted into the session gets it.
# Appends to the caller's __sf_defs, __sf_fx, __sf_fnames / __sf_fbodies
# and __sf_fseen (names already looked at).
__shellfirm_fn_defs() {
    local IFS=$' \t\n' __sf_todo=$1 __sf_w __sf_all __sf_b __sf_hdr __sf_ol __sf_i __sf_n __sf_src
    local -a __sf_ws __sf_new
    while [[ -n $__sf_todo ]]; do
        __sf_ws=(${__sf_todo//$__shellfirm_nonname/ })
        __sf_todo="" __sf_new=()
        for __sf_w in "${__sf_ws[@]}"; do
            [[ $__sf_w == __shellfirm_* || $__sf_w == [0-9.+-]* || " $__sf_fseen " == *" $__sf_w "* ]] && continue
            builtin declare -F -- "$__sf_w" >/dev/null 2>&1 || continue
            __sf_fseen+=" $__sf_w"
            __sf_new+=("$__sf_w")
        done
        __sf_n=${#__sf_new[@]}
        (( __sf_n )) || return 0
        __sf_all=$'\n'$(builtin declare -f -- "${__sf_new[@]}" 2>/dev/null)
        for (( __sf_i = 0; __sf_i < __sf_n; __sf_i++ )); do
            __sf_w=${__sf_new[__sf_i]}
            __sf_hdr=$'\n'"$__sf_w () "$'\n'
            [[ $__sf_all == *"$__sf_hdr"* ]] || continue
            __sf_all=${__sf_all#*"$__sf_hdr"}
            if (( __sf_i + 1 < __sf_n )); then
                __sf_b=${__sf_all%%$'\n'"${__sf_new[__sf_i+1]} () "$'\n'*}
            else
                __sf_b=$__sf_all
            fi
            # shellfirm's own functions (and those that wrap a plugin).
            [[ $__sf_b == *__shellfirm_* ]] && continue
            if (( ${#__sf_b} > 16000 )); then
                __sf_src=$(builtin shopt -s extdebug; builtin declare -F -- "$__sf_w" 2>/dev/null)
                __sf_src=${__sf_src#"$__sf_w "} __sf_src=${__sf_src#* }
                __shellfirm_from_file "$__sf_w" "$__sf_src" || __sf_fx+=$'\n'"shellfirm-function-depth-limit $__sf_w # a function too large for the hook to read ahead"
                continue
            fi
            if (( ${#__sf_fnames[@]} >= 64 || __sf_fbytes + ${#__sf_b} > 64000 )); then
                __sf_fx+=$'\n'"shellfirm-function-depth-limit $__sf_w # calls more functions than the hook reads ahead"
                return 0
            fi
            (( __sf_fbytes += ${#__sf_b} ))
            __sf_fnames+=("$__sf_w") __sf_fbodies+=("$__sf_b")
            # `$K delete ...` in the body, with K set in this session.
            if [[ $__sf_b =~ (^|[\;\&\|\({]|$'\n')[[:space:]]*\$\{?[A-Za-z_] ]]; then
                local __sf_ax __sf_nd __sf_defnames="" __sf_segmark=""
                local -a __sf_fcseg __sf_calls=()
                __shellfirm_segments "$__sf_b"
            fi
            __shellfirm_one_line "$__sf_b"
            __sf_defs+=$'\n'"$__sf_w() $__sf_ol"
            if [[ $__sf_b =~ (^|[[:space:]\;\&\|\({])(set[[:space:]]+(--|[^-+[:space:]])|getopts[[:space:]]|OPTIND) ]] \
                || [[ $__sf_b == *shift* && $__sf_b =~ (^|[[:space:]\;\&\|\({])(while|until|for|select)[[:space:]] ]]; then
                __sf_fx+=$'\n'$__sf_b
            fi
            __sf_todo+=" $__sf_b"
        done
    done
}

# Returns 0 when the function $1 (bash names its source $2) was loaded from
# a file: an absolute path to a regular file, a relative one that named a
# regular file when it was sourced (see __shellfirm_note_relsrc), or
# `source <(cat FILE)` (see __shellfirm_note_catsrc). A function typed or
# pasted at the prompt has the source `main` (and so has one from `eval
# "$(cat FILE)"`), whatever files the current directory holds; process
# substitution is /dev/fd/N.
__shellfirm_from_file() {
    case $2 in
        /dev/fd/*|/proc/*)
            [[ -n $__shellfirm_catfns && " $__shellfirm_catfns " == *" $1:"* ]] || return 1
            local __sf_k
            __sf_k=$(builtin declare -f -- "$1" 2>/dev/null | builtin command cksum 2>/dev/null)
            [[ " $__shellfirm_catfns " == *" $1:${__sf_k%% *} "* ]] ;;
        /*) [[ -f $2 ]] ;;
        main|environment|'') return 1 ;;
        *) [[ " $__shellfirm_relfns " == *" $1|$2 "* ]] ;;
    esac
}
# After a line that sources a file (and at the first prompt, after the rc
# files): the functions whose source is a relative path (`source ./nvm.sh`,
# `. nvm.sh`) that names a regular file from the current directory (or the
# one the line left, `cd d; . ./f; cd -`) are remembered as loaded from that
# file (bash keeps the path as written, which no longer resolves after a
# `cd`).
__shellfirm_relsrc=""
__shellfirm_relfns=""
__shellfirm_note_relsrc() {
    local __sf_l __sf_n __sf_s __sf_all
    __shellfirm_relsrc=""
    __sf_all=$(builtin shopt -s extdebug; builtin declare -F $(builtin compgen -A function) 2>/dev/null)
    while IFS= builtin read -r __sf_l; do
        __sf_n=${__sf_l%% *} __sf_s=${__sf_l#* } __sf_s=${__sf_s#* }
        case $__sf_s in main|environment|''|/*) continue ;; esac
        [[ $__sf_n == __shellfirm_* || " $__shellfirm_relfns " == *" $__sf_n|$__sf_s "* ]] && continue
        [[ -f $__sf_s || ( -n ${OLDPWD-} && -f $OLDPWD/$__sf_s ) ]] || continue
        (( ${#__shellfirm_relfns} < 64000 )) && __shellfirm_relfns+=" $__sf_n|$__sf_s"
    done <<< "$__sf_all"
}
# After a line that was exactly `source <(cat FILE)` (or `.`), FILE a
# regular file: the large functions it defined (source /dev/fd/N) count as
# loaded from FILE. Each is remembered with a checksum of its definition,
# so the same name defined again from another process substitution is not.
__shellfirm_catsrc=""
__shellfirm_catfns=""
__shellfirm_note_catsrc() {
    local __sf_f=$__shellfirm_catsrc __sf_l __sf_n __sf_s __sf_k __sf_all
    __shellfirm_catsrc=""
    [[ -f $__sf_f ]] || return
    __sf_all=$(builtin shopt -s extdebug; builtin declare -F $(builtin compgen -A function) 2>/dev/null)
    while IFS= builtin read -r __sf_l; do
        __sf_n=${__sf_l%% *} __sf_s=${__sf_l#* } __sf_s=${__sf_s#* }
        [[ $__sf_s == /dev/fd/* || $__sf_s == /proc/* ]] || continue
        [[ $__sf_n == __shellfirm_* ]] && continue
        __sf_k=$(builtin declare -f -- "$__sf_n" 2>/dev/null | builtin command cksum 2>/dev/null)
        (( ${#__shellfirm_catfns} < 64000 )) && __shellfirm_catfns+=" $__sf_n:${__sf_k%% *}"
    done <<< "$__sf_all"
}

# `fc` / `eval` in the body of a function the line calls (`rr() { command
# fc -s "$@"; }`) are resolved like typed ones, with the call's arguments in
# place. Appends to the caller's __sf_bfcseg / __sf_bnd.
__shellfirm_body_fc() {
    local __sf_k __sf_j __sf_i __sf_b __sf_args
    local -a __sf_av
    for (( __sf_k = 0; __sf_k < ${#__sf_calls[@]}; __sf_k += 2 )); do
        __sf_b="" __sf_args=${__sf_calls[__sf_k+1]}
        for (( __sf_j = 0; __sf_j < ${#__sf_fnames[@]}; __sf_j++ )); do
            [[ ${__sf_fnames[__sf_j]} == "${__sf_calls[__sf_k]}" ]] && { __sf_b=${__sf_fbodies[__sf_j]}; break; }
        done
        [[ $__sf_b == *fc* || $__sf_b == *eval* ]] || continue
        builtin read -r -a __sf_av <<< "$__sf_args"
        for __sf_i in '"$@"' '"${@}"' '"$*"' '"${*}"' '$@' '${@}' '$*' '${*}'; do
            __sf_b=${__sf_b//"$__sf_i"/$__sf_args}
        done
        for __sf_i in 9 8 7 6 5 4 3 2 1; do
            __sf_b=${__sf_b//"\"\${$__sf_i}\""/${__sf_av[__sf_i-1]}}
            __sf_b=${__sf_b//"\"\$$__sf_i\""/${__sf_av[__sf_i-1]}}
            __sf_b=${__sf_b//"\${$__sf_i}"/${__sf_av[__sf_i-1]}}
            __sf_b=${__sf_b//"\$$__sf_i"/${__sf_av[__sf_i-1]}}
        done
        local __sf_ax __sf_nd __sf_defnames="" __sf_segmark=""
        local -a __sf_fcseg __sf_calls=()
        __shellfirm_segments "$__sf_b"
        __sf_bfcseg+=("${__sf_fcseg[@]}")
        [[ $__sf_nd == *fc* ]] && __sf_bnd+=$'\n'$__sf_nd
    done
}

# Functions that run by themselves (PROMPT_COMMAND, traps, `bind -x` keys,
# PS0..PS4, bash-preexec's arrays) and the functions they name, however
# deep: a line that (re)defines one of them is checked as if it called it.
# Sets the caller's __sf_reach (names).
__shellfirm_hook_reach() {
    local __sf_roots="${PROMPT_COMMAND[*]} ${precmd_functions[*]} ${preexec_functions[*]} ${PS0-} ${PS1-} ${PS2-} ${PS4-}"
    __sf_roots+=" $(builtin trap -p 2>/dev/null) ${__shellfirm_traps-} $(builtin bind -X 2>/dev/null)"
    local __sf_fseen="" __sf_defs="" __sf_fx="" __sf_fbytes=0
    local -a __sf_fnames=() __sf_fbodies=()
    __shellfirm_fn_defs "$__sf_roots"
    __sf_reach=$__sf_fseen
}

# Splits $1 into the caller's __sf_lead (blanks), __sf_w (first word, quotes
# kept: `x='a b'` is one word) and __sf_after (the rest).
__shellfirm_word() {
    local __sf_wre="^([[:space:]]*)(([^[:space:]'\"\\\\]|\\\\.|'[^']*'|\"([^\"\\\\]|\\\\.)*\")*)"
    [[ $1 =~ $__sf_wre ]]
    __sf_lead=${BASH_REMATCH[1]} __sf_w=${BASH_REMATCH[2]}
    __sf_after=${1:${#BASH_REMATCH[0]}}
    # An unterminated quote: the rest of the text is that word.
    if [[ -z $__sf_w && -n $__sf_after && $__sf_after != [[:space:]]* ]]; then
        __sf_w=$__sf_after __sf_after=""
    fi
}

# The words of $1 with quotes and backslashes removed, in __sf_tw. Returns 1
# when they are not certain: an expansion (`$`, a backtick) or an open quote.
__shellfirm_words() {
    __sf_tw=()
    local __sf_s=$1 __sf_c __sf_q="" __sf_t="" __sf_have="" __sf_i __sf_n=${#1}
    (( __sf_n <= 4000 )) || return 1
    for (( __sf_i = 0; __sf_i < __sf_n; __sf_i++ )); do
        __sf_c=${__sf_s:__sf_i:1}
        if [[ $__sf_q == "'" ]]; then
            if [[ $__sf_c == "'" ]]; then __sf_q=""; else __sf_t+=$__sf_c; fi
            continue
        fi
        if [[ $__sf_q == '"' ]]; then
            case $__sf_c in
                '"') __sf_q="" ;;
                '\')
                    __sf_c=${__sf_s:__sf_i+1:1}
                    case $__sf_c in
                        '$'|'`'|'"'|'\') __sf_t+=$__sf_c; (( __sf_i++ )) ;;
                        $'\n') (( __sf_i++ )) ;;
                        *) __sf_t+='\' ;;
                    esac ;;
                '$'|'`') return 1 ;;
                *) __sf_t+=$__sf_c ;;
            esac
            continue
        fi
        case $__sf_c in
            [[:space:]])
                [[ -n $__sf_have ]] && __sf_tw+=("$__sf_t")
                __sf_t="" __sf_have="" ;;
            "'"|'"') __sf_q=$__sf_c __sf_have=1 ;;
            '\')
                (( __sf_i++ ))
                __sf_c=${__sf_s:__sf_i:1}
                [[ $__sf_c == $'\n' ]] || { __sf_t+=$__sf_c; __sf_have=1; } ;;
            '$'|'`') return 1 ;;
            *) __sf_t+=$__sf_c __sf_have=1 ;;
        esac
    done
    [[ -z $__sf_q ]] || return 1
    [[ -n $__sf_have ]] && __sf_tw+=("$__sf_t")
    return 0
}

# `fc` arguments (in "$@", quotes removed): re-run (`-s`, `-e -`) or edit.
# Sets the caller's __sf_rerun, __sf_list, __sf_edit_kw, __sf_old (the
# commands a re-run runs, after old=new).
__shellfirm_fc_parse() {
    local __sf_a __sf_next="" __sf_pat="" __sf_rep="" __sf_sel=-1 __sf_set=""
    __sf_rerun="" __sf_list="" __sf_old=""
    for __sf_a in "$@"; do
        if [[ -n $__sf_next ]]; then
            __sf_next=""
            [[ $__sf_a == - ]] && __sf_rerun=1
            continue
        fi
        case $__sf_a in
            -e) __sf_next=1 ;;
            -[0-9]*) __sf_sel=$__sf_a ;;
            -*l*) __sf_list=1 ;;
            -*s*) __sf_rerun=1 ;;
            -*) ;;
            *=*)
                if [[ -z $__sf_set ]]; then
                    __sf_set=1; __sf_pat=${__sf_a%%=*}; __sf_rep=${__sf_a#*=}
                else
                    __sf_sel=$__sf_a
                fi ;;
            *) __sf_sel=$__sf_a ;;
        esac
    done
    [[ -n $__sf_list || -z $__sf_rerun ]] && return
    # In a subshell fc skips the newest entry (taken to be the fc command
    # itself); push a dummy entry so it skips that instead.
    __sf_old=$(builtin enable fc 2>/dev/null; builtin history -s :; builtin fc -ln "$__sf_sel" "$__sf_sel" 2>/dev/null)
    __sf_old=${__sf_old#"${__sf_old%%[![:space:]]*}"}
    [[ -n $__sf_old && -n $__sf_pat ]] && __sf_old=${__sf_old//"$__sf_pat"/$__sf_rep}
}

# One command (with `fc` or `eval` in it), word by word after removing
# quotes: `command fc -s 'a=b' x`, `builtin fc -s a\=b x`, and the text
# `eval` runs (expanded and checked like a typed line). Appends to the
# caller's __sf_fx; sets __shellfirm_block_msg for an unsafe `fc`.
__shellfirm_fc_eval() {
    local __sf_seg=$1 __sf_i=0 __sf_kw="" __sf_w __sf_rerun __sf_list __sf_old
    local -a __sf_tw
    # $2 = 1: a command in the body of a function the line calls.
    if ! __shellfirm_words "$__sf_seg"; then
        # Not certain what `command fc` / `builtin fc` would re-run or edit
        # (they skip the checked `fc`): refuse.
        if [[ $__sf_seg =~ (command|builtin)[[:space:]\'\"\\]+[\'\"\\]?f[\'\"\\]?c([[:space:]\'\"]|$) ]]; then
            __shellfirm_block_msg="shellfirm: cannot tell what this \`${BASH_REMATCH[1]} fc\` runs (quotes or expansions in its arguments): it skips the check. Use \`fc\` instead. Command not run."
        fi
        return
    fi
    while (( __sf_i < ${#__sf_tw[@]} )); do
        __sf_w=${__sf_tw[__sf_i]}
        case $__sf_w in
            time|-p|'!'|then|do|else|elif|if|while|until|coproc|[A-Za-z_]*=*) ;;
            [0-9]*[\<\>]*|[\<\>]*|'&>'*)
                # A redirection; a bare operator takes the next word.
                [[ $__sf_w =~ ^[0-9]*(\<|\>|\>\>|\<\<\<|\<\<|\>\||\<\>|\&\>|\&\>\>|\>\&|\<\&)$ ]] && (( __sf_i++ )) ;;
            command|builtin)
                [[ -n $__sf_kw ]] && break
                __sf_kw=$__sf_w ;;
            -*) [[ $__sf_kw == command ]] || break ;;
            *) break ;;
        esac
        (( __sf_i++ ))
    done
    __sf_w=${__sf_tw[__sf_i]:-}
    if [[ $__sf_w == fc ]]; then
        # A typed `command fc` / `builtin fc` read for certain: it may use
        # the builtin while this line runs.
        [[ -n $__sf_kw && -z ${2:-} ]] && __shellfirm_fc_typed=1
        __shellfirm_fc_parse "${__sf_tw[@]:__sf_i+1}"
        [[ -n $__sf_list ]] && return
        if [[ -z $__sf_rerun ]]; then
            [[ -n $__sf_kw ]] && __shellfirm_block_msg="shellfirm: \`$__sf_kw fc\` runs the edited commands without a check; use \`fc\` instead. Command not run."
            return
        fi
        if [[ -n $__sf_old && $'\n'$__shellfirm_fc_ok$'\n' != *$'\n'"$__sf_old"$'\n'* ]]; then
            __shellfirm_fc_ok+=$'\n'$__sf_old
            # The whole line is the re-run: check (and show) just that.
            if [[ ${__sf_cmd//[[:space:]]/} == "${__sf_seg//[[:space:]]/}" ]]; then
                __sf_cmd=$__sf_old
            else
                __sf_fx+=$'\n'$__sf_old
            fi
        fi
    elif [[ $__sf_w == eval && -z $__sf_kw ]] && (( ${#__sf_tw[@]} > __sf_i + 1 && __shellfirm_eval_depth < 3 )); then
        local __sf_saved=$__shellfirm_expanded
        (( __shellfirm_eval_depth++ ))
        __shellfirm_expand "${__sf_tw[*]:__sf_i+1}"
        (( __shellfirm_eval_depth-- ))
        [[ -n $__shellfirm_expanded ]] && __sf_fx+=$'\n'$__shellfirm_expanded
        __shellfirm_expanded=$__sf_saved
    fi
}
__shellfirm_eval_depth=0

# One command of a line (no control operators in it): expand the alias at
# its command position (after reserved words such as `time` / `!` and
# variable assignments) and collect the body of a small function it calls.
# Sets __sf_sx; appends to the caller's __sf_fx.
# The value of alias $1 in the caller's __sf_v; 1 when $1 is not an alias.
# bash 3.2 (macOS /bin/bash) has no BASH_ALIASES: the names are the ones
# __shellfirm_segments read (__sf_alnames) and the value comes from
# `alias NAME`, which prints it quoted for reuse as shell input.
__shellfirm_alias() {
    [[ -n $1 ]] || return 1
    if (( BASH_VERSINFO[0] >= 4 )); then
        [[ -n ${BASH_ALIASES[$1]+set} ]] || return 1
        __sf_v=${BASH_ALIASES[$1]}
        return 0
    fi
    [[ ${__sf_alnames-} == *" $1 "* ]] || return 1
    local __sf_d
    __sf_d=$(builtin alias -- "$1" 2>/dev/null) || return 1
    builtin eval "__sf_v=${__sf_d#*=}"
}
__shellfirm_segment() {
    local __sf_s=$1 __sf_pre="" __sf_w __sf_v __sf_i __sf_lead __sf_after="" __sf_trail="" __sf_tail=""
    __sf_sx=$1
    for (( __sf_i = 0; __sf_i <= 64; __sf_i++ )); do
        if (( __sf_i == 64 )); then
            # More leading words (`A=1 B=2 ... cmd`) than are read ahead.
            __sf_segmark=1
            break
        fi
        __shellfirm_word "$__sf_s"
        case $__sf_w in
            '') return ;;
            time|-p|'!'|then|do|else|elif|if|while|until|coproc|eval|[A-Za-z_]*=*)
                __sf_pre+=$__sf_lead$__sf_w
                __sf_s=$__sf_after ;;
            [0-9]*[\<\>]*|[\<\>]*|'&>'*)
                # A leading redirection (`>/dev/null kd ...`); a bare
                # operator takes the next word with it.
                __sf_pre+=$__sf_lead$__sf_w
                __sf_s=$__sf_after
                if [[ $__sf_w =~ ^[0-9]*(\<|\>|\>\>|\<\<\<|\<\<|\>\||\<\>|\&\>|\&\>\>|\>\&|\<\&)$ ]]; then
                    __shellfirm_word "$__sf_s"
                    __sf_pre+=$__sf_lead$__sf_w
                    __sf_s=$__sf_after
                fi ;;
            *) break ;;
        esac
    done
    if [[ -n ${2:-} ]]; then
        for (( __sf_i = 0; __sf_i < 5; __sf_i++ )); do
            __shellfirm_word "$__sf_s"
            __shellfirm_alias "$__sf_w" || break
            __sf_trail=$__sf_v __sf_tail=$__sf_after
            __sf_s=$__sf_lead$__sf_v$__sf_after
            # `alias ls='ls -l'`: bash does not expand an alias inside itself.
            __sf_v=${__sf_v#"${__sf_v%%[![:space:]]*}"}
            [[ ${__sf_v%%[[:space:]]*} == "$__sf_w" ]] && break
        done
        # An alias ending in a space also expands the next word (`sudo `).
        if [[ $__sf_trail == *[[:space:]] ]]; then
            __shellfirm_word "$__sf_tail"
            if __shellfirm_alias "$__sf_w"; then
                __sf_s=${__sf_s%"$__sf_tail"}$__sf_v$__sf_after
            fi
        fi
    fi
    __shellfirm_word "$__sf_s"
    # A command named by a variable set on an earlier line (`$K delete ...`,
    # `${K}`, `$f` naming a function): its value in this session. (One set
    # on the same line is read by the check itself.)
    if (( ! __sf_indef && ${__sf_vdepth:-0} < 2 )) && [[ $__sf_w =~ ^\$([A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\})$ ]]; then
        local __sf_vn=${BASH_REMATCH[1]#\{}
        __sf_vn=${__sf_vn%\}}
        if [[ $__sf_vn != __sf_* && -n ${!__sf_vn:+set} ]]; then
            local __sf_vv=${!__sf_vn} __sf_sxs=$__sf_sx __sf_vdepth=$(( ${__sf_vdepth:-0} + 1 ))
            if (( ${#__sf_vv} <= 4000 )) && [[ $__sf_vv != *__shellfirm_* ]]; then
                __shellfirm_segment "$__sf_vv$__sf_after" "${2:-}"
                __sf_fx+=$'\n'$__sf_sx
                __sf_sx=$__sf_sxs
                __shellfirm_word "$__sf_s"
            fi
        fi
    fi
    # A call of a function: its definition is sent with the line (see
    # __shellfirm_fn_defs); the arguments are kept for `fc` in its body.
    if (( ! __sf_indef && ${#__sf_calls[@]} < 16 )) && [[ -n $__sf_w && $__sf_w != __shellfirm_* ]] && builtin declare -F -- "$__sf_w" >/dev/null 2>&1; then
        [[ $__sf_after =~ ^[[:space:]]*(.*)$ ]]
        __sf_calls+=("$__sf_w" "${BASH_REMATCH[1]}")
        # After assignments / redirections (`A=1 f x`): the bare call too,
        # which the check binds to the definition.
        [[ -n $__sf_pre ]] && __sf_fx+=$'\n'"$__sf_w ${BASH_REMATCH[1]}"
    fi
    __sf_sx=$__sf_pre$__sf_s
}

# Expand every command of the line (after ; & | && || ( { and newlines).
# Sets __sf_ax; appends to the caller's __sf_calls (function calls),
# __sf_defnames (functions the line defines) and __sf_segmark (aliases past
# the read-ahead limit). $2 = 1: a huge line, only the first commands are
# expanded.
__shellfirm_segments() {
    local __sf_in=$1 __sf_seg __sf_op __sf_n=0 __sf_cap=512 __sf_al="" __sf_sx __sf_b
    local -i __sf_indef=0 __sf_defnext=0
    [[ ${2:-} == 1 ]] && __sf_cap=16
    local __sf_alnames=""
    if (( BASH_VERSINFO[0] >= 4 )); then
        builtin shopt -q expand_aliases && (( ${#BASH_ALIASES[@]} )) && __sf_al=1
    elif builtin shopt -q expand_aliases; then
        # bash 3.2: no BASH_ALIASES (see __shellfirm_alias).
        __sf_alnames=$(builtin compgen -a 2>/dev/null)
        [[ -n $__sf_alnames ]] && __sf_al=1
        __sf_alnames=" ${__sf_alnames//$'\n'/ } "
    fi
    __sf_ax=""
    # __sf_nd: the line without the bodies of the functions it defines.
    __sf_nd=""
    __sf_fcseg=()
    local __sf_re='^([^;&|(){}`'$'\n'']*)([;&|(){}`'$'\n'']*)'
    local __sf_defre='^[[:space:]]*(function[[:space:]]+[^[:space:]]+|'$__shellfirm_namere')[[:space:]]*$'
    while [[ -n $__sf_in ]]; do
        if (( ++__sf_n > __sf_cap )); then
            __sf_ax+=$__sf_in
            # Aliases further on are not expanded: say so (functions are
            # found anywhere on the line).
            [[ -n $__sf_al ]] && __sf_segmark=1
            break
        fi
        [[ $__sf_in =~ $__sf_re ]]
        __sf_seg=${BASH_REMATCH[1]} __sf_op=${BASH_REMATCH[2]}
        __sf_in=${__sf_in:${#BASH_REMATCH[0]}}
        __shellfirm_segment "$__sf_seg" "$__sf_al"
        __sf_ax+=$__sf_sx$__sf_op
        # A definition runs nothing: its `fc` / `eval` are looked at when
        # the function is called.
        if (( ! __sf_indef && ! __sf_defnext )); then
            __sf_nd+=$__sf_sx
            [[ $__sf_sx == *fc* || $__sf_sx == *eval* ]] && __sf_fcseg+=("$__sf_sx")
        fi
        __sf_nd+=$__sf_op
        # `name() {` / `function name {`: the body is a definition.
        if (( ! __sf_indef && ! __sf_defnext )) && [[ $__sf_seg =~ $__sf_defre ]] \
            && [[ $__sf_op == '('* || ( $__sf_seg == *function* && $__sf_op == '{'* ) || ( $__sf_seg == *function* && -z $__sf_op ) ]]; then
            __sf_defnext=1
            __sf_b=${BASH_REMATCH[1]#function}
            __sf_defnames+=" ${__sf_b//[[:space:]]/}"
        fi
        if (( __sf_defnext || __sf_indef )); then
            __sf_b=${__sf_op//[!\{]/}
            (( __sf_indef += ${#__sf_b} ))
            (( ${#__sf_b} )) && __sf_defnext=0
            __sf_b=${__sf_op//[!\}]/}
            (( __sf_indef -= ${#__sf_b} ))
            (( __sf_indef < 0 )) && __sf_indef=0
        fi
    done
}

# `fc -s [old=new] [cmd]` / `fc -e - ...` re-run a history entry: resolve
# what will run, wherever it appears on the line and however it is spelled
# (`command fc`, `builtin fc`, `\fc`, `eval fc ...`). `command fc` and
# `builtin fc` with an editor skip the checked `fc` wrapper: refused.
# Edits the caller's __sf_cmd / __sf_fx.
__shellfirm_resolve_fc() {
    local __sf_s=$1 __sf_i __sf_kw __sf_args __sf_whole __sf_old __sf_rerun __sf_list
    local -a __sf_fa
    local __sf_re='(^|[[:space:];&|(){}`"\])((command|builtin)[[:space:]]+|\\)?fc(([[:space:]][^;&|()`'$'\n'']*)?)([;&|()`'$'\n'']|$)'
    local __sf_one='^[[:space:]]*((command|builtin)[[:space:]]+|\\)?fc([[:space:]][^;&|()`'$'\n'']*)?$'
    for (( __sf_i = 0; __sf_i < 8; __sf_i++ )); do
        [[ $__sf_s =~ $__sf_re ]] || break
        __sf_kw=${BASH_REMATCH[3]} __sf_args=${BASH_REMATCH[4]}
        __sf_s=${__sf_s#*"${BASH_REMATCH[0]}"}
        # Quoted or escaped arguments are resolved word by word (__shellfirm_fc_eval).
        [[ $__sf_args == *[\'\"\\]* ]] && continue
        __sf_whole=""
        [[ $__sf_i == 0 && -z ${2:-} && $1 =~ $__sf_one ]] && __sf_whole=1
        __sf_fa=()
        builtin read -r -a __sf_fa <<< "$__sf_args"
        __shellfirm_fc_parse "${__sf_fa[@]}"
        [[ -n $__sf_list ]] && continue
        if [[ -z $__sf_rerun ]]; then
            [[ -n $__sf_kw ]] && __shellfirm_block_msg="shellfirm: \`$__sf_kw fc\` runs the edited commands without a check; use \`fc\` instead. Command not run."
            continue
        fi
        [[ -z $__sf_old ]] && continue
        __shellfirm_fc_ok+=$'\n'$__sf_old
        if [[ -n $__sf_whole ]]; then
            __sf_cmd=$__sf_old
        else
            __sf_fx+=$'\n'$__sf_old
        fi
    done
}

# The commands an assignment to PROMPT_COMMAND adds ($1 = `[n]` or "", $2 =
# `=` or `+=`, $3 = the value as written), in __sf_v: the new value is
# worked out in a subshell, and the value it had before is left out.
# Returns 1 (the value is then read as text) when the value could run
# something by itself (a command substitution, arithmetic, `${x@P}`) or
# cannot be worked out.
__shellfirm_pc_added() {
    local __sf_t=$3 __sf_ov __sf_nv __sf_re='\[[0-9@*]+\]' __sf_are='\$\{[^}]*:[^-+=?]'
    __sf_v=""
    [[ -z $1 || $1 =~ ^\[[0-9]+\]$ ]] || return 1
    (( BASH_VERSINFO[0] > 4 || ( BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 4 ) )) || return 1
    # A PROMPT_COMMAND with the integer or nameref attribute evaluates what
    # is assigned.
    [[ ${PROMPT_COMMAND@a} == *[in]* ]] && return 1
    # Plain subscripts (`${PROMPT_COMMAND[@]}`, `${a[1]}`) only.
    while [[ $__sf_t =~ $__sf_re ]]; do
        __sf_t=${__sf_t/"${BASH_REMATCH[0]}"/}
    done
    [[ $__sf_t == *[\`\[]* || $__sf_t == *'$('* || $__sf_t == *[\<\>]\(* || $__sf_t == *@P* || $__sf_t == *'${!'* ]] && return 1
    [[ $__sf_t =~ $__sf_are ]] && return 1
    [[ $3 == \(* && $3 == *[\;\&\|\<\>$'\n']* ]] && return 1
    local IFS=$'\n'
    __sf_ov="${PROMPT_COMMAND[*]}"
    __sf_nv=$(builtin eval "PROMPT_COMMAND$1$2$3" 2>/dev/null || builtin exit 1; builtin printf '%s' "${PROMPT_COMMAND[*]}") || return 1
    [[ -n $__sf_ov && $__sf_nv == *"$__sf_ov"* ]] && __sf_nv=${__sf_nv/"$__sf_ov"/}
    __sf_v=${__sf_nv#"${__sf_nv%%[![:space:];&|]*}"}
    return 0
}

# Code the line installs to run by itself later is checked now, like a
# PROMPT_COMMAND or a trap: the command of a `bind -x` key binding, and the
# body of a command_not_found_handle defined on the line (as a `{ ... }`
# group). Sets the caller's __sf_auto.
__shellfirm_autorun() {
    local __sf_s=$1 __sf_v __sf_i
    local __sf_re=$'(^|[;&|({[:space:]])bind[[:space:]]+([^;&|]*[[:space:]])?-[A-Za-z]*x[[:space:]]*(\'([^\']*)\'|"(([^"\\\\]|\\\\.)*)")'
    local __sf_kre=$'^[[:space:]]*("([^"\\\\]|\\\\.)*"|[^:[:space:]]+)[[:space:]]*:[[:space:]]*(.*)$'
    for (( __sf_i = 0; __sf_i < 8; __sf_i++ )); do
        [[ $__sf_s =~ $__sf_re ]] || break
        __sf_s=${__sf_s#*"${BASH_REMATCH[0]}"}
        if [[ -n ${BASH_REMATCH[4]} ]]; then
            __sf_v=${BASH_REMATCH[4]}
        else
            __sf_v=${BASH_REMATCH[5]//\\\"/\"}
            __sf_v=${__sf_v//\\\\/\\}
        fi
        [[ $__sf_v =~ $__sf_kre ]] || continue
        __sf_v=${BASH_REMATCH[3]}
        [[ $__sf_v == \"*\" ]] && __sf_v=${__sf_v:1:${#__sf_v}-2}
        [[ -n ${__sf_v//[[:space:]]/} ]] && __sf_auto+=$'\n'$__sf_v
    done
    # PROMPT_COMMAND (string or array, `=f` naming a function, one element
    # `[1]=`, `+=`) and the command substitutions of PS0..PS4 run at every
    # prompt; a trap's command runs on its signal (`trap f DEBUG`).
    local __sf_wd=$'((\'[^\']*\'|"([^"\\\\]|\\\\.)*"|\\$\\{([^{}]|\\{[^{}]*\\})*\\}|\\\\.|[^][:space:];&|()<>\'"\\\\])+)'
    local __sf_pre=$'(^|[;&|({[:space:]])(PROMPT_COMMAND|PS[0-4])(\\[[^]]*\\])?(\\+?=)(\\(([^)]*)\\)|'"$__sf_wd)"
    local __sf_ere=$'\'[^\']*\'|"([^"\\\\]|\\\\.)*"|[^[:space:]]+'
    local __sf_sre=$'\\$\\{PROMPT_COMMAND(\\[[^]]*\\])?(:?[-+=])?(([^{}]|\\{[^{}]*\\})*)\\}'
    local __sf_q1=$'^\'([^\']*)\'$' __sf_q2='^"(([^"\\]|\\.)*)"$'
    local __sf_n __sf_ix __sf_op __sf_val __sf_arr __sf_w __sf_e __sf_j
    __sf_s=$1
    for (( __sf_i = 0; __sf_i < 8; __sf_i++ )); do
        [[ $__sf_s =~ $__sf_pre ]] || break
        __sf_s=${__sf_s#*"${BASH_REMATCH[0]}"}
        __sf_n=${BASH_REMATCH[2]} __sf_ix=${BASH_REMATCH[3]} __sf_op=${BASH_REMATCH[4]}
        __sf_val=${BASH_REMATCH[5]} __sf_arr=${BASH_REMATCH[6]} __sf_w=${BASH_REMATCH[7]}
        # What the assignment adds to PROMPT_COMMAND, however it is spelled
        # (`"${PROMPT_COMMAND:+$PROMPT_COMMAND; }x"`, `[1]=x`, `+=(x)`).
        if [[ $__sf_n == PROMPT_COMMAND ]] && __shellfirm_pc_added "$__sf_ix" "$__sf_op" "$__sf_val"; then
            [[ -n ${__sf_v//[[:space:]]/} ]] && __sf_auto+=$'\n'$__sf_v
            continue
        fi
        if [[ $__sf_val == \(* ]]; then
            # An array: each element is a command.
            __sf_v=""
            while [[ $__sf_arr =~ $__sf_ere ]]; do
                __sf_arr=${__sf_arr#*"${BASH_REMATCH[0]}"}
                __sf_e=${BASH_REMATCH[0]}
                [[ $__sf_e == [\'\"]* ]] && __sf_e=${__sf_e:1:${#__sf_e}-2}
                __sf_v+=$'\n'$__sf_e
            done
        elif [[ $__sf_w =~ $__sf_q1 ]]; then
            __sf_v=${BASH_REMATCH[1]}
        elif [[ $__sf_w =~ $__sf_q2 ]]; then
            __sf_v=${BASH_REMATCH[1]//\\\"/\"}
            __sf_v=${__sf_v//\\\$/\$}
            __sf_v=${__sf_v//\\\`/\`}
        else
            __sf_v=${__sf_w//[\'\"]/}
        fi
        # A prompt string only runs its command substitutions.
        [[ $__sf_n == PS* && $__sf_v != *'$('* && $__sf_v != *'`'* ]] && continue
        if [[ $__sf_n == PROMPT_COMMAND ]]; then
            # Read as text: the earlier value is not part of what it adds.
            for (( __sf_j = 0; __sf_j < 4; __sf_j++ )); do
                [[ $__sf_v =~ $__sf_sre ]] || break
                __sf_v=${__sf_v/"${BASH_REMATCH[0]}"/${BASH_REMATCH[3]}}
            done
            __sf_v=${__sf_v//'$PROMPT_COMMAND'/}
            __sf_v=${__sf_v#"${__sf_v%%[![:space:];&|]*}"}
        fi
        [[ -n ${__sf_v//[[:space:]]/} ]] && __sf_auto+=$'\n'$__sf_v
    done
    local __sf_tre=$'(^|[;&|({[:space:]])trap[[:space:]]+(--[[:space:]]+)?(\'([^\']*)\'|"(([^"\\\\]|\\\\.)*)"|('$__shellfirm_namere'))[[:space:]]+[A-Za-z0-9]'
    __sf_s=$1
    for (( __sf_i = 0; __sf_i < 8; __sf_i++ )); do
        [[ $__sf_s =~ $__sf_tre ]] || break
        __sf_s=${__sf_s#*"${BASH_REMATCH[0]}"}
        __sf_v=${BASH_REMATCH[4]}${BASH_REMATCH[5]}${BASH_REMATCH[7]}
        [[ -n ${__sf_v//[[:space:]]/} && $__sf_v != - ]] && __sf_auto+=$'\n'$__sf_v
    done
    local __sf_dre='(^|[;&|({[:space:]])(function[[:space:]]+)?command_not_found_handle[[:space:]]*(\([[:space:]]*\))?[[:space:]]*\{'
    if [[ $1 =~ $__sf_dre ]]; then
        __sf_auto+=$'\n'${1/"${BASH_REMATCH[0]}"/"${BASH_REMATCH[1]}{"}
    fi
    # `${K} delete ...` (the braces would split the command): the session
    # value of K in its place, like `$K` (see __shellfirm_segment).
    local __sf_vre='(^|[;&|(]|'$'\n'')[[:space:]]*\$\{([A-Za-z_][A-Za-z0-9_]*)\}([^;&|'$'\n'']*)'
    __sf_s=$1
    for (( __sf_i = 0; __sf_i < 8; __sf_i++ )); do
        [[ $__sf_s =~ $__sf_vre ]] || break
        __sf_s=${__sf_s#*"${BASH_REMATCH[0]}"}
        __sf_v=${BASH_REMATCH[2]}
        [[ $__sf_v != __sf_* && -n ${!__sf_v:+set} ]] || continue
        __sf_v=${!__sf_v}
        (( ${#__sf_v} <= 4000 )) && [[ $__sf_v != *__shellfirm_* ]] && __sf_auto+=$'\n'$__sf_v${BASH_REMATCH[3]}
    done
}

# Join continuation lines and expand aliases (in every command of the line)
# and `fc -s`, and add the definitions of the functions the line calls, so
# the check sees what bash will actually run (history references are
# expanded by the caller). Sets __shellfirm_expanded ("" = nothing to
# check). $2 = 1: a huge line (the work is capped).
__shellfirm_expand() {
    # Byte-wise matching is enough here and much faster.
    local LC_ALL=C
    local __sf_cmd=${1//$'\\\n'/} __sf_ax __sf_nd __sf_bnd="" __sf_fx="" __sf_seg __sf_fseen="" __sf_shown=""
    local __sf_defs="" __sf_defnames="" __sf_segmark="" __sf_fbytes=0 __sf_n
    local -a __sf_fcseg __sf_bfcseg=() __sf_calls=() __sf_fnames=() __sf_fbodies=()
    if [[ $__sf_cmd == *bind* || $__sf_cmd == *command_not_found_handle* || $__sf_cmd == *'${'[A-Za-z_]* \
        || $__sf_cmd == *PROMPT_COMMAND* || $__sf_cmd == *PS[0-4]* || $__sf_cmd == *trap* ]]; then
        local __sf_auto=""
        __shellfirm_autorun "$__sf_cmd"
        [[ -n $__sf_auto ]] && __sf_shown=$__sf_cmd
        __sf_cmd+=$__sf_auto
    fi
    __shellfirm_segments "$__sf_cmd" "${2:-}"
    __sf_cmd=$__sf_ax
    __shellfirm_expanded=""
    # Only adds text to history: nothing runs.
    if [[ $__sf_cmd =~ ^[[:space:]]*(builtin[[:space:]]+)?history[[:space:]]+-s[[:space:]] && $__sf_cmd != *[\;\|\&\`\$\(\)\<\>]* && $__sf_cmd != *$'\n'* ]]; then
        return
    fi
    [[ -n $__sf_segmark ]] && __sf_fx+=$'\n'"shellfirm-function-depth-limit line # more commands than the hook reads ahead"
    # A function that runs by itself (a hook, a trap, a key binding),
    # redefined on this line: checked as if it was called.
    if [[ -n $__sf_defnames ]]; then
        local __sf_reach=""
        __shellfirm_hook_reach
        for __sf_n in $__sf_defnames; do
            [[ " $__sf_reach " == *" $__sf_n "* ]] && __sf_fx+=$'\n'$__sf_n
        done
    fi
    __shellfirm_fn_defs "$__sf_cmd$__sf_fx"
    (( ${#__sf_calls[@]} )) && __shellfirm_body_fc
    local __sf_fx0=$__sf_fx __sf_cmd0=$__sf_cmd
    [[ $__sf_nd == *fc* ]] && __shellfirm_resolve_fc "$__sf_nd"
    [[ -n $__sf_bnd ]] && __shellfirm_resolve_fc "$__sf_bnd" 1
    for __sf_seg in "${__sf_fcseg[@]:0:8}"; do
        __shellfirm_fc_eval "$__sf_seg"
    done
    for __sf_seg in "${__sf_bfcseg[@]:0:8}"; do
        __shellfirm_fc_eval "$__sf_seg" 1
    done
    # Re-runs and `eval` text added just now can call functions too.
    if [[ $__sf_fx != "$__sf_fx0" || $__sf_cmd != "$__sf_cmd0" ]]; then
        __shellfirm_fn_defs "$__sf_cmd ${__sf_fx#"$__sf_fx0"}"
    fi
    __shellfirm_expanded=${__sf_defs#$'\n'}${__sf_defs:+$'\n'}$__sf_cmd$__sf_fx
    __shellfirm_line=${__sf_shown:-$__sf_cmd}
}

# `fc` and Ctrl-X Ctrl-E / vi `v` (edit-and-execute-command, which runs
# `fc`): the edited text is checked before bash runs it. A blocked edit is
# discarded (fc runs nothing when the editor fails).
__shellfirm_fcedit() {
    local __sf_f=${!#}
    builtin eval "$__shellfirm_fc_editor"' "$__sf_f"' || return
    local __sf_c
    __sf_c=$(<"$__sf_f")
    [[ -z ${__sf_c//[[:space:]]/} ]] && return 0
    __shellfirm_expand "$__sf_c"
    [[ -z $__shellfirm_expanded ]] && return 0
    __shellfirm_check "$__shellfirm_expanded" && return 0
    : > "$__sf_f"
    return 1
}
# `fc -s` / `fc -e -` (re-run) are checked here too, whatever the line looks
# like (`\fc`, `eval fc ...`, `x=1 fc ...`); lines checked on Enter are not
# asked about twice.
if ! builtin declare -F fc >/dev/null; then
fc() {
    local __sf_a __sf_ed="" __sf_next="" __sf_edit=1 __sf_rerun="" __sf_list=""
    local -a __sf_args=()
    for __sf_a in "$@"; do
        if [[ -n $__sf_next ]]; then
            __sf_ed=$__sf_a; __sf_next=""
            [[ $__sf_a == - ]] && { __sf_edit=""; __sf_rerun=1; }
            continue
        fi
        case $__sf_a in
            -e) __sf_next=1; continue ;;
            -[0-9]*) ;;
            -*l*) __sf_edit=""; __sf_list=1 ;;
            -*s*) __sf_edit=""; __sf_rerun=1 ;;
        esac
        __sf_args+=("$__sf_a")
    done
    if [[ -n $__sf_rerun && -z $__sf_list ]]; then
        local __sf_pat="" __sf_rep="" __sf_sel=-1 __sf_old __sf_set=""
        for __sf_a in "${__sf_args[@]}"; do
            [[ $__sf_a == -* && $__sf_a != -[0-9]* ]] && continue
            if [[ -z $__sf_set && $__sf_a == *=* ]]; then
                __sf_set=1; __sf_pat=${__sf_a%%=*}; __sf_rep=${__sf_a#*=}
            else
                __sf_sel=$__sf_a
            fi
        done
        __sf_old=$(builtin enable fc 2>/dev/null; builtin fc -ln "$__sf_sel" "$__sf_sel" 2>/dev/null)
        __sf_old=${__sf_old#"${__sf_old%%[![:space:]]*}"}
        [[ -n $__sf_pat ]] && __sf_old=${__sf_old//"$__sf_pat"/$__sf_rep}
        if [[ -n ${__sf_old//[[:space:]]/} && $'\n'$__shellfirm_fc_ok$'\n' != *$'\n'"$__sf_old"$'\n'* ]]; then
            __shellfirm_expand "$__sf_old"
            if [[ -n $__shellfirm_expanded ]] && ! __shellfirm_check "$__shellfirm_expanded"; then
                return 1
            fi
        fi
    fi
    if [[ -z $__sf_edit ]]; then
        __shellfirm_bfc "$@"
        return
    fi
    local __shellfirm_fc_editor=${__sf_ed:-${FCEDIT:-${EDITOR:-vi}}}
    __shellfirm_bfc -e __shellfirm_fcedit "${__sf_args[@]}"
}
# The fc builtin, which shellfirm keeps turned off (see below).
__shellfirm_bfc() {
    builtin enable fc 2>/dev/null
    builtin fc "$@"
    local __sf_r=$?
    [[ -n $__shellfirm_fc_off ]] && builtin enable -n fc 2>/dev/null
    return $__sf_r
}
__shellfirm_fc_off=""
fi

# atuin's enter_accept runs the chosen command with `eval` inside its own
# `bind -x` widget; check it first (atuin is usually loaded after shellfirm).
__shellfirm_wrap_plugins() {
    if [[ -z ${__shellfirm_atuin_wrapped:-} ]] && builtin declare -F __atuin_accept_line >/dev/null; then
        __shellfirm_atuin_wrapped=1
        local __sf_f
        __sf_f=$(builtin declare -f __atuin_accept_line)
        builtin eval "__shellfirm_orig_atuin_accept_line ${__sf_f#__atuin_accept_line}"
        __atuin_accept_line() {
            builtin export -n READLINE_LINE READLINE_POINT READLINE_MARK 2>/dev/null
            __shellfirm_seen=1
            __shellfirm_fc_ok=""
            __shellfirm_expand "$1"
            if [[ -n $__shellfirm_expanded ]] && ! __shellfirm_check "$__shellfirm_expanded"; then
                return 1
            fi
            __shellfirm_orig_atuin_accept_line "$@"
        }
    fi
}

# Removes a DEBUG-trap hook pasted from shellfirm <= 0.3.10, which would
# prompt a second time and can leave the shell unusable after a cancel.
__shellfirm_disable_legacy() {
    if [[ $(builtin trap -p DEBUG) == *_shellfirm_hook* ]]; then
        builtin trap - DEBUG
        builtin shopt -u extdebug
        if [[ $(builtin declare -p PROMPT_COMMAND 2>/dev/null) != "declare -a"* ]]; then
            PROMPT_COMMAND=${PROMPT_COMMAND//_shellfirm_prompt;/}
            PROMPT_COMMAND=${PROMPT_COMMAND//_shellfirm_prompt/}
        fi
        builtin printf '%s\n' "shellfirm: disabled an old shellfirm hook (DEBUG trap) found in your shell startup files; remove it (run \`shellfirm init bash\` to see where)." >&2
    fi
}

__shellfirm_precmd() {
    __shellfirm_sync_ps0
    __shellfirm_pending=""
    __shellfirm_pending_x=""
    __shellfirm_cont=""
    # The fc builtin stays off (a checked line may have turned it on).
    [[ -n $__shellfirm_fc_off ]] && builtin enable -n fc 2>/dev/null
    __shellfirm_wrap_plugins
    # Enter is looked at by __shellfirm_postcmd, after the other
    # PROMPT_COMMAND entries (a plugin may rebind Enter in one); here only
    # when that is not in place yet.
    if ! __shellfirm_install_postcmd; then
        __shellfirm_postcmd
    fi
}

# Last before the prompt: Enter (or Ctrl-J) rebound since the last look is
# bound to the check again, so the next command is checked.
__shellfirm_postcmd() {
    if [[ -z $__shellfirm_legacy_checked ]]; then
        __shellfirm_legacy_checked=1
        __shellfirm_disable_legacy
        __shellfirm_check_bindings
        __shellfirm_relsrc=1
    elif [[ -n $__shellfirm_histcmd && $HISTCMD != "$__shellfirm_histcmd" && -z $__shellfirm_seen ]]; then
        # A command ran (new history entry) without passing through the
        # Enter binding: something rebound Enter. Say so every time.
        builtin printf '%s\n' "shellfirm: warning: the last command did not pass through shellfirm (Enter was rebound) and was NOT checked; shellfirm bound Enter to the check again." >&2
        __shellfirm_unchecked_seen=1
        __shellfirm_rw_every=1
        __shellfirm_check_bindings
    elif [[ -n $__shellfirm_rebind_maybe || -n $__shellfirm_rw_every ]]; then
        # The line could have rebound Enter (`bind`, `source`), or something
        # rebinds it again and again (a plugin's PROMPT_COMMAND): look now,
        # before the next command runs.
        __shellfirm_check_bindings
    fi
    __shellfirm_rebind_maybe=""
    __shellfirm_seen=""
    __shellfirm_histcmd=$HISTCMD
    [[ -n $__shellfirm_catsrc ]] && __shellfirm_note_catsrc
    [[ -n $__shellfirm_relsrc ]] && __shellfirm_note_relsrc
}
__shellfirm_legacy_checked=""
__shellfirm_rebind_maybe=""
__shellfirm_rw_every=""
# Returns 1 when __shellfirm_postcmd was not the last PROMPT_COMMAND entry
# (it is then made the last one, from the next prompt on).
__shellfirm_install_postcmd() { return 1; }

if [[ ( -o emacs || -o vi ) && ${BASH_VERSINFO[0]:-0} -ge 4 ]]; then

# Prints the keys whose binding no longer goes through shellfirm.
__shellfirm_unbound_keys() {
    local __sf_km __sf_s __sf_k __sf_l __sf_out=""
    for __sf_km in emacs vi-insert vi-command; do
        __sf_s=$'\n'$(builtin bind -m "$__sf_km" -s 2>/dev/null)$'\n'
        for __sf_k in '\C-m' '\C-j'; do
            # The key's own line: the check, then accept-line or the wrapped
            # binding; or a macro that ends in the check (see
            # __shellfirm_fuse_macro).
            __sf_l=${__sf_s#*$'\n'"\"$__sf_k\": \""}
            if [[ $__sf_l == "$__sf_s" ]]; then
                __sf_out+=" $__sf_km:$__sf_k"
                continue
            fi
            __sf_l=${__sf_l%%$'\n'*}
            [[ $__sf_l == '\e[9900~\e[990'[156]'~"' || $__sf_l == *'\e[9900~\e[9901~"' ]] || __sf_out+=" $__sf_km:$__sf_k"
        done
    done
    builtin printf '%s' "$__sf_out"
}
# A macro on Enter that ends with a key bound to accept-line (`"\C-m":
# "\e[7777~\C-x\C-a"`, the first key rewriting the line): what it ends with
# is replaced by the check and accept-line, so the line it wrote is the
# line checked. Sets __sf_spec to the new macro; returns 1 when the macro
# does not end that way.
__shellfirm_fuse_macro() {
    local __sf_m=${2#\"} __sf_l __sf_key
    __sf_m=${__sf_m%\"}
    while IFS= builtin read -r __sf_l; do
        [[ $__sf_l == \"*\":\ accept-line ]] || continue
        __sf_key=${__sf_l#\"} __sf_key=${__sf_key%\": accept-line}
        [[ -z $__sf_key || $__sf_key == '\e[990'* || $__sf_key == '\C-m' || $__sf_key == '\C-j' ]] && continue
        if [[ $__sf_m == *"$__sf_key" && $__sf_m != "$__sf_key" ]]; then
            __sf_spec="\"${__sf_m%"$__sf_key"}\\e[9900~\\e[9901~\""
            return 0
        fi
    done < <(builtin bind -m "$1" -p 2>/dev/null)
    return 1
}
# Enter (or Ctrl-J) rebound after shellfirm loaded (a plugin, `bind
# '"\C-m": ...'`): bind it to the check again, and run that binding after
# the check (a readline function, a macro or a `bind -x` command).
# __shellfirm_rw holds those bindings ("keymap seq kind spec" lines).
__shellfirm_rw=""
__shellfirm_rw_seen=""
__shellfirm_check_bindings() {
    local __sf_bad __sf_e __sf_km __sf_k __sf_seq __sf_l __sf_kind __sf_spec __sf_q __sf_new="" __sf_fail=""
    __sf_bad=$(__shellfirm_unbound_keys)
    [[ -z $__sf_bad ]] && return
    for __sf_e in $__sf_bad; do
        __sf_km=${__sf_e%%:*} __sf_k=${__sf_e#*:}
        if [[ $__sf_k == '\C-m' ]]; then __sf_seq='\e[9905~'; else __sf_seq='\e[9906~'; fi
        __sf_q="\"$__sf_k\": "
        __sf_kind="" __sf_spec=""
        __sf_l=$(builtin bind -m "$__sf_km" -p 2>/dev/null | builtin command grep -F -m1 -- "$__sf_q")
        if [[ -n $__sf_l ]]; then
            __sf_kind=fn __sf_spec=${__sf_l#"$__sf_q"}
        else
            __sf_l=$(builtin bind -m "$__sf_km" -s 2>/dev/null | builtin command grep -F -m1 -- "$__sf_q")
            if [[ -n $__sf_l ]]; then
                __sf_kind=macro __sf_spec=${__sf_l#"$__sf_q"}
            else
                __sf_l=$(builtin bind -m "$__sf_km" -X 2>/dev/null | builtin command grep -F -m1 -- "$__sf_q")
                [[ -n $__sf_l ]] && __sf_kind=x __sf_spec=${__sf_l#"$__sf_q"}
            fi
        fi
        # Unbound, or bound to shellfirm's own sequences: plain accept-line.
        if [[ -z $__sf_kind || $__sf_spec == *9900~* || $__sf_spec == *__shellfirm_* ]]; then
            __sf_kind=fn __sf_spec=accept-line
        fi
        if [[ $__sf_kind == macro ]] && __shellfirm_fuse_macro "$__sf_km" "$__sf_spec"; then
            builtin bind -m "$__sf_km" "\"$__sf_k\": $__sf_spec" 2>/dev/null || { __sf_fail+=" $__sf_e"; continue; }
            __sf_new+=$'\n'"$__sf_km $__sf_seq fn redraw-current-line"
            continue
        fi
        __shellfirm_rw_bind "$__sf_km" "$__sf_seq" "$__sf_kind" "$__sf_spec" || { __sf_fail+=" $__sf_e"; continue; }
        builtin bind -m "$__sf_km" "\"$__sf_k\": \"\\e[9900~$__sf_seq\"" 2>/dev/null || { __sf_fail+=" $__sf_e"; continue; }
        __sf_new+=$'\n'"$__sf_km $__sf_seq $__sf_kind $__sf_spec"
    done
    if [[ -n $__sf_new ]]; then
        # Replace older entries for the same keymap and key.
        local __sf_old __sf_keep=""
        while IFS= builtin read -r __sf_old; do
            [[ -z $__sf_old || $__sf_new == *$'\n'"${__sf_old%%~ *}~ "* ]] && continue
            __sf_keep+=$'\n'$__sf_old
        done <<< "$__shellfirm_rw"
        __shellfirm_rw=$__sf_keep$__sf_new
        for __sf_e in $__sf_bad; do
            [[ " $__shellfirm_rw_seen " == *" $__sf_e "* ]] || __shellfirm_rw_seen+=" $__sf_e"
        done
        # Something rebinds Enter: look before every prompt from now on.
        __shellfirm_rw_every=1
        if [[ -z $__shellfirm_rebound_warned && -z ${__shellfirm_loading:-} ]]; then
            __shellfirm_rebound_warned=1
            builtin printf '%s\n' "shellfirm: Enter was rebound after shellfirm loaded (${__sf_bad# }); shellfirm now checks the line first, then runs that binding." >&2
        fi
    fi
    if [[ -n $__sf_fail && -z $__shellfirm_bypass_warned ]]; then
        __shellfirm_bypass_warned=1
        builtin printf '%s\n' "shellfirm: warning: Enter was rebound after shellfirm loaded (${__sf_fail# }) and shellfirm could not wrap it; commands are NOT being checked. Run \`shellfirm doctor\`." >&2
    fi
}
__shellfirm_rebound_warned=""
# __shellfirm_rw_bind <keymap> <seq> <kind> <spec>: bind seq to the binding.
__shellfirm_rw_bind() {
    case $3 in
        x) builtin bind -m "$1" -x "\"$2\": $4" 2>/dev/null ;;
        *) builtin bind -m "$1" "\"$2\": $4" 2>/dev/null ;;
    esac
}
# $1 = 1: run the re-wrapped bindings after the check; else skip them.
__shellfirm_rw_arm() {
    local __sf_l __sf_km __sf_seq __sf_kind __sf_spec
    while IFS= builtin read -r __sf_l; do
        [[ -z $__sf_l ]] && continue
        __sf_km=${__sf_l%% *} __sf_l=${__sf_l#* }
        __sf_seq=${__sf_l%% *} __sf_l=${__sf_l#* }
        __sf_kind=${__sf_l%% *} __sf_spec=${__sf_l#* }
        if [[ $1 == 1 ]]; then
            __shellfirm_rw_bind "$__sf_km" "$__sf_seq" "$__sf_kind" "$__sf_spec"
        else
            builtin bind -m "$__sf_km" "\"$__sf_seq\": redraw-current-line" 2>/dev/null
        fi
    done <<< "$__shellfirm_rw"
}

# Returns 0 when bash will ask for more input (PS2) instead of running $1.
__shellfirm_incomplete() {
    local __sf_re=$'[][\\\\\'"(){}<|&`]|(^|[[:space:];&|])(if|case|for|select|while|until|function|coproc)([[:space:]]|$)'
    [[ $1 =~ $__sf_re ]] || return 1
    local __sf_err
    __sf_err=$("${BASH:-bash}" --norc --noprofile -O extglob -n -c "$1" 2>&1 >/dev/null)
    case $__sf_err in
        *"unexpected end of file"*|*"unexpected EOF"*|*"here-document at line"*) return 0 ;;
    esac
    local __sf_bs=${1##*[!\\]}
    if [[ -z $__sf_err ]] && (( ${#__sf_bs} % 2 )); then
        # Trailing backslash: a line continuation unless it sits in a comment.
        "${BASH:-bash}" --norc --noprofile -O extglob -n -c "$1"$'\nfi' >/dev/null 2>&1 && return 0
        # After an operator (`a && \`): without the backslash the line is
        # still open (a backslash in a comment would leave it complete).
        __sf_err=$("${BASH:-bash}" --norc --noprofile -O extglob -n -c "${1%\\}" 2>&1 >/dev/null)
        [[ $__sf_err == *"unexpected end of file"* || $__sf_err == *"unexpected EOF"* ]] && return 0
    fi
    return 1
}

# The same for text after history expansion, with aliases expanded too.
__shellfirm_incomplete_expanded() {
    __shellfirm_incomplete "$1" || return 1
    local __sf_ax __sf_nd __sf_defnames="" __sf_segmark="" __sf_fx=""
    local -a __sf_fcseg __sf_calls=()
    __shellfirm_segments "$1"
    [[ $__sf_ax == "$1" ]] && return 0
    __shellfirm_incomplete "$__sf_ax"
}

# Keep __shellfirm_precmd (which resets the multi-line buffer) running before
# every primary prompt, even if PROMPT_COMMAND is reassigned later. Chains
# with bash-preexec and with string or array PROMPT_COMMAND.
# Returns 1 if it had to (re)install it.
__shellfirm_install_precmd() {
    if [[ -n ${bash_preexec_imported:-}${__bp_imported:-} ]]; then
        [[ " ${precmd_functions[*]} " == *" __shellfirm_precmd "* ]] && return 0
        precmd_functions=(__shellfirm_precmd "${precmd_functions[@]}")
        return 1
    fi
    [[ "${PROMPT_COMMAND[*]}" == *__shellfirm_precmd* ]] && return 0
    if [[ $(builtin declare -p PROMPT_COMMAND 2>/dev/null) == "declare -a"* ]]; then
        PROMPT_COMMAND=(__shellfirm_precmd "${PROMPT_COMMAND[@]}")
    else
        PROMPT_COMMAND="__shellfirm_precmd${PROMPT_COMMAND:+$'\n'$PROMPT_COMMAND}"
    fi
    return 1
}
__shellfirm_install_postcmd() {
    local __sf_e
    local -a __sf_keep=()
    if [[ -n ${bash_preexec_imported:-}${__bp_imported:-} ]]; then
        # bash-preexec runs precmd_functions from its first PROMPT_COMMAND
        # entry, and keeps the entries added later (a plugin that rebinds
        # Enter at every prompt) after it: shellfirm's look goes last in
        # PROMPT_COMMAND too, just before bash-preexec's own last entry.
        local __sf_r=0
        if [[ ${precmd_functions[${#precmd_functions[@]}-1]-} != __shellfirm_postcmd ]]; then
            for __sf_e in "${precmd_functions[@]}"; do
                [[ $__sf_e == __shellfirm_postcmd ]] || __sf_keep+=("$__sf_e")
            done
            precmd_functions=("${__sf_keep[@]}" __shellfirm_postcmd)
            __sf_r=1
        fi
        __shellfirm_pc_last || __sf_r=1
        return $__sf_r
    fi
    if [[ $(builtin declare -p PROMPT_COMMAND 2>/dev/null) == "declare -a"* ]]; then
        [[ ${PROMPT_COMMAND[${#PROMPT_COMMAND[@]}-1]} == __shellfirm_postcmd ]] && return 0
        for __sf_e in "${PROMPT_COMMAND[@]}"; do
            [[ $__sf_e == __shellfirm_postcmd ]] || __sf_keep+=("$__sf_e")
        done
        PROMPT_COMMAND=("${__sf_keep[@]}" __shellfirm_postcmd)
        return 1
    fi
    [[ $PROMPT_COMMAND == *$'\n'__shellfirm_postcmd ]] && return 0
    __sf_e=${PROMPT_COMMAND//$'\n'__shellfirm_postcmd/}
    PROMPT_COMMAND=$__sf_e$'\n'__shellfirm_postcmd
    return 1
}

# Under bash-preexec: `__shellfirm_postcmd` as the last PROMPT_COMMAND entry
# before `__bp_interactive_mode` (array) or its last line (string). Returns 1
# when it had to move it.
__shellfirm_pc_last() {
    local __sf_e __sf_s
    local -a __sf_keep=()
    if [[ $(builtin declare -p PROMPT_COMMAND 2>/dev/null) == "declare -a"* ]]; then
        local __sf_n=${#PROMPT_COMMAND[@]} __sf_bp=""
        if [[ ${PROMPT_COMMAND[__sf_n-1]//[[:space:]]/} == __bp_interactive_mode ]]; then
            (( __sf_n >= 2 )) && [[ ${PROMPT_COMMAND[__sf_n-2]} == __shellfirm_postcmd ]] && return 0
        else
            [[ ${PROMPT_COMMAND[__sf_n-1]-} == __shellfirm_postcmd ]] && return 0
        fi
        for __sf_e in "${PROMPT_COMMAND[@]}"; do
            if [[ ${__sf_e//[[:space:]]/} == __bp_interactive_mode ]]; then
                __sf_bp=$__sf_e
            elif [[ $__sf_e != __shellfirm_postcmd ]]; then
                __sf_keep+=("$__sf_e")
            fi
        done
        __sf_keep+=(__shellfirm_postcmd)
        [[ -n $__sf_bp ]] && __sf_keep+=("$__sf_bp")
        PROMPT_COMMAND=("${__sf_keep[@]}")
        return 1
    fi
    __sf_s=${PROMPT_COMMAND-}
    [[ $__sf_s == *$'\n__shellfirm_postcmd\n__bp_interactive_mode' || $__sf_s == *$'\n__shellfirm_postcmd' ]] && return 0
    __sf_s=${__sf_s//$'\n'__shellfirm_postcmd/}
    if [[ $__sf_s =~ ^(.*[^[:space:]\;])[[:space:]\;]*__bp_interactive_mode[[:space:]\;]*$ ]]; then
        __sf_s=${BASH_REMATCH[1]}$'\n__shellfirm_postcmd\n__bp_interactive_mode'
    else
        __sf_s+=$'\n__shellfirm_postcmd'
    fi
    PROMPT_COMMAND=$__sf_s
    return 1
}

__shellfirm_accept() {
    # bash exports READLINE_LINE to programs started here: a huge line would
    # make every exec fail with E2BIG.
    builtin export -n READLINE_LINE READLINE_POINT READLINE_MARK 2>/dev/null
    # The DEBUG / ERR / RETURN traps (see the binding below).
    __shellfirm_traps=${1-}
    builtin bind '"\e[9901~": accept-line'
    builtin bind '"\e[9903~": operate-and-get-next' 2>/dev/null
    [[ -n $__shellfirm_rw ]] && __shellfirm_rw_arm 1
    # starship-style DEBUG-trap timers started at this key press (this
    # `bind -x` command); re-arm them so they time the command, not the check.
    [[ -n ${STARSHIP_PREEXEC_READY+set} ]] && STARSHIP_PREEXEC_READY=true
    __shellfirm_seen=1
    __shellfirm_install_precmd || { __shellfirm_pending=""; __shellfirm_pending_x=""; __shellfirm_cont=""; }
    __shellfirm_fc_ok=""
    __shellfirm_block_msg=""
    __shellfirm_rest=""
    local __sf_line=$READLINE_LINE __sf_full __sf_x __sf_cont=$__shellfirm_cont
    # Only input bash is still collecting (an open quote or block, PS2) is
    # joined with this line. A line bash rejected (history expansion failed:
    # "event not found") ran nothing and is not kept.
    if [[ -n $__sf_cont ]]; then
        __sf_full=$__shellfirm_pending$'\n'$__sf_line
    else
        __sf_full=$__sf_line
        __shellfirm_pending_x=""
    fi
    __shellfirm_cont=""
    __shellfirm_pending=$__sf_full
    # The line can rebind Enter: look at the next prompt.
    [[ $__sf_full == *bind* || $__sf_full == *source* || $__sf_full == *.[[:space:]]* ]] && __shellfirm_rebind_maybe=1
    __shellfirm_catsrc=""
    local __sf_srcre='(^|[;&|({[:space:]])(source|\.)[[:space:]]+[^/<[:space:]]'
    [[ $__sf_full =~ $__sf_srcre ]] && __shellfirm_relsrc=1
    if [[ $__sf_full == *'<(cat'* ]]; then
        local __sf_cre='^[[:space:]]*(source|\.)[[:space:]]+<\([[:space:]]*cat[[:space:]]+([^][:space:];&|()<>`$'"'"'"\\*?[{}]+)[[:space:]]*\)[[:space:]]*$'
        if [[ $__sf_full =~ $__sf_cre ]]; then
            __shellfirm_catsrc=${BASH_REMATCH[2]}
            [[ $__shellfirm_catsrc == '~/'* ]] && __shellfirm_catsrc=$HOME/${__shellfirm_catsrc#'~/'}
        fi
    fi
    __shellfirm_fc_typed=""
    # History references (!!, !$, ^a^b) are expanded line by line, as bash
    # does. `history -p` drops the newest entry unless one was just pushed;
    # push and delete a dummy entry (in the subshell only) to avoid that.
    __sf_x=$__sf_line
    # The history characters can be changed (`histchars='@^#'`).
    local __sf_hc=${histchars-!^#}
    local __sf_h1=${__sf_hc:0:1} __sf_h2=${__sf_hc:1:1}
    if [[ $- == *H* && -n $__sf_h1 && ( $__sf_line == *"$__sf_h1"* || ( -n $__sf_h2 && $__sf_line == "$__sf_h2"* ) ) ]]; then
        __sf_x=$(builtin history -s :; builtin history -d -1; builtin history -p -- "$__sf_line" 2>/dev/null) || __sf_x=$__sf_line
    fi
    [[ -n $__sf_cont ]] && __sf_x=$__shellfirm_pending_x$'\n'$__sf_x
    __shellfirm_pending_x=$__sf_x
    [[ -z ${__sf_full//[[:space:]]/} ]] && return
    local __sf_len
    __shellfirm_len "$__sf_full"
    if (( __sf_len > __shellfirm_max_arg )); then
        # Huge input: no (slow) completeness probe; expansions are capped.
        __shellfirm_expand "$__sf_x" 1
        __shellfirm_check "${__shellfirm_expanded:-$__sf_x}" && return
    else
        # Incomplete input (open quote/block, trailing \): bash shows PS2 and
        # the whole construct is checked once it is complete. bash decides
        # that after history and alias expansion (`!$` or an alias can be
        # the `fi`), so the expanded text is probed.
        if __shellfirm_incomplete_expanded "$__sf_x"; then
            __shellfirm_cont=1
            return
        fi
        __shellfirm_expand "$__sf_x"
        if [[ -n $__shellfirm_block_msg ]]; then
            builtin printf '%s\n' "$__shellfirm_block_msg" >&2
        else
            # A typed `command fc` / `builtin fc` was read and checked: the
            # builtin is on while this line runs (off at the next prompt).
            [[ -n $__shellfirm_fc_typed && -n $__shellfirm_fc_off ]] && builtin enable fc 2>/dev/null
            [[ -z $__shellfirm_expanded ]] && return
            __shellfirm_check "$__shellfirm_expanded" 1 "$__sf_cont" && return
        fi
    fi
    # Blocked: skip accept-line. A single line stays in the buffer for
    # editing; a multi-line construct is discarded with SIGINT (a user INT
    # trap would swallow it, so lift it around the signal).
    builtin bind '"\e[9901~": redraw-current-line'
    builtin bind '"\e[9903~": redraw-current-line'
    [[ -n $__shellfirm_rw ]] && __shellfirm_rw_arm 0
    [[ -n $__shellfirm_fc_off ]] && builtin enable -n fc 2>/dev/null
    __shellfirm_pending=""
    __shellfirm_pending_x=""
    local __sf_rn __sf_rv __sf_rp
    [[ -n $__shellfirm_rest ]] && __shellfirm_rest_count
    if [[ $__sf_full == "$__sf_line" ]]; then
        # The cursor at the end (a binding that rewrote the line before the
        # check leaves it where the old line ended), so Ctrl-U clears it all
        # (also every line of a pasted block: readline edits it as one).
        if [[ -n $__shellfirm_rest ]]; then
            # The lines read ahead of the challenge stay with it.
            READLINE_LINE+=$'\n'$__shellfirm_rest
            builtin printf '%s\n' "shellfirm: the line and the $__sf_rn typed or pasted after it are kept for editing (Ctrl-U clears them all)." >&2
        elif [[ $READLINE_LINE == *$'\n'* ]]; then
            builtin printf '%s\n' "shellfirm: the lines are kept for editing (Ctrl-U clears them all)." >&2
        else
            builtin printf '%s\n' "shellfirm: the line is kept for editing (Ctrl-U clears it)." >&2
        fi
        READLINE_POINT=${#READLINE_LINE}
    else
        [[ -n $__shellfirm_rest ]] && builtin printf '%s\n' "shellfirm: the $__sf_rn typed or pasted after it $__sf_rv discarded too." >&2
        local __sf_int
        __sf_int=$(builtin trap -p INT)
        builtin trap - INT
        builtin kill -INT $$
        [[ -n $__sf_int ]] && builtin eval "$__sf_int"
    fi
    __shellfirm_rest=""
}

__sf_wrap=""
for __sf_km in emacs vi-insert vi-command; do
    # Passing "$_" keeps $_ (last argument of the previous command) intact.
    # A function does not see the DEBUG, ERR and RETURN traps (`trap -p`
    # prints nothing for them there): they are read here, at the top level.
    builtin bind -m "$__sf_km" -x '"\e[9900~": __shellfirm_accept "$(builtin trap -p DEBUG ERR RETURN 2>/dev/null)" "$_"'
    builtin bind -m "$__sf_km" '"\e[9901~": accept-line'
    # Enter bound before shellfirm loaded to something other than
    # accept-line (a macro or a command that rewrites the line): kept, and
    # wrapped below like a binding made later.
    __sf_l=$'\n'$(builtin bind -m "$__sf_km" -s 2>/dev/null; builtin bind -m "$__sf_km" -X 2>/dev/null)
    for __sf_k in '\C-m' '\C-j'; do
        if [[ $__sf_l == *$'\n'"\"$__sf_k\": "* ]]; then
            __sf_wrap=1
        else
            builtin bind -m "$__sf_km" "\"$__sf_k\": \"\\e[9900~\\e[9901~\""
        fi
    done
done
if [[ -n $__sf_wrap ]]; then
    __shellfirm_loading=1
    __shellfirm_check_bindings
    __shellfirm_loading=""
fi
unset __sf_wrap __sf_l __sf_k
# Ctrl-O (operate-and-get-next) runs the line too.
if [[ $(builtin bind -m emacs -q operate-and-get-next 2>/dev/null) == *'"\C-o"'* ]]; then
    builtin bind -m emacs '"\e[9903~": operate-and-get-next'
    builtin bind -m emacs '"\C-o": "\e[9900~\e[9903~"'
fi
unset __sf_km
__shellfirm_install_precmd
__shellfirm_install_postcmd
__shellfirm_disable_legacy
# `bind` that changes what Enter (or Ctrl-J) does: Enter is bound to the
# check again at once. A plugin that rebinds Enter from a PROMPT_COMMAND
# entry that runs after shellfirm's (appended, or loaded later) would
# otherwise leave the first command of a new shell unchecked: the look
# before each prompt runs before that entry.
if ! builtin declare -F bind >/dev/null && [[ -z ${BASH_ALIASES[bind]+set} ]]; then
bind() {
    builtin bind "$@"
    local __sf_r=$? __sf_a __sf_l __sf_need=""
    for __sf_a in "$@"; do
        __sf_l=${__sf_a,,}
        case $__sf_l in
            -*[fru]*) [[ $__sf_l == -[a-z]* ]] && __sf_need=1 ;;
            *c-m*|*c-j*|*'\r'*|*'\n'*|*'\015'*|*'\012'*|*'\x0d'*|*'\x0a'*|*ret*|*lfd*|*newline*|*$'\r'*|*$'\n'*) __sf_need=1 ;;
        esac
    done
    [[ -n $__sf_need && -z ${__shellfirm_loading:-} ]] && __shellfirm_check_bindings
    return $__sf_r
}
fi
# `command fc` / `builtin fc` skip the checked `fc` above, also where the
# line checked on Enter does not show them (in a function, a variable,
# PROMPT_COMMAND or a trap). With the builtin turned off they cannot: bash
# hands `command fc ...` to command_not_found_handle, which runs the checked
# `fc` (in a subshell, as bash runs that handler), and `builtin fc` fails.
if builtin declare -F __shellfirm_bfc >/dev/null && builtin enable -n fc 2>/dev/null; then
    __shellfirm_fc_off=1
    if builtin declare -F command_not_found_handle >/dev/null; then
        __sf_f=$(builtin declare -f command_not_found_handle)
        builtin eval "__shellfirm_orig_cnfh ${__sf_f#command_not_found_handle}"
        unset __sf_f
    fi
    command_not_found_handle() {
        if [[ $1 == fc ]]; then
            builtin shift
            \fc "$@"
            return
        fi
        if builtin declare -F __shellfirm_orig_cnfh >/dev/null; then
            __shellfirm_orig_cnfh "$@"
            return
        fi
        builtin printf 'bash: %s: command not found\n' "$1" >&2
        return 127
    }
fi

else
__shellfirm_check_bindings() { :; }
# Fallback without readline: DEBUG trap (reads the command from history).
if [[ -n $(builtin trap -p DEBUG) ]]; then
    builtin printf '%s\n' "shellfirm: a DEBUG trap is already set; not installing the fallback hook (line editing is off)" >&2
else
__shellfirm_ready=""
__shellfirm_blocked=""
__shellfirm_histnum="__sf_none__"
__shellfirm_dbg_precmd() { __shellfirm_ready=1; __shellfirm_blocked=""; }
__shellfirm_dbg() {
    # extdebug implies functrace: never interfere with our own functions.
    [[ $BASH_COMMAND == __shellfirm_* || ${FUNCNAME[1]:-} == __shellfirm_* ]] && return 0
    if [[ -z $__shellfirm_ready ]]; then
        [[ -n $__shellfirm_blocked ]] && return 1
        return 0
    fi
    [[ -n ${COMP_LINE:-} ]] && return 0
    local __sf_h __sf_n __sf_cmd
    __sf_h=$(HISTTIMEFORMAT='' builtin history 1)
    __sf_n=${__sf_h#"${__sf_h%%[![:space:]]*}"}
    __sf_n=${__sf_n%%[[:space:]]*}
    [[ $__sf_n == "$__shellfirm_histnum" ]] && return 0
    __shellfirm_ready=""
    __shellfirm_histnum=$__sf_n
    __sf_cmd=${__sf_h#*[0-9][[:space:]]}
    __sf_cmd=${__sf_cmd#"${__sf_cmd%%[![:space:]]*}"}
    [[ -z $__sf_cmd ]] && return 0
    # bash 3.2 (macOS /bin/bash) always runs here (no readline mode): its
    # aliases and functions are expanded as Enter does in readline mode,
    # so `alias kd='kubectl delete'; kd ns prod` is checked as what runs.
    if (( BASH_VERSINFO[0] < 4 )); then
        __shellfirm_expand "$__sf_cmd"
        __sf_cmd=${__shellfirm_expanded:-$__sf_cmd}
    fi
    if ! __shellfirm_check "$__sf_cmd"; then
        __shellfirm_blocked=1
        return 1
    fi
    return 0
}
PROMPT_COMMAND="__shellfirm_dbg_precmd${PROMPT_COMMAND:+$'\n'$PROMPT_COMMAND}"
builtin shopt -s extdebug
builtin trap '__shellfirm_dbg' DEBUG
fi
fi

# `shellfirm doctor` runs this in a fresh interactive shell; run it in this
# shell to check the live state: `__shellfirm_doctor_probe | shellfirm doctor --stdin`
__shellfirm_doctor_probe() {
    builtin printf 'shell=bash\nshell_version=%s\nhook_version=%s\npid=%s\n' "$BASH_VERSION" "$__shellfirm_hook_version" "$$"
    if [[ ( -o emacs || -o vi ) && ${BASH_VERSINFO[0]:-0} -ge 4 ]]; then
        local __sf_bad __sf_first="" __sf_e
        if [[ -z $__shellfirm_legacy_checked ]]; then
            # A new shell (`shellfirm doctor`): what its first prompt does,
            # PROMPT_COMMAND included (a plugin can rebind Enter there, after
            # shellfirm's look; the first command would then not be checked).
            {
                if [[ $(builtin declare -p PROMPT_COMMAND 2>/dev/null) == "declare -a"* ]]; then
                    for __sf_e in "${PROMPT_COMMAND[@]}"; do builtin eval "$__sf_e"; done
                else
                    builtin eval "${PROMPT_COMMAND-}"
                fi
            } >/dev/null 2>&1
            __sf_first=$(__shellfirm_unbound_keys)
        fi
        # What the next prompt does: Enter rebound after shellfirm loaded is
        # wrapped again.
        __shellfirm_check_bindings 2>/dev/null
        __sf_bad=$(__shellfirm_unbound_keys)
        if [[ -n $__sf_first ]]; then
            builtin printf 'mode=readline\nenter=%s (rebound at the first prompt by a PROMPT_COMMAND entry that runs after shellfirm looks: the first command of a new shell is not checked)\n' "${__sf_first# }"
        else
            builtin printf 'mode=readline\nenter=%s\n' "${__sf_bad:-ok}"
        fi
        if [[ $(builtin bind -m emacs -q operate-and-get-next 2>/dev/null) == *'"\C-o"'* ]]; then
            builtin printf 'ctrl_o=unchecked\n'
        else
            builtin printf 'ctrl_o=ok\n'
        fi
    else
        builtin printf 'mode=debug-trap\nenter=n/a\n'
    fi
    [[ "${PROMPT_COMMAND[*]} ${precmd_functions[*]}" == *__shellfirm_precmd* || "${PROMPT_COMMAND[*]}" == *__shellfirm_dbg_precmd* ]] \
        && builtin printf 'precmd=ok\n' || builtin printf 'precmd=missing\n'
    [[ $(builtin type -t fc) == function && $(builtin declare -f fc) == *__shellfirm_fcedit* ]] \
        && builtin printf 'fc=ok\n' || builtin printf 'fc=unchecked\n'
    if [[ $(builtin enable -n -p 2>/dev/null) == *"enable -n fc"* ]]; then
        if [[ $(builtin declare -f command_not_found_handle 2>/dev/null) == *'\fc "$@"'* ]]; then
            builtin printf 'fc_builtin=off\n'
        else
            builtin printf 'fc_builtin=off-no-handler\n'
        fi
    else
        builtin printf 'fc_builtin=on\n'
    fi
    [[ -n $__shellfirm_rw_seen ]] && builtin printf 'rewrapped=%s\n' "${__shellfirm_rw_seen# }"
    [[ $(builtin trap -p DEBUG) == *_shellfirm_hook* ]] && builtin printf 'legacy_hook=active\n'
    [[ -n $__shellfirm_bypass_warned || -n ${__shellfirm_unchecked_seen:-} ]] && builtin printf 'bypass_seen=yes\n'
    __shellfirm_wrap_plugins
    local __sf_pl=""
    builtin declare -F __atuin_accept_line >/dev/null && __sf_pl+=" atuin:${__shellfirm_atuin_wrapped:+checked}"
    [[ -n ${bash_preexec_imported:-}${__bp_imported:-} ]] && __sf_pl+=" bash-preexec"
    builtin declare -F __fzf_select__ >/dev/null && __sf_pl+=" fzf"
    [[ -n ${BLE_VERSION:-} ]] && __sf_pl+=" ble.sh:unsupported"
    builtin declare -F starship_precmd >/dev/null && __sf_pl+=" starship"
    builtin printf 'plugins=%s\n' "${__sf_pl# }"
}
fi
"#;

/// zsh: wraps the accept-line family of ZLE widgets (one wrapper per widget,
/// chaining any existing user widget, installed once even when the rc file
/// is sourced again), routes Ctrl-R + Enter through it, and checks
/// `$PREBUFFER$BUFFER` once the command is complete, with aliases (also
/// global and suffix aliases), `r` / `fc` re-runs and small functions
/// expanded in every command of the line. `fc` / `r` typed later run
/// through a checking wrapper (an alias set at the first prompt).
const ZSH_HOOK: &str = r#"# shellfirm hook for zsh
if [[ -o interactive ]]; then
typeset -g _shellfirm_hook_version=13
# Lets `shellfirm doctor` tell whether the shell it runs in loaded the hook
# (SHELLFIRM_HOOK_LOAD changes at every load, also after `exec zsh`).
export SHELLFIRM_HOOK_PID=$$ SHELLFIRM_HOOK_LOAD=$$.$RANDOM$RANDOM
zmodload zsh/zleparameter zsh/parameter 2>/dev/null
typeset -gA _shellfirm_orig_widget
typeset -g _shellfirm_warned="" _shellfirm_seen="" _shellfirm_bypass_warned="" _shellfirm_expanded=""
typeset -g _shellfirm_notes="" _shellfirm_block_msg="" _shellfirm_trashed=""
typeset -ga _shellfirm_fc_ok
# Longer lines cannot be passed as one argument (Linux MAX_ARG_STRLEN is
# 128 KiB); they are checked through stdin instead and never prompt.
typeset -gi _shellfirm_max_arg=100000

# A message on a line of its own, also while a line is being edited (zle
# then redraws the prompt below it by itself).
_shellfirm_say() {
    if zle; then
        zle -I
        _shellfirm_trashed=1
    fi
    print -ru2 -- "$@"
}

_shellfirm_warn_missing() {
    [[ -n $_shellfirm_warned ]] && return 0
    _shellfirm_warned=1
    _shellfirm_say "shellfirm: binary not found in PATH; commands are NOT being checked"
}

# The command hash can point at a binary that was removed or moved.
_shellfirm_have_binary() {
    (( $+commands[shellfirm] )) && [[ -x ${commands[shellfirm]} ]] && return 0
    rehash
    (( $+commands[shellfirm] )) && [[ -x ${commands[shellfirm]} ]]
}

# shellfirm prints settings, policy and custom-check problems on every call.
# Look once per session (and again when SHELLFIRM_CONFIG_DIR changes), show
# them once on a line of their own, and from then on keep them away from
# safe lines (they would be glued to the line being edited).
_shellfirm_probe_notes() {
    [[ -n $_shellfirm_notes && $_shellfirm_notes_key == "${SHELLFIRM_CONFIG_DIR-}" ]] && return
    typeset -g _shellfirm_notes_key=${SHELLFIRM_CONFIG_DIR-}
    local _sf_w
    _sf_w=$(command shellfirm pre-command --test --command=: 2>&1 >/dev/null)
    # Not runnable: the check itself reports it.
    (( $? >= 126 )) && return
    [[ -n $_sf_w ]] && _shellfirm_say "$_sf_w"
    # A SHELLFIRM_CONFIG_DIR that is not a directory: said once (above);
    # the checks then use the default directory, as shellfirm itself does,
    # without saying it again on every line.
    if [[ -n $_sf_w ]] && _shellfirm_stale_dir; then
        _sf_w=$(SHELLFIRM_CONFIG_DIR= command shellfirm pre-command --test --command=: 2>&1 >/dev/null)
    fi
    if [[ -n $_sf_w ]]; then
        _shellfirm_notes=1
    else
        _shellfirm_notes=0
    fi
}
_shellfirm_stale_dir() { [[ -n ${SHELLFIRM_CONFIG_DIR//[[:space:]]/} && ! -d ${SHELLFIRM_CONFIG_DIR} ]] }

# Reads the input waiting on the terminal into _shellfirm_rest (Enter as a
# newline; control characters and bracketed-paste marks left out).
typeset -g _shellfirm_rest="" _shellfirm_rest_note=""
_shellfirm_drain() {
    setopt localoptions extendedglob
    local _sf_c _sf_r=""
    local -i _sf_n=0
    while (( PENDING > 0 && _sf_n++ < 65536 )); do
        read -k 1 _sf_c || break
        _sf_r+=$_sf_c
    done
    _sf_r=${_sf_r//$'\e[200~'/}
    _sf_r=${_sf_r//$'\e[201~'/}
    _sf_r=${_sf_r//$'\r'/$'\n'}
    _sf_r=${_sf_r//[$'\001'-$'\010\013'-$'\037\177']/}
    _sf_r=${_sf_r%%$'\n'##}
    [[ -n ${_sf_r//[[:space:]]/} ]] && _shellfirm_rest=$_sf_r
}
# "1 line" / "N lines" for _shellfirm_rest, in _sf_rn ("was" / "were" in
# _sf_rv, "it is" / "they are" in _sf_rp).
_shellfirm_rest_count() {
    setopt localoptions extendedglob
    local -a _sf_ls=("${(@f)_shellfirm_rest}")
    _sf_ls=(${_sf_ls:#[[:space:]]#})
    local -i _sf_k=${#_sf_ls}
    (( _sf_k )) || _sf_k=1
    if (( _sf_k == 1 )); then
        _sf_rn="1 line" _sf_rv=was _sf_rp="it is"
    else
        _sf_rn="$_sf_k lines" _sf_rv=were _sf_rp="they are"
    fi
}
# The line runs: what was read ahead of it goes back to the editor, for the
# next prompt (it is not run, and is checked when Enter runs it).
_shellfirm_give_back() {
    [[ -n $_shellfirm_rest ]] || return 0
    setopt localoptions extendedglob
    local _sf_rn _sf_rv _sf_rp
    _shellfirm_rest_count
    print -z -- "$_shellfirm_rest"
    _shellfirm_rest=""
    _shellfirm_rest_note="shellfirm: $_sf_rn typed or pasted after this command $_sf_rv not run (a challenge discards waiting input); $_sf_rp back in the editor."
}

# Returns 0 to allow, 1 to block. A missing binary fails open; anything else
# that goes wrong (exit 126, a line too long to pass) fails closed.
_shellfirm_run() {
    if ! _shellfirm_have_binary; then
        _shellfirm_warn_missing
        return 0
    fi
    # Keep ZLE (and the buffer) alive when ^C cancels the challenge.
    setopt localoptions localtraps
    trap ':' INT
    # Without interactivecomments (zsh's default) `#` starts no comment:
    # `rm -rf a # b` removes b too.
    [[ -o interactivecomments ]] || local -x SHELLFIRM_NO_COMMENTS=1
    local -i _sf_len _sf_rc
    local _sf_out
    () { setopt localoptions nomultibyte; _sf_len=${#1} } "$1"
    if (( _sf_len > _shellfirm_max_arg )); then
        _shellfirm_line=""
        print -rn -- "$1" | command shellfirm check --stdin --exit-code >/dev/null 2>&1
        _sf_rc=$?
        (( _sf_rc == 0 )) && return 0
        if (( _sf_rc == 127 )); then
            _shellfirm_say "shellfirm: warning: ${commands[shellfirm]} is installed but could not run (exit 127); this command was NOT checked. Run \`shellfirm doctor\`."
            return 0
        fi
        if (( _sf_rc == 10 || _sf_rc == 11 )); then
            _shellfirm_say "shellfirm: blocked: this line is too long to confirm interactively ($_sf_len bytes) and it matches a risky pattern. Run it from a script file instead."
        else
            _shellfirm_say "shellfirm: blocked: this line ($_sf_len bytes) could not be checked (exit $_sf_rc). Run it from a script file instead."
        fi
        return 1
    fi
    # In the line editor the "approved, running" line is printed from
    # preexec, once zle (and a transient prompt) has redrawn the line.
    local -a _sf_env=()
    if zle; then
        _shellfirm_probe_notes
        if [[ -n $_shellfirm_notes && $_shellfirm_notes_key == "${SHELLFIRM_CONFIG_DIR-}" ]] && _shellfirm_stale_dir; then
            local -x SHELLFIRM_CONFIG_DIR=
        fi
        _sf_env=(SHELLFIRM_DEFER_APPROVED=1)
        if [[ $_shellfirm_notes == 1 ]]; then
            # Dry run first (quietly): the warnings only show for risky lines.
            _sf_out=$(command shellfirm pre-command --test --command="$1" 2>/dev/null)
            _sf_rc=$?
            (( _sf_rc == 0 )) && [[ $_sf_out != *"skipped (below"* ]] && return 0
            zle -I
            _shellfirm_trashed=1
        fi
        # Input typed or pasted after this line (not as one bracketed
        # paste) that zle has not read yet: a challenge discards it (it
        # could answer the challenge). Unless the line is plainly safe, it is
        # read first, and given back to the editor (_shellfirm_give_back).
        if (( PENDING > 0 )); then
            if [[ $_shellfirm_notes != 1 ]]; then
                command shellfirm pre-command --test --command="$1" >/dev/null 2>&1
                _sf_rc=$?
            fi
            # 65: a challenge, 77: denied.
            (( _sf_rc == 65 || _sf_rc == 77 )) && _shellfirm_drain
        fi
    fi
    local -a _sf_la=()
    local _sf_shown=${_shellfirm_line:-$1}
    [[ -n $_shellfirm_line && $_shellfirm_line != "$1" ]] && _sf_la=(--line="$_shellfirm_line")
    _shellfirm_line=""
    if (( ${#_sf_env} )); then
        # Exit 3 after any passed challenge (also with approved_notice off):
        # the screen below the line is then put right (_shellfirm_below).
        SHELLFIRM_DEFER_APPROVED=1 SHELLFIRM_SIGNAL_PROMPTED=1 command shellfirm pre-command --direct-tty --command="$1" "${_sf_la[@]}"
    else
        command shellfirm pre-command --direct-tty --command="$1" "${_sf_la[@]}"
    fi
    _sf_rc=$?
    (( ${#_sf_env} && _sf_rc != 0 && _sf_rc != 127 )) && _shellfirm_below $(( _sf_rc == 3 ))
    case $_sf_rc in
        0) return 0 ;;
        3) _shellfirm_approved=$_sf_shown; return 0 ;;
        127) _shellfirm_say "shellfirm: warning: ${commands[shellfirm]} is installed but could not run (exit 127); this command was NOT checked. Run \`shellfirm doctor\`."; return 0 ;;
        126) _shellfirm_say "shellfirm: could not run shellfirm (exit 126); command not run"; return 1 ;;
        *) return 1 ;;
    esac
}

# The banner and the challenge were printed below the line zle drew, and
# zle does not know: drawing the line again (a paste highlight going away, a
# transient prompt, the kept line after a cancel) it would move up over the
# challenge and the typed answer. Move down as many rows as zle moves up, so
# it draws below the answer instead. $1 = 1 (approved): the answer's next
# row is saved, and preexec erases from there what zle draws again (as bash
# does), so the approved line comes right after the answer.
typeset -g _shellfirm_restore=""
_shellfirm_below() {
    [[ -t 2 && -n ${TERM-} && $TERM != dumb ]] || return 0
    setopt localoptions extendedglob
    local _sf_p=${(%)PS1} _sf_l
    _sf_p=${_sf_p//$'\e'\[[0-9;?]#[ -\/]#[@-~]/}
    _sf_p=${_sf_p//$'\e'\][^$'\a\e']#($'\a'|$'\e'\\)/}
    local -a _sf_pl=("${(@f)_sf_p}")
    local -i _sf_cols=${COLUMNS:-80} _sf_k _sf_n=0 _sf_w
    (( _sf_cols > 0 )) || _sf_cols=80
    # Rows above the cursor: the prompt's first lines, then its last line
    # with the text before the cursor (one more row per line than it
    # strictly needs, which only leaves a blank row).
    (( _sf_k = ${#_sf_pl} - 1 ))
    _sf_p=${_sf_pl[-1]}$LBUFFER
    for _sf_l in "${(@f)_sf_p}"; do
        _sf_w=${(m)#_sf_l}
        (( _sf_k += _sf_w / _sf_cols + 1 ))
    done
    (( _sf_k-- ))
    _sf_p=${_sf_pl[-1]}$BUFFER
    for _sf_l in "${(@f)_sf_p}"; do
        _sf_w=${(m)#_sf_l}
        (( _sf_n += _sf_w / _sf_cols + 1 ))
    done
    (( _sf_n += ${#_sf_pl} + 2 ))
    local _sf_s=""
    if [[ $1 == 1 ]]; then
        # Make room first (nothing scrolls after the row is saved), come
        # back, save the row, then go down.
        _sf_s=${(pl:_sf_n::\n:)}$'\e['$_sf_n$'A\e7'
        _shellfirm_restore=1
    fi
    (( _sf_k > 0 )) && _sf_s+=${(pl:_sf_k::\n:)}
    print -rnu2 -- "$_sf_s"
}

# Returns 0 when $1 is a complete command list that zsh would run now.
# Parsing it as a function body never executes anything.
_shellfirm_complete() {
    { functions[_shellfirm_probe]=$1 } 2>/dev/null
    (( $+functions[_shellfirm_probe] )) || return 1
    unfunction _shellfirm_probe
    local _sf_bs=${1##*[^\\]}
    if (( ${#_sf_bs} % 2 )); then
        # Trailing backslash: a line continuation unless quoted/commented.
        { functions[_shellfirm_probe]=$1$'\nfi' } 2>/dev/null
        if (( $+functions[_shellfirm_probe] )); then
            unfunction _shellfirm_probe
            return 1
        fi
        # After an operator (`a && \`) the probe above is a syntax error;
        # zsh's own word splitting tells a continuation from a comment.
        local -a _sf_ws
        if [[ -o interactivecomments ]]; then
            _sf_ws=("${(@Z+c+)1}")
        else
            _sf_ws=("${(@z)1}")
        fi
        _sf_bs=${_sf_ws[-1]##*[^\\]}
        [[ ${_sf_ws[-1]} != \#* ]] && (( ${#_sf_bs} % 2 )) && return 1
    fi
    return 0
}

# Parse the arguments of `fc` / `r` ($1 = fc or r). Sets the caller's
# _sf_how (rerun: `r`, `fc -e -`; edit: an editor runs; other: list, read,
# write or push history), _sf_ed, _sf_subs (old=new), _sf_sel (first [last])
# and _sf_rest (the arguments without `-e <editor>`).
_shellfirm_fc_args() {
    local _sf_a _sf_next=""
    _sf_how=edit _sf_ed=""
    _sf_subs=() _sf_sel=() _sf_rest=()
    [[ $1 == r ]] && _sf_how=rerun
    shift
    for _sf_a in "$@"; do
        if [[ -n $_sf_next ]]; then
            if [[ $_sf_next == e ]]; then
                _sf_ed=$_sf_a
                [[ $_sf_a == - && $_sf_how != other ]] && _sf_how=rerun
            else
                _sf_rest+=("$_sf_a")
            fi
            _sf_next=""
            continue
        fi
        case $_sf_a in
            -e) _sf_next=e; continue ;;
            -[mt]) _sf_next=x ;;
            -[0-9]*) _sf_sel+=("$_sf_a") ;;
            --) ;;
            -*[lLRWAPp]*) _sf_how=other ;;
            -*s*) [[ $_sf_how == other ]] || _sf_how=rerun ;;
            -*) ;;
            *=*) if (( ${#_sf_sel} )); then _sf_sel+=("$_sf_a"); else _sf_subs+=("$_sf_a"); fi ;;
            *) _sf_sel+=("$_sf_a") ;;
        esac
        _sf_rest+=("$_sf_a")
    done
}

# The commands a re-run (`r`, `fc -e -`) will run, in _sf_fc_out.
# _sf_fc_err: why zsh will refuse the re-run (no such event, an old=new
# that matches nothing), in zsh's words.
_shellfirm_fc_text() {
    setopt localoptions extendedglob
    local _sf_s _sf_first=${_sf_sel[1]:--1} _sf_subbed=""
    local _sf_last=${_sf_sel[2]:-$_sf_first}
    _sf_fc_err=""
    _sf_fc_out=$(builtin fc -ln "$_sf_first" "$_sf_last" 2>&1) || {
        # zsh prefixes the message with this function's name.
        _sf_fc_err=${${_sf_fc_out##*fc:}##<->:}
        _sf_fc_err=${_sf_fc_err##[[:space:]]#}
        _sf_fc_out=""
        return
    }
    _sf_fc_out=${_sf_fc_out##[[:space:]]#}
    for _sf_s in $_sf_subs; do
        [[ $_sf_fc_out == *"${_sf_s%%=*}"* ]] && _sf_subbed=1
        _sf_fc_out=${_sf_fc_out//"${_sf_s%%=*}"/${_sf_s#*=}}
    done
    (( ${#_sf_subs} )) && [[ -z $_sf_subbed ]] && _sf_fc_err="no substitutions performed"
}

# `fc` / `r` typed on the command line (an alias set up at the first prompt,
# so functions in rc files that use `fc -p -a` are not affected): re-runs
# and edited commands are checked before zsh runs them.
_shellfirm_fc() {
    local _sf_name=$1 _sf_how _sf_ed _sf_fc_out _sf_fc_err
    local -a _sf_subs _sf_sel _sf_rest
    shift
    _shellfirm_fc_args "$_sf_name" "$@"
    case $_sf_how in
        rerun)
            _shellfirm_fc_text
            # zsh's own message, without this wrapper's name in front of it.
            if [[ -n $_sf_fc_err ]]; then
                print -ru2 -- "fc: $_sf_fc_err"
                return 1
            fi
            if [[ -n ${_sf_fc_out//[[:space:]]/} ]] && (( ! ${_shellfirm_fc_ok[(Ie)$_sf_fc_out]} )); then
                _shellfirm_expand "$_sf_fc_out"
                if [[ -n $_shellfirm_expanded ]] && ! _shellfirm_run "$_shellfirm_expanded"; then
                    return 1
                fi
            fi
            # A command the re-run cannot find is reported in zsh's words,
            # not with this wrapper's name in front.
            if (( $+functions[command_not_found_handler] )); then
                builtin $_sf_name "$@"
            else
                {
                    command_not_found_handler() { print -ru2 -- "zsh: command not found: $1"; return 127 }
                    builtin $_sf_name "$@"
                } always {
                    unfunction command_not_found_handler 2>/dev/null
                }
            fi ;;
        edit)
            local _shellfirm_fc_editor=${_sf_ed:-${FCEDIT:-${EDITOR:-vi}}}
            builtin fc -e _shellfirm_fcedit "${_sf_rest[@]}" ;;
        *) builtin fc "$@" ;;
    esac
}

# The editor `fc` runs: the real editor, then a check of the edited text. A
# blocked edit is emptied, and zsh runs nothing when the editor fails.
_shellfirm_fcedit() {
    local _sf_f=$1 _sf_c
    eval "$_shellfirm_fc_editor"' "$_sf_f"' || return
    _sf_c=$(<$_sf_f)
    [[ -z ${_sf_c//[[:space:]]/} ]] && return 0
    _shellfirm_expand "$_sf_c"
    [[ -z $_shellfirm_expanded ]] && return 0
    _shellfirm_run "$_shellfirm_expanded" && return 0
    : >| $_sf_f
    return 1
}

typeset -gi _shellfirm_depth=0
# What separates the words that can name a function: blanks, control
# characters and ASCII punctuation other than `_ : . @ + -`. Any other
# character (`nettoyé`, `日本`) can be part of a function name.
typeset -g _shellfirm_nonname='[]!#"$%&'\''()*,/;<=>?[\\^`{|}~[:space:][:cntrl:]]'
# Variables assigned on the line being checked; functions expanded for it.
typeset -gA _shellfirm_assigned
typeset -ga _shellfirm_fn_seen
typeset -g _shellfirm_vv="" _shellfirm_fb="" _shellfirm_fb_big="" _shellfirm_line="" _shellfirm_ol=""
typeset -g _shellfirm_defs="" _shellfirm_defs_extra="" _shellfirm_expanded_extra=""
typeset -gi _shellfirm_defs_n=0 _shellfirm_defs_bytes=0
typeset -ga _shellfirm_reach

# The value of variable $1 (in _shellfirm_vv): from an assignment earlier on
# the line being checked, else from this session.
_shellfirm_var_value() {
    _shellfirm_vv=""
    if (( ${+_shellfirm_assigned[$1]} )); then
        _shellfirm_vv=${_shellfirm_assigned[$1]}
    elif (( ${+parameters[$1]} )); then
        _shellfirm_vv="${(P)1}"
    fi
}

# The body of the function $1 when it is worth checking with a call (in
# _shellfirm_fb): a small function that is not shellfirm's. A function that
# is autoloaded but not loaded yet (`autoload -Uz nuke`) is read from its
# file (zsh's own functions, under .../share/zsh/, are left out).
_shellfirm_fn_body() {
    _shellfirm_fb=""
    (( $+functions[$1] )) || return 1
    local _sf_b=${functions[$1]} _sf_d _sf_f=""
    if [[ $_sf_b == builtin\ autoload\ -X* ]]; then
        _sf_f=${functions_source[$1]-}
        if [[ -z $_sf_f ]]; then
            for _sf_d in $fpath; do
                [[ -f $_sf_d/$1 && -r $_sf_d/$1 ]] && { _sf_f=$_sf_d/$1; break; }
            done
        fi
        [[ -n $_sf_f && $_sf_f != */share/zsh/* && -f $_sf_f && -r $_sf_f ]] || return 1
        _sf_b=$(<$_sf_f) 2>/dev/null || return 1
    fi
    _shellfirm_fb_big=""
    (( ${#_sf_b} > 0 )) || return 1
    [[ $_sf_b == *_shellfirm_* ]] && return 1
    if (( ${#_sf_b} > 16000 )); then
        # Loaded from a file: like a program on PATH (see _shellfirm_fn_defs).
        [[ -n $_sf_f || -f ${functions_source[$1]-} ]] || _shellfirm_from_file $1 || _shellfirm_fb_big=1
        return 1
    fi
    _shellfirm_fb=$_sf_b
}

# Functions loaded from a file in a way their source does not show: a
# relative path (`source ./nvm.sh`: zsh keeps it as written, which no longer
# resolves after a `cd`) and `source <(cat FILE)` (/proc/self/fd/N). Noted
# at the prompt after such a line (and at the first prompt, after the rc
# files); name -> "rel:<source>" or "cat:<body>" (the same name defined
# again from somewhere else does not count).
typeset -gA _shellfirm_srcfns
typeset -g _shellfirm_srcnote="" _shellfirm_catsrc=""
_shellfirm_from_file() {
    local _sf_v=${_shellfirm_srcfns[$1]-} _sf_s=${functions_source[$1]-}
    case $_sf_v in
        (rel:*) [[ -n $_sf_s && ${_sf_v#rel:} == "$_sf_s" ]] ;;
        (cat:*) [[ $_sf_s == (/proc/*|/dev/fd/*) && ${_sf_v#cat:} == "${functions[$1]}" ]] ;;
        (*) return 1 ;;
    esac
}
# The line $1 sources a file: look at the next prompt.
_shellfirm_src_line() {
    setopt localoptions extendedglob nobashrematch norematchpcre
    [[ $1 == (|*[\;\&\|\(\{[:space:]])(source|.)[[:space:]]* ]] || return 0
    _shellfirm_srcnote=1
    local _sf_re='^[[:space:]]*(source|\.)[[:space:]]+<\([[:space:]]*cat[[:space:]]+([^][:space:];&|()<>`$'"'"'"\\*?[{}]+)[[:space:]]*\)[[:space:]]*$'
    if [[ $1 =~ $_sf_re ]]; then
        _shellfirm_catsrc=${match[2]}
        [[ $_shellfirm_catsrc == '~/'* ]] && _shellfirm_catsrc=$HOME/${_shellfirm_catsrc#'~/'}
    fi
}
_shellfirm_note_src() {
    local _sf_n _sf_s _sf_f=$_shellfirm_catsrc
    _shellfirm_srcnote="" _shellfirm_catsrc=""
    (( ${+functions_source} )) || return 0
    [[ -n $_sf_f && -f $_sf_f ]] || _sf_f=""
    for _sf_n _sf_s in "${(@kv)functions_source}"; do
        [[ $_sf_n == _shellfirm* || -z $_sf_s ]] && continue
        case $_sf_s in
            (/proc/*|/dev/fd/*)
                [[ -n $_sf_f ]] && (( ${#functions[$_sf_n]} > 16000 && ${#_shellfirm_srcfns} < 256 )) \
                    && _shellfirm_srcfns[$_sf_n]="cat:${functions[$_sf_n]}" ;;
            (/*) ;;
            (*)
                [[ ${_shellfirm_srcfns[$_sf_n]-} == "rel:$_sf_s" ]] && continue
                [[ -f $_sf_s || ( -n ${OLDPWD-} && -f $OLDPWD/$_sf_s ) ]] && (( ${#_shellfirm_srcfns} < 4096 )) \
                    && _shellfirm_srcfns[$_sf_n]="rel:$_sf_s" ;;
        esac
    done
}

# A function body as one line, which is how the check reads a definition.
# A here-document cannot be joined: that body stays as it is (its commands
# are then read as written, `$1` unknown). Sets _shellfirm_ol.
_shellfirm_one_line() {
    setopt localoptions extendedglob
    _shellfirm_ol=$1
    [[ ${1//<<</} == *'<<'* ]] && return
    local _sf_l _sf_o=""
    for _sf_l in "${(@f)1}"; do
        _sf_l=${${_sf_l##[[:space:]]#}%%[[:space:]]#}
        [[ -z $_sf_l ]] && continue
        case $_sf_o in
            (''|*'{'|*'('|*';'|*'|'|*'&'|then|*[[:space:]]then|do|*[[:space:]]do|else|*[[:space:]]else|*[[:space:]]in) _sf_o+=" $_sf_l" ;;
            (*) _sf_o+="; $_sf_l" ;;
        esac
    done
    _shellfirm_ol=${_sf_o# }
}

# The functions named in $1 (and those their bodies name, and so on), each
# once, are sent ahead of the line as definitions (`name() { body; }`): the
# check binds every call's arguments itself (`shift`, `"$@"`, any depth),
# so what it reads is what runs. A body that rewrites its arguments in a way
# the check does not follow (`set --`, `argv=`, `getopts`, `shift` in a
# loop) is also added as written, where its `$1` counts as unknown. Past the
# budget (64 functions, 64 KB, 16 KB for one body) the rest is not read: a
# marker says so (shell:function_depth_limit), so nothing is skipped
# silently. A function over 16 KB loaded from a file (nvm, sdkman, conda) is
# treated like a program on PATH: its arguments are checked, its body is not
# read (no marker); one typed or pasted into the session gets the marker.
# Appends to _shellfirm_defs and _shellfirm_defs_extra.
_shellfirm_fn_defs() {
    setopt localoptions extendedglob
    local IFS=$' \t\n' _sf_todo=$1 _sf_w _sf_fb _sf_saved
    local -a _sf_ws
    while [[ -n $_sf_todo ]]; do
        _sf_ws=(${=_sf_todo//${~_shellfirm_nonname}/ })
        _sf_todo=""
        for _sf_w in $_sf_ws; do
            [[ $_sf_w == (_shellfirm*|[0-9.+-]*) ]] && continue
            (( $+functions[$_sf_w] )) || continue
            (( ${_shellfirm_fn_seen[(Ie)$_sf_w]} )) && continue
            _shellfirm_fn_seen+=($_sf_w)
            if ! _shellfirm_fn_body $_sf_w; then
                [[ -n $_shellfirm_fb_big ]] && _shellfirm_defs_extra+=$'\n'"shellfirm-function-depth-limit $_sf_w # a function too large for the hook to read ahead"
                continue
            fi
            _sf_fb=$_shellfirm_fb
            if (( ++_shellfirm_defs_n > 64 || _shellfirm_defs_bytes + ${#_sf_fb} > 64000 )); then
                _shellfirm_defs_extra+=$'\n'"shellfirm-function-depth-limit $_sf_w # calls more functions than the hook reads ahead"
                return
            fi
            (( _shellfirm_defs_bytes += ${#_sf_fb} ))
            _shellfirm_one_line "$_sf_fb"
            _shellfirm_defs+=$'\n'"$_sf_w() { $_shellfirm_ol; }"
            if [[ $_sf_fb =~ '(^|[[:space:];&|({])(set[[:space:]]+(--|-A[[:space:]]+argv|[^-+[:space:]])|getopts[[:space:]]|OPTIND|argv(\[[^]]*\])?\+?=)' ]] \
                || [[ $_sf_fb == *shift* && $_sf_fb =~ '(^|[[:space:];&|({])(while|until|for|foreach|select|repeat)[[:space:]]' ]]; then
                _shellfirm_defs_extra+=$'\n'"{ $_sf_fb }"
            fi
            # What the body runs that the check cannot see by itself
            # (`$K delete ...` with K from this session, `r`, aliases
            # resolved at definition), not the body itself.
            _sf_saved=$_shellfirm_expanded
            (( _shellfirm_depth++ ))
            _shellfirm_expand "$_sf_fb"
            (( _shellfirm_depth-- ))
            _shellfirm_defs_extra+=$_shellfirm_expanded_extra
            _shellfirm_expanded=$_sf_saved
            _sf_todo+=" $_sf_fb"
        done
    done
}

# Functions that run by themselves (the *_functions hook arrays, zle
# widgets, traps, zsh's hook function names) and the functions they name,
# however deep: in _shellfirm_reach (computed once per check).
_shellfirm_hook_reach() {
    setopt localoptions extendedglob
    local _sf_roots="$precmd_functions $preexec_functions $chpwd_functions $periodic_functions $zshexit_functions $zshaddhistory_functions $zsh_directory_name_functions"
    local _sf_v
    for _sf_v in ${(v)widgets}; do
        [[ $_sf_v == user:* ]] && _sf_roots+=" ${_sf_v#user:}"
    done
    _sf_roots+=" ${(k)functions[(I)(precmd|preexec|chpwd|periodic|zshexit|zshaddhistory|TRAP*)]}"
    _sf_roots+=" $(trap 2>/dev/null)"
    _shellfirm_reach=()
    local -a _sf_ws _sf_todo
    local _sf_w _sf_t=$_sf_roots
    local -i _sf_n=0
    while [[ -n $_sf_t ]] && (( _sf_n < 256 )); do
        _sf_ws=(${=_sf_t//${~_shellfirm_nonname}/ })
        _sf_t=""
        for _sf_w in $_sf_ws; do
            [[ $_sf_w == (_shellfirm*|azhw:*|[0-9.+-]*) ]] && continue
            (( $+functions[$_sf_w] )) || continue
            (( ${_shellfirm_reach[(Ie)$_sf_w]} )) && continue
            _shellfirm_reach+=($_sf_w)
            (( ++_sf_n < 256 )) || break
            _sf_t+=" ${functions[$_sf_w]}"
        done
    done
}

# The commands a mistyped command name $1 is one edit away from (what
# CORRECT offers: a swapped, missing, extra or wrong character).
_shellfirm_spell_candidates() {
    local _sf_w=$1 _sf_c _sf_x
    local -i _sf_i _sf_n=${#1}
    local -aU _sf_out
    (( _sf_n >= 2 && _sf_n <= 32 )) || return 0
    local -a _sf_al=({a..z} {0..9} - _ .)
    for (( _sf_i = 1; _sf_i <= _sf_n; _sf_i++ )); do
        _sf_x=${_sf_w[1,_sf_i-1]}${_sf_w[_sf_i+1,-1]}
        (( $+commands[$_sf_x] )) && _sf_out+=($_sf_x)
        if (( _sf_i < _sf_n )); then
            _sf_x=${_sf_w[1,_sf_i-1]}${_sf_w[_sf_i+1]}${_sf_w[_sf_i]}${_sf_w[_sf_i+2,-1]}
            (( $+commands[$_sf_x] )) && _sf_out+=($_sf_x)
        fi
        for _sf_c in $_sf_al; do
            _sf_x=${_sf_w[1,_sf_i-1]}$_sf_c${_sf_w[_sf_i+1,-1]}
            (( $+commands[$_sf_x] )) && _sf_out+=($_sf_x)
            _sf_x=${_sf_w[1,_sf_i-1]}$_sf_c${_sf_w[_sf_i,-1]}
            (( $+commands[$_sf_x] )) && _sf_out+=($_sf_x)
        done
    done
    for _sf_c in $_sf_al; do
        (( $+commands[$_sf_w$_sf_c] )) && _sf_out+=($_sf_w$_sf_c)
    done
    print -r -- ${_sf_out[1,8]}
}

# Expand what zsh expands before it runs a line, in every command of it
# (after ; && || | ( { ! time and assignments): aliases, global and suffix
# aliases, `r` / `fc -e -` re-runs (also `builtin fc`) and small functions.
# Sets _shellfirm_expanded ("" = nothing to check).
_shellfirm_expand() {
    setopt localoptions extendedglob
    local _sf_cmd=${1//$'\\\n'/} _sf_w _sf_v _sf_name _sf_kw="" _sf_extra="" _sf_head _sf_tail _sf_nh
    local _sf_how _sf_ed _sf_fc_out _sf_fc_err _sf_body _sf_p _sf_saved _sf_dn
    local -a _sf_words _sf_fargs _sf_subs _sf_sel _sf_rest _sf_av _sf_subst _sf_hookw _sf_hookb
    local -aU _sf_auto
    local -i _sf_i _sf_k _sf_j _sf_cmdpos=1 _sf_changed=0 _sf_nf=0 _sf_nfc=0 _sf_whole=0
    local -i _sf_indef=0 _sf_defnext=0 _sf_skip=0 _sf_hook=0 _sf_pre=0 _sf_reach=0
    _shellfirm_expanded="" _shellfirm_expanded_extra=""
    if (( ! _shellfirm_depth )); then
        _shellfirm_assigned=()
        _shellfirm_fn_seen=()
        _shellfirm_defs="" _shellfirm_defs_extra="" _shellfirm_defs_n=0 _shellfirm_defs_bytes=0
    fi
    _sf_words=(${(z)_sf_cmd})
    # Functions that run by themselves once this line has run (zsh hook
    # functions, `zle -N` widgets, `add-zsh-hook`, the *_functions arrays):
    # their bodies are checked now, like a PROMPT_COMMAND or a trap.
    if [[ $_sf_cmd == *(zle|add-zsh-hook|_functions|functions\[|PROMPT|PS[1-4]|RPS[12]|trap)* ]]; then
        for (( _sf_k = 1; _sf_k <= ${#_sf_words} && _sf_k <= 4000; _sf_k++ )); do
            case ${_sf_words[_sf_k]} in
                zle)
                    if [[ ${_sf_words[_sf_k+1]-} == -N ]]; then
                        _sf_v=${_sf_words[_sf_k+3]-}
                        [[ -z $_sf_v || $_sf_v == [\;\&\|\)\}]* ]] && _sf_v=${_sf_words[_sf_k+2]-}
                        _sf_auto+=(${(Q)_sf_v})
                    fi ;;
                add-zsh-hook)
                    _sf_j=$(( _sf_k + 1 ))
                    while [[ ${_sf_words[_sf_j]-} == -[^d]* ]]; do (( _sf_j++ )); done
                    [[ ${_sf_words[_sf_j]-} != -d* && -n ${_sf_words[_sf_j+1]-} ]] && _sf_auto+=(${(Q)_sf_words[_sf_j+1]}) ;;
                trap)
                    # `trap f SIG` / `trap 'cmd' SIG`: runs on the signal.
                    _sf_v=${(Q)_sf_words[_sf_k+1]-}
                    if [[ -n $_sf_v && $_sf_v != -* && -n ${_sf_words[_sf_k+2]-} ]]; then
                        if (( $+functions[$_sf_v] )); then _sf_auto+=($_sf_v); else _sf_hookb+=("$_sf_v"); fi
                    fi ;;
                functions\[(precmd|preexec|chpwd|periodic|zshexit|zshaddhistory|zsh_directory_name|command_not_found_handler|TRAP[A-Z0-9]##)\]=*)
                    # A hook function defined through the functions array.
                    _sf_hookb+=("${(Q)_sf_words[_sf_k]#*=}") ;;
                (PROMPT|RPROMPT|PS[1-4]|RPS[12]|PROMPT[234]|RPROMPT2)=*)
                    # A prompt runs its command substitutions (prompt_subst).
                    _sf_v=${(Q)_sf_words[_sf_k]#*=}
                    [[ $_sf_v == *('$('|'`')* ]] && _sf_hookb+=("$_sf_v") ;;
                (precmd|preexec|chpwd|periodic|zshexit|zshaddhistory|zsh_directory_name)_functions(\[*\]|)(|+)=\(*)
                    for (( _sf_j = _sf_k + 1; _sf_j <= ${#_sf_words}; _sf_j++ )); do
                        [[ ${_sf_words[_sf_j]} == ')' ]] && break
                        _sf_auto+=(${(Q)_sf_words[_sf_j]})
                    done ;;
                (precmd|preexec|chpwd|periodic|zshexit|zshaddhistory|zsh_directory_name)_functions(\[*\]|)(|+)=?*)
                    # One element (`precmd_functions[1]=f`, `+=f`).
                    _sf_auto+=(${(Q)_sf_words[_sf_k]#*=}) ;;
            esac
        done
    fi
    for (( _sf_i = 1; _sf_i <= ${#_sf_words} && _sf_i <= 4000; _sf_i++ )); do
        _sf_w=${_sf_words[_sf_i]}
        if [[ -o aliases && -n ${galiases[$_sf_w]-} ]]; then
            _sf_words[_sf_i]=${galiases[$_sf_w]}
            _sf_w=${_sf_words[_sf_i]}
            _sf_changed=1
        fi
        # Command substitutions (`$( )`, backticks, `<( )`) run commands of
        # their own: expanded like a line of their own.
        if [[ $_sf_w == *('$('|'`'|'<('|'>(')* && $_sf_w != \'* ]] && (( ${#_sf_subst} < 8 )); then
            _sf_subst+=("$_sf_w")
        fi
        # A function definition (`f() { ... }`, `function f { ... }`) runs
        # nothing: its body is checked when it is called.
        if (( _sf_defnext || _sf_indef )); then
            case $_sf_w in
                '{') (( _sf_indef++ )); _sf_defnext=0 ;;
                '}') (( _sf_indef > 0 )) && (( _sf_indef-- )) ;;
            esac
            # The body of a function that runs by itself, as a `{ ... }` group.
            if (( _sf_hook && ( _sf_indef > 0 || ! _sf_defnext ) )); then
                _sf_hookw+=("$_sf_w")
                if (( ! _sf_indef )); then
                    _sf_hookb+=("${(j: :)_sf_hookw}")
                    _sf_hook=0 _sf_hookw=()
                fi
            fi
        fi
        if (( _sf_cmdpos && ! _sf_indef && ! _sf_defnext )); then
            if [[ $_sf_w == function && -z $_sf_kw ]] || [[ ${_sf_words[_sf_i+1]-} == '()' && $_sf_w != [\;\&\|\(\)\{\}]* ]]; then
                _sf_defnext=1
                if [[ $_sf_w == function ]]; then _sf_dn=${(Q)_sf_words[_sf_i+1]-}; else _sf_dn=${(Q)_sf_w}; fi
                # A function that runs by itself, also one registered
                # earlier (`add-zsh-hook precmd g`, `zle -N w`) and the
                # functions those call: its new body is checked now.
                (( _sf_reach || _shellfirm_depth )) || { _sf_reach=1; _shellfirm_hook_reach; }
                if [[ $_sf_dn == (precmd|preexec|chpwd|periodic|zshexit|zshaddhistory|zsh_directory_name|command_not_found_handler|TRAP[A-Z0-9]##) ]] || (( ${_sf_auto[(Ie)$_sf_dn]} )) \
                    || (( ! _shellfirm_depth && ${_shellfirm_reach[(Ie)$_sf_dn]} )); then
                    _sf_hook=1 _sf_hookw=()
                    _sf_auto=(${_sf_auto:#$_sf_dn})
                fi
            fi
        fi
        case $_sf_w in
            ';'|'&&'|'||'|'|'|'|&'|'&'|'&!'|'&|'|'('|')'|'{'|'}'|';;'|';&'|';|'|'!'|then|do|else|elif|if|while|until|time|nocorrect|noglob|coproc|'()')
                _sf_cmdpos=1 _sf_kw="" _sf_skip=0 _sf_pre=0
                continue ;;
        esac
        (( _sf_cmdpos )) || continue
        if (( _sf_skip )); then
            _sf_skip=0
            continue
        fi
        # Variable assignments before the command name (remembered: a later
        # `$name` in command position runs that value).
        if [[ -z $_sf_kw && $_sf_w == [[:alpha:]_][[:alnum:]_]#=* ]]; then
            [[ $_sf_w == *=\(* ]] || _shellfirm_assigned[${_sf_w%%=*}]=${(Q)_sf_w#*=}
            _sf_pre=1
            continue
        fi
        # A redirection before the command (`>/dev/null kd ...`).
        if [[ $_sf_w == [0-9]#(\<|\>|\>\>|\<\<\<|\>\||\>\!|\<\>|\&\>|\&\>\>|\>\&|\<\&)* ]]; then
            _sf_pre=1
            [[ $_sf_w == [0-9]#(\<|\>|\>\>|\<\<\<|\>\||\>\!|\<\>|\&\>|\&\>\>|\>\&|\<\&) ]] && _sf_skip=1
            continue
        fi
        case $_sf_w in
            builtin|command|exec|-)
                [[ -z $_sf_kw ]] && { _sf_kw=$_sf_w; continue; } ;;
            repeat)
                # `repeat N cmd`: the count, then the command.
                [[ -z $_sf_kw ]] && { _sf_skip=1; continue; } ;;
        esac
        _sf_cmdpos=0
        (( _sf_indef || _sf_defnext )) && { _sf_kw=""; continue; }
        _sf_name=${(Q)_sf_w}
        if [[ -z $_sf_kw && -o aliases && -n ${aliases[$_sf_w]-} && ${aliases[$_sf_w]} != _shellfirm_fc\ * ]]; then
            _sf_head=$_sf_w _sf_tail=""
            for (( _sf_k = 0; _sf_k < 5; _sf_k++ )); do
                _sf_v=${aliases[$_sf_head]-}
                [[ -n $_sf_v ]] || break
                _sf_v=${_sf_v##[[:space:]]#}
                _sf_nh=${_sf_v%%[[:space:]]*}
                _sf_tail=${_sf_v#"$_sf_nh"}$_sf_tail
                # `alias ls='ls -G'`: zsh does not expand an alias inside itself.
                [[ $_sf_nh == $_sf_head ]] && break
                _sf_head=$_sf_nh
            done
            _sf_words[_sf_i]=$_sf_head$_sf_tail
            _sf_name=$_sf_head
            _sf_changed=1
            # An alias ending in a space also expands the next word.
            [[ $_sf_tail == *[[:space:]] ]] && _sf_cmdpos=1
        elif [[ -z $_sf_kw && -o aliases && $_sf_w == *.[^./]## && -n ${saliases[${_sf_w:e}]-} ]]; then
            # Suffix alias: `alias -s d='rm -rf'` makes `build.d` run `rm -rf build.d`.
            _sf_words[_sf_i]="${saliases[${_sf_w:e}]} $_sf_w"
            _sf_name=${${saliases[${_sf_w:e}]}%%[[:space:]]*}
            _sf_changed=1
        fi
        # The arguments of this command (up to the next control operator).
        _sf_fargs=()
        for (( _sf_k = _sf_i + 1; _sf_k <= ${#_sf_words} && _sf_k <= _sf_i + 64; _sf_k++ )); do
            case ${_sf_words[_sf_k]} in
                ';'|'&&'|'||'|'|'|'|&'|'&'|'&!'|'&|'|')'|'}'|';;') break ;;
            esac
            _sf_fargs+=("${(Q)_sf_words[_sf_k]}")
        done
        # A command named by a variable (`$K delete ...`, `${K}`, `${(P)n}`):
        # its value from earlier on this line, else from this session.
        if [[ -z $_sf_kw && $_sf_w == \$([[:alpha:]_][[:alnum:]_]#|\{(\(P\)|)[[:alpha:]_][[:alnum:]_]#\}) ]] && (( _shellfirm_depth < 3 )); then
            _sf_v=${${${_sf_w#\$}#\{}%\}}
            _shellfirm_var_value "${_sf_v#'(P)'}"
            if [[ $_sf_v == '(P)'* ]]; then
                _sf_v=$_shellfirm_vv
                _shellfirm_vv=""
                [[ $_sf_v == [[:alpha:]_][[:alnum:]_]# ]] && _shellfirm_var_value "$_sf_v"
            fi
            _sf_p=$_shellfirm_vv
            if [[ -n ${_sf_p//[[:space:]]/} && $_sf_p != *_shellfirm* ]] && (( ${#_sf_p} <= 4000 )); then
                _sf_saved=$_shellfirm_expanded
                (( _shellfirm_depth++ ))
                _shellfirm_expand "$_sf_p${_sf_fargs:+ ${(j: :)${(@q-)_sf_fargs}}}"
                (( _shellfirm_depth-- ))
                [[ -n $_shellfirm_expanded ]] && _sf_extra+=$'\n'$_shellfirm_expanded
                _shellfirm_expanded=$_sf_saved
            fi
        fi
        # CORRECT / CORRECT_ALL: zsh offers to correct a mistyped command
        # name (`kubeclt` -> `kubectl`) after this check. Check the
        # commands it could be corrected to as well.
        if [[ ( -o correct || -o correctall ) && -z $_sf_kw && $_sf_name != */* && -n $_sf_name ]] \
            && (( ! $+commands[$_sf_name] && ! $+aliases[$_sf_name] && ! $+functions[$_sf_name] && ! $+builtins[$_sf_name] && ! $+reswords[$_sf_name] )); then
            for _sf_p in $(_shellfirm_spell_candidates "$_sf_name"); do
                _sf_extra+=$'\n'"$_sf_p ${(j: :)${(@qq)_sf_fargs}}"
            done
        fi
        if [[ ( $_sf_name == fc || ( $_sf_name == r && ( -z $_sf_kw || $_sf_kw == builtin ) ) ) ]] && (( _sf_nfc < 8 )) \
            && (( ! $+functions[$_sf_name] || ${+aliases[$_sf_name]} )) || [[ $_sf_kw == builtin && $_sf_name == (fc|r) ]]; then
            (( _sf_nfc++ ))
            _shellfirm_fc_args "$_sf_name" "${_sf_fargs[@]}"
            if [[ $_sf_how == rerun ]]; then
                _shellfirm_fc_text
                if [[ -n $_sf_fc_out ]]; then
                    _shellfirm_fc_ok+=("$_sf_fc_out")
                    # The whole line is the re-run: check (and show) just that.
                    if (( _sf_i <= 2 && _sf_k > ${#_sf_words} && ! _sf_changed )); then
                        _sf_whole=1
                        _sf_cmd=$_sf_fc_out
                    else
                        _sf_extra+=$'\n'$_sf_fc_out
                    fi
                fi
            elif [[ $_sf_how == edit && ( -n $_sf_kw || $_sf_w == \\* ) ]]; then
                _shellfirm_block_msg="shellfirm: \`${_sf_kw:+$_sf_kw }$_sf_w\` with an editor runs the edited commands without a check; use \`fc\` instead. Command not run."
            fi
        elif [[ -z $_sf_kw && $_sf_name != _shellfirm* ]] && (( $+functions[$_sf_name] )); then
            # A call of a function: its definition is sent with the line
            # (_shellfirm_fn_defs). After assignments or a redirection
            # (`A=1 f x`) the bare call too, which the check binds to it.
            (( _sf_pre )) && _sf_extra+=$'\n'"$_sf_name ${(j: :)${(@q-)_sf_fargs}}"
        elif [[ $_sf_name == eval && -z $_sf_kw ]] && (( ${#_sf_fargs} && _shellfirm_depth < 3 )); then
            # The text `eval` runs (`eval 'builtin fc -e - a=b x'`), expanded
            # and checked like a typed line.
            _sf_saved=$_shellfirm_expanded
            (( _shellfirm_depth++ ))
            _shellfirm_expand "${(j: :)_sf_fargs}"
            (( _shellfirm_depth-- ))
            [[ -n $_shellfirm_expanded ]] && _sf_extra+=$'\n'$_shellfirm_expanded
            _shellfirm_expanded=$_sf_saved
        fi
        _sf_kw=""
    done
    # Command substitutions: the commands inside them.
    if (( ${#_sf_subst} && _shellfirm_depth < 3 )); then
        _sf_saved=$_shellfirm_expanded
        (( _shellfirm_depth++ ))
        for _sf_w in $_sf_subst; do
            _sf_v=${_sf_w#*(\$\(|\`|\<\(|\>\()}
            _sf_v=${_sf_v%(\)|\`)*}
            [[ -n ${_sf_v//[[:space:]]/} ]] || continue
            _shellfirm_expand "$_sf_v"
            [[ -n $_shellfirm_expanded && $_shellfirm_expanded != $_sf_v ]] && _sf_extra+=$'\n'$_shellfirm_expanded
        done
        (( _shellfirm_depth-- ))
        _shellfirm_expanded=$_sf_saved
    fi
    # Functions that run by themselves: the bodies defined on this line, and
    # those of functions this line registers that are already defined.
    for _sf_v in ${_sf_auto:#_shellfirm*}; do
        _shellfirm_fn_body "$_sf_v" && _sf_hookb+=("{ $_shellfirm_fb }")
    done
    if (( ${#_sf_hookb} && _shellfirm_depth < 3 )); then
        _sf_saved=$_shellfirm_expanded
        (( _shellfirm_depth++ ))
        for _sf_v in ${_sf_hookb[1,8]}; do
            _shellfirm_expand "$_sf_v"
            _sf_extra+=$'\n'${_shellfirm_expanded:-$_sf_v}
        done
        (( _shellfirm_depth-- ))
        _shellfirm_expanded=$_sf_saved
    fi
    (( _sf_changed && ! _sf_whole )) && _sf_cmd=${(j: :)_sf_words}
    # Only adds text to history: nothing runs.
    if [[ $_sf_cmd == [[:space:]]#(builtin[[:space:]]##|)print[[:space:]]##-[sS][[:space:]]* && $_sf_cmd != *[\;\|\&\`\$\(\)\<\>$'\n']* ]]; then
        return
    fi
    _shellfirm_expanded_extra=$_sf_extra
    if (( ! _shellfirm_depth )); then
        # The definitions of the functions the line (and what it adds)
        # names, ahead of it.
        _shellfirm_fn_defs "$_sf_cmd$_sf_extra"
        _shellfirm_expanded=${_shellfirm_defs#$'\n'}${_shellfirm_defs:+$'\n'}$_sf_cmd$_sf_extra$_shellfirm_defs_extra
        # What the banner and the audit log show: the line as typed
        # (aliases and re-runs resolved), not the definitions.
        _shellfirm_line=$_sf_cmd
    else
        _shellfirm_expanded=$_sf_cmd$_sf_extra
    fi
}

# Blocked: a single line stays in the buffer; a multi-line construct is
# pulled back into one editable buffer. (After `zle -I` zle redraws by
# itself; a reset-prompt would overwrite the message above it.)
_shellfirm_keep_line() {
    # The same words as in bash (the challenge already said "command not
    # run"). A multi-line construct comes back as one buffer: Ctrl-U would
    # only clear its last line.
    local _sf_msg="shellfirm: the line is kept for editing (Ctrl-U clears it)." _sf_rn _sf_rv _sf_rp
    # Ctrl-U (kill-whole-line) clears only one line of a multi-line buffer.
    [[ -n $PREBUFFER || $BUFFER == *$'\n'* ]] && _sf_msg="shellfirm: the lines are kept for editing (Ctrl-C clears them all; Ctrl-U clears one line)."
    if [[ -n $_shellfirm_rest ]]; then
        # The lines read ahead of the challenge stay with it.
        _shellfirm_rest_count
        BUFFER+=$'\n'$_shellfirm_rest
        CURSOR=${#BUFFER}
        _shellfirm_rest=""
        _sf_msg="shellfirm: the line and the $_sf_rn typed or pasted after it are kept for editing (Ctrl-C clears them all; Ctrl-U clears one line)."
    fi
    [[ -n ${1-} ]] && _sf_msg=""
    # The display was given up (`zle -I`) before the check printed: zle
    # draws the prompt again below whatever is printed now. A `zle -M`
    # message would share the prompt's row and overwrite it.
    # A multi-line construct is redrawn from its first line, which would
    # take a `zle -M` message away: print it above instead.
    if [[ ( -n $_shellfirm_trashed || -n $PREBUFFER ) && -n $_sf_msg ]]; then
        [[ -z $_shellfirm_trashed ]] && { zle -I; _shellfirm_trashed=1; }
        print -ru2 -- "$_sf_msg"
        _sf_msg=""
    fi
    if [[ -n $PREBUFFER ]]; then
        zle push-line-or-edit
    elif [[ -z $_shellfirm_trashed ]]; then
        zle reset-prompt
    fi
    # Shown below the line (a multi-line prompt redraw can hide the
    # message printed above it); it goes away at the next key.
    [[ -n $_sf_msg ]] && zle -M "$_sf_msg"
}

# $1 = name of the wrapped widget (never $WIDGET: that is the widget bound
# to the key, e.g. atuin-search when atuin calls `zle accept-line`).
_shellfirm_widget() {
    local _sf_name=$1; shift
    local _sf_orig=${_shellfirm_orig_widget[$_sf_name]:-.$_sf_name}
    _shellfirm_seen=1
    # Re-entered through a plugin chain: already checked, finish the chain.
    if (( ${_shellfirm_in_widget:-0} )); then
        if [[ $_sf_name == accept-* ]]; then
            zle ".$_sf_name" -- "$@"
        else
            zle "$_sf_orig" -- "$@"
        fi
        return
    fi
    local -i _shellfirm_in_widget=1
    _shellfirm_approved="" _shellfirm_restore="" _shellfirm_rest="" _shellfirm_rest_note=""
    # In a recursive edit that a transient prompt runs from zle-line-init
    # (romkatv / p10k style: it draws the line again once the edit ends),
    # the line is checked at zle-line-finish instead, after that redraw: the
    # banner then goes below the collapsed line and nothing draws over it.
    # A blocked line comes back at the next prompt; in vi mode Ctrl-U would
    # not clear it there, so vi mode keeps the check here.
    if (( ${ZLE_RECURSIVE:-0} > 0 )) && [[ $_sf_name == accept-line && -z $PREBUFFER ]] \
        && [[ $(bindkey -lL main 2>/dev/null) != *viins* ]] && _shellfirm_add_gate; then
        zle "$_sf_orig" -- "$@"
        return
    fi
    # Here-document body lines are data; the line that opened the
    # here-document was checked when it was accepted.
    if [[ -n $PREBUFFER && ${(%):-%_} == *heredoc* ]]; then
        zle "$_sf_orig" -- "$@"
        return
    fi
    setopt localoptions extendedglob
    _shellfirm_fc_ok=()
    _shellfirm_block_msg=""
    _shellfirm_trashed=""
    # History references are expanded first: zsh decides whether the input
    # is complete after expanding them (`!$` can be the closing `fi`). The
    # history characters can be changed (`histchars='@^#'`).
    local _sf_h1=${histchars[1]-} _sf_h2=${histchars[2]-}
    if [[ -o banghist && -n $_sf_h1 && ( $BUFFER == *"$_sf_h1"* || ( -n $_sf_h2 && $BUFFER == "$_sf_h2"* ) ) ]]; then
        zle expand-history 2>/dev/null
    fi
    local _sf_full=$PREBUFFER$BUFFER
    if [[ -n ${_sf_full//[[:space:]]/} ]] && _shellfirm_complete "$_sf_full"; then
        _shellfirm_expand "$_sf_full"
        if [[ -n $_shellfirm_block_msg ]]; then
            _shellfirm_say "$_shellfirm_block_msg"
            _shellfirm_keep_line said
            return 1
        fi
        if [[ -n $_shellfirm_expanded ]] && ! _shellfirm_run "$_shellfirm_expanded"; then
            _shellfirm_keep_line
            return 1
        fi
        _shellfirm_give_back
        _shellfirm_src_line "$_sf_full"
    fi
    # Checked: the line-finish gate lets exactly this text through.
    _shellfirm_allowed=$PREBUFFER$BUFFER
    zle "$_sf_orig" -- "$@"
}

# zle-line-finish: the last moment before zsh runs the line, whatever Enter
# is bound to. A line that did not pass through the wrapped widgets (Enter
# bound later, by a plugin loaded after the first prompt, to a widget that
# calls `.accept-line`), or that the widget shellfirm ran after its check
# changed (`BUFFER=...; zle .accept-line`), is checked here. Blocked: the
# line is emptied, so nothing runs, and put back for editing.
_shellfirm_line_finish() {
    local _sf_full=$PREBUFFER$BUFFER
    local _sf_ok=$_shellfirm_allowed
    _shellfirm_allowed=""
    [[ -n ${_sf_full//[[:space:]]/} && $_sf_full != "$_sf_ok" ]] || return 0
    [[ -n $PREBUFFER && ${(%):-%_} == *heredoc* ]] && return 0
    _shellfirm_complete "$_sf_full" || return 0
    setopt localoptions extendedglob
    local _sf_h1=${histchars[1]-} _sf_h2=${histchars[2]-}
    if [[ -o banghist && -n $_sf_h1 && ( $BUFFER == *"$_sf_h1"* || ( -n $_sf_h2 && $BUFFER == "$_sf_h2"* ) ) ]]; then
        zle expand-history 2>/dev/null
        _sf_full=$PREBUFFER$BUFFER
    fi
    _shellfirm_gated=1
    _shellfirm_fc_ok=()
    _shellfirm_block_msg=""
    _shellfirm_trashed=""
    _shellfirm_rest="" _shellfirm_rest_note=""
    _shellfirm_expand "$_sf_full"
    if [[ -n $_shellfirm_block_msg ]]; then
        _shellfirm_say "$_shellfirm_block_msg"
    elif [[ -z $_shellfirm_expanded ]] || _shellfirm_run "$_shellfirm_expanded"; then
        _shellfirm_give_back
        _shellfirm_src_line "$_sf_full"
        return 0
    fi
    local _sf_rn _sf_rv _sf_rp
    if [[ -n $_shellfirm_rest ]]; then
        _shellfirm_rest_count
        print -rz -- "$_sf_full"$'\n'"$_shellfirm_rest"
        _shellfirm_rest=""
        print -ru2 -- "shellfirm: the line and the $_sf_rn typed or pasted after it are kept for editing (Ctrl-C clears them all; Ctrl-U clears one line)."
    elif [[ -n $PREBUFFER || $_sf_full == *$'\n'* ]]; then
        print -rz -- "$_sf_full"
        print -ru2 -- "shellfirm: the lines are kept for editing (Ctrl-C clears them all; Ctrl-U clears one line)."
    else
        print -rz -- "$_sf_full"
        print -ru2 -- "shellfirm: the line is kept for editing (Ctrl-U clears it)."
    fi
    BUFFER=""
    # A multi-line construct: abandon it (the whole text is back in the editor).
    [[ -n $PREBUFFER ]] && zle send-break
    return 0
}

# zle-line-init: the zle-line-finish check is in place for this line.
_shellfirm_line_init() { _shellfirm_add_gate }

# Ctrl-R (incremental search) + Enter: accept the search, then run the
# (checked) accept-line instead of zsh's built-in one.
_shellfirm_isearch_accept() {
    zle accept-search
    zle accept-line -- "$@"
}

# A command is about to run that did not pass through the wrapped widgets
# (Enter bound to a widget that calls `zle .accept-line`): the next prompt
# wraps what Enter runs again. Without the line-finish check, warn once.
_shellfirm_preexec() {
    # After a passed challenge: "approved, running ..." now, below the line
    # as zle (or a transient prompt) left it.
    if [[ -n $_shellfirm_restore ]]; then
        _shellfirm_restore=""
        print -rnu2 -- $'\e8\e[J'
    fi
    if [[ -n $_shellfirm_approved ]]; then
        if [[ $_shellfirm_notes == 0 ]]; then
            # Nothing to keep quiet: stderr stays the terminal, so the line
            # is dim when the terminal has colour.
            command shellfirm pre-command --approved-notice --command="$_shellfirm_approved"
        elif [[ -t 2 && -z ${NO_COLOR-} && ${CLICOLOR-} != 0 && ${TERM-} == (xterm|screen|tmux|rxvt|*color*|kitty|alacritty|foot|wezterm|vte|linux|iterm|ghostty)* && $TERM != *mono* ]]; then
            CLICOLOR_FORCE=1 command shellfirm pre-command --approved-notice --command="$_shellfirm_approved" 2>/dev/null
        else
            command shellfirm pre-command --approved-notice --command="$_shellfirm_approved" 2>/dev/null
        fi
        _shellfirm_approved=""
    fi
    if [[ -n $_shellfirm_rest_note ]]; then
        print -ru2 -- "$_shellfirm_rest_note"
        _shellfirm_rest_note=""
    fi
    if [[ -z $_shellfirm_seen ]]; then
        _shellfirm_rewrap_sig=""
        if [[ -z $_shellfirm_gated && -z $_shellfirm_bypass_warned ]]; then
            _shellfirm_bypass_warned=1
            print -ru2 -- "shellfirm: warning: this command did not pass through shellfirm (Enter is bound to \`$(bindkey -M main '^M' 2>/dev/null)\`); commands are NOT being checked. Run \`shellfirm doctor\`."
        fi
    fi
    _shellfirm_seen=""
    _shellfirm_gated=""
}

# At the first prompt (after the rc files ran): `fc` and `r` typed on the
# command line go through _shellfirm_fc, unless they are already an alias or
# a function.
_shellfirm_first_prompt() {
    add-zsh-hook -d precmd _shellfirm_first_prompt
    _shellfirm_srcnote=1
    (( $+aliases[fc] || $+functions[fc] )) || alias fc='_shellfirm_fc fc'
    (( $+aliases[r] || $+functions[r] )) || alias r='_shellfirm_fc r'
}

# How the widget $1 (bound to Enter) runs a command: `chained` (it calls the
# checked accept-line), `bypass` (it calls zsh's built-in .accept-line) or
# `unknown`. Looks one call deep into the functions it uses.
_shellfirm_enter_kind() {
    setopt localoptions extendedglob
    local _sf_f=${widgets[$1]-} _sf_b _sf_w _sf_d
    [[ $_sf_f == user:* ]] || { print -r -- unknown; return; }
    _sf_f=${_sf_f#user:}
    local -a _sf_todo=($_sf_f)
    for (( _sf_d = 0; _sf_d < 2 && ${#_sf_todo}; _sf_d++ )); do
        local -a _sf_next=()
        for _sf_f in $_sf_todo; do
            _sf_b=${functions[$_sf_f]-}
            if [[ $_sf_b == *zle[[:space:]]##(-w[[:space:]]##|)[\"\']#.accept-* ]]; then
                print -r -- bypass; return
            fi
            if [[ $_sf_b == *zle[[:space:]]##(-w[[:space:]]##|)[\"\']#(accept-line|accept-and-hold|accept-line-and-down-history|accept-and-infer-next-history)* ]]; then
                print -r -- chained; return
            fi
            for _sf_w in ${(z)_sf_b}; do
                [[ $_sf_w != $_sf_f && $_sf_w != _shellfirm* ]] || continue
                if (( $+functions[$_sf_w] )); then
                    _sf_next+=($_sf_w)
                elif [[ ${widgets[$_sf_w]-} == user:* ]]; then
                    _sf_next+=(${widgets[$_sf_w]#user:})
                fi
            done
        done
        _sf_todo=(${(u)_sf_next})
    done
    print -r -- unknown
}

# `shellfirm doctor` runs this in a fresh interactive shell; run it in this
# shell to check the live state: `__shellfirm_doctor_probe | shellfirm doctor --stdin`
# (the same name in every shell; `_shellfirm_doctor_probe` is the old one).
__shellfirm_doctor_probe() {
    # What the next prompt would do anyway (a probe run with -c has none).
    _shellfirm_rewrap
    print -r -- "shell=zsh"
    print -r -- "shell_version=$ZSH_VERSION"
    print -r -- "hook_version=$_shellfirm_hook_version"
    print -r -- "pid=$$"
    local _sf_w _sf_ok _sf_bad=""
    for _sf_w in accept-line accept-and-hold accept-line-and-down-history accept-and-infer-next-history; do
        _sf_ok=""
        [[ ${widgets[$_sf_w]-} == user:_shellfirm_widget_$_sf_w ]] && _sf_ok=1
        [[ -z $_sf_ok && " ${(v)widgets} " == *" user:_shellfirm_widget_$_sf_w "* ]] && _sf_ok=1
        [[ -z $_sf_ok ]] && _sf_bad+=" $_sf_w=${widgets[$_sf_w]-}"
    done
    print -r -- "widgets=${${_sf_bad# }:-ok}"
    local _sf_k=${${(z)$(bindkey -M main '^M' 2>/dev/null)}[2]}
    [[ -n $_shellfirm_rewrapped ]] && print -r -- "rewrapped=${_shellfirm_rewrapped# }"
    [[ -o correct || -o correctall ]] && print -r -- "correct=checked"
    if [[ ${widgets[$_sf_k]-} == user:_shellfirm_widget_* ]]; then
        print -r -- "enter=ok"
    else
        case $_sf_k in
            accept-line|accept-and-hold|accept-line-and-down-history|accept-and-infer-next-history) print -r -- "enter=ok" ;;
            .accept-*) print -r -- "enter=bypass:$_sf_k" ;;
            *) print -r -- "enter=$(_shellfirm_enter_kind $_sf_k):$_sf_k" ;;
        esac
    fi
    _sf_k=${${(z)$(bindkey -M isearch '^M' 2>/dev/null)}[2]}
    [[ $_sf_k == _shellfirm_isearch_accept ]] && print -r -- "isearch=ok" || print -r -- "isearch=unchecked:$_sf_k"
    (( ${preexec_functions[(I)_shellfirm_preexec]} )) && print -r -- "precmd=ok" || print -r -- "precmd=missing"
    if [[ ${aliases[fc]-} == '_shellfirm_fc fc' ]] || (( ${precmd_functions[(I)_shellfirm_first_prompt]} )); then
        print -r -- "fc=ok"
    else
        print -r -- "fc=unchecked"
    fi
    # The zle-line-finish check (registered again when a plugin replaced it).
    _shellfirm_add_gate && print -r -- "line_finish=ok" || print -r -- "line_finish=missing"
    [[ -n $_shellfirm_bypass_warned ]] && print -r -- "bypass_seen=yes"
    [[ ${widgets[accept-line]-} == user:shellfirm-pre-command ]] && print -r -- "legacy_hook=active"
    local _sf_pl=""
    (( $+widgets[atuin-search] )) && _sf_pl+=" atuin"
    (( $+widgets[fzf-cd-widget] || $+widgets[fzf-file-widget] )) && _sf_pl+=" fzf"
    (( $+functions[_zsh_autosuggest_start] )) && _sf_pl+=" zsh-autosuggestions"
    (( $+functions[_zsh_highlight] )) && _sf_pl+=" zsh-syntax-highlighting"
    (( $+functions[zvm_init] )) && _sf_pl+=" zsh-vi-mode"
    (( $+functions[abbr] )) && _sf_pl+=" zsh-abbr"
    (( $+functions[prompt_powerlevel9k_setup] || $+functions[_p9k_precmd] )) && _sf_pl+=" powerlevel10k"
    (( $+functions[starship_precmd] || $+functions[prompt_starship_precmd] )) && _sf_pl+=" starship"
    print -r -- "plugins=${_sf_pl# }"
}
_shellfirm_doctor_probe() { __shellfirm_doctor_probe "$@" }

# Wrap the widget $1 so that it checks the line first, then runs what the
# widget did before.
_shellfirm_wrap_widget() {
    local _sf_w=$1
    functions[_shellfirm_widget_$_sf_w]="_shellfirm_widget $_sf_w \"\$@\""
    case ${widgets[$_sf_w]-} in
        user:_shellfirm_widget_*) ;;
        user:shellfirm-pre-command)
            # Hook pasted from shellfirm <= 0.3.10: replace it.
            print -ru2 -- "shellfirm: replaced an old shellfirm hook found in your shell startup files; remove it (run \`shellfirm init zsh\` to see where)."
            _shellfirm_orig_widget[$_sf_w]=.$_sf_w
            zle -N "$_sf_w" "_shellfirm_widget_$_sf_w" ;;
        user:*|completion:*)
            # A copy of the current widget, under a name of its own each time
            # (a plugin may have replaced an earlier copy).
            local -i _sf_n=1
            while (( $+widgets[_shellfirm_orig${_sf_n}_$_sf_w] )); do (( _sf_n++ )); done
            zle -A "$_sf_w" "_shellfirm_orig${_sf_n}_$_sf_w"
            _shellfirm_orig_widget[$_sf_w]=_shellfirm_orig${_sf_n}_$_sf_w
            zle -N "$_sf_w" "_shellfirm_widget_$_sf_w" ;;
        *)
            _shellfirm_orig_widget[$_sf_w]=.$_sf_w
            zle -N "$_sf_w" "_shellfirm_widget_$_sf_w" ;;
    esac
}

# Before every prompt: a plugin loaded after shellfirm may have replaced an
# accept-line widget (`zle -N accept-line auto-ls`) or bound Enter to a
# widget that calls zsh's built-in `.accept-line`. Wrap those again, before
# the first command runs. A widget chain that still reaches shellfirm's
# wrapper (zsh-autosuggestions keeps a copy of it) is left alone.
_shellfirm_rewrap() {
    [[ -n $_shellfirm_srcnote ]] && _shellfirm_note_src
    _shellfirm_add_gate
    # Nothing changed since the last prompt (no widget was added or
    # replaced, no command bypassed the wrappers): nothing to do, and no
    # `bindkey` subshell per prompt.
    local _sf_sig="${#widgets}:${widgets[accept-line]-}:${widgets[accept-and-hold]-}"
    [[ $_sf_sig == "$_shellfirm_rewrap_sig" ]] && return
    _shellfirm_rewrap_sig=$_sf_sig
    local _sf_w _sf_k _sf_vals=" ${(v)widgets} "
    for _sf_w in accept-line accept-and-hold accept-line-and-down-history accept-and-infer-next-history; do
        [[ $_sf_vals == *" user:_shellfirm_widget_$_sf_w "* ]] && continue
        _shellfirm_wrap_widget $_sf_w
        _shellfirm_rewrapped+=" $_sf_w"
    done
    for _sf_k in '^M' '^J'; do
        _sf_w=${${(z)$(bindkey -M main "$_sf_k" 2>/dev/null)}[2]}
        [[ -n $_sf_w && $_sf_w != (accept-line|accept-and-hold|accept-line-and-down-history|accept-and-infer-next-history|.*) ]] || continue
        [[ ${widgets[$_sf_w]-} == user:_shellfirm_widget_* ]] && continue
        [[ $(_shellfirm_enter_kind $_sf_w) == bypass ]] || continue
        _shellfirm_wrap_widget $_sf_w
        _shellfirm_rewrapped+=" $_sf_w"
    done
}
typeset -g _shellfirm_rewrapped="" _shellfirm_rewrap_sig=""
typeset -g _shellfirm_allowed="" _shellfirm_gated="" _shellfirm_approved=""

# Registers the zle-line-finish check (zsh 5.3+) as the last line-finish
# hook: after one added later (a plugin that rewrites $BUFFER there), and
# again when a plugin replaced the zle-line-finish widget with its own
# (`zle -N zle-line-finish f`), which is kept and runs first. Returns 1
# when it is not in place.
_shellfirm_add_gate() {
    setopt localoptions extendedglob
    local -a _sf_h
    local _sf_e _sf_cur=${widgets[zle-line-finish]-}
    local -i _sf_max=0 _sf_ours=-1 _sf_n=1
    zstyle -g _sf_h zle-line-finish widgets
    for _sf_e in $_sf_h; do
        if [[ $_sf_e == <->:_shellfirm_line_finish ]]; then
            _sf_ours=${_sf_e%%:*}
        elif [[ $_sf_e == <->:* ]] && (( ${_sf_e%%:*} > _sf_max )); then
            _sf_max=${_sf_e%%:*}
        fi
    done
    [[ $_sf_cur == user:azhw:zle-line-finish ]] && (( _sf_ours > _sf_max )) && return 0
    (( $+functions[add-zle-hook-widget] )) || autoload -Uz add-zle-hook-widget 2>/dev/null || return 1
    # The dispatcher (azhw:*) is defined the first time add-zle-hook-widget runs.
    (( $+functions[azhw:zle-line-finish] )) || add-zle-hook-widget -L >/dev/null 2>&1
    (( $+functions[azhw:zle-line-finish] )) || return 1
    _sf_h=(${_sf_h:#<->:_shellfirm_line_finish})
    if [[ -n $_sf_cur && $_sf_cur != user:azhw:zle-line-finish ]]; then
        # A plugin's own zle-line-finish: a copy of it stays a hook. A
        # plugin that sets the same widget again at every prompt keeps the
        # one copy it has (it must not run once more per prompt).
        local _sf_have=""
        for _sf_e in ${(M)_sf_h:#<->:_shellfirm_prev_lf*}; do
            [[ ${widgets[${_sf_e#*:}]-} == "$_sf_cur" ]] && { _sf_have=1; break; }
        done
        if [[ -z $_sf_have ]]; then
            while (( $+widgets[_shellfirm_prev_lf$_sf_n] )); do (( _sf_n++ )); done
            zle -A zle-line-finish _shellfirm_prev_lf$_sf_n 2>/dev/null && _sf_h+=("$(( ++_sf_max )):_shellfirm_prev_lf$_sf_n")
        fi
    fi
    (( $+widgets[_shellfirm_line_finish] )) || zle -N _shellfirm_line_finish
    _sf_h+=("$(( _sf_max + 1 )):_shellfirm_line_finish")
    zstyle zle-line-finish widgets "${_sf_h[@]}"
    zle -N zle-line-finish azhw:zle-line-finish
    [[ ${widgets[zle-line-finish]-} == user:azhw:zle-line-finish ]]
}

# Wrap once: re-sourcing ~/.zshrc must not wrap our own wrappers again
# (with plugins such as zsh-autosuggestions that would loop forever).
if (( ! ${+_shellfirm_zsh_loaded} )); then
typeset -g _shellfirm_zsh_loaded=1
() {
    local _sf_w
    for _sf_w in accept-line accept-and-hold accept-line-and-down-history accept-and-infer-next-history; do
        _shellfirm_wrap_widget $_sf_w
    done
    zle -N _shellfirm_isearch_accept
    local _sf_k
    for _sf_k in '^M' '^J'; do
        [[ $(bindkey -M isearch "$_sf_k" 2>/dev/null) == *undefined-key ]] && bindkey -M isearch "$_sf_k" _shellfirm_isearch_accept
    done
    if autoload -Uz add-zsh-hook 2>/dev/null; then
        add-zsh-hook preexec _shellfirm_preexec
        add-zsh-hook precmd _shellfirm_first_prompt
        add-zsh-hook precmd _shellfirm_rewrap
    fi
    _shellfirm_add_gate
    # Again when the editor starts, after every precmd hook: a plugin whose
    # precmd (run after shellfirm's) replaces zle-line-finish cannot take
    # the check away for that line.
    if (( $+functions[add-zle-hook-widget] )) || autoload -Uz add-zle-hook-widget 2>/dev/null; then
        zle -N _shellfirm_line_init
        add-zle-hook-widget line-init _shellfirm_line_init 2>/dev/null
    fi
}
fi
fi
"#;

/// fish: binds Enter / Ctrl-J (default and vi insert/normal modes), checks
/// the whole command line (Alt-Enter multi-line buffers, the abbreviation
/// fish is about to expand, small alias functions anywhere on the line),
/// routes `commandline -f execute` from plugins through the same check, and
/// runs an Enter binding to a fish function that was there before
/// (transient prompts) after the check.
const FISH_HOOK: &str = r#"# shellfirm hook for fish
if status is-interactive
    set -g __shellfirm_hook_version 13
    # Lets `shellfirm doctor` tell whether the shell it runs in loaded the hook
    # (SHELLFIRM_HOOK_LOAD changes at every load, also after `exec fish`).
    set -gx SHELLFIRM_HOOK_PID $fish_pid
    set -gx SHELLFIRM_HOOK_LOAD $fish_pid.(random)(random)
    set -g __shellfirm_warned 0
    set -g __shellfirm_seen 0
    set -g __shellfirm_bypass_warned 0

    function __shellfirm_warn_missing
        if test $__shellfirm_warned = 0
            set -g __shellfirm_warned 1
            echo >&2
            echo "shellfirm: binary not found in PATH; commands are NOT being checked" >&2
        end
    end

    # The expansion of the abbreviation under the cursor, which fish expands
    # when the line is executed (after this check reads the buffer).
    function __shellfirm_abbr_expansion
        set -l tok (builtin commandline -t)
        test -n "$tok"; or return 1
        set -l first (builtin commandline -po)[1]
        for line in (abbr --show)
            set -l parts (string split -m1 -- ' -- ' $line)
            set -q parts[2]; or continue
            set -l opts
            set -l toks
            printf '%s\n' $parts[1] | read -lat opts
            printf '%s\n' $parts[2] | read -lat toks
            set -l regex
            set -l func
            set -l position command
            set -l i 1
            while test $i -lt (count $opts)
                set -l next (math $i + 1)
                switch $opts[$i]
                    case --regex -r
                        set regex $opts[$next]
                    case --function -f
                        set func $opts[$next]
                    case --position -p
                        set position $opts[$next]
                end
                set i $next
            end
            if set -q regex[1]
                string match -qr -- $regex $tok; or continue
            else
                test "$tok" = "$toks[1]"; or continue
            end
            if test "$position" != anywhere; and test "$tok" != "$first"
                continue
            end
            if set -q func[1]
                $func $tok | string collect
            else
                set -e toks[1]
                string join ' ' -- $toks
            end
            return 0
        end
        return 1
    end

    # The source of the function $argv[1] when its body is worth checking
    # with a call: a small function that is not one of fish's own (those in
    # $__fish_data_dir/functions, unless redefined) and not shellfirm's.
    # Which functions are fish's own is remembered for the session (until a
    # line could define functions, or a file for one shows up in a function
    # directory that comes before fish's own).
    function __shellfirm_function_source
        set -l w $argv[1]
        string match -q '__shellfirm*' -- $w; and return 1
        if test "$__shellfirm_fn_path" != "$fish_function_path"
            set -g __shellfirm_fn_path $fish_function_path
            set -g __shellfirm_fn_shipped
        end
        if set -l i (contains -i -- $w $__shellfirm_fn_shipped)
            set -l own 1
            for d in $fish_function_path
                test "$d" = "$__fish_data_dir/functions"; and break
                if test -e "$d/$w.fish"
                    set own 0
                    break
                end
            end
            test $own = 1; and return 1
            set -e __shellfirm_fn_shipped[$i]
        end
        functions -q -- $w; or return 1
        set -l file (functions --details -- $w 2>/dev/null)
        if set -q __fish_data_dir[1]; and string match -q -- "$__fish_data_dir/functions/*" $file
            set -a __shellfirm_fn_shipped $w
            return 1
        end
        set -l body (functions --no-details -- $w 2>/dev/null | string collect)
        string match -q '*__shellfirm*' -- $body; and return 1
        if test (string length -- "$body") -gt 16000
            # Loaded from a file (a plugin): like a program on PATH, its
            # arguments are checked and its body is not read. Typed or
            # pasted into the session: not read, said so
            # (shell:function_depth_limit), never skipped silently.
            test -f "$file"; and return 1
            printf '%s' "shellfirm-function-depth-limit $w # a function too large for the hook to read ahead"
            return 0
        end
        printf '%s' $body
    end

    # Bodies of small functions (fish aliases) called anywhere in $argv[1],
    # with `$argv` replaced by the arguments of the call. The text is split
    # into commands with fish's own tokenizer, so redirections (`>&2`,
    # `2>&1`) stay what they are, and an argument is put in quoted when it
    # has characters that would change the body's meaning. Functions already
    # in __shellfirm_fn_seen are not repeated. $argv[2] = probe: print only
    # the names of the functions that would be expanded.
    function __shellfirm_function_bodies
        set -l toks
        printf '%s' $argv[1] | read -lzat toks
        set -l seg
        set -l subs
        set -l n 0
        set -l skip 0
        for t in $toks ';'
            if test $skip = 1
                set skip 0
                continue
            end
            if not contains -- $t ';' '|' '&&' '||' '&' \n
                # A redirection operator takes the next word (its target).
                if string match -qr -- '^([0-9]*[<>]+[&?|]?|&>>?)$' $t
                    set skip 1
                    continue
                end
                string match -qr -- '^[0-9]*[<>]|^&>' $t; and continue
                # Command substitutions run commands of their own.
                if string match -q -- '*(*' $t
                    set -a subs (string match -ra -- '\(([^()]*)\)' $t | string match -rv -- '^\(')
                end
                set -a seg $t
                continue
            end
            set -l words $seg
            set seg
            while set -q words[1]; and contains -- $words[1] and or not '!' begin time if while else eval
                set -e words[1]
            end
            set -q words[1]; or continue
            # `command x` / `builtin x` / `exec x` do not call a function.
            contains -- $words[1] command builtin exec; and continue
            contains -- $words[1] $__shellfirm_fn_seen; and continue
            functions -q -- $words[1]; or continue
            set -l body (__shellfirm_function_source $words[1]); or continue
            set -ga __shellfirm_fn_seen $words[1]
            if test "$argv[2]" = probe
                echo $words[1]
                continue
            end
            set -e words[1]
            set -l q
            for a in $words
                if string match -qr -- '[^A-Za-z0-9_./~:=@%+,-]' $a
                    set -a q "'"(string replace -a -- "'" "\\'" (string replace -a -- '\\' '\\\\' $a))"'"
                else
                    set -a q $a
                end
            end
            # A body that changes its arguments (`set -e argv[1]`, `set
            # argv ...`, argparse) keeps `$argv` as written: unknown.
            if string match -qr -- '(^|[\s;|&(])(set\s+(-\S+\s+)*argv\b|argparse\s)' $body
                printf '%s\n' $body
                continue
            end
            set body (string replace -a -- '$argv[' \x1f $body | string collect)
            for i in (seq (count $q))
                test $i -le 9; or break
                set body (string replace -a -- \x1f"$i]" $q[$i] $body | string collect)
            end
            set body (string replace -a -- '$argv' "$q" $body | string collect)
            string replace -a -- \x1f '$argv[' $body
        end
        for s in $subs[1..4]
            __shellfirm_function_bodies $s $argv[2]
        end
    end

    # A command named by a variable (`$c delete ...`, `eval $x`), with the
    # value the variable has in this session or from a `set` earlier on the
    # line: prints those commands with the value in place of the variable.
    function __shellfirm_var_commands
        string match -q -- '*$*' $argv[1]; or return
        test (string length -- "$argv[1]") -le 4000; or return
        set -l toks
        printf '%s' $argv[1] | read -lzat toks
        set -l names
        set -l values
        set -l seg
        set -l n 0
        for t in $toks ';'
            if not contains -- $t ';' '|' '&&' '||' '&' \n
                set -a seg $t
                continue
            end
            while set -q seg[1]; and contains -- $seg[1] and or not begin command builtin exec time eval
                set -e seg[1]
            end
            if test "$seg[1]" = set
                # `set [options] NAME VALUE...` with literal values.
                set -e seg[1]
                while set -q seg[1]; and string match -q -- '-*' $seg[1]
                    set -e seg[1]
                end
                if set -q seg[2]; and string match -qr -- '^[A-Za-z_][A-Za-z0-9_]*$' $seg[1]; and not string match -qr -- '[$(]' "$seg[2..-1]"
                    set -a names $seg[1]
                    set -a values (string join ' ' -- $seg[2..-1])
                end
            else if set -q seg[1]; and string match -qr -- '^\$[A-Za-z_][A-Za-z0-9_]*$' $seg[1]
                set -l name (string sub -s 2 -- $seg[1])
                set -l value
                if set -l i (contains -i -- $name $names)
                    set value $values[$i]
                else if set -q $name
                    set value (string join ' ' -- $$name)
                end
                if test -n "$value"
                    string join ' ' -- $value $seg[2..-1]
                    set n (math $n + 1)
                    test $n -ge 8; and return
                end
            end
            set seg
        end
    end

    # `bind KEY 'command'` installs code that runs when the key is pressed:
    # print those commands (not fish's input functions) so they are checked
    # when the binding is made, like a function that runs by itself.
    function __shellfirm_bind_commands
        string match -qr -- '(^|[;|&\n(]|\s)bind\s' $argv[1]; or return
        test (string length -- "$argv[1]") -le 4000; or return
        set -l toks
        printf '%s' $argv[1] | read -lzat toks
        set -l seg
        set -l fnames (bind --function-names)
        for t in $toks ';'
            if not contains -- $t ';' '|' '&&' '||' '&' \n
                set -a seg $t
                continue
            end
            while set -q seg[1]; and contains -- $seg[1] and or not begin command builtin
                set -e seg[1]
            end
            if test "$seg[1]" = bind
                set -e seg[1]
                set -l run 1
                while set -q seg[1]; and string match -q -- '-*' $seg[1]
                    switch $seg[1]
                        case -M --mode -m --sets-mode
                            set -e seg[1]
                        case -e --erase -a --all -L --list-modes -f --function-names -K --key-names -h --help
                            set run 0
                    end
                    set -e seg[1]
                end
                if test $run = 1; and set -q seg[2]
                    for c in $seg[2..-1]
                        contains -- $c $fnames; or echo $c
                    end
                end
            end
            set seg
        end
    end

    # Defining a function, abbreviation or alias runs nothing: those
    # statements are left out of the check (calling them is checked).
    # Prints the rest. Anything it cannot read for certain (an open quote,
    # a command substitution in a header) is printed unchanged.
    function __shellfirm_strip_defs
        set -l s $argv[1]
        if test (string length -- "$s") -gt 4000; or not string match -qr '(^|[;\n&|({]|\s)(function|abbr|alias)\s' -- $s
            printf '%s' $s
            return
        end
        set -l q ''
        set -l esc 0
        set -l par 0
        set -l spec 0
        set -l comment 0
        set -l stmt ''
        set -l stmts
        set -l specs
        for c in (string replace -a \n \x1e -- $s | string split '')
            if test $comment = 1
                test "$c" = \x1e; or continue
                set comment 0
            end
            if test $esc = 1
                set esc 0
                set stmt "$stmt$c"
                continue
            end
            if test -n "$q"
                test "$c" = '\\'; and set esc 1
                test "$c" = "$q"; and set q ''
                set stmt "$stmt$c"
                continue
            end
            switch $c
                case "'" '"'
                    set q $c
                case '\\'
                    set esc 1
                case '('
                    set par (math $par + 1)
                    set spec 1
                case ')'
                    set par (math $par - 1)
                case '|' '&' '<' '>' '$'
                    test $par = 0; and set spec 1
                case '#'
                    if test $par = 0; and string match -qr '(^|\s)$' -- $stmt
                        set comment 1
                        continue
                    end
                case ';' \x1e
                    if test $par = 0
                        set -a stmts $stmt
                        set -a specs $spec
                        set stmt ''
                        set spec 0
                        continue
                    end
            end
            set stmt "$stmt$c"
        end
        if test -n "$q"; or test $esc = 1; or test $par != 0
            printf '%s' $s
            return
        end
        set -a stmts $stmt
        set -a specs $spec
        # Functions that run by themselves (event handlers, the prompt, key
        # bindings) and those they call: redefining one is checked.
        set -l reach (__shellfirm_hook_reach)
        set -l depth 0
        set -l fnlevel -1
        set -l kept
        set -l i 0
        for st in $stmts
            set i (math $i + 1)
            set -l words (string trim -- $st | string split -n ' ')
            while set -q words[1]; and contains -- $words[1] and or not time
                set -e words[1]
            end
            set -l w $words[1]
            if test $fnlevel -ge 0
                switch "$w"
                    case function if while for begin switch
                        set depth (math $depth + 1)
                    case end
                        if test (count $words) -gt 1
                            printf '%s' $s
                            return
                        end
                        set depth (math $depth - 1)
                        test $depth -eq $fnlevel; and set fnlevel -1
                end
                continue
            end
            switch "$w"
                case function
                    if test $specs[$i] != 0
                        printf '%s' $s
                        return
                    end
                    # An event handler (`--on-event fish_prompt`, ...) and
                    # the functions fish calls by name (the prompt, the
                    # title, command-not-found) run by themselves: they are
                    # checked when they are defined.
                    if string match -qr -- '^(--on-(event|variable|signal|process-exit|job-exit)(=.*)?|-[a-zA-Z]*[evspj])$' $words[3..-1]; \
                        or contains -- "$words[2]" fish_prompt fish_right_prompt fish_mode_prompt fish_title fish_greeting fish_command_not_found $reach
                        set depth (math $depth + 1)
                        set -a kept (string replace -a \x1e \n -- $st)
                        continue
                    end
                    set fnlevel $depth
                    set depth (math $depth + 1)
                    continue
                case abbr alias
                    test $specs[$i] = 0; and continue
                case if while for begin switch
                    set depth (math $depth + 1)
                case end
                    set depth (math $depth - 1)
            end
            set -a kept (string replace -a \x1e \n -- $st)
        end
        if test $fnlevel -ge 0
            printf '%s' $s
            return
        end
        string join \n -- $kept
    end

    # The functions that run by themselves (event handlers, the prompt and
    # title, key bindings) and the functions they name, however deep.
    function __shellfirm_hook_reach
        set -l fns (functions -n)
        set -l todo (functions --handlers 2>/dev/null | string match -rv '^Event ' | string match -ra '[A-Za-z0-9_:.@+-]+') \
            fish_prompt fish_right_prompt fish_mode_prompt fish_title fish_greeting fish_command_not_found \
            (builtin bind 2>/dev/null | string replace -r -- '^bind( -M \S+| -m \S+| --preset| --user)* \S+ ' '' | string match -ra '[A-Za-z0-9_:.@+-]+')
        set -l seen
        while set -q todo[1]; and test (count $seen) -lt 128
            set -l next
            for w in $todo
                contains -- $w $fns; or continue
                contains -- $w $seen $next; and continue
                string match -q -- '__fish*' $w; and continue
                string match -q -- '__shellfirm*' $w; and continue
                set -a next $w
            end
            set todo
            for w in $next
                set -a seen $w
                # fish's own functions (from its data directory) are not read.
                set -l file (functions --details -- $w 2>/dev/null)
                string match -q -- "$__fish_data_dir/*" $file; and continue
                set -a todo (functions --no-details -- $w 2>/dev/null | string match -ra '[A-Za-z0-9_:.@+-]+')
            end
        end
        printf '%s\n' $seen
    end

    # After the check: run the Enter binding that was there before shellfirm
    # (a transient-prompt plugin, ...), else execute.
    function __shellfirm_run_enter
        set -l var __shellfirm_enter_$fish_bind_mode
        if set -q $var
            set -g __shellfirm_allowed (builtin commandline | string collect)
            for c in $$var
                if contains -- $c (builtin bind --function-names)
                    builtin commandline -f $c
                else if functions -q -- $c; and functions --no-details -- $c | string match -qr 'builtin\s+commandline'
                    # It runs the line with `builtin commandline -f execute`,
                    # which skips the check: a copy of it that goes through
                    # the checked `commandline` (a line it rewrote is checked).
                    functions --no-details -- $c | string replace -r -- '^function\s+\S+' "function __shellfirm_via_$c" \
                        | string replace -ar -- 'builtin(\s+)commandline\b' 'commandline' | source
                    eval __shellfirm_via_$c
                else
                    eval $c
                end
            end
            return
        end
        builtin commandline -f execute
    end

    # shellfirm prints settings problems (a stale SHELLFIRM_CONFIG_DIR, an
    # invalid setting) on every call. Shown once per session (and again when
    # SHELLFIRM_CONFIG_DIR changes) on a line of their own, not glued to the
    # line being edited; after that only above a challenge.
    function __shellfirm_probe_notes
        set -l key "$SHELLFIRM_CONFIG_DIR"
        set -q __shellfirm_notes; and test "$__shellfirm_notes_key" = "$key"; and return
        set -g __shellfirm_notes_key $key
        set -l w (command shellfirm pre-command --test --command=: 2>&1 >/dev/null | string collect)
        if test -n "$w"
            echo >&2
            printf '%s\n' $w >&2
        end
        # A SHELLFIRM_CONFIG_DIR that is not a directory: the checks use the
        # default directory (as shellfirm itself does) without saying it again.
        if test -n "$w"; and __shellfirm_stale_dir
            set w (env SHELLFIRM_CONFIG_DIR= shellfirm pre-command --test --command=: 2>&1 >/dev/null | string collect)
        end
        if test -n "$w"
            set -g __shellfirm_notes 1
        else
            set -g __shellfirm_notes 0
        end
    end
    # shellfirm, with the default configuration directory once a stale
    # SHELLFIRM_CONFIG_DIR was reported.
    function __shellfirm_pc
        if test "$__shellfirm_notes_key" = "$SHELLFIRM_CONFIG_DIR"; and __shellfirm_stale_dir
            env SHELLFIRM_CONFIG_DIR= shellfirm $argv
        else
            command shellfirm $argv
        end
    end
    function __shellfirm_stale_dir
        set -q SHELLFIRM_CONFIG_DIR; or return 1
        set -l t (string trim -- "$SHELLFIRM_CONFIG_DIR")
        test -n "$t"; and not test -d "$SHELLFIRM_CONFIG_DIR"
    end

    function __shellfirm_check
        set -g __shellfirm_seen 1
        set -e __shellfirm_allowed
        set -e __shellfirm_pending_change
        set -l cmd (builtin commandline | string collect)
        if test -z (string trim -- "$cmd" | string collect)
            __shellfirm_run_enter
            return
        end
        # This line can define functions: which are fish's own is looked up again.
        if string match -qr -- '(^|[^\w-])(function|funcsave|funced|functions|alias|source|\.)(\s|$)' $cmd
            set -g __shellfirm_fn_shipped
        end
        # Incomplete input (open block or quote): let fish add a new line.
        builtin commandline --is-valid
        if test $status -eq 2
            builtin commandline -f execute
            return
        end
        if not command -q shellfirm
            __shellfirm_warn_missing
            __shellfirm_run_enter
            return
        end
        set -l check $cmd
        set -l exp (__shellfirm_abbr_expansion | string collect)
        if test -n "$exp"
            set -l tok (builtin commandline -t)
            set -l pos (builtin commandline -C)
            set -l before (string sub -l $pos -- $cmd)
            if string match -q -- "*$tok" $before
                set -l start (math (string length -- $before) - (string length -- $tok))
                set -l pre ""
                test $start -gt 0; and set pre (string sub -l $start -- $cmd | string collect)
                set -l post (string sub -s (math $pos + 1) -- $cmd | string collect)
                set check "$pre$exp$post"
            else
                set check "$cmd"\n"$exp"
            end
        end
        set check (__shellfirm_strip_defs "$check" | string collect)
        if test -z (string trim -- "$check" | string collect)
            __shellfirm_run_enter
            return
        end
        # What the banner and the audit log show (not the function bodies).
        set -l shown $check
        set -l vc (__shellfirm_var_commands "$check" | string collect)
        test -n "$vc"; and set check "$check"\n"$vc"
        set -l bc (__shellfirm_bind_commands "$check" | string collect)
        test -n "$bc"; and set check "$check"\n"$bc"
        # Functions and aliases, and those their bodies call (`alias nk2
        # rmr`, `function w1; w2 $argv; end`), each once, however deep,
        # within a budget (64 functions, 64 KB). Past it the rest is not
        # read: a marker says so (shell:function_depth_limit).
        set -g __shellfirm_fn_seen
        set -l body (__shellfirm_function_bodies "$check" | string collect)
        set -l bodies
        set -l bytes 0
        while test -n "$body"
            set check "$check"\n"$body"
            set -a bodies $body
            set bytes (math $bytes + (string length -- "$body"))
            if test (count $__shellfirm_fn_seen) -gt 64; or test $bytes -gt 64000
                set -l deeper (__shellfirm_function_bodies "$body" probe)
                set -q deeper[1]; and set check "$check"\n"shellfirm-function-depth-limit $deeper[1] # calls more functions than the hook reads ahead"
                break
            end
            set body (__shellfirm_function_bodies "$body" | string collect)
        end
        # `eval $x` / `$c ...` inside those bodies: the session value.
        if set -q bodies[1]
            set -l bvc (__shellfirm_var_commands (string join \n -- $bodies | string replace -a \n ';' | string collect) | string collect)
            test -n "$bvc"; and set check "$check"\n"$bvc"
        end
        if test (string length -- "$check") -gt 30000
            # Too long to pass as one argument: checked through stdin, no prompt.
            printf '%s' $check | command shellfirm check --stdin --exit-code >/dev/null 2>&1
            set -l rc $status
            if test $rc -eq 0
                __shellfirm_run_enter
                return
            end
            echo >&2
            echo "shellfirm: blocked: this line is too long to confirm interactively and it matches a risky pattern (or could not be checked, exit $rc). Run it from a script file instead." >&2
            builtin commandline -f repaint
            return
        end
        set -l line
        test "$shown" != "$check"; and set line --line="$shown"
        __shellfirm_probe_notes
        if test "$__shellfirm_notes" = 1
            # Dry run first (quietly): the notes only show for risky lines.
            set -l out (__shellfirm_pc pre-command --test --command="$check" 2>/dev/null)
            set -l rc $status
            if test $rc -eq 0; and not string match -q '*skipped (below*' -- $out
                __shellfirm_run_enter
                return
            end
            echo >&2
        end
        # Exit 3: allowed after a passed challenge; the approved line is
        # printed by __shellfirm_approved_notice once fish has moved below
        # the line. (Set here for this call only, so a value exported by
        # the user changes nothing.)
        begin
            set -lx SHELLFIRM_SIGNAL_PROMPTED 1
            set -lx SHELLFIRM_DEFER_APPROVED 1
            __shellfirm_pc pre-command --command="$check" $line
        end
        switch $status
            case 0
                __shellfirm_run_enter
            case 3
                set -g __shellfirm_approved "$shown"
                set -e __shellfirm_approved_mark
                if isatty stderr; and test -n "$TERM"; and test "$TERM" != dumb
                    # fish redraws the line before it runs, starting as
                    # many rows up as the line takes (a long or wide line
                    # wraps). Keep room below the answer (no scrolling
                    # later), mark the row after it for the approved line,
                    # and move down so the redraw starts on that row, not
                    # over the answered challenge.
                    set -l n (__shellfirm_line_rows)
                    for i in (seq (math $n + 1))
                        echo >&2
                    end
                    printf '\e[%dA\e7' (math $n + 1) >&2
                    set -g __shellfirm_approved_mark 1
                    if test $n -gt 1
                        for i in (seq (math $n - 1))
                            echo >&2
                        end
                    end
                end
                __shellfirm_run_enter
            case 127
                echo >&2
                echo "shellfirm: warning: "(command -s shellfirm)" is installed but could not run (exit 127); this command was NOT checked. Run `shellfirm doctor`." >&2
                __shellfirm_run_enter
            case '*'
                # Blocked: keep the buffer so it can be edited. fish redraws
                # a multi-line buffer from where it starts: make room so the
                # messages above it stay visible.
                echo "shellfirm: the line is kept for editing (Ctrl-U clears it)." >&2
                set -l n (count (builtin commandline))
                if test $n -gt 1
                    for i in (seq $n)
                        echo >&2
                    end
                end
                builtin commandline -f repaint
        end
    end

    # The terminal rows the prompt and the buffer take (display columns:
    # CJK characters and emoji count two).
    function __shellfirm_line_rows
        set -l pw (string length --visible -- (fish_prompt 2>/dev/null)[-1] 2>/dev/null)
        test -n "$pw"; or set pw 0
        set -l cols $COLUMNS
        test -n "$cols"; and test "$cols" -gt 0 2>/dev/null; or set cols 80
        set -l rows 0
        for l in (builtin commandline)
            set -l w (math $pw + (string length --visible -- "$l"))
            set rows (math $rows + "max(1, ceil($w / $cols))")
        end
        test $rows -gt 0; or set rows 1
        echo $rows
    end

    # After a passed challenge: "approved, running ..." on the row after
    # the answer (in place of the line fish redrew there), right before the
    # command runs.
    function __shellfirm_approved_notice --on-event fish_preexec
        set -q __shellfirm_approved[1]; or return
        set -l a $__shellfirm_approved
        set -e __shellfirm_approved
        if set -q __shellfirm_approved_mark[1]
            set -e __shellfirm_approved_mark
            printf '\e8\r\e[J' >&2
        end
        if test "$__shellfirm_notes" = 0
            command shellfirm pre-command --approved-notice --command="$a"
        else
            command shellfirm pre-command --approved-notice --command="$a" 2>/dev/null
        end
    end

    # Plugins that run the line themselves with `commandline -f execute`
    # (atuin enter_accept, transient-prompt Enter bindings, ...) go through
    # the same check.
    if not functions -q commandline; or functions commandline | string match -q '*__shellfirm_check*'
        function commandline --description 'shellfirm: check the line before `commandline -f execute`'
            if contains -- execute $argv; and begin; contains -- -f $argv; or contains -- --function $argv; end
                set -l rest
                set -l changes 0
                # An earlier call in the same binding queued a function that
                # changes the line (`commandline -f accept-autosuggestion;
                # commandline -f execute`): it has not run yet.
                if set -q __shellfirm_pending_change; and test "$__shellfirm_pending_change" = (builtin commandline | string collect)
                    set changes 1
                end
                set -e __shellfirm_pending_change
                for a in $argv
                    switch $a
                        case execute
                        case -f --function repaint force-repaint repaint-mode expand-abbr suppress-autosuggestion beginning-of-line beginning-of-buffer backward-char cancel
                            set -a rest $a
                        case '*'
                            set -a rest $a
                            set changes 1
                    end
                end
                if test $changes = 1
                    # The other functions (accept-autosuggestion, history
                    # search, ...) only run after this binding returns and can
                    # change the line, so it cannot be checked now: run them
                    # and leave running the line to Enter (which is checked).
                    test (count $rest) -gt 1; and builtin commandline $rest
                    echo >&2
                    echo "shellfirm: press Enter to run the line (it is checked first)." >&2
                    builtin commandline -f repaint
                    return
                end
                if test (count $rest) -gt 1
                    builtin commandline $rest
                end
                # Already checked (shellfirm ran the previous Enter binding).
                if set -q __shellfirm_allowed; and test "$__shellfirm_allowed" = (builtin commandline | string collect)
                    set -e __shellfirm_allowed
                    builtin commandline -f execute
                    return
                end
                __shellfirm_check
                return
            end
            if begin; contains -- -f $argv; or contains -- --function $argv; end
                for a in $argv
                    switch $a
                        case -f --function repaint force-repaint repaint-mode expand-abbr suppress-autosuggestion beginning-of-line beginning-of-buffer end-of-line end-of-buffer backward-char forward-char cancel
                        case '*'
                            set -g __shellfirm_pending_change (builtin commandline | string collect)
                    end
                end
            end
            builtin commandline $argv
        end
    end

    # A command ran without passing through shellfirm (Enter rebound to
    # `execute` directly, ...): warn once.
    function __shellfirm_preexec --on-event fish_preexec
        set -e __shellfirm_allowed
        set -e __shellfirm_pending_change
        if test $__shellfirm_seen = 0; and test $__shellfirm_bypass_warned = 0
            set -g __shellfirm_bypass_warned 1
            set -l b (bind \r | string join '; ')
            echo "shellfirm: warning: this command did not pass through shellfirm (Enter was rebound: $b); commands are NOT being checked. Run `shellfirm doctor`." >&2
        end
        set -g __shellfirm_seen 0
    end

    # What key $argv[2] runs in bind mode $argv[1]: the user binding, else
    # the preset one (`bind` prints both), without the `bind ... KEY` part.
    function __shellfirm_binding
        set -l lines (builtin bind -M $argv[1] $argv[2] 2>/dev/null)
        set -l user (string match -v -- 'bind --preset*' $lines)
        set -q user[1]; or set user $lines
        string replace -r -- '^bind( -M \S+| -m \S+| --preset| --user)* \S+ ' '' $user
    end

    # Enter / Ctrl-J run the check. An Enter binding to a fish function that
    # was there before (transient prompts, ...) runs after the check.
    function __shellfirm_bind
        for mode in default insert
            set -l cur (__shellfirm_binding $mode \r)
            if set -q cur[1]; and not string match -q '*__shellfirm_check*' -- $cur
                set -l first (string split ' ' -- $cur[1])[1]
                if functions -q -- $first
                    eval set -g __shellfirm_enter_$mode $cur[1]
                end
            end
            builtin bind -M $mode \r __shellfirm_check 2>/dev/null
            builtin bind -M $mode \n __shellfirm_check 2>/dev/null
        end
    end
    __shellfirm_bind
    # `bind` that rebinds Enter / Ctrl-J (`bind \r execute`, typed or from a
    # plugin, also one that does it from a fish_prompt handler at every
    # prompt, loaded before or after shellfirm) does not take the check
    # away: the new binding runs after the check, as one that was there
    # before shellfirm loaded does.
    if not functions -q bind; or functions bind | string match -q '*__shellfirm_enter_*'
        function bind --description 'shellfirm: Enter stays checked when it is rebound'
            set -l mode default
            set -l a $argv
            set -l plain 1
            while set -q a[1]
                switch $a[1]
                    case -M --mode
                        set -e a[1]
                        set mode $a[1]
                    case --user
                    case --
                        set -e a[1]
                        break
                    case '-*'
                        # --preset, -e, -k, -m, -s, listing...: as it is.
                        set plain 0
                    case '*'
                        break
                end
                set -e a[1]
            end
            if test $plain = 1; and set -q a[2]; and contains -- $mode default insert; \
                and contains -- $a[1] \r \n enter ctrl-m ctrl-j; and not contains -- __shellfirm_check $a[2..-1]
                if contains -- $a[1] \r enter ctrl-m
                    set -g __shellfirm_enter_$mode $a[2..-1]
                end
                builtin bind -M $mode \r __shellfirm_check 2>/dev/null
                builtin bind -M $mode \n __shellfirm_check 2>/dev/null
                return 0
            end
            builtin bind $argv
        end
    end
    # Re-apply after fish_vi_key_bindings / fish_default_key_bindings.
    function __shellfirm_rebind --on-variable fish_key_bindings
        __shellfirm_bind
    end

    # `shellfirm doctor` runs this in a fresh interactive shell; run it in
    # this shell to check the live state: `__shellfirm_doctor_probe | shellfirm doctor --stdin`
    function __shellfirm_doctor_probe
        echo shell=fish
        echo shell_version=$version
        echo hook_version=$__shellfirm_hook_version
        echo pid=$fish_pid
        set -l bad
        set -l chained
        for mode in default insert
            set -l b (__shellfirm_binding $mode \r)
            # fish 4 names the key `enter`.
            set -q b[1]; or set b (__shellfirm_binding $mode enter)
            if set -q b[1]; and not string match -q '*__shellfirm_check*' -- $b
                # A function (a transient prompt plugin loaded after
                # shellfirm) that runs the line with the wrapped
                # `commandline -f execute` is still checked.
                set -l f (string split ' ' -- $b[1])[1]
                set -l body (functions --no-details -- $f 2>/dev/null | string collect)
                if test (count $b) = 1; and functions -q -- $f; and functions commandline | string match -q '*__shellfirm_check*'; \
                    and string match -qr 'commandline\s+(-f|--function)\s+(\S+\s+)*execute' -- $body; \
                    and not string match -qr 'builtin\s+commandline\s+(-f|--function)\s+(\S+\s+)*execute' -- $body
                    contains -- $f $chained; or set -a chained $f
                else
                    set -a bad "$mode:\\r="(string join ',' -- $b)
                end
            end
            set b (__shellfirm_binding $mode \n)
            if set -q b[1]; and not string match -q '*__shellfirm_check*' -- $b
                set -a bad "$mode:\\n="(string join ',' -- $b)
            end
        end
        if set -q bad[1]
            echo "enter="(string join ' ' -- $bad)
        else if set -q chained[1]
            echo "enter=chained:"(string join ',' -- $chained)
        else
            echo enter=ok
        end
        set -q __shellfirm_enter_default; and echo "enter_chain="(string join ' ' -- $__shellfirm_enter_default)
        if functions -q commandline; and functions commandline | string match -q '*__shellfirm_check*'
            echo execute_wrapper=ok
        else
            echo execute_wrapper=missing
        end
        test $__shellfirm_bypass_warned = 1; and echo bypass_seen=yes
        functions -q _shellfirm_check; and echo legacy_hook=active
        set -l pl
        functions -q _atuin_search; and set -a pl atuin
        functions -q _fzf_search_directory; and set -a pl fzf.fish
        functions -q _tide_prompt; or set -q tide_prompt_add_newline_before; and set -a pl tide
        if functions -q transient_execute
            if contains -- transient_execute $__shellfirm_enter_default $__shellfirm_enter_insert
                set -a pl transient:chained
            else
                set -a pl transient:wrapped
            end
        end
        set -l pls (string join ' ' -- $pl)
        echo "plugins=$pls"
    end
end
"#;

const NUSHELL_HOOK: &str = r#"# shellfirm hook for nushell
# nushell cannot cancel a command from a hook. A risky line made of external
# programs is challenged, and on deny PATH is cleared for that line so they
# cannot start. Built-ins (rm, mv, cp, save, ...), custom commands and
# programs run by path cannot be stopped: for those shellfirm only warns.
# SHELLFIRM_HOOK_PID lets `shellfirm doctor` tell whether this shell loaded the hook.
$env.SHELLFIRM_HOOK_PID = ($nu.pid | into string)
$env.config = ($env.config? | default {} | upsert hooks {|c| $c.hooks? | default {} })
$env.config.hooks = ($env.config.hooks | upsert pre_execution {|h| $h.pre_execution? | default [] })
$env.config.hooks = ($env.config.hooks | upsert pre_prompt {|h| $h.pre_prompt? | default [] })
$env.config.hooks.pre_execution = ($env.config.hooks.pre_execution | append {||
    let cmd = (commandline)
    if ($cmd | str trim | is-empty) { return }
    if (which shellfirm | is-empty) {
        if ($env.__SHELLFIRM_WARNED? | is-empty) {
            $env.__SHELLFIRM_WARNED = true
            print -e "shellfirm: binary not found in PATH; commands are NOT being checked"
        }
        return
    }
    if ($cmd | str length) > 30000 {
        # Too long to pass as one argument: checked through stdin, no prompt.
        let big = (try { $cmd | ^shellfirm check --stdin --exit-code | complete | get exit_code } catch { 1 })
        if $big == 0 { return }
        $env.__SHELLFIRM_SAVED_PATH = $env.PATH
        $env.PATH = []
        print -e "shellfirm: WARNING: this line is too long to confirm and it is risky (or could not be checked). External programs on it will not start; nushell built-ins like rm may still run."
        return
    }
    # Defining a custom command or an alias runs nothing (calling it is checked).
    let ast = (try { ast --json $cmd | get block | from json | get pipelines } catch { [] })
    if ($cmd | str trim) =~ '^(export\s+)?(def|alias)\s' and ($ast | length) == 1 and ($ast.0.elements | length) == 1 { return }
    # Aliases are replaced by what they stand for, and the source of small
    # custom commands is checked with the call, and so are the custom
    # commands and aliases that source calls, each once, however deep,
    # within a budget (32 commands, 32 KB). Past it the rest is not read: a
    # marker says so (shell:function_depth_limit).
    mut check = $cmd
    mut extra = []
    mut queue = [$cmd]
    mut seen = []
    mut level = 0
    mut nfn = 0
    mut bytes = 0
    mut over = false
    while ($queue | is-not-empty) and not $over {
        $level += 1
        mut next = []
        for text in $queue {
            if $over { break }
            let words = ($text | split row -r '[;|\n{}()]|&&|\|\|' | each {|s| $s | str trim | split row -r '\s+' | first } | where {|w| $w != "" } | uniq)
            for w in ($words | first 16) {
                if $w in $seen { continue }
                # `which` is cheap; the scope tables are only read for an
                # alias or a custom command.
                let t = (try { which $w | get type? | append "" | first } catch { "" })
                if $t not-in [alias custom] { continue }
                $seen = ($seen | append $w)
                let al = if $t == alias { try { scope aliases | where name == $w } catch { [] } } else { [] }
                if ($al | is-not-empty) {
                    if $level == 1 {
                        let re = ('(^|[;|\n{(]\s*|&&\s*|\|\|\s*)' + ($w | str replace -ra '([.^$*+?()\[\]{}|\\])' '\$1') + '(\s|$)')
                        $check = ($check | str replace -ra $re ('${1}' + ($al.0.expansion | str replace -a '$' '$$') + '${2}'))
                    } else {
                        $extra = ($extra | append $al.0.expansion)
                    }
                    $next = ($next | append $al.0.expansion)
                } else if $t == custom {
                    let src = (try { view source $w } catch { "" })
                    if ($src | str length) <= 2000 {
                        $nfn += 1
                        $bytes += ($src | str length)
                        if $nfn > 32 or $bytes > 32000 {
                            $extra = ($extra | append $"shellfirm-function-depth-limit ($w) # calls more functions than the hook reads ahead")
                            $over = true
                            break
                        }
                        $extra = ($extra | append $src)
                        $next = ($next | append $src)
                    }
                }
            }
        }
        $queue = $next
    }
    # `let c = "kubectl"; ^$c ...`: the program named by a variable set to a
    # literal on the same line.
    mut named = $check
    for l in ($cmd | parse -r r#'(?:^|[;\n|])\s*(?:let|mut)\s+(?P<n>[A-Za-z_][A-Za-z0-9_-]*)\s*=\s*["']?(?P<v>[^"'\s;|()]+)["']?\s*(?:$|[;\n|])'#) {
        $named = ($named | str replace -a ('^$' + $l.n) ('^' + $l.v))
    }
    # `^$env.K ...` / `$env.K ...`: the program named by an environment
    # variable, set on this line or earlier in the session.
    if ($named | str contains '$env.') {
        mut envs = {}
        for l in ($cmd | parse -r r#'\$env\.(?P<n>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']?(?P<v>[^"'\s;|()]+)["']?'#) {
            $envs = ($envs | upsert $l.n $l.v)
        }
        for l in ($named | parse -r r#'(?:^|[;\n|({]\s*)\^?\$env\.(?P<n>[A-Za-z_][A-Za-z0-9_]*)'# | uniq) {
            let v = if ($l.n in $envs) { $envs | get $l.n } else { $env | get -i $l.n }
            if ($v | describe) == "string" and ($v | str trim | is-not-empty) {
                $named = ($named | str replace -ra ('\^?\$env\.' + $l.n + '(?![A-Za-z0-9_])') ('^' + $v))
            }
        }
    }
    if $named != $check { $extra = ($extra | append $named) }
    let full = ([$check] | append $extra | str join "\n")
    # Dry run first (no prompt, and no external context probes such as the
    # blast radius: the real check below runs them once). A match skipped
    # for its severity can still be raised by context: check it for real.
    let dry = (try { do { ^shellfirm pre-command --test --no-context $"--command=($full)" } | complete } catch { {exit_code: 1, stdout: ""} })
    if $dry.exit_code == 0 and not ($dry.stdout | str contains "skipped (below") { return }
    # Can shellfirm actually stop this line? Only external programs found
    # through PATH can be stopped (by clearing PATH).
    let heads = ($check | split row -r '[;|\n{}()]|&&|\|\|' | each {|s| $s | str trim | split row -r '\s+' | first } | where {|w| $w != "" })
    let unstoppable = ($check =~ '\$env\.PATH|with-env|load-env|overlay' or ($heads | any {|w|
        if ($w | str starts-with "^") {
            ($w | str contains "/")
        } else if ($w | str contains "/") {
            true
        } else {
            let t = (which $w | get type? | append "external" | first)
            $w in [rm mv cp save] or $t in [custom alias]
        }
    }))
    if $unstoppable {
        let ids = ($dry.stdout | lines | where {|l| $l starts-with "  - " } | each {|l| $l | str substring 4.. | split row " " | first } | str join ", ")
        $env.__SHELLFIRM_SAVED_PATH = $env.PATH
        $env.PATH = []
        print -e $"shellfirm: WARNING: this line is risky \(($ids)\), but shellfirm cannot stop nushell built-ins like rm, custom commands or programs run by path: they may still run. External programs on this line will not start."
        return
    }
    # The banner and challenge use the terminal; `complete` waits for the exit code.
    let rc = (^shellfirm pre-command --direct-tty $"--command=($full)" e> /dev/tty | complete | get exit_code)
    # 3: allowed after a passed challenge (SHELLFIRM_SIGNAL_PROMPTED=1 set
    # in the environment by the user).
    if $rc in [0 3] { return }
    if $rc == 127 {
        print -e "shellfirm: warning: shellfirm is installed but could not run (exit 127); this command was NOT checked. Run `shellfirm doctor`."
        return
    }
    $env.__SHELLFIRM_SAVED_PATH = $env.PATH
    $env.PATH = []
    print -e "shellfirm: external programs on this line will not start (nushell may report them as not found)."
})
$env.config.hooks.pre_prompt = ($env.config.hooks.pre_prompt | append {||
    if ($env.__SHELLFIRM_SAVED_PATH? != null) {
        $env.PATH = $env.__SHELLFIRM_SAVED_PATH
        hide-env __SHELLFIRM_SAVED_PATH
        $env.LAST_EXIT_CODE = 1
    }
})"#;

const POWERSHELL_HOOK: &str = r#"# shellfirm hook for PowerShell
$global:__shellfirm_hook_version = 13
# Lets `shellfirm doctor` tell whether the shell it runs in loaded the hook.
$env:SHELLFIRM_HOOK_PID = "$PID"
Set-PSReadLineKeyHandler -Key Enter -ScriptBlock {
    $line = $null
    $cursor = $null
    [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]$line, [ref]$cursor)

    if ([string]::IsNullOrWhiteSpace($line) -or -not (Get-Command shellfirm -CommandType Application -ErrorAction SilentlyContinue)) {
        [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
        return
    }

    Write-Host ""
    & shellfirm pre-command --direct-tty "--command=$line"
    # 3: allowed after a passed challenge (SHELLFIRM_SIGNAL_PROMPTED=1 in
    # the environment).
    if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 3) {
        [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
    } else {
        [Microsoft.PowerShell.PSConsoleReadLine]::InvokePrompt()
    }
}"#;

const ELVISH_HOOK: &str = r#"# shellfirm hook for elvish
use re
use str
# Lets `shellfirm doctor` tell whether the shell it runs in loaded the hook.
set-env SHELLFIRM_HOOK_PID (to-string $pid)
var shellfirm-warned = $false
var shellfirm-rebound-warned = $false
var shellfirm-orig-enter = $edit:insert:binding[Enter]
# The Enter binding that was there when shellfirm loaded. When the binding
# shellfirm runs after its check calls back into shellfirm (a plugin loaded
# after shellfirm that chains to "the previous Enter", which is shellfirm's),
# this one runs instead, so one Enter press is checked once and never loops.
var shellfirm-base-enter = $shellfirm-orig-enter
var shellfirm-in-enter = $false
var shellfirm-checked = ''
# True when elvish would wait for more input: the code has a parse error
# right at its end (an open block, list or string). Other errors (a
# variable defined in this session, a real syntax error) are not "incomplete".
fn shellfirm-incomplete {|cmd|
    if (not (has-external elvish)) {
        put $false
        return
    }
    var out = (try { e:elvish -norc -compileonly -json -c $cmd 2>/dev/null } catch { nop } | slurp)
    var errs = $nil
    try { set errs = (echo $out | from-json) } catch { }
    if (not-eq (kind-of $errs) list) {
        put $false
        return
    }
    var len = (str:to-utf8-bytes $cmd | count)
    for err $errs {
        if (and (has-key $err start) (== $err[start] $len)) {
            put $true
            return
        }
    }
    put $false
}
# The code in the option defaults of a lambda signature (`fn a {|&x=(code)|
# ... }`, `{|&x=(code)| ...}`): elvish runs it when the closure is made, so
# at definition time. One command per line ('' = none).
fn shellfirm-sig-code {|cmd|
    var out = ''
    if (str:contains $cmd '|') {
        for m [(re:find '\{\s*\|([^|]*)\|' $cmd)] {
            for g [(re:find '\(([^()]*)\)' $m[groups][1][text])] {
                set out = $out"\n"$g[groups][1][text]
            }
        }
    }
    put $out
}
# True when the line only defines a function (`fn name { ... }`): that runs
# nothing, and calling it is what gets checked. Option defaults with code
# in them run now: not "only".
fn shellfirm-only-fn {|cmd|
    var t = (str:trim-space $cmd)
    if (not (re:match '^fn\s+[^\s{]+\s*\{' $t)) {
        put $false
        return
    }
    if (not-eq (shellfirm-sig-code $t) '') {
        put $false
        return
    }
    var depth = (num 0)
    var q = ''
    var esc = $false
    var comment = $false
    var closed = $false
    for c [(str:split '' $t)] {
        if $closed {
            if (not (re:match '^\s$' $c)) {
                put $false
                return
            }
            continue
        }
        if $comment {
            if (eq $c "\n") { set comment = $false }
            continue
        }
        if $esc {
            set esc = $false
            continue
        }
        if (eq $q '"') {
            if (eq $c '\') { set esc = $true } elif (eq $c '"') { set q = '' }
            continue
        }
        if (eq $q "'") {
            if (eq $c "'") { set q = '' }
            continue
        }
        if (or (eq $c '"') (eq $c "'")) {
            set q = $c
        } elif (eq $c '#') {
            set comment = $true
        } elif (has-value ['{' '[' '('] $c) {
            set depth = (+ $depth 1)
        } elif (has-value ['}' ']' ')'] $c) {
            set depth = (- $depth 1)
            if (== $depth 0) { set closed = $true }
        }
    }
    put (and $closed (eq $q ''))
}
# The last line shellfirm checked (a chained binding that rewrote the line
# and called back into shellfirm had the new line checked already; when it
# was not let through, the binding did not accept it).
var shellfirm-last-checked = ''
var shellfirm-saved-paths = $nil
# The binding that ran after the check changed the line it accepts (an
# abbreviation-style plugin loaded before shellfirm: `set
# edit:current-command = ...` then the built-in Enter). elvish runs that new
# line once the binding returns and it cannot be taken back, so it is
# checked now; if it is not confirmed, external programs cannot start for
# that line (PATH is emptied until the next prompt).
fn shellfirm-recheck {|cmd|
    var now = $edit:current-command
    if (or (eq $now $cmd) (eq $now $shellfirm-last-checked) (eq (str:trim-space $now) '') (not (has-external shellfirm))) {
        return
    }
    var incomplete = $false
    if (str:contains-any $now '{[("''|^') {
        try { set incomplete = (shellfirm-incomplete $now) } catch { }
    }
    if $incomplete {
        return
    }
    set shellfirm-last-checked = $now
    var ok = $false
    try {
        set ok = ?(e:shellfirm pre-command --direct-tty --command=$now </dev/tty >/dev/tty 2>/dev/tty)
    } catch {
        set ok = $false
    }
    if $ok {
        return
    }
    set shellfirm-saved-paths = $paths
    set paths = []
    echo "shellfirm: the Enter binding changed the line after the check and it was not confirmed: external programs on it will not start (elvish built-ins still run)." >/dev/tty
}
# The check, for the line $line ($cmd: with what it calls). Exit 3 is
# "allowed after a passed challenge": with $defer the approved line is not
# printed yet (after-readline prints it below the line). Set for this call
# only, so a SHELLFIRM_SIGNAL_PROMPTED the user exported changes nothing.
var shellfirm-approved = ''
fn shellfirm-env {|name value|
    if (eq $value $nil) { unset-env $name } else { set-env $name $value }
}
fn shellfirm-check {|cmd line defer|
    var saved = [&]
    for n [SHELLFIRM_SIGNAL_PROMPTED SHELLFIRM_DEFER_APPROVED] {
        set saved[$n] = (if (has-env $n) { get-env $n } else { put $nil })
    }
    set-env SHELLFIRM_SIGNAL_PROMPTED 1
    if $defer { set-env SHELLFIRM_DEFER_APPROVED 1 } else { unset-env SHELLFIRM_DEFER_APPROVED }
    var r = $ok
    try {
        set r = ?(e:shellfirm pre-command --direct-tty --command=$cmd --line=$line </dev/tty >/dev/tty 2>/dev/tty)
    } finally {
        for n [SHELLFIRM_SIGNAL_PROMPTED SHELLFIRM_DEFER_APPROVED] { shellfirm-env $n $saved[$n] }
    }
    if (eq $r $ok) {
        put $true
        return
    }
    var st = -1
    try { set st = $r[reason][exit-status] } catch { }
    if (eq (to-string $st) 3) {
        if $defer { set shellfirm-approved = $line }
        put $true
        return
    }
    put $false
}
# Runs the binding after the check, marking that a check is in progress.
fn shellfirm-next {|next cmd|
    var was-in = $shellfirm-in-enter
    var was-checked = $shellfirm-checked
    set shellfirm-in-enter = $true
    set shellfirm-checked = $cmd
    try { $next } finally {
        set shellfirm-in-enter = $was-in
        set shellfirm-checked = $was-checked
    }
    if (not $was-in) {
        shellfirm-recheck $cmd
    }
}
# A fn (not a bare lambda): `return` only works inside fn.
fn shellfirm-enter {
    var cmd = $edit:current-command
    var next = $shellfirm-orig-enter
    if (not $shellfirm-in-enter) {
        set shellfirm-last-checked = ''
    }
    if $shellfirm-in-enter {
        # Called back from the binding shellfirm runs after its check: run
        # the binding from before shellfirm loaded. The line is checked
        # again only when that binding changed it.
        set next = $shellfirm-base-enter
        if (eq $cmd $shellfirm-checked) {
            $next
            return
        }
    }
    if (eq (str:trim-space $cmd) '') {
        shellfirm-next $next $cmd
        return
    }
    if (not (has-external shellfirm)) {
        if (not $shellfirm-warned) {
            set shellfirm-warned = $true
            echo "shellfirm: binary not found in PATH; commands are NOT being checked" >/dev/tty
        }
        shellfirm-next $next $cmd
        return
    }
    # Code that does not parse yet is never run: let Enter insert the
    # newline, and check the block once it is complete.
    var incomplete = $false
    if (str:contains-any $cmd '{[("''|^') {
        try { set incomplete = (shellfirm-incomplete $cmd) } catch { }
    }
    if $incomplete {
        shellfirm-next $next $cmd
        return
    }
    var only-fn = $false
    try { set only-fn = (shellfirm-only-fn $cmd) } catch { }
    if $only-fn {
        shellfirm-next $next $cmd
        return
    }
    set shellfirm-last-checked = $cmd
    var ok = $false
    try {
        if (> (count $cmd) 30000) {
            # Too long to pass as one argument: checked through stdin, no prompt.
            set ok = ?(print $cmd | e:shellfirm check --stdin --exit-code >/dev/null 2>/dev/null)
            if (not $ok) {
                echo "shellfirm: blocked: this line is too long to confirm interactively and it matches a risky pattern (or could not be checked). Run it from a script file instead." >/dev/tty
            }
        } else {
            set ok = (shellfirm-check $cmd(shellfirm-sig-code $cmd) $cmd $true)
        }
    } catch err {
        echo "shellfirm: could not check this line ("(to-string $err[reason])"); command not run" >/dev/tty
        set ok = $false
    }
    if $ok {
        shellfirm-next $next $cmd
    } else {
        edit:notify 'shellfirm: the line is kept for editing (Ctrl-U clears it).'
        edit:redraw &full=$true
    }
}
# Load once: evaluating this file again (reloading the rc) must not wrap
# shellfirm's own Enter binding, which would check every line twice. The
# marker holds this shell's pid, so a child elvish installs its own.
fn shellfirm-marker {|b| put $pid':'(repr $b) }
if (not-eq (shellfirm-marker $edit:insert:binding[Enter]) (if (has-env __SHELLFIRM_ELV_ENTER) { get-env __SHELLFIRM_ELV_ENTER } else { put '' })) {
    var shellfirm-binding = { shellfirm-enter }
    set edit:insert:binding[Enter] = $shellfirm-binding
    set-env __SHELLFIRM_ELV_ENTER (shellfirm-marker $shellfirm-binding)
    # Enter rebound after shellfirm loaded (a plugin, `set
    # edit:insert:binding[Enter] = ...`): before the next prompt, check
    # the line first again, then run that binding. This hook keeps itself
    # the last one, so a plugin that rebinds Enter at every prompt from a
    # hook added later is wrapped too.
    var shellfirm-before = $nil
    set shellfirm-before = {
        # PATH emptied for a line shellfirm did not let through: back now.
        if (not-eq $shellfirm-saved-paths $nil) {
            set paths = $shellfirm-saved-paths
            set shellfirm-saved-paths = $nil
        }
        set shellfirm-last-checked = ''
        var hooks = $edit:before-readline
        if (and (> (count $hooks) 0) (not-eq $hooks[-1] $shellfirm-before)) {
            set edit:before-readline = [(each {|h| if (not-eq $h $shellfirm-before) { put $h } } $hooks) $shellfirm-before]
        }
        var cur = $edit:insert:binding[Enter]
        if (not-eq (repr $cur) (repr $shellfirm-binding)) {
            set shellfirm-orig-enter = $cur
            set edit:insert:binding[Enter] = $shellfirm-binding
            if (not $shellfirm-rebound-warned) {
                set shellfirm-rebound-warned = $true
                echo "shellfirm: Enter was rebound after shellfirm loaded; shellfirm now checks the line first, then runs that binding." >/dev/tty
            }
        }
    }
    set edit:before-readline = [$@edit:before-readline $shellfirm-before]
    # The last moment before elvish runs the line: one that did not pass
    # through shellfirm's Enter (rebound by a hook that ran after
    # shellfirm's at this prompt) is checked here. Not confirmed: external
    # programs on it cannot start (PATH is emptied until the next prompt).
    # (No `return` here: it only works inside fn.)
    set edit:after-readline = [$@edit:after-readline {|line|
        # After a passed challenge: "approved, running ..." now, on the row
        # elvish left blank below the answer.
        if (not-eq $shellfirm-approved '') {
            var a = $shellfirm-approved
            set shellfirm-approved = ''
            if (and (not-eq $E:TERM dumb) (not-eq $E:TERM '')) {
                try { print "\e[A" >/dev/tty } catch { }
            }
            try { e:shellfirm pre-command --approved-notice --command=$a </dev/tty >/dev/tty 2>/dev/null } catch { }
        }
        var skip = (or (eq $line $shellfirm-last-checked) (eq (str:trim-space $line) '') (not (has-external shellfirm)))
        if (not $skip) {
            try { set skip = (shellfirm-only-fn $line) } catch { }
        }
        if (not $skip) {
            set shellfirm-last-checked = $line
            var ok = $false
            try {
                set ok = (shellfirm-check $line(shellfirm-sig-code $line) $line $false)
            } catch {
                set ok = $false
            }
            if (not $ok) {
                set shellfirm-saved-paths = $paths
                set paths = []
                echo "shellfirm: this line did not pass through shellfirm's Enter (it was rebound) and was not confirmed: external programs on it will not start (elvish built-ins still run)." >/dev/tty
            }
        }
    }]
}"#;

const XONSH_HOOK: &str = r#"# shellfirm hook for xonsh
import ast as _sf_ast
import builtins as _sf_builtins
import inspect as _sf_inspect
import os as _sf_os
import re as _sf_re
import shlex as _sf_shlex
import shutil as _sf_shutil
import subprocess as _sf_subprocess
import sys as _sf_sys

_sf_state = {"warned": False, "pending": None}
# Lets `shellfirm doctor` tell whether the shell it runs in loaded the hook.
__xonsh__.env["SHELLFIRM_HOOK_PID"] = str(_sf_os.getpid())


def _sf_keep_for_editing(cmd):
    """Put a blocked line back into the next prompt so it can be edited."""
    _sf_state["pending"] = cmd
    shell = getattr(__xonsh__.shell, "shell", None)
    prompter = getattr(shell, "prompter", None)
    if prompter is None:
        # readline backend: a queued line without a newline is put into the
        # next prompt for editing.
        queue = getattr(shell, "cmdqueue", None)
        if queue is not None:
            _sf_state["pending"] = None
            queue.append(cmd)
        return
    if getattr(prompter, "_sf_wrapped", False):
        return
    orig_prompt = prompter.prompt

    def _sf_prompt(*args, **kwargs):
        pending = _sf_state["pending"]
        if pending:
            _sf_state["pending"] = None
            kwargs["default"] = pending
        return orig_prompt(*args, **kwargs)

    prompter.prompt = _sf_prompt
    prompter._sf_wrapped = True


def _sf_code_words(code, out, depth=0):
    """The string constants of a function: the commands a callable alias
    runs (`git push --force ...` compiles to a list of its words)."""
    for c in code.co_consts:
        if isinstance(c, str):
            out.append(c)
        elif isinstance(c, (tuple, frozenset)):
            # `['kubectl', 'delete'] + a` keeps its words in a tuple.
            out.extend(w for w in c if isinstance(w, str))
        elif hasattr(c, "co_consts") and depth < 3:
            _sf_code_words(c, out, depth + 1)


def _sf_expand(line):
    """The line with aliases replaced by what they run, plus the commands
    of callable aliases and literal `@([...])` / `subprocess.run([...])`."""
    extra = []
    try:
        aliases = __xonsh__.aliases
    except Exception:
        aliases = {}
    parts = _sf_re.split(r"(\|\||&&|[;|\n]|\band\b|\bor\b)", line)
    out = []
    for seg in parts[:64]:
        # An alias can name another alias (`nk2` -> `rmr` -> `rm -rf`):
        # follow the chain, each alias once, at most 10 deep.
        seen = set()
        while len(seen) < 10:
            m = _sf_re.match(r"^(\s*)([^\s()]+)(.*)$", seg, _sf_re.S)
            name = m.group(2) if m else None
            if not name or name in seen or name not in aliases:
                break
            seen.add(name)
            try:
                value = aliases[name]
            except Exception:
                break
            if isinstance(value, (list, tuple)):
                seg = m.group(1) + " ".join(_sf_shlex.quote(str(w)) for w in value) + m.group(3)
            elif hasattr(value, "src") and isinstance(getattr(value, "src"), str):
                seg = m.group(1) + value.src + m.group(3)
            elif callable(value):
                try:
                    src = _sf_inspect.getsource(value)
                except Exception:
                    words = []
                    code = getattr(value, "__code__", None)
                    if code is not None:
                        _sf_code_words(code, words)
                    src = " ".join(words)
                if len(src) <= 2000:
                    extra.append(src)
                break
            else:
                break
        out.append(seg)
    text = "".join(out) + "".join(parts[64:])
    for m in _sf_re.finditer(r"(?:@\(|subprocess\.(?:run|call|check_call|check_output|Popen)\()\s*(\[[^\]]*\])", "\n".join([line] + extra)):
        try:
            words = _sf_ast.literal_eval(m.group(1))
            extra.append(" ".join(_sf_shlex.quote(str(w)) for w in words))
        except Exception:
            pass
    # `@($K) delete ...` / `@(cmd)`: the command named by an environment or
    # Python variable, set on this line or earlier in the session.
    if "@(" in line:
        env_set = dict(_sf_re.findall(r"\$([A-Za-z_]\w*)\s*=\s*['\"]([^'\"]*)['\"]", line))
        py_set = {}
        for name, value in _sf_re.findall(r"(?:^|[;\n])\s*([A-Za-z_]\w*)\s*=\s*(\[[^\]]*\]|'[^']*'|\"[^\"]*\")", line):
            try:
                py_set[name] = _sf_ast.literal_eval(value)
            except Exception:
                pass
        for m in _sf_re.finditer(r"@\(\s*(\$?)([A-Za-z_]\w*)\s*\)([^\n;|]*)", line):
            name = m.group(2)
            value = None
            try:
                if m.group(1):
                    value = env_set[name] if name in env_set else __xonsh__.env.get(name)
                elif name in py_set:
                    value = py_set[name]
                else:
                    value = (getattr(__xonsh__, "ctx", None) or {}).get(name)
            except Exception:
                value = None
            if isinstance(value, str):
                words = [value]
            elif isinstance(value, (list, tuple)) and all(isinstance(w, (str, int, float)) for w in value):
                words = [str(w) for w in value]
            else:
                continue
            if words and len(" ".join(words)) <= 4000:
                extra.append(" ".join(_sf_shlex.quote(w) for w in words) + m.group(3))
    # xonsh's own subprocess forms (`![...]`, `$[...]`, `!(...)`, `$(...)`),
    # shell strings handed to Python (`os.system('...')`, `subprocess.run(
    # '...', shell=True)`, `evalx('...')`) and `$K ...` (an environment
    # variable as the command): the commands they run.
    try:
        extra.extend(_sf_hidden_commands("\n".join([line] + extra), line))
    except Exception:
        pass
    return "\n".join([text] + extra)


def _sf_env_value(name, line):
    """The value of $name: set on this line (`$K = 'kubectl'`), else in the session."""
    m = _sf_re.search(r"\$" + _sf_re.escape(name) + r"\s*=\s*(['\"])([^'\"]*)\1", line)
    if m:
        return m.group(2)
    try:
        v = __xonsh__.env.get(name)
    except Exception:
        return None
    if isinstance(v, (list, tuple)) and all(isinstance(w, str) for w in v):
        return " ".join(v)
    return v if isinstance(v, str) else None


_SF_OPENERS = {"![": "]", "$[": "]", "!(": ")", "$(": ")"}
_SF_SHELL_CALL = _sf_re.compile(
    r"\b(os\.system|os\.popen|evalx|execx|subprocess\.(?:run|call|check_call|check_output|Popen|getoutput|getstatusoutput))\s*\("
)
_SF_STRING = _sf_re.compile(
    r"\s*([rRbBuU]?)('{3}[\s\S]*?'{3}|\"{3}[\s\S]*?\"{3}|'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\")"
)


def _sf_closing(text, start, close):
    """Index of the bracket that closes the one before `start` (quotes and
    nested brackets skipped), or -1."""
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack = [close]
    i, n, q = start, len(text), None
    while i < n:
        c = text[i]
        if q:
            if c == "\\":
                i += 2
                continue
            if c == q:
                q = None
        elif c in "'\"":
            q = c
        elif c in pairs:
            stack.append(pairs[c])
        elif c in ")]}":
            if c != stack[-1]:
                return -1
            stack.pop()
            if not stack:
                return i
        i += 1
    return -1


def _sf_literal_or_name(args):
    """The first argument of a call: a string literal, or a Python variable
    holding a string or a list of words; None when it is not known."""
    lit = _SF_STRING.match(args)
    if lit:
        try:
            value = _sf_ast.literal_eval(lit.group(1) + lit.group(2))
        except Exception:
            return None
        if isinstance(value, bytes):
            value = value.decode("utf-8", "replace")
        return value if isinstance(value, str) else None
    name = _sf_re.match(r"\s*([A-Za-z_]\w*)\s*[,)]", args + ")")
    if not name:
        return None
    try:
        v = (getattr(__xonsh__, "ctx", None) or {}).get(name.group(1))
    except Exception:
        return None
    if isinstance(v, str):
        return v
    if isinstance(v, (list, tuple)) and all(isinstance(w, str) for w in v):
        return " ".join(_sf_shlex.quote(w) for w in v)
    return None


def _sf_hidden_commands(src, line):
    out = []
    todo = [src]
    rounds = 0
    while todo and rounds < 32:
        text = todo.pop()
        rounds += 1
        i = 0
        while i < len(text) - 1:
            op = text[i:i + 2]
            if op in _SF_OPENERS and not (i > 0 and text[i - 1] == "\\"):
                end = _sf_closing(text, i + 2, _SF_OPENERS[op])
                if end < 0:
                    break
                inner = text[i + 2:end]
                if inner.strip():
                    out.append(inner)
                    todo.append(inner)
                i = end + 1
                continue
            i += 1
        for m in _SF_SHELL_CALL.finditer(text):
            func = m.group(1)
            end = _sf_closing(text, m.end(), ")")
            args = text[m.end():end] if end >= 0 else text[m.end():]
            if _sf_re.match(r"\s*[\[(]", args):
                continue  # a literal list of words: read above
            shell_text = not func.startswith("subprocess.") or func.endswith("output") \
                or _sf_re.search(r"\bshell\s*=\s*True\b", args)
            value = _sf_literal_or_name(args)
            if value is not None:
                if value.strip():
                    out.append(value)
                    todo.append(value)
            elif shell_text:
                # A shell string that is only known when it runs.
                out.append("shellfirm-unknown-shell-payload " + func)
        # `$K delete ...`: the program named by an environment variable.
        for m in _sf_re.finditer(r"(?:^|[;\n|&(]|\band\b|\bor\b)[ \t]*\$([A-Za-z_]\w*)(?![\w\[(])(?![ \t]*=)([^\n;|&)]*)", text):
            v = _sf_env_value(m.group(1), line)
            if v and v.strip() and len(v) <= 4000:
                out.append(v + m.group(2))
    return out


def _sf_only_alias_def(line):
    """True when the line only defines an alias (`aliases['k'] = 'rm -rf'`,
    a list of words, or a lambda): that runs nothing, and calling the alias
    is what gets checked. A value that runs something now is not skipped."""
    try:
        tree = _sf_ast.parse(line)
    except Exception:
        return False
    if len(tree.body) != 1:
        return False
    node = tree.body[0]
    if isinstance(node, _sf_ast.Assign):
        targets = node.targets
    elif isinstance(node, (_sf_ast.AnnAssign, _sf_ast.AugAssign)):
        targets = [node.target]
    else:
        return False
    for t in targets:
        if not (isinstance(t, _sf_ast.Subscript) and isinstance(t.value, _sf_ast.Name) and t.value.id == "aliases"):
            return False
        if not isinstance(t.slice, _sf_ast.Constant):
            return False
    v = node.value
    if v is None:
        return False
    if isinstance(v, _sf_ast.Lambda):
        # Default values are evaluated when the lambda is made.
        return all(d is None or isinstance(d, _sf_ast.Constant) for d in v.args.defaults + v.args.kw_defaults)
    try:
        _sf_ast.literal_eval(v)
        return True
    except Exception:
        return False


def _sf_check_line(cmd):
    if not cmd or not cmd.strip():
        return cmd
    if _sf_shutil.which("shellfirm") is None:
        if not _sf_state["warned"]:
            _sf_state["warned"] = True
            print("shellfirm: binary not found in PATH; commands are NOT being checked")
        return cmd
    line = cmd.rstrip("\n")
    # Defining a function runs nothing (calling it, or the alias that
    # names it, is what gets checked).
    rows = line.split("\n")
    if _sf_re.match(r"def\s+\w+\s*\(", rows[0]) and all(not r.strip() or r[:1].isspace() for r in rows[1:]):
        return cmd
    if "aliases" in line and _sf_only_alias_def(line):
        return cmd
    try:
        check = _sf_expand(line)
    except Exception:
        check = line
    try:
        if len(check.encode("utf-8", "surrogateescape")) > 100000:
            # Too long to pass as one argument: checked through stdin, no prompt.
            rc = _sf_subprocess.run(
                ["shellfirm", "check", "--stdin", "--exit-code"],
                input=check.encode("utf-8", "surrogateescape"),
                stdout=_sf_subprocess.DEVNULL,
                stderr=_sf_subprocess.DEVNULL,
            ).returncode
            if rc != 0:
                print("shellfirm: blocked: this line is too long to confirm interactively and it matches a risky pattern (or could not be checked). Run it from a script file instead.")
        else:
            # The banner and the audit log show the line as typed, not
            # the expansion checked with it.
            argv = ["shellfirm", "pre-command", "--direct-tty", "--command=" + check]
            if check != line:
                argv.append("--line=" + line)
            rc = _sf_subprocess.call(argv)
    except FileNotFoundError as e:
        # Found on PATH but it does not start (missing interpreter/library).
        print("shellfirm: warning: shellfirm is installed but could not run ({}); this command was NOT checked. Run `shellfirm doctor`.".format(e))
        return cmd
    except OSError as e:
        # Fail closed: the binary exists but could not be run.
        print("shellfirm: could not run shellfirm ({}); command not run".format(e))
        rc = 1
    if rc == 127:
        print("shellfirm: warning: shellfirm is installed but could not run (exit 127); this command was NOT checked. Run `shellfirm doctor`.")
    # 3: allowed after a passed challenge (SHELLFIRM_SIGNAL_PROMPTED=1 in
    # the environment).
    if rc in (0, 3, 127):
        return cmd
    print("shellfirm: the line is kept for editing.")
    _sf_keep_for_editing(line)
    return ""


# Load once: sourcing this file again (reloading the rc) only updates the
# functions above; the handler is registered a single time.
if not getattr(_sf_builtins, "_shellfirm_xonsh_loaded", False):
    _sf_builtins._shellfirm_xonsh_loaded = True

    @events.on_transform_command
    def _shellfirm_transform(cmd, **kwargs):
        # prompt_toolkit's Enter asks whether the line compiles
        # (`can_compile` runs the transform too): nothing runs there, and
        # the line is checked once, when it is run.
        f = _sf_sys._getframe(1)
        for _ in range(6):
            if f is None:
                break
            if f.f_code.co_name == "can_compile":
                return cmd
            f = f.f_back
        return _sf_check_line(cmd)"#;

/// Oils (OSH/YSH): DEBUG trap + history (no `bind -x` in Oils).
const OILS_HOOK: &str = r#"# shellfirm hook for Oils (OSH/YSH)
__shellfirm_hook_version=13
# Lets `shellfirm doctor` tell whether the shell it runs in loaded the hook.
export SHELLFIRM_HOOK_PID=$$
__shellfirm_ready=""
__shellfirm_histnum="__sf_none__"
__shellfirm_blocked=""

__shellfirm_prompt() {
    __shellfirm_ready="1"
    __shellfirm_blocked=""
}

__shellfirm_hook() {
    [[ "$BASH_COMMAND" == __shellfirm_* || "${FUNCNAME[1]:-}" == __shellfirm_* ]] && return 0
    if [[ -z "$__shellfirm_ready" ]]; then
        [[ -n "$__shellfirm_blocked" ]] && return 1
        return 0
    fi
    [[ -n "${COMP_LINE:-}" ]] && return 0
    command -v shellfirm >/dev/null 2>&1 || return 0

    local histnum
    histnum=$(HISTTIMEFORMAT='' builtin history 1 | awk '{print $1}')
    [[ "$histnum" == "$__shellfirm_histnum" ]] && return 0

    __shellfirm_ready=""
    __shellfirm_histnum="$histnum"

    local full_cmd
    full_cmd=$(HISTTIMEFORMAT='' builtin history 1 | sed 's/^[ ]*[0-9]*[ ]*//')
    [[ -z "$full_cmd" ]] && return 0

    shellfirm pre-command --command="$full_cmd"
    case $? in
        0|3|127) return 0 ;;
    esac
    __shellfirm_blocked="1"
    return 1
}

PROMPT_COMMAND="__shellfirm_prompt${PROMPT_COMMAND:+$'\n'$PROMPT_COMMAND}"
shopt -s extdebug
trap '__shellfirm_hook' DEBUG
"#;

/// Hooks written by shellfirm <= 0.3.10, kept verbatim so they can be found
/// and removed (`--uninstall`) or upgraded.
mod legacy {
    pub const NUSHELL_HOOK: &str = r#"# shellfirm hook for nushell
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
)"#;

    pub const POWERSHELL_HOOK: &str = r#"# shellfirm hook for PowerShell
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
}"#;

    pub const ELVISH_HOOK: &str = r#"# shellfirm hook for elvish
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
}"#;

    pub const XONSH_HOOK: &str = r#"# shellfirm hook for xonsh
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
            raise PermissionError("Command blocked by shellfirm")"#;

    /// Printed by `shellfirm init` 0.3.10 (pasted by hand into rc files).
    pub const BASH_HOOK: &str = r#"# shellfirm hook for bash — intercepts risky commands via DEBUG trap.
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
trap '_shellfirm_hook' DEBUG"#;

    /// Printed by `shellfirm init` 0.3.10 (pasted by hand into rc files).
    pub const ZSH_HOOK: &str = r#"# shellfirm hook for zsh — intercepts Enter via the accept-line widget
shellfirm-pre-command() {
    if [[ -z "${BUFFER}" || "${BUFFER}" == *"shellfirm"* ]]; then
        zle .accept-line
        return
    fi
    shellfirm pre-command --direct-tty -c "${BUFFER}"
    if [[ $? -eq 0 ]]; then
        zle .accept-line
    else
        zle reset-prompt
    fi
}
zle -N accept-line shellfirm-pre-command"#;

    /// Printed by `shellfirm init` 0.3.10 (pasted by hand into rc files).
    pub const FISH_HOOK: &str = r#"# shellfirm hook for fish — intercepts Enter via key binding
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
bind -M insert \r _shellfirm_check 2>/dev/null"#;

    /// Printed by `shellfirm init` 0.3.10 (pasted by hand into rc files).
    pub const OILS_HOOK: &str = r#"# shellfirm hook for Oils (OSH/YSH) — same approach as the bash hook.
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
trap '_shellfirm_hook' DEBUG"#;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn env_with(home: &str) -> RcEnv {
        RcEnv {
            home: Some(PathBuf::from(home)),
            platform_config: Some(PathBuf::from(format!("{home}/.platform-config"))),
            zdotdir: None,
            xdg_config_home: None,
        }
    }

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
    fn rc_paths_default_locations() {
        let env = env_with("/h");
        let p = |s: Shell| s.rc_file_path_in(&env).unwrap();
        assert_eq!(p(Shell::Bash), PathBuf::from("/h/.bashrc"));
        assert_eq!(p(Shell::Zsh), PathBuf::from("/h/.zshrc"));
        assert_eq!(p(Shell::Fish), PathBuf::from("/h/.config/fish/config.fish"));
        assert_eq!(p(Shell::Elvish), PathBuf::from("/h/.config/elvish/rc.elv"));
        assert_eq!(p(Shell::Oils), PathBuf::from("/h/.config/oils/oshrc"));
        assert_eq!(p(Shell::Xonsh), PathBuf::from("/h/.xonshrc"));
        assert_eq!(
            p(Shell::Nushell),
            PathBuf::from("/h/.platform-config/nushell/config.nu")
        );
    }

    #[test]
    fn rc_paths_respect_zdotdir_and_xdg() {
        let mut env = env_with("/h");
        env.zdotdir = Some(PathBuf::from("/h/.config/zsh"));
        env.xdg_config_home = Some(PathBuf::from("/xdg"));
        let p = |s: Shell| s.rc_file_path_in(&env).unwrap();
        assert_eq!(p(Shell::Zsh), PathBuf::from("/h/.config/zsh/.zshrc"));
        assert_eq!(p(Shell::Fish), PathBuf::from("/xdg/fish/config.fish"));
        assert_eq!(p(Shell::Nushell), PathBuf::from("/xdg/nushell/config.nu"));
        assert_eq!(p(Shell::Elvish), PathBuf::from("/xdg/elvish/rc.elv"));
        assert_eq!(p(Shell::Bash), PathBuf::from("/h/.bashrc"));
    }

    #[test]
    fn rc_snippet_returns_eval_for_eval_shells() {
        for shell in [Shell::Zsh, Shell::Bash, Shell::Fish, Shell::Oils] {
            assert!(shell.uses_eval());
            assert!(
                shell.rc_snippet().contains("shellfirm init"),
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
            assert!(!shell.uses_eval());
            let block = shell.rc_block();
            assert!(block.contains(shell.hook()));
            assert!(block.trim_end().ends_with(END_MARKER));
        }
    }

    #[test]
    fn hooks_do_not_skip_commands_containing_shellfirm() {
        for shell in Shell::ALL {
            let hook = shell.hook();
            for pattern in [
                "*shellfirm*",
                "*\"shellfirm\"*",
                "str contains \"shellfirm\"",
                "-match 'shellfirm'",
                "\"shellfirm\" in cmd",
                "str:contains $cmd \"shellfirm\"",
            ] {
                assert!(
                    !hook.contains(pattern),
                    "{shell} hook must not skip commands containing 'shellfirm' ({pattern})"
                );
            }
        }
    }

    #[test]
    fn hooks_pass_command_with_equals_form() {
        // `-c "$cmd"` breaks for commands that start with `-`; the
        // `--command=<value>` form is always parsed as a value.
        for shell in Shell::ALL {
            let hook = shell.hook();
            assert!(
                hook.contains("--command="),
                "{shell} hook must use --command="
            );
            assert!(
                !hook.contains("pre-command -c "),
                "{shell} hook must not use -c"
            );
        }
    }

    #[test]
    fn hooks_fail_open_when_binary_missing() {
        assert!(Shell::Bash.hook().contains(
            "if ! builtin type -P shellfirm >/dev/null 2>&1; then\n        __shellfirm_warn_missing\n        return 0"
        ));
        assert!(Shell::Zsh
            .hook()
            .contains("if ! _shellfirm_have_binary; then"));
        assert!(Shell::Fish.hook().contains("if not command -q shellfirm"));
        assert!(Shell::Nushell.hook().contains("which shellfirm | is-empty"));
        assert!(Shell::Elvish.hook().contains("has-external shellfirm"));
        assert!(Shell::Xonsh.hook().contains("which(\"shellfirm\") is None"));
    }

    #[test]
    fn bash_hook_does_not_depend_on_history_in_readline_mode() {
        let hook = Shell::Bash.hook();
        let readline_part = hook.split("# Fallback without readline").next().unwrap();
        assert!(readline_part.contains("READLINE_LINE"));
        assert!(!readline_part.contains("history 1"));
        // `extdebug` is never turned on in the shell itself (only inside a
        // command substitution, to look up where a function was defined).
        assert!(readline_part
            .lines()
            .filter(|l| l.contains("shopt -s extdebug"))
            .all(|l| l.contains("$(builtin shopt -s extdebug;")));
        assert!(!readline_part.contains("trap '__shellfirm"));
    }

    #[test]
    fn zsh_hook_uses_direct_tty_prompt() {
        assert!(
            Shell::Zsh
                .hook()
                .contains("shellfirm pre-command --direct-tty"),
            "zsh hook must force DirectTtyPrompter to avoid crossterm hangs in zle"
        );
    }

    #[test]
    fn zsh_hook_chains_existing_widgets() {
        let hook = Shell::Zsh.hook();
        assert!(hook.contains("zle -A \"$_sf_w\" \"_shellfirm_orig${_sf_n}_$_sf_w\""));
        assert!(hook.contains("accept-and-hold"));
        assert!(hook.contains("$PREBUFFER$BUFFER"));
        // A plugin that replaces accept-line after init is wrapped again at
        // the prompt, before the first command runs.
        assert!(hook.contains("add-zsh-hook precmd _shellfirm_rewrap"));
    }

    #[test]
    fn hooks_resolve_rerun_and_eval_spellings() {
        let bash = Shell::Bash.hook();
        // Quoted `old=new` and single-quoted `eval` payloads are read word
        // by word after removing quotes.
        assert!(bash.contains("__shellfirm_words"));
        assert!(bash.contains("__shellfirm_fc_eval"));
        // The completeness probe sees history- and alias-expanded text.
        assert!(bash.contains("__shellfirm_incomplete_expanded \"$__sf_x\""));
        assert!(bash.contains("${histchars-!^#}"));
        let zsh = Shell::Zsh.hook();
        assert!(zsh.contains("_shellfirm_spell_candidates"));
        assert!(zsh.contains("$_sf_kw == builtin"));
        assert!(zsh.contains("${histchars[1]-}"));
    }

    #[test]
    fn hooks_load_once_and_skip_definitions() {
        assert!(Shell::Elvish.hook().contains("__SHELLFIRM_ELV_ENTER"));
        assert!(Shell::Elvish.hook().contains("shellfirm-only-fn"));
        assert!(Shell::Xonsh.hook().contains("_shellfirm_xonsh_loaded"));
        assert!(Shell::Xonsh.hook().contains("__xonsh__.aliases"));
        assert!(Shell::Fish.hook().contains("__shellfirm_strip_defs"));
        assert!(Shell::Fish.hook().contains("__shellfirm_pending_change"));
        assert!(Shell::Nushell.hook().contains("scope aliases"));
        assert!(Shell::Elvish.limitation().is_some());
        assert!(Shell::Xonsh.limitation().is_some());
    }

    #[test]
    fn eval_shells_hook_contains_shellfirm_pre_command() {
        for shell in [Shell::Zsh, Shell::Bash, Shell::Fish, Shell::Oils] {
            assert!(
                shell.hook().contains("shellfirm pre-command"),
                "{shell} hook must contain 'shellfirm pre-command' for interception"
            );
        }
    }

    #[test]
    fn validate_shell_arg_accepts_known_and_aliases() {
        for shell in Shell::ALL {
            assert!(validate_shell_arg(Some(shell.name())).is_ok());
            for bin in shell.binaries() {
                assert_eq!(validate_shell_arg(Some(bin)).ok(), Some(shell));
            }
        }
        assert_eq!(Shell::from_name("nu"), Some(Shell::Nushell));
        assert_eq!(Shell::from_name("pwsh"), Some(Shell::PowerShell));
        assert_eq!(Shell::from_name("ZSH"), Some(Shell::Zsh));
    }

    #[test]
    fn validate_shell_arg_rejects_unknown() {
        assert!(validate_shell_arg(Some("csh")).is_err());
        assert!(validate_shell_arg(None).is_err());
    }

    #[test]
    fn from_binary_path_detects_shell() {
        assert_eq!(Shell::from_binary_path("/bin/zsh"), Some(Shell::Zsh));
        assert_eq!(
            Shell::from_binary_path("/usr/local/bin/nu"),
            Some(Shell::Nushell)
        );
        assert_eq!(Shell::from_binary_path("/bin/tcsh"), None);
    }

    #[test]
    fn detect_installed_shells_does_not_panic() {
        let _ = detect_installed_shells();
    }

    #[test]
    fn plan_install_new_and_existing_files() {
        assert_eq!(
            plan_install(Shell::Zsh, None),
            InstallPlan::Append(Shell::Zsh.rc_block())
        );
        assert_eq!(
            plan_install(Shell::Zsh, Some("export A=1\n")),
            InstallPlan::Append(Shell::Zsh.rc_block())
        );
        let installed = format!("export A=1\n{}", Shell::Zsh.rc_block());
        assert_eq!(
            plan_install(Shell::Zsh, Some(&installed)),
            InstallPlan::AlreadyInstalled
        );
    }

    #[test]
    fn plan_install_detects_manual_guarded_line() {
        let content = "command -v shellfirm >/dev/null && eval \"$(shellfirm init zsh)\"\n";
        assert_eq!(
            plan_install(Shell::Zsh, Some(content)),
            InstallPlan::AlreadyInstalled
        );
        // ...but a line for another shell does not count.
        assert!(matches!(
            plan_install(Shell::Bash, Some(content)),
            InstallPlan::Append(_)
        ));
    }

    #[test]
    fn plan_install_detects_hand_pasted_hook() {
        let content = format!(
            "$env.config.show_banner = false\n{}\n",
            Shell::Nushell.hook()
        );
        assert_eq!(
            plan_install(Shell::Nushell, Some(&content)),
            InstallPlan::AlreadyInstalled
        );
    }

    #[test]
    fn plan_install_ignores_comment_mentioning_shellfirm_init() {
        let content = "# TODO: try `shellfirm init zsh` some day\n";
        assert!(matches!(
            plan_install(Shell::Zsh, Some(content)),
            InstallPlan::Append(_)
        ));
    }

    #[test]
    fn plan_install_upgrades_legacy_embedded_hook() {
        let legacy = format!("# mine\n\n{MARKER}\n{}\n", legacy::NUSHELL_HOOK);
        let InstallPlan::Upgrade(new_content) = plan_install(Shell::Nushell, Some(&legacy)) else {
            panic!("expected upgrade");
        };
        assert!(new_content.starts_with("# mine\n"));
        assert!(!new_content.contains("str contains \"shellfirm\""));
        assert!(new_content.contains(Shell::Nushell.hook()));
        assert_eq!(
            plan_install(Shell::Nushell, Some(&new_content)),
            InstallPlan::AlreadyInstalled
        );
    }

    #[test]
    fn plan_install_upgrades_older_marked_embedded_hook() {
        let old = format!("a\n\n{MARKER}\n# old hook text\n{END_MARKER}\nb\n");
        let InstallPlan::Upgrade(new_content) = plan_install(Shell::Xonsh, Some(&old)) else {
            panic!("expected upgrade");
        };
        assert!(new_content.contains("a\n"));
        assert!(new_content.contains("b\n"));
        assert!(!new_content.contains("# old hook text"));
        assert_eq!(new_content.matches(MARKER).count(), 1);
    }

    #[test]
    fn install_to_temp_file_and_detect() {
        let dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let rc = dir.root.join(".zshrc");
        fs::write(&rc, format!("# existing config\n{}", Shell::Zsh.rc_block())).unwrap();
        assert!(is_already_installed(&rc, Shell::Zsh));
        fs::write(&rc, "# existing config\n").unwrap();
        assert!(!is_already_installed(&rc, Shell::Zsh));
        assert!(!is_already_installed(&dir.root.join("missing"), Shell::Zsh));
    }

    #[test]
    fn uninstall_removes_block_with_current_marker() {
        let snippet = Shell::Zsh.rc_snippet();
        let content = format!("# my config\nPATH=/usr/bin\n\n{MARKER}\n{snippet}\n");
        let (result, changed) = remove_shellfirm_block(&content, Shell::Zsh);
        assert!(changed);
        assert_eq!(result, "# my config\nPATH=/usr/bin\n");
    }

    #[test]
    fn uninstall_round_trip_is_byte_identical() {
        for shell in Shell::ALL {
            for original in ["", "a=1\n", "a=1", "a=1\n\n# end\n"] {
                let InstallPlan::Append(block) = plan_install(shell, Some(original)) else {
                    panic!("{shell}: expected append");
                };
                let installed = format!("{original}{block}");
                let (result, changed) = remove_shellfirm_block(&installed, shell);
                assert!(changed, "{shell}: block not found");
                assert_eq!(result, original, "{shell}: uninstall must restore the file");
            }
        }
    }

    #[test]
    fn uninstall_removes_embedded_and_legacy_hooks() {
        for shell in [
            Shell::Nushell,
            Shell::PowerShell,
            Shell::Elvish,
            Shell::Xonsh,
        ] {
            let current = format!("# existing stuff\n{}", shell.rc_block());
            let (result, changed) = remove_shellfirm_block(&current, shell);
            assert!(changed, "{shell}");
            assert_eq!(result, "# existing stuff\n", "{shell}");

            let legacy = format!(
                "# existing stuff\n\n{MARKER}\n{}\n",
                shell.legacy_hooks()[0]
            );
            let (result, changed) = remove_shellfirm_block(&legacy, shell);
            assert!(changed, "{shell} legacy");
            assert_eq!(result, "# existing stuff\n", "{shell} legacy");
        }
    }

    #[test]
    fn uninstall_noop_when_not_installed() {
        let content = "# my config\nPATH=/usr/bin\n";
        let (result, changed) = remove_shellfirm_block(content, Shell::Zsh);
        assert!(!changed);
        assert_eq!(result, content);
    }

    #[test]
    fn uninstall_preserves_rest_of_file() {
        let snippet = Shell::Fish.rc_snippet();
        let content =
            format!("# before\nexport FOO=bar\n\n{MARKER}\n{snippet}\n\n# after\nexport BAZ=qux\n");
        let (result, changed) = remove_shellfirm_block(&content, Shell::Fish);
        assert!(changed);
        assert_eq!(
            result,
            "# before\nexport FOO=bar\n\n# after\nexport BAZ=qux\n"
        );
    }

    #[test]
    fn friendly_error_mentions_read_only() {
        let e = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let msg = friendly_io_error("write", Path::new("/x/.zshrc"), &e);
        assert!(msg.contains("/x/.zshrc") && msg.contains("read-only"));
    }

    #[test]
    fn activate_hints() {
        assert_eq!(Shell::Bash.activate_hint(), "exec bash");
        assert_eq!(Shell::Zsh.activate_hint(), "exec zsh");
        assert_eq!(Shell::Fish.activate_hint(), "exec fish");
        assert_eq!(Shell::Oils.activate_hint(), "exec osh");
        assert_eq!(Shell::Nushell.activate_hint(), "exec nu");
        for shell in Shell::ALL {
            assert!(!shell.activate_hint().is_empty());
        }
    }

    #[test]
    fn limitations_documented_for_partial_shells() {
        assert!(Shell::Nushell.limitation().is_some());
        assert!(Shell::Bash.limitation().is_none());
        assert!(Shell::Zsh.limitation().is_none());
    }

    #[test]
    fn from_name_round_trip() {
        for shell in Shell::ALL {
            assert_eq!(Shell::from_name(shell.name()), Some(shell));
        }
    }

    #[test]
    fn display_matches_name() {
        for shell in Shell::ALL {
            assert_eq!(shell.to_string(), shell.name());
        }
    }

    #[test]
    fn hook_snapshots() {
        for shell in Shell::ALL {
            insta::assert_snapshot!(format!("hook_{}", shell.name()), shell.hook());
        }
    }

    /// Run `shell -n` style syntax checks when the shell is installed.
    /// The hook is read from stdin: a Windows path (`C:\Users\…`) is
    /// not a file name every `bash` there understands (WSL's `bash.exe`).
    fn syntax_check(bin: &str, args: &[&str], hook: &str) {
        use std::io::Write as _;
        // A shell that cannot run a trivial command (Windows' WSL launcher
        // without a distribution) cannot judge the hook either.
        let usable = std::process::Command::new(bin)
            .args(["-c", "echo ok"])
            .stdin(std::process::Stdio::null())
            .output()
            .is_ok_and(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "ok");
        if !usable {
            eprintln!("{bin} not installed or not usable; skipping syntax check");
            return;
        }
        let mut child = std::process::Command::new(bin)
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(hook.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "{bin} rejected the hook: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn bash_hook_is_valid_bash() {
        syntax_check("bash", &["-n"], Shell::Bash.hook());
    }

    #[test]
    fn zsh_hook_is_valid_zsh() {
        syntax_check("zsh", &["-n"], Shell::Zsh.hook());
    }

    #[test]
    fn fish_hook_is_valid_fish() {
        syntax_check("fish", &["-n"], Shell::Fish.hook());
    }

    /// Exercise the bash helper functions in a real (interactive, no tty)
    /// bash: completeness detection, alias expansion and the fail-open path.
    #[test]
    fn bash_hook_helpers_behave() {
        let script = format!(
            r#"{hook}
__sf_t() {{ if __shellfirm_incomplete "$1"; then echo "INC:$1"; else echo "COMP:$1"; fi; }}
__sf_t 'echo hi'
__sf_t 'for f in x; do'
__sf_t $'for f in x; do\necho $f\ndone'
__sf_t 'echo "abc'
__sf_t 'cat <<EOF'
__sf_t 'git push \'
__sf_t 'echo a # \'
__sf_t 'echo a )'
alias kd='kubectl delete'
__shellfirm_expand 'kd ns prod'; echo "EXP:$__shellfirm_expanded"
__shellfirm_expand $'git push \\\n-f origin'; echo "EXP:$__shellfirm_expanded"
PATH=/nonexistent __shellfirm_check 'rm -rf /' && echo FAILOPEN
"#,
            hook = Shell::Bash.hook()
        );
        let Ok(out) = std::process::Command::new("bash")
            .args(["--norc", "--noprofile", "-i", "-c", &script])
            .stdin(std::process::Stdio::null())
            .output()
        else {
            eprintln!("bash not installed; skipping");
            return;
        };
        let stdout = String::from_utf8_lossy(&out.stdout);
        // Completeness detection is part of the readline mode (bash 4+).
        let readline = bash_version().is_some_and(|v| v.0 >= 4);
        let completeness = [
            "COMP:echo hi",
            "INC:for f in x; do",
            "COMP:for f in x; do\necho $f\ndone",
            "INC:echo \"abc",
            "INC:cat <<EOF",
            "INC:git push \\",
            "COMP:echo a # \\",
            "COMP:echo a )",
        ];
        let always = [
            "EXP:kubectl delete ns prod",
            "EXP:git push -f origin",
            "FAILOPEN",
        ];
        let readline_only: &[&str] = if readline { &completeness } else { &[] };
        for expected in readline_only.iter().chain(always.iter()) {
            assert!(
                stdout.contains(expected),
                "missing {expected:?} in output:\n{stdout}\nstderr:\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    #[test]
    fn every_hook_reports_the_hook_version() {
        for shell in [
            Shell::Bash,
            Shell::Zsh,
            Shell::Fish,
            Shell::Oils,
            Shell::PowerShell,
        ] {
            assert!(
                shell.hook().contains(&format!(
                    "hook_version{}",
                    match shell {
                        Shell::Fish => format!(" {HOOK_VERSION}"),
                        Shell::PowerShell => format!(" = {HOOK_VERSION}"),
                        _ => format!("={HOOK_VERSION}"),
                    }
                )),
                "{shell} hook must set the hook version {HOOK_VERSION}"
            );
        }
    }

    #[test]
    fn hooks_never_treat_exit_126_as_missing_binary() {
        for shell in Shell::ALL {
            let hook = shell.hook();
            assert!(!hook.contains("126|127"), "{shell}: 126 must fail closed");
            assert!(!hook.contains("0|126|127"), "{shell}: 126 must fail closed");
            assert!(!hook.contains("[126 127]"), "{shell}: 126 must fail closed");
            assert!(
                !hook.contains("(0, 126, 127)"),
                "{shell}: 126 must fail closed"
            );
        }
    }

    #[test]
    fn hooks_check_long_lines_through_stdin() {
        for shell in [
            Shell::Bash,
            Shell::Zsh,
            Shell::Fish,
            Shell::Nushell,
            Shell::Elvish,
            Shell::Xonsh,
        ] {
            let hook = shell.hook();
            assert!(
                hook.contains("check --stdin --exit-code")
                    || hook.contains(r#""check", "--stdin", "--exit-code""#),
                "{shell}: long lines must be checked through stdin"
            );
        }
    }

    #[test]
    fn zsh_hook_does_not_use_widget_variable_for_chaining() {
        let hook = Shell::Zsh.hook();
        assert!(
            !hook.contains("[$WIDGET]"),
            "zsh: $WIDGET is the key widget"
        );
        assert!(hook.contains("functions[_shellfirm_widget_$_sf_w]"));
        assert!(
            hook.contains("_shellfirm_zsh_loaded"),
            "re-sourcing must not re-wrap"
        );
        assert!(hook.contains("bindkey -M isearch"));
    }

    #[test]
    fn nushell_hook_never_claims_builtins_are_stopped() {
        let hook = Shell::Nushell.hook();
        assert!(hook.contains("cannot stop nushell built-ins like rm"));
        assert!(hook.contains("pre-command --test"));
    }

    #[test]
    fn fish_hook_expands_abbreviations_and_wraps_execute() {
        let hook = Shell::Fish.hook();
        assert!(hook.contains("abbr --show"));
        assert!(hook.contains("function commandline"));
        assert!(hook.contains("builtin commandline -f execute"));
    }

    #[test]
    fn plan_install_replaces_hand_pasted_legacy_hook() {
        for shell in [Shell::Bash, Shell::Zsh, Shell::Fish] {
            let content = format!("export A=1\n{}\nexport B=2\n", shell.legacy_hooks()[0]);
            let InstallPlan::Upgrade(new_content) = plan_install(shell, Some(&content)) else {
                panic!("{shell}: expected the old hook to be replaced");
            };
            assert!(legacy_hook_line(&new_content, shell).is_none(), "{shell}");
            assert!(new_content.contains("export A=1\n"), "{shell}");
            assert!(new_content.contains("export B=2\n"), "{shell}");
            assert!(new_content.contains(&shell.rc_snippet()), "{shell}");
            assert_eq!(
                plan_install(shell, Some(&new_content)),
                InstallPlan::AlreadyInstalled
            );
        }
    }

    #[test]
    fn legacy_hook_line_finds_edited_old_hooks() {
        let content = "a=1\n_shellfirm_hook() { :; }\ntrap '_shellfirm_hook' DEBUG\n";
        assert_eq!(legacy_hook_line(content, Shell::Bash), Some(2));
        assert_eq!(
            legacy_hook_line("# trap '_shellfirm_hook' DEBUG\n", Shell::Bash),
            None
        );
        assert_eq!(
            legacy_hook_line("zle -N accept-line shellfirm-pre-command\n", Shell::Zsh),
            Some(1)
        );
        assert_eq!(legacy_hook_line(Shell::Bash.hook(), Shell::Bash), None);
        assert_eq!(legacy_hook_line(Shell::Zsh.hook(), Shell::Zsh), None);
        assert_eq!(legacy_hook_line(Shell::Fish.hook(), Shell::Fish), None);
    }

    #[test]
    fn loader_lines_are_recognised() {
        for (line, shell) in [
            (r#"eval "$(shellfirm init bash)""#, Shell::Bash),
            (r#"eval "$(shellfirm init zsh)";"#, Shell::Zsh),
            (
                r#"eval "$( /usr/local/bin/shellfirm init zsh )""#,
                Shell::Zsh,
            ),
            (
                r#"command -v shellfirm >/dev/null 2>&1 && eval "$(shellfirm init bash)""#,
                Shell::Bash,
            ),
            ("shellfirm init fish | source", Shell::Fish),
        ] {
            assert!(is_loader_line(line, shell), "{line}");
        }
        assert!(!is_loader_line(
            r#"eval "$(shellfirm init zsh)""#,
            Shell::Bash
        ));
        assert!(!is_loader_line(
            r#"# eval "$(shellfirm init bash)""#,
            Shell::Bash
        ));
        assert!(!is_loader_line(
            r#"[ -x x ] && eval "$(shellfirm init bash)" || true"#,
            Shell::Bash
        ));
    }

    #[test]
    fn uninstall_removes_hand_written_eval_line() {
        let content = "a=1\neval \"$(shellfirm init bash)\"\nb=2\n";
        let r = plan_uninstall(content, Shell::Bash);
        assert!(r.changed);
        assert_eq!(r.content, "a=1\nb=2\n");
        assert!(!r.delete_file);
    }

    #[test]
    fn uninstall_keeps_loader_lines_inside_a_construct() {
        let content = "if true; then\neval \"$(shellfirm init bash)\"\nfi\n";
        let r = plan_uninstall(content, Shell::Bash);
        assert!(
            !r.changed,
            "removing it would leave `then` with an empty body"
        );
        let content = "if status is-interactive\n    shellfirm init fish | source\nend\n";
        assert!(!plan_uninstall(content, Shell::Fish).changed);
    }

    #[test]
    fn uninstall_deletes_file_that_init_created() {
        for shell in Shell::ALL {
            let created = format!(
                "{CREATED_NOTE}\n{}",
                shell.rc_block().trim_start_matches('\n')
            );
            let r = plan_uninstall(&created, shell);
            assert!(r.changed && r.delete_file, "{shell}");
            // Something else was added later: keep the file, drop the note.
            let r = plan_uninstall(&format!("{created}alias x=y\n"), shell);
            assert!(r.changed && !r.delete_file, "{shell}");
            assert_eq!(r.content, "alias x=y\n", "{shell}");
        }
        // A file the user created is never deleted, even if it ends up empty.
        let r = plan_uninstall(Shell::Zsh.rc_block().trim_start_matches('\n'), Shell::Zsh);
        assert!(r.changed && !r.delete_file);
        assert_eq!(r.content, "");
    }

    #[test]
    fn created_file_is_already_installed() {
        for shell in Shell::ALL {
            let created = format!(
                "{CREATED_NOTE}\n{}",
                shell.rc_block().trim_start_matches('\n')
            );
            assert_eq!(
                plan_install(shell, Some(&created)),
                InstallPlan::AlreadyInstalled,
                "{shell}"
            );
        }
    }

    #[test]
    fn hook_load_count_detects_double_hooks() {
        let one = format!("a=1\n{}", Shell::Bash.rc_block());
        assert_eq!(hook_load_count(&one, Shell::Bash), 1);
        let two = format!("{one}eval \"$(shellfirm init bash)\"\n");
        assert_eq!(hook_load_count(&two, Shell::Bash), 2);
        // An old hook is reported on its own (legacy_hook_line), not as a
        // second load.
        let legacy = format!("{one}{}\n", legacy::BASH_HOOK);
        assert_eq!(hook_load_count(&legacy, Shell::Bash), 1);
        assert!(legacy_hook_line(&legacy, Shell::Bash).is_some());
    }

    #[test]
    fn init_accepts_every_shell_name_for_completion() {
        let cmd = command();
        let arg = cmd
            .get_arguments()
            .find(|a| a.get_id() == "shell")
            .expect("shell arg");
        let values: Vec<String> = arg
            .get_possible_values()
            .iter()
            .map(|v| v.get_name().to_string())
            .collect();
        for shell in Shell::ALL {
            assert!(values.contains(&shell.name().to_string()), "{shell}");
            for bin in shell.binaries() {
                assert!(values.contains(&(*bin).to_string()), "{bin}");
            }
        }
        let m = command()
            .try_get_matches_from(["init", "ZSH"])
            .expect("case-insensitive");
        assert_eq!(
            m.get_one::<String>("shell").map(String::as_str),
            Some("ZSH")
        );
        assert!(command().try_get_matches_from(["init", "csh"]).is_err());
    }

    /// Exercise the bash expansion helpers: aliases (also `alias g=git`),
    /// functions, `history -s` and `fc -s`.
    #[test]
    fn bash_hook_expansion_behaves() {
        let script = format!(
            r#"{hook}
alias g=git
alias ls='ls -l'
alias s='sudo '
alias k=kubectl
__shellfirm_expand 'g reset --hard'; echo "EXP1:$__shellfirm_expanded"
__shellfirm_expand 'ls -a'; echo "EXP2:$__shellfirm_expanded"
__shellfirm_expand 's k delete ns x'; echo "EXP3:$__shellfirm_expanded"
nuke() {{ rm -rf "$@"; }}
__shellfirm_expand 'nuke build src'; echo "EXP4:${{__shellfirm_expanded//$'\n'/ }}"
del1() {{ kubectl delete ns "$1"; }}
__shellfirm_expand 'del1 prod'; echo "EXP5:${{__shellfirm_expanded//$'\n'/ }}"
__shellfirm_expand 'history -s kubectl delete ns x'; echo "EXP6:[$__shellfirm_expanded]"
__shellfirm_expand 'history -s x; rm -rf y'; echo "EXP7:[$__shellfirm_expanded]"
builtin history -s 'kubectl delete ns st1'
__shellfirm_expand 'fc -s st1=t5 kubectl'; echo "EXP8:$__shellfirm_expanded"
"#,
            hook = Shell::Bash.hook()
        );
        let Ok(out) = std::process::Command::new("bash")
            .args(["--norc", "--noprofile", "-i", "-c", &script])
            .stdin(std::process::Stdio::null())
            .output()
        else {
            eprintln!("bash not installed; skipping");
            return;
        };
        let stdout = String::from_utf8_lossy(&out.stdout);
        for expected in [
            "EXP1:git reset --hard",
            "EXP2:ls -l -a",
            "EXP3:sudo kubectl delete ns x",
            "EXP4:nuke() { rm -rf \"$@\"; } nuke build src",
            "EXP5:del1() { kubectl delete ns \"$1\"; } del1 prod",
            "EXP6:[]",
            "EXP7:[history -s x; rm -rf y]",
            "EXP8:kubectl delete ns t5",
        ] {
            assert!(
                stdout.contains(expected),
                "missing {expected:?} in output:\n{stdout}\nstderr:\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    /// The zsh expansion helper: aliases (also `alias g=git`), global
    /// aliases, functions and `print -s`.
    #[test]
    fn zsh_hook_expansion_behaves() {
        let script = format!(
            r#"{hook}
alias g=git
alias ls='ls -G'
alias -g F=--force
_shellfirm_expand 'g reset --hard'; print -r -- "EXP1:$_shellfirm_expanded"
_shellfirm_expand 'ls -a'; print -r -- "EXP2:$_shellfirm_expanded"
_shellfirm_expand 'git push F origin main'; print -r -- "EXP3:$_shellfirm_expanded"
nuke() {{ rm -rf "$@" }}
_shellfirm_expand 'nuke build src'; print -r -- "EXP4:${{_shellfirm_expanded//$'\n'/ }}"
_shellfirm_expand 'print -s kubectl delete ns x'; print -r -- "EXP5:[$_shellfirm_expanded]"
_shellfirm_expand '  g push'; print -r -- "EXP6:$_shellfirm_expanded"
"#,
            hook = Shell::Zsh.hook()
        );
        let Ok(out) = std::process::Command::new("zsh")
            .args(["-f", "-i", "-c", &script])
            .stdin(std::process::Stdio::null())
            .output()
        else {
            eprintln!("zsh not installed; skipping");
            return;
        };
        let stdout = String::from_utf8_lossy(&out.stdout);
        for expected in [
            "EXP1:git reset --hard",
            "EXP2:ls -G -a",
            "EXP3:git push --force origin main",
            "EXP4:nuke() { rm -rf \"$@\"; } nuke build src",
            "EXP5:[]",
            "EXP6:git push",
        ] {
            assert!(
                stdout.contains(expected),
                "missing {expected:?} in output:\n{stdout}\nstderr:\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    /// `bash`'s (major, minor) version; None when bash is not installed.
    /// Before bash 4 (macOS /bin/bash is 3.2) the hook has no readline
    /// mode (`bind -x`): it uses the DEBUG-trap fallback, so the readline
    /// helpers (`__shellfirm_accept`, `__shellfirm_incomplete`) are not
    /// defined.
    fn bash_version() -> Option<(u32, u32)> {
        let out = std::process::Command::new("bash")
            .args(["-c", "echo ${BASH_VERSINFO[0]} ${BASH_VERSINFO[1]}"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        let mut it = text.split_whitespace().map(|n| n.parse().unwrap_or(0));
        Some((it.next()?, it.next()?))
    }

    /// Runs `script` in an interactive bash with the hook loaded; None when
    /// bash is not installed.
    fn run_bash(script: &str) -> Option<(String, String)> {
        let script = format!("{}\n{script}", Shell::Bash.hook());
        let out = std::process::Command::new("bash")
            .args(["--norc", "--noprofile", "-i", "-c", &script])
            .stdin(std::process::Stdio::null())
            .output()
            .ok()?;
        Some((
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        ))
    }

    fn assert_has(out: &(String, String), expected: &[&str]) {
        for e in expected {
            assert!(
                out.0.contains(e),
                "missing {e:?} in output:\n{}\nstderr:\n{}",
                out.0,
                out.1
            );
        }
    }

    /// Aliases and functions are expanded in every command of a line, not
    /// only at its start.
    #[test]
    fn bash_hook_expands_every_command_of_a_line() {
        let Some(out) = run_bash(
            r#"
alias kd='kubectl delete'
nuke() { rm -rf "$@"; }
for c in 'true && kd ns b' 'time kd ns c' '(kd ns d)' '{ kd ns e; }' 'x=1 kd ns f' \
         'echo | kd ns g' '! kd ns h' 'if true; then kd ns j; fi' 'echo hi; nuke build'; do
  __shellfirm_expand "$c"; echo "EXP:${__shellfirm_expanded//$'\n'/ }"
done
big="kd ns bigal # $(printf '%0120000d' 0)"
__shellfirm_expand "$big" 1; echo "BIG:${__shellfirm_expanded:0:23}"
"#,
        ) else {
            return;
        };
        assert_has(
            &out,
            &[
                "EXP:true && kubectl delete ns b",
                "EXP:time kubectl delete ns c",
                "EXP:(kubectl delete ns d)",
                "EXP:{ kubectl delete ns e; }",
                "EXP:x=1 kubectl delete ns f",
                "EXP:echo | kubectl delete ns g",
                "EXP:! kubectl delete ns h",
                "EXP:if true; then kubectl delete ns j; fi",
                "nuke() { rm -rf \"$@\"; } echo hi; nuke build",
                "BIG:kubectl delete ns bigal",
            ],
        );
    }

    /// `fc -s` re-runs are resolved wherever they appear and however `fc`
    /// is spelled; `command fc` / `builtin fc` with an editor are refused.
    #[test]
    fn bash_hook_resolves_fc_reruns_anywhere() {
        let Some(out) = run_bash(
            r#"
builtin history -s 'kubectl delete ns st1'
for c in 'command fc -s st1=a kubectl' '\fc -s st1=b kubectl' 'fc -s st1=c kubectl && true' \
         'eval fc -s st1=d kubectl' 'x=1 fc -s st1=e kubectl' 'builtin fc -e - st1=f kubectl'; do
  __shellfirm_block_msg=""; __shellfirm_expand "$c"; echo "EXP:${__shellfirm_expanded//$'\n'/ | }"
done
__shellfirm_block_msg=""; __shellfirm_expand 'command fc'; echo "BLOCK:$__shellfirm_block_msg"
__shellfirm_block_msg=""; __shellfirm_expand 'fc -l'; echo "LIST:[$__shellfirm_block_msg]"
"#,
        ) else {
            return;
        };
        assert_has(
            &out,
            &[
                "EXP:kubectl delete ns a",
                "EXP:kubectl delete ns b",
                "kubectl delete ns c",
                "kubectl delete ns d",
                "kubectl delete ns e",
                "EXP:kubectl delete ns f",
                "BLOCK:shellfirm: `command fc`",
                "LIST:[]",
            ],
        );
    }

    /// A line that bash rejected (history expansion failed) is not kept:
    /// the next line is checked on its own, with `!` references expanded.
    #[test]
    fn bash_hook_drops_lines_bash_rejected() {
        // `__shellfirm_accept` is the readline mode's Enter (bash 4+).
        if bash_version().is_some_and(|v| v.0 < 4) {
            eprintln!("bash older than 4: no readline mode; skipping");
            return;
        }
        let Some(out) = run_bash(
            r#"
set -H
builtin history -s 'kubectl delete ns hx7'
__shellfirm_check() { echo "CHECK:${1//$'\n'/ | }"; return 0; }
bind() { :; }
READLINE_LINE='echo "hello!world"'; __shellfirm_accept
READLINE_LINE='!kubectl'; __shellfirm_accept
READLINE_LINE='for i in 1; do'; __shellfirm_accept
READLINE_LINE='kubectl delete ns x; done'; __shellfirm_accept
"#,
        ) else {
            return;
        };
        assert_has(
            &out,
            &[
                "CHECK:kubectl delete ns hx7",
                "CHECK:for i in 1; do | kubectl delete ns x; done",
            ],
        );
        assert!(!out.0.contains("hello!world | !kubectl"), "{}", out.0);
        assert!(!out.1.contains("history expansion failed"), "{}", out.1);
    }

    /// zsh: aliases in every command, suffix aliases, `r` / `fc -e -`
    /// re-runs anywhere on the line and `builtin fc` with an editor.
    #[test]
    fn zsh_hook_expands_every_command_of_a_line() {
        let script = format!(
            r#"{hook}
alias kd='kubectl delete'
alias -s d='rm -rf'
print -s 'kubectl delete ns z1'
# In `zsh -c` the newest history entry stands for the line being run, and
# `r` / `fc` skip it (as they skip the typed line in an interactive shell).
print -s ': the line being run'
for c in 'true && kd ns b' 'time kd ns c' '(kd ns d)' '{{ kd ns e }}' 'x=1 kd ns f' 'build.d' \
         'r z1=z2 kubectl; true' 'true; r z1=z3 kubectl' 'builtin fc -e - z1=z4 kubectl'; do
  _shellfirm_block_msg=""; _shellfirm_expand "$c"; print -r -- "EXP:${{_shellfirm_expanded//$'\n'/ | }}"
done
_shellfirm_block_msg=""; _shellfirm_expand 'builtin fc'; print -r -- "BLOCK:$_shellfirm_block_msg"
"#,
            hook = Shell::Zsh.hook()
        );
        let Ok(out) = std::process::Command::new("zsh")
            .args(["-f", "-i", "-c", &script])
            .stdin(std::process::Stdio::null())
            .output()
        else {
            eprintln!("zsh not installed; skipping");
            return;
        };
        let out = (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        );
        assert_has(
            &out,
            &[
                "EXP:true && kubectl delete ns b",
                "EXP:time kubectl delete ns c",
                "EXP:( kubectl delete ns d )",
                "EXP:{ kubectl delete ns e }",
                "EXP:x=1 kubectl delete ns f",
                "EXP:rm -rf build.d",
                "kubectl delete ns z2",
                "kubectl delete ns z3",
                "EXP:kubectl delete ns z4",
                "BLOCK:shellfirm: `builtin fc`",
            ],
        );
    }

    #[test]
    fn every_hook_exports_its_pid_for_doctor() {
        for shell in Shell::ALL {
            assert!(
                shell.hook().contains("SHELLFIRM_HOOK_PID"),
                "{shell}: doctor needs SHELLFIRM_HOOK_PID"
            );
        }
    }

    #[test]
    fn elvish_hook_never_throws_from_the_parse_probe() {
        let hook = Shell::Elvish.hook();
        assert!(hook.contains("-compileonly -json"));
        assert!(hook.contains("try { e:elvish"));
        assert!(!hook.contains("var parsed = (e:elvish"));
    }

    #[test]
    fn bash_hook_runs_one_process_per_enter() {
        let hook = Shell::Bash.hook();
        // The dry run is only used when shellfirm prints warnings; the
        // banner already shows the command.
        assert!(hook.contains("if [[ $__shellfirm_notes == 1 ]]; then"));
        // pre-command says when it prompted (exit 3): no timing guess.
        assert!(hook.contains("SHELLFIRM_SIGNAL_PROMPTED=1 builtin command shellfirm pre-command"));
        assert!(!hook.contains("EPOCHREALTIME"));
        assert!(!hook.contains("shellfirm: checking:"));
    }

    #[test]
    fn uninstall_dry_run_notes_match_a_real_uninstall() {
        let content = format!("a=1\n{}", Shell::Bash.rc_block());
        let r = plan_uninstall(&content, Shell::Bash);
        assert!(r.changed);
        // What a dry run reports as left over is computed on this content.
        assert!(!has_manual_hook(&r.content, Shell::Bash));
    }

    #[test]
    fn uninstall_removes_directories_init_created() {
        let dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let created = dir.root.join("cfg/nushell");
        let rc = created.join("config.nu");
        let content = format!(
            "{CREATED_NOTE}\n{CREATED_DIR_NOTE}{}\n{CREATED_DIR_NOTE}{}\n{}",
            created.display(),
            dir.root.join("cfg").display(),
            Shell::Nushell.rc_block().trim_start_matches('\n')
        );
        let r = plan_uninstall(&content, Shell::Nushell);
        assert!(r.delete_file);
        assert_eq!(r.created_dirs, vec![created.clone(), dir.root.join("cfg")]);
        fs::create_dir_all(&created).unwrap();
        fs::write(dir.root.join("keep"), "").unwrap();
        remove_created_dirs(&rc, &r.created_dirs);
        assert!(!dir.root.join("cfg").exists());
        // Never anything that is not an ancestor of the rc file, nor a
        // directory that is not empty.
        fs::create_dir_all(dir.root.join("other")).unwrap();
        fs::create_dir_all(dir.root.join("full/x")).unwrap();
        remove_created_dirs(
            &dir.root.join("full/x/rc"),
            &[dir.root.join("other"), dir.root.join("full")],
        );
        assert!(dir.root.join("other").exists() && dir.root.join("full").exists());
    }

    #[test]
    fn rc_report_finds_the_hook_in_fish_conf_d() {
        let dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let env = RcEnv {
            home: Some(dir.root.clone()),
            platform_config: None,
            zdotdir: None,
            xdg_config_home: Some(dir.root.join("cfg")),
        };
        fs::create_dir_all(dir.root.join("cfg/fish/conf.d")).unwrap();
        fs::write(dir.root.join("cfg/fish/config.fish"), "set -g x 1\n").unwrap();
        fs::write(
            dir.root.join("cfg/fish/conf.d/shellfirm.fish"),
            "shellfirm init fish | source\n",
        )
        .unwrap();
        let r = rc_report_in(Shell::Fish, &env);
        assert!(!r.installed);
        assert_eq!(
            r.loaded_from,
            Some(dir.root.join("cfg/fish/conf.d/shellfirm.fish"))
        );
    }

    /// Lines of `out` (stdout) that start with `prefix`.
    fn lines_with<'a>(out: &'a (String, String), prefix: &str) -> Vec<&'a str> {
        out.0.lines().filter(|l| l.starts_with(prefix)).collect()
    }

    /// bash: code a line installs to run by itself (`bind -x`, a
    /// command_not_found_handle) is checked when it is defined; a command
    /// named by a session variable is resolved; a chain of functions deeper
    /// than the expansion limit is still read (as written), a recursive one
    /// ends, and only a call graph past the budget is flagged.
    #[test]
    fn bash_hook_checks_autorun_code_session_variables_and_deep_chains() {
        let Some(out) = run_bash(
            r#"
export K=kubectl
nk() { kubectl delete ns fv; }
f=nk
a1() { kubectl delete ns d1; }; a2() { a1; }; a3() { a2; }; a4() { a3; }; a6() { a4; }
e1() { echo hi; }; e2() { e1; }; e3() { e2; }; e4() { e3; }; e5() { e4; }
c0() { echo leaf; }
for i in $(seq 1 80); do eval "c$i() { c$((i-1)); }"; done
pc() { kubectl delete ns pcf; }
rec() { rec; }
for c in "bind -x '\"\\C-t\": kubectl delete ns bx'" 'command_not_found_handle() { kubectl delete ns cn; }' \
         '$K delete ns s1' '${K} delete ns s2' 'echo a; ${K} delete ns s3' '$f'; do
  __shellfirm_expand "$c"; echo "EXP:${__shellfirm_expanded//$'\n'/ | }"
done
for c in "PROMPT_COMMAND='kubectl delete ns p1'" 'PROMPT_COMMAND=pc' "PROMPT_COMMAND+=('kubectl delete ns p2')" \
         "PS1='\$(kubectl delete ns p3) \$ '" 'trap pc USR1'; do
  __shellfirm_expand "$c"; echo "AUTO:${__shellfirm_expanded//$'\n'/ | }"
done
for c in a3 a4 a6 e5 c80 rec; do
  __shellfirm_expand "$c"; echo "DEPTH-$c:${__shellfirm_expanded//$'\n'/ | }"
done
"#,
        ) else {
            return;
        };
        assert_has(
            &out,
            &[
                "| kubectl delete ns bx",
                "| { kubectl delete ns cn; }",
                "kubectl delete ns s1",
                "kubectl delete ns s2",
                "kubectl delete ns s3",
                "kubectl delete ns fv",
            ],
        );
        let auto = lines_with(&out, "AUTO:").join("\n");
        for want in [
            "kubectl delete ns p1",
            "kubectl delete ns pcf",
            "kubectl delete ns p2",
            "kubectl delete ns p3",
        ] {
            assert!(auto.contains(want), "{want}: {auto}");
        }
        assert_eq!(auto.matches("kubectl delete ns pcf").count(), 2, "{auto}");
        let depth = |name: &str| lines_with(&out, &format!("DEPTH-{name}:")).join("\n");
        for name in ["a3", "a4", "a6"] {
            assert!(
                depth(name).contains("kubectl delete ns d1"),
                "{name}: {}",
                depth(name)
            );
        }
        for name in ["a3", "a4", "a6", "e5", "rec"] {
            assert!(
                !depth(name).contains("shellfirm-"),
                "{name}: {}",
                depth(name)
            );
        }
        assert!(
            depth("c80").contains("shellfirm-function-depth-limit"),
            "{}",
            depth("c80")
        );
    }

    /// bash: functions with non-ASCII names are followed; what an
    /// assignment adds to PROMPT_COMMAND is checked however it is spelled
    /// (and a default that is not used is not); a function a DEBUG trap runs
    /// is a hook root; a big function sourced by a relative path counts as
    /// loaded from a file, one typed at the prompt (`main`) does not.
    #[test]
    fn bash_hook_reads_unicode_names_prompt_command_idioms_and_trap_roots() {
        let Some(out) = run_bash(
            r#"
nettoyé() { kubectl delete ns na1; }
日本() { kubectl delete ns na2; }
for c in 'nettoyé' '日本' 'x=1; nettoyé'; do
  __shellfirm_expand "$c"; echo "NA:${__shellfirm_expanded//$'\n'/ | }"
done
for c in 'PROMPT_COMMAND="${PROMPT_COMMAND:+$PROMPT_COMMAND; }kubectl delete ns q1"' \
         "PROMPT_COMMAND=\${PROMPT_COMMAND:+\$PROMPT_COMMAND;}'kubectl delete ns q2'" \
         "PROMPT_COMMAND[1]='kubectl delete ns q3'" \
         'PROMPT_COMMAND="$(true);kubectl delete ns q4"'; do
  __shellfirm_expand "$c"; echo "PC:${__shellfirm_expanded//$'\n'/ | }"
done
__shellfirm_expand 'PROMPT_COMMAND="${PROMPT_COMMAND:-kubectl delete ns q9}"'; echo "PCDEF:${__shellfirm_expanded//$'\n'/ | }"
g() { true; }
__shellfirm_traps="trap -- 'g' DEBUG"
__shellfirm_expand 'g() { kubectl delete ns t1; }'; echo "TRAP:${__shellfirm_expanded//$'\n'/ | }"
__shellfirm_relfns=" bigf|./nvm.sh"
__shellfirm_from_file bigf ./nvm.sh && echo REL:yes
__shellfirm_from_file bigf main || echo MAIN:no
__shellfirm_from_file other ./nvm.sh || echo OTHER:no
"#,
        ) else {
            return;
        };
        assert_has(
            &out,
            &[
                "kubectl delete ns na1",
                "kubectl delete ns na2",
                "REL:yes",
                "MAIN:no",
                "OTHER:no",
            ],
        );
        let na = lines_with(&out, "NA:");
        assert_eq!(na.len(), 3, "{na:?}");
        assert!(
            na.iter().all(|l| l.contains("kubectl delete ns na")),
            "{na:?}"
        );
        let pc = lines_with(&out, "PC:").join("\n");
        // The line itself, and what it adds after it.
        for want in ["q1", "q2", "q3", "q4"] {
            assert_eq!(
                pc.matches(&format!("kubectl delete ns {want}")).count(),
                2,
                "{want}: {pc}"
            );
        }
        let pcdef = lines_with(&out, "PCDEF:").join("\n");
        // Before bash 4.4 the hook cannot evaluate what the assignment adds
        // (`__shellfirm_pc_added`) and reads it as text: an unused default
        // is checked too (fail safe).
        if bash_version().is_some_and(|v| v >= (4, 4)) {
            assert!(!pcdef.contains("| kubectl delete ns q9"), "{pcdef}");
        }
        let trap = lines_with(&out, "TRAP:").join("\n");
        assert!(trap.contains("| g"), "{trap}");
    }

    /// bash: the functions a line calls go with it as one-line definitions
    /// (the check binds their arguments, `shift` included); a body that
    /// rewrites its arguments is also sent as written; every cap ends in
    /// the depth-limit marker; redefining a function a hook runs is checked.
    #[test]
    fn bash_hook_sends_function_definitions() {
        let Some(out) = run_bash(
            r#"
sh1() { shift; rm -rf "$1"; }
sh3() { set -- "$2"; rm -rf "$1"; }
h9() { kubectl delete ns wd1; }
g() { true; }; inner() { true; }; outer() { inner; }
PROMPT_COMMAND="outer;g"
eval "big() { $(for i in $(seq 1 900); do printf 'echo %s;' "line-number-$i"; done) }"
for c in 'sh1 nothere src' 'sh3 nothere src' 'A=1 B=2 C=3 D=4 E=5 F=6 G=7 H=8 I=9 h9' \
         'g() { kubectl delete ns rd1; }' 'inner() { kubectl delete ns rd2; }' 'plain() { kubectl delete ns no; }' 'big'; do
  __shellfirm_expand "$c"; echo "DEF-${c%% *}:${__shellfirm_expanded//$'\n'/ | }"
done
"#,
        ) else {
            return;
        };
        let get = |name: &str| lines_with(&out, &format!("DEF-{name}:")).join("\n");
        assert!(
            get("sh1").contains(r#"sh1() { shift; rm -rf "$1"; } | sh1 nothere src"#),
            "{}",
            get("sh1")
        );
        assert!(get("sh3").contains("| { "), "raw body: {}", get("sh3"));
        assert!(get("A=1").contains("| h9 "), "{}", get("A=1"));
        assert!(get("g()").ends_with("| g"), "{}", get("g()"));
        assert!(get("inner()").ends_with("| inner"), "{}", get("inner()"));
        assert!(!get("plain()").contains("| plain"), "{}", get("plain()"));
        assert!(
            get("big").contains("shellfirm-function-depth-limit big"),
            "{}",
            get("big")
        );
    }

    /// bash: the binding repair runs after the other PROMPT_COMMAND entries
    /// (a plugin can rebind Enter in one of them).
    #[test]
    fn bash_hook_repairs_enter_last_in_prompt_command() {
        let hook = Shell::Bash.hook();
        assert!(hook.contains("__shellfirm_postcmd() {"));
        assert!(hook.contains("PROMPT_COMMAND=$__sf_e$'\\n'__shellfirm_postcmd"));
        assert!(hook.contains("precmd_functions=(\"${__sf_keep[@]}\" __shellfirm_postcmd)"));
        // Every bypass is reported, not only the first.
        assert!(hook.contains("the last command did not pass through shellfirm"));
    }

    /// zsh: hook functions, widgets and `*_functions` entries defined or
    /// registered on a line are checked; `$K` / `${(P)n}` from the session;
    /// deep chains fail closed; a zle-line-finish check backs up Enter.
    #[test]
    fn zsh_hook_checks_autorun_code_session_variables_and_deep_chains() {
        let hook = Shell::Zsh.hook();
        assert!(hook.contains("_sf_h+=(\"$(( _sf_max + 1 )):_shellfirm_line_finish\")"));
        assert!(hook.contains("__shellfirm_doctor_probe() {"));
        assert!(hook.contains("_shellfirm_doctor_probe() { __shellfirm_doctor_probe \"$@\" }"));
        let script = format!(
            r#"{hook}
K=kubectl; n=K
a1() {{ kubectl delete ns d1 }}; a2() {{ a1 }}; a3() {{ a2 }}; a4() {{ a3 }}; a6() {{ a4 }}
e1() {{ echo hi }}; e2() {{ e1 }}; e3() {{ e2 }}; e4() {{ e3 }}; e5() {{ e4 }}
c0() {{ echo leaf }}
for i in {{1..80}}; do functions[c$i]="c$((i-1))"; done
pc() {{ kubectl delete ns pcf }}
zd=${{TMPDIR:-/tmp}}/sfz$$; mkdir -p $zd; print -r -- 'kubectl delete ns al' > $zd/nukez; fpath=($zd $fpath); autoload -Uz nukez
for c in 'autoload -Uz add-zsh-hook; add-zsh-hook precmd pc' "functions[precmd]='kubectl delete ns fp'" \
         "PROMPT='\$(kubectl delete ns pr)%# '" 'nukez'; do
  _shellfirm_block_msg=""; _shellfirm_expand "$c"; print -r -- "AUTO:${{_shellfirm_expanded//$'\n'/ | }}"
done
for c in a3 a4 a6 e5 c80; do _shellfirm_expand $c; print -r -- "DEPTH-$c:${{_shellfirm_expanded//$'\n'/ | }}"; done
rm -rf $zd
for c in 'precmd() {{ kubectl delete ns pc; }}' 'w() {{ kubectl delete ns w1; }}; zle -N w' \
         'g() {{ kubectl delete ns pe; }}; preexec_functions+=(g)' 'TRAPDEBUG() {{ kubectl delete ns td; }}' \
         '$K delete ns s1' '${{(P)n}} delete ns s2' 'x="kubectl delete ns ev"; eval $x' 'plain() {{ kubectl delete ns no; }}'; do
  _shellfirm_block_msg=""; _shellfirm_expand "$c"; print -r -- "EXP:${{_shellfirm_expanded//$'\n'/ | }}"
done
"#
        );
        let Ok(out) = std::process::Command::new("zsh")
            .args(["-f", "-i", "-c", &script])
            .stdin(std::process::Stdio::null())
            .output()
        else {
            eprintln!("zsh not installed; skipping");
            return;
        };
        let out = (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        );
        assert_has(
            &out,
            &[
                "| { kubectl delete ns pc ; }",
                "| { kubectl delete ns w1 ; }",
                "| { kubectl delete ns pe ; }",
                "| { kubectl delete ns td ; }",
                "kubectl delete ns s1",
                "kubectl delete ns s2",
                "kubectl delete ns ev",
            ],
        );
        let exp = lines_with(&out, "EXP:plain()").join("\n");
        assert!(
            !exp.contains("| {"),
            "a plain function definition runs nothing: {exp}"
        );
        let auto = lines_with(&out, "AUTO:").join("\n");
        for want in [
            "kubectl delete ns pcf",
            "kubectl delete ns fp",
            "kubectl delete ns pr",
            "kubectl delete ns al",
        ] {
            assert!(auto.contains(want), "{want}: {auto}");
        }
        let depth = |name: &str| lines_with(&out, &format!("DEPTH-{name}:")).join("\n");
        for name in ["a3", "a4", "a6"] {
            assert!(
                depth(name).contains("kubectl delete ns d1"),
                "{name}: {}",
                depth(name)
            );
        }
        for name in ["a3", "a4", "a6", "e5"] {
            assert!(
                !depth(name).contains("shellfirm-"),
                "{name}: {}",
                depth(name)
            );
        }
        assert!(
            depth("c80").contains("shellfirm-function-depth-limit"),
            "{}",
            depth("c80")
        );
    }

    /// fish: fish's own functions (`cd`, `prevd`, `ls`, ...) are not
    /// expanded, redirections stay intact, arguments cannot add operators,
    /// event handlers and `bind` commands are checked, deep chains fail
    /// closed.
    #[test]
    fn fish_hook_function_expansion() {
        let hook = Shell::Fish.hook();
        assert!(hook.contains("\"$__fish_data_dir/functions/*\""));
        let script = format!(
            r#"{hook}
function nuke; kubectl delete ns $argv; end
function redir; echo hi >&2; echo $argv[1] 2>&1; end
function a1; kubectl delete ns $argv; end; function a2; a1 $argv; end; function a3; a2 $argv; end; function a4; a3 $argv; end
for c in 'cd /tmp' 'prevd' 'ls' 'nuke q1' 'redir "a;b"' 'echo (nuke q2)' 'command nuke q3'
    set -g __shellfirm_fn_seen
    set -l r (__shellfirm_function_bodies $c | string join ' | ')
    echo "FB:$c=>$r"
end
set -g __shellfirm_fn_seen; set r (__shellfirm_function_bodies 'a1 x' probe); echo "PROBE:$r"
set r (__shellfirm_bind_commands "bind \ct 'kubectl delete ns bd'; bind \ce end-of-line" | string join ' | '); echo "BIND:$r"
set r (__shellfirm_strip_defs 'function hk --on-event fish_prompt; kubectl delete ns ev; end' | string join ' | '); echo "DEFS:$r"
set r (__shellfirm_strip_defs 'function hk; kubectl delete ns ev; end' | string join ' | '); echo "PLAIN:$r"
set r (__shellfirm_strip_defs 'function fish_prompt; kubectl delete ns fp; end' | string join ' | '); echo "PROMPTFN:$r"
"#
        );
        let Ok(out) = std::process::Command::new("fish")
            .args(["--no-config", "-i", "-c", &script])
            .stdin(std::process::Stdio::null())
            .output()
        else {
            eprintln!("fish not installed; skipping");
            return;
        };
        let out = (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        );
        assert_has(
            &out,
            &[
                "FB:cd /tmp=>\n",
                "FB:prevd=>\n",
                "FB:ls=>\n",
                "kubectl delete ns q1",
                "echo hi >&2; echo 'a;b' 2>&1;",
                "kubectl delete ns q2",
                "FB:command nuke q3=>\n",
                "PROBE:a1",
                "BIND:kubectl delete ns bd\n",
                "DEFS:function hk --on-event fish_prompt",
                "PLAIN:\n",
                "PROMPTFN:function fish_prompt",
            ],
        );
    }

    #[test]
    fn nushell_install_notes_and_uninstall_removes_the_created_env_nu() {
        let dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let rc = dir.root.join("config.nu");
        assert_eq!(
            companion_file(Shell::Nushell, &rc),
            Some(dir.root.join("env.nu"))
        );
        assert_eq!(companion_file(Shell::Bash, &rc), None);
        assert_eq!(
            create_companion(Shell::Nushell, &rc),
            Some(dir.root.join("env.nu"))
        );
        // Already there: not created (and so not noted) again.
        assert_eq!(create_companion(Shell::Nushell, &rc), None);
        let content = format!(
            "{CREATED_NOTE}\n{CREATED_FILE_NOTE}{}\n{}",
            dir.root.join("env.nu").display(),
            Shell::Nushell.rc_block().trim_start_matches('\n')
        );
        let r = plan_uninstall(&content, Shell::Nushell);
        assert!(r.delete_file);
        assert_eq!(r.created_files, vec![dir.root.join("env.nu")]);
        // Not empty any more: kept.
        fs::write(dir.root.join("env.nu"), "$env.X = 1").unwrap();
        remove_created_files(&rc, &r.created_files);
        assert!(dir.root.join("env.nu").exists());
        fs::write(dir.root.join("env.nu"), "").unwrap();
        remove_created_files(&rc, &r.created_files);
        assert!(!dir.root.join("env.nu").exists());
        // Never a file that is not next to the rc file.
        fs::create_dir_all(dir.root.join("other")).unwrap();
        fs::write(dir.root.join("other/env.nu"), "").unwrap();
        remove_created_files(&rc, &[dir.root.join("other/env.nu")]);
        assert!(dir.root.join("other/env.nu").exists());
    }

    /// nushell: a program named by `$env.NAME` (set earlier or on the
    /// line) is resolved; xonsh: `@($K)` / `@(cmd)` from the session.
    #[test]
    fn nushell_and_xonsh_hooks_resolve_session_variables() {
        let nu = Shell::Nushell.hook();
        assert!(nu.contains(r"\^?\$env\.(?P<n>[A-Za-z_][A-Za-z0-9_]*)"));
        assert!(nu.contains("$env | get -i $l.n"));
        let xonsh = Shell::Xonsh.hook();
        assert!(xonsh.contains("__xonsh__.env.get(name)"));
        assert!(xonsh.contains(r#"(getattr(__xonsh__, "ctx", None) or {}).get(name)"#));
    }

    /// elvish: a binding that rewrites the line after the check (a plugin
    /// loaded before shellfirm) has the new line checked before it runs.
    #[test]
    fn elvish_hook_rechecks_a_rewritten_line() {
        let hook = Shell::Elvish.hook();
        assert!(hook.contains("fn shellfirm-recheck {|cmd|"));
        assert!(hook.contains("shellfirm-recheck $cmd"));
        assert!(hook.contains("set paths = $shellfirm-saved-paths"));
    }
}
