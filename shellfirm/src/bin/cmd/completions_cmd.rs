use clap::{Arg, ArgMatches, Command};
use clap_complete::{generate, Generator, Shell};

/// Names accepted by `shellfirm completions` (binary names too).
const NAMES: [&str; 12] = [
    "bash",
    "zsh",
    "fish",
    "elvish",
    "powershell",
    "pwsh",
    "nushell",
    "nu",
    "xonsh",
    "oils",
    "osh",
    "ysh",
];

pub fn command() -> Command {
    Command::new("completions")
        .about("Generate shell completion scripts")
        .long_about(
            "Generate a shell completion script on stdout.\n\n\
             xonsh and Oils load bash completion scripts, so `xonsh` and `oils` (osh) \
             print the bash script.",
        )
        .arg(
            Arg::new("shell")
                .help(
                    "Shell to generate completions for: bash, zsh, fish, elvish, \
                     powershell (pwsh), nushell (nu), xonsh, oils (osh, ysh)",
                )
                .required(true)
                .ignore_case(true)
                .value_parser(NAMES),
        )
}

/// Positional values that are free text for the parser (validated, case
/// insensitively, by the subcommand) but a fixed set for completion. Without
/// them the generated scripts offer a literal placeholder such as `[value]`.
const VALUE_HINTS: &[(&[&str], &str, &[&str])] = &[
    (&["config", "challenge"], "value", &["Math", "Enter", "Yes"]),
    (&["config", "approved-notice"], "value", &["on", "off"]),
    (
        &["config", "severity"],
        "level",
        &["all", "Info", "Low", "Medium", "High", "Critical"],
    ),
    (
        &["config", "escalation", "check"],
        "challenge",
        &["Math", "Enter", "Yes"],
    ),
    (
        &["config", "escalation", "group"],
        "challenge",
        &["Math", "Enter", "Yes"],
    ),
];

/// Apply [`VALUE_HINTS`] to `cmd` (only for generating completions).
fn with_value_hints(cmd: Command) -> Command {
    fn apply(cmd: Command, path: &[&str], arg: &str, values: &'static [&'static str]) -> Command {
        match path.split_first() {
            None => {
                if cmd.get_arguments().any(|a| a.get_id() == arg) {
                    cmd.mut_arg(arg, |a| a.value_parser(values.to_vec()))
                } else {
                    cmd
                }
            }
            Some((first, rest)) => {
                if cmd.find_subcommand(first).is_some() {
                    cmd.mut_subcommand(*first, |sub| apply(sub, rest, arg, values))
                } else {
                    cmd
                }
            }
        }
    }
    VALUE_HINTS.iter().fold(cmd, |cmd, (path, arg, values)| {
        apply(cmd, path, arg, values)
    })
}

pub fn run(matches: &ArgMatches, app: &mut Command) -> shellfirm::CmdExit {
    *app = with_value_hints(std::mem::replace(app, Command::new("shellfirm")));
    let shell_name = matches
        .get_one::<String>("shell")
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    let script = match shell_name.as_str() {
        "bash" | "oils" | "osh" | "ysh" => generate_completions(Shell::Bash, app),
        "xonsh" => {
            let mut script =
                b"# shellfirm completions for xonsh: xonsh reads bash completion scripts.\n\
                 # Save this file and add its path to $BASH_COMPLETIONS in ~/.xonshrc.\n"
                    .to_vec();
            script.extend(generate_completions(Shell::Bash, app));
            script
        }
        "zsh" => generate_completions(Shell::Zsh, app),
        "fish" => {
            let mut script = generate_completions(Shell::Fish, app);
            script.extend(fish_positional_values(app).into_bytes());
            script
        }
        "elvish" => generate_completions(Shell::Elvish, app),
        "powershell" | "pwsh" => generate_completions(Shell::PowerShell, app),
        "nushell" | "nu" => generate_completions(clap_complete_nushell::Nushell, app),
        _ => {
            return shellfirm::CmdExit {
                code: exitcode::USAGE,
                message: Some(format!(
                    "Unsupported shell: {shell_name}. Supported: {}",
                    NAMES.join(", ")
                )),
            };
        }
    };

    // Generated into memory and written once, so a closed pipe
    // (`shellfirm completions bash | head`) exits quietly instead of
    // panicking inside the generator.
    let text = String::from_utf8_lossy(&script);
    crate::print_stdout(text.strip_suffix('\n').unwrap_or(&text))
}

/// `clap_complete`'s fish script completes options and subcommands but not
/// positional values (`shellfirm init <TAB>`). One `complete` line per
/// positional argument that has a fixed set of values.
fn fish_positional_values(app: &Command) -> String {
    fn walk(cmd: &Command, path: &mut Vec<String>, out: &mut String) {
        use std::fmt::Write as _;
        if !path.is_empty() {
            for arg in cmd.get_positionals().filter(|a| !a.is_hide_set()) {
                let values: Vec<String> = arg
                    .get_possible_values()
                    .iter()
                    .filter(|v| !v.is_hide_set())
                    .map(|v| v.get_name().to_string())
                    .collect();
                if values.is_empty() {
                    continue;
                }
                let values = values.join(" ");
                let mut cond = format!("__fish_shellfirm_using_subcommand {}", path[0]);
                for p in &path[1..] {
                    let _ = write!(cond, "; and __fish_seen_subcommand_from {p}");
                }
                // Not once a value was given.
                let _ = write!(cond, "; and not __fish_seen_subcommand_from {values}");
                let _ = writeln!(
                    out,
                    "complete -c shellfirm -n \"{cond}\" -f -a \"{values}\""
                );
            }
        }
        for sub in cmd.get_subcommands().filter(|s| !s.is_hide_set()) {
            path.push(sub.get_name().to_string());
            walk(sub, path, out);
            path.pop();
        }
    }
    let mut out = String::new();
    walk(app, &mut Vec::new(), &mut out);
    out
}

fn generate_completions(gen: impl Generator, app: &mut Command) -> Vec<u8> {
    let mut buf = Vec::new();
    generate(gen, app, "shellfirm", &mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> Command {
        with_value_hints(
            Command::new("shellfirm")
                .subcommand(super::super::init::command())
                .subcommand(super::super::config::command())
                .subcommand(command()),
        )
    }

    fn generated(shell: &str) -> String {
        let mut app = app();
        let mut buf = Vec::new();
        match shell {
            "bash" => generate(Shell::Bash, &mut app, "shellfirm", &mut buf),
            "zsh" => generate(Shell::Zsh, &mut app, "shellfirm", &mut buf),
            _ => unreachable!(),
        }
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn fish_completes_positional_values() {
        let script = fish_positional_values(&app());
        let init = script
            .lines()
            .find(|l| l.contains("__fish_shellfirm_using_subcommand init;"))
            .unwrap_or_default();
        assert!(init.contains("-a \"bash zsh fish"), "{script}");
        assert!(script.contains("__fish_shellfirm_using_subcommand completions;"));
        assert!(script.contains("__fish_seen_subcommand_from challenge"));
        assert!(script.contains("Math Enter Yes"));
    }

    #[test]
    fn accepts_binary_names() {
        for name in ["nu", "xonsh", "oils", "osh", "ysh", "pwsh", "Bash"] {
            assert!(
                command()
                    .try_get_matches_from(["completions", name])
                    .is_ok(),
                "{name}"
            );
        }
        assert!(command()
            .try_get_matches_from(["completions", "csh"])
            .is_err());
    }

    #[test]
    fn completion_scripts_offer_init_shell_values() {
        // clap_complete's fish generator does not complete positional
        // values, so only bash and zsh are checked.
        for shell in ["bash", "zsh"] {
            let script = generated(shell);
            for value in ["nushell", "xonsh", "oils"] {
                assert!(script.contains(value), "{shell} completions miss {value}");
            }
            assert!(!script.contains("[shell]"), "{shell}: literal placeholder");
        }
        let bash = generated("bash");
        for placeholder in ["[value]", "[level]", "[challenge]"] {
            assert!(!bash.contains(placeholder), "bash: literal {placeholder}");
        }
        assert!(bash.contains("Math Enter Yes"));
    }
}
