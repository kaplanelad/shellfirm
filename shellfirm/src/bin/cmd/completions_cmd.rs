use clap::{Arg, ArgMatches, Command};
use clap_complete::{generate, Generator, Shell};

pub fn command() -> Command {
    Command::new("completions")
        .about("Generate shell completion scripts")
        .arg(
            Arg::new("shell")
                .help("Shell to generate completions for: bash, zsh, fish, elvish, powershell, nushell")
                .required(true)
                .value_parser(["bash", "zsh", "fish", "elvish", "powershell", "nushell"]),
        )
}

pub fn run(matches: &ArgMatches, app: &mut Command) -> shellfirm::CmdExit {
    let shell_name = matches
        .get_one::<String>("shell")
        .expect("shell argument is required");

    match shell_name.as_str() {
        "bash" => generate_completions(Shell::Bash, app),
        "zsh" => generate_completions(Shell::Zsh, app),
        "fish" => generate_completions(Shell::Fish, app),
        "elvish" => generate_completions(Shell::Elvish, app),
        "powershell" => generate_completions(Shell::PowerShell, app),
        "nushell" => generate_completions(clap_complete_nushell::Nushell, app),
        _ => {
            return shellfirm::CmdExit {
                code: exitcode::USAGE,
                message: Some(format!(
                    "Unsupported shell: {shell_name}. Supported: bash, zsh, fish, elvish, powershell, nushell"
                )),
            };
        }
    }

    shellfirm::CmdExit {
        code: exitcode::OK,
        message: None,
    }
}

fn generate_completions(gen: impl Generator, app: &mut Command) {
    generate(gen, app, "shellfirm", &mut std::io::stdout());
}
