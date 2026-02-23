use clap::{Arg, ArgMatches, Command};
use shellfirm::error::Result;
use shellfirm::{
    checks::Check,
    env::RealEnvironment,
    prompt::TerminalPrompter,
    wrap::{PtyProxy, WrapperConfig},
    Config, Settings,
};

pub fn command() -> Command {
    Command::new("wrap")
        .about("Wrap an interactive program with shellfirm PTY protection")
        .long_about(
            "Launch an interactive program (psql, mysql, redis-cli, etc.) inside a PTY proxy.\n\
             shellfirm intercepts statements at the delimiter boundary (`;` for SQL, `\\n` for\n\
             line-oriented tools) and runs them through the check pipeline before forwarding.\n\n\
             Examples:\n  \
               shellfirm wrap psql -h localhost -U postgres\n  \
               shellfirm wrap redis-cli\n  \
               shellfirm wrap --delimiter ';' mysql -u root",
        )
        .arg(
            Arg::new("delimiter")
                .long("delimiter")
                .short('d')
                .help("Override the statement delimiter (e.g. ';' or '\\n')")
                .num_args(1),
        )
        .trailing_var_arg(true)
        .arg(
            Arg::new("command")
                .help("The program to wrap and its arguments")
                .required(true)
                .num_args(1..)
                .allow_hyphen_values(true),
        )
}

pub fn run(
    matches: &ArgMatches,
    settings: &Settings,
    checks: &[Check],
    config: &Config,
) -> Result<shellfirm::CmdExit> {
    let mut cmd_args: Vec<String> = matches
        .get_many::<String>("command")
        .expect("command is required")
        .cloned()
        .collect();

    let program = cmd_args.remove(0);
    let args = cmd_args;

    let cli_delimiter = matches.get_one::<String>("delimiter").map(String::as_str);

    let wrapper_config = WrapperConfig::resolve(&program, cli_delimiter, &settings.wrappers);

    tracing::info!(
        "shellfirm wrap: program={}, delimiter={:?}, check_groups={:?}",
        wrapper_config.program,
        wrapper_config.delimiter,
        wrapper_config.check_groups
    );

    // If wrapper has specific check_groups, filter checks accordingly
    let active_checks: Vec<Check> = if wrapper_config.check_groups.is_empty() {
        checks.to_vec()
    } else {
        checks
            .iter()
            .filter(|c| wrapper_config.check_groups.contains(&c.from))
            .cloned()
            .collect()
    };

    let env = RealEnvironment;
    let prompter = TerminalPrompter;

    let proxy = PtyProxy {
        wrapper_config,
        settings,
        checks: &active_checks,
        env: &env,
        prompter: &prompter,
        config,
    };

    let exit_code = proxy.run(&program, &args)?;

    Ok(shellfirm::CmdExit {
        code: exit_code,
        message: None,
    })
}
