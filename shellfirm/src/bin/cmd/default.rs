use clap::{crate_version, Arg, Command};

pub fn command() -> Command {
    Command::new("shellfirm")
        .version(crate_version!())
        .about("Protect yourself from risky shell commands with interactive challenges")
        .arg_required_else_help(true)
        .arg(
            Arg::new("log")
                .long("log")
                .help("Set logging level")
                .value_name("LEVEL")
                .value_parser(["off", "trace", "debug", "info", "warn", "error"])
                .default_value("error")
                .ignore_case(true),
        )
}
