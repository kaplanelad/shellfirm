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
                .value_parser([
                    log::LevelFilter::Off.as_str(),
                    log::LevelFilter::Trace.as_str(),
                    log::LevelFilter::Debug.as_str(),
                    log::LevelFilter::Info.as_str(),
                    log::LevelFilter::Warn.as_str(),
                    log::LevelFilter::Error.as_str(),
                ])
                .default_value(log::Level::Info.as_str())
                .ignore_case(true),
        )
}
