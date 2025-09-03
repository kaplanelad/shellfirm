use clap::{builder::PossibleValuesParser, crate_version, Arg, Command};

pub fn command() -> Command {
    Command::new("shellfirm")
        .version(crate_version!())
        .about("Intercept any risky patterns")
        .arg(
            Arg::new("log")
                .long("log")
                .help("Set logging level")
                .value_name("LEVEL")
                .value_parser(PossibleValuesParser::new([
                    "off", "trace", "debug", "info", "warn", "error",
                ]))
                .default_value("info")
                .ignore_case(true)
                .global(true),
        )
}
