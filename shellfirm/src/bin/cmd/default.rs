use clap::crate_version;
use clap::{Arg, Command};

pub fn command() -> Command<'static> {
    Command::new("shellfirm")
        .version(env!("VERGEN_GIT_SEMVER"))
        .version(crate_version!())
        .about("XXX")
        .arg(
            Arg::new("log")
                .long("log")
                .help("Set logging level")
                .value_name("LEVEL")
                .possible_values(vec![
                    log::LevelFilter::Off.as_str(),
                    log::LevelFilter::Trace.as_str(),
                    log::LevelFilter::Debug.as_str(),
                    log::LevelFilter::Info.as_str(),
                    log::LevelFilter::Warn.as_str(),
                    log::LevelFilter::Error.as_str(),
                ])
                .default_value(log::Level::Info.as_str())
                .ignore_case(true)
                .takes_value(true),
        )
}
