//! Project cli command interface

use clap::{crate_name, crate_version, App, Arg};

pub const UPDATE_CONFIGURATION_OVERRIDE: &str = "override";

pub const UPDATE_CONFIGURATION_ONLY_DIFF: &str = "only-diff";

pub fn get_app() -> App<'static> {
    App::new(crate_name!())
        .version(crate_version!())
        // .about("TODO...")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .help("External configuration file path.")
                .takes_value(true),
        )
        .subcommand(
            App::new("pre-command")
                .about("Check if given command marked as sensitive command that need your extra approval.")
                .arg(
                    Arg::new("command")
                        .short('c')
                        .long("command")
                        .help("get the user command that should run.")
                        .required(true)
                        .takes_value(true),
                ),
        )
        .subcommand(
            App::new("update-configuration")
                .about("Update configuration file")
                .arg(
                    Arg::new("behavior") 
                        .short('b')
                        .long("behavior")
                        .help("The behavior of the update, you can replace your existing one with the default config application or just add new checks")
                        .possible_values(&[UPDATE_CONFIGURATION_OVERRIDE, UPDATE_CONFIGURATION_ONLY_DIFF])
                        .default_value(UPDATE_CONFIGURATION_ONLY_DIFF)
                        .takes_value(true)
                ),
        )
}
