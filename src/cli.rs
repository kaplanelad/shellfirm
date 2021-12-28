//! Project cli command interface

use clap::{crate_name, crate_version, App, Arg};

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
}
