//! Project cli command interface

use clap::{crate_name, crate_version, App, Arg};

pub fn get_app() -> App<'static> {
    App::new(crate_name!())
        .version(crate_version!())
        .about("TODO...")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .help("External configuration file path.")
                .takes_value(true),
        )
}
