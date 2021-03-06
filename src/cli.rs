//! Project cli command interface

use clap::{crate_name, crate_version, App, Arg};

/// List of files name on `checks` folder. populated in `build.rs`.
const ALL_GROUP_CHECKS: &[&str] = &include!(concat!(env!("OUT_DIR"), "/all_the_files.rs"));

/// Return the APP cli.
pub fn get_app() -> App<'static> {
    App::new(crate_name!())
        .version(crate_version!())
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
                ).arg(
                    Arg::new("test")
                        .short('t')
                        .long("test")
                        .help("Check if the command is risky and exit")
                        .takes_value(false),
                ),
        )
        .subcommand(
            App::new("config")
                .about("Manage app config")
                .subcommand(
                    App::new("update")
                        .about("add/remove check group")
                        .arg(
                            Arg::new("check-group") 
                                .short('c')
                                .long("check-group")
                                .help("Check group")
                                .possible_values(ALL_GROUP_CHECKS)
                                .multiple_values(true)
                                .required(true)
                                .min_values(1)
                        )
                        .arg(
                            Arg::new("remove") 
                                .long("remove")
                                .help("remove the given checks")
                                .possible_values(ALL_GROUP_CHECKS)
                                .takes_value(false)
                        ),
                )
                .subcommand(
                    App::new("reset")
                        .about("Reset configuration")
                )
                .subcommand(
                    App::new("challenge")
                        .about("Reset configuration")
                        .arg(
                            Arg::new("challenge") 
                                .long("challenge")
                                .help("Change challenge prompt")
                                .possible_values(&["Math", "Enter", "Yes"])
                                .required(true)
                                .takes_value(true)
                        ),
                )
        )
}
