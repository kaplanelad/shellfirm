use clap::{crate_version, Arg, Command};

pub fn command() -> Command {
    Command::new("shellfirm")
        .version(crate_version!())
        .about("Protect yourself from risky shell commands with interactive challenges")
        .arg_required_else_help(true)
        .after_help(
            "Environment:\n  \
             SHELLFIRM_CONFIG_DIR=DIR  configuration directory for every command (settings,\n    \
             custom checks, audit log); DIR must exist (exit 2 otherwise). --config-dir\n    \
             wins; shell hooks, agent hooks and `shellfirm mcp` fall back to the default location\n  \
             SHELLFIRM_NO_CONTEXT=1    run no external programs (git, kubectl, du, ...)\n  \
             SHELLFIRM_LOG=LEVEL       log level (off|error|warn|info|debug|trace); --log wins\n  \
             NO_COLOR=1                no colour (TERM=dumb / monochrome terminals: none either)",
        )
        .arg(
            Arg::new("log")
                .long("log")
                .help("Set the log level (logs go to stderr; overrides SHELLFIRM_LOG)")
                .value_name("LEVEL")
                .value_parser(["off", "trace", "debug", "info", "warn", "error"])
                .ignore_case(true)
                .global(true)
                // Listed under its own heading in every subcommand's help,
                // instead of in the middle of that command's own options.
                .help_heading("Global options"),
        )
}
