pub mod audit_cmd;
pub mod check_cmd;
pub mod command;
pub mod completions_cmd;
pub mod config;
pub mod connect_cmd;
pub mod default;
pub mod doctor_cmd;
pub mod init;
#[cfg(feature = "mcp")]
pub mod mcp_cmd;
pub mod policy_cmd;
pub mod status_cmd;
#[cfg(feature = "wrap")]
pub mod wrap_cmd;

/// `--config-dir DIR` for `status`, `config` and `audit` (global, so it can
/// go before or after their subcommands): use the configuration in DIR
/// instead of the default location or `SHELLFIRM_CONFIG_DIR`. DIR must
/// exist (exit 2 otherwise), as for `check --config-dir`.
pub fn config_dir_arg() -> clap::Arg {
    clap::Arg::new("config-dir")
        .long("config-dir")
        .value_name("DIR")
        .global(true)
        .help("Use the shellfirm configuration in DIR (settings, custom checks, audit log)")
}
