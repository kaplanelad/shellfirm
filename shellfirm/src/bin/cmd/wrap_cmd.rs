use std::path::Path;

use clap::{Arg, ArgMatches, Command};
use console::style;
use shellfirm::error::Result;
use shellfirm::{
    checks::Check,
    config,
    env::{Environment, RealEnvironment},
    policy,
    wrap::{check_startup, LiveRules, PtyProxy, StatementMode, WrapperConfig},
    Config, Settings,
};

pub fn command() -> Command {
    Command::new("wrap")
        .about("Wrap an interactive program with shellfirm PTY protection")
        .long_about(
            "Launch an interactive program (psql, mysql, redis-cli, mongosh, ...) inside a PTY proxy.\n\
             When you press Enter, shellfirm checks the statement(s) the program is about to run\n\
             (`;`-terminated SQL, one line for redis-cli/shells, `;` or a complete line for mongosh)\n\
             and holds them back until any challenge is solved. Declining a challenge discards the\n\
             statement and keeps your session open.\n\n\
             The real client is detected through sudo, docker/podman exec, kubectl exec and ssh.\n\n\
             What is checked, beyond plain statements:\n  \
               - the client's own command line, before it starts: psql -c/-f, mysql -e,\n    \
                 mongosh --eval and script files, sqlite3 <db> \"SQL\", redis-cli <command>,\n    \
                 clickhouse-client -q, cqlsh -e/-f, sqlcmd -Q/-q/-i (so an alias\n    \
                 psql='shellfirm wrap psql' protects `psql -c ...` without a shell hook).\n  \
               - client commands that run files or shell commands: psql \\i/\\ir/\\!/\\e/\\gexec,\n    \
                 \\o|cmd/\\g|cmd/\\w|cmd, mysql source/\\./system/\\!, sqlite3 .read/.shell and\n    \
                 .once/.output/.import '|cmd', mongosh load(). Local files are read the way the\n    \
                 client reads them (DELIMITER, client commands and nested includes, up to 8 levels\n    \
                 deep), line by line up to 256 MiB; files that cannot be read (or are larger) get a\n    \
                 Medium challenge.\n  \
               - settings changed while the session is open (`shellfirm config deny ...`) apply\n    \
                 from the next Enter.\n  \
               - psql \\set variables are substituted; mysql DELIMITER and `use db` are understood.\n  \
               - string literals are data: `INSERT ... VALUES ('DROP TABLE x')` is not flagged.\n  \
               - keys typed into a pager/editor or at a password prompt never become part of a\n    \
                 statement, and passwords are never logged.\n\n\
             If you approve or decline a statement in the middle of a paste, the rest of the paste\n\
             is NOT sent (it was typed before you saw the warning). Lines before the challenged one\n\
             were already sent, so check your transaction (COMMIT/ROLLBACK) before going on.\n\n\
             Examples:\n  \
               shellfirm wrap psql -h localhost -U postgres\n  \
               shellfirm wrap redis-cli\n  \
               shellfirm wrap kubectl exec -it pg-0 -- psql\n  \
               shellfirm wrap --tool psql ./my-psql-wrapper.sh\n  \
               shellfirm wrap --delimiter ';' mysql -u root",
        )
        .arg(
            Arg::new("delimiter")
                .long("delimiter")
                .short('d')
                .help("Override the statement delimiter (e.g. ';' or '\\n' for one statement per line)")
                .num_args(1),
        )
        .arg(
            Arg::new("tool")
                .long("tool")
                .visible_alias("as")
                .help("Treat the program as this tool (psql, mysql, redis-cli, mongosh, ...)")
                .num_args(1),
        )
        .trailing_var_arg(true)
        .arg(
            Arg::new("command")
                .help("The program to wrap and its arguments")
                .required(true)
                .num_args(1..)
                .allow_hyphen_values(true),
        )
}

/// Outcome of looking a program up on `PATH`.
enum Lookup {
    Found,
    NotFound,
    NotExecutable,
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        path.metadata()
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

fn lookup_program(program: &str) -> Lookup {
    if program.contains('/') || program.contains('\\') {
        let p = Path::new(program);
        return if !p.exists() {
            Lookup::NotFound
        } else if is_executable(p) {
            Lookup::Found
        } else {
            Lookup::NotExecutable
        };
    }
    #[cfg(windows)]
    {
        // PATHEXT resolution is left to the ConPTY spawn.
        Lookup::Found
    }
    #[cfg(not(windows))]
    {
        let mut saw_non_exec = false;
        for dir in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
            let candidate = dir.join(program);
            if candidate.exists() {
                if is_executable(&candidate) {
                    return Lookup::Found;
                }
                saw_non_exec = true;
            }
        }
        if saw_non_exec {
            Lookup::NotExecutable
        } else {
            Lookup::NotFound
        }
    }
}

/// Load the settings and the active checks the way `shellfirm` does at
/// startup (custom checks, project policy). Used to pick up settings
/// changed while a wrap session is open.
fn load_rules(config: &Config) -> Option<(Settings, Vec<Check>)> {
    let (mut settings, error) = config.load_settings_lenient();
    if let Some(e) = error {
        tracing::warn!("[wrap] settings: {e}");
    }
    let custom = config::load_custom_checks_report(&config.custom_checks_dir());
    settings.migrate_custom_groups_into_enabled_groups(&custom.checks);
    settings.apply_custom_check_challenges(&custom.explicit_challenges);
    let env = RealEnvironment;
    let cwd = env.current_dir().unwrap_or_default();
    let discovery = policy::discover_all(&env, &cwd);
    if let Some(p) = &discovery.policy {
        let _ = policy::apply_to_settings(&mut settings, p);
    }
    let checks = settings
        .get_active_checks_enforced(&custom.checks, discovery.policy.as_ref())
        .ok()?;
    Some((settings, checks))
}

fn fail(code: i32, msg: &str) -> shellfirm::CmdExit {
    eprintln!("{} {msg}", style("shellfirm wrap:").red().bold());
    shellfirm::CmdExit {
        code,
        message: None,
    }
}

/// What the client runs from its own command line (`psql -c`, `-f`,
/// `mysql -e`, `mongosh --eval`, ...) is checked before it starts, so an
/// alias `psql='shellfirm wrap psql'` protects it with or without a shell
/// hook. Returns the exit to use when it was not approved.
fn check_command_line(
    wrapper_config: &WrapperConfig,
    program: &str,
    args: &[String],
    settings: &Settings,
    active_checks: &[Check],
    checks: &[Check],
    config: &Config,
) -> Option<shellfirm::CmdExit> {
    #[cfg(unix)]
    let prompter = shellfirm::prompt::DirectTtyPrompter;
    #[cfg(not(unix))]
    let prompter = shellfirm::prompt::TerminalPrompter;
    let env = RealEnvironment;
    let rules = LiveRules::new(settings, active_checks, checks, wrapper_config);
    let ctx = rules.context(&env, &prompter, config);
    let decision = check_startup(wrapper_config, program, args, &ctx, &|_| {});
    (!decision.forward).then(|| {
        fail(
            1,
            &format!(
                "{} was not started: what its command line runs was not approved.",
                wrapper_config.display_name
            ),
        )
    })
}

#[allow(clippy::unnecessary_wraps, clippy::too_many_lines)] // same signature as the other subcommands
pub fn run(
    matches: &ArgMatches,
    settings: &Settings,
    checks: &[Check],
    config: &Config,
) -> Result<shellfirm::CmdExit> {
    let mut cmd_args: Vec<String> = matches
        .get_many::<String>("command")
        .expect("command is required")
        .cloned()
        .collect();

    let program = cmd_args.remove(0);
    let args = cmd_args;

    match lookup_program(&program) {
        Lookup::Found => {}
        Lookup::NotFound => return Ok(fail(127, &format!("{program}: command not found"))),
        Lookup::NotExecutable => return Ok(fail(126, &format!("{program}: permission denied"))),
    }

    let cli_delimiter = matches.get_one::<String>("delimiter").map(String::as_str);
    let wrapper_config = matches.get_one::<String>("tool").map_or_else(
        || WrapperConfig::resolve(&program, &args, cli_delimiter, &settings.wrappers),
        |tool| {
            let mut wc = WrapperConfig::resolve(tool, &[], cli_delimiter, &settings.wrappers);
            wc.program.clone_from(&program);
            wc
        },
    );

    tracing::info!(
        "shellfirm wrap: program={}, tool={}, delimiter={:?}, check_groups={:?}",
        wrapper_config.program,
        wrapper_config.tool,
        wrapper_config.delimiter,
        wrapper_config.check_groups
    );

    let active_checks = wrapper_config.filter_checks(checks);

    let groups = if wrapper_config.check_groups.is_empty() {
        "all enabled groups".to_string()
    } else {
        wrapper_config.check_groups.join(", ")
    };
    let unit = match wrapper_config.mode {
        StatementMode::Line => "each line".to_string(),
        StatementMode::Delimited {
            delimiter,
            enter_completes: true,
            ..
        } => format!("statements ending with '{delimiter}' or a complete line"),
        // sqlcmd runs a batch at a `GO` line too.
        StatementMode::Delimited { delimiter, .. } if wrapper_config.tool == "sqlcmd" => {
            format!("statements ending with '{delimiter}' or a GO line")
        }
        StatementMode::Delimited { delimiter, .. } => {
            format!("statements ending with '{delimiter}'")
        }
    };
    if active_checks.is_empty() {
        eprintln!(
            "{} no active checks for {} (groups: {groups}) — nothing will be intercepted. \
             Check `enabled_groups` / `wrappers.tools.{}.check_groups` in your settings.",
            style("shellfirm wrap: warning:").yellow().bold(),
            wrapper_config.display_name,
            wrapper_config.tool
        );
    } else {
        eprintln!(
            "{}",
            style(format!(
                "shellfirm: protecting {} ({} checks from {groups}; checking {unit} on Enter)",
                wrapper_config.display_name,
                active_checks.len()
            ))
            .dim()
        );
    }

    let env = RealEnvironment;
    if let Some(exit) = check_command_line(
        &wrapper_config,
        &program,
        &args,
        settings,
        &active_checks,
        checks,
        config,
    ) {
        return Ok(exit);
    }
    // `shellfirm config deny ...` in another terminal applies to this
    // session on the next Enter.
    let reload = || load_rules(config);
    let proxy = PtyProxy {
        wrapper_config,
        settings,
        checks: &active_checks,
        all_checks: checks,
        env: &env,
        config,
        reload: Some(&reload),
        watch: vec![config.setting_file_path.clone(), config.custom_checks_dir()],
    };

    match proxy.run(&program, &args) {
        Ok(code) => Ok(shellfirm::CmdExit {
            code,
            message: None,
        }),
        Err(e) => {
            let msg = e.to_string();
            let code = if msg.contains("command not found") {
                127
            } else if msg.contains("permission denied") {
                126
            } else {
                1
            };
            Ok(fail(code, &msg))
        }
    }
}
