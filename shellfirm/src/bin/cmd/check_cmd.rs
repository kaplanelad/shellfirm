use std::fmt::Write;

use clap::{Arg, ArgAction, ArgMatches, Command};
use shellfirm::error::Result;
use shellfirm::{
    blast_radius,
    checks::{self, Check},
    env::RealEnvironment,
    Settings,
};

pub fn command() -> Command {
    Command::new("check")
        .about("Test commands against shellfirm checks or list available checks")
        .arg_required_else_help(true)
        .arg(
            Arg::new("command")
                .short('c')
                .long("command")
                .help("Command to test (dry-run, no challenge prompted)")
                .conflicts_with("list"),
        )
        .arg(
            Arg::new("list")
                .short('l')
                .long("list")
                .help("List all active checks")
                .action(ArgAction::SetTrue)
                .conflicts_with("command"),
        )
        .arg(
            Arg::new("group")
                .short('g')
                .long("group")
                .help("Filter checks by group (used with --list)")
                .requires("list"),
        )
        .arg(
            Arg::new("all")
                .short('a')
                .long("all")
                .help("Include checks from disabled groups (used with --list)")
                .action(ArgAction::SetTrue)
                .requires("list"),
        )
}

pub fn run(
    matches: &ArgMatches,
    settings: &Settings,
    checks: &[Check],
) -> Result<shellfirm::CmdExit> {
    if matches.get_flag("list") {
        let group_filter = matches.get_one::<String>("group").map(String::as_str);
        let show_all = matches.get_flag("all");
        run_list(settings, checks, group_filter, show_all)
    } else if let Some(command) = matches.get_one::<String>("command") {
        Ok(run_check(command, checks))
    } else {
        Ok(shellfirm::CmdExit {
            code: exitcode::USAGE,
            message: Some("Provide --command or --list. See: shellfirm check --help".to_string()),
        })
    }
}

fn run_check(command: &str, checks: &[Check]) -> shellfirm::CmdExit {
    let env = RealEnvironment;
    let splitted = checks::split_command(command);
    let matches: Vec<&Check> = splitted
        .iter()
        .flat_map(|c| checks::run_check_on_command_with_env(checks, c, &env))
        .collect();

    if matches.is_empty() {
        return shellfirm::CmdExit {
            code: exitcode::OK,
            message: Some("No risky patterns matched.".to_string()),
        };
    }

    let mut output = String::new();
    let _ = writeln!(output, "{} risky pattern(s) matched:", matches.len());
    for m in &matches {
        let _ = write!(
            output,
            "\n  [{}] [{}] {}\n",
            m.id, m.severity, m.description
        );
        // Blast radius
        let segment = splitted
            .iter()
            .find(|seg| m.test.is_match(seg))
            .map_or(command, String::as_str);
        if let Some(br) = blast_radius::compute(&m.id, &m.test, segment, &env) {
            let _ = writeln!(
                output,
                "    Blast radius: [{}] — {}",
                br.scope, br.description
            );
        }
        if let Some(ref alt) = m.alternative {
            let _ = write!(output, "    > Safe alternative: {alt}");
            if let Some(ref info) = m.alternative_info {
                let _ = write!(output, " ({info})");
            }
            output.push('\n');
        }
    }

    shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some(output),
    }
}

fn run_list(
    settings: &Settings,
    active_checks: &[Check],
    group_filter: Option<&str>,
    show_all: bool,
) -> Result<shellfirm::CmdExit> {
    if show_all {
        let all = checks::get_all()?;
        let filtered: Vec<Check> = match group_filter {
            Some(group) => all.into_iter().filter(|c| c.from == group).collect(),
            None => all,
        };
        let mut output = format!("{} check(s) available:\n\n", filtered.len());
        for c in &filtered {
            let active = if active_checks.iter().any(|ac| ac.id == c.id) {
                "+"
            } else {
                "-"
            };
            let _ = writeln!(
                output,
                "  [{active}] {id:<45} {group:<18} {sev:<10} {desc}",
                id = c.id,
                group = c.from,
                sev = format!("{}", c.severity),
                desc = c.description
            );
        }
        output.push_str("\n  [+] = active, [-] = inactive\n");
        println!("{output}");
        return Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: None,
        });
    }

    let checks_to_show: Vec<&Check> = group_filter.map_or_else(
        || active_checks.iter().collect(),
        |group| active_checks.iter().filter(|c| c.from == group).collect(),
    );

    let mut output = format!(
        "{} active check(s) (groups: {}):\n\n",
        checks_to_show.len(),
        settings.enabled_groups.join(", ")
    );
    for c in &checks_to_show {
        let _ = writeln!(
            output,
            "  {id:<45} {group:<18} {sev:<10} {desc}",
            id = c.id,
            group = c.from,
            sev = format!("{}", c.severity),
            desc = c.description
        );
    }

    println!("{output}");
    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: None,
    })
}
