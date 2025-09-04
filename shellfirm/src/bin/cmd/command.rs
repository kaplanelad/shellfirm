use anyhow::Result;
use clap::{Arg, ArgAction, ArgMatches, Command};
use shellfirm::{challenge, Settings};
use shellfirm_core::checks::{get_all_checks, Check};
use std::collections::HashSet;
use tracing::debug;

pub fn command() -> Command {
    Command::new("pre-command")
        .about("Check if given command marked as sensitive command that need your extra approval.")
        .arg(
            Arg::new("command")
                .short('c')
                .long("command")
                .help("get the user command that should run.")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("test")
                .short('t')
                .long("test")
                .help("Check if the command is risky and exit")
                .action(ArgAction::SetTrue),
        )
}

pub fn run(
    arg_matches: &ArgMatches,
    settings: &Settings,
    checks: &[Check],
) -> Result<shellfirm::CmdExit> {
    execute(
        arg_matches
            .get_one::<String>("command")
            .map_or("", String::as_str),
        settings,
        checks,
        arg_matches.get_flag("test"),
    )
}

fn execute(
    command: &str,
    settings: &Settings,
    checks: &[Check],
    dryrun: bool,
) -> Result<shellfirm::CmdExit> {
    // Use the new core function that handles command parsing and splitting
    let matches: Vec<Check> = challenge::validate_command_with_split(
        checks,
        command,
        &challenge::ValidationOptions::default(),
    );

    debug!(matches_count = matches.len(), matches = ?matches, "matches found");

    if dryrun {
        return Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: Some(serde_yaml::to_string(&matches)?),
        });
    }

    // Compute ignored matches (rules that matched but are ignored by config)
    let all_checks = get_all_checks()?;
    let all_matches: Vec<challenge::Check> = challenge::validate_command_with_split(
        &all_checks,
        command,
        &challenge::ValidationOptions::default(),
    );

    let active_ids: HashSet<String> = matches.iter().map(|c| c.id.clone()).collect();
    let ignored_set: HashSet<String> = settings.ignores_patterns_ids.iter().cloned().collect();
    let ignored_matches: Vec<challenge::Check> = all_matches
        .into_iter()
        .filter(|c| ignored_set.contains(&c.id) && !active_ids.contains(&c.id))
        .collect();

    if !matches.is_empty() {
        challenge::show(
            &settings.challenge,
            &matches,
            &ignored_matches,
            &settings.deny_patterns_ids,
        )?;
    } else if !ignored_matches.is_empty() {
        eprintln!("Note: The following rules are ignored by your config:");
        let mut seen: HashSet<String> = HashSet::new();
        for c in ignored_matches {
            if seen.insert(c.id.clone()) {
                eprintln!("* [{}] {}", c.id, c.description);
            }
        }
    }

    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: None,
    })
}

#[cfg(test)]
mod test_command_cli_command {

    use super::*;
    use insta::assert_debug_snapshot;
    use shellfirm::Config;
    use std::path::Path;

    fn initialize_config_folder(temp_dir: &Path) -> Config {
        let temp_dir = temp_dir.join("app");
        Config::new(Some(&temp_dir.display().to_string())).expect("Failed to create new config")
    }

    #[test]
    fn can_run_pre_command() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("Failed to create temp directory");
        let settings = initialize_config_folder(temp_dir.root.as_path())
            .get_settings_from_file()
            .expect("Failed to get settings from file");

        // Redact the verbose regex content in the `test` field from the snapshot output
        insta::with_settings!({
            filters => vec![(r#"test: \\".*?\\""#, "test: \"<redacted>\"")]
        }, {
            assert_debug_snapshot!(execute(
                "rm -rf /",
                &settings,
                &settings
                    .get_active_checks()
                    .expect("Failed to get active checks"),
                true
            ));
        });
    }

    #[test]
    fn can_run_pre_command_without_match() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("Failed to create temp directory");
        let settings = initialize_config_folder(temp_dir.root.as_path())
            .get_settings_from_file()
            .expect("Failed to get settings from file");

        assert_debug_snapshot!(execute(
            "command",
            &settings,
            &settings
                .get_active_checks()
                .expect("Failed to get active checks"),
            true
        ));
    }
}
