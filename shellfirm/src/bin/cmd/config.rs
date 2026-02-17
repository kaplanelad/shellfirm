use anyhow::{anyhow, Result};
use clap::{Arg, ArgAction, ArgMatches, Command};
use shellfirm::{
    format_yaml_value, known_enum_values, validate_config_key, value_get, value_list_paths,
    value_set, Config, Settings,
};

pub fn command() -> Command {
    Command::new("config")
        .about("Manage shellfirm configuration")
        .arg_required_else_help(true)
        .subcommand(Command::new("reset").about("Reset configuration"))
        .subcommand(
            Command::new("set")
                .about("Set any configuration value by dot-notation key")
                .arg(
                    Arg::new("list")
                        .long("list")
                        .short('l')
                        .help("List all configuration keys and their current values")
                        .action(ArgAction::SetTrue),
                )
                .arg(Arg::new("key").help("Configuration key (dot-notation, e.g. llm.model)"))
                .arg(
                    Arg::new("value")
                        .help("Value to set (parsed as YAML)")
                        .num_args(1..),
                ),
        )
        .subcommand(
            Command::new("get")
                .about("Get a configuration value by dot-notation key")
                .arg(
                    Arg::new("key")
                        .help("Configuration key (dot-notation, e.g. llm.model)")
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("edit").about("Open settings.yaml in $EDITOR with post-save validation"),
        )
}

pub fn run(matches: &ArgMatches, config: &Config) -> Result<shellfirm::CmdExit> {
    match matches.subcommand() {
        None => Err(anyhow!("command not found")),
        Some(tup) => match tup {
            ("reset", _subcommand_matches) => Ok(run_reset(config, None)),
            ("set", subcommand_matches) => {
                if subcommand_matches.get_flag("list") {
                    run_set_list(config)
                } else {
                    let key = subcommand_matches.get_one::<String>("key").ok_or_else(|| {
                        anyhow!("missing <key> argument (use --list to see all keys)")
                    })?;
                    let value_str: String = subcommand_matches
                        .get_many::<String>("value")
                        .ok_or_else(|| anyhow!("missing <value> argument"))?
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(" ");
                    run_set_key_value(config, key, &value_str)
                }
            }
            ("get", subcommand_matches) => {
                let key = subcommand_matches.get_one::<String>("key").unwrap();
                run_get_key(config, key)
            }
            ("edit", _subcommand_matches) => run_edit(config),
            _ => unreachable!(),
        },
    }
}

pub fn run_reset(config: &Config, force_selection: Option<usize>) -> shellfirm::CmdExit {
    match config.reset_config(force_selection) {
        Ok(()) => shellfirm::CmdExit {
            code: exitcode::OK,
            message: Some("shellfirm configuration reset successfully".to_string()),
        },
        Err(e) => shellfirm::CmdExit {
            code: exitcode::CONFIG,
            message: Some(format!("reset settings error: {e:?}")),
        },
    }
}

pub fn run_set_key_value(
    config: &Config,
    key: &str,
    value_str: &str,
) -> Result<shellfirm::CmdExit> {
    // Validate key before doing anything
    if let Err(e) = validate_config_key(key) {
        return Ok(shellfirm::CmdExit {
            code: exitcode::CONFIG,
            message: Some(e),
        });
    }

    let new_value: serde_yaml::Value = match serde_yaml::from_str(value_str) {
        Ok(v) => v,
        Err(e) => {
            return Ok(shellfirm::CmdExit {
                code: exitcode::CONFIG,
                message: Some(format!("failed to parse value as YAML: {e}")),
            });
        }
    };
    let mut root = config.read_config_as_value()?;
    value_set(&mut root, key, new_value)?;
    if let Err(e) = config.save_config_from_value(&root) {
        let enum_hint = known_enum_values()
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, vals)| format!("\n\n  Valid values: {}", vals.join(", ")));
        let hint = enum_hint.unwrap_or_default();
        return Ok(shellfirm::CmdExit {
            code: exitcode::CONFIG,
            message: Some(format!(
                "invalid value '{value_str}' for '{key}': {e}{hint}"
            )),
        });
    }
    let display = value_get(&root, key).map_or_else(|| value_str.to_string(), format_yaml_value);
    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: Some(format!("{key} = {display}")),
    })
}

pub fn run_set_list(config: &Config) -> Result<shellfirm::CmdExit> {
    let user_root = config.read_config_as_value()?;
    let default_root = serde_yaml::to_value(Settings::default())
        .map_err(|e| anyhow!("failed to serialize defaults: {e}"))?;
    let merged = merge_for_display(&default_root, &user_root);
    let paths = value_list_paths(&merged);
    let enum_map = known_enum_values();
    let max_key_len = paths.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    for (key, value) in &paths {
        let hint = enum_map
            .iter()
            .find(|(k, _)| *k == key.as_str())
            .map(|(_, vals)| format!("  (valid: {})", vals.join(", ")))
            .unwrap_or_default();
        println!("{key:<width$}  {value}{hint}", width = max_key_len);
    }
    Ok(shellfirm::CmdExit {
        code: exitcode::OK,
        message: None,
    })
}

/// Recursively merge `overrides` on top of `base`.
/// Keys in `overrides` replace keys in `base`; both must be mappings at the
/// top level.
fn merge_for_display(base: &serde_yaml::Value, overrides: &serde_yaml::Value) -> serde_yaml::Value {
    match (base, overrides) {
        (serde_yaml::Value::Mapping(b), serde_yaml::Value::Mapping(o)) => {
            let mut result = b.clone();
            for (k, v) in o {
                let merged = if let Some(base_v) = b.get(k) {
                    merge_for_display(base_v, v)
                } else {
                    v.clone()
                };
                result.insert(k.clone(), merged);
            }
            serde_yaml::Value::Mapping(result)
        }
        (_, override_val) => override_val.clone(),
    }
}

pub fn run_get_key(config: &Config, key: &str) -> Result<shellfirm::CmdExit> {
    let root = config.read_config_as_value()?;
    match value_get(&root, key) {
        Some(v) => {
            let display = format_yaml_value(v);
            println!("{display}");
            Ok(shellfirm::CmdExit {
                code: exitcode::OK,
                message: None,
            })
        }
        None => Ok(shellfirm::CmdExit {
            code: exitcode::CONFIG,
            message: Some(format!(
                "key not found: {key}\n\nUse 'config set --list' to see valid keys."
            )),
        }),
    }
}

pub fn run_edit(config: &Config) -> Result<shellfirm::CmdExit> {
    // Ensure file exists before opening editor
    if !config.setting_file_path.exists() {
        config.reset_config(Some(0))?;
    }
    let original = config.read_config_file()?;
    let editor = std::env::var("EDITOR")
        .or_else(|_| std::env::var("VISUAL"))
        .unwrap_or_else(|_| "vi".to_string());

    let status = std::process::Command::new(&editor)
        .arg(&config.setting_file_path)
        .status()
        .map_err(|e| anyhow!("failed to launch editor '{editor}': {e}"))?;

    if !status.success() {
        return Ok(shellfirm::CmdExit {
            code: exitcode::CONFIG,
            message: Some(format!("editor exited with status: {status}")),
        });
    }

    // Validate the edited file
    match config.get_settings_from_file() {
        Ok(_) => Ok(shellfirm::CmdExit {
            code: exitcode::OK,
            message: Some("Configuration updated successfully.".to_string()),
        }),
        Err(e) => {
            // Restore original on validation failure
            let mut file = std::fs::File::create(&config.setting_file_path)?;
            std::io::Write::write_all(&mut file, original.as_bytes())?;
            Ok(shellfirm::CmdExit {
                code: exitcode::CONFIG,
                message: Some(format!(
                    "Invalid configuration, changes discarded: {e}\n\nRun 'config edit' to try again."
                )),
            })
        }
    }
}

#[cfg(test)]
mod test_config_cli_command {

    use std::fs;

    use insta::{assert_debug_snapshot, with_settings};
    use tempfile::TempDir;

    use super::*;
    use shellfirm::Challenge;

    fn initialize_config_folder(temp_dir: &TempDir) -> Config {
        let temp_dir = temp_dir.path().join("app");
        let config = Config::new(Some(&temp_dir.display().to_string())).unwrap();
        config.reset_config(Some(0)).unwrap();
        config
    }

    #[test]
    fn can_run_reset() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = initialize_config_folder(&temp_dir);
        // Change challenge via generic value_set so reset has something to restore
        let mut root = config.read_config_as_value().unwrap();
        value_set(
            &mut root,
            "challenge",
            serde_yaml::Value::String("Yes".into()),
        )
        .unwrap();
        config.save_config_from_value(&root).unwrap();
        assert_debug_snapshot!(run_reset(&config, Some(1)));
        assert_debug_snapshot!(config.get_settings_from_file());
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_run_reset_with_error() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = initialize_config_folder(&temp_dir);
        fs::remove_file(&config.setting_file_path).unwrap();
        with_settings!({filters => vec![
            (r"error:.+", "error message"),
        ]}, {
            assert_debug_snapshot!(run_reset(&config, Some(1)));
        });
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_run_set_scalar() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = initialize_config_folder(&temp_dir);
        let result = run_set_key_value(&config, "challenge", "Yes").unwrap();
        assert_eq!(result.code, exitcode::OK);
        assert_eq!(
            config.get_settings_from_file().unwrap().challenge,
            Challenge::Yes
        );
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_run_set_bool() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = initialize_config_folder(&temp_dir);
        assert!(config.get_settings_from_file().unwrap().audit_enabled);
        let result = run_set_key_value(&config, "audit_enabled", "false").unwrap();
        assert_eq!(result.code, exitcode::OK);
        assert!(!config.get_settings_from_file().unwrap().audit_enabled);
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_run_set_nested() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = initialize_config_folder(&temp_dir);
        let result = run_set_key_value(&config, "llm.model", "gpt-4").unwrap();
        assert_eq!(result.code, exitcode::OK);
        assert_eq!(config.get_settings_from_file().unwrap().llm.model, "gpt-4");
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_run_set_deep_nested() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = initialize_config_folder(&temp_dir);
        let result = run_set_key_value(&config, "context.escalation.elevated", "Yes").unwrap();
        assert_eq!(result.code, exitcode::OK);
        assert_eq!(
            config
                .get_settings_from_file()
                .unwrap()
                .context
                .escalation
                .elevated,
            Challenge::Yes
        );
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_run_set_list_value() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = initialize_config_folder(&temp_dir);
        let result =
            run_set_key_value(&config, "context.protected_branches", "[main, develop]").unwrap();
        assert_eq!(result.code, exitcode::OK);
        assert_eq!(
            config
                .get_settings_from_file()
                .unwrap()
                .context
                .protected_branches,
            vec!["main", "develop"]
        );
        temp_dir.close().unwrap();
    }

    #[test]
    fn set_rejects_invalid_value() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = initialize_config_folder(&temp_dir);
        let original = config.get_settings_from_file().unwrap().challenge;
        let result = run_set_key_value(&config, "challenge", "Foo").unwrap();
        assert_eq!(result.code, exitcode::CONFIG);
        assert!(result.message.as_ref().unwrap().contains("invalid value"));
        // Original value is unchanged
        assert_eq!(config.get_settings_from_file().unwrap().challenge, original);
        temp_dir.close().unwrap();
    }

    #[test]
    fn set_rejects_wrong_type() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = initialize_config_folder(&temp_dir);
        let result = run_set_key_value(&config, "audit_enabled", "not_a_bool").unwrap();
        assert_eq!(result.code, exitcode::CONFIG);
        // Original value is unchanged
        assert!(config.get_settings_from_file().unwrap().audit_enabled);
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_run_set_list_flag() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = initialize_config_folder(&temp_dir);
        let result = run_set_list(&config).unwrap();
        assert_eq!(result.code, exitcode::OK);
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_run_get_scalar() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = initialize_config_folder(&temp_dir);
        let result = run_get_key(&config, "challenge").unwrap();
        assert_eq!(result.code, exitcode::OK);
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_run_get_nested() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = initialize_config_folder(&temp_dir);
        let result = run_get_key(&config, "context.escalation.critical").unwrap();
        assert_eq!(result.code, exitcode::OK);
        temp_dir.close().unwrap();
    }

    #[test]
    fn get_nonexistent_returns_error() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = initialize_config_folder(&temp_dir);
        let result = run_get_key(&config, "nonexistent.key").unwrap();
        assert_eq!(result.code, exitcode::CONFIG);
        assert!(result.message.unwrap().contains("key not found"));
        temp_dir.close().unwrap();
    }

    #[test]
    fn set_rejects_unknown_key() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = initialize_config_folder(&temp_dir);
        let result = run_set_key_value(&config, "challange", "Yes").unwrap();
        assert_eq!(result.code, exitcode::CONFIG);
        let msg = result.message.unwrap();
        assert!(msg.contains("unknown configuration key: 'challange'"));
        assert!(msg.contains("Did you mean 'challenge'?"));
        temp_dir.close().unwrap();
    }

    #[test]
    fn set_rejects_completely_unknown_key() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = initialize_config_folder(&temp_dir);
        let result = run_set_key_value(&config, "zzz_nonexistent_zzz", "true").unwrap();
        assert_eq!(result.code, exitcode::CONFIG);
        let msg = result.message.unwrap();
        assert!(msg.contains("unknown configuration key"));
        assert!(!msg.contains("Did you mean"));
        temp_dir.close().unwrap();
    }

    #[test]
    fn set_on_fresh_install_creates_sparse_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_path = temp_dir.path().join("fresh");
        let config = Config::new(Some(&temp_path.display().to_string())).unwrap();
        // No reset_config — simulates fresh install with no file
        assert!(!config.setting_file_path.exists());
        let result = run_set_key_value(&config, "challenge", "Yes").unwrap();
        assert_eq!(result.code, exitcode::OK);
        // File should be sparse — only contains the key we set
        let content = config.read_config_file().unwrap();
        assert!(content.contains("challenge"));
        assert!(!content.contains("enabled_groups"));
        // Settings still load correctly with defaults
        let settings = config.get_settings_from_file().unwrap();
        assert_eq!(settings.challenge, Challenge::Yes);
        assert!(!settings.enabled_groups.is_empty());
        temp_dir.close().unwrap();
    }

    #[test]
    fn set_invalid_value_shows_enum_hint() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = initialize_config_folder(&temp_dir);
        let result = run_set_key_value(&config, "challenge", "Foo").unwrap();
        assert_eq!(result.code, exitcode::CONFIG);
        let msg = result.message.unwrap();
        assert!(msg.contains("Valid values: Math, Enter, Yes"));
        temp_dir.close().unwrap();
    }
}
