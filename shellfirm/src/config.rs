//! Manage the app configuration by creating, deleting and modify the
//! configuration

use std::{
    env, fs,
    io::{Read, Write},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Result as AnyResult};
use serde_derive::{Deserialize, Serialize};
use tracing::debug;

use crate::{challenge, dialog};

// Re-export Challenge for public API compatibility
pub use shellfirm_core::checks::{get_all_checks, Challenge, Severity};

const DEFAULT_SETTING_FILE_NAME: &str = "settings.yaml";

pub const DEFAULT_INCLUDE_SEVERITY_CHECKS: [Severity; 2] = [Severity::High, Severity::Critical];

/// The user challenge when user need to confirm the command.
/// This type is imported from [`Challenge`]
#[derive(Debug)]
/// describe configuration folder
pub struct Config {
    /// Configuration folder path.
    pub root_folder: String,
    /// config file.
    pub setting_file_path: String,
}

/// Describe the configuration yaml
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Settings {
    /// Type of the challenge.
    pub challenge: Challenge,
    /// List of severities to include
    pub includes_severities: Vec<Severity>,
    /// List of all ignore checks
    pub ignores_patterns_ids: Vec<String>,
    /// List of pattens id to prevent
    pub deny_patterns_ids: Vec<String>,
}

impl Config {
    /// Get application  setting config.
    ///
    /// # Errors
    ///
    /// Will return `Err` error return on load/save config
    pub fn new(path: Option<&str>) -> AnyResult<Self> {
        let package_name = env!("CARGO_PKG_NAME");

        let config_folder = match path {
            Some(p) => PathBuf::from(p),
            None => match dirs::home_dir() {
                Some(p) => {
                    // The project started with $HOME path to save the config file. In order the
                    // requests to use $XDG_CACHE_HOME and keep backward
                    // compatibility if the folder $HOME/.shellfirm exists, shillfirm
                    // continue work with that folder. If the folder does not exists, the default
                    // use config dir
                    let homedir = p.join(format!(".{package_name}"));
                    let conf_dir = dirs::config_dir().unwrap_or_else(|| homedir.clone());
                    if homedir.is_dir() {
                        homedir
                    } else {
                        conf_dir.join(package_name)
                    }
                }
                None => bail!("could not get directory path"),
            },
        };

        let setting_config = Self {
            root_folder: config_folder.display().to_string(),
            setting_file_path: config_folder
                .join(DEFAULT_SETTING_FILE_NAME)
                .to_str()
                .unwrap_or("")
                .to_string(),
        };

        setting_config.create_config_folder()?;
        setting_config.manage_setting_file()?;
        debug!(configuration = ?setting_config, "configuration settings loaded");
        Ok(setting_config)
    }

    /// Convert user settings yaml to struct.
    ///
    /// # Errors
    ///
    /// Will return `Err` has an error when loading the config file
    pub fn get_settings_from_file(&self) -> AnyResult<Settings> {
        Ok(serde_yaml::from_str(&self.read_config_file()?)?)
    }

    /// Manage setting folder & file.
    /// * Create config folder if not exists.
    /// * Create default config yaml file if not exists.
    ///
    /// # Errors
    ///
    /// Will return `Err` file could not created or loaded
    pub fn manage_setting_file(&self) -> AnyResult<()> {
        if fs::metadata(&self.setting_file_path).is_err() {
            debug!(path = %self.setting_file_path, "setting file not found");
            self.create_default_settings_file()?;
        }
        debug!(settings = ?self.get_settings_from_file()?, "setting file loaded");
        Ok(())
    }

    /// Update check groups
    ///
    /// # Arguments
    ///
    /// * `remove_checks` - if true the given `check_group` parameter will
    ///   remove from configuration / if false will add.
    /// * `check_groups` - list of check groups to act.
    ///
    /// # Errors
    ///
    /// Will return `Err` group didn't added/removed
    pub fn update_check_groups(&self, check_groups: Vec<String>) -> AnyResult<()> {
        let mut settings = self.get_settings_from_file()?;
        // Convert provided strings to severities (case-insensitive)
        let mut severities: Vec<Severity> = Vec::new();
        for s in check_groups {
            match s.to_lowercase().as_str() {
                "low" => severities.push(Severity::Low),
                "medium" => severities.push(Severity::Medium),
                "high" => severities.push(Severity::High),
                "critical" => severities.push(Severity::Critical),
                other => bail!("unsupported severity: {}", other),
            }
        }
        settings.includes_severities = severities;
        self.save_settings_file_from_struct(&settings)
    }

    /// Update default user challenge.
    ///
    /// # Arguments
    ///
    /// * `challenge` - new challenge to update
    ///
    /// # Errors
    ///
    /// Will return `Err` error return on load/save config
    pub fn update_challenge(&self, challenge: Challenge) -> AnyResult<()> {
        let mut settings = self.get_settings_from_file()?;
        settings.challenge = challenge;
        self.save_settings_file_from_struct(&settings)?;
        Ok(())
    }
    /// Reset user configuration to the default app.
    ///
    /// # Errors
    ///
    /// Will return `Err` create config folder return an error
    pub fn reset_config(&self, force_selection: Option<usize>) -> AnyResult<()> {
        let selected = if let Some(force_selection) = force_selection {
            force_selection
        } else {
            dialog::reset_config()?
        };

        match selected {
            0 => self.create_default_settings_file()?,
            1 => {
                self.backup()?;
                self.create_default_settings_file()?;
            }
            _ => bail!("unexpected option"),
        }
        Ok(())
    }

    /// Create config folder if not exists.
    fn create_config_folder(&self) -> AnyResult<()> {
        if let Err(err) = fs::create_dir(&self.root_folder) {
            if err.kind() != std::io::ErrorKind::AlreadyExists {
                bail!("could not create folder: {}", err);
            }
            debug!(path = %self.root_folder, "configuration folder found");
        } else {
            debug!(path = %self.root_folder, "configuration folder created");
        }
        Ok(())
    }

    /// Create config file from default template.
    fn create_default_settings_file(&self) -> AnyResult<()> {
        self.save_settings_file_from_struct(&Settings {
            challenge: Challenge::Math,
            includes_severities: DEFAULT_INCLUDE_SEVERITY_CHECKS.to_vec(),
            ignores_patterns_ids: vec![],
            deny_patterns_ids: vec![],
        })
    }

    /// Convert the given config to YAML format and the file.
    ///
    /// # Arguments
    ///
    /// * `settings` - Config struct
    fn save_settings_file_from_struct(&self, settings: &Settings) -> AnyResult<()> {
        let content = serde_yaml::to_string(settings)?;
        let mut file = fs::File::create(&self.setting_file_path)?;
        file.write_all(content.as_bytes())?;
        debug!(path = %self.setting_file_path, settings = ?settings, "settings file created");
        Ok(())
    }

    /// Return config content.
    fn read_config_file(&self) -> AnyResult<String> {
        let mut file = std::fs::File::open(&self.setting_file_path)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        Ok(content)
    }

    fn backup(&self) -> AnyResult<String> {
        let backup_to = format!(
            "{}.{}.bak",
            self.setting_file_path,
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
        );
        fs::rename(&self.setting_file_path, &backup_to)?;
        Ok(backup_to)
    }

    /// Update patterns ids to ignore
    ///
    /// # Arguments
    /// * `ignores_patterns_ids` - Full list of patterns ids
    ///
    /// # Errors
    ///
    /// Will return `Err` when could not load/save config
    pub fn update_ignores_pattern_ids(&self, ignores_patterns_ids: Vec<String>) -> AnyResult<()> {
        let mut settings = self.get_settings_from_file()?;
        settings.ignores_patterns_ids = ignores_patterns_ids;
        self.save_settings_file_from_struct(&settings)?;
        Ok(())
    }

    /// Update patterns ids to deny
    ///
    /// # Arguments
    /// * `deny_patterns_ids` - Full list of patterns ids
    ///
    /// # Errors
    ///
    /// Will return `Err` when could not load/save config
    pub fn update_deny_pattern_ids(&self, deny_patterns_ids: Vec<String>) -> AnyResult<()> {
        let mut settings = self.get_settings_from_file()?;
        settings.deny_patterns_ids = deny_patterns_ids;
        self.save_settings_file_from_struct(&settings)?;
        Ok(())
    }
}

impl Settings {
    /// Return list of active patterns by user groups
    ///
    /// # Errors
    ///
    /// Will return `Err` when could not load config file
    pub fn get_active_checks(&self) -> AnyResult<Vec<challenge::Check>> {
        Ok(get_all_checks()?
            .iter()
            .filter(|&c| self.includes_severities.contains(&c.severity))
            .filter(|&c| !self.ignores_patterns_ids.contains(&c.id))
            .cloned()
            .collect::<Vec<_>>())
    }

    #[must_use]
    pub const fn get_active_groups(&self) -> &Vec<Severity> {
        &self.includes_severities
    }
}

#[cfg(test)]
mod test_config {
    use std::{fs::read_dir, path::Path};

    use insta::assert_debug_snapshot;

    use super::*;

    fn initialize_config_folder(temp_dir: &Path) -> Config {
        // let temp_dir = temp_dir.join("app");
        Config::new(Some(&temp_dir.display().to_string())).expect("Failed to create new config")
    }

    #[test]
    fn can_crate_new_config() {
        let temp_dir = tree_fs::TreeBuilder::default();
        let config = initialize_config_folder(temp_dir.root.as_path());
        assert_debug_snapshot!(Path::new(&config.root_folder).is_dir());
        assert_debug_snapshot!(Path::new(&config.setting_file_path).is_file());
    }

    #[test]
    fn cat_get_settings_from_file() {
        let temp_dir = tree_fs::TreeBuilder::default();
        let config = initialize_config_folder(temp_dir.root.as_path());

        assert_debug_snapshot!(config.get_settings_from_file());
    }

    #[test]
    fn can_manage_config_file() {
        let temp_dir = tree_fs::TreeBuilder::default();
        let mut config = initialize_config_folder(temp_dir.root.as_path());

        config.setting_file_path = temp_dir.root.join("new-file.yaml").display().to_string();

        assert_debug_snapshot!(Path::new(&config.setting_file_path).is_file());
        config
            .manage_setting_file()
            .expect("Failed to manage setting file");
        assert_debug_snapshot!(Path::new(&config.setting_file_path).is_file());
    }

    #[test]
    fn can_update_challenge() {
        let temp_dir = tree_fs::TreeBuilder::default();
        let config = initialize_config_folder(temp_dir.root.as_path());

        assert_debug_snapshot!(config.get_settings_from_file());
        config
            .update_challenge(Challenge::Yes)
            .expect("Failed to update challenge");
        assert_debug_snapshot!(config.get_settings_from_file());
    }

    #[test]
    fn can_update_ignores() {
        let temp_dir = tree_fs::TreeBuilder::default();
        let config = initialize_config_folder(temp_dir.root.as_path());

        assert_debug_snapshot!(config.get_settings_from_file());
        config
            .update_ignores_pattern_ids(vec!["id-1".to_string(), "id-2".to_string()])
            .expect("Failed to update ignore patterns");
        assert_debug_snapshot!(config.get_settings_from_file());
    }

    #[test]
    fn can_update_deny() {
        let temp_dir = tree_fs::TreeBuilder::default();
        let config = initialize_config_folder(temp_dir.root.as_path());
        assert_debug_snapshot!(config.get_settings_from_file());
        config
            .update_deny_pattern_ids(vec!["id-1".to_string(), "id-2".to_string()])
            .expect("Failed to update deny patterns");
        assert_debug_snapshot!(config.get_settings_from_file());
    }

    #[test]
    fn can_reset_config_with_override() {
        let temp_dir = tree_fs::TreeBuilder::default();
        let config = initialize_config_folder(temp_dir.root.as_path());
        config
            .update_challenge(Challenge::Yes)
            .expect("Failed to update challenge");
        assert_debug_snapshot!(config.get_settings_from_file());
        config
            .reset_config(Some(0))
            .expect("Failed to reset config");
        assert_debug_snapshot!(config.get_settings_from_file());
        assert_debug_snapshot!(read_dir(config.root_folder)
            .expect("Failed to read root folder")
            .count());
    }

    #[test]
    fn can_reset_config_with_with_backup() {
        let temp_dir = tree_fs::TreeBuilder::default();
        let config = initialize_config_folder(temp_dir.root.as_path());
        config
            .update_challenge(Challenge::Yes)
            .expect("Failed to update challenge");
        assert_debug_snapshot!(config.get_settings_from_file());
        config
            .reset_config(Some(1))
            .expect("Failed to reset config");
        assert_debug_snapshot!(config.get_settings_from_file());
        assert_debug_snapshot!(read_dir(config.root_folder)
            .expect("Failed to read root folder")
            .count());
    }
}

#[cfg(test)]
mod test_settings {
    use std::path::Path;

    use insta::assert_debug_snapshot;

    use super::*;

    fn initialize_config_folder(temp_dir: &Path) -> Config {
        let temp_dir = temp_dir.join("app");
        Config::new(Some(&temp_dir.display().to_string())).expect("Failed to create new config")
    }

    #[test]
    fn can_get_active_checks() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("Failed to create temp directory");
        let config = initialize_config_folder(temp_dir.root.as_path());
        assert_debug_snapshot!(config
            .get_settings_from_file()
            .expect("Failed to get settings from file")
            .get_active_checks()
            .is_ok());
    }

    #[test]
    fn can_get_settings_from_file() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("Failed to create temp directory");
        let config = initialize_config_folder(temp_dir.root.as_path());
        assert_debug_snapshot!(config
            .get_settings_from_file()
            .expect("Failed to get settings from file")
            .get_active_groups());
    }
}
