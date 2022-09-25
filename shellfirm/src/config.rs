//! Manage the app configuration by creating, deleting and modify the
//! configuration

use std::{
    env, fmt, fs,
    io::{Read, Write},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Result as AnyResult};
use log::debug;
use serde_derive::{Deserialize, Serialize};
use strum::EnumIter;

use crate::{
    checks::{get_all_checks, Check},
    dialog,
};

const DEFAULT_SETTING_FILE_NAME: &str = "settings.yaml";

pub const DEFAULT_CHALLENGE: Challenge = Challenge::Math;

pub const DEFAULT_INCLUDE_CHECKS: [&str; 3] = ["base", "fs", "git"];

/// The method type go the check.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub enum Method {
    /// Run start with check.
    StartWith,
    /// Run contains check.
    Contains,
    /// Run regex check.
    Regex,
}

/// The user challenge when user need to confirm the command.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, EnumIter)]
pub enum Challenge {
    /// Math challenge.
    Math,
    /// Only enter will approve the command.
    Enter,
    /// only yes typing will approve the command.
    Yes,
}

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
    /// List of all include files
    pub includes: Vec<String>,
    /// List of all ignore checks
    pub ignores: Vec<String>,
}

impl fmt::Display for Challenge {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Challenge::Math => write!(f, "Math"),
            Challenge::Enter => write!(f, "Enter"),
            Challenge::Yes => write!(f, "Yes"),
        }
    }
}

impl Default for Challenge {
    fn default() -> Self {
        DEFAULT_CHALLENGE
    }
}

impl Challenge {
    pub fn from_string(str: &str) -> AnyResult<Self> {
        match str.to_lowercase().as_str() {
            "math" => Ok(Self::Math),
            "enter" => Ok(Self::Enter),
            "yes" => Ok(Self::Yes),
            _ => bail!("given challenge name not found"),
        }
    }
}

impl Config {
    /// Get application  setting config.
    ///
    /// # Errors
    ///
    /// Will return `Err` error return on load/save config
    pub fn new(path: Option<&str>) -> AnyResult<Config> {
        let package_name = env!("CARGO_PKG_NAME");

        let config_folder = match path {
            Some(p) => PathBuf::from(p),
            None => match dirs::home_dir() {
                Some(p) => {
                    // The project started with $HOME path to save the config file. In order the
                    // requests to use $XDG_CACHE_HOME and keep backward
                    // compatibility if the folder $HOME/.shellform exists shillfirm
                    // continue work with that folder. If the folder does not exists, the default
                    // use config dir
                    let homedir = p.join(format!(".{}", package_name));
                    let confdir = dirs::config_dir().unwrap_or_else(|| homedir.clone());
                    if homedir.is_dir() {
                        homedir
                    } else {
                        confdir.join(package_name)
                    }
                }
                None => bail!("could not get directory path"),
            },
        };

        let setting_config = Config {
            root_folder: config_folder.display().to_string(),
            setting_file_path: config_folder
                .join(DEFAULT_SETTING_FILE_NAME)
                .to_str()
                .unwrap_or("")
                .to_string(),
        };

        setting_config.create_config_folder()?;
        setting_config.manage_setting_file()?;
        debug!("configuration settings: {:?}", setting_config);
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
            debug!("setting file file not found: {}", &self.setting_file_path);
            self.create_default_settings_file()?;
        }
        debug!("setting file: {:?}", self.get_settings_from_file()?);
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
        settings.includes = check_groups.to_vec();
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
        };
        Ok(())
    }

    /// Create config folder if not exists.
    fn create_config_folder(&self) -> AnyResult<()> {
        if let Err(err) = fs::create_dir(&self.root_folder) {
            if err.kind() != std::io::ErrorKind::AlreadyExists {
                bail!("could not create folder: {}", err);
            }
            debug!("configuration folder found: {}", &self.root_folder);
        } else {
            debug!("configuration created in path: {}", &self.root_folder);
        }
        Ok(())
    }

    /// Create config file from default template.
    fn create_default_settings_file(&self) -> AnyResult<()> {
        self.save_settings_file_from_struct(&Settings {
            challenge: DEFAULT_CHALLENGE,
            includes: DEFAULT_INCLUDE_CHECKS
                .iter()
                .map(|i| i.to_string())
                .collect::<_>(),
            ignores: vec![],
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
        debug!(
            "settings file crated in path: {}. config data: {:?}",
            &self.setting_file_path, settings
        );
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
}

impl Settings {
    pub fn get_active_checks(&self) -> AnyResult<Vec<Check>> {
        Ok(get_all_checks()?
            .iter()
            .filter(|&c| self.includes.contains(&c.from))
            .cloned()
            .collect::<Vec<Check>>())
    }

    pub fn get_active_groups(&self) -> &Vec<String> {
        &self.includes
    }
}

#[cfg(test)]
mod test_config {
    use std::{fs::read_dir, path::Path};

    use insta::assert_debug_snapshot;
    use tempdir::TempDir;

    use super::*;

    fn initialize_config_folder(temp_dir: &TempDir) -> Config {
        let temp_dir = temp_dir.path().join("app");
        Config::new(Some(&temp_dir.display().to_string())).unwrap()
    }

    #[test]
    fn can_crate_new_config() {
        let temp_dir = TempDir::new("config-app").unwrap();
        let config = initialize_config_folder(&temp_dir);
        assert_debug_snapshot!(Path::new(&config.root_folder).is_dir());
        assert_debug_snapshot!(Path::new(&config.setting_file_path).is_file());
        temp_dir.close().unwrap();
    }

    #[test]
    fn cat_get_settings_from_file() {
        let temp_dir = TempDir::new("config-app").unwrap();
        let config = initialize_config_folder(&temp_dir);

        assert_debug_snapshot!(config.get_settings_from_file());
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_manage_config_file() {
        let temp_dir = TempDir::new("config-app").unwrap();
        let mut config = initialize_config_folder(&temp_dir);

        config.setting_file_path = temp_dir
            .path()
            .join("app")
            .join("new-file.yaml")
            .display()
            .to_string();

        assert_debug_snapshot!(Path::new(&config.setting_file_path).is_file());
        config.manage_setting_file().unwrap();
        assert_debug_snapshot!(Path::new(&config.setting_file_path).is_file());
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_add_check_groups() {
        let temp_dir = TempDir::new("config-app").unwrap();
        let config = initialize_config_folder(&temp_dir);
        assert_debug_snapshot!(config.get_settings_from_file());
        config
            .update_check_groups(vec!["group-1".to_string(), "group-2".to_string()])
            .unwrap();
        assert_debug_snapshot!(config.get_settings_from_file());
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_can_update_challenge() {
        let temp_dir = TempDir::new("config-app").unwrap();
        let config = initialize_config_folder(&temp_dir);

        assert_debug_snapshot!(config.get_settings_from_file());
        config.update_challenge(Challenge::Yes).unwrap();
        assert_debug_snapshot!(config.get_settings_from_file());
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_reset_config_with_override() {
        let temp_dir = TempDir::new("config-app").unwrap();
        let config = initialize_config_folder(&temp_dir);
        config.update_challenge(Challenge::Yes).unwrap();
        assert_debug_snapshot!(config.get_settings_from_file());
        config.reset_config(Some(0)).unwrap();
        assert_debug_snapshot!(config.get_settings_from_file());
        assert_debug_snapshot!(read_dir(config.root_folder).unwrap().count());
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_reset_config_with_with_backup() {
        let temp_dir = TempDir::new("config-app").unwrap();
        let config = initialize_config_folder(&temp_dir);
        config.update_challenge(Challenge::Yes).unwrap();
        assert_debug_snapshot!(config.get_settings_from_file());
        config.reset_config(Some(1)).unwrap();
        assert_debug_snapshot!(config.get_settings_from_file());
        assert_debug_snapshot!(read_dir(config.root_folder).unwrap().count());
        temp_dir.close().unwrap();
    }
}

#[cfg(test)]
mod test_settings {
    use insta::assert_debug_snapshot;
    use tempdir::TempDir;

    use super::*;

    fn initialize_config_folder(temp_dir: &TempDir) -> Config {
        let temp_dir = temp_dir.path().join("app");
        Config::new(Some(&temp_dir.display().to_string())).unwrap()
    }

    #[test]
    fn can_get_active_checks() {
        let temp_dir = TempDir::new("config-app").unwrap();
        let config = initialize_config_folder(&temp_dir);
        assert_debug_snapshot!(config
            .get_settings_from_file()
            .unwrap()
            .get_active_checks()
            .is_ok());
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_get_settings_from_file() {
        let temp_dir = TempDir::new("config-app").unwrap();
        let config = initialize_config_folder(&temp_dir);
        assert_debug_snapshot!(config.get_settings_from_file().unwrap().get_active_groups());
        temp_dir.close().unwrap();
    }
}
