//! Configuration management

use crate::checks::Check;
use anyhow::anyhow;
use anyhow::Result as AnyResult;
use serde_derive::Deserialize;
use std::fs;
use std::io::{Read, Write};

pub const DEFAULT_CONFIG_FILE: &str = include_str!("config.yaml");

/// The method type go the check.
#[derive(Debug, Deserialize, Clone)]
pub enum Method {
    /// If the command start with.
    StartWith,
    /// if the command contains.
    Contains,
    /// if the command match to the given regex.
    Regex,
}

/// The user challenge when user need to confirm the command.
#[derive(Debug, Deserialize)]
pub enum Challenge {
    /// Math challenge.
    Math,
    /// Only enter will approve the command.
    Enter,
    /// only yes/no typing will approve the command.
    YesNo,
}

/// describe configuration folder
pub struct SettingsConfig {
    /// Configuration folder path.
    pub path: String,
    /// config file.
    pub config_file_path: String,
    /// If configuration path overridden by the user.
    pub default: bool,
}

/// Describe the configuration yaml
#[derive(Debug, Deserialize)]
pub struct Config {
    /// Type of the challenge.
    pub challenge: Challenge,
    /// List of checks.
    pub checks: Vec<Check>,
}

// /// Describe single check
// #[derive(Debug, Deserialize, Clone)]
// pub struct Check {
//     pub is: String,
//     pub method: Method,
//     pub enable: bool,
//     pub description: String,
// }

impl SettingsConfig {
    /// Convert config yaml file to struct.
    pub fn load_config_from_file(&self) -> AnyResult<Config> {
        Ok(serde_yaml::from_str(&self.read_config_file()?)?)
    }

    /// Manage configuration folder/ file.
    /// * Create config folder if not exists
    /// * Create config yaml file if not exists
    pub fn manage_config_file(&self) -> AnyResult<()> {
        self.create_config_folder()?;
        if fs::metadata(&self.config_file_path).is_err() {
            self.create_default_config_file()?;
        }
        Ok(())
    }

    /// Create config folder if not exists.
    fn create_config_folder(&self) -> AnyResult<()> {
        if let Err(err) = fs::create_dir(&self.path) {
            if err.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(anyhow!("could not create folder: {}", err.to_string()));
            }
        }
        Ok(())
    }

    /// Create config file with default configuration content
    fn create_default_config_file(&self) -> AnyResult<()> {
        let mut file = fs::File::create(&self.config_file_path)?;
        file.write_all(DEFAULT_CONFIG_FILE.as_bytes())?;
        Ok(())
    }

    /// Convert config file to config struct.
    fn read_config_file(&self) -> AnyResult<String> {
        let mut file = std::fs::File::open(&self.config_file_path)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        Ok(content)
    }
}

/// Get config config application details.
///
/// # Arguments
///
/// * `path` - Config folder path. if is empty default path will be returned.
pub fn get_config_folder(path: &str) -> AnyResult<SettingsConfig> {
    let package_name = std::env::var("CARGO_PKG_NAME").unwrap();

    let mut config_folder = path.into();
    let mut is_default = false;
    if path.is_empty() {
        match home::home_dir() {
            Some(path) => {
                is_default = true;
                config_folder = format!("{}/.{}", path.display(), package_name);
            }
            None => return Err(anyhow!("could not get directory path")),
        }
    }
    Ok(SettingsConfig {
        path: config_folder.clone(),
        default: is_default,
        config_file_path: format!("{}/config.yaml", config_folder),
    })
}

#[cfg(test)]
mod password {
    use super::*;

    fn get_current_project_path() -> String {
        std::env::current_dir().unwrap().to_str().unwrap().into()
    }
    #[test]
    fn can_get_config_default_folder() {
        let conf = get_config_folder("").unwrap();
        assert_ne!(conf.path, "");
        assert!(conf.default);
        assert_eq!(conf.config_file_path, format!("{}/config.yaml", conf.path));
    }

    #[test]
    fn can_get_config_custom_folder() {
        let folder_path = "/custom/folder/path";
        let conf = get_config_folder(folder_path).unwrap();
        assert_eq!(conf.path, folder_path);
        assert!(!conf.default);
        assert_eq!(conf.config_file_path, format!("{}/config.yaml", conf.path));
    }

    #[test]
    fn can_load_config_from_file() {
        let settings_config = SettingsConfig {
            path: get_current_project_path(),
            default: false,
            config_file_path: format!("{}/src/config.yaml", get_current_project_path()),
        };

        assert!(settings_config.load_config_from_file().is_ok())
    }

    #[test]
    fn cant_load_config_from_file() {
        let settings_config = SettingsConfig {
            path: String::from(""),
            default: false,
            config_file_path: String::from(""),
        };

        assert!(settings_config.load_config_from_file().is_err())
    }

    #[test]
    fn can_write_config_file() {
        let tmp_folder = format!("{}/tmp", get_current_project_path());
        if fs::metadata(&tmp_folder).is_ok() {
            fs::remove_dir_all(&tmp_folder).unwrap();
        }

        let settings_config = SettingsConfig {
            path: format!("{}", tmp_folder),
            default: false,
            config_file_path: format!("{}/config.yaml", tmp_folder),
        };

        assert!(settings_config.manage_config_file().is_ok());
        assert!(settings_config.read_config_file().is_ok());
    }
}
