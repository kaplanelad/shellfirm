//! Configuration management

use crate::checks::Check;
use crate::cli::{UPDATE_CONFIGURATION_ONLY_DIFF, UPDATE_CONFIGURATION_OVERRIDE};
use anyhow::anyhow;
use anyhow::Result as AnyResult;
use serde_derive::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};

pub const DEFAULT_CONFIG_FILE: &str = include_str!("config.yaml");

/// The method type go the check.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub enum Method {
    /// If the command start with.
    StartWith,
    /// if the command contains.
    Contains,
    /// if the command match to the given regex.
    Regex,
}

/// The user challenge when user need to confirm the command.
#[derive(Debug, Deserialize, Serialize)]
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
#[derive(Debug, Deserialize, Serialize)]
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

    /// Return default app config as a config struct.
    pub fn load_default_config(&self) -> AnyResult<Config> {
        Ok(serde_yaml::from_str(DEFAULT_CONFIG_FILE)?)
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

    pub fn update_config_content(&self, behavior: &str) -> AnyResult<()> {
        match behavior {
            UPDATE_CONFIGURATION_ONLY_DIFF => self.add_diff_configuration_file(),
            UPDATE_CONFIGURATION_OVERRIDE => self.override_configuration_file(),
            _ => return Err(anyhow!("unsupported behavior")),
        }
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

    /// Create config file with default configuration content
    fn create_config_file_from_struct(&self, config: &Config) -> AnyResult<()> {
        let content = serde_yaml::to_string(config)?;
        let mut file = fs::File::create(&self.config_file_path)?;
        file.write_all(content.as_bytes())?;
        Ok(())
    }

    /// Convert config file to config struct.
    fn read_config_file(&self) -> AnyResult<String> {
        let mut file = std::fs::File::open(&self.config_file_path)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        Ok(content)
    }

    /// override existing config yaml file with the application configuration
    fn override_configuration_file(&self) -> AnyResult<()> {
        self.create_default_config_file()
    }

    /// adding only new check into configuration file.
    fn add_diff_configuration_file(&self) -> AnyResult<()> {
        match self.load_config_from_file() {
            Ok(mut conf) => {

                let default_app_config =  self.load_default_config()?;

                for default_check in default_app_config.checks.clone() {
                    let mut found = false;
                    for user_check in &conf.checks{
                        if user_check.is == default_check.is {found = true; break;}
                    }
                    if !found {
                        conf.checks.push(default_check.clone())
                    }
                }
                self.create_config_file_from_struct(&conf)?;
                Ok(())
            },
            Err(_e) => return Err(anyhow!("could not parse current config file. please try to fix the yaml file or override the current configuration by use the flag `--behavior override`"))
        }
    }
}

/// Get config config application details.
///
/// # Arguments
///
/// * `path` - Config folder path. if is empty default path will be returned.
pub fn get_config_folder(path: &str) -> AnyResult<SettingsConfig> {
    let package_name = env!("CARGO_PKG_NAME");

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
mod config {
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
        let config_file_path = format!("{}/config.yaml", &tmp_folder);
        if fs::metadata(&config_file_path).is_ok() {
            fs::remove_file(&config_file_path).unwrap();
        }

        let settings_config = SettingsConfig {
            path: format!("{}", tmp_folder),
            default: false,
            config_file_path: config_file_path,
        };

        assert!(settings_config.manage_config_file().is_ok());
        assert!(settings_config.read_config_file().is_ok());
    }

    #[test]
    fn can_load_default_config() {
        let conf = get_config_folder("").unwrap();
        assert!(conf.load_default_config().is_ok())
    }

    #[test]
    fn can_override_existing_config() {
        let settings_config = SettingsConfig {
            path: get_current_project_path(),
            default: false,
            config_file_path: format!("{}/tmp/override.yaml", get_current_project_path()),
        };

        // check if we file created successfully
        assert!(fs::File::create(&settings_config.config_file_path)
            .unwrap()
            .write_all("".as_bytes())
            .is_ok());

        // then read the file and make sure that the content is empty
        let file_content = settings_config
            .read_config_file()
            .unwrap_or(format!("error"));

        assert_eq!(file_content, "");

        // create the default configuration
        assert!(settings_config.override_configuration_file().is_ok());
        // make sure that the file is not empty
        assert!(!settings_config.read_config_file().unwrap().is_empty());
    }

    #[test]
    fn can_add_diff_configuration_file() {
        let settings_config = SettingsConfig {
            path: get_current_project_path(),
            default: false,
            config_file_path: format!("{}/tmp/add-diff.yaml", get_current_project_path()),
        };

        let orig_config = settings_config.load_default_config().unwrap();
        let mut config = settings_config.load_default_config().unwrap();

        // creates configuration file with only 1 check (we want to check that we not change existing check and just append new ones)
        config.checks = vec![Check {
            is: String::from("is value"),
            method: Method::Contains,
            enable: true,
            description: String::from("description"),
        }];

        // create configuration file with 1 check
        assert!(settings_config
            .create_config_file_from_struct(&config)
            .is_ok());

        // make sure that the configuration created with 1 check
        assert_eq!(
            settings_config
                .load_config_from_file()
                .unwrap()
                .checks
                .len(),
            config.checks.len()
        );

        // create the config diff command
        assert!(settings_config.add_diff_configuration_file().is_ok());

        // make sure that the count of check that change equal to existing config + the default application config
        assert_eq!(
            settings_config
                .load_config_from_file()
                .unwrap()
                .checks
                .len(),
            config.checks.len() + orig_config.checks.len()
        );
    }
}
