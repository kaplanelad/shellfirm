//! Manage the app configuration by creating, deleting and modify the configuration

use crate::checks::Check;
use anyhow::anyhow;
use anyhow::Result as AnyResult;
use log::debug;
use serde_derive::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

/// Default configuration file.
pub const DEFAULT_CONFIG_FILE: &str = include_str!("config.yaml");
/// String with all checks from `checks` folder (prepared in build.rs) in YAML format.
pub const ALL_CHECKS: &str = include_str!(concat!(env!("OUT_DIR"), "/all-checks.yaml"));

/// The method type go the check.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub enum Method {
    /// Run start with check.
    StartWith,
    /// Run contains check.
    Contains,
    /// Run regex check.
    Regex,
}

/// The user challenge when user need to confirm the command.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub enum Challenge {
    /// Math challenge.
    Math,
    /// Only enter will approve the command.
    Enter,
    /// only yes typing will approve the command.
    Yes,
    /// Default application challenge
    Default,
}

impl Default for Challenge {
    fn default() -> Self {
        Challenge::Default
    }
}

#[derive(Debug)]
/// describe configuration folder
pub struct SettingsConfig {
    /// Configuration folder path.
    pub path: String,
    /// config file.
    pub config_file_path: String,
}

/// Describe the configuration yaml
#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    /// Type of the challenge.
    pub challenge: Challenge,
    /// List of all include files
    pub includes: Vec<String>,
    /// App version.
    #[serde(default)]
    pub version: String,
    /// List of checks.
    // #[serde(skip_deserializing)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub checks: Vec<Check>,
}

impl SettingsConfig {
    /// Convert user config yaml to struct.
    pub fn load_config_from_file(&self) -> AnyResult<Config> {
        Ok(serde_yaml::from_str(&self.read_config_file()?)?)
    }

    /// Return default app config.
    pub fn load_default_config(&self) -> AnyResult<Config> {
        Ok(serde_yaml::from_str(DEFAULT_CONFIG_FILE)?)
    }

    /// update config file with the updated baseline checks.
    pub fn update_config_version(&self, config: Config) -> AnyResult<()> {
        let mut config = self.add_checks_group(&config.includes)?;
        self.save_config_file_from_struct(&mut config)
    }

    /// Manage configuration folder & file.
    /// * Create config folder if not exists.
    /// * Create default config yaml file if not exists.
    ///
    // TODO:: need to test this function
    pub fn manage_config_file(&self) -> AnyResult<()> {
        self.create_config_folder()?;
        if fs::metadata(&self.config_file_path).is_err() {
            debug!("config file not found");
            self.create_default_config_file()?;
        }
        debug!("config content: {:?}", self.load_config_from_file()?);
        Ok(())
    }

    /// Update user settings files.
    ///
    /// # Arguments
    ///
    /// * remove_checks - if true the given `check_group` parameter will remove from configuration / if false will add.
    /// * check_groups - list of check groups to act.
    ///
    // TODO:: need to test this function
    pub fn update_config_content(
        &self,
        remove_checks: bool,
        check_groups: &[String],
    ) -> AnyResult<()> {
        if remove_checks {
            self.save_config_file_from_struct(&mut self.remove_checks_group(check_groups)?)?;
        } else {
            self.save_config_file_from_struct(&mut self.add_checks_group(check_groups)?)?;
        }
        Ok(())
    }

    /// Reset user configuration to the default app.
    ///
    // TODO:: need to test this function
    pub fn reset_config(&self) -> AnyResult<()> {
        eprintln!(
            "Rest configuration will reset all checks settings. Select how to continue...\n \
            1. Yes, i want to override the current configuration\n \
            2. Override and backup the existing file\n \
            3. Cancel Or ^C"
        );
        let mut answer = String::new();
        io::stdin()
            .read_line(&mut answer)
            .expect("Failed to read line");

        match answer.trim() {
            "1" => self.create_default_config_file()?,
            "2" => {
                fs::rename(
                    &self.config_file_path,
                    format!(
                        "{}.{}.bak",
                        self.config_file_path,
                        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
                    ),
                )?;
                self.create_default_config_file()?
            }
            _ => return Err(anyhow!("unexpected option")),
        };

        Ok(())
    }

    /// Update default user challenge.
    ///
    /// # Arguments
    ///
    /// * `challenge` - new challenge to update
    ///
    // TODO:: need to test this function
    pub fn update_challenge(&self, challenge: Challenge) -> AnyResult<()> {
        let mut conf = self.load_config_from_file()?;
        conf.challenge = challenge;
        self.save_config_file_from_struct(&mut conf)?;
        Ok(())
    }

    /// Create config folder if not exists.
    ///
    // TODO:: need to test this function
    fn create_config_folder(&self) -> AnyResult<()> {
        if let Err(err) = fs::create_dir(&self.path) {
            if err.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(anyhow!("could not create folder: {}", err));
            }
            debug!("configuration folder found: {}", &self.path);
        } else {
            debug!("configuration created in path: {}", &self.path);
        }
        Ok(())
    }

    /// Create config file from default template.
    fn create_default_config_file(&self) -> AnyResult<()> {
        let mut conf = self.load_default_config()?;
        conf.checks = self.get_default_checks(&conf.includes)?;
        self.save_config_file_from_struct(&mut conf)
    }

    /// Convert the given config to YAML format and the file.
    ///
    /// # Arguments
    ///
    /// * `config` - Config struct
    fn save_config_file_from_struct(&self, mut config: &mut Config) -> AnyResult<()> {
        config.version = env!("CARGO_PKG_VERSION").to_string();
        let content = serde_yaml::to_string(config)?;
        let mut file = fs::File::create(&self.config_file_path)?;
        file.write_all(content.as_bytes())?;
        debug!(
            "config file crated in path: {}. config data: {:?}",
            &self.config_file_path, config
        );
        Ok(())
    }

    /// Return config content.
    fn read_config_file(&self) -> AnyResult<String> {
        let mut file = std::fs::File::open(&self.config_file_path)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        Ok(content)
    }

    /// Add checks group to user configuration.
    ///
    /// # Arguments
    ///
    /// * `checks_group` - list of groups to add.
    fn add_checks_group(&self, checks_group: &[String]) -> AnyResult<Config> {
        //load user config file
        match self.load_config_from_file() {
            Ok(mut conf) => {

                for c in checks_group{
                    if !conf.includes.contains(c){
                        conf.includes.push(c.clone());
                    }
                }
                debug!("new list of includes groups: {:?}", checks_group);

                // List of checks that the user disable or change the challenge type
                let override_check_settings = conf.checks.iter().filter(|&c| checks_group.contains(&c.from)).filter(|c| !c.enable || c.challenge != Challenge::Default).cloned().collect::<Vec<Check>>();
                debug!("override checks settings: {:?}", override_check_settings);

                // remove checks group that we want to add for make sure that we not have duplicated checks
                let mut checks = conf.checks.iter().filter(|&c| !checks_group.contains(&c.from)).cloned().collect::<Vec<Check>>();
                checks.extend( self.get_default_checks(checks_group)?);

                for override_check in override_check_settings{
                    for c in  &mut checks{
                        if c.test == override_check.test{
                            c.enable = override_check.enable;
                            c.challenge = override_check.challenge.clone();
                        }
                    }
                }

                conf.checks = checks;
                debug!("new check list: {:?}", conf.checks);
                Ok(conf)
            },
            Err(e) => return Err(anyhow!("could not parse current config file. please try to fix the yaml. Try resolving by running `shellfirm config reset` Error: {}", e))
        }
    }

    /// Remove checks group from user configuration
    ///
    /// # Arguments
    ///
    /// * `checks_group` - list of groups to add.
    fn remove_checks_group(&self, checks_group: &[String]) -> AnyResult<Config> {
        //load user config file
        match self.load_config_from_file() {
            Ok(mut conf) => {

                for c in checks_group{
                    if conf.includes.contains(c){
                        conf.includes.retain(|x| x != c);
                    }
                }
                debug!("new list of includes groups: {:?}", checks_group);
                // remove checks group that we want to add for make sure that we not have duplicated checks
                conf.checks = conf.checks.iter().filter(|&c| conf.includes.contains(&c.from)).cloned().collect::<Vec<Check>>();

                debug!("new check list: {:?}", conf.checks);
                Ok(conf)
            },
            Err(_e) => return Err(anyhow!("could not parse current config file. please try to fix the yaml file or override the current configuration by use the flag `--behavior override`"))
        }
    }

    fn get_default_checks(&self, includes: &[String]) -> AnyResult<Vec<Check>> {
        Ok(get_all_available_checks()?
            .iter()
            .filter(|&c| includes.contains(&c.from))
            .cloned()
            .collect::<Vec<Check>>())
    }
}

/// Get application  setting config.
pub fn get_config_folder() -> AnyResult<SettingsConfig> {
    let package_name = env!("CARGO_PKG_NAME");

    match home::home_dir() {
        Some(path) => {
            let config_folder = path.join(format!(".{}", package_name));

            let setting_config = SettingsConfig {
                path: config_folder.to_str().unwrap().to_string(),
                config_file_path: config_folder
                    .join("config.yaml")
                    .to_str()
                    .unwrap()
                    .to_string(),
            };
            debug!("configuration settings: {:?}", setting_config);
            Ok(setting_config)
        }
        None => return Err(anyhow!("could not get directory path")),
    }
}

/// parse `ALL_CHECKS` const to vector of checks
fn get_all_available_checks() -> AnyResult<Vec<Check>> {
    Ok(serde_yaml::from_str(ALL_CHECKS)?)
}

#[cfg(test)]
mod test_config {
    use super::*;
    use insta::assert_debug_snapshot;
    use std::path::Path;

    fn get_current_project_path() -> String {
        std::env::current_dir().unwrap().to_str().unwrap().into()
    }

    fn get_temp_config_folder(file_name: &str) -> AnyResult<SettingsConfig> {
        let tmp_folder = Path::new(&get_current_project_path())
            .join("tmp")
            .to_str()
            .unwrap()
            .to_string();
        let config_file_path = Path::new(&tmp_folder)
            .join(file_name)
            .to_str()
            .unwrap()
            .to_string();
        if fs::metadata(&config_file_path).is_ok() {
            fs::remove_file(&config_file_path).unwrap();
        }

        Ok(SettingsConfig {
            path: tmp_folder,
            config_file_path,
        })
    }

    #[test]
    fn can_load_config_from_file() -> AnyResult<()> {
        let settings_config = SettingsConfig {
            path: get_current_project_path(),
            config_file_path: Path::new(&get_current_project_path())
                .join("src")
                .join("config.yaml")
                .to_str()
                .unwrap()
                .to_string(),
        };

        assert_debug_snapshot!(settings_config.load_config_from_file());
        Ok(())
    }

    #[test]
    fn can_load_default_config() {
        let conf = get_config_folder().unwrap();
        assert_debug_snapshot!(conf.load_default_config());
    }

    #[test]
    fn can_write_config_file() -> AnyResult<()> {
        let settings_config = get_temp_config_folder("config.yaml").unwrap();
        assert_debug_snapshot!(settings_config.manage_config_file());
        assert_debug_snapshot!(settings_config.read_config_file().unwrap());
        Ok(())
    }

    #[test]
    fn can_create_default_config_file() {
        let settings_config = get_temp_config_folder("default.yaml").unwrap();
        assert_debug_snapshot!(settings_config.create_default_config_file());
        assert_debug_snapshot!(Path::new(&settings_config.config_file_path).exists())
    }

    #[test]
    fn can_save_config_file_from_struct() {
        let settings_config = get_temp_config_folder("save-from-struct.yaml").unwrap();

        let mut config = settings_config.load_default_config().unwrap();

        // creates configuration file with only 1 check (we want to check that we not change existing check and just append new ones)
        config.checks = vec![Check {
            test: String::from("is value"),
            method: Method::Contains,
            enable: true,
            description: String::from("description"),
            from: String::from("from"),
            challenge: Challenge::Default,
            filters: std::collections::HashMap::new(),
        }];

        assert_debug_snapshot!(settings_config.save_config_file_from_struct(&mut config));
        assert_debug_snapshot!(settings_config.load_config_from_file());
    }

    #[test]
    fn can_add_checks_group() {
        let settings_config = get_temp_config_folder("add-checks.yaml").unwrap();

        let mut config = settings_config.load_default_config().unwrap();

        config.includes = vec!["test".into()];
        config.checks = vec![Check {
            test: String::from("is value"),
            method: Method::Contains,
            enable: true,
            description: String::from("description"),
            from: String::from(""),
            challenge: Challenge::Default,
            filters: std::collections::HashMap::new(),
        }];

        assert_debug_snapshot!(settings_config.save_config_file_from_struct(&mut config));
        assert_debug_snapshot!(settings_config.add_checks_group(&["base".into()]));
    }

    // #[ignore]
    // #[test]
    // fn can_remove_checks_group() {
    //     let settings_config = get_temp_config_folder("add-checks.yaml").unwrap();

    //     let mut config = settings_config.load_default_config().unwrap();

    //     config.includes = vec!["test".into()];
    //     config.checks = vec![Check {
    //         test: String::from("is value"),
    //         method: Method::Contains,
    //         enable: true,
    //         description: String::from("description"),
    //         from: String::from("test"),
    //         challenge: Challenge::Default,
    //         filters: std::collections::HashMap::new(),
    //     }];

    //     assert_debug_snapshot!(settings_config.save_config_file_from_struct(&mut config));
    //     assert_debug_snapshot!(settings_config.remove_checks_group(&["test".into()]));
    // }
}
