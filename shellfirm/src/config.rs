//! Manage the app configuration by creating, deleting and modify the configuration

use crate::checks::Check;
use anyhow::anyhow;
use anyhow::Result as AnyResult;
use log::debug;
use requestty::{DefaultSeparator, Question};
use serde_derive::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

/// Default configuration file.
pub const DEFAULT_CONFIG_FILE: &str = include_str!("config.yaml");

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
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
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
pub struct Config {
    // Latest shellfirm version
    pub latest_version: String,
    all_checks: Vec<Check>,
    /// Configuration folder path.
    pub path: String,
    /// config file.
    pub config_file_path: String,
}

/// Describe the configuration yaml
#[derive(Debug, Deserialize, Serialize)]
pub struct Context {
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

impl Config {
    /// Convert user config yaml to struct.
    ///
    /// # Errors
    ///
    /// Will return `Err` has an error when loading the config file
    pub fn load_config_from_file(&self) -> AnyResult<Context> {
        Ok(serde_yaml::from_str(&self.read_config_file()?)?)
    }

    /// Return default app config.
    /// # Errors
    ///
    /// Will return `Err` could not parse default config to yaml file
    pub fn load_default_config(&self) -> AnyResult<Context> {
        Ok(serde_yaml::from_str(DEFAULT_CONFIG_FILE)?)
    }

    /// update config file with the updated baseline checks.
    ///
    /// # Errors
    ///
    /// Will return `Err` adding check group return an error
    pub fn update_config_version(&self, config: &Context) -> AnyResult<()> {
        let mut config = self.add_checks_group(&config.includes)?;
        self.save_config_file_from_struct(&mut config)
    }

    /// Manage configuration folder & file.
    /// * Create config folder if not exists.
    /// * Create default config yaml file if not exists.
    ///
    /// # Errors
    ///
    /// Will return `Err` file could not created or loaded
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
    /// * `remove_checks` - if true the given `check_group` parameter will remove from configuration / if false will add.
    /// * `check_groups` - list of check groups to act.
    ///
    /// # Errors
    ///
    /// Will return `Err` group didn't added/removed
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
    /// # Errors
    ///
    /// Will return `Err` create config folder return an error
    pub fn reset_config(&self, force_selection: Option<usize>) -> AnyResult<()> {
        let selected = if let Some(force_selection) = force_selection {
            force_selection
        } else {
            let questions = requestty::prompt_one(
            Question::raw_select("reset")
                .message(
                    "Rest configuration will reset all checks settings. Select how to continue...",
                )
                .choices(vec![
                    "Yes, i want to override the current configuration".into(),
                    "Override and backup the existing file".into(),
                    DefaultSeparator,
                    "Cancel Or ^C".into(),
                ])
                .build(),
        )?;
            questions.as_list_item().map_or(3, |s| s.index)
        };

        match selected {
            0 => self.create_default_config_file()?,
            1 => {
                self.backup()?;
                self.create_default_config_file()?;
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
    /// # Errors
    ///
    /// Will return `Err` error return on load/save config
    pub fn update_challenge(&self, challenge: Challenge) -> AnyResult<()> {
        let mut conf = self.load_config_from_file()?;
        conf.challenge = challenge;
        self.save_config_file_from_struct(&mut conf)?;
        Ok(())
    }

    /// Create config folder if not exists.
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
        conf.checks = self.get_default_checks(&conf.includes);
        self.save_config_file_from_struct(&mut conf)
    }

    /// Convert the given config to YAML format and the file.
    ///
    /// # Arguments
    ///
    /// * `config` - Config struct
    fn save_config_file_from_struct(&self, mut config: &mut Context) -> AnyResult<()> {
        config.version = self.latest_version.to_string();
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
    fn add_checks_group(&self, checks_group: &[String]) -> AnyResult<Context> {
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
                let override_check_settings = conf.checks.iter()
                    .filter(|&c| checks_group.contains(&c.from))
                    .filter(|c| !c.enable || c.challenge != Challenge::Default)
                    .cloned()
                    .collect::<Vec<Check>>();

                debug!("override checks settings: {:?}", override_check_settings);

                // remove checks group that we want to add for make sure that we not have duplicated checks
                let mut checks = conf.checks.iter()
                    .filter(|&c| !checks_group.contains(&c.from))
                    .cloned()
                    .collect::<Vec<Check>>();

                checks.extend( self.get_default_checks(checks_group));

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
            Err(e) => Err(anyhow!("could not parse current config file. please try to fix the yaml. Try resolving by running `shellfirm config reset` Error: {}", e))
        }
    }

    /// Remove checks group from user configuration
    ///
    /// # Arguments
    ///
    /// * `checks_group` - list of groups to add.
    fn remove_checks_group(&self, checks_group: &[String]) -> AnyResult<Context> {
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
                conf.checks = conf.checks.iter().filter(|&c|{
                        println!("{:?}.containn.{} => {}", conf.includes, &c.from, conf.includes.contains(&c.from));
                     conf.includes.contains(&c.from)
                }).cloned().collect::<Vec<Check>>();

                debug!("new check list: {:?}", conf.checks);
                Ok(conf)
            },
            Err(_e) => Err(anyhow!("could not parse current config file. please try to fix the yaml file or override the current configuration by use the flag `--behavior override`"))
        }
    }

    fn backup(&self) -> AnyResult<String> {
        let backup_to = format!(
            "{}.{}.bak",
            self.config_file_path,
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
        );
        fs::rename(&self.config_file_path, &backup_to)?;
        Ok(backup_to)
    }

    fn get_default_checks(&self, includes: &[String]) -> Vec<Check> {
        self.all_checks
            .iter()
            .filter(|&c| includes.contains(&c.from))
            .cloned()
            .collect::<Vec<Check>>()
    }
}

/// Get application  setting config.
///
/// # Errors
///
/// Will return `Err` error return on load/save config
pub fn get_config_folder(all_checks: Vec<Check>) -> AnyResult<Config> {
    let package_name = env!("CARGO_PKG_NAME");

    match dirs::home_dir() {
        Some(path) => {
            let config_folder = {
                // The project started with $HOME path to save the config file. In order the requests
                // to use $XDG_CACHE_HOME and keep backward compatibility if the folder $HOME/.shellform exists
                // shillfirm continue work with that folder. If the folder does not exists, the default use config dir
                let homedir = path.join(format!(".{}", package_name));
                let confdir = dirs::config_dir().unwrap_or_else(|| homedir.clone());
                if homedir.is_dir() {
                    homedir
                } else {
                    confdir.join(package_name)
                }
            };

            let setting_config = Config {
                latest_version: env!("CARGO_PKG_VERSION").to_string(),
                all_checks,
                path: config_folder.display().to_string(),
                config_file_path: config_folder
                    .join("config.yaml")
                    .to_str()
                    .unwrap_or("")
                    .to_string(),
            };

            setting_config.manage_config_file()?;
            debug!("configuration settings: {:?}", setting_config);
            Ok(setting_config)
        }
        None => Err(anyhow!("could not get directory path")),
    }
}

// /// parse `ALL_CHECKS` const to vector of checks
// fn get_all_available_checks() -> AnyResult<Vec<Check>> {
//     Ok(serde_yaml::from_str(ALL_CHECKS)?)
// }

#[cfg(test)]
mod test_config {
    use super::*;
    use insta::assert_debug_snapshot;
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;
    use tempdir::TempDir;

    const CONFIG: &str = r###"---
challenge: Math
includes:
  - default-check
version: 0.2.2
checks: 
- from: default-check
  test: default-check
  method: Regex
  enable: true
  description: ""
"###;
    const CHECKS: &str = r###"
- from: test-1
  test: test-1
  method: Regex
  enable: true
  description: ""
- from: test-2
  test: test-2
  method: Regex
  enable: true
  description: ""
- from: test-disabled
  test: test-disabled
  method: Regex
  enable: true
  description: ""
"###;

    fn initialize_config_folder(temp_dir: &TempDir) -> Config {
        let app_path = temp_dir.path().join("app");
        fs::create_dir_all(&app_path).unwrap();
        let config_file_path = app_path.join("config.yaml");

        let mut f = File::create(&config_file_path).unwrap();
        f.write_all(CONFIG.as_bytes()).unwrap();
        f.sync_all().unwrap();
        Config {
            latest_version: "0.0.0".to_string(),
            all_checks: serde_yaml::from_str(CHECKS).unwrap(),
            path: app_path.display().to_string(),
            config_file_path: config_file_path.to_str().unwrap().to_string(),
        }
    }

    #[test]
    fn can_load_config_from_file() {
        let temp_dir = TempDir::new("config-app").unwrap();
        let config = initialize_config_folder(&temp_dir);
        assert_debug_snapshot!(config.load_config_from_file());
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_load_default_config() {
        let temp_dir = TempDir::new("config-app").unwrap();
        let config = initialize_config_folder(&temp_dir);
        assert_debug_snapshot!(config.load_default_config());
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_update_config_version() {
        let temp_dir = TempDir::new("config-app").unwrap();
        let config = initialize_config_folder(&temp_dir);
        let context = {
            let mut context = config.load_config_from_file().unwrap();
            context.includes.push("test-1".to_string());
            context
        };
        assert_debug_snapshot!(config.update_config_version(&context));
        assert_debug_snapshot!(config.read_config_file());
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_manage_config_file() {
        let temp_dir = TempDir::new("config-app").unwrap();
        let app_path = temp_dir.path().join("app");
        let config = Config {
            latest_version: "0.0.0".to_string(),
            all_checks: vec![],
            path: app_path.display().to_string(),
            config_file_path: app_path.to_str().unwrap().to_string(),
        };

        assert_debug_snapshot!(Path::new(&config.path).is_dir());
        assert_debug_snapshot!(config.manage_config_file());
        assert_debug_snapshot!(Path::new(&config.path).is_dir());
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_update_config_content() {
        let temp_dir = TempDir::new("config-app").unwrap();
        let config = initialize_config_folder(&temp_dir);

        assert_debug_snapshot!(config.update_config_content(false, &vec!["test-2".to_string()]));
        assert_debug_snapshot!(config.read_config_file());
        assert_debug_snapshot!(config.update_config_content(true, &vec!["test-2".to_string()]));
        assert_debug_snapshot!(config.read_config_file());
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_reset_config() {
        let temp_dir = TempDir::new("config-app").unwrap();
        let config = initialize_config_folder(&temp_dir);

        assert_debug_snapshot!(config.update_config_content(false, &vec!["test-2".to_string()]));
        assert_debug_snapshot!(config.read_config_file());
        assert_debug_snapshot!(config.reset_config(Some(1)));
        assert_debug_snapshot!(config.read_config_file());
    }

    #[test]
    fn can_update_challenge() {
        let temp_dir = TempDir::new("config-app").unwrap();
        let config = initialize_config_folder(&temp_dir);
        assert_debug_snapshot!(config.load_config_from_file().unwrap().challenge);
        assert_debug_snapshot!(config.update_challenge(Challenge::Yes));
        assert_debug_snapshot!(config.read_config_file());
    }

    #[test]
    fn can_create_config_folder() {
        let temp_dir = TempDir::new("config-app").unwrap();
        let app_path = temp_dir.path().join("app");
        let config = Config {
            latest_version: "0.0.0".to_string(),
            all_checks: vec![],
            path: app_path.display().to_string(),
            config_file_path: app_path.to_str().unwrap().to_string(),
        };

        assert_debug_snapshot!(Path::new(&config.path).is_dir());
        assert_debug_snapshot!(config.create_config_folder());
        assert_debug_snapshot!(Path::new(&config.path).is_dir());
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_create_default_config_file() {
        let temp_dir = TempDir::new("config-app").unwrap();
        let config = initialize_config_folder(&temp_dir);
        assert_debug_snapshot!(config.create_default_config_file());
        assert_debug_snapshot!(config.read_config_file());
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_save_config_file_from_struct() {
        let temp_dir = TempDir::new("config-app").unwrap();
        let config = initialize_config_folder(&temp_dir);
        let mut context = {
            let mut context = config.load_config_from_file().unwrap();
            context.includes.extend([
                "test-1".to_string(),
                "test-2".to_string(),
                "test-disabled".to_string(),
            ]);
            context.checks = vec![Check {
                test: String::from("test-value"),
                method: Method::Contains,
                enable: true,
                description: String::from("description"),
                from: String::from("test"),
                challenge: Challenge::Default,
                filters: std::collections::HashMap::new(),
            }];
            context
        };

        assert_debug_snapshot!(config.save_config_file_from_struct(&mut context));
        assert_debug_snapshot!(config.read_config_file());
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_add_checks_group() {
        let temp_dir = TempDir::new("config-app").unwrap();
        let config = initialize_config_folder(&temp_dir);
        assert_debug_snapshot!(
            config.add_checks_group(&["test-1".to_string(), "test-2".to_string()])
        );
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_remove_checks_group() {
        let temp_dir = TempDir::new("config-app").unwrap();
        let config = initialize_config_folder(&temp_dir);
        let context = config.add_checks_group(&["test-1".to_string(), "test-2".to_string()]);
        assert_debug_snapshot!(&context);
        assert_debug_snapshot!(config.save_config_file_from_struct(&mut context.unwrap()));
        assert_debug_snapshot!(config.remove_checks_group(&["test-1".to_string()]));
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_get_default_checks() {
        let temp_dir = TempDir::new("config-app").unwrap();
        let config = initialize_config_folder(&temp_dir);
        assert_debug_snapshot!(
            config.get_default_checks(&["test-1".to_string(), "test-2".to_string()])
        );
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_backup() {
        let temp_dir = TempDir::new("config-app").unwrap();
        let config = initialize_config_folder(&temp_dir);
        let backup = config.backup();

        assert_debug_snapshot!(backup.is_ok());
        let mut file = std::fs::File::open(&backup.unwrap()).unwrap();
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();

        assert_debug_snapshot!(content);
        temp_dir.close().unwrap();
    }
}
