//! Configuration management

use anyhow::anyhow;
use anyhow::Result as AnyResult;
use serde_derive::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};

pub const DEFAULT_CONFIG_FILE: &str = include_str!("config.yaml");

/// The method type go the check.
#[derive(Debug, Deserialize)]
pub enum Method {
    /// If the command start with.
    Startwith,
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
pub struct ConfigFolder {
    /// Configuration folder path.
    pub path: String,
    /// If configuration path overridden by the user.
    pub default: bool,
}

/// Describe the configuration yaml
#[derive(Debug, Deserialize)]
pub struct Config {
    /// Type of the challenge.
    pub challenge: Challenge,
    /// List of checks.
    pub checks: HashMap<String, Check>,
}

/// Describe single check
#[derive(Debug, Deserialize)]
pub struct Check {
    pub is: String,
    pub method: Method,
}

impl ConfigFolder {
    pub fn get_config_file_path(&self) -> String {
        format!("{}/config.yaml", self.path)
    }

    pub fn load_config_from_file(&self) -> AnyResult<Config> {
        let config_content = read_file(&self.get_config_file_path())?;
        let config = serde_yaml::from_str(&config_content)?;
        Ok(config)
    }
}

pub fn get_config_folder(path: &str) -> AnyResult<ConfigFolder> {
    let package_name = std::env::var("CARGO_PKG_NAME").unwrap();

    let mut config_folder = path.into();
    let mut is_default = false;
    if path == "" {
        match home::home_dir() {
            Some(path) => {
                is_default = true;
                config_folder = format!("{}/.{}", path.display(), package_name);
            }
            None => return Err(anyhow!("could not get directory path")),
        }
    }
    Ok(ConfigFolder {
        path: config_folder,
        default: is_default,
    })
}

pub fn manage_config_file(conf: &ConfigFolder) -> AnyResult<()> {
    let config_file = conf.get_config_file_path();
    if fs::metadata(&config_file).is_err() {
        create_default_config_file(&config_file)?;
    }
    Ok(())
}

fn create_default_config_file(file_path: &str) -> AnyResult<()> {
    let mut file = fs::File::create(file_path)?;
    file.write_all(DEFAULT_CONFIG_FILE.as_bytes())?;
    Ok(())
}

fn read_file(filepath: &str) -> AnyResult<String> {
    let mut file = std::fs::File::open(filepath)?;

    let mut content = String::new();
    file.read_to_string(&mut content)?;
    Ok(content)
}
