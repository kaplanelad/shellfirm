//! Manage the app configuration by creating, deleting and modify the
//! configuration

use std::{
    collections::{HashMap, HashSet},
    env, fmt, fs,
    io::{Read, Write},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::error::{Error, Result};
use crate::{checks, checks::Severity, context::ContextConfig, prompt};
use serde_derive::{Deserialize, Serialize};
use tracing::debug;

/// Configuration for the optional LLM-powered command analysis.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LlmConfig {
    /// LLM provider name: "anthropic" or "openai-compatible".
    #[serde(default = "default_llm_provider")]
    pub provider: String,
    /// Model ID to use (e.g. "claude-sonnet-4-20250514").
    #[serde(default = "default_llm_model")]
    pub model: String,
    /// Custom base URL for openai-compatible providers.
    #[serde(default)]
    pub base_url: Option<String>,
    /// Request timeout in milliseconds.
    #[serde(default = "default_llm_timeout_ms")]
    pub timeout_ms: u64,
    /// Max tokens in the LLM response.
    #[serde(default = "default_llm_max_tokens")]
    pub max_tokens: u32,
}

fn default_llm_provider() -> String {
    "anthropic".into()
}

fn default_llm_model() -> String {
    "claude-sonnet-4-20250514".into()
}

const fn default_llm_timeout_ms() -> u64 {
    5000
}

const fn default_llm_max_tokens() -> u32 {
    512
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            provider: default_llm_provider(),
            model: default_llm_model(),
            base_url: None,
            timeout_ms: default_llm_timeout_ms(),
            max_tokens: default_llm_max_tokens(),
        }
    }
}

/// Configuration for AI agent guardrails.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AgentConfig {
    /// Auto-deny commands at or above this severity when running in agent mode.
    #[serde(default = "default_auto_deny_severity")]
    pub auto_deny_severity: Severity,
    /// Require human approval for agent-denied commands (reserved for future use).
    #[serde(default)]
    pub require_human_approval: bool,
}

const fn default_auto_deny_severity() -> Severity {
    Severity::High
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            auto_deny_severity: default_auto_deny_severity(),
            require_human_approval: false,
        }
    }
}

/// Configuration for the `shellfirm wrap` PTY proxy.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct WrappersConfig {
    /// Per-tool overrides keyed by program name (e.g. "psql", "redis-cli").
    #[serde(default)]
    pub tools: HashMap<String, WrapperToolConfig>,
}

/// Per-tool configuration for the `shellfirm wrap` proxy.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct WrapperToolConfig {
    /// Statement delimiter: ";" for SQL tools, "\n" for line-oriented tools.
    #[serde(default = "default_wrap_delimiter")]
    pub delimiter: String,
    /// Override which check groups are active (empty = use global setting).
    #[serde(default)]
    pub check_groups: Vec<String>,
}

fn default_wrap_delimiter() -> String {
    ";".into()
}

impl Default for WrapperToolConfig {
    fn default() -> Self {
        Self {
            delimiter: default_wrap_delimiter(),
            check_groups: vec![],
        }
    }
}

const DEFAULT_SETTING_FILE_NAME: &str = "settings.yaml";

pub const DEFAULT_CHALLENGE: Challenge = Challenge::Math;

fn default_enabled_groups() -> Vec<String> {
    DEFAULT_ENABLED_GROUPS
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

const fn default_audit_enabled() -> bool {
    true
}

const fn default_blast_radius() -> bool {
    true
}

pub const DEFAULT_ENABLED_GROUPS: [&str; 16] = [
    "aws",
    "azure",
    "base",
    "database",
    "docker",
    "fs",
    "gcp",
    "git",
    "heroku",
    "kubernetes",
    "mongodb",
    "mysql",
    "network",
    "psql",
    "redis",
    "terraform",
];

/// The user challenge when user need to confirm the command.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
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
    pub root_folder: PathBuf,
    /// config file.
    pub setting_file_path: PathBuf,
}

/// Describe the configuration yaml
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Settings {
    /// Type of the challenge.
    #[serde(default)]
    pub challenge: Challenge,
    /// Whitelist of check groups to enable (default: all 12 groups).
    #[serde(default = "default_enabled_groups")]
    pub enabled_groups: Vec<String>,
    /// Blacklist of check groups to disable (applied after whitelist).
    #[serde(default)]
    pub disabled_groups: Vec<String>,
    /// List of all ignore checks
    #[serde(default)]
    pub ignores_patterns_ids: Vec<String>,
    /// List of pattens id to prevent
    #[serde(default)]
    pub deny_patterns_ids: Vec<String>,
    /// Context-aware protection configuration.
    #[serde(default)]
    pub context: ContextConfig,
    /// Enable audit trail (log intercepted commands).
    #[serde(default = "default_audit_enabled")]
    pub audit_enabled: bool,
    /// Enable blast radius computation (shows impact details for risky commands).
    #[serde(default = "default_blast_radius")]
    pub blast_radius: bool,
    /// Minimum severity for a check to trigger a challenge.
    /// When `None`, all severities trigger. When set, checks below this
    /// threshold are skipped (but still logged to audit as `Skipped`).
    #[serde(default)]
    pub min_severity: Option<Severity>,
    /// AI agent guardrail configuration.
    #[serde(default)]
    pub agent: AgentConfig,
    /// LLM-powered analysis configuration (requires `llm` feature).
    /// `None` means LLM is not configured (disabled by default).
    #[serde(default)]
    pub llm: Option<LlmConfig>,
    /// PTY wrapper configuration (requires `wrap` feature).
    #[serde(default)]
    pub wrappers: WrappersConfig,
}

impl fmt::Display for Challenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Math => write!(f, "Math"),
            Self::Enter => write!(f, "Enter"),
            Self::Yes => write!(f, "Yes"),
        }
    }
}

impl Default for Challenge {
    fn default() -> Self {
        DEFAULT_CHALLENGE
    }
}

impl Challenge {
    /// Convert challenge string to enum
    ///
    /// # Errors
    /// when the given challenge string is not supported
    pub fn from_string(str: &str) -> Result<Self> {
        match str.to_lowercase().as_str() {
            "math" => Ok(Self::Math),
            "enter" => Ok(Self::Enter),
            "yes" => Ok(Self::Yes),
            _ => Err(Error::Config("given challenge name not found".into())),
        }
    }

    /// Return the stricter of two challenges.
    /// Order: Math < Enter < Yes
    #[must_use]
    pub fn stricter(self, other: Self) -> Self {
        let rank = |c: Self| match c {
            Self::Math => 0,
            Self::Enter => 1,
            Self::Yes => 2,
        };
        if rank(self) >= rank(other) {
            self
        } else {
            other
        }
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            challenge: DEFAULT_CHALLENGE,
            enabled_groups: default_enabled_groups(),
            disabled_groups: vec![],
            ignores_patterns_ids: vec![],
            deny_patterns_ids: vec![],
            context: ContextConfig::default(),
            audit_enabled: default_audit_enabled(),
            blast_radius: default_blast_radius(),
            min_severity: None,
            agent: AgentConfig::default(),
            llm: None,
            wrappers: WrappersConfig::default(),
        }
    }
}

impl Config {
    /// Get application  setting config.
    ///
    /// # Errors
    ///
    /// Will return `Err` error return on load/save config
    pub fn new(path: Option<&str>) -> Result<Self> {
        let package_name = env!("CARGO_PKG_NAME");

        let config_folder = match path {
            Some(p) => PathBuf::from(p),
            None => match dirs::config_dir() {
                Some(conf_dir) => conf_dir.join(package_name),
                None => return Err(Error::Config("could not get directory path".into())),
            },
        };

        let setting_file_path = config_folder.join(DEFAULT_SETTING_FILE_NAME);
        let setting_config = Self {
            root_folder: config_folder,
            setting_file_path,
        };

        debug!("configuration settings: {setting_config:?}");
        Ok(setting_config)
    }

    /// Get the path to the audit log file.
    #[must_use]
    pub fn audit_log_path(&self) -> PathBuf {
        self.root_folder.join("audit.log")
    }

    /// Get the path to the custom checks directory.
    #[must_use]
    pub fn custom_checks_dir(&self) -> PathBuf {
        self.root_folder.join("checks")
    }

    /// Convert user settings yaml to struct.
    ///
    /// # Errors
    ///
    /// Will return `Err` has an error when loading the config file
    pub fn get_settings_from_file(&self) -> Result<Settings> {
        match self.read_config_file() {
            Ok(content) => match serde_yaml::from_str(&content) {
                Ok(settings) => Ok(settings),
                Err(e) => {
                    tracing::warn!(
                        "Settings file could not be parsed, using defaults: {e}. \
                         Run `shellfirm config reset` to fix."
                    );
                    Ok(Settings::default())
                }
            },
            Err(_) if !self.setting_file_path.exists() => Ok(Settings::default()),
            Err(e) => Err(e),
        }
    }

    /// Reset user configuration to the default app.
    ///
    /// # Errors
    ///
    /// Will return `Err` create config folder return an error
    pub fn reset_config(&self, force_selection: Option<usize>) -> Result<()> {
        let selected = if let Some(force_selection) = force_selection {
            force_selection
        } else {
            prompt::reset_config()?
        };

        match selected {
            0 => self.create_default_settings_file()?,
            1 => {
                self.backup()?;
                self.create_default_settings_file()?;
            }
            _ => return Err(Error::Config("unexpected option".into())),
        }
        Ok(())
    }

    /// Create config folder (and parent directories) if not exists.
    fn ensure_config_dir(&self) -> Result<()> {
        if let Err(err) = fs::create_dir_all(&self.root_folder) {
            if err.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(Error::Config(format!("could not create folder: {err}")));
            }
            debug!("configuration folder found: {}", self.root_folder.display());
        } else {
            debug!(
                "configuration created in path: {}",
                self.root_folder.display()
            );
        }
        Ok(())
    }

    /// Create config file from default template.
    fn create_default_settings_file(&self) -> Result<()> {
        self.save_settings_file_from_struct(&Settings::default())
    }

    /// Convert the given config to YAML format and save to file.
    ///
    /// # Arguments
    ///
    /// * `settings` - Config struct
    ///
    /// # Errors
    ///
    /// Will return `Err` if the config directory cannot be created or the file
    /// cannot be written.
    pub fn save_settings_file_from_struct(&self, settings: &Settings) -> Result<()> {
        self.ensure_config_dir()?;
        let content = serde_yaml::to_string(settings)?;
        let mut file = fs::File::create(&self.setting_file_path)?;
        file.write_all(content.as_bytes())?;
        debug!(
            "settings file crated in path: {}. config data: {:?}",
            self.setting_file_path.display(),
            settings
        );
        Ok(())
    }

    /// Return config content.
    ///
    /// # Errors
    ///
    /// Will return `Err` if the config file cannot be opened or read.
    pub fn read_config_file(&self) -> Result<String> {
        let mut file = std::fs::File::open(&self.setting_file_path)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        Ok(content)
    }

    /// Load settings as a raw [`serde_yaml::Value`] tree.
    ///
    /// # Errors
    ///
    /// Will return `Err` if the config file cannot be read or parsed.
    pub fn read_config_as_value(&self) -> Result<serde_yaml::Value> {
        match self.read_config_file() {
            Ok(content) => Ok(serde_yaml::from_str(&content)?),
            Err(_) if !self.setting_file_path.exists() => {
                Ok(serde_yaml::Value::Mapping(serde_yaml::Mapping::default()))
            }
            Err(e) => Err(e),
        }
    }

    /// Validate a [`serde_yaml::Value`] tree by round-tripping through
    /// [`Settings`] deserialization, then save the YAML to disk.
    ///
    /// # Errors
    ///
    /// Will return `Err` if validation fails or the file cannot be written.
    pub fn save_config_from_value(&self, value: &serde_yaml::Value) -> Result<()> {
        self.ensure_config_dir()?;
        let yaml_str = serde_yaml::to_string(value)?;
        // Validate: round-trip through Settings deserialization
        let _settings: Settings = serde_yaml::from_str(&yaml_str)?;
        let mut file = fs::File::create(&self.setting_file_path)?;
        file.write_all(yaml_str.as_bytes())?;
        Ok(())
    }

    fn backup(&self) -> Result<PathBuf> {
        let backup_to = PathBuf::from(format!(
            "{}.{}.bak",
            self.setting_file_path.display(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
        ));
        fs::rename(&self.setting_file_path, &backup_to)?;
        Ok(backup_to)
    }
}

impl Settings {
    /// Return list of active patterns by user groups
    ///
    /// # Errors
    ///
    /// Will return `Err` when could not load config file
    pub fn get_active_checks(&self) -> Result<Vec<checks::Check>> {
        let enabled: HashSet<&str> = self.enabled_groups.iter().map(String::as_str).collect();
        let disabled: HashSet<&str> = self.disabled_groups.iter().map(String::as_str).collect();
        let ignores: HashSet<&str> = self
            .ignores_patterns_ids
            .iter()
            .map(String::as_str)
            .collect();
        // Filter from the static cache directly — only clone checks that pass
        // all filters, instead of cloning all ~100 checks then discarding.
        Ok(checks::all_checks_cached()
            .iter()
            .filter(|c| enabled.contains(c.from.as_str()))
            .filter(|c| !disabled.contains(c.from.as_str()))
            .filter(|c| !ignores.contains(c.id.as_str()))
            .cloned()
            .collect())
    }

    #[must_use]
    pub const fn get_active_groups(&self) -> &Vec<String> {
        &self.enabled_groups
    }
}

/// Set a value at a dot-notation path, creating intermediate mappings as
/// needed.
///
/// # Errors
///
/// Will return `Err` if an intermediate value exists but is not a mapping.
pub fn value_set(
    root: &mut serde_yaml::Value,
    path: &str,
    new_value: serde_yaml::Value,
) -> Result<()> {
    let segments: Vec<&str> = path.split('.').collect();
    let mut current = root;

    for (i, segment) in segments.iter().enumerate() {
        if i == segments.len() - 1 {
            // Final segment — set the value
            let map = current.as_mapping_mut().ok_or_else(|| {
                Error::Config(format!("expected a mapping at parent of '{path}'"))
            })?;
            map.insert(serde_yaml::Value::String((*segment).to_string()), new_value);
            return Ok(());
        }
        // Intermediate segment — descend or create
        let key = serde_yaml::Value::String((*segment).to_string());
        if !current.as_mapping().is_some_and(|m| m.contains_key(&key)) {
            let map = current
                .as_mapping_mut()
                .ok_or_else(|| Error::Config(format!("expected a mapping at '{segment}'")))?;
            map.insert(
                key.clone(),
                serde_yaml::Value::Mapping(serde_yaml::Mapping::default()),
            );
        }
        current = current
            .get_mut(segment)
            .ok_or_else(|| Error::Config(format!("failed to descend into '{segment}'")))?;
    }
    Ok(())
}

#[cfg(test)]
mod test_config {
    use std::fs::read_dir;

    use tree_fs::Tree;

    use super::*;

    fn initialize_config_folder(temp_dir: &Tree) -> Config {
        let temp_dir = temp_dir.root.join("app");
        Config::new(Some(&temp_dir.display().to_string())).unwrap()
    }

    fn initialize_config_folder_with_file(temp_dir: &Tree) -> Config {
        let config = initialize_config_folder(temp_dir);
        config.reset_config(Some(0)).unwrap();
        config
    }

    #[test]
    fn new_config_does_not_create_files() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        assert!(!config.root_folder.is_dir());
        assert!(!config.setting_file_path.is_file());
    }

    #[test]
    fn get_settings_returns_defaults_without_file() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        let settings = config.get_settings_from_file().unwrap();
        assert_eq!(settings.challenge, DEFAULT_CHALLENGE);
        assert_eq!(settings.enabled_groups, default_enabled_groups());
        assert!(settings.audit_enabled);
    }

    #[test]
    fn can_reset_config_with_override() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder_with_file(&temp_dir);
        let mut settings = config.get_settings_from_file().unwrap();
        settings.challenge = Challenge::Yes;
        config.save_settings_file_from_struct(&settings).unwrap();
        assert_eq!(
            config.get_settings_from_file().unwrap().challenge,
            Challenge::Yes
        );
        config.reset_config(Some(0)).unwrap();
        assert_eq!(
            config.get_settings_from_file().unwrap().challenge,
            Challenge::Math
        );
        assert_eq!(read_dir(&config.root_folder).unwrap().count(), 1);
    }

    #[test]
    fn can_reset_config_with_with_backup() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder_with_file(&temp_dir);
        let mut settings = config.get_settings_from_file().unwrap();
        settings.challenge = Challenge::Yes;
        config.save_settings_file_from_struct(&settings).unwrap();
        assert_eq!(
            config.get_settings_from_file().unwrap().challenge,
            Challenge::Yes
        );
        config.reset_config(Some(1)).unwrap();
        assert_eq!(
            config.get_settings_from_file().unwrap().challenge,
            Challenge::Math
        );
        assert_eq!(read_dir(&config.root_folder).unwrap().count(), 2);
    }

    #[test]
    fn sparse_config_on_fresh_install() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder(&temp_dir);
        // initialize_config_folder does not create any files — fresh install
        assert!(!config.setting_file_path.exists());
        // read_config_as_value should return empty mapping
        let root = config.read_config_as_value().unwrap();
        assert!(root.as_mapping().unwrap().is_empty());
        // Setting a value and saving should produce a sparse file
        let mut root = root;
        value_set(
            &mut root,
            "challenge",
            serde_yaml::Value::String("Yes".into()),
        )
        .unwrap();
        config.save_config_from_value(&root).unwrap();
        let content = config.read_config_file().unwrap();
        assert!(content.contains("challenge"));
        assert!(!content.contains("enabled_groups"));
        // Settings should still load with defaults filled in
        let settings = config.get_settings_from_file().unwrap();
        assert_eq!(settings.challenge, Challenge::Yes);
        assert_eq!(settings.enabled_groups, default_enabled_groups());
    }
}

#[cfg(test)]
mod test_settings {
    use super::*;

    #[test]
    fn can_get_active_checks() {
        // Uses Settings::default() — no file needed
        assert!(Settings::default().get_active_checks().is_ok());
    }

    #[test]
    fn can_get_settings_from_file() {
        let groups = Settings::default().get_active_groups().clone();
        assert_eq!(
            groups,
            vec![
                "aws",
                "azure",
                "base",
                "database",
                "docker",
                "fs",
                "gcp",
                "git",
                "heroku",
                "kubernetes",
                "mongodb",
                "mysql",
                "network",
                "psql",
                "redis",
                "terraform",
            ]
        );
    }

    #[test]
    fn settings_yaml_roundtrip_preserves_enabled_groups() {
        let original = Settings::default();
        let yaml = serde_yaml::to_string(&original).unwrap();
        let restored: Settings = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(restored.enabled_groups, original.enabled_groups);
        assert!(
            !restored.enabled_groups.is_empty(),
            "enabled_groups must not be empty after roundtrip"
        );
    }

    #[test]
    fn default_settings_produce_nonempty_active_checks() {
        let checks = Settings::default().get_active_checks().unwrap();
        assert!(
            !checks.is_empty(),
            "Settings::default() must produce active checks"
        );
        let groups: std::collections::HashSet<&str> =
            checks.iter().map(|c| c.from.as_str()).collect();
        assert!(groups.contains("fs"), "fs group must be active");
        assert!(groups.contains("git"), "git group must be active");
    }

    #[test]
    fn settings_file_roundtrip_produces_matches() {
        let temp = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = Config::new(Some(&temp.root.join("app").display().to_string())).unwrap();
        config.reset_config(Some(0)).unwrap();
        let settings = config.get_settings_from_file().unwrap();
        let checks = settings.get_active_checks().unwrap();
        assert!(
            !checks.is_empty(),
            "Active checks must not be empty after file roundtrip"
        );
        let matches = crate::checks::run_check_on_command(&checks, "git push --force origin main");
        assert!(
            !matches.is_empty(),
            "git push --force must match after file roundtrip"
        );
    }

    #[test]
    fn old_includes_field_falls_back_to_default_enabled_groups() {
        let old_yaml = "challenge: Math\nincludes:\n  - base\n  - fs\n  - git\n";
        let settings: Settings = serde_yaml::from_str(old_yaml).unwrap();
        // Old `includes` is unknown → ignored; enabled_groups gets serde default
        assert_eq!(settings.enabled_groups, default_enabled_groups());
        let checks = settings.get_active_checks().unwrap();
        assert!(!checks.is_empty());
    }
}
