//! Manage the app configuration by creating, deleting and modify the
//! configuration

use std::{
    collections::HashSet,
    env, fmt, fs,
    io::{Read, Write},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{checks, checks::Severity, context::ContextConfig, dialog};
use anyhow::{bail, Result as AnyResult};
use log::debug;
use serde_derive::{Deserialize, Serialize};

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

pub const DEFAULT_ENABLED_GROUPS: [&str; 12] = [
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
    "network",
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
    #[serde(default)]
    pub llm: LlmConfig,
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
    pub fn from_string(str: &str) -> AnyResult<Self> {
        match str.to_lowercase().as_str() {
            "math" => Ok(Self::Math),
            "enter" => Ok(Self::Enter),
            "yes" => Ok(Self::Yes),
            _ => bail!("given challenge name not found"),
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
            llm: LlmConfig::default(),
        }
    }
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
            None => match dirs::config_dir() {
                Some(conf_dir) => conf_dir.join(package_name),
                None => bail!("could not get directory path"),
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
    pub fn get_settings_from_file(&self) -> AnyResult<Settings> {
        match self.read_config_file() {
            Ok(content) => Ok(serde_yaml::from_str(&content)?),
            Err(_) if !self.setting_file_path.exists() => Ok(Settings::default()),
            Err(e) => Err(e),
        }
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

    /// Create config folder (and parent directories) if not exists.
    fn ensure_config_dir(&self) -> AnyResult<()> {
        if let Err(err) = fs::create_dir_all(&self.root_folder) {
            if err.kind() != std::io::ErrorKind::AlreadyExists {
                bail!("could not create folder: {err}");
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
    fn create_default_settings_file(&self) -> AnyResult<()> {
        self.save_settings_file_from_struct(&Settings::default())
    }

    /// Convert the given config to YAML format and the file.
    ///
    /// # Arguments
    ///
    /// * `settings` - Config struct
    fn save_settings_file_from_struct(&self, settings: &Settings) -> AnyResult<()> {
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
    pub fn read_config_file(&self) -> AnyResult<String> {
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
    pub fn read_config_as_value(&self) -> AnyResult<serde_yaml::Value> {
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
    pub fn save_config_from_value(&self, value: &serde_yaml::Value) -> AnyResult<()> {
        self.ensure_config_dir()?;
        let yaml_str = serde_yaml::to_string(value)?;
        // Validate: round-trip through Settings deserialization
        let _settings: Settings = serde_yaml::from_str(&yaml_str)?;
        let mut file = fs::File::create(&self.setting_file_path)?;
        file.write_all(yaml_str.as_bytes())?;
        Ok(())
    }

    fn backup(&self) -> AnyResult<PathBuf> {
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
    pub fn get_active_checks(&self) -> AnyResult<Vec<checks::Check>> {
        let enabled: HashSet<&str> = self.enabled_groups.iter().map(String::as_str).collect();
        let disabled: HashSet<&str> = self.disabled_groups.iter().map(String::as_str).collect();
        let ignores: HashSet<&str> = self
            .ignores_patterns_ids
            .iter()
            .map(String::as_str)
            .collect();
        Ok(checks::get_all()?
            .into_iter()
            .filter(|c| enabled.contains(c.from.as_str()))
            .filter(|c| !disabled.contains(c.from.as_str()))
            .filter(|c| !ignores.contains(c.id.as_str()))
            .collect())
    }

    #[must_use]
    pub const fn get_active_groups(&self) -> &Vec<String> {
        &self.enabled_groups
    }
}

/// Navigate a [`serde_yaml::Value`] tree by dot-notation path.
///
/// Returns `None` if any segment is missing.
#[must_use]
pub fn value_get<'a>(root: &'a serde_yaml::Value, path: &str) -> Option<&'a serde_yaml::Value> {
    let mut current = root;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
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
) -> AnyResult<()> {
    let segments: Vec<&str> = path.split('.').collect();
    let mut current = root;

    for (i, segment) in segments.iter().enumerate() {
        if i == segments.len() - 1 {
            // Final segment — set the value
            let map = current
                .as_mapping_mut()
                .ok_or_else(|| anyhow::anyhow!("expected a mapping at parent of '{path}'"))?;
            map.insert(serde_yaml::Value::String((*segment).to_string()), new_value);
            return Ok(());
        }
        // Intermediate segment — descend or create
        let key = serde_yaml::Value::String((*segment).to_string());
        if !current.as_mapping().is_some_and(|m| m.contains_key(&key)) {
            let map = current
                .as_mapping_mut()
                .ok_or_else(|| anyhow::anyhow!("expected a mapping at '{segment}'"))?;
            map.insert(
                key.clone(),
                serde_yaml::Value::Mapping(serde_yaml::Mapping::default()),
            );
        }
        current = current
            .get_mut(segment)
            .ok_or_else(|| anyhow::anyhow!("failed to descend into '{segment}'"))?;
    }
    Ok(())
}

/// Recursively collect all `(key_path, display_value)` leaf pairs from a
/// [`serde_yaml::Value`] tree.
#[must_use]
pub fn value_list_paths(root: &serde_yaml::Value) -> Vec<(String, String)> {
    let mut result = Vec::new();
    collect_paths(root, &mut String::new(), &mut result);
    result
}

fn collect_paths(
    value: &serde_yaml::Value,
    prefix: &mut String,
    result: &mut Vec<(String, String)>,
) {
    if let Some(mapping) = value.as_mapping() {
        for (k, v) in mapping {
            let key_str = k
                .as_str()
                .map_or_else(|| format!("{k:?}"), ToString::to_string);
            let old_len = prefix.len();
            if !prefix.is_empty() {
                prefix.push('.');
            }
            prefix.push_str(&key_str);
            collect_paths(v, prefix, result);
            prefix.truncate(old_len);
        }
    } else {
        result.push((prefix.clone(), format_yaml_value(value)));
    }
}

/// Format a [`serde_yaml::Value`] for human-readable display.
#[must_use]
pub fn format_yaml_value(value: &serde_yaml::Value) -> String {
    match value {
        serde_yaml::Value::Null => "null".to_string(),
        serde_yaml::Value::Bool(b) => b.to_string(),
        serde_yaml::Value::Number(n) => n.to_string(),
        serde_yaml::Value::String(s) => s.clone(),
        serde_yaml::Value::Sequence(seq) => {
            let items: Vec<String> = seq.iter().map(format_yaml_value).collect();
            format!("[{}]", items.join(", "))
        }
        serde_yaml::Value::Mapping(_) => {
            serde_yaml::to_string(value).unwrap_or_else(|_| "<mapping>".to_string())
        }
        serde_yaml::Value::Tagged(tagged) => format_yaml_value(&tagged.value),
    }
}

/// Return all valid dot-notation key paths derived from `Settings::default()`.
///
/// # Panics
///
/// Panics if `Settings::default()` cannot be serialized to a YAML value,
/// which should never happen.
#[must_use]
pub fn valid_config_keys() -> Vec<String> {
    let default_value =
        serde_yaml::to_value(Settings::default()).expect("Settings::default() must serialize");
    let paths = value_list_paths(&default_value);
    let mut keys: Vec<String> = paths.into_iter().map(|(k, _)| k).collect();
    // Also include intermediate mapping paths (e.g. "context", "context.escalation")
    let mut intermediates = std::collections::BTreeSet::new();
    for key in &keys {
        let parts: Vec<&str> = key.split('.').collect();
        for i in 1..parts.len() {
            intermediates.insert(parts[..i].join("."));
        }
    }
    for intermediate in intermediates {
        if !keys.contains(&intermediate) {
            keys.push(intermediate);
        }
    }
    keys
}

/// Validate that a key is a known configuration path.
///
/// Returns `Ok(())` if valid, or `Err` with an error message including a
/// "did you mean?" suggestion when a close match is found.
///
/// # Errors
///
/// Returns `Err(String)` when the key is not a known configuration path.
pub fn validate_config_key(key: &str) -> Result<(), String> {
    let valid = valid_config_keys();
    if valid.iter().any(|k| k == key) {
        return Ok(());
    }

    // Find closest match via Levenshtein distance
    let threshold = (key.len() / 2).max(3);
    let mut best: Option<(&str, usize)> = None;
    for valid_key in &valid {
        let dist = strsim::levenshtein(key, valid_key);
        if dist <= threshold && best.is_none_or(|(_, d)| dist < d) {
            best = Some((valid_key, dist));
        }
    }

    let mut msg = format!("unknown configuration key: '{key}'");
    if let Some((suggestion, _)) = best {
        use std::fmt::Write;
        let _ = write!(msg, "\n\n  Did you mean '{suggestion}'?");
    }
    msg.push_str("\n\nRun 'shellfirm config set --list' to see all valid keys.");
    Err(msg)
}

/// Return known enum fields and their valid values.
///
/// This is used to show helpful hints when a user provides an invalid value.
#[must_use]
pub fn known_enum_values() -> Vec<(&'static str, &'static [&'static str])> {
    vec![
        ("challenge", &["Math", "Enter", "Yes"]),
        (
            "min_severity",
            &["null", "Info", "Low", "Medium", "High", "Critical"],
        ),
        ("context.escalation.elevated", &["Math", "Enter", "Yes"]),
        ("context.escalation.critical", &["Math", "Enter", "Yes"]),
        (
            "agent.auto_deny_severity",
            &["Info", "Low", "Medium", "High", "Critical"],
        ),
    ]
}

#[cfg(test)]
mod test_config {
    use std::fs::read_dir;

    use tempfile::TempDir;

    use super::*;

    fn initialize_config_folder(temp_dir: &TempDir) -> Config {
        let temp_dir = temp_dir.path().join("app");
        Config::new(Some(&temp_dir.display().to_string())).unwrap()
    }

    fn initialize_config_folder_with_file(temp_dir: &TempDir) -> Config {
        let config = initialize_config_folder(temp_dir);
        config.reset_config(Some(0)).unwrap();
        config
    }

    #[test]
    fn new_config_does_not_create_files() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = initialize_config_folder(&temp_dir);
        assert!(!config.root_folder.is_dir());
        assert!(!config.setting_file_path.is_file());
        temp_dir.close().unwrap();
    }

    #[test]
    fn get_settings_returns_defaults_without_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = initialize_config_folder(&temp_dir);
        let settings = config.get_settings_from_file().unwrap();
        assert_eq!(settings.challenge, DEFAULT_CHALLENGE);
        assert_eq!(settings.enabled_groups, default_enabled_groups());
        assert!(settings.audit_enabled);
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_reset_config_with_override() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = initialize_config_folder_with_file(&temp_dir);
        // Change challenge via generic value_set
        let mut root = config.read_config_as_value().unwrap();
        value_set(
            &mut root,
            "challenge",
            serde_yaml::Value::String("Yes".into()),
        )
        .unwrap();
        config.save_config_from_value(&root).unwrap();
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
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_reset_config_with_with_backup() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = initialize_config_folder_with_file(&temp_dir);
        // Change challenge via generic value_set
        let mut root = config.read_config_as_value().unwrap();
        value_set(
            &mut root,
            "challenge",
            serde_yaml::Value::String("Yes".into()),
        )
        .unwrap();
        config.save_config_from_value(&root).unwrap();
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
        temp_dir.close().unwrap();
    }

    #[test]
    fn value_get_simple_key() {
        let yaml: serde_yaml::Value =
            serde_yaml::from_str("challenge: Math\naudit_enabled: true").unwrap();
        assert_eq!(
            value_get(&yaml, "challenge").and_then(|v| v.as_str()),
            Some("Math")
        );
    }

    #[test]
    fn value_get_nested_key() {
        let yaml: serde_yaml::Value =
            serde_yaml::from_str("context:\n  escalation:\n    elevated: Enter").unwrap();
        assert_eq!(
            value_get(&yaml, "context.escalation.elevated").and_then(|v| v.as_str()),
            Some("Enter")
        );
    }

    #[test]
    fn value_get_missing_key() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("challenge: Math").unwrap();
        assert!(value_get(&yaml, "nonexistent").is_none());
        assert!(value_get(&yaml, "a.b.c").is_none());
    }

    #[test]
    fn value_set_simple() {
        let mut yaml: serde_yaml::Value = serde_yaml::from_str("challenge: Math").unwrap();
        value_set(
            &mut yaml,
            "challenge",
            serde_yaml::Value::String("Yes".into()),
        )
        .unwrap();
        assert_eq!(
            value_get(&yaml, "challenge").and_then(|v| v.as_str()),
            Some("Yes")
        );
    }

    #[test]
    fn value_set_nested() {
        let mut yaml: serde_yaml::Value =
            serde_yaml::from_str("context:\n  escalation:\n    elevated: Enter").unwrap();
        value_set(
            &mut yaml,
            "context.escalation.elevated",
            serde_yaml::Value::String("Yes".into()),
        )
        .unwrap();
        assert_eq!(
            value_get(&yaml, "context.escalation.elevated").and_then(|v| v.as_str()),
            Some("Yes")
        );
    }

    #[test]
    fn value_set_creates_intermediate() {
        let mut yaml: serde_yaml::Value = serde_yaml::from_str("challenge: Math").unwrap();
        value_set(
            &mut yaml,
            "new.nested.key",
            serde_yaml::Value::String("hello".into()),
        )
        .unwrap();
        assert_eq!(
            value_get(&yaml, "new.nested.key").and_then(|v| v.as_str()),
            Some("hello")
        );
    }

    #[test]
    fn value_list_paths_collects_all_leaves() {
        let yaml: serde_yaml::Value =
            serde_yaml::from_str("challenge: Math\ncontext:\n  escalation:\n    elevated: Enter")
                .unwrap();
        let paths = value_list_paths(&yaml);
        let keys: Vec<&str> = paths.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"challenge"));
        assert!(keys.contains(&"context.escalation.elevated"));
    }

    #[test]
    fn validate_config_key_accepts_known_keys() {
        assert!(validate_config_key("challenge").is_ok());
        assert!(validate_config_key("llm.model").is_ok());
        assert!(validate_config_key("context.escalation.elevated").is_ok());
        assert!(validate_config_key("agent.auto_deny_severity").is_ok());
        assert!(validate_config_key("audit_enabled").is_ok());
    }

    #[test]
    fn validate_config_key_accepts_intermediate_paths() {
        assert!(validate_config_key("context").is_ok());
        assert!(validate_config_key("context.escalation").is_ok());
        assert!(validate_config_key("llm").is_ok());
        assert!(validate_config_key("agent").is_ok());
    }

    #[test]
    fn validate_config_key_rejects_unknown_with_suggestion() {
        let err = validate_config_key("challange").unwrap_err();
        assert!(err.contains("unknown configuration key: 'challange'"));
        assert!(err.contains("Did you mean 'challenge'?"));
    }

    #[test]
    fn validate_config_key_rejects_completely_unknown() {
        let err = validate_config_key("zzz_nonexistent_zzz").unwrap_err();
        assert!(err.contains("unknown configuration key"));
        assert!(!err.contains("Did you mean"));
    }

    #[test]
    fn sparse_config_on_fresh_install() {
        let temp_dir = tempfile::tempdir().unwrap();
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
        temp_dir.close().unwrap();
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
                "network",
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
        let temp = tempfile::tempdir().unwrap();
        let config = Config::new(Some(&temp.path().join("app").display().to_string())).unwrap();
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
