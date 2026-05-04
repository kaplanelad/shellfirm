//! Manage the app configuration by creating, deleting and modify the
//! configuration

use std::{
    collections::{HashMap, HashSet},
    env, fmt, fs,
    io::{Read, Write},
    path::PathBuf,
};

use crate::error::{Error, Result};
use crate::{checks, checks::Severity, context::ContextConfig};
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

/// Runtime context that a settings value applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Interactive shell hook (`shellfirm pre-command`).
    Shell,
    /// AI agent integrations (Claude Code hook, MCP server).
    Ai,
    /// PTY proxy (`shellfirm wrap`).
    Wrap,
}

/// Per-mode override sentinel. `Inherit` means "use the global value";
/// `Set(value)` means "override with this value."
///
/// Serializes:
/// - `Inherit` → the YAML string literal `inherit`
/// - `Set(v)` → `v`'s normal serialization (including `null` if `T` is an `Option`)
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum InheritOr<T> {
    #[default]
    Inherit,
    Set(T),
}

impl<T> InheritOr<T> {
    /// Resolve to `Some(value)` if explicitly set, else `None` (inherit).
    pub const fn as_set(&self) -> Option<&T> {
        match self {
            Self::Inherit => None,
            Self::Set(v) => Some(v),
        }
    }
}

impl<T: serde::Serialize> serde::Serialize for InheritOr<T> {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Inherit => ser.serialize_str("inherit"),
            Self::Set(v) => v.serialize(ser),
        }
    }
}

impl<'de, T: serde::Deserialize<'de>> serde::Deserialize<'de> for InheritOr<T> {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> std::result::Result<Self, D::Error> {
        let v = serde_yaml::Value::deserialize(de)?;
        if let serde_yaml::Value::String(s) = &v {
            if s == "inherit" {
                return Ok(Self::Inherit);
            }
        }
        let inner = T::deserialize(v).map_err(serde::de::Error::custom)?;
        Ok(Self::Set(inner))
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
    /// Override for the global `challenge` when running in agent mode.
    #[serde(default)]
    pub challenge: InheritOr<Challenge>,
    /// Override for the global `min_severity` when running in agent mode.
    #[serde(default)]
    pub min_severity: InheritOr<Option<Severity>>,
    /// Override for the global `severity_escalation` when running in agent mode.
    #[serde(default)]
    pub severity_escalation: InheritOr<SeverityEscalationConfig>,
}

const fn default_auto_deny_severity() -> Severity {
    Severity::High
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            auto_deny_severity: default_auto_deny_severity(),
            require_human_approval: false,
            challenge: InheritOr::Inherit,
            min_severity: InheritOr::Inherit,
            severity_escalation: InheritOr::Inherit,
        }
    }
}

/// Configuration for the `shellfirm wrap` PTY proxy.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct WrappersConfig {
    /// Per-tool overrides keyed by program name (e.g. "psql", "redis-cli").
    #[serde(default)]
    pub tools: HashMap<String, WrapperToolConfig>,
    /// Override for the global `challenge` when running in wrap mode.
    #[serde(default)]
    pub challenge: InheritOr<Challenge>,
    /// Override for the global `min_severity` when running in wrap mode.
    #[serde(default)]
    pub min_severity: InheritOr<Option<Severity>>,
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

/// Configuration for severity-based challenge escalation.
///
/// When enabled (the default), checks at higher severity levels automatically
/// receive harder challenges — `Critical` → `Yes`, `High` → `Enter`.
/// Each mapping acts as a floor: `max_challenge(base, severity_floor)`.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct SeverityEscalationConfig {
    /// Whether severity-based escalation is active.
    #[serde(default = "default_severity_escalation_enabled")]
    pub enabled: bool,
    /// Minimum challenge for Critical severity checks.
    #[serde(default = "default_severity_critical")]
    pub critical: Challenge,
    /// Minimum challenge for High severity checks.
    #[serde(default = "default_severity_high")]
    pub high: Challenge,
    /// Minimum challenge for Medium severity checks.
    #[serde(default = "default_severity_medium")]
    pub medium: Challenge,
    /// Minimum challenge for Low severity checks.
    #[serde(default = "default_severity_low")]
    pub low: Challenge,
    /// Minimum challenge for Info severity checks.
    #[serde(default = "default_severity_info")]
    pub info: Challenge,
}

const fn default_severity_escalation_enabled() -> bool {
    true
}
const fn default_severity_critical() -> Challenge {
    Challenge::Yes
}
const fn default_severity_high() -> Challenge {
    Challenge::Enter
}
const fn default_severity_medium() -> Challenge {
    Challenge::Math
}
const fn default_severity_low() -> Challenge {
    Challenge::Math
}
const fn default_severity_info() -> Challenge {
    Challenge::Math
}

impl Default for SeverityEscalationConfig {
    fn default() -> Self {
        Self {
            enabled: default_severity_escalation_enabled(),
            critical: default_severity_critical(),
            high: default_severity_high(),
            medium: default_severity_medium(),
            low: default_severity_low(),
            info: default_severity_info(),
        }
    }
}

impl SeverityEscalationConfig {
    /// Return the challenge floor for the given severity, or `None` if
    /// severity escalation is disabled.
    #[must_use]
    pub const fn challenge_for_severity(&self, severity: Severity) -> Option<Challenge> {
        if !self.enabled {
            return None;
        }
        Some(match severity {
            Severity::Critical => self.critical,
            Severity::High => self.high,
            Severity::Medium => self.medium,
            Severity::Low => self.low,
            Severity::Info => self.info,
        })
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

pub const DEFAULT_ENABLED_GROUPS: [&str; 21] = [
    "aws",
    "azure",
    "base",
    "database",
    "docker",
    "flyio",
    "fs",
    "gcp",
    "git",
    "github",
    "heroku",
    "kubernetes",
    "mongodb",
    "mysql",
    "netlify",
    "network",
    "npm",
    "psql",
    "redis",
    "terraform",
    "vercel",
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
    /// Severity-based challenge escalation (enabled by default).
    #[serde(default)]
    pub severity_escalation: SeverityEscalationConfig,
    /// Per-group minimum challenge overrides (group name → challenge).
    #[serde(default)]
    pub group_escalation: HashMap<String, Challenge>,
    /// Per-check-ID minimum challenge overrides (check ID → challenge).
    #[serde(default)]
    pub check_escalation: HashMap<String, Challenge>,
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
            severity_escalation: SeverityEscalationConfig::default(),
            group_escalation: HashMap::new(),
            check_escalation: HashMap::new(),
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
    /// Will return `Err` if the config directory cannot be created or the file
    /// cannot be written.
    pub fn reset_config(&self) -> Result<()> {
        self.ensure_config_dir()?;
        // Write an empty file — serde defaults fill in all fields at load time.
        // The interactive setup will add only the keys the user picks.
        fs::File::create(&self.setting_file_path)?;
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
        let empty_mapping = || serde_yaml::Value::Mapping(serde_yaml::Mapping::default());
        match self.read_config_file() {
            Ok(content) => {
                let value: serde_yaml::Value = serde_yaml::from_str(&content)?;
                // serde_yaml::from_str("") returns Null — treat as empty mapping
                if value.is_null() {
                    Ok(empty_mapping())
                } else {
                    Ok(value)
                }
            }
            Err(_) if !self.setting_file_path.exists() => Ok(empty_mapping()),
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

    /// Like `get_active_checks` but also includes (and filters) custom checks.
    ///
    /// Custom checks are subject to the same `enabled_groups`, `disabled_groups`,
    /// and `ignores_patterns_ids` filters as built-ins.
    ///
    /// # Errors
    /// Propagates any error from check loading or compilation.
    pub fn get_active_checks_with_custom(
        &self,
        custom: &[checks::Check],
    ) -> Result<Vec<checks::Check>> {
        let enabled: HashSet<&str> = self.enabled_groups.iter().map(String::as_str).collect();
        let disabled: HashSet<&str> = self.disabled_groups.iter().map(String::as_str).collect();
        let ignores: HashSet<&str> = self
            .ignores_patterns_ids
            .iter()
            .map(String::as_str)
            .collect();

        let keep = |c: &checks::Check| -> bool {
            enabled.contains(c.from.as_str())
                && !disabled.contains(c.from.as_str())
                && !ignores.contains(c.id.as_str())
        };

        let mut out: Vec<checks::Check> = checks::all_checks_cached()
            .iter()
            .filter(|c| keep(c))
            .cloned()
            .collect();
        out.extend(custom.iter().filter(|c| keep(c)).cloned());
        Ok(out)
    }

    /// One-shot migration to keep custom-check behavior consistent after the
    /// load-order fix. For every custom check whose `from` group is neither in
    /// `enabled_groups` nor in `disabled_groups`, add it to `enabled_groups`.
    ///
    /// Returns the list of newly-added group names (caller logs).
    pub fn migrate_custom_groups_into_enabled_groups(
        &mut self,
        custom: &[checks::Check],
    ) -> Vec<String> {
        use std::collections::BTreeSet;
        let enabled: HashSet<&str> = self.enabled_groups.iter().map(String::as_str).collect();
        let disabled: HashSet<&str> = self.disabled_groups.iter().map(String::as_str).collect();
        let mut to_add: BTreeSet<String> = BTreeSet::new();
        for c in custom {
            if !enabled.contains(c.from.as_str()) && !disabled.contains(c.from.as_str()) {
                to_add.insert(c.from.clone());
            }
        }
        let added: Vec<String> = to_add.into_iter().collect();
        self.enabled_groups.extend(added.iter().cloned());
        added
    }

    #[must_use]
    pub const fn get_active_groups(&self) -> &Vec<String> {
        &self.enabled_groups
    }
}

/// Read-only view of settings with per-mode overrides resolved.
#[derive(Debug, Clone)]
pub struct ResolvedSettings {
    pub challenge: Challenge,
    pub min_severity: Option<Severity>,
    pub severity_escalation: SeverityEscalationConfig,
}

impl Settings {
    /// Resolve the settings for a given mode by applying any per-mode overrides
    /// on top of the global values.
    #[must_use]
    pub fn resolved_for(&self, mode: Mode) -> ResolvedSettings {
        let (challenge_o, min_sev_o, esc_o) = match mode {
            Mode::Shell => (None, None, None),
            Mode::Ai => (
                self.agent.challenge.as_set().copied(),
                self.agent.min_severity.as_set().copied(),
                self.agent.severity_escalation.as_set().cloned(),
            ),
            Mode::Wrap => (
                self.wrappers.challenge.as_set().copied(),
                self.wrappers.min_severity.as_set().copied(),
                None,
            ),
        };

        ResolvedSettings {
            challenge: challenge_o.unwrap_or(self.challenge),
            min_severity: min_sev_o.unwrap_or(self.min_severity),
            severity_escalation: esc_o.unwrap_or_else(|| self.severity_escalation.clone()),
        }
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
        config.reset_config().unwrap();
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
    fn can_reset_config() {
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
        config.reset_config().unwrap();
        assert_eq!(
            config.get_settings_from_file().unwrap().challenge,
            Challenge::Math
        );
        assert_eq!(read_dir(&config.root_folder).unwrap().count(), 1);
    }

    #[test]
    fn read_config_as_value_empty_file_returns_empty_mapping() {
        let temp_dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = initialize_config_folder_with_file(&temp_dir);
        // reset_config writes an empty file — read_config_as_value must return
        // an empty Mapping (not Null) so that value_set can work on it.
        let root = config.read_config_as_value().unwrap();
        let mapping = root
            .as_mapping()
            .expect("should be a Mapping, not Null");
        assert!(mapping.is_empty());
        // Verify value_set succeeds on the result
        let mut root = root;
        value_set(
            &mut root,
            "challenge",
            serde_yaml::Value::String("Enter".into()),
        )
        .unwrap();
        assert_eq!(
            root.get("challenge").unwrap().as_str().unwrap(),
            "Enter"
        );
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

    // -------------------------------------------------------------------
    // Phase 0: Mode enum, InheritOr<T>, per-mode overrides, ResolvedSettings
    // -------------------------------------------------------------------

    #[test]
    fn mode_enum_variants_exist() {
        let _ = Mode::Shell;
        let _ = Mode::Ai;
        let _ = Mode::Wrap;
    }

    #[test]
    fn mode_is_copy_and_eq() {
        let m1 = Mode::Shell;
        let m2 = m1;
        assert_eq!(m1, m2);
        assert_ne!(Mode::Shell, Mode::Ai);
    }

    #[test]
    fn inherit_or_deserializes_inherit_keyword() {
        let v: InheritOr<String> = serde_yaml::from_str("inherit").unwrap();
        assert!(matches!(v, InheritOr::Inherit));
    }

    #[test]
    fn inherit_or_deserializes_set_value() {
        let v: InheritOr<String> = serde_yaml::from_str("\"hello\"").unwrap();
        assert!(matches!(v, InheritOr::Set(s) if s == "hello"));
    }

    #[test]
    fn inherit_or_serializes_inherit_as_keyword() {
        let v: InheritOr<String> = InheritOr::Inherit;
        let s = serde_yaml::to_string(&v).unwrap();
        assert_eq!(s.trim(), "inherit");
    }

    #[test]
    fn inherit_or_serializes_set_value() {
        let v: InheritOr<String> = InheritOr::Set("hi".into());
        let s = serde_yaml::to_string(&v).unwrap();
        assert_eq!(s.trim(), "hi");
    }

    #[test]
    fn inherit_or_default_is_inherit() {
        let v: InheritOr<u32> = InheritOr::default();
        assert!(matches!(v, InheritOr::Inherit));
    }

    #[test]
    fn inherit_or_with_option_inner_handles_null() {
        let v: InheritOr<Option<Severity>> = serde_yaml::from_str("null").unwrap();
        assert!(matches!(v, InheritOr::Set(None)));
    }

    #[test]
    fn inherit_or_with_option_inner_handles_inherit() {
        let v: InheritOr<Option<Severity>> = serde_yaml::from_str("inherit").unwrap();
        assert!(matches!(v, InheritOr::Inherit));
    }

    #[test]
    fn agent_config_default_has_inherit_overrides() {
        let a = AgentConfig::default();
        assert!(matches!(a.challenge, InheritOr::Inherit));
        assert!(matches!(a.min_severity, InheritOr::Inherit));
        assert!(matches!(a.severity_escalation, InheritOr::Inherit));
    }

    #[test]
    fn agent_config_loads_old_yaml_with_no_overrides() {
        let yaml = "auto_deny_severity: High\nrequire_human_approval: false\n";
        let a: AgentConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(matches!(a.challenge, InheritOr::Inherit));
        assert!(matches!(a.min_severity, InheritOr::Inherit));
    }

    #[test]
    fn agent_config_loads_explicit_overrides() {
        let yaml = "auto_deny_severity: High\n\
                    require_human_approval: false\n\
                    challenge: Yes\n\
                    min_severity: Low\n";
        let a: AgentConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(matches!(a.challenge, InheritOr::Set(Challenge::Yes)));
        assert!(matches!(a.min_severity, InheritOr::Set(Some(Severity::Low))));
    }

    #[test]
    fn wrappers_config_default_has_inherit_overrides() {
        let w = WrappersConfig::default();
        assert!(matches!(w.challenge, InheritOr::Inherit));
        assert!(matches!(w.min_severity, InheritOr::Inherit));
    }

    #[test]
    fn wrappers_config_loads_old_yaml() {
        let yaml = "tools: {}\n";
        let w: WrappersConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(matches!(w.challenge, InheritOr::Inherit));
        assert!(matches!(w.min_severity, InheritOr::Inherit));
    }

    #[test]
    fn wrappers_config_loads_explicit_overrides() {
        let yaml = "tools: {}\nchallenge: Yes\nmin_severity: High\n";
        let w: WrappersConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(matches!(w.challenge, InheritOr::Set(Challenge::Yes)));
        assert!(matches!(w.min_severity, InheritOr::Set(Some(Severity::High))));
    }

    #[test]
    fn resolved_for_shell_returns_global() {
        let mut s = Settings::default();
        s.challenge = Challenge::Math;
        s.min_severity = Some(Severity::Medium);
        let r = s.resolved_for(Mode::Shell);
        assert_eq!(r.challenge, Challenge::Math);
        assert_eq!(r.min_severity, Some(Severity::Medium));
    }

    #[test]
    fn resolved_for_ai_inherits_when_no_overrides() {
        let mut s = Settings::default();
        s.challenge = Challenge::Math;
        s.min_severity = Some(Severity::Medium);
        let r = s.resolved_for(Mode::Ai);
        assert_eq!(r.challenge, Challenge::Math);
        assert_eq!(r.min_severity, Some(Severity::Medium));
    }

    #[test]
    fn resolved_for_ai_uses_overrides_when_set() {
        let mut s = Settings::default();
        s.challenge = Challenge::Math;
        s.min_severity = Some(Severity::Medium);
        s.agent.challenge = InheritOr::Set(Challenge::Yes);
        s.agent.min_severity = InheritOr::Set(Some(Severity::Low));
        let r = s.resolved_for(Mode::Ai);
        assert_eq!(r.challenge, Challenge::Yes);
        assert_eq!(r.min_severity, Some(Severity::Low));
    }

    #[test]
    fn resolved_for_wrap_uses_wrappers_overrides() {
        let mut s = Settings::default();
        s.challenge = Challenge::Math;
        s.wrappers.challenge = InheritOr::Set(Challenge::Yes);
        let r = s.resolved_for(Mode::Wrap);
        assert_eq!(r.challenge, Challenge::Yes);
    }

    #[test]
    fn resolved_for_severity_escalation_override_ai() {
        let mut s = Settings::default();
        let mut custom = SeverityEscalationConfig::default();
        custom.high = Challenge::Yes;
        s.agent.severity_escalation = InheritOr::Set(custom.clone());
        let r = s.resolved_for(Mode::Ai);
        assert_eq!(r.severity_escalation.high, Challenge::Yes);
        let r_shell = s.resolved_for(Mode::Shell);
        assert_eq!(r_shell.severity_escalation.high, Challenge::Enter); // default
    }

    // -------------------------------------------------------------------
    // Phase 1: get_active_checks_with_custom + migrate_custom_groups
    // -------------------------------------------------------------------

    #[test]
    fn get_active_checks_with_custom_excludes_disabled_custom_group() {
        use crate::checks::Check;
        use regex::Regex;

        let mut s = Settings::default();
        s.enabled_groups = vec!["git".into()];  // explicitly NOT including "my_team"
        let custom = vec![Check {
            id: "my_team:thing".into(),
            test: Regex::new("foo").unwrap(),
            description: "x".into(),
            from: "my_team".into(),
            challenge: Challenge::Math,
            filters: vec![],
            alternative: None,
            alternative_info: None,
            severity: Severity::Medium,
        }];
        let result = s.get_active_checks_with_custom(&custom).unwrap();
        assert!(result.iter().all(|c| c.id != "my_team:thing"));
    }

    #[test]
    fn get_active_checks_with_custom_includes_enabled_custom_group() {
        use crate::checks::Check;
        use regex::Regex;
        let mut s = Settings::default();
        s.enabled_groups = vec!["git".into(), "my_team".into()];
        let custom = vec![Check {
            id: "my_team:thing".into(),
            test: Regex::new("foo").unwrap(),
            description: "x".into(),
            from: "my_team".into(),
            challenge: Challenge::Math,
            filters: vec![],
            alternative: None,
            alternative_info: None,
            severity: Severity::Medium,
        }];
        let result = s.get_active_checks_with_custom(&custom).unwrap();
        assert!(result.iter().any(|c| c.id == "my_team:thing"));
    }

    #[test]
    fn get_active_checks_with_custom_respects_ignores() {
        use crate::checks::Check;
        use regex::Regex;
        let mut s = Settings::default();
        s.enabled_groups = vec!["my_team".into()];
        s.ignores_patterns_ids = vec!["my_team:thing".into()];
        let custom = vec![Check {
            id: "my_team:thing".into(),
            test: Regex::new("foo").unwrap(),
            description: "x".into(),
            from: "my_team".into(),
            challenge: Challenge::Math,
            filters: vec![],
            alternative: None,
            alternative_info: None,
            severity: Severity::Medium,
        }];
        let result = s.get_active_checks_with_custom(&custom).unwrap();
        assert!(result.iter().all(|c| c.id != "my_team:thing"));
    }

    #[test]
    fn migrate_custom_groups_into_enabled_groups_adds_missing() {
        use crate::checks::Check;
        use regex::Regex;
        let mut s = Settings::default();
        s.enabled_groups = vec!["git".into()];
        let custom = vec![Check {
            id: "my_team:foo".into(),
            test: Regex::new("x").unwrap(),
            description: "x".into(),
            from: "my_team".into(),
            challenge: Challenge::Math,
            filters: vec![],
            alternative: None,
            alternative_info: None,
            severity: Severity::Medium,
        }];
        let added = s.migrate_custom_groups_into_enabled_groups(&custom);
        assert_eq!(added, vec!["my_team".to_string()]);
        assert!(s.enabled_groups.contains(&"my_team".to_string()));
    }

    #[test]
    fn migrate_custom_groups_idempotent() {
        use crate::checks::Check;
        use regex::Regex;
        let mut s = Settings::default();
        s.enabled_groups = vec!["git".into(), "my_team".into()];
        let custom = vec![Check {
            id: "my_team:foo".into(),
            test: Regex::new("x").unwrap(),
            description: "x".into(),
            from: "my_team".into(),
            challenge: Challenge::Math,
            filters: vec![],
            alternative: None,
            alternative_info: None,
            severity: Severity::Medium,
        }];
        let added = s.migrate_custom_groups_into_enabled_groups(&custom);
        assert!(added.is_empty());
    }

    #[test]
    fn migrate_custom_groups_skips_disabled_groups() {
        use crate::checks::Check;
        use regex::Regex;
        let mut s = Settings::default();
        s.disabled_groups = vec!["my_team".into()];
        let custom = vec![Check {
            id: "my_team:foo".into(),
            test: Regex::new("x").unwrap(),
            description: "x".into(),
            from: "my_team".into(),
            challenge: Challenge::Math,
            filters: vec![],
            alternative: None,
            alternative_info: None,
            severity: Severity::Medium,
        }];
        let added = s.migrate_custom_groups_into_enabled_groups(&custom);
        assert!(added.is_empty());  // user explicitly disabled — leave alone
        assert!(!s.enabled_groups.contains(&"my_team".to_string()));
    }

    #[test]
    fn old_settings_yaml_round_trips_with_inherit_defaults() {
        let yaml = "challenge: Yes\n\
                    enabled_groups: [git, fs]\n\
                    disabled_groups: []\n\
                    ignores_patterns_ids: []\n\
                    deny_patterns_ids: []\n\
                    audit_enabled: true\n\
                    blast_radius: true\n\
                    min_severity: Medium\n\
                    agent:\n  auto_deny_severity: High\n  require_human_approval: false\n\
                    wrappers:\n  tools: {}\n";
        let s: Settings = serde_yaml::from_str(yaml).unwrap();
        assert!(matches!(s.agent.challenge, InheritOr::Inherit));
        assert!(matches!(s.wrappers.min_severity, InheritOr::Inherit));
        let out = serde_yaml::to_string(&s).unwrap();
        let s2: Settings = serde_yaml::from_str(&out).unwrap();
        assert_eq!(format!("{:?}", s), format!("{:?}", s2));
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
                "flyio",
                "fs",
                "gcp",
                "git",
                "github",
                "heroku",
                "kubernetes",
                "mongodb",
                "mysql",
                "netlify",
                "network",
                "npm",
                "psql",
                "redis",
                "terraform",
                "vercel",
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
        config.reset_config().unwrap();
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
