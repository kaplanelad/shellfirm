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

/// LLM provider names understood by shellfirm.
pub const SUPPORTED_LLM_PROVIDERS: &[&str] = &["anthropic", "openai-compatible"];

impl LlmConfig {
    /// Validate the configuration values.
    ///
    /// # Errors
    /// Returns a message naming the invalid field and the accepted values.
    pub fn validate(&self) -> Result<()> {
        if !SUPPORTED_LLM_PROVIDERS.contains(&self.provider.as_str()) {
            return Err(Error::Config(format!(
                "invalid LLM provider: '{}'. Valid values: {}",
                self.provider,
                SUPPORTED_LLM_PROVIDERS.join(", ")
            )));
        }
        if self.model.trim().is_empty() {
            return Err(Error::Config("LLM model must not be empty".into()));
        }
        if self.timeout_ms == 0 {
            return Err(Error::Config(
                "LLM timeout must be greater than 0 milliseconds".into(),
            ));
        }
        if let Some(url) = &self.base_url {
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                return Err(Error::Config(format!(
                    "invalid LLM base URL: '{url}' (must start with http:// or https://)"
                )));
            }
        }
        Ok(())
    }
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
#[allow(clippy::struct_excessive_bools)]
pub struct AgentConfig {
    /// Auto-deny commands at or above this severity when running in agent mode.
    #[serde(default = "default_auto_deny_severity")]
    pub auto_deny_severity: Severity,
    /// Ask a human (instead of auto-denying) when a command reaches
    /// `auto_deny_severity`. Deny-listed commands are still denied.
    #[serde(default)]
    pub require_human_approval: bool,
    /// Escalate agent decisions when the runtime context is Critical because of
    /// root, a production k8s context or production env vars (not a protected
    /// branch alone): the matched severity is raised one level before the deny
    /// threshold applies.
    #[serde(default = "default_true")]
    pub context_escalation: bool,
    /// Emit an explicit `allow` hook decision for commands that match nothing.
    /// Off by default: an explicit allow bypasses the agent's own permission
    /// prompts (e.g. Claude Code's), so shellfirm stays silent instead.
    #[serde(default)]
    pub allow_safe: bool,
    /// Built-in self-protection: in agent mode, commands that would disable or
    /// weaken shellfirm (config changes, uninstall, audit clear, editing its
    /// settings/hook files) require human approval.
    #[serde(default = "default_true")]
    pub self_protection: bool,
    /// Ask the configured LLM (`llm:` section) for a second opinion on agent
    /// commands. Can only make a decision stricter. Off by default.
    #[serde(default)]
    pub llm_review: bool,
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

const fn default_true() -> bool {
    true
}

const fn default_auto_deny_severity() -> Severity {
    Severity::High
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            auto_deny_severity: default_auto_deny_severity(),
            require_human_approval: false,
            context_escalation: true,
            allow_safe: false,
            self_protection: true,
            llm_review: false,
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
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct WrapperToolConfig {
    /// Statement delimiter: ";" for SQL tools, "\n" for line-oriented tools.
    /// `None` = use the built-in default for the tool (or newline).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delimiter: Option<String>,
    /// Override which check groups are active (empty = use global setting).
    #[serde(default)]
    pub check_groups: Vec<String>,
}

/// Configuration for severity-based challenge escalation.
///
/// When enabled (the default), checks at higher severity levels automatically
/// receive harder challenges — `Critical` → `Yes`, `High` → `Math`.
/// Lower severities default to `Enter` (the weakest challenge), so the
/// user's chosen base challenge always applies to them unchanged.
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
    Challenge::Math
}
const fn default_severity_medium() -> Challenge {
    Challenge::Enter
}
const fn default_severity_low() -> Challenge {
    Challenge::Enter
}
const fn default_severity_info() -> Challenge {
    Challenge::Enter
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

/// Environment variable naming the configuration directory, with the same
/// meaning as `--config-dir` (an explicit `--config-dir` wins).
pub const CONFIG_DIR_ENV: &str = "SHELLFIRM_CONFIG_DIR";

/// The configuration directory named by a [`CONFIG_DIR_ENV`] value.
///
/// `None` when unset or blank, an error when it does not name an existing
/// directory (like an explicit `--config-dir`: a typo would silently drop
/// the team's deny list).
///
/// # Errors
/// Returns an error when the value is not an existing directory.
pub fn config_dir_from_env(value: Option<&str>) -> Result<Option<PathBuf>> {
    let Some(v) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let dir = PathBuf::from(v);
    if dir.is_dir() {
        Ok(Some(dir))
    } else {
        Err(Error::Config(format!(
            "{CONFIG_DIR_ENV}={}: {}",
            dir.display(),
            if dir.exists() {
                "not a directory"
            } else {
                "no such directory"
            }
        )))
    }
}

/// Number of `settings.yaml.bak.*` files kept by `config reset`.
pub const MAX_SETTINGS_BACKUPS: usize = 3;

/// Guard for [`Config::lock_settings`]; the lock is released on drop.
#[derive(Debug)]
pub struct SettingsLock {
    #[cfg(unix)]
    _lock: Option<nix::fcntl::Flock<fs::File>>,
    #[cfg(not(unix))]
    _file: fs::File,
}

/// Recursive sparse merge of `new` into `root` (see
/// [`Config::save_settings_file_from_struct`]).
fn sparse_merge(
    path: &str,
    root: &mut serde_yaml::Value,
    new: &serde_yaml::Value,
    default: &serde_yaml::Value,
) {
    let (Some(new_map), Some(root_map)) = (new.as_mapping(), root.as_mapping_mut()) else {
        return;
    };
    let dynamic = DYNAMIC_MAP_PATHS.contains(&path);
    if dynamic {
        // Free-form maps: entries removed in memory are removed on disk.
        root_map.retain(|k, _| new_map.contains_key(k));
    }
    for (k, v) in new_map {
        let sub_default = default.get(k);
        let in_file = root_map.contains_key(k);
        // A key the default leaves out (`skip_serializing_if`) is at its
        // default when it is empty (`production_env_vars: {}`).
        let differs = sub_default.map_or_else(|| !is_empty_yaml(v), |d| d != v);
        let key_name = k.as_str().unwrap_or_default();
        let sub_path = if path.is_empty() {
            key_name.to_string()
        } else {
            format!("{path}.{key_name}")
        };
        // Turning the LLM on writes the section even when every field is a
        // default (its presence is the setting).
        let differs = differs || (sub_path == "llm" && !in_file && v.is_mapping());
        // A map whose default has entries is replaced as a whole when it is
        // read back, so it is written whole too (an entry left out because
        // it equals a default entry would be lost on the next load).
        if WHOLE_MAP_PATHS.contains(&sub_path.as_str()) {
            if differs {
                root_map.insert(k.clone(), v.clone());
            } else {
                root_map.remove(k);
            }
            continue;
        }
        let both_maps = v.is_mapping()
            && root_map.get(k).is_none_or(serde_yaml::Value::is_mapping)
            && sub_default.is_some_and(serde_yaml::Value::is_mapping);
        if both_maps && (in_file || differs) {
            let entry = root_map
                .entry(k.clone())
                .or_insert_with(|| serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
            sparse_merge(
                &sub_path,
                entry,
                v,
                sub_default.unwrap_or(&serde_yaml::Value::Null),
            );
            // A section left empty and equal to its default is noise
            // (`group_escalation: {}` after removing the last entry). The
            // `llm` section is kept: its presence turns the LLM on.
            let empty = entry
                .as_mapping()
                .is_some_and(serde_yaml::Mapping::is_empty);
            if empty && !differs && sub_path != "llm" {
                root_map.remove(k);
            } else if empty && sub_path == "llm" {
                // `llm: {}` reads like a leftover; keep the section (it turns
                // the LLM on) but name the provider so it says what it does.
                if let (Some(entry), Some(p)) = (entry.as_mapping_mut(), v.get("provider")) {
                    entry.insert(serde_yaml::Value::String("provider".into()), p.clone());
                }
            }
        } else if in_file && !differs && (is_empty_yaml(v) || v.is_sequence()) {
            // Back to an empty default (`ignore --remove` of the last id,
            // `groups --enable` of the last disabled group, `severity all`):
            // drop the key instead of leaving `[]` / `{}` / `null` behind.
            // A list equal to its built-in default is dropped as well
            // (`context branches --add x` then `--remove x`): keeping a copy
            // of today's defaults would pin them and hide later additions.
            root_map.remove(k);
        } else if in_file && !differs && DROP_AT_DEFAULT_PATHS.contains(&sub_path.as_str()) {
            // A switch set back to its default by a setter: the file says
            // nothing (`config impact-budget 400`).
            root_map.remove(k);
        } else if in_file || differs {
            root_map.insert(k.clone(), v.clone());
        }
    }
}

/// Scalar settings removed from the file when they are set back to their
/// default (see [`sparse_merge`]).
const DROP_AT_DEFAULT_PATHS: &[&str] =
    &["blast_radius", "blast_radius_budget_ms", "approved_notice"];

/// `null`, `[]` or `{}`.
fn is_empty_yaml(v: &serde_yaml::Value) -> bool {
    match v {
        serde_yaml::Value::Null => true,
        serde_yaml::Value::Sequence(s) => s.is_empty(),
        serde_yaml::Value::Mapping(m) => m.is_empty(),
        _ => false,
    }
}

fn top_level_key(line: &str) -> Option<&str> {
    if line.starts_with([' ', '\t', '#', '-']) {
        return None;
    }
    let (k, _) = line.split_once(':')?;
    let k = k.trim().trim_matches(['"', '\'']);
    (!k.is_empty()).then_some(k)
}

/// Re-insert the full-line comments of `old` into freshly serialized YAML:
/// the leading comment block, and the comment lines directly above each
/// top-level key.
fn reattach_comments(old: &str, new_yaml: &str) -> String {
    let mut header: Vec<&str> = Vec::new();
    let mut per_key: HashMap<String, Vec<&str>> = HashMap::new();
    let mut lines = old.lines().peekable();
    while let Some(l) = lines.peek() {
        let t = l.trim_start();
        if t.starts_with('#') || t.is_empty() {
            header.push(l);
            lines.next();
        } else {
            break;
        }
    }
    let mut pending: Vec<&str> = Vec::new();
    for l in lines {
        if l.trim_start().starts_with('#') {
            pending.push(l);
        } else if let Some(k) = top_level_key(l) {
            if !pending.is_empty() {
                per_key.insert(k.to_string(), std::mem::take(&mut pending));
            }
        } else if !l.trim().is_empty() {
            pending.clear();
        }
    }
    while header.last().is_some_and(|l| l.trim().is_empty()) {
        header.pop();
    }
    let mut out = String::new();
    for h in &header {
        out.push_str(h);
        out.push('\n');
    }
    for l in new_yaml.lines() {
        if let Some(c) = top_level_key(l).and_then(|k| per_key.get(k)) {
            for cl in c {
                out.push_str(cl);
                out.push('\n');
            }
        }
        out.push_str(l);
        out.push('\n');
    }
    out
}

/// Content written by `config reset` (all values come from the defaults).
const SETTINGS_HEADER: &str =
    "# shellfirm settings. Keys that are not listed use the built-in defaults.\n\
# Reference: https://github.com/kaplanelad/shellfirm/blob/main/docs/config.md\n";

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

const fn default_approved_notice() -> bool {
    true
}

/// Default for [`Settings::blast_radius_budget_ms`].
pub const DEFAULT_BLAST_RADIUS_BUDGET_MS: u64 = 400;

/// Upper bound for [`Settings::blast_radius_budget_ms`] (ms).
///
/// A larger value is used as this, with a settings warning, so an agent
/// hook (which `shellfirm connect` gives a 30 s timeout) never comes near
/// its limit.
pub const MAX_BLAST_RADIUS_BUDGET_MS: u64 = 5_000;

const fn default_blast_radius_budget_ms() -> u64 {
    DEFAULT_BLAST_RADIUS_BUDGET_MS
}

const fn default_audit_max_files() -> usize {
    crate::audit::DEFAULT_MAX_AUDIT_FILES
}

pub const DEFAULT_ENABLED_GROUPS: [&str; 23] = [
    "aws",
    "azure",
    "base",
    "database",
    "docker",
    "exfil",
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
    "shell",
    "terraform",
    "vercel",
];

/// The user challenge when user need to confirm the command.
///
/// Variants are declared from **weakest to strictest** and the derived
/// ordering reflects that: `Enter < Math < Yes`. Pressing Enter is a reflex
/// (it is the same key that ran the command), solving a sum requires
/// attention, and typing `yes` requires a deliberate decision. Escalation
/// layers only ever move a challenge *up* this order (see [`Self::stricter`]).
/// Denying a command outright is not a challenge: it is a separate,
/// absolute decision (deny list / project policy) that wins over any
/// challenge.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Challenge {
    /// Only enter will approve the command (weakest).
    Enter,
    /// Math challenge.
    Math,
    /// only yes typing will approve the command (strictest).
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
    /// Number of rotated audit log files to keep (`audit.log.1` …
    /// `audit.log.N`). Older generations are deleted on rotation.
    #[serde(default = "default_audit_max_files")]
    pub audit_max_files: usize,
    /// Enable blast radius computation (shows impact details for risky commands).
    #[serde(default = "default_blast_radius")]
    pub blast_radius: bool,
    /// Total time (milliseconds) all blast-radius work for one command may
    /// take (`find`, `du`, `git`, `docker` queries together). Work still
    /// pending when it is spent is skipped and its subprocesses are killed;
    /// `0` skips the blast radius entirely.
    #[serde(default = "default_blast_radius_budget_ms")]
    pub blast_radius_budget_ms: u64,
    /// After a passed challenge in a terminal, print one dim line
    /// (`✓ approved — running <command>…`) so a slow command does not look
    /// hung. Never printed by the agent hooks or MCP.
    #[serde(default = "default_approved_notice")]
    pub approved_notice: bool,
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
    /// Order: Enter < Math < Yes
    #[must_use]
    pub fn stricter(self, other: Self) -> Self {
        std::cmp::max(self, other)
    }

    /// Whether `self` is strictly stronger than `other`.
    #[must_use]
    pub fn is_stricter_than(self, other: Self) -> bool {
        self > other
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
            audit_max_files: default_audit_max_files(),
            blast_radius: default_blast_radius(),
            blast_radius_budget_ms: default_blast_radius_budget_ms(),
            approved_notice: default_approved_notice(),
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
            None => match config_dir_from_env(std::env::var(CONFIG_DIR_ENV).ok().as_deref())? {
                Some(dir) => dir,
                None => match dirs::config_dir() {
                    Some(conf_dir) => conf_dir.join(package_name),
                    None => return Err(Error::Config("could not get directory path".into())),
                },
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

    /// The default configuration directory, ignoring [`CONFIG_DIR_ENV`].
    ///
    /// Used where an explicit `--config-dir` wins over the environment, and
    /// by the agent hooks and the MCP server, which never stop without a
    /// decision because of a stale environment variable.
    ///
    /// # Errors
    /// Returns an error when the platform has no configuration directory.
    pub fn default_location() -> Result<Self> {
        let dir = dirs::config_dir()
            .map(|d| d.join(env!("CARGO_PKG_NAME")))
            .ok_or_else(|| Error::Config("could not get directory path".into()))?;
        Self::new(Some(&dir.display().to_string()))
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

    /// Load and strictly parse the user settings file.
    ///
    /// - A missing file (or an empty / comment-only file) yields the
    ///   built-in defaults.
    /// - A file that cannot be read or parsed is an **error** whose message
    ///   names the file and (when available) the line/column of the problem.
    ///   The file is never modified.
    ///
    /// # Errors
    ///
    /// Will return `Err` when the file exists but cannot be read or parsed.
    pub fn get_settings_from_file(&self) -> Result<Settings> {
        match self.read_config_file() {
            Ok(content) => parse_settings_strict(&content).map_err(|e| {
                Error::Config(format!(
                    "invalid settings file {}: {e}",
                    self.setting_file_path.display()
                ))
            }),
            Err(_) if !self.setting_file_path.exists() => Ok(Settings::default()),
            Err(e) => Err(Error::Config(format!(
                "could not read settings file {}: {e}",
                self.setting_file_path.display()
            ))),
        }
    }

    /// Load settings for the interception hot path (`pre-command`, `check`,
    /// `mcp`, `wrap`), which must never lock the user's shell.
    ///
    /// On success returns `(settings, None)`. When the file is invalid, the
    /// error is returned alongside a best-effort in-memory configuration:
    /// every top-level key that is valid on its own is kept (so a typo in
    /// `challenge` does not drop the user's deny list) and every invalid key
    /// falls back to its built-in default. Nothing is written to disk.
    #[must_use]
    pub fn load_settings_lenient(&self) -> (Settings, Option<String>) {
        match self.get_settings_from_file() {
            Ok(s) => (s, None),
            Err(e) => {
                let settings = self
                    .read_config_file()
                    .map(|content| parse_settings_lenient(&content).0)
                    .unwrap_or_default();
                (settings, Some(e.to_string()))
            }
        }
    }

    /// Non-fatal problems with a *valid* settings file that would otherwise
    /// go unnoticed: unknown keys (at any level, e.g.
    /// `agent.auto_deny_severty`). Empty when the file is missing.
    #[must_use]
    pub fn settings_warnings(&self) -> Vec<String> {
        let Ok(content) = self.read_config_file() else {
            return Vec::new();
        };
        let mut out = unknown_settings_key_warnings(&content);
        if let Some(msg) = serde_yaml::from_str::<serde_yaml::Value>(&content)
            .ok()
            .and_then(|v| v.get("audit_max_files").and_then(serde_yaml::Value::as_u64))
            .filter(|n| *n == 0)
            .and_then(|_| audit_max_files_error(0))
        {
            out.push(format!("{msg}; the default is used"));
        }
        if let Ok(s) = parse_settings_strict(&content) {
            if s.blast_radius_budget_ms > MAX_BLAST_RADIUS_BUDGET_MS {
                out.push(format!(
                    "`blast_radius_budget_ms: {}` is capped at {MAX_BLAST_RADIUS_BUDGET_MS} (ms); a \
                     longer wait could push agent hooks toward their timeout",
                    s.blast_radius_budget_ms
                ));
            }
            if s.audit_max_files > crate::audit::MAX_AUDIT_FILES_LIMIT {
                out.push(format!(
                    "`audit_max_files: {}` is capped at {}",
                    s.audit_max_files,
                    crate::audit::MAX_AUDIT_FILES_LIMIT
                ));
            }
        }
        out
    }

    /// Reset user configuration to the default app.
    ///
    /// Writes a settings file that contains only a comment header (all
    /// values come from the built-in defaults). Call
    /// [`Config::backup_settings_file`] first if the old file must be kept.
    ///
    /// # Errors
    ///
    /// Will return `Err` if the config directory cannot be created or the file
    /// cannot be written.
    pub fn reset_config(&self) -> Result<()> {
        self.ensure_config_dir()?;
        self.write_settings_atomically(SETTINGS_HEADER)
    }

    /// Copy the current settings file to `settings.yaml.bak.<timestamp>`.
    ///
    /// Only the newest [`MAX_SETTINGS_BACKUPS`] backups are kept. Returns
    /// `Ok(None)` when there is no settings file to back up, or when it
    /// only holds the header `config reset` writes (repeated resets in a
    /// provisioning loop therefore leave no backups behind).
    ///
    /// # Errors
    ///
    /// Will return `Err` if the copy fails.
    pub fn backup_settings_file(&self) -> Result<Option<PathBuf>> {
        if !self.setting_file_path.is_file() {
            return Ok(None);
        }
        // Nothing worth keeping: the file is exactly what `reset` writes.
        if self
            .read_config_file()
            .is_ok_and(|c| c.trim() == SETTINGS_HEADER.trim())
        {
            return Ok(None);
        }
        let stamp = crate::audit::now_timestamp().replace([':', '-'], "");
        let mut backup = self
            .setting_file_path
            .with_file_name(format!("{DEFAULT_SETTING_FILE_NAME}.bak.{stamp}"));
        let mut n = 1;
        while backup.exists() {
            backup = self
                .setting_file_path
                .with_file_name(format!("{DEFAULT_SETTING_FILE_NAME}.bak.{stamp}.{n}"));
            n += 1;
        }
        fs::copy(&self.setting_file_path, &backup).map_err(|e| {
            Error::Config(format!(
                "could not back up {} to {}: {e}",
                self.setting_file_path.display(),
                backup.display()
            ))
        })?;
        self.prune_backups(MAX_SETTINGS_BACKUPS);
        Ok(Some(backup))
    }

    /// Delete all but the newest `keep` `settings.yaml.bak.*` files.
    fn prune_backups(&self, keep: usize) {
        let prefix = format!("{DEFAULT_SETTING_FILE_NAME}.bak.");
        let mut backups: Vec<(std::time::SystemTime, String, PathBuf)> =
            fs::read_dir(&self.root_folder)
                .into_iter()
                .flatten()
                .filter_map(std::result::Result::ok)
                .filter_map(|e| {
                    let name = e.file_name().to_string_lossy().to_string();
                    if !name.starts_with(&prefix) {
                        return None;
                    }
                    let mtime = e.metadata().and_then(|m| m.modified()).ok()?;
                    Some((mtime, name, e.path()))
                })
                .collect();
        backups.sort();
        let excess = backups.len().saturating_sub(keep);
        for (_, _, path) in backups.into_iter().take(excess) {
            let _ = fs::remove_file(path);
        }
    }

    /// Remove copies left behind by earlier rejected `config edit` runs
    /// (`.settings.edit-<pid>.yaml`), except `keep`.
    pub fn cleanup_edit_leftovers(&self, keep: Option<&std::path::Path>) {
        for entry in fs::read_dir(&self.root_folder)
            .into_iter()
            .flatten()
            .filter_map(std::result::Result::ok)
        {
            let name = entry.file_name().to_string_lossy().to_string();
            let path = entry.path();
            if name.starts_with(".settings.edit-")
                && path
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("yaml"))
                && Some(path.as_path()) != keep
            {
                let _ = fs::remove_file(path);
            }
        }
    }

    /// Take the exclusive settings lock (`.settings.lock` in the config
    /// directory). Every read-modify-write of the settings file holds it so
    /// parallel `shellfirm config …` runs never lose each other's updates.
    ///
    /// # Errors
    /// Returns an error if the config directory or lock file cannot be
    /// created.
    pub fn lock_settings(&self) -> Result<SettingsLock> {
        self.ensure_config_dir()?;
        let path = self.root_folder.join(".settings.lock");
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;
            // Opened with no sharing: while one handle is open (also in
            // another thread or process) a second open fails with a
            // sharing violation, so the open itself is the exclusive lock.
            // The system closes the handle when the process dies, so a
            // crash never leaves a stale lock behind.
            const ERROR_SHARING_VIOLATION: i32 = 32;
            const RETRY: std::time::Duration = std::time::Duration::from_millis(10);
            const GIVE_UP: std::time::Duration = std::time::Duration::from_secs(60);
            let start = std::time::Instant::now();
            loop {
                match fs::OpenOptions::new()
                    .create(true)
                    .truncate(false)
                    .write(true)
                    .share_mode(0)
                    .open(&path)
                {
                    Ok(file) => return Ok(SettingsLock { _file: file }),
                    Err(e)
                        if e.raw_os_error() == Some(ERROR_SHARING_VIOLATION)
                            && start.elapsed() < GIVE_UP =>
                    {
                        std::thread::sleep(RETRY);
                    }
                    Err(e) => {
                        return Err(Error::Config(format!(
                            "could not lock {}: {e}",
                            path.display()
                        )))
                    }
                }
            }
        }
        #[cfg(not(windows))]
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(|e| Error::Config(format!("could not open {}: {e}", path.display())))?;
        #[cfg(unix)]
        {
            match nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusive) {
                Ok(l) => Ok(SettingsLock { _lock: Some(l) }),
                Err((_, e)) => Err(Error::Config(format!(
                    "could not lock {}: {e}",
                    path.display()
                ))),
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            Ok(SettingsLock { _file: file })
        }
    }

    /// Atomically read, modify and (when `f` says so) save the settings:
    /// the settings lock is held throughout, the file is re-read strictly
    /// under the lock (an invalid file is an error and is never
    /// overwritten), and the write is sparse and atomic.
    ///
    /// `f` returns its result plus `true` when the settings changed and
    /// must be written.
    ///
    /// # Errors
    /// Returns an error when the file is invalid, `f` fails, or the file
    /// cannot be written.
    pub fn modify_settings<T>(
        &self,
        f: impl FnOnce(&mut Settings) -> Result<(T, bool)>,
    ) -> Result<T> {
        let _lock = self.lock_settings()?;
        let mut settings = self.get_settings_from_file()?;
        let (out, changed) = f(&mut settings)?;
        if changed {
            self.save_settings_unlocked(&settings)?;
        }
        Ok(out)
    }

    /// Validate raw settings YAML and, if valid, replace the settings file
    /// with it verbatim (comments preserved), atomically.
    ///
    /// # Errors
    ///
    /// Will return `Err` if the content is invalid or cannot be written.
    pub fn save_settings_text(&self, content: &str) -> Result<()> {
        parse_settings_strict(content)?;
        self.ensure_config_dir()?;
        self.write_settings_atomically(content)
    }

    /// Write `content` to the settings file atomically (temp file + rename),
    /// preserving the existing file's permissions. Refuses to replace a
    /// read-only settings file.
    fn write_settings_atomically(&self, content: &str) -> Result<()> {
        let path = &self.setting_file_path;
        let existing_perms = fs::metadata(path).ok().map(|m| m.permissions());
        if let Some(perms) = &existing_perms {
            if perms.readonly() {
                return Err(Error::Config(format!(
                    "settings file {} is read-only; not modifying it",
                    path.display()
                )));
            }
        }
        let tmp = path.with_file_name(format!(
            ".{DEFAULT_SETTING_FILE_NAME}.tmp-{}",
            std::process::id()
        ));
        let write = || -> std::io::Result<()> {
            let mut file = fs::File::create(&tmp)?;
            file.write_all(content.as_bytes())?;
            file.sync_all()?;
            if let Some(perms) = &existing_perms {
                fs::set_permissions(&tmp, perms.clone())?;
            }
            fs::rename(&tmp, path)
        };
        write().map_err(|e| {
            let _ = fs::remove_file(&tmp);
            Error::Config(format!(
                "could not write settings file {}: {e}",
                path.display()
            ))
        })
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

    /// Save the given settings to the settings file.
    ///
    /// The write is **sparse** at every nesting level: only keys that are
    /// already present in the file, or whose value differs from the
    /// built-in default, are written (adding one protected branch writes
    /// `context.protected_branches`, not the whole `context` block). Unknown
    /// keys already in the file are preserved. Full-line comments are kept:
    /// the comment block at the top of the file and the comment lines
    /// directly above each top-level key (inline `# …` comments after a
    /// value are not). The settings lock is held for the write. The write is atomic
    /// and refuses to touch a file that is not valid YAML (so a corrupt file
    /// is never silently replaced).
    ///
    /// # Arguments
    ///
    /// * `settings` - Config struct
    ///
    /// # Errors
    ///
    /// Will return `Err` if the config directory cannot be created, the
    /// existing file is not valid YAML, or the file cannot be written.
    pub fn save_settings_file_from_struct(&self, settings: &Settings) -> Result<()> {
        let _lock = self.lock_settings()?;
        self.save_settings_unlocked(settings)
    }

    fn save_settings_unlocked(&self, settings: &Settings) -> Result<()> {
        self.ensure_config_dir()?;
        let old_text = self.read_config_file().unwrap_or_default();
        let mut root = self.read_config_as_value().map_err(|e| {
            Error::Config(format!(
                "refusing to overwrite {} because it is not valid YAML ({e}); \
                 fix it with `shellfirm config edit` or `shellfirm config reset`",
                self.setting_file_path.display()
            ))
        })?;
        if !root.is_mapping() {
            root = serde_yaml::Value::Mapping(serde_yaml::Mapping::default());
        }
        let new_value = serde_yaml::to_value(settings)?;
        let mut default_value = serde_yaml::to_value(Settings::default())?;
        // `llm` is off by default (no section); once it is on, only the
        // fields that differ from the LLM defaults are written, so the
        // default model is not pinned in the file forever.
        if new_value
            .get("llm")
            .is_some_and(serde_yaml::Value::is_mapping)
        {
            if let Some(map) = default_value.as_mapping_mut() {
                map.insert(
                    serde_yaml::Value::String("llm".into()),
                    serde_yaml::to_value(LlmConfig::default())?,
                );
            }
        }
        sparse_merge("", &mut root, &new_value, &default_value);
        let body = if root.as_mapping().is_some_and(serde_yaml::Mapping::is_empty) {
            String::new()
        } else {
            serde_yaml::to_string(&root)?
        };
        let mut content = reattach_comments(&old_text, &body);
        if content.trim().is_empty() {
            content = SETTINGS_HEADER.to_string();
        }
        self.write_settings_atomically(&content)?;
        debug!(
            "settings file saved to: {}",
            self.setting_file_path.display()
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
        let _settings: Settings = parse_settings_strict(&yaml_str)?;
        self.write_settings_atomically(&yaml_str)
    }
}

impl Settings {
    /// Whether the impact (blast radius) is measured: the one switch is
    /// `blast_radius_budget_ms` (`0` = off). `blast_radius: false` is an
    /// older spelling of off that is still honoured.
    #[must_use]
    pub const fn blast_radius_on(&self) -> bool {
        self.blast_radius && self.blast_radius_budget_ms > 0
    }

    /// Turn the impact measurement on (the default budget, unless one is
    /// set) or off (`blast_radius_budget_ms: 0`), clearing the older
    /// `blast_radius: false` switch so one key decides.
    pub const fn set_blast_radius_on(&mut self, on: bool) {
        self.blast_radius = true;
        if !on {
            self.blast_radius_budget_ms = 0;
        } else if self.blast_radius_budget_ms == 0 {
            self.blast_radius_budget_ms = DEFAULT_BLAST_RADIUS_BUDGET_MS;
        }
    }

    /// The blast-radius time budget actually used (ms):
    /// `blast_radius_budget_ms`, capped at [`MAX_BLAST_RADIUS_BUDGET_MS`].
    #[must_use]
    pub fn blast_radius_budget(&self) -> u64 {
        self.blast_radius_budget_ms.min(MAX_BLAST_RADIUS_BUDGET_MS)
    }

    /// Start the time budget for evaluating one command with these
    /// settings (see [`crate::env::CommandScope`]).
    pub fn command_scope(&self) -> crate::env::CommandScope {
        crate::env::CommandScope::enter(self.blast_radius_budget())
    }

    /// Return list of active patterns by user groups
    ///
    /// # Errors
    ///
    /// Will return `Err` when could not load config file
    pub fn get_active_checks(&self) -> Result<Vec<checks::Check>> {
        let enabled: HashSet<&str> = self.enabled_groups.iter().map(String::as_str).collect();
        let disabled: HashSet<&str> = self.disabled_groups.iter().map(String::as_str).collect();
        let ignores = self.effective_ignores();
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
        let ignores = self.effective_ignores();

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

    /// Ignored ids that actually take effect: an id that is in both
    /// `ignores_patterns_ids` and `deny_patterns_ids` stays active, because a
    /// personal deny is documented as "always blocked" and wins.
    #[must_use]
    pub fn effective_ignores(&self) -> HashSet<&str> {
        self.ignores_patterns_ids
            .iter()
            .map(String::as_str)
            .filter(|id| !self.deny_patterns_ids.iter().any(|d| d == id))
            .collect()
    }

    /// Ids that are in both the personal ignore and deny lists (the deny
    /// wins; see [`Settings::effective_ignores`]).
    #[must_use]
    pub fn ignore_deny_conflicts(&self) -> Vec<String> {
        self.ignores_patterns_ids
            .iter()
            .filter(|id| self.deny_patterns_ids.contains(id))
            .cloned()
            .collect()
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

// ---------------------------------------------------------------------------
// Settings parsing (strict / lenient) and key validation
// ---------------------------------------------------------------------------

/// Parse settings YAML strictly.
///
/// Empty and comment-only documents yield the
/// defaults. Errors carry serde's `at line X column Y` location (a duplicate
/// key, which serde reports without a location, gets the line of the
/// repeated key added).
///
/// # Errors
/// Returns an error when the YAML is malformed or a value has the wrong type
/// or an unknown enum variant.
pub fn parse_settings_strict(content: &str) -> Result<Settings> {
    let value: serde_yaml::Value =
        serde_yaml::from_str(content).map_err(|e| locate_error(content, e))?;
    if value.is_null() {
        return Ok(Settings::default());
    }
    if !value.is_mapping() {
        return Err(Error::Config(
            "expected a YAML mapping of `key: value` settings at the top level".into(),
        ));
    }
    // Deserialize from the original text so error messages keep line numbers.
    let mut settings: Settings =
        serde_yaml::from_str(content).map_err(|e| locate_error(content, e))?;
    // `audit_max_files: 0` is never used (it would delete the history), but
    // it does not make the whole file invalid: the default applies and
    // [`Config::settings_warnings`] reports it.
    if audit_max_files_error(settings.audit_max_files).is_some() {
        settings.audit_max_files = default_audit_max_files();
    }
    Ok(settings)
}

/// `audit_max_files: 0` would make every rotation delete the history, so it
/// is rejected (the default is kept).
fn audit_max_files_error(n: usize) -> Option<String> {
    (n == 0).then(|| {
        format!(
            "`audit_max_files` must be at least 1 (0 would delete the audit history on \
             every rotation); remove the key to keep the default of {}",
            crate::audit::DEFAULT_MAX_AUDIT_FILES
        )
    })
}

/// Add a line number to serde errors that lack one (duplicate keys).
fn locate_error(content: &str, e: serde_yaml::Error) -> Error {
    let msg = e.to_string();
    if msg.contains(" line ") || !msg.contains("duplicate") {
        return Error::Yaml(e);
    }
    duplicate_key_line(content, &msg).map_or(Error::Yaml(e), |(key, line)| {
        Error::Config(format!(
            "duplicate key `{key}` at line {line} (each key may appear only once)"
        ))
    })
}

/// Find the line (1-based) where a key named in a serde "duplicate" message
/// is repeated at the same indentation.
fn duplicate_key_line(content: &str, msg: &str) -> Option<(String, usize)> {
    let key = msg
        .split_once("with key \"")
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(k, _)| k.to_string())
        .or_else(|| {
            msg.split_once("duplicate field `")
                .and_then(|(_, rest)| rest.split_once('`'))
                .map(|(k, _)| k.to_string())
        })?;
    let mut seen: HashMap<usize, usize> = HashMap::new();
    for (i, line) in content.lines().enumerate() {
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        let trimmed = trimmed.trim_start_matches("- ");
        let Some(rest) = trimmed.strip_prefix(key.as_str()) else {
            continue;
        };
        let rest = rest.trim_start_matches(['"', '\'']);
        if rest.trim_start().starts_with(':') {
            let n = seen.entry(indent).or_insert(0);
            *n += 1;
            if *n > 1 {
                return Some((key, i + 1));
            }
        }
    }
    None
}

/// Wrap `v` in nested mappings along `path` (`["agent", "challenge"]` →
/// `{agent: {challenge: v}}`).
fn wrap_path(path: &[serde_yaml::Value], v: serde_yaml::Value) -> serde_yaml::Value {
    path.iter().rev().fold(v, |acc, k| {
        let mut m = serde_yaml::Mapping::new();
        m.insert(k.clone(), acc);
        serde_yaml::Value::Mapping(m)
    })
}

fn path_label(path: &[serde_yaml::Value]) -> String {
    path.iter()
        .map(|k| {
            k.as_str()
                .map_or_else(|| "?".to_string(), ToString::to_string)
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// Keep the parts of `v` (located at `path`) that deserialize on their own;
/// recurse into mappings so one invalid value does not drop its valid
/// siblings. Returns `None` when nothing at this path is usable.
fn lenient_value(
    path: &mut Vec<serde_yaml::Value>,
    v: &serde_yaml::Value,
    dropped: &mut Vec<String>,
) -> Option<serde_yaml::Value> {
    let probe = |val: serde_yaml::Value, path: &[serde_yaml::Value]| {
        serde_yaml::from_value::<Settings>(wrap_path(path, val))
    };
    let Err(err) = probe(v.clone(), path) else {
        return Some(v.clone());
    };
    if let (Some(map), true) = (v.as_mapping(), path.len() < 4) {
        let mut kept = serde_yaml::Mapping::new();
        for (k, sub) in map {
            path.push(k.clone());
            if let Some(ok) = lenient_value(path, sub, dropped) {
                kept.insert(k.clone(), ok);
            }
            path.pop();
        }
        let kept = serde_yaml::Value::Mapping(kept);
        if probe(kept.clone(), path).is_ok() {
            return Some(kept);
        }
    }
    dropped.push(format!(
        "`{}` ignored (using default): {}",
        path_label(path),
        one_line(&err.to_string())
    ));
    None
}

/// Parse settings YAML leniently.
///
/// Keeps every value that is valid on its own (at any nesting level: one invalid `agent.challenge` does not drop a
/// valid `agent.auto_deny_severity`) and replace invalid ones with the
/// built-in default. Returns the settings plus one message per dropped value.
#[must_use]
pub fn parse_settings_lenient(content: &str) -> (Settings, Vec<String>) {
    let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(content) else {
        return (
            Settings::default(),
            vec!["the file is not valid YAML; using built-in defaults".into()],
        );
    };
    let Some(map) = value.as_mapping() else {
        return (Settings::default(), Vec::new());
    };
    let mut kept = serde_yaml::Mapping::new();
    let mut dropped = Vec::new();
    for (k, v) in map {
        let mut path = vec![k.clone()];
        if let Some(ok) = lenient_value(&mut path, v, &mut dropped) {
            kept.insert(k.clone(), ok);
        }
    }
    let mut settings: Settings =
        serde_yaml::from_value(serde_yaml::Value::Mapping(kept)).unwrap_or_default();
    if let Some(msg) = audit_max_files_error(settings.audit_max_files) {
        settings.audit_max_files = default_audit_max_files();
        dropped.push(format!("`audit_max_files` ignored (using default): {msg}"));
    }
    (settings, dropped)
}

/// All top-level keys understood by [`Settings`].
#[must_use]
pub fn known_settings_keys() -> Vec<String> {
    serde_yaml::to_value(Settings::default())
        .ok()
        .and_then(|v| {
            v.as_mapping().map(|m| {
                m.keys()
                    .filter_map(|k| k.as_str().map(ToString::to_string))
                    .collect()
            })
        })
        .unwrap_or_default()
}

/// Free-form maps with a non-empty default: written whole when they differ
/// from the default, removed when they are equal to it (see [`sparse_merge`]).
const WHOLE_MAP_PATHS: &[&str] = &["context.production_env_vars"];

/// Settings paths whose keys are free-form (user-chosen names).
const DYNAMIC_MAP_PATHS: &[&str] = &[
    "group_escalation",
    "check_escalation",
    "context.production_env_vars",
    "wrappers.tools",
];

/// The shape of every known settings key (defaults, with optional sections
/// filled in so their keys are known too).
fn settings_schema() -> serde_yaml::Value {
    let s = Settings {
        llm: Some(LlmConfig {
            base_url: Some(String::new()),
            ..LlmConfig::default()
        }),
        ..Settings::default()
    };
    serde_yaml::to_value(s).unwrap_or(serde_yaml::Value::Null)
}

fn wrapper_tool_schema() -> serde_yaml::Value {
    serde_yaml::to_value(WrapperToolConfig {
        delimiter: Some(String::new()),
        check_groups: Vec::new(),
    })
    .unwrap_or(serde_yaml::Value::Null)
}

fn collect_unknown(
    prefix: &str,
    value: &serde_yaml::Value,
    schema: &serde_yaml::Value,
    out: &mut Vec<String>,
) {
    let (Some(map), Some(schema_map)) = (value.as_mapping(), schema.as_mapping()) else {
        return;
    };
    for (k, v) in map {
        let Some(name) = k.as_str() else { continue };
        let path = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}.{name}")
        };
        match schema_map.get(k) {
            None => out.push(path),
            Some(sub) => {
                if path == "wrappers.tools" {
                    if let Some(tools) = v.as_mapping() {
                        let tool_schema = wrapper_tool_schema();
                        for (tk, tv) in tools {
                            let tp = format!("{path}.{}", tk.as_str().unwrap_or("?"));
                            collect_unknown(&tp, tv, &tool_schema, out);
                        }
                    }
                } else if !DYNAMIC_MAP_PATHS.contains(&path.as_str()) {
                    collect_unknown(&path, v, sub, out);
                }
            }
        }
    }
}

/// Return the keys in `content` that [`Settings`] does not know.
///
/// Keys are dotted paths — top-level typos such as `deny_pattern_ids` or obsolete keys such
/// as `includes`, and nested ones such as `agent.auto_deny_severty`. Serde
/// ignores these silently, so they are reported separately.
#[must_use]
pub fn unknown_settings_keys(content: &str) -> Vec<String> {
    let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(content) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    collect_unknown("", &value, &settings_schema(), &mut out);
    out
}

/// Human-readable warnings for unknown settings keys, with "did you mean"
/// suggestions.
#[must_use]
pub fn unknown_settings_key_warnings(content: &str) -> Vec<String> {
    let schema = settings_schema();
    unknown_settings_keys(content)
        .into_iter()
        .map(|path| {
            let (parent, leaf) = path.rsplit_once('.').unwrap_or(("", path.as_str()));
            let siblings: Vec<String> = parent
                .split('.')
                .filter(|p| !p.is_empty())
                .try_fold(&schema, |node, seg| node.get(seg))
                .and_then(serde_yaml::Value::as_mapping)
                .map(|m| {
                    m.keys()
                        .filter_map(|k| k.as_str().map(ToString::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let hint = suggest_similar(leaf, siblings.iter().map(String::as_str), 1)
                .into_iter()
                .next()
                .map_or_else(String::new, |s| format!(" — did you mean `{s}`?"));
            format!("unknown setting `{path}` is ignored{hint}")
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Terminal capabilities shared by the CLI, the challenge and the TUI
// ---------------------------------------------------------------------------

/// `TERM` values of terminals that cannot show colour. An empty `TERM=`
/// (set but blank) names no terminal type, so it gets no colour either.
fn term_is_monochrome(term: &str) -> bool {
    let t = term.trim().to_ascii_lowercase();
    matches!(
        t.as_str(),
        "" | "dumb"
            | "unknown"
            | "vt52"
            | "vt100"
            | "vt102"
            | "vt220"
            | "vt320"
            | "ansi-m"
            | "linux-m"
    ) || t.ends_with("-mono")
        || t.ends_with("-m")
}

/// What the environment says about colour, before looking at whether the
/// output is a terminal.
///
/// - `Some(true)`: forced on (`CLICOLOR_FORCE` set to anything but `0`).
/// - `Some(false)`: off — `NO_COLOR` set to a **non-empty** value (an empty
///   `NO_COLOR=` does not disable colour, per <https://no-color.org>),
///   `CLICOLOR=0`, or a monochrome or empty `TERM` (`dumb`, `vt100`,
///   `xterm-mono`, `TERM=`, …).
/// - `None`: no preference; use colour when the stream is a terminal.
#[must_use]
pub fn color_preference(get: impl Fn(&str) -> Option<String>) -> Option<bool> {
    if get("CLICOLOR_FORCE").is_some_and(|v| !v.is_empty() && v != "0") {
        return Some(true);
    }
    if get("NO_COLOR").is_some_and(|v| !v.is_empty()) || get("CLICOLOR").as_deref() == Some("0") {
        return Some(false);
    }
    if get("TERM").is_some_and(|t| term_is_monochrome(&t)) {
        return Some(false);
    }
    None
}

/// Whether text output may use non-ASCII glyphs (`—`, `→`, `✓`): the first
/// non-empty of `LC_ALL`, `LC_CTYPE`, `LANG` names a UTF-8 locale, or none
/// is set.
#[must_use]
pub fn unicode_locale(get: impl Fn(&str) -> Option<String>) -> bool {
    ["LC_ALL", "LC_CTYPE", "LANG"]
        .into_iter()
        .filter_map(&get)
        .find(|v| !v.is_empty())
        .is_none_or(|l| {
            let l = l.to_ascii_lowercase();
            l.contains("utf-8") || l.contains("utf8")
        })
}

/// [`unicode_locale`] for this process (computed once).
#[must_use]
pub fn unicode_output() -> bool {
    static U: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *U.get_or_init(|| unicode_locale(|k| std::env::var(k).ok()))
}

/// `unicode` under a UTF-8 locale, `ascii` otherwise.
#[must_use]
pub fn glyph(unicode: &'static str, ascii: &'static str) -> &'static str {
    if unicode_output() {
        unicode
    } else {
        ascii
    }
}

/// Replace the non-ASCII punctuation shellfirm prints (`—`, `→`, `✓`, `✗`,
/// `…`, `·`) with ASCII when the locale is not UTF-8.
#[must_use]
pub fn ascii_fallback(text: &str) -> String {
    if unicode_output() {
        return text.to_string();
    }
    text.replace('—', "-")
        .replace('→', "->")
        .replace('✓', "ok")
        .replace('✗', "x")
        .replace('…', "...")
        .replace('·', "-")
        .replace('‹', "<")
        .replace('›', ">")
}

// ---------------------------------------------------------------------------
// "Did you mean" suggestions
// ---------------------------------------------------------------------------

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            cur[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

/// Up to `max` candidates similar to `needle`, best first.
///
/// Uses case-insensitive edit distance, also comparing with `_`/`-` removed, plus prefix and substring
/// matches), best first. Used for "did you mean" hints on check ids, group
/// names and setting keys: `git:forcepush` → `git:force_push`, `shel` →
/// `shell`.
#[must_use]
pub fn suggest_similar<'a>(
    needle: &str,
    candidates: impl IntoIterator<Item = &'a str>,
    max: usize,
) -> Vec<String> {
    let norm = |s: &str| -> String {
        s.to_lowercase()
            .chars()
            .filter(|c| *c != '_' && *c != '-')
            .collect()
    };
    let n_low = needle.to_lowercase();
    let n_norm = norm(needle);
    if n_norm.is_empty() {
        return Vec::new();
    }
    let n_name = n_low.rsplit(':').next().unwrap_or(&n_low).to_string();
    let mut scored: Vec<(usize, String)> = candidates
        .into_iter()
        .filter(|c| !c.eq_ignore_ascii_case(needle))
        .filter_map(|c| {
            let c_low = c.to_lowercase();
            let c_norm = norm(c);
            let mut score = levenshtein(&n_low, &c_low).min(levenshtein(&n_norm, &c_norm));
            // Same name in another group, or a prefix of the full id.
            let c_name = c_low.rsplit(':').next().unwrap_or(&c_low);
            if norm(c_name) == norm(&n_name) {
                score = score.min(1);
            }
            if c_norm.starts_with(&n_norm) && n_norm.len() >= 3 {
                score = score.min(1);
            }
            // `gti` -> `git`: one swap of neighbouring letters.
            if is_one_transposition(&n_low, &c_low) {
                score = score.min(1);
            }
            let limit = (n_norm.len() / 3).clamp(1, 3);
            if score <= limit {
                return Some((score, c.to_string()));
            }
            if n_name.len() >= 4 && c_low.contains(&n_name) {
                return Some((limit + 1, c.to_string()));
            }
            None
        })
        .collect();
    scored.sort();
    scored.dedup_by(|a, b| a.1 == b.1);
    scored.into_iter().take(max).map(|(_, c)| c).collect()
}

/// `true` when `b` is `a` with two neighbouring characters swapped.
fn is_one_transposition(a: &str, b: &str) -> bool {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.len() != b.len() || a.len() < 2 {
        return false;
    }
    let diff: Vec<usize> = (0..a.len()).filter(|&i| a[i] != b[i]).collect();
    matches!(diff.as_slice(), [i, j] if *j == i + 1 && a[*i] == b[*j] && a[*j] == b[*i])
}

/// Exit code for a usage mistake (`EX_USAGE`-like, the same as clap's): a
/// typo'd group name in `check --list -g` and `config groups`.
pub const EXIT_USAGE: i32 = 2;

/// The one message for a group name that does not exist, with a "Did you
/// mean" hint (`check --list -g gti`, `config groups --disable gti`).
#[must_use]
pub fn unknown_group_message<'a>(
    name: &str,
    available: impl IntoIterator<Item = &'a str>,
) -> String {
    let mut groups: Vec<&str> = available.into_iter().collect();
    groups.sort_unstable();
    groups.dedup();
    let hint = suggest_similar(name, groups.iter().copied(), 3);
    let hint = if hint.is_empty() {
        String::new()
    } else {
        format!(" Did you mean: {}?", hint.join(", "))
    };
    crate::context::escape_invisible(&format!(
        "unknown check group '{name}'.{hint} Known groups: {}",
        groups.join(", ")
    ))
}

/// Why a check id does not follow the `group:snake_case` form the built-in
/// checks use (`git:force_push`, `fs-strict:any_deletion`), or `None`.
///
/// The text names the id escaped (`mine:b\u{202e}x`), never raw.
#[must_use]
pub fn check_id_format_problem(id: &str) -> Option<String> {
    let shown = crate::context::escape_invisible(id);
    let Some((group, name)) = id.split_once(':') else {
        return Some(format!(
            "id `{shown}` must have the form `group:name` (lowercase letters, digits, `_`; \
             the group may also use `-`)"
        ));
    };
    let group_ok = !group.is_empty()
        && group
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    let name_ok = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    if group_ok && name_ok {
        None
    } else {
        Some(format!(
            "id `{shown}` should be lowercase `group:name` (letters, digits, `_`; the group may \
             also use `-`), like the built-in checks"
        ))
    }
}

/// `true` when a check id has characters that would make it look like a
/// different id when printed: whitespace, control, bidi or zero-width
/// characters. Such a custom check is not loaded.
#[must_use]
pub fn check_id_has_hidden_chars(id: &str) -> bool {
    id.chars()
        .any(|c| c.is_whitespace() || c.is_control() || crate::context::is_invisible(c))
}

// ---------------------------------------------------------------------------
// Custom checks loading (lenient, per-file) and the check catalog
// ---------------------------------------------------------------------------

/// Result of loading the user's custom checks directory.
#[derive(Debug, Default, Clone)]
pub struct CustomChecksLoad {
    /// Every custom check that loaded successfully (deduplicated).
    pub checks: Vec<checks::Check>,
    /// One human-readable warning per skipped file or check. Each names the
    /// offending file.
    pub warnings: Vec<String>,
    /// Checks whose YAML explicitly set `challenge:`. The value is a
    /// per-check challenge **floor** — see
    /// [`Settings::apply_custom_check_challenges`].
    pub explicit_challenges: HashMap<String, Challenge>,
}

/// Load custom checks from every `*.yaml` / `*.yml` file in `checks_dir`.
///
/// Unlike [`checks::load_custom_checks`], a broken file never drops the
/// other files: it is skipped with a warning that names it. Checks whose id
/// collides with a built-in check or with an earlier custom check are
/// skipped with a warning too. Files are processed in name order.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn load_custom_checks_report(checks_dir: &std::path::Path) -> CustomChecksLoad {
    let mut out = CustomChecksLoad::default();
    if !checks_dir.is_dir() {
        return out;
    }
    let mut paths: Vec<PathBuf> = match fs::read_dir(checks_dir) {
        Ok(entries) => {
            let all: Vec<PathBuf> = entries
                .filter_map(std::result::Result::ok)
                .map(|e| e.path())
                .collect();
            // Only the top level is read: say so for a subdirectory with
            // check files instead of ignoring them silently.
            let mut subdirs: Vec<&PathBuf> = all
                .iter()
                .filter(|p| p.is_dir() && dir_has_yaml(p))
                .collect();
            subdirs.sort();
            for d in subdirs {
                out.warnings.push(format!(
                    "{}: subdirectory ignored (custom checks are read only from *.yaml / *.yml \
                     files directly in {}; move the files up)",
                    d.display(),
                    checks_dir.display()
                ));
            }
            all.into_iter()
                .filter(|p| p.is_file())
                .filter(|p| p.extension().is_some_and(|e| e == "yaml" || e == "yml"))
                .collect()
        }
        Err(e) => {
            out.warnings.push(format!(
                "could not read custom checks directory {}: {e}",
                checks_dir.display()
            ));
            return out;
        }
    };
    paths.sort();

    let builtin: HashSet<&str> = checks::all_checks_cached()
        .iter()
        .map(|c| c.id.as_str())
        .collect();
    let mut seen: HashSet<String> = HashSet::new();

    for path in paths {
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                out.warnings
                    .push(format!("{}: skipped (could not read: {e})", path.display()));
                continue;
            }
        };
        let raw: serde_yaml::Value = match serde_yaml::from_str(&content) {
            Ok(v) => v,
            Err(e) => {
                out.warnings
                    .push(format!("{}: skipped (invalid YAML: {e})", path.display()));
                continue;
            }
        };
        if raw.is_null() {
            continue;
        }
        if !raw.is_sequence() {
            out.warnings.push(format!(
                "{}: skipped (expected a YAML list of checks)",
                path.display()
            ));
            continue;
        }
        let parsed: Vec<checks::Check> = match serde_yaml::from_str(&content) {
            Ok(v) => v,
            Err(e) => {
                out.warnings
                    .push(format!("{}: skipped ({e})", path.display()));
                continue;
            }
        };
        let raw_items = raw.as_sequence().cloned().unwrap_or_default();
        for (check, raw_item) in parsed.into_iter().zip(raw_items) {
            if check.id.trim().is_empty() {
                out.warnings.push(format!(
                    "{}: skipped a check with an empty id",
                    path.display()
                ));
                continue;
            }
            // An id with bidi / zero-width / control characters prints as a
            // different id (`mine:b\u{202e}x` shows as `mine:bx`).
            if check_id_has_hidden_chars(&check.id) {
                out.warnings.push(format!(
                    "{}: skipped check `{}` (the id contains spaces, control, bidi or \
                     zero-width characters)",
                    path.display(),
                    crate::context::escape_invisible(&check.id)
                ));
                continue;
            }
            if let Some(problem) = check_id_format_problem(&check.id) {
                out.warnings
                    .push(format!("{}: check {problem}", path.display()));
            }
            if builtin.contains(check.id.as_str()) {
                out.warnings.push(format!(
                    "{}: skipped check `{}` (the id is already used by a built-in check)",
                    path.display(),
                    check.id
                ));
                continue;
            }
            if !seen.insert(check.id.clone()) {
                out.warnings.push(format!(
                    "{}: skipped check `{}` (duplicate id; the first definition wins)",
                    path.display(),
                    check.id
                ));
                continue;
            }
            if let Some(m) = raw_item.as_mapping() {
                for k in m.keys().filter_map(serde_yaml::Value::as_str) {
                    if !crate::policy::CHECK_KEYS.contains(&k) {
                        let hint = suggest_similar(k, crate::policy::CHECK_KEYS.iter().copied(), 1)
                            .into_iter()
                            .next()
                            .map_or_else(String::new, |s| format!(" — did you mean `{s}`?"));
                        out.warnings.push(format!(
                            "{}: check `{}`: unknown key `{k}` is ignored{hint}",
                            path.display(),
                            check.id
                        ));
                    }
                }
            }
            let mut check = check;
            // An empty alternative would print `Safe alternative:  ()`.
            if check
                .alternative
                .as_deref()
                .is_some_and(|a| a.trim().is_empty())
            {
                out.warnings.push(format!(
                    "{}: check `{}`: empty `alternative` is ignored (remove the key or give a \
                     command)",
                    path.display(),
                    check.id
                ));
                check.alternative = None;
            }
            if check
                .alternative_info
                .as_deref()
                .is_some_and(|a| a.trim().is_empty())
            {
                out.warnings.push(format!(
                    "{}: check `{}`: empty `alternative_info` is ignored",
                    path.display(),
                    check.id
                ));
                check.alternative_info = None;
            }
            if check.alternative.is_none() && check.alternative_info.is_some() {
                out.warnings.push(format!(
                    "{}: check `{}`: `alternative_info` without an `alternative` is not shown",
                    path.display(),
                    check.id
                ));
            }
            let removed = crate::policy::removed_text_chars(&check);
            if crate::policy::sanitize_check_text(&mut check) && !removed.is_empty() {
                out.warnings.push(format!(
                    "{}: check `{}`: removed {} from its text (control or bidi characters \
                     are not shown)",
                    path.display(),
                    check.id,
                    removed.join(", ")
                ));
            }
            let groups = check.test.captures_len().saturating_sub(1);
            for f in &check.filters {
                if let checks::Filter::PathExists(n) = f {
                    if *n > groups {
                        out.warnings.push(format!(
                            "{}: check `{}`: PathExists capture group {n} does not exist (the \
                             regex has {groups}); the check never matches",
                            path.display(),
                            check.id
                        ));
                    }
                }
            }
            if raw_item.get("challenge").is_some() {
                out.explicit_challenges
                    .insert(check.id.clone(), check.challenge);
            }
            if let Some(w) = alternative_trigger_warning(&check) {
                out.warnings.push(format!("{}: {w}", path.display()));
            }
            out.checks.push(check);
        }
    }
    let mut seen_w = HashSet::new();
    out.warnings = out
        .warnings
        .iter()
        .map(|w| crate::policy::sanitize_untrusted_text(&one_line(w)))
        .filter(|w| seen_w.insert(w.clone()))
        .collect();
    out
}

/// An [`crate::env::Environment`] in which every path exists and nothing
/// runs: a check's `PathExists` filter never hides what its pattern says.
struct EveryPathExists;

impl crate::env::Environment for EveryPathExists {
    fn var(&self, _key: &str) -> Option<String> {
        None
    }
    fn current_dir(&self) -> Result<std::path::PathBuf> {
        Ok(std::path::PathBuf::from("/"))
    }
    fn path_exists(&self, _path: &std::path::Path) -> bool {
        true
    }
    fn home_dir(&self) -> Option<std::path::PathBuf> {
        None
    }
    fn run_command(&self, _cmd: &str, _args: &[&str], _timeout_ms: u64) -> Option<String> {
        None
    }
    fn read_file(&self, path: &std::path::Path) -> Result<String> {
        Err(Error::Other(format!("not read: {}", path.display())))
    }
    fn find_file_upward(
        &self,
        _start: &std::path::Path,
        _name: &str,
    ) -> Option<std::path::PathBuf> {
        None
    }
}

/// A custom check whose `alternative` would itself trigger a built-in check
/// at the same or a higher severity: the "safe" suggestion is not safe (the
/// built-in checks are tested for the same rule).
fn alternative_trigger_warning(check: &checks::Check) -> Option<String> {
    let alt = check.alternative.as_deref()?;
    let hit =
        checks::run_check_on_command_with_env(checks::all_checks_cached(), alt, &EveryPathExists)
            .into_iter()
            .filter(|m| m.id != check.id && m.severity >= check.severity)
            .max_by_key(|m| m.severity)?;
    Some(format!(
        "check `{}` ({}): its alternative `{alt}` triggers the built-in check `{}` ({}); \
         suggest a safer command",
        check.id, check.severity, hit.id, hit.severity
    ))
}

/// `true` when `dir` directly contains a `*.yaml` / `*.yml` file.
fn dir_has_yaml(dir: &std::path::Path) -> bool {
    fs::read_dir(dir).is_ok_and(|entries| {
        entries.filter_map(std::result::Result::ok).any(|e| {
            e.path()
                .extension()
                .is_some_and(|x| x == "yaml" || x == "yml")
        })
    })
}

/// Collapse a (possibly multi-line) message into a single line.
#[must_use]
pub fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Every check id shellfirm knows about: built-ins plus the given custom
/// checks.
#[must_use]
pub fn known_check_ids(custom: &[checks::Check]) -> HashSet<String> {
    checks::all_checks_cached()
        .iter()
        .chain(custom.iter())
        .map(|c| c.id.clone())
        .collect()
}

/// Built-in agent-protection rule ids that may be listed in `ignores_patterns_ids`.
///
/// They are not checks. The other `shellfirm-self:*` ids and
/// `shellfirm:input_too_large` are controlled only by `agent.self_protection`.
pub const IGNORABLE_BUILTIN_RULE_IDS: &[&str] = &["shellfirm-self:agent_instructions_edit"];

/// Built-in agent-protection rules that stay on with
/// `agent.self_protection: false` (they protect the machine, or they guard
/// the analysis itself).
pub const ALWAYS_ON_BUILTIN_RULE_IDS: &[&str] = &[
    "shellfirm-self:persistence_file_edit",
    "shellfirm-self:persistence_file_write",
    "shellfirm-self:persistence_install",
    "shellfirm-self:invalid_project_policy",
    "shellfirm:input_too_large",
    "shellfirm:invalid_hook_input",
];

/// Every built-in agent-protection rule id (`shellfirm-self:*`,
/// `shellfirm:*`). The others are switched off together with
/// `agent.self_protection: false`.
pub const BUILTIN_RULE_IDS: &[&str] = &[
    "shellfirm-self:agent_hooks_bypass",
    "shellfirm-self:agent_instructions_edit",
    "shellfirm-self:audit_clear",
    "shellfirm-self:bash_hook_options",
    "shellfirm-self:bulk_rewrite_protected",
    "shellfirm-self:config_change",
    "shellfirm-self:config_env_override",
    "shellfirm-self:connect_uninstall",
    "shellfirm-self:init_uninstall",
    "shellfirm-self:install_other_version",
    "shellfirm-self:invalid_project_policy",
    "shellfirm-self:persistence_file_edit",
    "shellfirm-self:persistence_file_write",
    "shellfirm-self:persistence_install",
    "shellfirm-self:protected_file_edit",
    "shellfirm-self:protected_file_write",
    "shellfirm-self:rc_file_edit",
    "shellfirm-self:rc_hook_edit",
    "shellfirm-self:remove_zsh_hook",
    "shellfirm-self:reset_hook_arrays",
    "shellfirm-self:shadow_binary",
    "shellfirm-self:trap_debug",
    "shellfirm-self:uninstall_binary",
    "shellfirm-self:unset_hook_function",
    "shellfirm-self:zle_accept_line",
    "shellfirm:input_too_large",
    "shellfirm:invalid_hook_input",
];

/// `true` for an id of a built-in agent protection rule (`shellfirm-self:*`,
/// `shellfirm:*`) rather than a check.
#[must_use]
pub fn is_builtin_protection_id(id: &str) -> bool {
    id.starts_with("shellfirm-self:") || id.starts_with("shellfirm:")
}

/// Why `id` (a built-in agent protection id) cannot be put on the given
/// list, or `None` when it can (`list` is `ignores_patterns_ids` or
/// `deny_patterns_ids`).
#[must_use]
pub fn builtin_protection_refusal(id: &str, list: &str) -> Option<String> {
    if !is_builtin_protection_id(id) {
        return None;
    }
    let ignorable = IGNORABLE_BUILTIN_RULE_IDS.contains(&id);
    if list == "ignores_patterns_ids" && ignorable {
        return None;
    }
    let shown = crate::context::escape_invisible(id);
    if !BUILTIN_RULE_IDS.contains(&id) {
        let mut msg =
            format!("unknown check id `{shown}`: no check or built-in agent protection has it");
        if let Some(s) = suggest_similar(id, BUILTIN_RULE_IDS.iter().copied(), 1)
            .into_iter()
            .next()
        {
            msg.push_str("; did you mean `");
            msg.push_str(&s);
            msg.push_str("`?");
        }
        return Some(msg);
    }
    let mut msg = if ALWAYS_ON_BUILTIN_RULE_IDS.contains(&id) {
        format!(
            "`{shown}` is a built-in agent protection, not a check; it is always on (even with \
             `agent.self_protection: false`) and cannot be ignored or denied by id"
        )
    } else {
        format!(
            "`{shown}` is a built-in agent protection, not a check; it is controlled by \
             `agent.self_protection` in settings.yaml (`shellfirm config edit`)"
        )
    };
    if ALWAYS_ON_BUILTIN_RULE_IDS.contains(&id) {
        return Some(msg);
    }
    if list == "deny_patterns_ids" {
        msg.push_str(", and it already blocks or asks on its own");
    }
    if ignorable {
        msg.push_str("; it can only be ignored, not denied");
    } else if list == "ignores_patterns_ids" {
        msg.push_str("; the only one that can be ignored by id is ");
        msg.push_str(&IGNORABLE_BUILTIN_RULE_IDS.join(", "));
    }
    Some(msg)
}

/// What makes a context *elevated*, worded the same in `status`,
/// `config show`, the TUI and the docs.
pub const ELEVATED_CONTEXTS: &str = "SSH, or git / kubectl did not answer in time";

/// What makes a context *critical* (see [`ELEVATED_CONTEXTS`]).
pub const CRITICAL_CONTEXTS: &str = "root, production k8s / env, sensitive paths, and commands \
                                     that push to, rewrite or delete a protected branch";

/// Every check group name: built-in groups (including ones that are off by
/// default, such as `shell`) plus the groups of the given custom checks.
#[must_use]
pub fn known_groups(custom: &[checks::Check]) -> std::collections::BTreeSet<String> {
    checks::all_checks_cached()
        .iter()
        .chain(custom.iter())
        .map(|c| c.from.clone())
        .collect()
}

/// Warnings for settings entries that name an unknown check id or group.
///
/// Covers check ids in `ignores_patterns_ids`, `deny_patterns_ids` and
/// `check_escalation`, and groups in `enabled_groups`, `disabled_groups`
/// and `group_escalation`. Hand-edited files (`config edit`, baseline files
/// handed out by a team) get the same "did you mean" feedback as the CLI
/// setters: a typo in the deny list protects nobody.
///
/// Ids defined by a project policy's own `checks` are accepted too.
#[must_use]
pub fn unknown_reference_warnings(
    settings: &Settings,
    custom: &[checks::Check],
    extra_ids: &[String],
) -> Vec<String> {
    let mut ids = known_check_ids(custom);
    ids.extend(extra_ids.iter().cloned());
    let groups = known_groups(custom);
    let mut out = Vec::new();
    let id_lists: [(&str, Vec<&String>); 3] = [
        (
            "ignores_patterns_ids",
            settings.ignores_patterns_ids.iter().collect(),
        ),
        (
            "deny_patterns_ids",
            settings.deny_patterns_ids.iter().collect(),
        ),
        ("check_escalation", {
            let mut v: Vec<&String> = settings.check_escalation.keys().collect();
            v.sort();
            v
        }),
    ];
    for (key, list) in id_lists {
        for id in list {
            if key != "check_escalation" && is_builtin_protection_id(id) {
                if let Some(why) = builtin_protection_refusal(id, key) {
                    out.push(format!("`{key}`: {why} (it has no effect here)"));
                }
                continue;
            }
            if !ids.contains(id.as_str()) {
                let hint = suggest_similar(id, ids.iter().map(String::as_str), 3);
                let hint = if hint.is_empty() {
                    String::new()
                } else {
                    crate::context::escape_invisible(&format!(
                        " — did you mean {}?",
                        hint.join(", ")
                    ))
                };
                let effect = if key == "deny_patterns_ids" {
                    "it denies nothing"
                } else {
                    "it has no effect"
                };
                out.push(format!(
                    "`{key}`: unknown check id `{}` ({effect}){hint}",
                    crate::context::escape_invisible(id)
                ));
            }
        }
    }
    let group_lists: [(&str, Vec<&String>); 3] = [
        ("enabled_groups", settings.enabled_groups.iter().collect()),
        ("disabled_groups", settings.disabled_groups.iter().collect()),
        ("group_escalation", {
            let mut v: Vec<&String> = settings.group_escalation.keys().collect();
            v.sort();
            v
        }),
    ];
    for (key, list) in group_lists {
        for g in list {
            if !groups.contains(g.as_str()) {
                let hint = suggest_similar(g, groups.iter().map(String::as_str), 3);
                let hint = if hint.is_empty() {
                    String::new()
                } else {
                    crate::context::escape_invisible(&format!(
                        " — did you mean {}?",
                        hint.join(", ")
                    ))
                };
                out.push(format!(
                    "`{key}`: unknown group `{}` (it has no effect){hint}",
                    crate::context::escape_invisible(g)
                ));
            }
        }
    }
    out
}

impl Settings {
    /// Honour the per-check `challenge:` field of custom checks: each
    /// explicitly-set value becomes a floor in `check_escalation` (in memory
    /// only), so it is applied by the existing per-check escalation layer.
    /// An existing stricter `check_escalation` entry is kept.
    pub fn apply_custom_check_challenges(&mut self, explicit: &HashMap<String, Challenge>) {
        for (id, ch) in explicit {
            let entry = self.check_escalation.entry(id.clone()).or_insert(*ch);
            *entry = entry.stricter(*ch);
        }
    }

    /// Active checks for an interception, with a project policy enforced.
    ///
    /// Starts from the user-filtered set
    /// ([`Settings::get_active_checks_with_custom`]) and adds back every
    /// built-in or custom check that the policy names (`deny` or
    /// `overrides`), even when the user ignored it, disabled its group or
    /// left it out of `enabled_groups`. Policy-defined `checks` are matched
    /// separately by the pipeline and are not included here.
    ///
    /// # Errors
    /// Propagates errors from [`Settings::get_active_checks_with_custom`].
    pub fn get_active_checks_enforced(
        &self,
        custom: &[checks::Check],
        policy: Option<&crate::policy::ProjectPolicy>,
    ) -> Result<Vec<checks::Check>> {
        let mut out = self.get_active_checks_with_custom(custom)?;
        let Some(policy) = policy else {
            return Ok(out);
        };
        let named = policy.referenced_check_ids();
        if named.is_empty() {
            return Ok(out);
        }
        let present: HashSet<String> = out.iter().map(|c| c.id.clone()).collect();
        let policy_own: HashSet<&str> = policy.checks.iter().map(|c| c.id.as_str()).collect();
        for c in checks::all_checks_cached().iter().chain(custom.iter()) {
            if named.contains(&c.id)
                && !present.contains(&c.id)
                && !policy_own.contains(c.id.as_str())
            {
                out.push(c.clone());
            }
        }
        Ok(out)
    }
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
        // settings.yaml plus the `.settings.lock` sidecar.
        let files: Vec<String> = read_dir(&config.root_folder)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .filter(|n| n != ".settings.lock")
            .collect();
        assert_eq!(files, vec!["settings.yaml".to_string()]);
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
        let mapping = root.as_mapping().expect("should be a Mapping, not Null");
        assert!(mapping.is_empty());
        // Verify value_set succeeds on the result
        let mut root = root;
        value_set(
            &mut root,
            "challenge",
            serde_yaml::Value::String("Enter".into()),
        )
        .unwrap();
        assert_eq!(root.get("challenge").unwrap().as_str().unwrap(), "Enter");
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
        assert!(matches!(
            a.min_severity,
            InheritOr::Set(Some(Severity::Low))
        ));
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
        assert!(matches!(
            w.min_severity,
            InheritOr::Set(Some(Severity::High))
        ));
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
        assert_eq!(r_shell.severity_escalation.high, Challenge::Math); // default
    }

    // -------------------------------------------------------------------
    // Phase 1: get_active_checks_with_custom + migrate_custom_groups
    // -------------------------------------------------------------------

    #[test]
    fn get_active_checks_with_custom_excludes_disabled_custom_group() {
        use crate::checks::Check;
        use regex::Regex;

        let mut s = Settings::default();
        s.enabled_groups = vec!["git".into()]; // explicitly NOT including "my_team"
        let custom = vec![Check {
            id: "my_team:thing".into(),
            test: Regex::new("foo").unwrap().into(),
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
            test: Regex::new("foo").unwrap().into(),
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
            test: Regex::new("foo").unwrap().into(),
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
            test: Regex::new("x").unwrap().into(),
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
            test: Regex::new("x").unwrap().into(),
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
            test: Regex::new("x").unwrap().into(),
            description: "x".into(),
            from: "my_team".into(),
            challenge: Challenge::Math,
            filters: vec![],
            alternative: None,
            alternative_info: None,
            severity: Severity::Medium,
        }];
        let added = s.migrate_custom_groups_into_enabled_groups(&custom);
        assert!(added.is_empty()); // user explicitly disabled — leave alone
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
mod test_loading {
    use super::*;

    fn config_in(tree: &tree_fs::Tree) -> Config {
        Config::new(Some(&tree.root.join("app").display().to_string())).unwrap()
    }

    #[test]
    fn strict_load_reports_file_and_line_and_never_writes() {
        let tree = tree_fs::TreeBuilder::default()
            .add(
                "app/settings.yaml",
                "deny_patterns_ids: [git:force_push]\nchallenge: Banana\n",
            )
            .create()
            .unwrap();
        let config = config_in(&tree);
        let err = config.get_settings_from_file().unwrap_err().to_string();
        assert!(err.contains("settings.yaml"), "{err}");
        assert!(err.contains("line 2"), "{err}");
        let (lenient, e) = config.load_settings_lenient();
        assert!(e.is_some());
        // valid keys are kept, the invalid one falls back to its default
        assert_eq!(
            lenient.deny_patterns_ids,
            vec!["git:force_push".to_string()]
        );
        assert_eq!(lenient.challenge, Challenge::default());
        assert_eq!(
            config.read_config_file().unwrap(),
            "deny_patterns_ids: [git:force_push]\nchallenge: Banana\n"
        );
    }

    #[test]
    fn wrong_type_and_garbage_are_errors() {
        assert!(parse_settings_strict("disabled_groups: git\n").is_err());
        assert!(parse_settings_strict("::: [").is_err());
        assert!(parse_settings_strict("- a\n- b\n").is_err());
        assert!(parse_settings_strict("").is_ok());
        assert!(parse_settings_strict("# comment only\n").is_ok());
        let (s, dropped) = parse_settings_lenient("disabled_groups: git\nmin_severity: High\n");
        assert_eq!(dropped.len(), 1);
        assert_eq!(s.min_severity, Some(Severity::High));
        assert!(s.disabled_groups.is_empty());
    }

    #[test]
    fn unknown_keys_are_detected() {
        let u = unknown_settings_keys("deny_pattern_ids: [x]\nchallenge: Yes\n");
        assert_eq!(u, vec!["deny_pattern_ids".to_string()]);
    }

    #[test]
    fn save_refuses_to_overwrite_invalid_yaml() {
        let tree = tree_fs::TreeBuilder::default()
            .add("app/settings.yaml", "::: [ broken")
            .create()
            .unwrap();
        let config = config_in(&tree);
        assert!(config
            .save_settings_file_from_struct(&Settings::default())
            .is_err());
        assert_eq!(config.read_config_file().unwrap(), "::: [ broken");
    }

    #[cfg(unix)]
    #[test]
    fn save_refuses_read_only_file() {
        use std::os::unix::fs::PermissionsExt;
        let tree = tree_fs::TreeBuilder::default()
            .add("app/settings.yaml", "challenge: Yes\n")
            .create()
            .unwrap();
        let config = config_in(&tree);
        fs::set_permissions(&config.setting_file_path, fs::Permissions::from_mode(0o444)).unwrap();
        let err = config
            .save_settings_file_from_struct(&Settings::default())
            .unwrap_err()
            .to_string();
        assert!(err.contains("read-only"), "{err}");
    }

    #[test]
    fn custom_checks_bad_file_does_not_drop_others() {
        let tree = tree_fs::TreeBuilder::default()
            .add(
                "checks/team.yaml",
                "- id: team:deploy\n  from: team\n  test: deploy\n  description: d\n  challenge: Yes\n- id: team:other\n  from: team\n  test: other\n  description: d\n",
            )
            .add("checks/broken.yaml", "- id: b:x\n  from: b\n  test: 'foo(('\n  description: d\n")
            .add("checks/mapping.yml", "id: m:x\n")
            .add(
                "checks/dups.yaml",
                "- id: git:force_push\n  from: git\n  test: x\n  description: d\n- id: team:deploy\n  from: team\n  test: y\n  description: d\n",
            )
            .add("checks/README.md", "not yaml")
            .create()
            .unwrap();
        let load = load_custom_checks_report(&tree.root.join("checks"));
        let ids: Vec<&str> = load.checks.iter().map(|c| c.id.as_str()).collect();
        // dups.yaml sorts before team.yaml, so its team:deploy wins
        assert!(ids.contains(&"team:deploy"));
        assert!(ids.contains(&"team:other"));
        assert!(!ids.contains(&"git:force_push"));
        assert_eq!(load.checks.len(), 2, "{ids:?}");
        assert!(load.warnings.iter().any(|w| w.contains("broken.yaml")));
        assert!(load.warnings.iter().any(|w| w.contains("mapping.yml")));
        assert!(load.warnings.iter().any(|w| w.contains("built-in")));
        assert!(load.warnings.iter().any(|w| w.contains("duplicate")));
    }

    #[test]
    fn custom_check_explicit_challenge_becomes_check_escalation_floor() {
        let tree = tree_fs::TreeBuilder::default()
            .add(
                "checks/team.yaml",
                "- id: team:a\n  from: team\n  test: a\n  description: d\n  challenge: Yes\n- id: team:b\n  from: team\n  test: b\n  description: d\n",
            )
            .create()
            .unwrap();
        let load = load_custom_checks_report(&tree.root.join("checks"));
        assert_eq!(
            load.explicit_challenges.get("team:a"),
            Some(&Challenge::Yes)
        );
        assert!(!load.explicit_challenges.contains_key("team:b"));
        let mut s = Settings::default();
        s.apply_custom_check_challenges(&load.explicit_challenges);
        assert_eq!(s.check_escalation.get("team:a"), Some(&Challenge::Yes));
    }

    #[test]
    fn policy_named_checks_survive_personal_filters() {
        let policy = crate::policy::parse_policy("version: 1\ndeny: [git:force_push]\n").unwrap();
        for s in [
            Settings {
                ignores_patterns_ids: vec!["git:force_push".into()],
                ..Settings::default()
            },
            Settings {
                disabled_groups: vec!["git".into()],
                ..Settings::default()
            },
            Settings {
                enabled_groups: vec!["fs".into()],
                ..Settings::default()
            },
        ] {
            let checks = s.get_active_checks_enforced(&[], Some(&policy)).unwrap();
            assert!(checks.iter().any(|c| c.id == "git:force_push"));
            let without = s.get_active_checks_enforced(&[], None).unwrap();
            assert!(!without.iter().any(|c| c.id == "git:force_push"));
        }
    }

    #[test]
    fn known_groups_include_off_by_default_groups() {
        assert!(known_groups(&[]).contains("shell"));
    }

    #[test]
    fn backup_copies_file() {
        let tree = tree_fs::TreeBuilder::default()
            .add("app/settings.yaml", "challenge: Yes\n")
            .create()
            .unwrap();
        let config = config_in(&tree);
        let b = config.backup_settings_file().unwrap().unwrap();
        assert_eq!(fs::read_to_string(b).unwrap(), "challenge: Yes\n");
    }

    #[test]
    fn llm_config_validation() {
        assert!(LlmConfig::default().validate().is_ok());
        let bad = LlmConfig {
            provider: "nope".into(),
            ..LlmConfig::default()
        };
        assert!(bad.validate().is_err());
        let bad = LlmConfig {
            base_url: Some("ftp://x".into()),
            ..LlmConfig::default()
        };
        assert!(bad.validate().is_err());
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
        // Derived from DEFAULT_ENABLED_GROUPS so adding a group only needs
        // that list (and the `config reset` snapshot) updated.
        let groups = Settings::default().get_active_groups().clone();
        assert_eq!(groups, DEFAULT_ENABLED_GROUPS.to_vec());
        let tree = tree_fs::TreeBuilder::default().create().unwrap();
        let config = Config::new(Some(&tree.root.display().to_string())).unwrap();
        fs::write(&config.setting_file_path, "challenge: Yes\n").unwrap();
        let from_file = config.get_settings_from_file().unwrap();
        assert_eq!(from_file.challenge, Challenge::Yes);
        assert_eq!(from_file.enabled_groups, DEFAULT_ENABLED_GROUPS.to_vec());
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

    #[test]
    fn lenient_parse_keeps_valid_siblings() {
        let (s, dropped) = parse_settings_lenient(
            "agent:\n  auto_deny_severity: Low\n  challenge: Banana\ncontext:\n  escalation:\n    elevated: Nope\n    critical: Enter\n",
        );
        assert_eq!(s.agent.auto_deny_severity, Severity::Low);
        assert_eq!(s.context.escalation.critical, Challenge::Enter);
        assert_eq!(dropped.len(), 2, "{dropped:?}");
        assert!(
            dropped.iter().any(|d| d.contains("agent.challenge")),
            "{dropped:?}"
        );
    }

    #[test]
    fn nested_unknown_keys_are_reported_with_suggestions() {
        let w = unknown_settings_key_warnings(
            "agent:\n  auto_deny_severty: Low\nchalenge: Yes\ngroup_escalation:\n  anything: Math\nwrappers:\n  tools:\n    psql:\n      delimter: ';'\n",
        );
        assert_eq!(w.len(), 3, "{w:?}");
        assert!(w
            .iter()
            .any(|x| x.contains("agent.auto_deny_severty") && x.contains("auto_deny_severity")));
        assert!(w
            .iter()
            .any(|x| x.contains("`chalenge`") && x.contains("`challenge`")));
        assert!(w.iter().any(|x| x.contains("wrappers.tools.psql.delimter")));
    }

    #[test]
    fn duplicate_key_error_has_a_line_number() {
        let err = parse_settings_strict("challenge: Math\nmin_severity: High\nchallenge: Yes\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("line 3"), "{err}");
    }

    #[test]
    fn personal_deny_beats_personal_ignore() {
        let s = Settings {
            ignores_patterns_ids: vec!["git:reset".into()],
            deny_patterns_ids: vec!["git:reset".into()],
            ..Settings::default()
        };
        assert!(s
            .get_active_checks()
            .unwrap()
            .iter()
            .any(|c| c.id == "git:reset"));
        assert!(s
            .get_active_checks_with_custom(&[])
            .unwrap()
            .iter()
            .any(|c| c.id == "git:reset"));
        assert_eq!(s.ignore_deny_conflicts(), vec!["git:reset".to_string()]);
    }

    #[test]
    fn nested_sparse_write_and_comments_are_kept() {
        let tree = tree_fs::TreeBuilder::default().create().unwrap();
        let config = Config::new(Some(&tree.root.join("app").display().to_string())).unwrap();
        fs::create_dir_all(&config.root_folder).unwrap();
        fs::write(
            &config.setting_file_path,
            "# ACME team baseline\n# keep me\n\n# the challenge\nchallenge: Yes\n",
        )
        .unwrap();
        config
            .modify_settings(|s| {
                s.context.protected_branches.push("develop".into());
                Ok(((), true))
            })
            .unwrap();
        let text = fs::read_to_string(&config.setting_file_path).unwrap();
        assert!(
            text.starts_with("# ACME team baseline\n# keep me\n"),
            "{text}"
        );
        assert!(text.contains("# the challenge\nchallenge: Yes"), "{text}");
        assert!(text.contains("develop"));
        assert!(
            !text.contains("production_k8s_patterns"),
            "whole context block written:\n{text}"
        );
        assert!(!text.contains("escalation"), "{text}");
        // Removing an entry from a free-form map removes it on disk.
        config
            .modify_settings(|s| {
                s.group_escalation.insert("git".into(), Challenge::Yes);
                Ok(((), true))
            })
            .unwrap();
        config
            .modify_settings(|s| {
                s.group_escalation.clear();
                Ok(((), true))
            })
            .unwrap();
        let s = config.get_settings_from_file().unwrap();
        assert!(s.group_escalation.is_empty());
    }

    #[test]
    fn config_dir_env_value_is_validated() {
        let tree = tree_fs::TreeBuilder::default()
            .add("file", "x")
            .create()
            .unwrap();
        assert!(config_dir_from_env(None).unwrap().is_none());
        assert!(config_dir_from_env(Some("  ")).unwrap().is_none());
        let dir = tree.root.display().to_string();
        assert_eq!(
            config_dir_from_env(Some(&format!(" {dir} "))).unwrap(),
            Some(tree.root.clone())
        );
        let e = config_dir_from_env(Some(&tree.root.join("file").display().to_string()))
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("SHELLFIRM_CONFIG_DIR") && e.contains("not a directory"),
            "{e}"
        );
        let e = config_dir_from_env(Some(&tree.root.join("nope").display().to_string()))
            .unwrap_err()
            .to_string();
        assert!(e.contains("no such directory"), "{e}");
    }

    #[test]
    fn keys_back_at_their_defaults_are_removed() {
        let tree = tree_fs::TreeBuilder::default().create().unwrap();
        let config = Config::new(Some(&tree.root.join("app").display().to_string())).unwrap();
        fs::create_dir_all(&config.root_folder).unwrap();
        fs::write(&config.setting_file_path, "audit_enabled: true\n").unwrap();
        let edit = |f: &dyn Fn(&mut Settings)| {
            config
                .modify_settings(|s| {
                    f(s);
                    Ok(((), true))
                })
                .unwrap();
        };
        // Adding an env var keeps the default ones (the map is written whole).
        edit(&|s| {
            s.context
                .production_env_vars
                .insert("STAGE".into(), "prod".into());
        });
        let loaded = config.get_settings_from_file().unwrap();
        assert!(loaded.context.production_env_vars.contains_key("STAGE"));
        assert!(loaded.context.production_env_vars.contains_key("NODE_ENV"));
        edit(&|s| {
            s.context.production_env_vars.remove("STAGE");
        });
        edit(&|s| s.context.protected_branches.push("hotfix/*".into()));
        edit(&|s| s.context.protected_branches.retain(|b| b != "hotfix/*"));
        edit(&|s| s.context.production_k8s_patterns.push("staging".into()));
        edit(&|s| s.context.production_k8s_patterns.retain(|b| b != "staging"));
        let text = fs::read_to_string(&config.setting_file_path).unwrap();
        assert!(!text.contains("context"), "{text}");
        assert!(text.contains("audit_enabled: true"), "{text}");
        // An LLM section with only default values names its provider
        // instead of `llm: {}` (the section's presence turns the LLM on).
        edit(&|s| s.llm = Some(LlmConfig::default()));
        let text = fs::read_to_string(&config.setting_file_path).unwrap();
        assert!(!text.contains("llm: {}"), "{text}");
        assert!(text.contains("provider:"), "{text}");
        assert!(config.get_settings_from_file().unwrap().llm.is_some());
    }

    #[test]
    fn parallel_modifications_keep_every_update() {
        let tree = tree_fs::TreeBuilder::default().create().unwrap();
        let config = std::sync::Arc::new(
            Config::new(Some(&tree.root.join("app").display().to_string())).unwrap(),
        );
        let ids: Vec<String> = checks::all_checks_cached()
            .iter()
            .take(30)
            .map(|c| c.id.clone())
            .collect();
        let handles: Vec<_> = ids
            .iter()
            .cloned()
            .map(|id| {
                let config = config.clone();
                std::thread::spawn(move || {
                    config
                        .modify_settings(|s| {
                            s.deny_patterns_ids.push(id);
                            Ok(((), true))
                        })
                        .unwrap();
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let s = config.get_settings_from_file().unwrap();
        assert_eq!(s.deny_patterns_ids.len(), ids.len());
    }

    #[test]
    fn backups_are_pruned() {
        let tree = tree_fs::TreeBuilder::default().create().unwrap();
        let config = Config::new(Some(&tree.root.join("app").display().to_string())).unwrap();
        fs::create_dir_all(&config.root_folder).unwrap();
        fs::write(&config.setting_file_path, "challenge: Yes\n").unwrap();
        for _ in 0..6 {
            config.backup_settings_file().unwrap();
        }
        let n = fs::read_dir(&config.root_folder)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains(".bak.")
            })
            .count();
        assert_eq!(n, MAX_SETTINGS_BACKUPS);
    }

    #[test]
    fn suggestions_find_the_obvious_id() {
        let ids = [
            "git:force_push",
            "git:force_checkout",
            "docker:force_remove_images",
            "git:clean_force",
        ];
        assert_eq!(
            suggest_similar("git:forcepush", ids, 3)
                .first()
                .map(String::as_str),
            Some("git:force_push")
        );
        assert_eq!(
            suggest_similar("shel", ["shell", "fs", "git"], 3),
            vec!["shell".to_string()]
        );
        assert!(suggest_similar("zzzz", ["shell", "git"], 3).is_empty());
    }

    #[test]
    fn custom_check_text_is_sanitized_and_unknown_keys_warned() {
        let tree = tree_fs::TreeBuilder::default()
            .add(
                "checks/team.yaml",
                "- id: team:x\n  from: team\n  test: tx\n  description: \"ok\\nshellfirm: ALLOWED\"\n  severty: Critical\n",
            )
            .create()
            .unwrap();
        let r = load_custom_checks_report(&tree.root.join("checks"));
        assert_eq!(r.checks.len(), 1);
        assert_eq!(r.checks[0].description, "ok shellfirm: ALLOWED");
        assert!(
            r.warnings
                .iter()
                .any(|w| w.contains("severty") && w.contains("severity")),
            "{:?}",
            r.warnings
        );
        assert!(
            r.warnings.iter().any(|w| w.contains("removed newlines")),
            "{:?}",
            r.warnings
        );
        // Joiners are text (Persian ZWNJ, emoji ZWJ): kept, no warning. A
        // bidi control is removed and named.
        let tree = tree_fs::TreeBuilder::default()
            .add(
                "checks/team.yaml",
                concat!(
                    r#"- id: team:fa
  from: team
  test: tx
  description: "\u0645\u06cc\u200c\u06a9\u0646\u062f \U0001F469\u200d\U0001F4BB"
"#,
                    r#"- id: team:bidi
  from: team
  test: ty
  description: "a\u202eb"
"#
                ),
            )
            .create()
            .unwrap();
        let r = load_custom_checks_report(&tree.root.join("checks"));
        assert_eq!(
            r.checks[0].description,
            "\u{645}\u{6cc}\u{200c}\u{6a9}\u{646}\u{62f} \u{1F469}\u{200d}\u{1F4BB}"
        );
        assert_eq!(r.checks[1].description, "ab");
        assert_eq!(r.warnings.len(), 1, "{:?}", r.warnings);
        assert!(r.warnings[0].contains("team:bidi") && r.warnings[0].contains("U+202E"));
    }

    #[test]
    fn custom_check_ids_and_empty_alternatives_are_validated() {
        let tree = tree_fs::TreeBuilder::default()
            .add(
                "checks/team.yaml",
                "- id: \"mine:b\\u202ex\"\n  from: mine\n  test: zzqq\n  description: d\n\
                 - id: \"team:Bad Id\"\n  from: team\n  test: zzbad\n  description: d\n\
                 - id: team:Upper\n  from: team\n  test: zzup\n  description: d\n  alternative: \"\"\n  alternative_info: \"  \"\n\
                 - id: team:ok\n  from: team\n  test: zzok\n  description: d\n",
            )
            .add("checks/sub/more.yaml", "- id: team:sub\n  from: team\n  test: zzsub\n  description: d\n")
            .create()
            .unwrap();
        let r = load_custom_checks_report(&tree.root.join("checks"));
        let ids: Vec<&str> = r.checks.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, vec!["team:Upper", "team:ok"], "{:?}", r.warnings);
        let all = r.warnings.join("\n");
        assert!(
            all.contains("mine:b\\u{202e}x") && !all.contains('\u{202e}'),
            "{all}"
        );
        assert!(all.contains("team:Bad Id"), "{all}");
        assert!(all.contains("id `team:Upper` should be lowercase"), "{all}");
        assert!(all.contains("empty `alternative` is ignored"), "{all}");
        assert!(all.contains("empty `alternative_info` is ignored"), "{all}");
        assert!(all.contains("subdirectory ignored"), "{all}");
        let upper = r.checks.iter().find(|c| c.id == "team:Upper").unwrap();
        assert!(upper.alternative.is_none() && upper.alternative_info.is_none());
        assert!(check_id_format_problem("fs-strict:any_deletion").is_none());
        assert!(check_id_format_problem("nomad").is_some());
    }

    #[test]
    fn a_custom_alternative_that_triggers_a_built_in_is_reported() {
        let tree = tree_fs::TreeBuilder::default()
            .add(
                "checks/team.yaml",
                "- id: team:wipe\n  from: team\n  test: \"wipe\\\\s+cache\"\n  description: d\n  severity: Medium\n  alternative: \"rm -rf ~\"\n\
                 - id: team:fine\n  from: team\n  test: zzfine\n  description: d\n  severity: Critical\n  alternative: \"git status\"\n\
                 - id: team:lower\n  from: team\n  test: zzlow\n  description: d\n  severity: Critical\n  alternative: \"git stash clear\"\n",
            )
            .create()
            .unwrap();
        let r = load_custom_checks_report(&tree.root.join("checks"));
        assert_eq!(r.checks.len(), 3, "{:?}", r.warnings);
        let all = r.warnings.join("\n");
        assert!(
            all.contains("check `team:wipe`") && all.contains("alternative `rm -rf ~` triggers"),
            "{all}"
        );
        assert!(!all.contains("team:fine"), "{all}");
        // A less severe built-in is fine (as for the built-in checks).
        assert!(!all.contains("team:lower"), "{all}");
    }

    #[test]
    fn group_typos_get_a_suggestion() {
        // A transposition (`gti`) suggests `git`.
        let m = unknown_group_message("gti", ["git", "fs", "aws"]);
        assert!(m.contains("Did you mean: git?"), "{m}");
        assert!(m.starts_with("unknown check group 'gti'."), "{m}");
    }

    #[test]
    fn custom_path_exists_out_of_range_is_warned() {
        let tree = tree_fs::TreeBuilder::default()
            .add(
                "checks/50-path.yaml",
                "- id: team:path\n  from: team\n  test: \"zap\\\\s+(\\\\S+)\"\n  description: x\n  filters: [{type: PathExists, value: 3}]\n- id: team:ok\n  from: team\n  test: \"zop\\\\s+(\\\\S+)\"\n  description: y\n  filters: [{type: PathExists, value: 1}]\n",
            )
            .create()
            .unwrap();
        let r = load_custom_checks_report(&tree.root.join("checks"));
        assert_eq!(r.checks.len(), 2);
        let w: Vec<&String> = r
            .warnings
            .iter()
            .filter(|w| w.contains("PathExists"))
            .collect();
        assert_eq!(w.len(), 1, "{:?}", r.warnings);
        assert!(w[0].contains("team:path") && w[0].contains("group 3") && w[0].contains("has 1"));
    }

    #[test]
    fn a_huge_impact_budget_is_capped_with_a_warning() {
        let s = parse_settings_strict("blast_radius_budget_ms: 600000\n").unwrap();
        assert_eq!(s.blast_radius_budget(), MAX_BLAST_RADIUS_BUDGET_MS);
        let temp = tree_fs::TreeBuilder::default().create().unwrap();
        let config = Config::new(Some(&temp.root.display().to_string())).unwrap();
        std::fs::write(
            &config.setting_file_path,
            "blast_radius_budget_ms: 600000\n",
        )
        .unwrap();
        assert!(config
            .settings_warnings()
            .iter()
            .any(|w| w.contains("blast_radius_budget_ms: 600000") && w.contains("capped at 5000")));
        std::fs::write(&config.setting_file_path, "blast_radius_budget_ms: 5000\n").unwrap();
        assert!(config.settings_warnings().is_empty());
    }

    #[test]
    fn audit_max_files_zero_is_rejected_and_never_used() {
        // Not a fatal error (read-only views keep working): the default is
        // used and a warning is reported.
        let s = parse_settings_strict("audit_max_files: 0\n").unwrap();
        assert_eq!(s.audit_max_files, crate::audit::DEFAULT_MAX_AUDIT_FILES);
        let dir = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let config = Config::new(Some(&dir.root.display().to_string())).unwrap();
        std::fs::write(&config.setting_file_path, "audit_max_files: 0\n").unwrap();
        assert!(config
            .settings_warnings()
            .iter()
            .any(|w| w.contains("audit_max_files") && w.contains("default is used")));
        let (s, dropped) = parse_settings_lenient("audit_max_files: 0\nchallenge: Yes\n");
        assert_eq!(s.audit_max_files, crate::audit::DEFAULT_MAX_AUDIT_FILES);
        assert_eq!(s.challenge, Challenge::Yes);
        assert!(dropped.iter().any(|d| d.contains("audit_max_files")));
        assert_eq!(
            parse_settings_strict("audit_max_files: 2\n")
                .unwrap()
                .audit_max_files,
            2
        );
    }

    #[test]
    fn unknown_ids_and_groups_in_the_file_are_warned() {
        let s = parse_settings_strict(
            "deny_patterns_ids: [git:resett]\nignores_patterns_ids: [git:reset]\n\
             enabled_groups: [gti, git]\ndisabled_groups: [herok]\n\
             check_escalation: {git:forse_push: Yes}\ngroup_escalation: {kube: Yes}\n",
        )
        .unwrap();
        let w = unknown_reference_warnings(&s, &[], &[]);
        assert_eq!(w.len(), 5, "{w:?}");
        assert!(w.iter().any(|m| m.contains("git:resett")
            && m.contains("deny_patterns_ids")
            && m.contains("git:reset")));
        assert!(w
            .iter()
            .any(|m| m.contains("`enabled_groups`: unknown group `gti`")));
        assert!(w
            .iter()
            .any(|m| m.contains("herok") && m.contains("heroku")));
        assert!(w.iter().any(|m| m.contains("git:forse_push")));
        assert!(w.iter().any(|m| m.contains("`kube`")));
        // Defaults, and policy-defined ids, are fine.
        assert!(unknown_reference_warnings(&Settings::default(), &[], &[]).is_empty());
        let p = parse_settings_strict("ignores_patterns_ids: [team:pol]\n").unwrap();
        assert!(unknown_reference_warnings(&p, &[], &["team:pol".to_string()]).is_empty());
    }

    #[test]
    fn color_and_locale_rules() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                pairs
                    .iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| (*v).to_string())
            }
        };
        assert_eq!(color_preference(env(&[])), None);
        assert_eq!(color_preference(env(&[("NO_COLOR", "")])), None);
        assert_eq!(color_preference(env(&[("NO_COLOR", "1")])), Some(false));
        assert_eq!(color_preference(env(&[("CLICOLOR", "0")])), Some(false));
        assert_eq!(color_preference(env(&[("TERM", "dumb")])), Some(false));
        assert_eq!(color_preference(env(&[("TERM", "vt100")])), Some(false));
        assert_eq!(
            color_preference(env(&[("TERM", "xterm-mono")])),
            Some(false)
        );
        assert_eq!(color_preference(env(&[("TERM", "VT220")])), Some(false));
        assert_eq!(color_preference(env(&[("TERM", "")])), Some(false));
        assert_eq!(color_preference(env(&[("TERM", "xterm-256color")])), None);
        assert_eq!(
            color_preference(env(&[("NO_COLOR", "1"), ("CLICOLOR_FORCE", "1")])),
            Some(true)
        );
        assert!(unicode_locale(env(&[])));
        assert!(unicode_locale(env(&[("LANG", "en_US.UTF-8")])));
        assert!(!unicode_locale(env(&[
            ("LC_ALL", "C"),
            ("LANG", "en_US.UTF-8")
        ])));
        assert!(unicode_locale(env(&[("LC_ALL", ""), ("LANG", "C.utf8")])));
    }

    #[test]
    fn reset_header_only_file_is_not_backed_up() {
        let tree = tree_fs::TreeBuilder::default().create().unwrap();
        let config = Config::new(Some(&tree.root.join("app").display().to_string())).unwrap();
        config.reset_config().unwrap();
        assert!(config.backup_settings_file().unwrap().is_none());
        fs::write(&config.setting_file_path, "challenge: Yes\n").unwrap();
        assert!(config.backup_settings_file().unwrap().is_some());
    }
}
