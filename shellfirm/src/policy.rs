//! Project-level policies (`.shellfirm.yaml`) and the optional org policy.
//!
//! A `.shellfirm.yaml` file committed to a repository lets teams codify
//! safety rules that travel with the code. Policies are **additive only and
//! enforced**:
//!
//! - `deny` ids are always blocked, and `checks` / `overrides` always apply,
//!   even if the developer's personal settings ignore the check, disable its
//!   group, leave it out of `enabled_groups`, or set a higher `min_severity`.
//! - `overrides` can only make a challenge stricter, never weaker.
//! - `context` entries are added to the developer's own context settings.
//!
//! There is no user-side switch that turns a policy off. A developer who
//! disagrees with a rule must change the policy file itself (which is
//! visible in code review).
//!
//! # Discovery
//!
//! 1. **Org policy** (optional): `/etc/shellfirm/policy.yaml` (on Windows
//!    `%ProgramData%\shellfirm\policy.yaml`), plus the file named by
//!    `SHELLFIRM_ORG_POLICY` when that variable is set. The variable can only
//!    *add* a file — it never replaces or hides the system-wide one, so it
//!    cannot weaken anything; it must be an absolute path (a relative one is
//!    reported as not applied). Org policies apply everywhere, inside and
//!    outside repositories, and are merged first (outermost). An org file
//!    the current (non-root) user can write is reported as a warning.
//! 2. **Repository policies**: starting at the current directory, every
//!    `.shellfirm.yaml` (or `.shellfirm.yml`) found while walking up is
//!    loaded, up to and including the **outermost** enclosing repository
//!    root. Nested repositories (git submodules and worktrees whose `.git`
//!    is a file, vendored clones, empty or bare `.git` directories) do not
//!    stop the walk, so a submodule inherits the superproject's policy and
//!    `mkdir .git` cannot escape it. Outside any repository the walk
//!    continues to the filesystem root.
//!
//! All the files are merged: the outermost file first, nested files add to
//! it. A nested policy can never remove what a parent policy declares.
//!
//! A command that targets another directory (`git -C X`, `cd X && …`,
//! `terraform -chdir=X`) should be checked against [`discover_for`], the
//! union of the policies of the current directory and of the targets.
//!
//! # Validation
//!
//! Runtime loading, `shellfirm status` and `shellfirm policy validate` use
//! the same code ([`load_policy_text`]), so they always agree:
//!
//! - Fatal problems (invalid YAML, missing or unsupported `version`) mean
//!   the file is **not applied** ([`PolicyDiscovery::errors`]).
//! - Everything else is applied as far as possible (a policy only ever makes
//!   things stricter, so applying the valid parts is the safe choice) and
//!   reported as an error ([`PolicyDiscovery::problems`]): unknown keys,
//!   unknown / wildcard / group-name ids in `deny` and `overrides`, checks
//!   that shadow a built-in id (dropped), duplicate check ids (dropped),
//!   invalid individual checks (dropped), and control characters in
//!   descriptions (stripped).
//! - Ids are validated against the built-in catalog plus the policy's own
//!   `checks` only — never against a developer's personal custom checks —
//!   so a policy is valid or invalid identically on every machine and in CI.
//!
//! Agent integrations that must fail closed can use [`load`], which returns
//! a [`PolicyLoad`] with every error and warning in one place.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

use crate::error::{Error, Result};
use serde_derive::{Deserialize, Serialize};
use tracing::debug;

use crate::{
    checks::{self, Check},
    config::{Challenge, Settings},
    context::ContextConfig,
    env::Environment,
};

/// The canonical filename searched for when walking up directories.
pub const POLICY_FILENAME: &str = ".shellfirm.yaml";

/// Alternative filename that is also recognised.
pub const POLICY_FILENAME_ALT: &str = ".shellfirm.yml";

/// The only policy schema version this build understands.
pub const SUPPORTED_POLICY_VERSION: u32 = 1;

/// System-wide org policy path.
#[cfg(not(windows))]
pub const ORG_POLICY_PATH: &str = "/etc/shellfirm/policy.yaml";

/// Environment variable naming an *additional* org policy file.
pub const ORG_POLICY_ENV: &str = "SHELLFIRM_ORG_POLICY";

/// Maximum length (in characters) of policy / custom-check text shown to
/// humans and agents. Longer text is truncated when loaded.
pub const MAX_UNTRUSTED_TEXT_CHARS: usize = 500;

/// A project-level policy loaded from `.shellfirm.yaml`.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct ProjectPolicy {
    /// Schema version (currently `1`). Required field.
    pub version: u32,
    /// Additional check patterns specific to this project.
    #[serde(default, deserialize_with = "null_as_default")]
    pub checks: Vec<Check>,
    /// Challenge overrides (escalations) for existing patterns.
    #[serde(default, deserialize_with = "null_as_default")]
    pub overrides: Vec<Override>,
    /// Pattern IDs that are unconditionally denied in this project.
    #[serde(default, deserialize_with = "null_as_default")]
    pub deny: Vec<String>,
    /// Project-specific context configuration (added to the user's own).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<PolicyContext>,
    /// Policy `checks` whose YAML explicitly set `challenge:` (id → floor).
    /// Filled by [`parse_policy`]; not part of the file format.
    #[serde(skip)]
    pub explicit_check_challenges: HashMap<String, Challenge>,
    /// Files this (merged) policy was loaded from, outermost first. Filled
    /// by discovery; not part of the file format.
    #[serde(skip)]
    pub sources: Vec<PathBuf>,
    /// The org-level files among [`Self::sources`] (`/etc/shellfirm/policy.yaml`,
    /// `SHELLFIRM_ORG_POLICY`). Filled by discovery.
    #[serde(skip)]
    pub org_sources: Vec<PathBuf>,
    /// For every id the policy names (`deny`, `overrides`, own `checks`),
    /// the files that name it, outermost first. Filled by discovery.
    #[serde(skip)]
    pub id_sources: BTreeMap<String, Vec<PathBuf>>,
    /// The files whose `context:` section has an effect (see
    /// [`PolicyContext::has_effect`]), outermost first. Filled by discovery.
    #[serde(skip)]
    pub context_sources: Vec<PathBuf>,
}

/// Treat an explicit YAML `null` (e.g. `deny:` with every item commented
/// out) the same as a missing key.
fn null_as_default<'de, D, T>(de: D) -> std::result::Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Default + serde::Deserialize<'de>,
{
    Ok(<Option<T> as serde::Deserialize>::deserialize(de)?.unwrap_or_default())
}

/// A challenge override (escalation) for a single pattern in this project.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Override {
    /// The pattern ID to override (e.g. `"git:force_push"`).
    pub id: String,
    /// The minimum challenge (only applied if stricter than the current one).
    #[serde(default)]
    pub challenge: Option<Challenge>,
    /// Optional: only apply this override when on specific branches.
    #[serde(default)]
    pub on_branches: Option<Vec<String>>,
}

/// Context settings a policy can add. Every list is **added** to the user's
/// own list; escalation values only apply when stricter.
#[derive(Debug, Deserialize, Serialize, Clone, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyContext {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protected_branches: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub production_k8s_patterns: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub production_env_vars: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sensitive_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escalation: Option<PolicyEscalation>,
}

/// Context escalation floors a policy can set.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyEscalation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elevated: Option<Challenge>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub critical: Option<Challenge>,
}

impl ProjectPolicy {
    /// Ids of existing (built-in or custom) checks this policy names in
    /// `deny` or `overrides`. These checks are enforced regardless of the
    /// user's personal filters.
    #[must_use]
    pub fn referenced_check_ids(&self) -> HashSet<String> {
        self.deny
            .iter()
            .cloned()
            .chain(self.overrides.iter().map(|o| o.id.clone()))
            .collect()
    }

    /// Every id this policy enforces: `deny`, `overrides` and its own
    /// `checks`.
    #[must_use]
    pub fn enforced_ids(&self) -> HashSet<String> {
        let mut ids = self.referenced_check_ids();
        ids.extend(self.checks.iter().map(|c| c.id.clone()));
        ids
    }

    /// `true` when the policy declares nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.checks.is_empty()
            && self.overrides.is_empty()
            && self.deny.is_empty()
            && self
                .context
                .as_ref()
                .is_none_or(|c| *c == PolicyContext::default())
    }

    /// The effective (strictest) override challenge per id, ignoring
    /// `on_branches` conditions. Used for display.
    #[must_use]
    pub fn strictest_overrides(&self) -> BTreeMap<String, Challenge> {
        let mut out: BTreeMap<String, Challenge> = BTreeMap::new();
        for o in &self.overrides {
            if let Some(ch) = o.challenge {
                out.entry(o.id.clone())
                    .and_modify(|e| *e = e.stricter(ch))
                    .or_insert(ch);
            }
        }
        out
    }
}

impl PolicyContext {
    /// This context without the escalation values that cannot change
    /// anything: a policy can only make escalation stricter, so a value at
    /// or below the built-in default is dropped (what `policy show` lists as
    /// effective).
    #[must_use]
    pub fn effective(&self) -> Self {
        let defaults = crate::context::EscalationConfig::default();
        let keep =
            |v: Option<Challenge>, default: Challenge| v.filter(|c| c.is_stricter_than(default));
        let escalation = self.escalation.and_then(|e| {
            let e = PolicyEscalation {
                elevated: keep(e.elevated, defaults.elevated),
                critical: keep(e.critical, defaults.critical),
            };
            (e.elevated.is_some() || e.critical.is_some()).then_some(e)
        });
        Self {
            escalation,
            ..self.clone()
        }
    }

    /// Whether this context changes anything: a protected branch, a
    /// production pattern or variable, a sensitive path, or an escalation
    /// stricter than the built-in default.
    #[must_use]
    pub fn has_effect(&self) -> bool {
        let e = self.effective();
        !e.protected_branches.is_empty()
            || !e.production_k8s_patterns.is_empty()
            || !e.production_env_vars.is_empty()
            || !e.sensitive_paths.is_empty()
            || e.escalation.is_some()
    }

    /// The escalation values [`Self::effective`] drops, as notes.
    #[must_use]
    pub fn no_effect_notes(&self) -> Vec<String> {
        let defaults = crate::context::EscalationConfig::default();
        let Some(e) = self.escalation else {
            return Vec::new();
        };
        [
            ("elevated", e.elevated, defaults.elevated),
            ("critical", e.critical, defaults.critical),
        ]
        .into_iter()
        .filter_map(|(key, v, default)| {
            let v = v?;
            (!v.is_stricter_than(default)).then(|| {
                format!(
                    "context.escalation.{key}: {v} is not stricter than the built-in default \
                     ({default}), so it has no effect (not listed above)"
                )
            })
        })
        .collect()
    }

    /// Add this policy context to the user's context configuration.
    /// Returns notes for entries that could not be applied.
    pub fn apply_to(&self, ctx: &mut ContextConfig) -> Vec<String> {
        let mut notes = Vec::new();
        let add_all = |dst: &mut Vec<String>, src: &[String]| {
            for v in src {
                if !dst.contains(v) {
                    dst.push(v.clone());
                }
            }
        };
        add_all(&mut ctx.protected_branches, &self.protected_branches);
        add_all(
            &mut ctx.production_k8s_patterns,
            &self.production_k8s_patterns,
        );
        add_all(&mut ctx.sensitive_paths, &self.sensitive_paths);
        for (k, v) in &self.production_env_vars {
            match ctx.production_env_vars.get(k) {
                None => {
                    ctx.production_env_vars.insert(k.clone(), v.clone());
                }
                Some(existing) if existing == v => {}
                Some(existing) => notes.push(format!(
                    "policy context production_env_vars.{k}={v} not applied: your settings \
                     already map {k} to '{existing}'"
                )),
            }
        }
        if let Some(esc) = self.escalation {
            if let Some(e) = esc.elevated {
                ctx.escalation.elevated = ctx.escalation.elevated.stricter(e);
            }
            if let Some(c) = esc.critical {
                ctx.escalation.critical = ctx.escalation.critical.stricter(c);
            }
        }
        notes
    }

    fn merge_from(&mut self, other: &Self) {
        let add_all = |dst: &mut Vec<String>, src: &[String]| {
            for v in src {
                if !dst.contains(v) {
                    dst.push(v.clone());
                }
            }
        };
        add_all(&mut self.protected_branches, &other.protected_branches);
        add_all(
            &mut self.production_k8s_patterns,
            &other.production_k8s_patterns,
        );
        add_all(&mut self.sensitive_paths, &other.sensitive_paths);
        for (k, v) in &other.production_env_vars {
            self.production_env_vars
                .entry(k.clone())
                .or_insert_with(|| v.clone());
        }
        if let Some(o) = other.escalation {
            let esc = self
                .escalation
                .get_or_insert_with(PolicyEscalation::default);
            esc.elevated = match (esc.elevated, o.elevated) {
                (Some(a), Some(b)) => Some(a.stricter(b)),
                (a, b) => a.or(b),
            };
            esc.critical = match (esc.critical, o.critical) {
                (Some(a), Some(b)) => Some(a.stricter(b)),
                (a, b) => a.or(b),
            };
        }
    }
}

// ---------------------------------------------------------------------------
// Untrusted text
// ---------------------------------------------------------------------------

const fn is_invisible_format_char(c: char) -> bool {
    matches!(
        c,
        '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}'
    )
}

/// [`is_invisible_format_char`] minus the zero-width non-joiner (U+200C)
/// and joiner (U+200D): human-readable text keeps them (Persian spelling,
/// Indic conjuncts, emoji sequences such as 👩‍💻). Ids still reject them.
const fn is_unsafe_text_format_char(c: char) -> bool {
    is_invisible_format_char(c) && !matches!(c, '\u{200c}' | '\u{200d}')
}

const fn is_line_break(c: char) -> bool {
    matches!(
        c,
        '\n' | '\r' | '\t' | '\u{2028}' | '\u{2029}' | '\u{85}' | '\u{0b}' | '\u{0c}'
    )
}

/// `true` when `s` contains unsafe characters.
///
/// Leading/trailing whitespace is ignored. Unsafe means newlines,
/// control characters, terminal escape sequences or invisible bidi / zero
/// width characters — anything that could fake shellfirm's own output when
/// the text is printed.
#[must_use]
pub fn has_unsafe_text(s: &str) -> bool {
    s.trim()
        .chars()
        .any(|c| c.is_control() || is_line_break(c) || is_unsafe_text_format_char(c))
}

/// Notes for `context.escalation` values below the built-in defaults: a
/// policy can only make escalation stricter, so they have no effect.
fn weak_escalation_notes(value: &serde_yaml::Value) -> Vec<String> {
    let defaults = crate::context::EscalationConfig::default();
    let mut out = Vec::new();
    for (key, default) in [
        ("elevated", defaults.elevated),
        ("critical", defaults.critical),
    ] {
        let Some(v) = value.get(key).and_then(serde_yaml::Value::as_str) else {
            continue;
        };
        if let Ok(ch) = Challenge::from_string(v) {
            if default.is_stricter_than(ch) {
                out.push(format!(
                    "context.escalation.{key}: {ch} is below the built-in default ({default}); \
                     escalation keeps the stricter value, so it has no effect in a policy"
                ));
            }
        }
    }
    out
}

/// Make untrusted text safe to print.
///
/// Applies to policy / custom-check descriptions and alternatives: terminal escape sequences, control and
/// invisible characters are removed, newlines and tabs become spaces,
/// runs of whitespace are collapsed, and the result is capped at
/// [`MAX_UNTRUSTED_TEXT_CHARS`] characters.
#[must_use]
pub fn sanitize_untrusted_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            match chars.peek() {
                Some('[') => {
                    chars.next();
                    // CSI: parameters until a final byte in 0x40..=0x7E.
                    for n in chars.by_ref() {
                        if ('\u{40}'..='\u{7e}').contains(&n) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    chars.next();
                    // OSC: until BEL or ESC \.
                    while let Some(n) = chars.next() {
                        if n == '\u{7}' {
                            break;
                        }
                        if n == '\u{1b}' {
                            if chars.peek() == Some(&'\\') {
                                chars.next();
                            }
                            break;
                        }
                    }
                }
                Some(_) => {
                    chars.next();
                }
                None => {}
            }
        } else if is_line_break(c) {
            out.push(' ');
        } else if c.is_control() || is_unsafe_text_format_char(c) {
            // dropped
        } else {
            out.push(c);
        }
    }
    let collapsed = out.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() > MAX_UNTRUSTED_TEXT_CHARS {
        let mut t: String = collapsed
            .chars()
            .take(MAX_UNTRUSTED_TEXT_CHARS - 1)
            .collect();
        t.push('…');
        t
    } else {
        collapsed
    }
}

/// A policy problem as printed, safe for the terminal.
///
/// Invisible and control characters are escaped (`\u{202e}`, never
/// stripped, so the text matches the file and `policy validate`), newlines
/// folded (see [`sanitize_untrusted_text`]).
#[must_use]
pub fn escaped_problem_text(s: &str) -> String {
    sanitize_untrusted_text(&crate::context::escape_invisible(s))
}

/// Sanitize the human-readable text of a check in place (see
/// [`sanitize_untrusted_text`]). Returns `true` when anything changed.
pub fn sanitize_check_text(check: &mut Check) -> bool {
    let mut changed = false;
    let mut fix = |s: &mut String| {
        let clean = sanitize_untrusted_text(s);
        if clean != s.trim() {
            changed = true;
        }
        *s = clean;
    };
    fix(&mut check.description);
    if let Some(a) = check.alternative.as_mut() {
        fix(a);
    }
    if let Some(a) = check.alternative_info.as_mut() {
        fix(a);
    }
    changed
}

/// What [`sanitize_check_text`] would remove from a check's text, for a
/// warning that names it: `newlines`, `U+202E`, … (in order, no repeats).
#[must_use]
pub fn removed_text_chars(check: &Check) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let texts = [
        Some(check.description.as_str()),
        check.alternative.as_deref(),
        check.alternative_info.as_deref(),
    ];
    for t in texts.into_iter().flatten() {
        for c in t.trim().chars() {
            let name = if matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}' | '\u{85}') {
                "newlines".to_string()
            } else if c == '\t' || c == ' ' {
                continue;
            } else if c.is_control() || is_line_break(c) || is_unsafe_text_format_char(c) {
                format!("U+{:04X}", c as u32)
            } else {
                continue;
            };
            if !out.contains(&name) {
                out.push(name);
            }
        }
    }
    out
}

/// A check id is well-formed when it is non-empty and contains no
/// whitespace or control characters (ids are printed in banners).
fn id_is_printable(id: &str) -> bool {
    !id.is_empty()
        && !id
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || is_invisible_format_char(c))
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse a policy YAML string **strictly** (any problem is an error).
///
/// Runtime loading is more forgiving, see [`load_policy_text`].
///
/// # Errors
/// Returns an error if the YAML is invalid, contains unknown keys, uses an
/// invalid value, or declares an unsupported `version`.
pub fn parse_policy(content: &str) -> Result<ProjectPolicy> {
    let raw: serde_yaml::Value = serde_yaml::from_str(content)?;
    if raw.is_null() {
        return Err(Error::Config(
            "the policy file is empty (expected at least `version: 1`)".into(),
        ));
    }
    let mut policy: ProjectPolicy = serde_yaml::from_str(content)?;
    if policy.version != SUPPORTED_POLICY_VERSION {
        return Err(Error::Config(format!(
            "unsupported policy version {} (this shellfirm supports version {SUPPORTED_POLICY_VERSION})",
            policy.version
        )));
    }
    policy.explicit_check_challenges = explicit_check_challenges(&raw, &policy.checks);
    Ok(policy)
}

fn explicit_check_challenges(
    raw: &serde_yaml::Value,
    checks: &[Check],
) -> HashMap<String, Challenge> {
    let mut out = HashMap::new();
    if let Some(items) = raw.get("checks").and_then(serde_yaml::Value::as_sequence) {
        for (item, check) in items.iter().zip(checks) {
            if item.get("challenge").is_some() {
                out.insert(check.id.clone(), check.challenge);
            }
        }
    }
    out
}

/// Result of validating a policy file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyReport {
    /// Problems that make the policy wrong or ineffective.
    pub errors: Vec<String>,
    /// Problems that are suspicious but do not change behaviour.
    pub warnings: Vec<String>,
    /// Informational notes (never fail `--strict`).
    pub notes: Vec<String>,
}

impl PolicyReport {
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }
}

/// A policy file's text, loaded the way runtime, `status` and `policy
/// validate` all load it.
#[derive(Debug, Clone, Default)]
pub struct LoadedPolicyText {
    /// The policy as it is applied (`None` when the file has a fatal
    /// problem and is not applied at all). Invalid parts are left out.
    pub policy: Option<ProjectPolicy>,
    /// Every problem found (`policy validate` prints exactly these).
    pub report: PolicyReport,
}

const TOP_KEYS: &[&str] = &["version", "checks", "overrides", "deny", "context"];
const CONTEXT_KEYS: &[&str] = &[
    "protected_branches",
    "production_k8s_patterns",
    "production_env_vars",
    "sensitive_paths",
    "escalation",
];
/// Keys a check definition (policy `checks` or a custom check file) may use.
pub const CHECK_KEYS: &[&str] = &[
    "id",
    "test",
    "description",
    "from",
    "challenge",
    "filters",
    "alternative",
    "alternative_info",
    "severity",
];

fn unknown_key_message(where_: &str, key: &str, valid: &[&str]) -> String {
    let hint = crate::config::suggest_similar(key, valid.iter().copied(), 1)
        .into_iter()
        .next()
        .map_or_else(String::new, |s| format!(" — did you mean `{s}`?"));
    format!(
        "{where_}unknown key `{key}`{hint} (valid keys: {}); it is ignored",
        valid.join(", ")
    )
}

fn yaml_err(e: &serde_yaml::Error) -> String {
    crate::config::one_line(&e.to_string())
}

/// Load a policy file's text leniently and validate it in depth.
///
/// This is the single source of truth used by runtime discovery, `status`
/// and `policy validate`. Fatal problems (invalid YAML, missing or
/// unsupported `version`) give `policy: None`. Everything else is reported
/// in `report` while the valid parts are kept in `policy`.
///
/// Check ids are validated against the built-in catalog plus the policy's
/// own `checks`. `personal_ids` (the developer's own custom check ids, may
/// be empty) only improves messages: a policy that references a personal
/// check is still an error, because teammates and CI don't have it.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn load_policy_text<S: std::hash::BuildHasher>(
    content: &str,
    personal_ids: &HashSet<String, S>,
) -> LoadedPolicyText {
    let mut report = PolicyReport::default();
    let fatal = |report: PolicyReport| LoadedPolicyText {
        policy: None,
        report,
    };

    let raw: serde_yaml::Value = match serde_yaml::from_str(content) {
        Ok(v) => v,
        Err(e) => {
            report
                .errors
                .push(format!("invalid YAML: {}", yaml_err(&e)));
            return fatal(report);
        }
    };
    if raw.is_null() {
        report
            .errors
            .push("the policy file is empty (expected at least `version: 1`)".into());
        return fatal(report);
    }
    let Some(map) = raw.as_mapping() else {
        report
            .errors
            .push("expected a YAML mapping with at least `version: 1`".into());
        return fatal(report);
    };

    // version (fatal when missing / wrong)
    match map.get("version") {
        None => {
            report
                .errors
                .push("missing required key `version` (add `version: 1`)".into());
            return fatal(report);
        }
        Some(v) => match serde_yaml::from_value::<u32>(v.clone()) {
            Ok(SUPPORTED_POLICY_VERSION) => {}
            Ok(other) => {
                report.errors.push(format!(
                    "unsupported policy version: {other}. Only version {SUPPORTED_POLICY_VERSION} is supported."
                ));
                return fatal(report);
            }
            Err(e) => {
                report
                    .errors
                    .push(format!("invalid `version`: {}", yaml_err(&e)));
                return fatal(report);
            }
        },
    }

    let mut policy = ProjectPolicy {
        version: SUPPORTED_POLICY_VERSION,
        ..ProjectPolicy::default()
    };

    for k in map.keys() {
        let name = k.as_str().unwrap_or("?");
        if !TOP_KEYS.contains(&name) {
            report.errors.push(unknown_key_message("", name, TOP_KEYS));
        }
    }

    // deny
    if let Some(v) = map.get("deny").filter(|v| !v.is_null()) {
        match v.as_sequence() {
            Some(items) => {
                for (i, item) in items.iter().enumerate() {
                    match item.as_str() {
                        Some(s) => policy.deny.push(s.trim().to_string()),
                        None => report.errors.push(format!(
                            "deny[{i}]: expected a check id string; it is ignored"
                        )),
                    }
                }
            }
            None => report.errors.push(
                "`deny` must be a list of check ids (e.g. `deny: [git:force_push]`); it is ignored"
                    .into(),
            ),
        }
    }

    // overrides
    if let Some(v) = map.get("overrides").filter(|v| !v.is_null()) {
        match v.as_sequence() {
            Some(items) => {
                for (i, item) in items.iter().enumerate() {
                    match serde_yaml::from_value::<Override>(item.clone()) {
                        Ok(o) => policy.overrides.push(o),
                        Err(e) => report.errors.push(format!(
                            "overrides[{i}]: {}; this override is ignored",
                            yaml_err(&e)
                        )),
                    }
                }
            }
            None => report
                .errors
                .push("`overrides` must be a list; it is ignored".into()),
        }
    }

    // context (per key, so one typo does not drop the rest)
    if let Some(v) = map.get("context").filter(|v| !v.is_null()) {
        if let Some(cmap) = v.as_mapping() {
            let mut kept = serde_yaml::Mapping::new();
            for (ck, cv) in cmap {
                let cname = ck.as_str().unwrap_or("?");
                if !CONTEXT_KEYS.contains(&cname) {
                    report
                        .errors
                        .push(unknown_key_message("context: ", cname, CONTEXT_KEYS));
                    continue;
                }
                let mut single = serde_yaml::Mapping::new();
                single.insert(ck.clone(), cv.clone());
                match serde_yaml::from_value::<PolicyContext>(serde_yaml::Value::Mapping(single)) {
                    Ok(_) => {
                        if cname == "escalation" {
                            report.notes.extend(weak_escalation_notes(cv));
                        }
                        kept.insert(ck.clone(), cv.clone());
                    }
                    Err(e) => report
                        .errors
                        .push(format!("context.{cname}: {}; it is ignored", yaml_err(&e))),
                }
            }
            policy.context = serde_yaml::from_value(serde_yaml::Value::Mapping(kept)).ok();
        } else {
            report
                .errors
                .push("`context` must be a mapping; it is ignored".into());
        }
    }

    // checks (per item)
    let builtin: HashSet<&str> = checks::all_checks_cached()
        .iter()
        .map(|c| c.id.as_str())
        .collect();
    if let Some(v) = map.get("checks").filter(|v| !v.is_null()) {
        if let Some(items) = v.as_sequence() {
            let mut own: HashSet<String> = HashSet::new();
            for (i, item) in items.iter().enumerate() {
                let label = item
                    .get("id")
                    .and_then(serde_yaml::Value::as_str)
                    .map_or_else(
                        || format!("checks[{i}]"),
                        // Shown escaped: an id with a bidi override must not
                        // read as a different id (`safe\u{202e}txt.exe`).
                        |id| format!("checks[{i}] `{}`", crate::context::escape_invisible(id)),
                    );
                if let Some(m) = item.as_mapping() {
                    for k in m.keys().filter_map(serde_yaml::Value::as_str) {
                        if !CHECK_KEYS.contains(&k) {
                            report.errors.push(unknown_key_message(
                                &format!("{label}: "),
                                k,
                                CHECK_KEYS,
                            ));
                        }
                    }
                }
                let mut check: Check = match serde_yaml::from_value(item.clone()) {
                    Ok(c) => c,
                    Err(e) => {
                        report.errors.push(format!(
                            "{label}: {}; this check is not loaded",
                            yaml_err(&e)
                        ));
                        continue;
                    }
                };
                check.id = check.id.trim().to_string();
                if check.id.is_empty() {
                    report.errors.push(format!(
                        "{label}: check pattern has empty id; it is not loaded"
                    ));
                    continue;
                }
                if !id_is_printable(&check.id) || !id_is_printable(check.from.trim()) {
                    report.errors.push(format!(
                        "{label}: the id / from must not contain spaces or control characters; \
                         this check is not loaded"
                    ));
                    continue;
                }
                if builtin.contains(check.id.as_str()) {
                    report.errors.push(format!(
                        "check id '{}' is already used by a built-in check; use `overrides` or `deny` \
                         to change built-in checks (this check is not loaded)",
                        check.id
                    ));
                    continue;
                }
                if !own.insert(check.id.clone()) {
                    report.errors.push(format!(
                        "duplicate check id '{}' (only the first definition is loaded)",
                        check.id
                    ));
                    continue;
                }
                if personal_ids.contains(&check.id) {
                    report.warnings.push(format!(
                        "check id '{}' is also defined by your personal custom checks",
                        check.id
                    ));
                }
                if check.description.trim().is_empty() {
                    report.errors.push(format!(
                        "check pattern '{}' has empty description.",
                        check.id
                    ));
                }
                let unsafe_fields: Vec<&str> = [
                    ("description", Some(check.description.as_str())),
                    ("alternative", check.alternative.as_deref()),
                    ("alternative_info", check.alternative_info.as_deref()),
                ]
                .into_iter()
                .filter(|(_, v)| v.is_some_and(has_unsafe_text))
                .map(|(n, _)| n)
                .collect();
                if !unsafe_fields.is_empty() {
                    report.errors.push(format!(
                        "check '{}': {} contains newlines, control characters or terminal escape \
                         sequences (they are removed when the policy is loaded)",
                        check.id,
                        unsafe_fields.join(", ")
                    ));
                }
                let too_long = [
                    Some(check.description.as_str()),
                    check.alternative.as_deref(),
                    check.alternative_info.as_deref(),
                ]
                .into_iter()
                .flatten()
                .any(|t| t.chars().count() > MAX_UNTRUSTED_TEXT_CHARS);
                if too_long {
                    report.warnings.push(format!(
                        "check '{}': text longer than {MAX_UNTRUSTED_TEXT_CHARS} characters is truncated",
                        check.id
                    ));
                }
                if !check.id.contains(':') {
                    report.warnings.push(format!(
                        "check id '{}' should look like `group:name`",
                        check.id
                    ));
                }
                for w in checks::validate_checks(std::slice::from_ref(&check)) {
                    report.errors.push(w);
                }
                sanitize_check_text(&mut check);
                if item.get("challenge").is_some() {
                    policy
                        .explicit_check_challenges
                        .insert(check.id.clone(), check.challenge);
                }
                policy.checks.push(check);
            }
        } else {
            report
                .errors
                .push("`checks` must be a list of checks; it is ignored".into());
        }
    }

    // ids referenced by deny / overrides
    let own_ids: HashSet<&str> = policy.checks.iter().map(|c| c.id.as_str()).collect();
    let groups: HashSet<&str> = checks::all_checks_cached()
        .iter()
        .map(|c| c.from.as_str())
        .collect();
    // The agent-instruction rule can be ignored personally, so a team can
    // also enforce it (`deny` / `overrides`).
    let is_known = |id: &str| {
        builtin.contains(id)
            || own_ids.contains(id)
            || crate::config::IGNORABLE_BUILTIN_RULE_IDS.contains(&id)
    };
    let candidates: Vec<&str> = builtin
        .iter()
        .copied()
        .chain(own_ids.iter().copied())
        .collect();
    let explain_unknown = |id: &str| -> String {
        if id.contains('*') || id.contains('?') {
            return "wildcards are not supported; list each check id (see `shellfirm check --list --all`)"
                .into();
        }
        if groups.contains(id) {
            return format!(
                "`{id}` is a group name; list check ids such as `{id}:…` instead (see `shellfirm check --list --group {id}`)"
            );
        }
        let mut s = "it would never match".to_string();
        if personal_ids.contains(id) {
            s.push_str(
                "; it is only defined by your personal custom checks, which teammates and CI \
                 don't have — define it in this policy's `checks` instead",
            );
        }
        if let Some(sug) = crate::config::suggest_similar(id, candidates.iter().copied(), 1)
            .into_iter()
            .next()
        {
            s.push_str("; did you mean `");
            s.push_str(&sug);
            s.push_str("`?");
        }
        s
    };
    let mut seen_deny = HashSet::new();
    for id in &policy.deny {
        if !is_known(id) {
            report.errors.push(format!(
                "deny: unknown check id '{id}' ({})",
                explain_unknown(id)
            ));
        }
        if !seen_deny.insert(id.as_str()) {
            report
                .warnings
                .push(format!("deny: '{id}' is listed more than once"));
        }
    }
    let mut seen_override: HashMap<&str, Option<Challenge>> = HashMap::new();
    for ov in &policy.overrides {
        if ov.id.trim().is_empty() {
            report.errors.push("override has empty id.".into());
            continue;
        }
        if !is_known(&ov.id) {
            report.errors.push(format!(
                "overrides: unknown check id '{}' ({})",
                ov.id,
                explain_unknown(&ov.id)
            ));
        }
        if ov.challenge.is_none() {
            report.warnings.push(format!(
                "overrides: '{}' has no `challenge`, so it has no effect",
                ov.id
            ));
        }
        if ov.on_branches.as_ref().is_some_and(Vec::is_empty) {
            report.warnings.push(format!(
                "overrides: '{}' has an empty `on_branches` list, so it never applies",
                ov.id
            ));
        }
        if policy.deny.contains(&ov.id) {
            report.warnings.push(format!(
                "overrides: '{}' is also in `deny`; the override has no effect",
                ov.id
            ));
        }
        if ov.on_branches.is_none() {
            if let Some(prev) = seen_override.insert(ov.id.as_str(), ov.challenge) {
                if prev != ov.challenge {
                    report.warnings.push(format!(
                        "overrides: '{}' is listed more than once; the strictest challenge applies",
                        ov.id
                    ));
                }
            }
        }
    }

    if policy.is_empty() {
        report.notes.push(if report.errors.is_empty() {
            "the policy declares no checks, overrides, deny entries or context yet".into()
        } else {
            "nothing from this policy is enforced: every entry it declares has an error (see above)"
                .into()
        });
    }

    LoadedPolicyText {
        policy: Some(policy),
        report,
    }
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/// A problem with one policy file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyLoadError {
    pub path: PathBuf,
    pub message: String,
}

/// Everything learned while discovering the policies for a directory.
#[derive(Debug, Clone, Default)]
pub struct PolicyDiscovery {
    /// The merged effective policy (`None` when no valid policy was found).
    pub policy: Option<ProjectPolicy>,
    /// Policy files that were applied (possibly partially), outermost first.
    pub sources: Vec<PathBuf>,
    /// Policy files that were found but are **not applied** at all (invalid
    /// YAML, missing / unsupported version, unreadable).
    pub errors: Vec<PolicyLoadError>,
    /// Errors in files that *were* applied (the invalid parts were left
    /// out): exactly what `policy validate` reports as errors.
    pub problems: Vec<PolicyLoadError>,
    /// Warnings (`policy validate` warnings, plus discovery warnings such as
    /// an ignored `.shellfirm.yml` next to `.shellfirm.yaml`).
    pub warnings: Vec<PolicyLoadError>,
    /// Notes produced while merging (e.g. duplicate check ids).
    pub notes: Vec<String>,
    /// Repository root that bounded the walk, if any.
    pub repo_root: Option<PathBuf>,
    /// Every policy file found (applied or not), outermost first.
    pub files: Vec<PathBuf>,
    /// Org-level policy files among `files`.
    pub org_files: Vec<PathBuf>,
}

impl PolicyDiscovery {
    /// `true` when at least one policy file exists (valid or not).
    #[must_use]
    pub const fn found_any(&self) -> bool {
        !self.files.is_empty() || !self.sources.is_empty() || !self.errors.is_empty()
    }

    /// Errors for one file (fatal or not).
    #[must_use]
    pub fn errors_for(&self, path: &Path) -> Vec<&str> {
        self.errors
            .iter()
            .chain(self.problems.iter())
            .filter(|e| e.path == path)
            .map(|e| e.message.as_str())
            .collect()
    }

    /// Warnings for one file.
    #[must_use]
    pub fn warnings_for(&self, path: &Path) -> Vec<&str> {
        self.warnings
            .iter()
            .filter(|e| e.path == path)
            .map(|e| e.message.as_str())
            .collect()
    }

    /// The structured view for callers that must decide whether to trust
    /// the policy (e.g. agent mode failing closed).
    #[must_use]
    pub fn to_load(&self) -> PolicyLoad {
        PolicyLoad {
            policy: self.policy.clone(),
            sources: self.sources.clone(),
            not_applied: self.errors.iter().map(|e| e.path.clone()).collect(),
            errors: self
                .errors
                .iter()
                .chain(self.problems.iter())
                .cloned()
                .collect(),
            warnings: self.warnings.clone(),
        }
    }
}

/// Structured policy load result.
///
/// `errors` holds **every** error `policy validate` would report for the
/// applicable files: files that were not applied at all (their paths are
/// also in `not_applied`) and errors in files that were applied with their
/// invalid parts left out. An agent integration that wants to fail closed
/// should treat `!errors.is_empty()` as "team rules may not be fully
/// enforced" (e.g. answer `ask` with [`PolicyLoad::summary`] in the reason).
#[derive(Debug, Clone, Default)]
pub struct PolicyLoad {
    /// The merged policy that is applied (may be partial, see `errors`).
    pub policy: Option<ProjectPolicy>,
    /// Files that contributed to `policy`, outermost first.
    pub sources: Vec<PathBuf>,
    /// Files that were found but not applied at all.
    pub not_applied: Vec<PathBuf>,
    /// Every error, per file.
    pub errors: Vec<PolicyLoadError>,
    /// Every warning, per file.
    pub warnings: Vec<PolicyLoadError>,
}

impl PolicyLoad {
    /// `true` when there is no error (warnings are allowed).
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }

    /// A one-line description of the errors, suitable for a hook reason,
    /// or `None` when there are none.
    #[must_use]
    pub fn summary(&self) -> Option<String> {
        let first = self.errors.first()?;
        let mut s = if self.not_applied.is_empty() {
            format!(
                "project policy {} has errors ({}): {}",
                first.path.display(),
                self.errors.len(),
                first.message
            )
        } else {
            format!(
                "project policy {} is invalid and NOT applied: {}",
                self.not_applied[0].display(),
                self.errors
                    .iter()
                    .find(|e| e.path == self.not_applied[0])
                    .map_or(first.message.as_str(), |e| e.message.as_str())
            )
        };
        if self.errors.len() > 1 {
            use std::fmt::Write as _;
            let _ = write!(
                s,
                " (+{} more; run `shellfirm policy validate`)",
                self.errors.len() - 1
            );
        }
        Some(escaped_problem_text(&s))
    }
}

/// Load the policy for `start_dir` as a [`PolicyLoad`] (never prints).
#[must_use]
pub fn load(env: &dyn Environment, start_dir: &Path) -> PolicyLoad {
    discover_all(env, start_dir).to_load()
}

/// Find the repository root that bounds the policy walk.
///
/// This is the **outermost** ancestor of `start` (inclusive) that contains `.git` (file or
/// directory). Nested repositories (submodules, vendored clones, empty
/// `.git` directories) therefore never stop the walk early.
#[must_use]
pub fn find_repo_root(env: &dyn Environment, start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .filter(|dir| env.path_exists(&dir.join(".git")))
        .last()
        .map(Path::to_path_buf)
}

/// Org-level policy files, in the order they are merged.
#[must_use]
pub fn org_policy_files(env: &dyn Environment) -> Vec<PathBuf> {
    let mut out = Vec::new();
    #[cfg(not(windows))]
    let system = Some(PathBuf::from(ORG_POLICY_PATH));
    #[cfg(windows)]
    let system = env
        .var("ProgramData")
        .filter(|v| !v.is_empty())
        .map(|d| PathBuf::from(d).join("shellfirm").join("policy.yaml"));
    if let Some(p) = system {
        if env.path_exists(&p) {
            out.push(p);
        }
    }
    if let Some(extra) = env.var(ORG_POLICY_ENV).filter(|v| !v.trim().is_empty()) {
        let p = PathBuf::from(extra.trim());
        // The variable only ever adds a file. A missing file is still
        // reported (as not applied) so a broken rollout is visible.
        if !out.contains(&p) {
            out.push(p);
        }
    }
    out
}

struct Scan {
    files: Vec<PathBuf>,
    org: Vec<PathBuf>,
    repo_root: Option<PathBuf>,
    /// `.shellfirm.yml` files ignored because `.shellfirm.yaml` sits next
    /// to them.
    shadowed_alt: Vec<PathBuf>,
}

fn scan(env: &dyn Environment, start_dir: &Path) -> Scan {
    // `/a/repo/../repo` is `/a/repo`: one spelling per file.
    let start_dir = &lexical(start_dir);
    let repo_root = find_repo_root(env, start_dir);
    let mut files = Vec::new();
    let mut shadowed_alt = Vec::new();
    for dir in start_dir.ancestors() {
        let main = dir.join(POLICY_FILENAME);
        let alt = dir.join(POLICY_FILENAME_ALT);
        if env.path_exists(&main) {
            files.push(main);
            if env.path_exists(&alt) {
                shadowed_alt.push(alt);
            }
        } else if env.path_exists(&alt) {
            files.push(alt);
        }
        if repo_root.as_deref() == Some(dir) {
            break;
        }
    }
    files.reverse();
    let org = org_policy_files(env);
    let mut all = org.clone();
    for f in files {
        if !all.contains(&f) {
            all.push(f);
        }
    }
    Scan {
        files: all,
        org,
        repo_root,
        shadowed_alt,
    }
}

/// List the policy files that apply to `start_dir`, outermost first (org
/// policies, then repository policies). The second value is the repository
/// root that bounded the walk.
#[must_use]
pub fn policy_files(env: &dyn Environment, start_dir: &Path) -> (Vec<PathBuf>, Option<PathBuf>) {
    let s = scan(env, start_dir);
    (s.files, s.repo_root)
}

/// Discover and merge every policy that applies to `start_dir`.
///
/// This never prints anything; see [`warn_policy_problems`].
#[must_use]
pub fn discover_all(env: &dyn Environment, start_dir: &Path) -> PolicyDiscovery {
    load_scan(env, scan(env, start_dir))
}

/// Discover the policies for a command that runs in `cwd` but **targets**
/// other directories, e.g. `git -C ../webapp push -f`, `cd ~/webapp && …`,
/// `terraform -chdir=infra destroy` or `make -C sub`.
///
/// The result is the **union** of the policies that apply to `cwd` and to
/// every directory in `target_dirs` (each walked up to its outermost
/// repository root, exactly like [`discover_all`]). Policies only ever add
/// rules, so the union is the safe choice: a command aimed at a repository
/// from outside it gets that repository's policy, and the policy of the
/// directory it was typed in still applies too.
///
/// Relative target directories are resolved against `cwd`; a leading `~`
/// is expanded to the home directory. Files are deduplicated and kept
/// outermost first (org policies, then the files of `cwd`, then the files
/// each target adds). `repo_root` is the one of `cwd`. Directories that do
/// not exist simply contribute nothing.
///
/// Callers (the shell hook, `check`, the agent hook) extract the target
/// directories from the parsed command and pass them here instead of
/// calling [`discover_all`]. With an empty `target_dirs` this is exactly
/// [`discover_all`].
#[must_use]
pub fn discover_for(env: &dyn Environment, cwd: &Path, target_dirs: &[PathBuf]) -> PolicyDiscovery {
    let mut combined = scan(env, cwd);
    let extra = EXTRA_TARGET_DIRS.with(|e| e.borrow().clone());
    for dir in target_dirs.iter().chain(extra.iter()) {
        let dir = real_dir(resolve_target_dir(env, cwd, dir));
        if dir == cwd {
            continue;
        }
        let s = scan(env, &dir);
        for f in s.files {
            if !combined.files.iter().any(|g| same_path(g, &f)) {
                combined.files.push(f);
            }
        }
        for a in s.shadowed_alt {
            if !combined.shadowed_alt.contains(&a) {
                combined.shadowed_alt.push(a);
            }
        }
    }
    load_scan(env, combined)
}

/// The current user's account name, for expanding `~name` to the home directory.
///
/// `$USER` / `$LOGNAME`, else the password-database entry of the
/// real uid (agent runners, cron and `env -i` often have no `$USER`).
#[must_use]
pub fn current_user_name(env: &dyn Environment) -> Option<String> {
    env.var("USER")
        .or_else(|| env.var("LOGNAME"))
        .filter(|u| !u.is_empty())
        .or_else(real_uid_account_name)
}

/// Account name of the real uid from the password database.
#[cfg(unix)]
fn real_uid_account_name() -> Option<String> {
    let mut buf = vec![0 as libc::c_char; 4096];
    // SAFETY: an all-zero passwd struct is a valid out-parameter.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: getuid has no preconditions; every pointer is valid for the
    // duration of the call and the buffer length matches the buffer.
    let rc = unsafe {
        libc::getpwuid_r(
            libc::getuid(),
            &raw mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &raw mut result,
        )
    };
    if rc != 0 || result.is_null() || pwd.pw_name.is_null() {
        return None;
    }
    // SAFETY: getpwuid_r succeeded, so pw_name points to a NUL-terminated
    // string inside `buf`.
    let name = unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) }
        .to_string_lossy()
        .to_string();
    (!name.is_empty()).then_some(name)
}

#[cfg(not(unix))]
const fn real_uid_account_name() -> Option<String> {
    None
}

/// `true` when `a` and `b` name the same file (same path, or the same
/// file after resolving symlinks).
pub(crate) fn same_path(a: &Path, b: &Path) -> bool {
    a == b
        || matches!(
            (std::fs::canonicalize(a), std::fs::canonicalize(b)),
            (Ok(x), Ok(y)) if x == y
        )
}

/// `dir` with symlinks resolved when it exists, else unchanged (a target
/// reached through a symlink is reported by its real path).
fn real_dir(dir: PathBuf) -> PathBuf {
    std::fs::canonicalize(&dir).unwrap_or(dir)
}

/// Lexically normalise `p` (`a/./b/../c` → `a/c`).
fn lexical(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

thread_local! {
    /// Extra target directories for [`discover_for`], set by
    /// [`with_extra_target_dirs`] for the duration of one analysis.
    static EXTRA_TARGET_DIRS: std::cell::RefCell<Vec<PathBuf>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Run `f` with `dirs` added to the target directories of every
/// [`discover_for`] call it makes (on this thread).
///
/// The analysis pipeline finds target directories itself (`cd`, `git -C`,
/// `make -C`, ...). Callers that know more targets — the agent walk also
/// counts path arguments such as `rm -rf projects/webapp/src` — use this so
/// the pipeline applies those repositories' policies too, from the real
/// working directory (relative paths keep resolving correctly). Policies
/// only add rules, so extra directories can only make a decision stricter.
pub fn with_extra_target_dirs<R>(dirs: &[PathBuf], f: impl FnOnce() -> R) -> R {
    struct Restore(Vec<PathBuf>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let prev = std::mem::take(&mut self.0);
            EXTRA_TARGET_DIRS.with(|e| *e.borrow_mut() = prev);
        }
    }
    let prev = EXTRA_TARGET_DIRS.with(|e| {
        let mut cur = e.borrow_mut();
        let prev = cur.clone();
        for d in dirs {
            if !cur.contains(d) {
                cur.push(d.clone());
            }
        }
        prev
    });
    let _restore = Restore(prev);
    f()
}

/// Resolve a command's target directory: `~`, `~/x`, `$HOME`, `${HOME}`
/// (and `~user` for the current user) → home, `$PWD` → `cwd`, relative →
/// against `cwd`, then lexically normalised (`a/../b` → `b`).
fn resolve_target_dir(env: &dyn Environment, cwd: &Path, dir: &Path) -> PathBuf {
    let s = dir.to_string_lossy();
    let home = env.home_dir();
    let user = current_user_name(env);
    // (prefix, base) pairs; the first that matches `s` exactly or followed
    // by `/` is replaced by its base.
    let mut bases: Vec<(String, Option<PathBuf>)> = vec![
        ("~".into(), home.clone()),
        ("$HOME".into(), home.clone()),
        ("${HOME}".into(), home.clone()),
        ("$PWD".into(), Some(cwd.to_path_buf())),
        ("${PWD}".into(), Some(cwd.to_path_buf())),
    ];
    if let Some(u) = user {
        bases.push((format!("~{u}"), home));
    }
    let expanded = bases
        .iter()
        .find_map(|(prefix, base)| {
            let rest = s.strip_prefix(prefix.as_str())?;
            let base = base.as_ref()?;
            if rest.is_empty() {
                Some(base.clone())
            } else {
                rest.strip_prefix('/').map(|r| base.join(r))
            }
        })
        .unwrap_or_else(|| dir.to_path_buf());
    let joined = if expanded.is_absolute() {
        expanded
    } else {
        cwd.join(expanded)
    };
    lexical(&joined)
}

/// `true` when the current (non-root) user can write `path`: an org policy
/// meant to be managed centrally (MDM, Ansible) should be root-owned.
#[cfg(unix)]
fn writable_by_current_user(env: &dyn Environment, path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    if env.effective_uid() == Some(0) {
        return false;
    }
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `c` is a valid NUL-terminated path for the duration of the call.
    unsafe { libc::access(c.as_ptr(), libc::W_OK) == 0 }
}

#[cfg(not(unix))]
const fn writable_by_current_user(_env: &dyn Environment, _path: &Path) -> bool {
    false
}

/// `true` when the current (non-root) user can replace `path` through its
/// directory: the directory is writable and either has no sticky bit or the
/// user owns the file (with the sticky bit only the owner may rename it).
#[cfg(unix)]
fn replaceable_by_current_user(env: &dyn Environment, path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) else {
        return false;
    };
    if !writable_by_current_user(env, dir) {
        return false;
    }
    let sticky = std::fs::metadata(dir).is_ok_and(|m| m.mode() & 0o1000 != 0);
    if !sticky {
        return true;
    }
    let owner = std::fs::metadata(path).map(|m| m.uid()).ok();
    owner.is_some() && owner == env.effective_uid()
}

#[cfg(not(unix))]
const fn replaceable_by_current_user(_env: &dyn Environment, _path: &Path) -> bool {
    false
}

fn load_scan(env: &dyn Environment, s: Scan) -> PolicyDiscovery {
    let mut out = PolicyDiscovery {
        repo_root: s.repo_root,
        files: s.files.clone(),
        org_files: s.org,
        ..PolicyDiscovery::default()
    };
    for alt in s.shadowed_alt {
        out.warnings.push(PolicyLoadError {
            message: format!(
                "ignored: {POLICY_FILENAME} in the same directory takes precedence; merge the two files"
            ),
            path: alt,
        });
    }
    let no_personal = HashSet::new();
    let mut parsed = Vec::new();
    for path in s.files {
        debug!("found policy at: {}", path.display());
        let is_org = out.org_files.contains(&path);
        if is_org && path.is_relative() {
            out.errors.push(PolicyLoadError {
                message: format!(
                    "{ORG_POLICY_ENV} must be an absolute path (a relative path would \
                     depend on the current directory); not applied"
                ),
                path,
            });
            continue;
        }
        if is_org && env.path_exists(&path) && writable_by_current_user(env, &path) {
            out.warnings.push(PolicyLoadError {
                message: "this org policy file is writable by you; a centrally managed org \
                          policy should be owned by root and not writable by users"
                    .to_string(),
                path: path.clone(),
            });
        } else if is_org && env.path_exists(&path) && replaceable_by_current_user(env, &path) {
            out.warnings.push(PolicyLoadError {
                message: format!(
                    "the directory {} is writable by you, so this org policy file can be \
                     moved away or replaced; a centrally managed org policy directory should \
                     be owned by root and not writable by users",
                    path.parent()
                        .map_or_else(String::new, |d| d.display().to_string())
                ),
                path: path.clone(),
            });
        }
        let content = match env.read_file(&path) {
            Ok(c) => c,
            Err(e) => {
                let msg = if env.path_exists(&path) {
                    format!("could not read file: {e}")
                } else {
                    "file not found".to_string()
                };
                out.errors.push(PolicyLoadError { path, message: msg });
                continue;
            }
        };
        let loaded = load_policy_text(&content, &no_personal);
        if let Some(p) = loaded.policy {
            for e in loaded.report.errors {
                out.problems.push(PolicyLoadError {
                    path: path.clone(),
                    message: escaped_problem_text(&e),
                });
            }
            for w in loaded.report.warnings {
                out.warnings.push(PolicyLoadError {
                    path: path.clone(),
                    message: escaped_problem_text(&w),
                });
            }
            out.sources.push(path);
            parsed.push(p);
        } else {
            let message = loaded
                .report
                .errors
                .first()
                .map_or_else(|| "invalid policy".to_string(), |e| escaped_problem_text(e));
            out.errors.push(PolicyLoadError { path, message });
        }
    }
    if !parsed.is_empty() {
        let (mut merged, notes) = merge_policies(parsed, &out.sources);
        merged.sources.clone_from(&out.sources);
        merged.org_sources = out
            .sources
            .iter()
            .filter(|p| out.org_files.contains(p))
            .cloned()
            .collect();
        out.policy = Some(merged);
        out.notes = notes;
    }
    out
}

/// Discover the effective policy for `start_dir` (see [`discover_all`]).
///
/// Invalid policy files are reported once per process on stderr (they are
/// never silently ignored).
#[must_use]
pub fn discover(env: &dyn Environment, start_dir: &Path) -> Option<ProjectPolicy> {
    let d = discover_all(env, start_dir);
    warn_policy_problems(&d);
    d.policy
}

static POLICY_WARNED: AtomicBool = AtomicBool::new(false);

/// The warning lines [`warn_policy_problems`] prints (without the
/// `shellfirm: ` prefix handling), for callers that want to show them
/// elsewhere.
#[must_use]
pub fn problem_lines(d: &PolicyDiscovery) -> Vec<String> {
    const MAX_PER_FILE: usize = 3;
    let mut lines = Vec::new();
    for e in &d.errors {
        lines.push(format!(
            "policy {} is invalid and was NOT applied: {}",
            e.path.display(),
            e.message
        ));
    }
    for src in &d.sources {
        let errs: Vec<&PolicyLoadError> = d.problems.iter().filter(|e| &e.path == src).collect();
        for e in errs.iter().take(MAX_PER_FILE) {
            lines.push(format!(
                "policy {} has an error (the rest of the file is applied): {}",
                src.display(),
                e.message
            ));
        }
        if errs.len() > MAX_PER_FILE {
            lines.push(format!(
                "policy {}: {} more error(s)",
                src.display(),
                errs.len() - MAX_PER_FILE
            ));
        }
    }
    for w in d
        .warnings
        .iter()
        .filter(|w| w.message.starts_with("ignored: "))
    {
        lines.push(format!("policy {} {}", w.path.display(), w.message));
    }
    lines
}

/// Never print [`warn_policy_problems`] lines in this process (the caller
/// reports the same problems itself, e.g. `check --strict`).
pub fn suppress_policy_warnings() {
    POLICY_WARNED.store(true, Ordering::SeqCst);
}

/// Print one warning line per policy problem to stderr.
///
/// At most once per process (so the hook path does not repeat it). Covers files that were
/// not applied, errors in applied files (the same errors `policy validate`
/// reports) and ignored `.shellfirm.yml` files.
pub fn warn_policy_problems(d: &PolicyDiscovery) {
    let lines = problem_lines(d);
    if lines.is_empty() || POLICY_WARNED.swap(true, Ordering::SeqCst) {
        return;
    }
    for l in &lines {
        eprintln!("shellfirm: warning: {l}");
    }
    eprintln!("shellfirm: run `shellfirm policy validate` for details.");
}

/// Merge several policies (outermost first) into one.
fn merge_policies(
    policies: Vec<ProjectPolicy>,
    sources: &[PathBuf],
) -> (ProjectPolicy, Vec<String>) {
    let mut merged = ProjectPolicy {
        version: SUPPORTED_POLICY_VERSION,
        ..ProjectPolicy::default()
    };
    let mut notes = Vec::new();
    let mut ctx: Option<PolicyContext> = None;
    for (i, p) in policies.into_iter().enumerate() {
        let src_path = sources.get(i).cloned();
        let src = src_path
            .as_ref()
            .map_or_else(String::new, |s| s.display().to_string());
        if let Some(sp) = &src_path {
            let named = p
                .deny
                .iter()
                .chain(p.overrides.iter().map(|o| &o.id))
                .chain(p.checks.iter().map(|c| &c.id));
            for id in named {
                let e = merged.id_sources.entry(id.clone()).or_default();
                if !e.contains(sp) {
                    e.push(sp.clone());
                }
            }
        }
        for c in p.checks {
            if merged.checks.iter().any(|e| e.id == c.id) {
                notes.push(format!(
                    "{src}: check `{}` is already defined by a parent policy; the parent definition is kept",
                    c.id
                ));
                continue;
            }
            if let Some(ch) = p.explicit_check_challenges.get(&c.id) {
                merged.explicit_check_challenges.insert(c.id.clone(), *ch);
            }
            merged.checks.push(c);
        }
        merged.overrides.extend(p.overrides);
        for id in p.deny {
            if !merged.deny.contains(&id) {
                merged.deny.push(id);
            }
        }
        if let Some(pc) = p.context {
            // Credit a file for context escalation only when its context
            // changes something (not an empty `version: 1` file, not an
            // escalation below the default).
            if let Some(sp) = src_path.as_ref().filter(|_| pc.has_effect()) {
                if !merged.context_sources.contains(sp) {
                    merged.context_sources.push(sp.clone());
                }
            }
            ctx.get_or_insert_with(PolicyContext::default)
                .merge_from(&pc);
        }
    }
    merged.context = ctx;
    (merged, notes)
}

// ---------------------------------------------------------------------------
// Applying a policy
// ---------------------------------------------------------------------------

/// Apply the parts of a policy that live in [`Settings`] (currently the
/// `context` section) to an in-memory settings value. Nothing is written.
/// Returns notes about entries that could not be applied.
pub fn apply_to_settings(settings: &mut Settings, policy: &ProjectPolicy) -> Vec<String> {
    // A built-in agent rule the policy enforces (`deny` / `overrides`) is not
    // switched off by a personal ignore.
    let enforced = policy.referenced_check_ids();
    settings.ignores_patterns_ids.retain(|id| {
        !(crate::config::IGNORABLE_BUILTIN_RULE_IDS.contains(&id.as_str()) && enforced.contains(id))
    });
    policy
        .context
        .as_ref()
        .map_or_else(Vec::new, |ctx| ctx.apply_to(&mut settings.context))
}

/// Describe where the user's personal settings conflict with the policy.
/// The policy always wins; these are informational.
#[must_use]
pub fn conflicts_with_settings(settings: &Settings, policy: &ProjectPolicy) -> Vec<String> {
    let mut out = Vec::new();
    let all = checks::all_checks_cached();
    for id in policy.enforced_ids() {
        if settings.ignores_patterns_ids.contains(&id) {
            out.push(format!(
                "`{id}` is in your ignores_patterns_ids, but the project policy enforces it"
            ));
        }
        let group = all
            .iter()
            .chain(policy.checks.iter())
            .find(|c| c.id == id)
            .map(|c| c.from.clone());
        if let Some(g) = group {
            if settings.disabled_groups.contains(&g) {
                out.push(format!(
                    "group `{g}` is disabled in your settings, but the project policy enforces `{id}`"
                ));
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Merge a project policy into the effective settings.
///
/// **Additive-only rule**: policies can only make things stricter.
/// - New checks are appended.
/// - Deny-list entries are merged (union).
/// - Challenge overrides are applied only if they escalate. When several
///   overrides (or nested policies) name the same id, the strictest wins.
/// - A policy check with an explicit `challenge:` gets that challenge as a
///   floor.
#[must_use]
pub fn merge_into_settings(
    _settings: &Settings,
    policy: &ProjectPolicy,
    current_branch: Option<&str>,
) -> MergedPolicy {
    let extra_checks = policy.checks.clone();
    let extra_deny: Vec<String> = policy.deny.clone();
    let mut challenge_overrides: HashMap<String, Challenge> = HashMap::new();
    let mut add = |id: &str, ch: Challenge| {
        challenge_overrides
            .entry(id.to_string())
            .and_modify(|e| *e = e.stricter(ch))
            .or_insert(ch);
    };

    for (id, ch) in &policy.explicit_check_challenges {
        add(id, *ch);
    }

    for ov in &policy.overrides {
        // If on_branches is specified, only apply when on a matching branch
        if let Some(ref branches) = ov.on_branches {
            if let Some(branch) = current_branch {
                if !branch_matches(branch, branches) {
                    continue;
                }
            } else {
                continue; // No branch info, skip branch-specific override
            }
        }

        if let Some(ch) = ov.challenge {
            add(&ov.id, ch);
        }
    }

    MergedPolicy {
        extra_checks,
        extra_deny,
        challenge_overrides,
        enforced_ids: policy.enforced_ids(),
        sources: policy.sources.clone(),
        org_sources: policy.org_sources.clone(),
        id_sources: policy.id_sources.clone(),
        context_sources: policy.context_sources.clone(),
    }
}

/// The result of merging a project policy. Consumed by the pipeline.
#[derive(Debug, Clone, Default)]
pub struct MergedPolicy {
    /// Additional checks from the project policy.
    pub extra_checks: Vec<Check>,
    /// Additional deny-listed pattern IDs.
    pub extra_deny: Vec<String>,
    /// Challenge overrides (`pattern_id` → new challenge).
    /// These are only applied if they **escalate** (see `effective_challenge`).
    pub challenge_overrides: HashMap<String, Challenge>,
    /// Ids the policy enforces (deny + overrides + own checks). Matches for
    /// these ids are never dropped by the user's `min_severity`.
    pub enforced_ids: HashSet<String>,
    /// Policy files the merged policy came from, outermost first (for
    /// audit records and "enforced by …" hints).
    pub sources: Vec<PathBuf>,
    /// The org-level files among `sources`.
    pub org_sources: Vec<PathBuf>,
    /// For each id the policy names, the files that name it.
    pub id_sources: BTreeMap<String, Vec<PathBuf>>,
    /// The files whose `context:` section has an effect.
    pub context_sources: Vec<PathBuf>,
}

impl MergedPolicy {
    /// Get the effective challenge for a pattern, respecting the
    /// additive-only rule. Returns the stricter of: base challenge,
    /// context-escalated challenge, or policy override.
    #[must_use]
    pub fn effective_challenge(&self, pattern_id: &str, base: &Challenge) -> Challenge {
        self.challenge_overrides
            .get(pattern_id)
            .map_or(*base, |&override_ch| {
                checks::max_challenge(*base, override_ch)
            })
    }

    /// Check if a pattern ID is in the project deny list.
    #[must_use]
    pub fn is_denied(&self, pattern_id: &str) -> bool {
        self.extra_deny.iter().any(|id| id == pattern_id)
    }

    /// Check if a pattern ID is enforced by the project policy (deny,
    /// override or the policy's own check). Enforced ids are exempt from
    /// the user's personal filters, so hints such as "`config ignore …`" or
    /// "`config deny --remove …`" do not apply to them.
    #[must_use]
    pub fn is_enforced(&self, pattern_id: &str) -> bool {
        self.enforced_ids.contains(pattern_id)
    }

    /// Display string for the files that supply the policy `context`
    /// (protected branches, production patterns, escalation), used to
    /// credit a context escalation; `None` when no file's context has an
    /// effect. An empty file or one whose context changes nothing on the
    /// way to the target is never credited.
    ///
    /// Each file is labelled with its kind, e.g. `org policy
    /// (/etc/shellfirm/policy.yaml), project policy (/repo/.shellfirm.yaml)`.
    #[must_use]
    pub fn sources_label(&self) -> Option<String> {
        if self.context_sources.is_empty() {
            return None;
        }
        Some(self.label_paths(&self.context_sources))
    }

    /// The files that name `pattern_id` (in `deny`, `overrides` or their
    /// own `checks`), outermost first. Falls back to every source when the
    /// per-id information is not available.
    #[must_use]
    pub fn sources_for(&self, pattern_id: &str) -> Vec<PathBuf> {
        self.id_sources
            .get(pattern_id)
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| self.sources.clone())
    }

    /// Like [`Self::sources_label`], limited to the files that name
    /// `pattern_id`: what a "denied by …" / "enforced by …" message should
    /// show, e.g. `org policy (/etc/shellfirm/policy.yaml)`.
    #[must_use]
    pub fn label_for(&self, pattern_id: &str) -> Option<String> {
        let files = self.sources_for(pattern_id);
        if files.is_empty() {
            return None;
        }
        Some(self.label_paths(&files))
    }

    /// Like [`Self::label_for`], but only for an id the policy files
    /// actually name (`deny`, `overrides`, their own checks): `None` when a
    /// challenge floor for `pattern_id` only comes from a target
    /// repository's `context:` (no rule for that id), so an escalation
    /// reason never credits a policy "for `git:reset`" it has no rule for.
    #[must_use]
    pub fn rule_label_for(&self, pattern_id: &str) -> Option<String> {
        let files = self.id_sources.get(pattern_id).filter(|v| !v.is_empty())?;
        Some(self.label_paths(files))
    }

    /// `org policy (<path>)` or `project policy (<path>)` for one file.
    #[must_use]
    pub fn source_label(&self, path: &Path) -> String {
        let kind = if self.org_sources.iter().any(|p| p == path) {
            "org policy"
        } else {
            "project policy"
        };
        format!(
            "{kind} ({})",
            sanitize_untrusted_text(&path.display().to_string())
        )
    }

    fn label_paths(&self, paths: &[PathBuf]) -> String {
        paths
            .iter()
            .map(|p| self.source_label(p))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Reuse the shared branch-matching helper from the context module.
fn branch_matches(branch: &str, patterns: &[String]) -> bool {
    crate::context::branch_matches_any(branch, patterns)
}

// ---------------------------------------------------------------------------
// Scaffold
// ---------------------------------------------------------------------------

/// Generate a default `.shellfirm.yaml` template.
///
/// The template passes `shellfirm policy validate --strict` as-is, and still
/// does when every commented example is uncommented (covered by tests).
#[must_use]
pub fn scaffold_policy() -> String {
    r#"# shellfirm project policy
# Docs: https://github.com/kaplanelad/shellfirm/blob/main/docs/team-policies.md
#
# Rules here are enforced for everyone working in this repository: personal
# settings (ignored checks, disabled groups, min_severity) cannot weaken them.
# Nested .shellfirm.yaml files in subdirectories add to this file.
# Check it with: shellfirm policy validate --strict
version: 1

# Additional patterns specific to this project
checks:
#   - id: project:deploy_prod
#     from: project
#     test: "deploy\\s+--env\\s+prod"
#     description: "Deploys to production."
#     severity: High
#     challenge: Yes

# Make the challenge for existing patterns stricter (never weaker).
# Valid challenges: Math, Enter, Yes
overrides:
#   - id: git:force_delete_branch
#     challenge: Yes
#   - id: git:reset
#     on_branches: [main, master]
#     challenge: Yes

# Patterns that are always denied in this project
deny:
#   - git:force_push
#   - kubernetes:delete_namespace

# Context settings added to every developer's own context settings
# context:
#   protected_branches: [main, master, develop, "release/*"]
#   production_k8s_patterns: [prod, production]
#   production_env_vars:
#     APP_ENV: production
#   escalation:
#     elevated: Enter
#     critical: Yes
"#
    .to_string()
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate a policy file in depth (see [`load_policy_text`]).
///
/// `personal_ids` are the developer's own custom check ids; they never make
/// a policy valid, they only improve the messages.
#[must_use]
pub fn validate_policy_report<S: std::hash::BuildHasher>(
    content: &str,
    personal_ids: &HashSet<String, S>,
) -> PolicyReport {
    load_policy_text(content, personal_ids).report
}

/// Validate a policy file and return a list of problems (errors and
/// warnings, flattened) against the built-in catalog.
///
/// # Errors
/// Returns an error if the YAML is invalid.
pub fn validate_policy(content: &str) -> Result<Vec<String>> {
    let _: serde_yaml::Value = serde_yaml::from_str(content)?;
    let report = validate_policy_report(content, &HashSet::new());
    Ok(report.errors.into_iter().chain(report.warnings).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::MockEnvironment;
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn env_with(files: &[(&str, &str)], cwd: &str, existing: &[&str]) -> MockEnvironment {
        MockEnvironment {
            cwd: PathBuf::from(cwd),
            files: files
                .iter()
                .map(|(p, c)| (PathBuf::from(p), (*c).to_string()))
                .collect(),
            existing_paths: existing.iter().map(PathBuf::from).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn test_parse_simple_policy() {
        let yaml = r#"
version: 1
deny:
  - git:force_push
  - kubernetes:delete_namespace
"#;
        let policy = parse_policy(yaml).unwrap();
        assert_eq!(policy.version, 1);
        assert_eq!(policy.deny.len(), 2);
        assert!(policy.deny.contains(&"git:force_push".to_string()));
    }

    #[test]
    fn parse_rejects_unknown_top_level_key() {
        let err = parse_policy("version: 1\ndenylist: [git:force_push]\n").unwrap_err();
        assert!(err.to_string().contains("denylist"), "{err}");
    }

    #[test]
    fn parse_rejects_unsupported_version_and_missing_version() {
        assert!(parse_policy("version: 2\n").is_err());
        assert!(parse_policy("deny: [git:force_push]\n").is_err());
        assert!(parse_policy("").is_err());
    }

    #[test]
    fn parse_rejects_bad_challenge_and_bad_regex() {
        assert!(
            parse_policy("version: 1\noverrides:\n  - id: git:reset\n    challenge: Deny\n")
                .is_err()
        );
        assert!(parse_policy(
            "version: 1\nchecks:\n  - id: a:b\n    from: a\n    test: 'foo(('\n    description: x\n"
        )
        .is_err());
    }

    #[test]
    fn test_discover_policy_walks_up() {
        let mut files = HashMap::new();
        files.insert(
            PathBuf::from("/repo/.shellfirm.yaml"),
            "version: 1\ndeny:\n  - git:force_push\n".into(),
        );
        let env = MockEnvironment {
            cwd: PathBuf::from("/repo/src/deep/nested"),
            files,
            ..Default::default()
        };
        let policy = discover(&env, &env.cwd);
        assert!(policy.is_some());
        assert!(policy.unwrap().deny.contains(&"git:force_push".to_string()));
    }

    #[test]
    fn test_discover_no_policy() {
        let env = MockEnvironment {
            cwd: PathBuf::from("/home/user/project"),
            ..Default::default()
        };
        let policy = discover(&env, &env.cwd);
        assert!(policy.is_none());
    }

    #[test]
    fn nested_policy_merges_with_parent() {
        let env = env_with(
            &[
                ("/repo/.shellfirm.yaml", "version: 1\ndeny: [git:force_push]\n"),
                (
                    "/repo/svc/.shellfirm.yaml",
                    "version: 1\ndeny: [git:reset]\noverrides:\n  - id: git:force_push\n    challenge: Enter\n",
                ),
            ],
            "/repo/svc/src",
            &["/repo/.git"],
        );
        let d = discover_all(&env, &env.cwd);
        let p = d.policy.unwrap();
        assert_eq!(d.sources.len(), 2);
        assert_eq!(d.sources[0], PathBuf::from("/repo/.shellfirm.yaml"));
        assert!(p.deny.contains(&"git:force_push".to_string()));
        assert!(p.deny.contains(&"git:reset".to_string()));
    }

    #[test]
    fn discovery_stops_at_repo_root() {
        let env = env_with(
            &[
                ("/home/u/.shellfirm.yaml", "version: 1\ndeny: [git:reset]\n"),
                (
                    "/home/u/repo/.shellfirm.yaml",
                    "version: 1\ndeny: [git:force_push]\n",
                ),
            ],
            "/home/u/repo/src",
            &["/home/u/repo/.git"],
        );
        let d = discover_all(&env, &env.cwd);
        assert_eq!(
            d.sources,
            vec![PathBuf::from("/home/u/repo/.shellfirm.yaml")]
        );
        assert!(!d.policy.unwrap().deny.contains(&"git:reset".to_string()));
    }

    #[test]
    fn discovery_recognises_yml_extension() {
        let env = env_with(
            &[(
                "/repo/.shellfirm.yml",
                "version: 1\ndeny: [git:force_push]\n",
            )],
            "/repo",
            &[],
        );
        assert!(discover_all(&env, &env.cwd).policy.is_some());
    }

    #[test]
    fn invalid_nested_policy_is_reported_and_parent_still_applies() {
        let env = env_with(
            &[
                (
                    "/repo/.shellfirm.yaml",
                    "version: 1\ndeny: [git:force_push]\n",
                ),
                ("/repo/svc/.shellfirm.yaml", "deny: [git:reset]\n"),
            ],
            "/repo/svc",
            &["/repo/.git"],
        );
        let d = discover_all(&env, &env.cwd);
        assert_eq!(d.errors.len(), 1);
        assert!(d.errors[0].message.contains("version"));
        assert!(d
            .policy
            .unwrap()
            .deny
            .contains(&"git:force_push".to_string()));
    }

    #[test]
    fn test_merge_adds_deny() {
        let settings = Settings {
            enabled_groups: vec![],
            audit_enabled: false,
            ..Settings::default()
        };
        let policy = ProjectPolicy {
            version: 1,
            deny: vec!["git:force_push".into()],
            ..Default::default()
        };
        let merged = merge_into_settings(&settings, &policy, None);
        assert!(merged.is_denied("git:force_push"));
        assert!(merged.is_enforced("git:force_push"));
    }

    #[test]
    fn duplicate_overrides_keep_the_strictest() {
        let policy = ProjectPolicy {
            version: 1,
            overrides: vec![
                Override {
                    id: "git:reset".into(),
                    challenge: Some(Challenge::Yes),
                    on_branches: None,
                },
                Override {
                    id: "git:reset".into(),
                    challenge: Some(Challenge::Math),
                    on_branches: None,
                },
            ],
            ..Default::default()
        };
        let merged = merge_into_settings(&Settings::default(), &policy, None);
        assert_eq!(
            merged.challenge_overrides.get("git:reset"),
            Some(&Challenge::Yes)
        );
    }

    #[test]
    fn policy_check_explicit_challenge_becomes_floor() {
        let p = parse_policy(
            "version: 1\nchecks:\n  - id: p:x\n    from: p\n    test: x\n    description: d\n    challenge: Yes\n  - id: p:y\n    from: p\n    test: y\n    description: d\n",
        )
        .unwrap();
        let merged = merge_into_settings(&Settings::default(), &p, None);
        assert_eq!(merged.challenge_overrides.get("p:x"), Some(&Challenge::Yes));
        assert!(!merged.challenge_overrides.contains_key("p:y"));
    }

    #[test]
    fn context_escalation_is_credited_only_to_files_whose_context_has_an_effect() {
        let ctx =
            |yaml: &str| -> Option<PolicyContext> { Some(serde_yaml::from_str(yaml).unwrap()) };
        let outer = ProjectPolicy {
            context: ctx("protected_branches: [develop]"),
            ..ProjectPolicy::default()
        };
        let empty = ProjectPolicy::default();
        let weak = ProjectPolicy {
            context: ctx("escalation: {critical: Enter}"),
            ..ProjectPolicy::default()
        };
        let sources = vec![
            PathBuf::from("/infra/.shellfirm.yaml"),
            PathBuf::from("/infra/svc/.shellfirm.yaml"),
            PathBuf::from("/infra/svc/a/.shellfirm.yaml"),
        ];
        let (merged, _) = merge_policies(vec![outer, empty, weak], &sources);
        assert_eq!(merged.context_sources, vec![sources[0].clone()]);
        let m = merge_into_settings(&Settings::default(), &merged, None);
        assert_eq!(
            m.sources_label().as_deref(),
            Some("project policy (/infra/.shellfirm.yaml)")
        );
        // An escalation below the default is not "effective".
        let w = ctx("escalation: {critical: Enter}").unwrap();
        assert!(w.effective().escalation.is_none());
        assert_eq!(w.no_effect_notes().len(), 1);
        assert!(w.no_effect_notes()[0].contains("context.escalation.critical: Enter"));
        assert!(!ctx("escalation: {critical: Enter}").unwrap().has_effect());
    }

    #[test]
    fn test_effective_challenge_escalates() {
        let mut overrides = std::collections::HashMap::new();
        overrides.insert("git:reset".into(), Challenge::Yes);
        let merged = MergedPolicy {
            challenge_overrides: overrides,
            ..Default::default()
        };
        assert_eq!(
            merged.effective_challenge("git:reset", &Challenge::Math),
            Challenge::Yes
        );
    }

    #[test]
    fn test_effective_challenge_cannot_weaken() {
        let mut overrides = std::collections::HashMap::new();
        overrides.insert("git:reset".into(), Challenge::Enter);
        let merged = MergedPolicy {
            challenge_overrides: overrides,
            ..Default::default()
        };
        assert_eq!(
            merged.effective_challenge("git:reset", &Challenge::Yes),
            Challenge::Yes
        );
    }

    #[test]
    fn test_branch_specific_override() {
        let settings = Settings {
            enabled_groups: vec![],
            audit_enabled: false,
            ..Settings::default()
        };
        let policy = ProjectPolicy {
            version: 1,
            overrides: vec![Override {
                id: "git:reset".into(),
                challenge: Some(Challenge::Yes),
                on_branches: Some(vec!["main".into(), "master".into()]),
            }],
            ..Default::default()
        };

        let merged = merge_into_settings(&settings, &policy, Some("main"));
        assert_eq!(
            merged.effective_challenge("git:reset", &Challenge::Math),
            Challenge::Yes
        );

        let merged = merge_into_settings(&settings, &policy, Some("feature/foo"));
        assert_eq!(
            merged.effective_challenge("git:reset", &Challenge::Math),
            Challenge::Math
        );
    }

    #[test]
    fn policy_context_is_added_to_user_context() {
        let p = parse_policy(
            "version: 1\ncontext:\n  protected_branches: [develop]\n  production_k8s_patterns: [acme-eks]\n  escalation:\n    elevated: Yes\n",
        )
        .unwrap();
        let mut s = Settings::default();
        let notes = apply_to_settings(&mut s, &p);
        assert!(notes.is_empty());
        assert!(s
            .context
            .protected_branches
            .contains(&"develop".to_string()));
        assert!(s.context.protected_branches.contains(&"main".to_string()));
        assert!(s
            .context
            .production_k8s_patterns
            .contains(&"acme-eks".to_string()));
        assert_eq!(s.context.escalation.elevated, Challenge::Yes);
    }

    #[test]
    fn policy_context_rejects_unknown_keys() {
        assert!(parse_policy("version: 1\ncontext:\n  protected_branchez: [x]\n").is_err());
    }

    #[test]
    fn conflicts_are_reported() {
        let p = parse_policy("version: 1\ndeny: [git:force_push]\n").unwrap();
        let s = Settings {
            ignores_patterns_ids: vec!["git:force_push".into()],
            disabled_groups: vec!["git".into()],
            ..Settings::default()
        };
        let c = conflicts_with_settings(&s, &p);
        assert_eq!(c.len(), 2, "{c:?}");
    }

    #[test]
    fn test_validate_policy() {
        let yaml = "version: 1\ndeny:\n  - git:force_push\n";
        let warnings = validate_policy(yaml).unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");
    }

    #[test]
    fn test_validate_policy_bad_version() {
        let yaml = "version: 99\n";
        let warnings = validate_policy(yaml).unwrap();
        assert!(!warnings.is_empty());
        assert!(warnings[0].contains("version"));
    }

    fn report(yaml: &str) -> PolicyReport {
        validate_policy_report(yaml, &crate::config::known_check_ids(&[]))
    }

    #[test]
    fn validate_detects_typo_ids_keys_duplicates_and_shadowing() {
        assert!(!report("version: 1\ndeny: [git:forse_push]\n").is_ok());
        assert!(!report("version: 1\ndenylist: [git:force_push]\n").is_ok());
        assert!(!report("version: 1\noverrides:\n  - id: git:nope\n    challenge: Yes\n").is_ok());
        let dup = "version: 1\nchecks:\n  - {id: 'a:x', from: a, test: x, description: d}\n  - {id: 'a:x', from: a, test: y, description: d}\n";
        assert!(report(dup).errors.iter().any(|e| e.contains("duplicate")));
        let shadow =
            "version: 1\nchecks:\n  - {id: 'git:force_push', from: git, test: x, description: d}\n";
        assert!(report(shadow).errors.iter().any(|e| e.contains("built-in")));
        let unknown_check_key = "version: 1\nchecks:\n  - {id: 'a:x', from: a, test: x, description: d, sevrity: High}\n";
        assert!(report(unknown_check_key)
            .errors
            .iter()
            .any(|e| e.contains("sevrity")));
        assert!(!report(
            "version: 1\nchecks:\n  - {id: 'a:x', from: a, test: 'x((', description: d}\n"
        )
        .is_ok());
        assert!(!report("version: 1\nchecks:\n  - {id: 'a:x', from: a, test: x, description: d, severity: Extreme}\n").is_ok());
        assert!(!report("").is_ok());
        assert!(!report("version: 1\ndeny: git:force_push\n").is_ok());
    }

    #[test]
    fn deny_may_reference_own_policy_check() {
        let yaml = "version: 1\nchecks:\n  - {id: 'p:x', from: p, test: x, description: d}\ndeny: ['p:x']\n";
        assert!(report(yaml).is_ok(), "{:?}", report(yaml));
    }

    #[test]
    fn test_scaffold_policy() {
        let yaml = scaffold_policy();
        assert!(yaml.contains("version: 1"));
        assert!(yaml.contains("deny:"));
        assert!(parse_policy(&yaml).is_ok());
    }

    /// Uncomment every commented example line in the scaffold (i.e. lines of
    /// the form `#   - ...` or `#     key: ...` and `# context:`), and make
    /// sure the result is still a valid policy.
    #[test]
    fn scaffold_is_valid_with_examples_uncommented() {
        let uncommented: String = scaffold_policy()
            .lines()
            .map(|l| {
                if let Some(rest) = l.strip_prefix("# ") {
                    if rest.starts_with("  ") || rest.starts_with("context:") {
                        return rest.to_string();
                    }
                }
                l.to_string()
            })
            .collect::<Vec<_>>()
            .join("\n");
        let p = parse_policy(&uncommented)
            .unwrap_or_else(|e| panic!("uncommented scaffold invalid: {e}\n{uncommented}"));
        assert_eq!(p.deny.len(), 2);
        assert_eq!(p.overrides.len(), 2);
        assert_eq!(p.checks.len(), 1);
        assert!(p.context.is_some());
        let r = report(&uncommented);
        assert!(r.is_ok(), "{r:?}");
        assert!(r.warnings.is_empty(), "strict mode would fail: {r:?}");
        let as_is = report(&scaffold_policy());
        assert!(
            as_is.is_ok() && as_is.warnings.is_empty(),
            "scaffold as-is fails --strict: {as_is:?}"
        );
    }

    #[test]
    fn runtime_reports_the_same_semantic_errors_as_validate() {
        let env = env_with(
            &[(
                "/repo/.shellfirm.yaml",
                "version: 1\ndeny: [git:forse_push, 'git:*', git]\n",
            )],
            "/repo",
            &["/repo/.git"],
        );
        let d = discover_all(&env, &env.cwd);
        // Applied (the policy is additive, so applying the rest is safe) ...
        assert_eq!(d.sources.len(), 1);
        assert!(d.errors.is_empty());
        // ... but every validate error is reported.
        assert_eq!(d.problems.len(), 3, "{:?}", d.problems);
        assert!(
            d.problems[0].message.contains("git:force_push"),
            "{:?}",
            d.problems
        );
        assert!(d.problems[1].message.contains("wildcards"));
        assert!(d.problems[2].message.contains("group name"));
        let load = d.to_load();
        assert!(!load.is_ok());
        assert!(load.summary().unwrap().contains("has errors"));
        assert!(!problem_lines(&d).is_empty());
    }

    #[test]
    fn unknown_top_level_key_does_not_drop_the_rest_of_the_policy() {
        let env = env_with(
            &[(
                "/repo/.shellfirm.yaml",
                "version: 1\ndeny: [git:force_push]\noverides: []\n",
            )],
            "/repo",
            &[],
        );
        let d = discover_all(&env, &env.cwd);
        assert!(d
            .policy
            .unwrap()
            .deny
            .contains(&"git:force_push".to_string()));
        assert!(
            d.problems[0].message.contains("did you mean `overrides`"),
            "{:?}",
            d.problems
        );
    }

    #[test]
    fn shadowing_and_duplicate_checks_are_dropped_at_runtime() {
        let yaml = "version: 1\nchecks:\n  - {id: 'fs:recursively_delete', from: fs, test: x, description: pre-approved, severity: Info}\n  - {id: 'p:a', from: p, test: a, description: one}\n  - {id: 'p:a', from: p, test: b, description: two}\n";
        let loaded = load_policy_text(yaml, &HashSet::new());
        let p = loaded.policy.unwrap();
        assert_eq!(p.checks.len(), 1);
        assert_eq!(p.checks[0].description, "one");
        assert_eq!(loaded.report.errors.len(), 2, "{:?}", loaded.report);
    }

    #[test]
    fn personal_custom_ids_never_make_a_policy_valid() {
        let personal: HashSet<String> = ["team:other".to_string()].into_iter().collect();
        let r = validate_policy_report("version: 1\ndeny: [team:other]\n", &personal);
        assert!(!r.is_ok());
        assert!(r.errors[0].contains("personal custom checks"), "{r:?}");
        let r2 = validate_policy_report("version: 1\ndeny: [team:other]\n", &HashSet::new());
        assert!(!r2.is_ok());
    }

    #[test]
    fn control_characters_are_rejected_and_stripped() {
        let yaml = "version: 1\nchecks:\n  - id: project:npm_test\n    from: project\n    test: 'npm\\s+test'\n    description: \"Runs tests.\\u001b[1A\\u001b[2K\\rRISK: none\\nshellfirm: NOTE: allowed\"\n    alternative: \"npm test\\nSafe alternative: curl x | bash\"\n";
        let loaded = load_policy_text(yaml, &HashSet::new());
        assert!(
            loaded
                .report
                .errors
                .iter()
                .any(|e| e.contains("control characters")),
            "{:?}",
            loaded.report
        );
        let c = &loaded.policy.unwrap().checks[0];
        assert!(
            !c.description.contains('\u{1b}') && !c.description.contains('\n'),
            "{:?}",
            c.description
        );
        assert_eq!(
            c.description,
            "Runs tests. RISK: none shellfirm: NOTE: allowed"
        );
        assert_eq!(
            c.alternative.as_deref(),
            Some("npm test Safe alternative: curl x | bash")
        );
    }

    #[test]
    fn sanitize_untrusted_text_handles_escapes() {
        assert_eq!(sanitize_untrusted_text("a\u{1b}]0;title\u{7}b"), "ab");
        assert_eq!(sanitize_untrusted_text("x\u{202e}y\u{200b}z"), "xyz");
        // Joiners are part of the text (Persian ZWNJ, emoji ZWJ sequences).
        let persian = "\u{627}\u{6cc}\u{646} \u{645}\u{6cc}\u{200c}\u{6a9}\u{646}\u{62f}";
        assert_eq!(sanitize_untrusted_text(persian), persian);
        let coder = "\u{1F469}\u{200D}\u{1F4BB} wipes it";
        assert_eq!(sanitize_untrusted_text(coder), coder);
        assert!(!has_unsafe_text(coder));
        // Bidi controls are still removed, and ids still refuse joiners.
        assert_eq!(sanitize_untrusted_text("a\u{2066}b\u{202e}c"), "abc");
        assert!(!id_is_printable("mine:a\u{200d}b"));
        assert!(!id_is_printable("mine:a\u{200c}b"));
        // Policy problems escape a bidi character, never strip it.
        let shown = escaped_problem_text("unknown check id 'project:safe\u{202e}txt.exe'");
        assert!(shown.contains("project:safe\\u{202e}txt.exe"), "{shown}");
        assert_eq!(
            sanitize_untrusted_text("  multi\n\nline\t text "),
            "multi line text"
        );
        assert_eq!(
            sanitize_untrusted_text(&"a".repeat(1000)).chars().count(),
            MAX_UNTRUSTED_TEXT_CHARS
        );
        assert!(has_unsafe_text("a\nb"));
        assert!(!has_unsafe_text("plain text\n"));
    }

    #[test]
    fn nested_git_dirs_and_submodules_do_not_stop_the_walk() {
        let env = env_with(
            &[(
                "/repo/.shellfirm.yaml",
                "version: 1\ndeny: [git:force_push]\n",
            )],
            "/repo/tools/sub",
            // empty dir in tools, a submodule `.git` file in tools/sub
            &["/repo/.git", "/repo/tools/.git", "/repo/tools/sub/.git"],
        );
        let d = discover_all(&env, &env.cwd);
        assert_eq!(d.repo_root, Some(PathBuf::from("/repo")));
        assert_eq!(d.sources, vec![PathBuf::from("/repo/.shellfirm.yaml")]);
    }

    #[test]
    fn yml_next_to_yaml_is_warned() {
        let env = env_with(
            &[
                ("/repo/.shellfirm.yaml", "version: 1\n"),
                ("/repo/.shellfirm.yml", "version: 1\ndeny: [git:reset]\n"),
            ],
            "/repo",
            &["/repo/.git"],
        );
        let d = discover_all(&env, &env.cwd);
        assert!(d
            .warnings
            .iter()
            .any(|w| w.path.ends_with(".shellfirm.yml")));
        assert!(problem_lines(&d)
            .iter()
            .any(|l| l.contains(".shellfirm.yml")));
    }

    #[cfg(not(windows))]
    #[test]
    fn org_policy_applies_everywhere_and_env_only_adds() {
        let mut env = env_with(
            &[
                (ORG_POLICY_PATH, "version: 1\ndeny: [git:force_push]\n"),
                ("/opt/extra.yaml", "version: 1\ndeny: [git:reset]\n"),
                (
                    "/repo/.shellfirm.yaml",
                    "version: 1\ndeny: [git:clean_force]\n",
                ),
            ],
            "/repo/src",
            &["/repo/.git"],
        );
        env.env_vars
            .insert(ORG_POLICY_ENV.to_string(), "/opt/extra.yaml".to_string());
        let d = discover_all(&env, &env.cwd);
        assert_eq!(d.sources[0], PathBuf::from(ORG_POLICY_PATH));
        assert_eq!(d.org_files.len(), 2);
        let p = d.policy.unwrap();
        for id in ["git:force_push", "git:reset", "git:clean_force"] {
            assert!(p.deny.contains(&id.to_string()), "{id}");
        }
        assert_eq!(p.sources.len(), 3);
        // Outside any repository the org policy still applies.
        let env2 = env_with(
            &[(ORG_POLICY_PATH, "version: 1\ndeny: [git:force_push]\n")],
            "/tmp",
            &[],
        );
        assert!(discover_all(&env2, &env2.cwd).policy.is_some());
        // A missing env file is reported, not silently ignored.
        let mut env3 = env_with(&[], "/tmp", &[]);
        env3.env_vars
            .insert(ORG_POLICY_ENV.to_string(), "/nope.yaml".to_string());
        assert_eq!(discover_all(&env3, &env3.cwd).errors.len(), 1);
    }

    #[test]
    fn merged_policy_carries_sources() {
        let env = env_with(
            &[(
                "/repo/.shellfirm.yaml",
                "version: 1\ndeny: [git:force_push]\n",
            )],
            "/repo",
            &[],
        );
        let p = discover_all(&env, &env.cwd).policy.unwrap();
        let m = merge_into_settings(&Settings::default(), &p, None);
        // No `context:` in the file: no context escalation is credited to it.
        assert_eq!(m.sources_label(), None);
        assert_eq!(m.sources, vec![PathBuf::from("/repo/.shellfirm.yaml")]);
        assert_eq!(
            m.label_for("git:force_push").as_deref(),
            Some("project policy (/repo/.shellfirm.yaml)")
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn org_sources_are_labelled_and_attributed_per_id() {
        let env = env_with(
            &[
                (
                    ORG_POLICY_PATH,
                    "version: 1\ndeny: [kubernetes:delete_namespace]\n",
                ),
                (
                    "/repo/.shellfirm.yaml",
                    "version: 1\ndeny: [git:force_push]\n",
                ),
            ],
            "/repo",
            &["/repo/.git"],
        );
        let p = discover_all(&env, &env.cwd).policy.unwrap();
        let m = merge_into_settings(&Settings::default(), &p, None);
        assert_eq!(
            m.label_for("kubernetes:delete_namespace").as_deref(),
            Some("org policy (/etc/shellfirm/policy.yaml)")
        );
        assert_eq!(
            m.label_for("git:force_push").as_deref(),
            Some("project policy (/repo/.shellfirm.yaml)")
        );
        assert_eq!(m.sources_label(), None, "neither file has a context");
    }

    #[test]
    fn relative_org_policy_env_is_rejected() {
        let mut env = env_with(
            &[("/repo/.shellfirm.yaml", "version: 1\ndeny: [git:reset]\n")],
            "/repo",
            &["/repo/.git"],
        );
        env.env_vars
            .insert(ORG_POLICY_ENV.to_string(), ".shellfirm.yaml".to_string());
        let d = discover_all(&env, &env.cwd);
        assert_eq!(d.errors.len(), 1, "{:?}", d.errors);
        assert!(d.errors[0].message.contains("absolute path"));
        // The repo policy itself is still applied, once.
        assert_eq!(d.sources, vec![PathBuf::from("/repo/.shellfirm.yaml")]);
    }

    #[test]
    fn discover_for_unions_the_target_directory_policy() {
        let env = env_with(
            &[(
                "/home/dev/projects/webapp/.shellfirm.yaml",
                "version: 1\ndeny: [git:force_push]\n",
            )],
            "/home/dev",
            &["/home/dev/projects/webapp/.git"],
        );
        // From outside the repo: nothing applies to the cwd alone.
        assert!(discover_all(&env, &env.cwd).policy.is_none());
        for target in [
            "projects/webapp",
            "/home/dev/projects/webapp",
            "./projects/x/../webapp",
            "projects/webapp/src",
        ] {
            let d = discover_for(&env, &env.cwd, &[PathBuf::from(target)]);
            let p = d.policy.unwrap_or_else(|| panic!("{target}: no policy"));
            assert!(p.deny.contains(&"git:force_push".to_string()), "{target}");
        }
        // No targets: identical to discover_all.
        assert!(discover_for(&env, &env.cwd, &[]).policy.is_none());
    }

    #[test]
    fn discover_for_keeps_the_cwd_policy_and_dedups() {
        let env = env_with(
            &[
                ("/a/.shellfirm.yaml", "version: 1\ndeny: [git:reset]\n"),
                ("/b/.shellfirm.yaml", "version: 1\ndeny: [git:force_push]\n"),
            ],
            "/a",
            &["/a/.git", "/b/.git"],
        );
        let d = discover_for(
            &env,
            &env.cwd,
            &[
                PathBuf::from("/b"),
                PathBuf::from("/b/sub"),
                PathBuf::from("."),
            ],
        );
        assert_eq!(
            d.sources,
            vec![
                PathBuf::from("/a/.shellfirm.yaml"),
                PathBuf::from("/b/.shellfirm.yaml")
            ]
        );
        let p = d.policy.unwrap();
        assert!(p.deny.contains(&"git:reset".to_string()));
        assert!(p.deny.contains(&"git:force_push".to_string()));
        assert_eq!(d.repo_root, Some(PathBuf::from("/a")));
    }

    #[test]
    fn discover_for_expands_home() {
        let mut env = env_with(
            &[(
                "/home/dev/w/.shellfirm.yaml",
                "version: 1\ndeny: [git:reset]\n",
            )],
            "/tmp",
            &["/home/dev/w/.git"],
        );
        env.home = Some(PathBuf::from("/home/dev"));
        env.env_vars.insert("USER".into(), "dev".into());
        for target in ["~/w", "$HOME/w", "${HOME}/w", "~dev/w", "~dev/w/sub/.."] {
            let d = discover_for(&env, &env.cwd, &[PathBuf::from(target)]);
            assert!(d.policy.is_some(), "{target}");
        }
        // Another user's home is not guessed.
        let d = discover_for(&env, &env.cwd, &[PathBuf::from("~other/w")]);
        assert!(d.policy.is_none());
    }
}
