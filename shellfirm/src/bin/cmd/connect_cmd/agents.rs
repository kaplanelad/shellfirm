//! Hook installation for Codex CLI, Gemini CLI, Qwen Code, GitHub Copilot
//! CLI, Windsurf, Cline and `OpenCode`.
//!
//! Three shapes of configuration:
//! - matcher groups (`hooks.<Event>[] = {matcher, hooks: [{type, command,
//!   timeout}]}`): Codex `hooks.json`, Gemini and Qwen `settings.json`;
//! - flat entry lists (`hooks.<event>[] = {command | bash, ...}`): Copilot
//!   (a `shellfirm.json` file of its own) and Windsurf `hooks.json`;
//! - a file shellfirm owns entirely: the Cline `PreToolUse` script and the
//!   `OpenCode` plugin. They carry a marker line; a file without it is never
//!   replaced or removed.

use std::fmt::Write as _;
use std::path::Path;

use serde_json::{json, Map, Value};

use super::{
    child_array, child_object, parse_shellfirm_hook, root_object, shell_quote, HookCmd,
    InstallSpec, IntegrationStatus, OpKind, OpResult, HOOK_TIMEOUT_SECS,
};

// ---------------------------------------------------------------------------
// Matcher-group agents (Codex, Gemini, Qwen)
// ---------------------------------------------------------------------------

/// How an agent reads a `matcher`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatcherRule {
    /// Codex: `*` / empty match all; letters, digits, `_` and `|` only are an
    /// exact list; anything else an unanchored regex
    /// (`codex-rs/hooks/src/engine/matcher.rs`).
    Codex,
    /// Gemini CLI: an unanchored regex, or an exact string when it does not
    /// compile (`packages/core/src/hooks/hookPlanner.ts`).
    Gemini,
    /// Qwen Code: `*` / empty match all; a `|` list of exact names unless
    /// it starts with `^` or `(`; otherwise an unanchored regex.
    Qwen,
}

impl MatcherRule {
    fn covers(self, matcher: Option<&str>, tool: &str) -> bool {
        let Some(m) = matcher.map(str::trim) else {
            return true;
        };
        if m.is_empty() || m == "*" {
            return true;
        }
        let exact_list = match self {
            Self::Codex => m
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '|'),
            Self::Gemini => false,
            Self::Qwen => {
                !m.starts_with('^')
                    && !m.starts_with('(')
                    && m.chars().all(|c| {
                        c.is_ascii_alphanumeric() || matches!(c, '_' | '|' | ' ' | '*' | '.')
                    })
            }
        };
        if exact_list {
            return m
                .split('|')
                .map(str::trim)
                .any(|t| t == tool || (self == Self::Qwen && matches!(t, "*" | ".*")));
        }
        regex::Regex::new(m).map_or(self == Self::Gemini && m == tool, |re| re.is_match(tool))
    }
}

/// A matcher-group hook configuration.
struct GroupSpec {
    /// `--hook` value and `check --hook` target.
    target: &'static str,
    /// Hook event key under `hooks`.
    event: &'static str,
    /// Tools the hook must cover: shell tools first, then file tools.
    shell_tools: &'static [&'static str],
    file_tools: &'static [&'static str],
    rule: MatcherRule,
    /// `timeout` value written (Gemini: milliseconds).
    timeout: u64,
    /// Extra fields of a new hook entry (Gemini `name`).
    name: Option<&'static str>,
}

impl GroupSpec {
    fn tools(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.shell_tools.iter().chain(self.file_tools).copied()
    }

    /// A matcher selecting exactly `tools` under this agent's rules.
    fn matcher_for(&self, tools: &[&str]) -> String {
        match self.rule {
            MatcherRule::Codex | MatcherRule::Qwen => tools.join("|"),
            MatcherRule::Gemini => format!("^({})$", tools.join("|")),
        }
    }

    fn entry(&self, spec: &InstallSpec) -> Value {
        let mut e = Map::new();
        if let Some(n) = self.name {
            e.insert("name".into(), json!(n));
        }
        e.insert("type".into(), json!("command"));
        e.insert(
            "command".into(),
            json!(spec.hook_command(&format!("check --hook {}", self.target))),
        );
        e.insert("timeout".into(), json!(self.timeout));
        Value::Object(e)
    }

    fn ours(&self, h: &Value) -> Option<HookCmd> {
        h.get("command")
            .and_then(Value::as_str)
            .and_then(|c| parse_shellfirm_hook(c, self.target))
    }
}

/// Codex CLI `hooks.json`: `PreToolUse`, tool `Bash` (shell commands) and
/// `apply_patch` (file edits). Timeouts are in seconds.
const CODEX: GroupSpec = GroupSpec {
    target: "codex",
    event: "PreToolUse",
    shell_tools: &["Bash"],
    file_tools: &["apply_patch"],
    rule: MatcherRule::Codex,
    timeout: HOOK_TIMEOUT_SECS,
    name: None,
};

/// Gemini CLI `settings.json`: `BeforeTool`. Timeouts are in milliseconds.
const GEMINI: GroupSpec = GroupSpec {
    target: "gemini",
    event: "BeforeTool",
    shell_tools: &["run_shell_command"],
    file_tools: &["write_file", "replace", "read_file", "read_many_files"],
    rule: MatcherRule::Gemini,
    timeout: HOOK_TIMEOUT_SECS * 1000,
    name: Some("shellfirm"),
};

/// Qwen Code `settings.json`: `PreToolUse`. Timeouts are in seconds.
/// `read_many_files` is a tool in Qwen Code versions that still expose it.
const QWEN: GroupSpec = GroupSpec {
    target: "qwen",
    event: "PreToolUse",
    shell_tools: &["run_shell_command"],
    file_tools: &["write_file", "edit", "read_file", "read_many_files"],
    rule: MatcherRule::Qwen,
    timeout: HOOK_TIMEOUT_SECS,
    name: None,
};

const fn group_spec(op: OpKind) -> Option<&'static GroupSpec> {
    match op {
        OpKind::CodexHooks => Some(&CODEX),
        OpKind::GeminiHooks => Some(&GEMINI),
        OpKind::QwenHooks => Some(&QWEN),
        _ => None,
    }
}

/// What a matcher-group file holds for shellfirm (read-only).
#[derive(Debug, Default)]
struct GroupState {
    covered: Vec<&'static str>,
    entries: usize,
    config_dirs: Vec<String>,
}

fn group_state(g: &GroupSpec, value: &Value) -> GroupState {
    let mut st = GroupState::default();
    let Some(groups) = value
        .get("hooks")
        .and_then(|h| h.get(g.event))
        .and_then(Value::as_array)
    else {
        return st;
    };
    for grp in groups {
        let matcher = grp.get("matcher").and_then(Value::as_str);
        let mut ours = false;
        for h in grp
            .get("hooks")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(hc) = g.ours(h) {
                ours = true;
                st.entries += 1;
                if let Some(d) = hc.config_dir {
                    if !st.config_dirs.contains(&d) {
                        st.config_dirs.push(d);
                    }
                }
            }
        }
        if ours {
            for t in g.tools() {
                if g.rule.covers(matcher, t) && !st.covered.contains(&t) {
                    st.covered.push(t);
                }
            }
        }
    }
    st
}

/// Bring one shellfirm hook entry up to date: pin `--config-dir` (in every
/// `command_keys` field), add a missing `timeout` (`(key, value)`). Returns
/// whether it changed.
fn upgrade_entry(
    h: &mut Value,
    hc: &HookCmd,
    command_keys: &[&str],
    timeout: Option<(&str, u64)>,
    spec: &InstallSpec,
) -> bool {
    let Some(obj) = h.as_object_mut() else {
        return false;
    };
    let mut changed = false;
    if hc.config_dir.is_none() {
        if let Some(dir) = &spec.config_dir {
            for k in command_keys {
                if let Some(old) = obj.get(*k).and_then(Value::as_str).map(str::to_string) {
                    obj.insert(
                        (*k).into(),
                        json!(format!("{old} --config-dir {}", shell_quote(dir))),
                    );
                    changed = true;
                }
            }
        }
    }
    if let Some((key, secs)) = timeout {
        // Copilot also reads `timeout` (seconds) when `timeoutSec` is absent.
        let has = obj.contains_key(key) || (key == "timeoutSec" && obj.contains_key("timeout"));
        if !has {
            obj.insert(key.into(), json!(secs));
            changed = true;
        }
    }
    changed
}

#[allow(clippy::too_many_lines)]
fn install_groups(
    g: &GroupSpec,
    value: &mut Value,
    path: &Path,
    spec: &InstallSpec,
) -> OpResult<Vec<String>> {
    let mut actions = Vec::new();
    let before = group_state(g, value);
    let spec = &InstallSpec {
        config_dir: before
            .config_dirs
            .first()
            .cloned()
            .or_else(|| spec.config_dir.clone()),
        ..spec.clone()
    };
    let root = root_object(value, path)?;
    let had_hooks = root.contains_key("hooks");
    let hooks = child_object(root, "hooks", path, true)?.expect("created");
    let groups =
        child_array(hooks, g.event, &format!("hooks.{}", g.event), path, true)?.expect("created");

    // Duplicates: within a group keep the first shellfirm hook; a group
    // whose matcher adds no tool beyond earlier shellfirm groups loses it.
    let mut covered: Vec<&'static str> = Vec::new();
    let mut removed = 0usize;
    groups.retain_mut(|grp| {
        let matcher = grp
            .get("matcher")
            .and_then(Value::as_str)
            .map(ToString::to_string);
        let Some(hs) = grp.get_mut("hooks").and_then(Value::as_array_mut) else {
            return true;
        };
        if !hs.iter().any(|h| g.ours(h).is_some()) {
            return true;
        }
        let adds: Vec<&'static str> = g
            .tools()
            .filter(|t| g.rule.covers(matcher.as_deref(), t) && !covered.contains(t))
            .collect();
        let keep_one = !adds.is_empty();
        let n = hs.len();
        let mut kept = false;
        hs.retain(|h| {
            if g.ours(h).is_none() {
                return true;
            }
            let keep = keep_one && !kept;
            kept = true;
            keep
        });
        removed += n - hs.len();
        covered.extend(adds);
        !hs.is_empty()
    });
    if removed > 0 {
        actions.push(format!(
            "remove {removed} duplicate shellfirm hook(s) from hooks.{}",
            g.event
        ));
    }
    let mut upgraded = 0usize;
    for grp in groups.iter_mut() {
        for h in grp
            .get_mut("hooks")
            .and_then(Value::as_array_mut)
            .into_iter()
            .flatten()
        {
            if let Some(hc) = g.ours(h) {
                upgraded += usize::from(upgrade_entry(
                    h,
                    &hc,
                    &["command"],
                    Some(("timeout", g.timeout)),
                    spec,
                ));
            }
        }
    }
    if upgraded > 0 {
        actions.push(format!(
            "upgrade {upgraded} existing shellfirm hook(s) in hooks.{} in place{}",
            g.event,
            if spec.config_dir.is_some() {
                " (pinned --config-dir)"
            } else {
                ""
            }
        ));
    }
    let missing: Vec<&str> = g.tools().filter(|t| !covered.contains(t)).collect();
    if !missing.is_empty() {
        let matcher = g.matcher_for(&missing);
        groups.push(json!({ "matcher": matcher, "hooks": [g.entry(spec)] }));
        actions.push(format!(
            "add hooks.{} entry (matcher \"{matcher}\") running `{}`",
            g.event,
            spec.hook_command(&format!("check --hook {}", g.target))
        ));
    }
    if groups.is_empty() {
        hooks.shift_remove(g.event);
    }
    if hooks.is_empty() && !had_hooks {
        root.shift_remove("hooks");
    }
    if g.target == GEMINI.target {
        actions.extend(gemini_reenable(g, root));
    }
    Ok(actions)
}

/// Take shellfirm's hook out of Gemini's `hooksConfig.disabled`.
fn gemini_reenable(g: &GroupSpec, root: &mut Map<String, Value>) -> Option<String> {
    let Some(Value::Array(disabled)) = root
        .get_mut("hooksConfig")
        .and_then(|h| h.get_mut("disabled"))
    else {
        return None;
    };
    let n = disabled.len();
    disabled.retain(|v| !gemini_disabled_entry(g, v));
    (disabled.len() < n)
        .then(|| "take shellfirm out of hooksConfig.disabled (it turned the hook off)".into())
}

fn uninstall_groups(g: &GroupSpec, value: &mut Value, path: &Path) -> OpResult<Vec<String>> {
    let mut actions = Vec::new();
    let Some(root) = value.as_object_mut() else {
        return Ok(actions);
    };
    let Some(hooks) = child_object(root, "hooks", path, false)? else {
        return Ok(actions);
    };
    let Some(groups) = child_array(hooks, g.event, &format!("hooks.{}", g.event), path, false)?
    else {
        return Ok(actions);
    };
    let mut removed = 0usize;
    groups.retain_mut(|grp| {
        let Some(inner) = grp.get_mut("hooks").and_then(Value::as_array_mut) else {
            return true;
        };
        let n = inner.len();
        inner.retain(|h| g.ours(h).is_none());
        removed += n - inner.len();
        !(n > 0 && inner.is_empty())
    });
    if removed > 0 {
        actions.push(format!(
            "remove {removed} shellfirm hook(s) from hooks.{}",
            g.event
        ));
        if groups.is_empty() {
            hooks.shift_remove(g.event);
            if hooks.is_empty() {
                root.shift_remove("hooks");
            }
        }
    }
    Ok(actions)
}

// ---------------------------------------------------------------------------
// Flat-list agents (Copilot, Windsurf)
// ---------------------------------------------------------------------------

struct ListSpec {
    target: &'static str,
    /// Hook events: one shellfirm entry in each.
    events: &'static [&'static str],
    /// Keys holding the command line (all are written).
    command_keys: &'static [&'static str],
    timeout_key: Option<&'static str>,
    /// Extra fields of a new entry.
    extra: fn() -> Map<String, Value>,
    /// Write `"version": 1` (Copilot hook files).
    version: bool,
}

fn copilot_extra() -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("type".into(), json!("command"));
    m
}

fn windsurf_extra() -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("show_output".into(), json!(false));
    m
}

/// GitHub Copilot CLI: `~/.copilot/hooks/shellfirm.json` (or
/// `.github/hooks/shellfirm.json`), camelCase `preToolUse` (fires for every
/// tool; non-zero exits deny).
const COPILOT: ListSpec = ListSpec {
    target: "copilot",
    events: &["preToolUse"],
    command_keys: &["bash", "powershell"],
    timeout_key: Some("timeoutSec"),
    extra: copilot_extra,
    version: true,
};

/// Windsurf Cascade `hooks.json`: shell commands, file writes and reads.
const WINDSURF: ListSpec = ListSpec {
    target: "windsurf",
    events: &["pre_run_command", "pre_write_code", "pre_read_code"],
    command_keys: &["command"],
    timeout_key: None,
    extra: windsurf_extra,
    version: false,
};

const fn list_spec(op: OpKind) -> Option<&'static ListSpec> {
    match op {
        OpKind::CopilotHooks => Some(&COPILOT),
        OpKind::WindsurfHooks => Some(&WINDSURF),
        _ => None,
    }
}

impl ListSpec {
    fn ours(&self, h: &Value) -> Option<HookCmd> {
        ["bash", "command", "powershell"]
            .iter()
            .filter_map(|k| h.get(*k).and_then(Value::as_str))
            .find_map(|c| parse_shellfirm_hook(c, self.target))
    }

    fn entry(&self, spec: &InstallSpec) -> Value {
        let mut e = (self.extra)();
        let cmd = spec.hook_command(&format!("check --hook {}", self.target));
        for k in self.command_keys {
            e.insert((*k).into(), json!(cmd));
        }
        if let Some(t) = self.timeout_key {
            e.insert(t.into(), json!(HOOK_TIMEOUT_SECS));
        }
        Value::Object(e)
    }

    fn entries<'a>(&self, value: &'a Value, event: &str) -> Vec<(HookCmd, &'a Value)> {
        value
            .get("hooks")
            .and_then(|h| h.get(event))
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|h| self.ours(h).map(|hc| (hc, h)))
                    .collect()
            })
            .unwrap_or_default()
    }
}

fn install_list(
    l: &ListSpec,
    value: &mut Value,
    path: &Path,
    spec: &InstallSpec,
) -> OpResult<Vec<String>> {
    let mut actions = Vec::new();
    let existing_dir = l
        .events
        .iter()
        .flat_map(|e| l.entries(value, e))
        .find_map(|(hc, _)| hc.config_dir);
    let spec = &InstallSpec {
        config_dir: existing_dir.or_else(|| spec.config_dir.clone()),
        ..spec.clone()
    };
    let root = root_object(value, path)?;
    let hooks = child_object(root, "hooks", path, true)?.expect("created");
    for event in l.events {
        let list =
            child_array(hooks, event, &format!("hooks.{event}"), path, true)?.expect("created");
        let n = list.len();
        let mut seen = false;
        list.retain(|h| {
            if l.ours(h).is_none() {
                return true;
            }
            let keep = !seen;
            seen = true;
            keep
        });
        if list.len() < n {
            actions.push(format!(
                "remove {} duplicate shellfirm hook(s) from hooks.{event}",
                n - list.len()
            ));
        }
        let mut upgraded = 0usize;
        for h in list.iter_mut() {
            if let Some(hc) = l.ours(h) {
                upgraded += usize::from(upgrade_entry(
                    h,
                    &hc,
                    l.command_keys,
                    l.timeout_key.map(|k| (k, HOOK_TIMEOUT_SECS)),
                    spec,
                ));
            }
        }
        if upgraded > 0 {
            actions.push(format!(
                "upgrade {upgraded} existing shellfirm hook(s) in hooks.{event} in place"
            ));
        }
        if !seen {
            list.push(l.entry(spec));
            actions.push(format!(
                "add hooks.{event} entry running `{}`",
                spec.hook_command(&format!("check --hook {}", l.target))
            ));
        }
    }
    if !actions.is_empty() && l.version && !root.contains_key("version") {
        root.shift_insert(0, "version".into(), json!(1));
    }
    Ok(actions)
}

fn uninstall_list(l: &ListSpec, value: &mut Value, path: &Path) -> OpResult<Vec<String>> {
    let mut actions = Vec::new();
    let Some(root) = value.as_object_mut() else {
        return Ok(actions);
    };
    let Some(hooks) = child_object(root, "hooks", path, false)? else {
        return Ok(actions);
    };
    for event in l.events {
        let Some(list) = child_array(hooks, event, &format!("hooks.{event}"), path, false)? else {
            continue;
        };
        let n = list.len();
        list.retain(|h| l.ours(h).is_none());
        if list.len() < n {
            actions.push(format!("remove shellfirm hook from hooks.{event}"));
            if list.is_empty() {
                hooks.shift_remove(*event);
            }
        }
    }
    if hooks.is_empty() && !actions.is_empty() {
        root.shift_remove("hooks");
    }
    Ok(actions)
}

// ---------------------------------------------------------------------------
// Dispatch (called from `connect_cmd::install` / `uninstall` / status)
// ---------------------------------------------------------------------------

/// Install `op` if it is one of this module's JSON operations.
pub(super) fn install(
    op: OpKind,
    value: &mut Value,
    path: &Path,
    spec: &InstallSpec,
) -> Option<OpResult<Vec<String>>> {
    if let Some(g) = group_spec(op) {
        return Some(install_groups(g, value, path, spec));
    }
    list_spec(op).map(|l| install_list(l, value, path, spec))
}

/// Uninstall `op` if it is one of this module's JSON operations.
pub(super) fn uninstall(
    op: OpKind,
    value: &mut Value,
    path: &Path,
) -> Option<OpResult<Vec<String>>> {
    if let Some(g) = group_spec(op) {
        return Some(uninstall_groups(g, value, path));
    }
    list_spec(op).map(|l| uninstall_list(l, value, path))
}

/// Fill the hook fields of `st` for one of this module's JSON operations.
/// Returns `false` for other operations.
pub(super) fn status(op: OpKind, value: &Value, st: &mut IntegrationStatus) -> bool {
    if let Some(g) = group_spec(op) {
        let s = group_state(g, value);
        st.hook_present = s.entries > 0;
        st.hook_installed = g.shell_tools.iter().all(|t| s.covered.contains(t));
        st.file_tools_covered = g.file_tools.iter().all(|t| s.covered.contains(t));
        st.config_dir = s.config_dirs.first().cloned();
        if s.entries > 0 {
            st.shell_tools_missing = g
                .shell_tools
                .iter()
                .copied()
                .filter(|t| !s.covered.contains(t))
                .collect();
        }
        if let Some(e) = shape_error(value, g.event) {
            st.error = Some(e);
        }
        if op == OpKind::GeminiHooks {
            let hc = value.get("hooksConfig");
            if hc.and_then(|h| h.get("enabled")).and_then(Value::as_bool) == Some(false) {
                st.hook_off.push(
                    "hooks are turned off (hooksConfig.enabled: false; set it to true)".into(),
                );
            }
            if hc
                .and_then(|h| h.get("disabled"))
                .and_then(Value::as_array)
                .is_some_and(|d| d.iter().any(|n| gemini_disabled_entry(g, n)))
            {
                st.hook_off.push(
                    "the shellfirm hook is listed in hooksConfig.disabled (re-run `shellfirm \
                     connect gemini` to take it out, or run `/hooks enable shellfirm` in Gemini \
                     CLI)"
                        .into(),
                );
            }
        }
        if op == OpKind::CodexHooks {
            let extra: Vec<&str> = value
                .as_object()
                .into_iter()
                .flat_map(|m| m.keys())
                .map(String::as_str)
                .filter(|k| *k != "hooks")
                .collect();
            if !extra.is_empty() {
                st.hook_off.push(format!(
                    "hooks.json has top-level keys other than `hooks` ({}), which Codex rejects \
                     (remove them)",
                    extra.join(", ")
                ));
            }
        }
        if op == OpKind::CodexHooks && s.entries > 0 {
            st.notes.push(
                "Codex runs a new or changed hook only after you trust it (the TUI asks at \
                 startup, or use /hooks; `codex exec` skips it until then)"
                    .into(),
            );
        }
        return true;
    }
    let Some(l) = list_spec(op) else {
        return false;
    };
    let per_event: Vec<Vec<(HookCmd, &Value)>> =
        l.events.iter().map(|e| l.entries(value, e)).collect();
    st.hook_present = per_event.iter().any(|e| !e.is_empty());
    st.hook_installed = !per_event[0].is_empty();
    st.file_tools_covered = per_event.iter().all(|e| !e.is_empty());
    st.config_dir = per_event
        .iter()
        .flatten()
        .find_map(|(hc, _)| hc.config_dir.clone());
    // Copilot denies a tool call when its hook command fails (except on a
    // timeout); Windsurf lets it through.
    st.fail_closed = op == OpKind::CopilotHooks && st.hook_installed;
    if let Some(e) = l.events.iter().find_map(|e| shape_error(value, e)) {
        st.error = Some(e);
    }
    if op == OpKind::CopilotHooks
        && value.get("disableAllHooks").and_then(Value::as_bool) == Some(true)
    {
        st.hook_off.push(
            "disableAllHooks is true in this file: no hook runs (remove it or set it to false)"
                .into(),
        );
    }
    true
}

/// `hooks` (or `hooks.<event>`) has a shape shellfirm cannot add its hook
/// to, so `connect` refuses the file: say so in `status`.
fn shape_error(value: &Value, event: &str) -> Option<String> {
    let hooks = value.get("hooks")?;
    if !hooks.is_object() {
        return Some("`hooks` is not an object; `shellfirm connect` refuses this file".into());
    }
    hooks
        .get(event)
        .filter(|v| !v.is_array())
        .map(|_| format!("`hooks.{event}` is not a list; `shellfirm connect` refuses this file"))
}

/// A `hooksConfig.disabled` entry naming shellfirm's Gemini hook (Gemini
/// names a hook by its `name`, else its command).
fn gemini_disabled_entry(g: &GroupSpec, v: &Value) -> bool {
    v.as_str()
        .is_some_and(|n| Some(n) == g.name || parse_shellfirm_hook(n, g.target).is_some())
}

// ---------------------------------------------------------------------------
// Files shellfirm owns (Cline script, OpenCode plugin)
// ---------------------------------------------------------------------------

/// First-lines marker of a file written by shellfirm.
pub(super) const fn marker(op: OpKind) -> &'static str {
    match op {
        OpKind::ClineScript => "# shellfirm-hook: cline",
        _ => "// shellfirm-hook: opencode",
    }
}

/// `true` when `content` is a file shellfirm wrote for `op`.
pub(super) fn is_ours(op: OpKind, content: &str) -> bool {
    content.lines().take(3).any(|l| l.trim() == marker(op))
}

/// `--config-dir` value recorded in a shellfirm-written file, if any.
pub(super) fn recorded_config_dir(op: OpKind, content: &str) -> Option<String> {
    let prefix = match op {
        OpKind::ClineScript => "# config-dir: ",
        _ => "// config-dir: ",
    };
    content
        .lines()
        .take(12)
        .find_map(|l| l.strip_prefix(prefix))
        .map(ToString::to_string)
}

/// Quote a string as a JavaScript (JSON) string literal.
fn js_string(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())
}

/// The Cline `PreToolUse` hook script. Cline (the VS Code extension and the
/// CLI) runs it with the payload on stdin and reads `{"cancel": ...}` from
/// stdout; it lets the tool call through when the script fails, so the
/// script answers `cancel: true` itself when shellfirm cannot run.
pub(super) fn cline_script(spec: &InstallSpec, fallback: Option<&str>) -> String {
    let mut s = String::new();
    s.push_str("#!/bin/sh\n");
    let _ = writeln!(s, "{}", marker(OpKind::ClineScript));
    if let Some(dir) = &spec.config_dir {
        let _ = writeln!(s, "# config-dir: {dir}");
    }
    s.push_str(
        "# Written by `shellfirm connect cline`; remove it with\n\
         # `shellfirm connect cline --uninstall`. Changes are overwritten when\n\
         # `shellfirm connect cline` runs again.\n\
         #\n\
         # Cline runs this before every tool call. shellfirm answers in Cline's\n\
         # format ({\"cancel\": true|false, ...}); if shellfirm cannot run, the\n\
         # tool call is cancelled.\n\
         SHELLFIRM=shellfirm\n",
    );
    if let Some(f) = fallback {
        let _ = writeln!(
            s,
            "command -v \"$SHELLFIRM\" >/dev/null 2>&1 || SHELLFIRM={}",
            shell_quote(f)
        );
    }
    let mut args = String::from("check --hook cline");
    if let Some(dir) = &spec.config_dir {
        let _ = write!(args, " --config-dir {}", shell_quote(dir));
    }
    let _ = writeln!(s, "out=$(\"$SHELLFIRM\" {args})");
    s.push_str(
        "status=$?\n\
         if [ \"$status\" -eq 0 ] && [ -n \"$out\" ]; then\n\
         \x20 printf '%s\\n' \"$out\"\n\
         else\n\
         \x20 printf '{\"cancel\": true, \"errorMessage\": \"shellfirm could not check this tool call (exit %s); cancelling it. Run `shellfirm doctor` or `shellfirm connect cline --uninstall`.\"}\\n' \"$status\"\n\
         fi\n\
         exit 0\n",
    );
    s
}

/// The `OpenCode` plugin (`tool.execute.before`): it sends shell, file-edit
/// and read calls to `shellfirm check --hook opencode` and throws (which
/// blocks the call) unless shellfirm answers `allow`.
pub(super) fn opencode_plugin(spec: &InstallSpec, fallback: Option<&str>) -> String {
    let mut args = vec![
        js_string("check"),
        js_string("--hook"),
        js_string("opencode"),
    ];
    if let Some(dir) = &spec.config_dir {
        args.push(js_string("--config-dir"));
        args.push(js_string(dir));
    }
    let mut s = String::new();
    let _ = writeln!(s, "{}", marker(OpKind::OpenCodePlugin));
    if let Some(dir) = &spec.config_dir {
        let _ = writeln!(s, "// config-dir: {dir}");
    }
    let _ = write!(
        s,
        r#"// Written by `shellfirm connect opencode`; remove it with
// `shellfirm connect opencode --uninstall`. Changes are overwritten when
// `shellfirm connect opencode` runs again.
//
// Before OpenCode runs a shell command, edits or reads a file, the call is
// sent to `shellfirm check --hook opencode`. Anything but an "allow" answer
// (a block, or shellfirm failing to run) throws, which stops the call.
import {{ spawn }} from "node:child_process"

const ARGS = [{args}]
const FALLBACK = {fallback}
const TOOLS = new Set(["bash", "write", "edit", "multiedit", "read", "apply_patch", "patch"])
const TIMEOUT_MS = {timeout}

function run(bin, input) {{
  return new Promise((resolve) => {{
    let child
    try {{
      child = spawn(bin, ARGS, {{ stdio: ["pipe", "pipe", "pipe"] }})
    }} catch (error) {{
      resolve({{ error }})
      return
    }}
    let stdout = ""
    let stderr = ""
    const timer = setTimeout(() => child.kill("SIGKILL"), TIMEOUT_MS)
    child.stdout.on("data", (d) => (stdout += d))
    child.stderr.on("data", (d) => (stderr += d))
    child.on("error", (error) => {{
      clearTimeout(timer)
      resolve({{ error }})
    }})
    child.on("close", (code, signal) => {{
      clearTimeout(timer)
      resolve({{ code, signal, stdout, stderr }})
    }})
    child.stdin.on("error", () => {{}})
    child.stdin.end(input)
  }})
}}

export const Shellfirm = async ({{ directory, client }}) => ({{
  "tool.execute.before": async (input, output) => {{
    if (!TOOLS.has(input.tool)) return
    const payload = JSON.stringify({{
      tool_name: input.tool,
      tool_input: output.args,
      session_id: input.sessionID,
      tool_use_id: input.callID,
      cwd: directory,
    }})
    let r = await run("shellfirm", payload)
    if (r.error && r.error.code === "ENOENT" && FALLBACK) r = await run(FALLBACK, payload)
    let answer
    try {{
      answer = r.code === 0 ? JSON.parse(r.stdout) : undefined
    }} catch {{
      answer = undefined
    }}
    if (answer && answer.decision === "allow") {{
      // An allowed change shellfirm wants reviewed (an agent-instruction edit).
      if (answer.warning) {{
        try {{
          await client.tui.showToast({{ body: {{ message: answer.warning, variant: "warning" }} }})
        }} catch {{}}
      }}
      return
    }}
    if (answer && answer.decision === "deny") {{
      throw new Error(answer.reason || "shellfirm blocked this tool call")
    }}
    const why = r.error ? r.error.message : r.signal ? `killed by ${{r.signal}}` : `exit ${{r.code}}`
    throw new Error(
      `shellfirm could not check this tool call (${{why}}${{r.stderr ? ": " + r.stderr.trim() : ""}}); blocking it. ` +
        "Run `shellfirm doctor` or `shellfirm connect opencode --uninstall`.",
    )
  }},
}})
"#,
        args = args.join(", "),
        fallback = fallback.map_or_else(|| "null".to_string(), js_string),
        timeout = HOOK_TIMEOUT_SECS * 1000,
    );
    s
}

/// The content shellfirm writes for a file it owns.
pub(super) fn owned_content(op: OpKind, spec: &InstallSpec, fallback: Option<&str>) -> String {
    match op {
        OpKind::ClineScript => cline_script(spec, fallback),
        _ => opencode_plugin(spec, fallback),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matcher_rules_follow_each_agent() {
        let c = MatcherRule::Codex;
        assert!(c.covers(None, "Bash"));
        assert!(c.covers(Some("*"), "Bash"));
        assert!(c.covers(Some("Bash|apply_patch"), "apply_patch"));
        assert!(!c.covers(Some("Bash"), "apply_patch"));
        assert!(c.covers(Some("^Ba"), "Bash"));
        assert!(
            !c.covers(Some("Bas"), "Bash"),
            "exact list, not a substring"
        );
        let g = MatcherRule::Gemini;
        assert!(
            g.covers(Some("run_shell"), "run_shell_command"),
            "unanchored regex"
        );
        assert!(g.covers(Some("^(run_shell_command|write_file)$"), "write_file"));
        assert!(!g.covers(Some("^(run_shell_command)$"), "write_file"));
        assert!(g.covers(Some(""), "read_file"));
        let q = MatcherRule::Qwen;
        assert!(q.covers(Some("run_shell_command | edit"), "edit"));
        assert!(!q.covers(Some("run_shell"), "run_shell_command"));
        assert!(q.covers(Some("^run_shell"), "run_shell_command"));
        assert!(q.covers(Some("write_file|*"), "edit"));
    }

    #[test]
    fn generated_matchers_select_exactly_the_tools() {
        for g in [&CODEX, &GEMINI, &QWEN] {
            let all: Vec<&str> = g.tools().collect();
            let m = g.matcher_for(&all);
            for t in &all {
                assert!(g.rule.covers(Some(&m), t), "{} {m} {t}", g.target);
            }
            for other in ["list_directory", "glob", "web_fetch", "Read", "mcp_x_run"] {
                assert!(!g.rule.covers(Some(&m), other), "{} {m} {other}", g.target);
            }
        }
    }

    #[test]
    fn owned_files_carry_the_marker_and_config_dir() {
        let spec = InstallSpec {
            config_dir: Some("/home/me/.config/shellfirm".into()),
            fail_closed: true,
        };
        for op in [OpKind::ClineScript, OpKind::OpenCodePlugin] {
            let content = owned_content(op, &spec, Some("/opt/bin/shellfirm"));
            assert!(is_ours(op, &content), "{content}");
            assert_eq!(
                recorded_config_dir(op, &content).as_deref(),
                Some("/home/me/.config/shellfirm")
            );
            assert!(content.contains("/opt/bin/shellfirm"));
            assert!(!is_ours(op, "#!/bin/sh\necho '{\"cancel\": false}'\n"));
        }
        let script = cline_script(&InstallSpec::default(), None);
        assert!(script.starts_with("#!/bin/sh\n# shellfirm-hook: cline\n"));
        assert!(script.contains("out=$(\"$SHELLFIRM\" check --hook cline)"));
        assert!(!script.contains("command -v"));
        let plugin = opencode_plugin(&InstallSpec::default(), None);
        assert!(plugin.contains("const ARGS = [\"check\", \"--hook\", \"opencode\"]"));
        assert!(plugin.contains("const FALLBACK = null"));
    }
}
