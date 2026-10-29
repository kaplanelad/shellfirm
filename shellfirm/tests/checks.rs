use std::{collections::HashSet, fs, path::PathBuf};

use serde_derive::Deserialize;
use shellfirm::checks::run_check_on_command_with_env;

/// A single test case in the consolidated YAML files.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct CheckTest {
    /// The command string to test against all check patterns.
    pub test: String,
    /// Human-readable description of what this test verifies.
    pub description: String,
    /// Exact set of check IDs that should match.
    /// Empty `[]` means the command must NOT match anything.
    pub expect_ids: Vec<String>,
}

/// A mock environment where every path is reported as existing.
/// This ensures check tests focus on regex matching, not filesystem state.
struct AllPathsExistEnv;

impl shellfirm::env::Environment for AllPathsExistEnv {
    fn var(&self, _key: &str) -> Option<String> {
        None
    }
    fn current_dir(&self) -> shellfirm::error::Result<PathBuf> {
        Ok(PathBuf::from("/mock"))
    }
    fn path_exists(&self, _path: &std::path::Path) -> bool {
        true
    }
    fn home_dir(&self) -> Option<PathBuf> {
        Some(PathBuf::from("/home/user"))
    }
    fn run_command(&self, _cmd: &str, _args: &[&str], _timeout_ms: u64) -> Option<String> {
        None
    }
    fn read_file(&self, _path: &std::path::Path) -> shellfirm::error::Result<String> {
        Err(shellfirm::error::Error::Other("not implemented".into()))
    }
    fn find_file_upward(&self, _start: &std::path::Path, _filename: &str) -> Option<PathBuf> {
        None
    }
}

/// The test-case files in `tests/checks/`.
///
/// Hidden files (editor locks such as `.#fs.yaml`, macOS AppleDouble
/// `._fs.yaml`) are skipped, like `build.rs` skips them for `checks/`. Any
/// other file that is not `*.yaml` (for example a `.yml` file, which would
/// otherwise be skipped silently and look like missing test cases) is an
/// error that names the file.
/// Test-case files that are not named after a check group (cases that span
/// groups).
const EXTRA_TEST_FILES: &[&str] = &["normalization"];

/// The check groups: the stems of `checks/*.yaml`.
fn check_groups() -> Vec<String> {
    fs::read_dir("./checks")
        .expect("read ./checks")
        .filter_map(|e| {
            let path = e.ok()?.path();
            if path.extension()? != "yaml" {
                return None;
            }
            Some(path.file_stem()?.to_string_lossy().to_string())
        })
        .collect()
}

fn test_files() -> Vec<PathBuf> {
    let groups = check_groups();
    let mut files = Vec::new();
    let mut wrong = Vec::new();
    for entry in fs::read_dir("./tests/checks").expect("read ./tests/checks") {
        let path = entry.expect("read a tests/checks entry").path();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if name.starts_with('.') {
            continue;
        }
        if path.is_dir() {
            wrong.push(format!(
                "{} (a directory: subdirectories are not read; put the cases in \
                 tests/checks/<group>.yaml)",
                path.display()
            ));
            continue;
        }
        let stem = path
            .file_stem()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if !path.extension().is_some_and(|ext| ext == "yaml") {
            wrong.push(path.display().to_string());
        } else if !groups.contains(&stem) && !EXTRA_TEST_FILES.contains(&stem.as_str()) {
            wrong.push(format!(
                "{} (no check group `{stem}`: there is no checks/{stem}.yaml)",
                path.display()
            ));
        } else {
            files.push(path);
        }
    }
    assert!(
        wrong.is_empty(),
        "tests/checks/ must only contain `<group>.yaml` test files named after a \
         checks/<group>.yaml file; rename or remove: {}",
        wrong.join(", ")
    );
    files.sort();
    files
}

/// Parse one test-case file; every error names the file.
fn read_cases(file: &std::path::Path) -> Vec<CheckTest> {
    let content = fs::read_to_string(file)
        .unwrap_or_else(|e| panic!("could not read {}: {e}", file.display()));
    serde_yaml::from_str(&content).unwrap_or_else(|e| {
        panic!("Failed to parse {}: {}", file.display(), e);
    })
}

/// Run every test case from every consolidated YAML file in `tests/checks/`
/// and assert that the matched check IDs exactly equal `expect_ids`.
///
/// Uses a mock environment where all paths exist so that `PathExists` filters
/// always pass. This isolates regex-matching tests from filesystem state.
#[test]
fn test_all_checks() {
    let checks = shellfirm::checks::get_all().unwrap();
    let env = AllPathsExistEnv;

    let test_files = test_files();

    assert!(
        !test_files.is_empty(),
        "No test YAML files found in tests/checks/"
    );

    let mut total_cases = 0;
    let mut total_positive = 0;
    let mut total_negative = 0;
    let mut failures: Vec<String> = Vec::new();

    for file in &test_files {
        let cases = read_cases(file);

        for case in &cases {
            let matched = run_check_on_command_with_env(&checks, &case.test, &env);
            let mut got_ids: Vec<String> = matched.iter().map(|c| c.id.clone()).collect();
            got_ids.sort();

            let mut want_ids = case.expect_ids.clone();
            want_ids.sort();

            if got_ids != want_ids {
                failures.push(format!(
                    "  File: {}\n  Command: {:?}\n  Description: {}\n  Expected: {:?}\n  Got: {:?}\n",
                    file.display(),
                    case.test,
                    case.description,
                    want_ids,
                    got_ids,
                ));
            }

            total_cases += 1;
            if case.expect_ids.is_empty() {
                total_negative += 1;
            } else {
                total_positive += 1;
            }
        }
    }

    eprintln!(
        "  check tests: {} total ({} positive, {} negative) across {} files",
        total_cases,
        total_positive,
        total_negative,
        test_files.len()
    );

    assert!(
        failures.is_empty(),
        "{} of {} check cases failed:\n\n{}",
        failures.len(),
        total_cases,
        failures.join("\n")
    );
}

/// Verify that every check ID returned by `get_all()` appears in at least
/// one `expect_ids` list across all test files. This ensures 100% coverage.
#[test]
fn test_coverage_completeness() {
    let checks = shellfirm::checks::get_all().unwrap();

    let all_check_ids: HashSet<String> = checks.iter().map(|c| c.id.clone()).collect();

    let mut covered_ids: HashSet<String> = HashSet::new();

    let test_files = test_files();

    for file in &test_files {
        let cases = read_cases(file);

        for case in cases {
            for id in &case.expect_ids {
                covered_ids.insert(id.clone());
            }
        }
    }

    let mut missing: Vec<&String> = all_check_ids.difference(&covered_ids).collect();
    missing.sort();

    assert!(
        missing.is_empty(),
        "Check IDs without any positive test case:\n  {}\n\nAdd test cases with these IDs in expect_ids to the appropriate test file in tests/checks/",
        missing
            .iter()
            .map(|id| id.as_str())
            .collect::<Vec<_>>()
            .join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// Catalogue hygiene: rules every built-in check file must follow.
//
// `build.rs` already rejects invalid YAML, unknown keys, bad regexes and a
// `from` that differs from the file name (with the file name in the error).
// The tests below re-check the per-file shape and add the rules that have
// documented legacy exceptions.
// ---------------------------------------------------------------------------

/// Groups that ship with shellfirm but are deliberately NOT in
/// `DEFAULT_ENABLED_GROUPS` (users enable them with
/// `shellfirm config groups --enable <group>`). Add a new group here only if
/// it is meant to be opt-in.
const OPT_IN_GROUPS: &[&str] = &[];

/// Ids that predate the `<group>:<name>` convention. They are kept so that
/// existing `ignores_patterns_ids` / `deny_patterns_ids` / policies keep
/// working. Do not add new entries: new checks must use `<file stem>:`.
const LEGACY_ID_PREFIXES: &[(&str, &str)] = &[
    ("base", "process"),
    ("base", "systemd"),
    ("base", "ssh"),
    ("fs", "fs-strict"),
    ("git", "git-strict"),
    ("kubernetes", "kubernetes-strict"),
    ("kubernetes", "helm"),
];

/// Ids that are intentionally defined by more than one entry (one logical
/// check split into several regexes). Every entry must have the same
/// severity. Prefer one regex per id for new checks.
const MULTI_PATTERN_IDS: &[&str] = &["git:restore_discard_all"];

const CHECK_KEYS: &[&str] = &[
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

fn builtin_check_files() -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir("./checks")
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|ext| ext == "yaml"))
        .filter(|p| !p.file_name().unwrap().to_string_lossy().starts_with('.'))
        .collect();
    files.sort();
    files
}

fn stem(p: &std::path::Path) -> String {
    p.file_stem().unwrap().to_string_lossy().into_owned()
}

/// Each `checks/<group>.yaml` parses on its own into `Vec<Check>` (so a
/// broken regex or bad enum value is reported with the file name), uses only
/// known keys, and every check's `from` equals the file name.
#[test]
fn builtin_check_files_are_well_formed() {
    let mut errors = Vec::new();
    for file in builtin_check_files() {
        let name = file.display().to_string();
        let content = fs::read_to_string(&file).unwrap();
        if let Err(e) = serde_yaml::from_str::<Vec<shellfirm::checks::Check>>(&content) {
            errors.push(format!("{name}: {e}"));
            continue;
        }
        let doc: serde_yaml::Value = serde_yaml::from_str(&content).unwrap();
        for (i, item) in doc.as_sequence().unwrap().iter().enumerate() {
            let map = item.as_mapping().unwrap();
            for k in map.keys() {
                let k = k.as_str().unwrap_or("<non-string>");
                if !CHECK_KEYS.contains(&k) {
                    errors.push(format!("{name}: [{i}] unknown key `{k}`"));
                }
            }
            if let Some(filters) = map.get("filters").and_then(|f| f.as_sequence()) {
                for (j, f) in filters.iter().enumerate() {
                    for k in f.as_mapping().unwrap().keys() {
                        let k = k.as_str().unwrap_or("<non-string>");
                        if k != "type" && k != "value" {
                            errors.push(format!("{name}: [{i}] filters[{j}] unknown key `{k}`"));
                        }
                    }
                }
            }
            let from = map.get("from").and_then(|v| v.as_str()).unwrap_or("");
            if from != stem(&file) {
                errors.push(format!(
                    "{name}: [{i}] `from: {from}` must equal the file name `{}`",
                    stem(&file)
                ));
            }
        }
    }
    assert!(
        errors.is_empty(),
        "malformed built-in checks:\n  {}",
        errors.join("\n  ")
    );
}

/// Every id is unique across all built-in files (except the documented
/// multi-pattern ids), and starts with `<file stem>:` (except documented
/// legacy prefixes).
#[test]
fn builtin_check_ids_are_unique_and_prefixed() {
    let mut errors = Vec::new();
    let mut seen: std::collections::HashMap<String, (String, String)> =
        std::collections::HashMap::new();
    for file in builtin_check_files() {
        let group = stem(&file);
        let checks: Vec<shellfirm::checks::Check> =
            serde_yaml::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
        for c in checks {
            let prefix = c.id.split(':').next().unwrap_or("");
            let legacy = LEGACY_ID_PREFIXES
                .iter()
                .any(|(g, p)| *g == group && *p == prefix);
            if !c.id.contains(':') || (prefix != group && !legacy) {
                errors.push(format!(
                    "{}: id `{}` must start with `{group}:`",
                    file.display(),
                    c.id
                ));
            }
            let sev = format!("{:?}", c.severity);
            if let Some((prev_file, prev_sev)) =
                seen.insert(c.id.clone(), (file.display().to_string(), sev.clone()))
            {
                if !MULTI_PATTERN_IDS.contains(&c.id.as_str()) {
                    errors.push(format!(
                        "{}: duplicate check id `{}` (already defined in {prev_file})",
                        file.display(),
                        c.id
                    ));
                } else if prev_sev != sev {
                    errors.push(format!(
                        "{}: multi-pattern id `{}` has different severities ({prev_sev} vs {sev})",
                        file.display(),
                        c.id
                    ));
                }
            }
        }
    }
    for id in MULTI_PATTERN_IDS {
        assert!(
            seen.contains_key(*id),
            "MULTI_PATTERN_IDS lists unknown id {id}"
        );
    }
    assert!(
        errors.is_empty(),
        "check id problems:\n  {}",
        errors.join("\n  ")
    );
}

/// A new `checks/<group>.yaml` must be registered in
/// `DEFAULT_ENABLED_GROUPS` (or listed in `OPT_IN_GROUPS`); otherwise every
/// test passes but the check never fires for users.
#[test]
fn every_builtin_group_is_enabled_by_default_or_opt_in() {
    let defaults = shellfirm::config::DEFAULT_ENABLED_GROUPS;
    let mut errors = Vec::new();
    let groups: Vec<String> = builtin_check_files().iter().map(|p| stem(p)).collect();
    for g in &groups {
        let default = defaults.contains(&g.as_str());
        let opt_in = OPT_IN_GROUPS.contains(&g.as_str());
        if default == opt_in {
            errors.push(format!(
                "group `{g}` must be in exactly one of DEFAULT_ENABLED_GROUPS \
                 (shellfirm/src/config.rs) or OPT_IN_GROUPS (tests/checks.rs)"
            ));
        }
    }
    let hint = |name: &str| {
        let close = shellfirm::config::suggest_similar(name, groups.iter().map(String::as_str), 1);
        close
            .first()
            .map_or_else(String::new, |g| format!(" (did you mean `{g}`?)"))
    };
    for d in defaults {
        if !groups.iter().any(|g| g == d) {
            errors.push(format!(
                "DEFAULT_ENABLED_GROUPS lists `{d}` but checks/{d}.yaml does not exist{}",
                hint(d)
            ));
        }
    }
    for o in OPT_IN_GROUPS {
        if !groups.iter().any(|g| g == o) {
            errors.push(format!(
                "OPT_IN_GROUPS lists `{o}` but checks/{o}.yaml does not exist{}",
                hint(o)
            ));
        }
    }
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

/// Alternatives a check's own regex accepts on purpose, as
/// `(check id, reason)`. Keep this list short: an alternative is what users
/// and agents are told to run instead ("Safe alternative: …"), so it should
/// not trigger the same check again.
const SELF_MATCHING_ALTERNATIVES: &[(&str, &str)] = &[];

/// Every built-in `alternative` is non-empty and does not itself trigger
/// the check it is the alternative of (following the advice must not lead
/// to the same challenge).
#[test]
fn alternatives_are_non_empty_and_do_not_trigger_their_own_check() {
    let checks = shellfirm::checks::get_all().unwrap();
    let env = AllPathsExistEnv;
    let mut errors = Vec::new();
    let mut used_allow_entries = HashSet::new();
    for c in &checks {
        if let Some(info) = &c.alternative_info {
            if info.trim().is_empty() {
                errors.push(format!("{}: `alternative_info` is empty", c.id));
            }
        }
        let Some(alt) = &c.alternative else { continue };
        if alt.trim().is_empty() {
            errors.push(format!("{}: `alternative` is empty", c.id));
            continue;
        }
        let matched = run_check_on_command_with_env(&checks, alt, &env);
        let allowed = SELF_MATCHING_ALTERNATIVES.iter().any(|(id, _)| *id == c.id);
        let self_matches = matched.iter().any(|m| m.id == c.id);
        if self_matches && allowed {
            used_allow_entries.insert(c.id.clone());
        }
        if self_matches && !allowed {
            errors.push(format!(
                "{}: its alternative `{alt}` triggers the same check again; change the \
                 alternative (or the regex), or list it in SELF_MATCHING_ALTERNATIVES with a reason",
                c.id
            ));
        }
    }
    for (id, _) in SELF_MATCHING_ALTERNATIVES {
        if !checks.iter().any(|c| c.id == *id) {
            errors.push(format!(
                "SELF_MATCHING_ALTERNATIVES lists `{id}`, which is not a built-in check"
            ));
        } else if !used_allow_entries.contains(*id) {
            errors.push(format!(
                "SELF_MATCHING_ALTERNATIVES lists `{id}`, but its alternative no longer \
                 triggers the check; remove the stale entry"
            ));
        }
    }
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

/// Alternatives that trigger *another* check at the same or a higher
/// severity on purpose, as `(check id, triggered check id, reason)`. Keep
/// this list short: "Safe alternative: X" must not lead to an equal or
/// bigger challenge.
const CROSS_MATCHING_ALTERNATIVES: &[(&str, &str, &str)] = &[(
    "base:crontab_replace",
    "fs:flush_file_content",
    "`crontab -l > crontab.backup` only overwrites when crontab.backup already exists \
     (this test reports every path as existing); writing a fresh backup is not flagged",
)];

/// Following a built-in alternative must not trigger any check (the same or
/// another one) at the same or a higher severity than the check it replaces.
/// Lower-severity matches are fine (the alternative is still safer).
#[test]
fn alternatives_do_not_trigger_checks_at_the_same_or_higher_severity() {
    let checks = shellfirm::checks::get_all().unwrap();
    let env = AllPathsExistEnv;
    let mut errors = Vec::new();
    let mut used = HashSet::new();
    for c in &checks {
        let Some(alt) = &c.alternative else { continue };
        for m in run_check_on_command_with_env(&checks, alt, &env) {
            if m.id == c.id || m.severity < c.severity {
                // Self-matches are covered (with their own allow-list) above.
                continue;
            }
            let allowed = CROSS_MATCHING_ALTERNATIVES
                .iter()
                .any(|(id, other, _)| *id == c.id && *other == m.id);
            if allowed {
                used.insert((c.id.clone(), m.id.clone()));
            } else {
                errors.push(format!(
                    "{} ({}): its alternative `{alt}` triggers `{}` ({}), which is not \
                     less severe; change the alternative (or narrow `{}`), or list the pair \
                     in CROSS_MATCHING_ALTERNATIVES with a reason",
                    c.id, c.severity, m.id, m.severity, m.id
                ));
            }
        }
    }
    for (id, other, _) in CROSS_MATCHING_ALTERNATIVES {
        if !used.contains(&((*id).to_string(), (*other).to_string())) {
            errors.push(format!(
                "CROSS_MATCHING_ALTERNATIVES lists (`{id}`, `{other}`), but that alternative no \
                 longer triggers it at the same or a higher severity; remove the stale entry"
            ));
        }
    }
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

/// Check ids whose regex starts with a bare command name on purpose, as
/// `(check id, reason)`. A regex that starts with a tool name must anchor it
/// (`(?:^|\s)tool\s+…`, `^tool`, `\btool`), or `mygit push -f`,
/// `hugh repo delete x` and `xdocker system prune` match too. `sudo`, `env`,
/// wrappers and `/usr/bin/` paths are removed by the parser before matching,
/// so the anchor never loses a real invocation. Keep this list empty unless
/// a rule has to match a name glued to other text.
const UNANCHORED_COMMAND_IDS: &[(&str, &str)] = &[];

/// The top-level alternatives of a regex (`a|b|(c|d)` gives `a`, `b`,
/// `(c|d)`), skipping escapes and character classes.
fn top_level_alternatives(re: &str) -> Vec<&str> {
    let bytes = re.as_bytes();
    let (mut depth, mut in_class, mut start, mut i) = (0i32, false, 0, 0);
    let mut out = Vec::new();
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 1,
            b']' if in_class => in_class = false,
            _ if in_class => {}
            b'[' => in_class = true,
            b'(' => depth += 1,
            b')' => depth -= 1,
            b'|' if depth == 0 => {
                out.push(&re[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    out.push(&re[start..]);
    out
}

/// Whether `branch` (one alternative of a check regex) starts with a command
/// name that is not anchored. Leading groups are looked into, so
/// `(?:sudo\s+)?(?:lvremove|…)` and `(halt|poweroff)` count as bare names,
/// while `(?:^|\s)tool`, `(^|\s)tool`, `^\s*DROP`, `\bdb\.` and patterns that
/// do not start with a word (`\.dropIndex(`, `:\(\)\{`) do not.
fn starts_with_unanchored_name(branch: &str) -> bool {
    let mut s = branch;
    loop {
        if let Some(rest) = s.strip_prefix("(?:") {
            s = rest;
        } else if let Some(rest) = strip_flag_group(s) {
            // `(?i:tool …)` / `(?i)tool`: flags change nothing about the
            // anchor.
            s = rest;
        } else if let Some(rest) = s.strip_prefix('(').filter(|r| !r.starts_with('?')) {
            s = rest;
        } else if let Some(rest) = s.strip_prefix("\\s*") {
            s = rest;
        } else {
            break;
        }
    }
    if let Some(rest) = s.strip_prefix("\\b") {
        // `\b` is not a command boundary: `\btool\s` also matches
        // `my-tool …` and `x.tool …`. A word that is not a command (`\bdb\.`)
        // is fine.
        let name_len = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
            .unwrap_or(rest.len());
        return name_len > 0 && rest[name_len..].starts_with("\\s");
    }
    if s.starts_with('^') || s.starts_with("\\s") {
        return false;
    }
    s.starts_with(|c: char| c.is_ascii_alphabetic())
}

/// `s` without a leading inline-flag group opener (`(?i:`, `(?ix:`) or
/// flag setting (`(?i)`), if it starts with one.
fn strip_flag_group(s: &str) -> Option<&str> {
    let rest = s.strip_prefix("(?")?;
    let end = rest.find([':', ')'])?;
    let flags = &rest[..end];
    (!flags.is_empty() && flags.chars().all(|c| c.is_ascii_alphabetic() || c == '-'))
        .then(|| &rest[end + 1..])
}

/// Every alternative of a group the regex starts with, recursively
/// (`(?:(?:^|\s)a|b)` must anchor `b` too).
fn leading_group_alternatives(re: &str) -> Vec<String> {
    let mut out = Vec::new();
    for branch in top_level_alternatives(re) {
        out.push(branch.to_string());
        let inner = branch
            .strip_prefix("(?:")
            .or_else(|| {
                // `(?i:…)`: an inline-flag group is looked into too.
                strip_flag_group(branch)
                    .filter(|_| branch.find(':').is_some_and(|c| Some(c) < branch.find(')')))
            })
            .or_else(|| branch.strip_prefix('(').filter(|r| !r.starts_with('?')));
        if let Some(inner) = inner {
            // The group's body up to its closing parenthesis.
            let bytes = inner.as_bytes();
            let (mut depth, mut in_class, mut i) = (0i32, false, 0);
            while i < bytes.len() {
                match bytes[i] {
                    b'\\' => i += 1,
                    b']' if in_class => in_class = false,
                    _ if in_class => {}
                    b'[' => in_class = true,
                    b'(' => depth += 1,
                    b')' if depth == 0 => break,
                    b')' => depth -= 1,
                    _ => {}
                }
                i += 1;
            }
            let body = &inner[..i.min(inner.len())];
            if body != "^" && !body.starts_with("^|") {
                out.extend(leading_group_alternatives(body));
            }
        }
    }
    out
}

#[test]
fn anchor_guard_sees_flag_groups_and_word_boundaries() {
    for bad in [
        "(?i:tool)\\s+delete",
        "(?i)tool\\s+delete",
        "\\btool\\s+delete",
        "(?:\\btool|other)\\s",
        "tool\\s",
    ] {
        assert!(
            leading_group_alternatives(bad)
                .iter()
                .any(|b| starts_with_unanchored_name(b)),
            "{bad}"
        );
    }
    for good in [
        "(?:^|\\s)tool\\s+delete",
        "(?i:(?:^|\\s)tool)\\s",
        "\\bdb\\.dropDatabase",
        "^\\s*DROP\\s",
        "\\.dropIndex\\(",
    ] {
        assert!(
            !leading_group_alternatives(good)
                .iter()
                .any(|b| starts_with_unanchored_name(b)),
            "{good}"
        );
    }
}

/// A check regex that starts with a command name must anchor
/// it, in every top-level alternative (and every alternative of a leading
/// group). Ratchet: new unanchored ids fail; listed ids must still be
/// unanchored (stale entries fail).
#[test]
fn command_name_regexes_are_anchored() {
    let checks = shellfirm::checks::get_all().unwrap();
    let mut errors = Vec::new();
    let mut used = HashSet::new();
    for c in &checks {
        let re = c.test.as_str();
        let re = re.strip_prefix("(?i)").unwrap_or(re);
        let bad: Vec<String> = leading_group_alternatives(re)
            .into_iter()
            .filter(|b| starts_with_unanchored_name(b))
            .collect();
        let allowed = UNANCHORED_COMMAND_IDS.iter().any(|(id, _)| *id == c.id);
        if bad.is_empty() {
            continue;
        }
        if allowed {
            used.insert(c.id.clone());
        } else {
            errors.push(format!(
                "{}: the regex starts with an unanchored command name ({}); write \
                 `(?:^|\\s)tool\\s+…` so that `mytool …` does not match",
                c.id,
                bad.join(" | ")
            ));
        }
    }
    for (id, _) in UNANCHORED_COMMAND_IDS {
        if !used.contains(*id) {
            errors.push(format!(
                "UNANCHORED_COMMAND_IDS lists `{id}`, which is anchored now (or not a \
                 built-in check); remove the stale entry"
            ));
        }
    }
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

/// Every built-in id has the form `<group>:<snake_case_name>` (build.rs
/// enforces the same rule with the file name and index in the error).
#[test]
fn builtin_check_ids_are_snake_case() {
    let checks = shellfirm::checks::get_all().unwrap();
    let bad: Vec<&str> = checks
        .iter()
        .map(|c| c.id.as_str())
        .filter(|id| {
            let Some((group, name)) = id.split_once(':') else {
                return true;
            };
            group.is_empty()
                || name.is_empty()
                || !group
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        })
        .collect();
    assert!(
        bad.is_empty(),
        "ids must be `<group>:<snake_case_name>` (^[a-z0-9-]+:[a-z0-9_]+$): {}",
        bad.join(", ")
    );
}

// ---------------------------------------------------------------------------
// Generated check catalogue (docs/checks/README.md).
//
// Regenerate after changing any checks/*.yaml:
//   make catalogue   (from the repository root)
// ---------------------------------------------------------------------------

const CATALOGUE_PATH: &str = "../docs/checks/README.md";

fn md_cell(s: &str) -> String {
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace('|', "\\|")
}

fn render_catalogue() -> String {
    use std::fmt::Write as _;
    let defaults = shellfirm::config::DEFAULT_ENABLED_GROUPS;
    let files = builtin_check_files();
    let mut out = String::new();
    out.push_str(
        "<!-- GENERATED FILE, do not edit by hand.\n     \
         Regenerate from the repository root: make catalogue -->\n\n",
    );
    out.push_str("# Built-in checks\n\n");
    let unique_ids = |f: &PathBuf| -> usize {
        serde_yaml::from_str::<Vec<shellfirm::checks::Check>>(&fs::read_to_string(f).unwrap())
            .unwrap()
            .into_iter()
            .map(|c| c.id)
            .collect::<HashSet<_>>()
            .len()
    };
    let total: usize = files.iter().map(unique_ids).sum();
    let _ = writeln!(
        out,
        "{total} checks in {} groups, generated from \
         [`shellfirm/checks/`](../../shellfirm/checks). List them locally with \
         `shellfirm check --list -a` (add `-g <group>` to filter).\n",
        files.len()
    );
    out.push_str("| Group | Checks | Enabled by default |\n|---|---:|---|\n");
    let mut sections = String::new();
    for f in &files {
        let group = stem(f);
        let checks: Vec<shellfirm::checks::Check> =
            serde_yaml::from_str(&fs::read_to_string(f).unwrap()).unwrap();
        let enabled = if defaults.contains(&group.as_str()) {
            "yes"
        } else {
            "no (opt-in)"
        };
        let _ = writeln!(
            out,
            "| [{group}](#{group}) | {} | {enabled} |",
            unique_ids(f)
        );
        let _ = writeln!(sections, "\n## {group}\n");
        sections.push_str("| Id | Severity | Description | Alternative |\n|---|---|---|---|\n");
        let mut seen = HashSet::new();
        for c in &checks {
            if !seen.insert(c.id.clone()) {
                continue; // multi-pattern id: list once
            }
            let alt = c
                .alternative
                .as_deref()
                .map(|a| format!("`{}`", md_cell(a).replace('`', "'")))
                .unwrap_or_default();
            let _ = writeln!(
                sections,
                "| `{}` | {} | {} | {alt} |",
                c.id,
                c.severity,
                md_cell(&c.description)
            );
        }
    }
    out.push_str(&sections);
    out
}

#[test]
fn catalogue_is_up_to_date() {
    let want = render_catalogue();
    if std::env::var_os("SHELLFIRM_UPDATE_CATALOGUE").is_some() {
        fs::write(CATALOGUE_PATH, &want).unwrap();
        return;
    }
    // A Windows checkout may convert the file to CRLF; compare line content only.
    let have = fs::read_to_string(CATALOGUE_PATH)
        .unwrap_or_default()
        .replace("\r\n", "\n");
    assert!(
        have == want,
        "docs/checks/README.md is out of date with shellfirm/checks/*.yaml.\n\
         Regenerate it from the repository root: make catalogue"
    );
}
