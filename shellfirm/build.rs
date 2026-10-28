//! Build script: concatenates `checks/*.yaml` into `$OUT_DIR/all-checks.yaml`
//! (embedded by `src/checks.rs`) and validates every file on its own first.
//!
//! Validation runs here so that a broken built-in check fails the build with
//! an error that names the source file (`checks/<group>.yaml`), instead of
//! panicking at runtime in every user's shell hook. It checks:
//! - the file is valid YAML and a list of mappings,
//! - required keys are present and no unknown keys are used (typos such as
//!   `severty:` would otherwise be ignored silently),
//! - `test` and `NotMatches`/`Matches` filter values compile as regexes,
//! - `severity`, `challenge` and filter `type` values are known,
//! - `from` equals the file name,
//! - every id has the form `<group>:<snake_case_name>`
//!   (`^[a-z0-9-]+:[a-z0-9_]+$`).
//!
//! Id-prefix and id-uniqueness rules have documented legacy exceptions, so
//! they are enforced by `tests/checks.rs` instead (see `LEGACY_ID_PREFIXES`).
//!
//! It also writes `$OUT_DIR/builtin-checks.rs`: every built-in check as
//! static Rust data (`BUILTIN_CHECKS`, in `all-checks.yaml` order), so the
//! shell hook does not parse YAML on every call. Each entry carries a set of
//! folded literals of which at least one must occur in any text its `test`
//! regex matches: at runtime a check whose literals are all absent is
//! skipped without compiling its regex (see `src/prefilter.rs`). The same
//! literals are derived for the agent self-protection patterns
//! (`$OUT_DIR/self-protection-prefilters.rs`).

use std::{env, fmt::Write as _, fs, path::Path};

use regex_syntax::hir::{Class, Hir, HirKind};
use serde_yaml::Value;

#[allow(dead_code)]
#[path = "src/prefilter.rs"]
mod prefilter;

#[allow(dead_code)]
#[path = "src/agent_patterns.rs"]
mod agent_patterns;

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
const REQUIRED_KEYS: &[&str] = &["id", "test", "description", "from"];
const SEVERITIES: &[&str] = &["Info", "Low", "Medium", "High", "Critical"];
const CHALLENGES: &[&str] = &["Enter", "Math", "Yes"];
const FILTER_TYPES: &[&str] = &[
    "PathExists",
    "NotContains",
    "Contains",
    "NotMatches",
    "Matches",
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=checks/");
    println!("cargo:rerun-if-changed=src/prefilter.rs");
    println!("cargo:rerun-if-changed=src/agent_patterns.rs");

    let out_dir = env::var("OUT_DIR")?;
    let dest_checks_path = Path::new(&out_dir).join("all-checks.yaml");

    let mut paths: Vec<_> = fs::read_dir("./checks")?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "yaml"))
        // Skip hidden files (editor swap files, macOS `._*` metadata).
        .filter(|p| {
            !p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with('.'))
        })
        .collect();
    paths.sort();

    let mut errors: Vec<String> = Vec::new();
    // A `.yml` (or any non-`.yaml`) file would be skipped silently and its
    // checks would never ship: name it instead.
    for entry in fs::read_dir("./checks")?.filter_map(Result::ok) {
        let p = entry.path();
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if !name.starts_with('.') && p.is_file() && p.extension().is_none_or(|e| e != "yaml") {
            errors.push(format!(
                "checks/{name}: built-in check files must be named `<group>.yaml`; rename it"
            ));
        } else if !name.starts_with('.') && p.is_dir() {
            // Only `checks/<group>.yaml` is read: checks in a subdirectory
            // would pass the tests and never ship.
            errors.push(format!(
                "checks/{name}/: built-in check files must be `checks/<group>.yaml`; \
                 subdirectories are not read (move the files up and name them after their group)"
            ));
        }
    }
    let mut all_group_checks = String::new();
    let mut builtin: Vec<String> = Vec::new();
    for path in &paths {
        let display = format!("checks/{}", path.file_name().unwrap().to_string_lossy());
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("check file name is UTF-8");
        let contents = fs::read_to_string(path)?;
        validate_file(&display, stem, &contents, &mut errors, &mut builtin);
        all_group_checks.push_str(&contents);
        all_group_checks.push('\n');
    }

    if !errors.is_empty() {
        eprintln!("error: {} problem(s) in built-in checks:", errors.len());
        for e in &errors {
            println!("cargo:warning={e}");
            eprintln!("  {e}");
        }
        std::process::exit(1);
    }

    fs::write(dest_checks_path, all_group_checks)?;
    fs::write(
        Path::new(&out_dir).join("builtin-checks.rs"),
        format!(
            "/// Every built-in check (generated by build.rs from `checks/*.yaml`).\n\
             static BUILTIN_CHECKS: &[BuiltinCheck] = &[\n{}];\n",
            builtin.concat()
        ),
    )?;
    let self_protection: Vec<(String, Vec<String>)> = agent_patterns::ALL
        .iter()
        .map(|p| ((*p).to_string(), required_literals(p)))
        .collect();
    fs::write(
        Path::new(&out_dir).join("self-protection-prefilters.rs"),
        render_prefilters("SELF_PROTECTION_PREFILTERS", &self_protection),
    )?;
    Ok(())
}

/// Rust source for a `(regex source, literals)` table named `name`. An
/// empty literal list means "no prefilter" (the regex is always run).
fn render_prefilters(name: &str, prefilters: &[(String, Vec<String>)]) -> String {
    let mut out = format!(
        "/// `(regex source, folded required literals)`, generated by build.rs.\n\
         pub(crate) const {name}: &[(&str, &[&str])] = &[\n",
    );
    for (test, lits) in prefilters {
        let _ = writeln!(out, "    ({test:?}, &{lits:?}),");
    }
    out.push_str("];\n");
    out
}

/// What a sub-expression requires: any match of it contains at least one of
/// `lits` (folded). When `exact`, every match of it is (after folding) exactly
/// one of `lits`, so it can be concatenated with its neighbours.
struct Req {
    lits: Vec<String>,
    exact: bool,
}

/// Largest literal set kept (alternations, cross products, classes).
const MAX_LITS: usize = 64;

/// Folded literals of which one must occur in every match of `pattern`, or
/// an empty list when no useful set can be derived.
fn required_literals(pattern: &str) -> Vec<String> {
    let Ok(hir) = regex_syntax::Parser::new().parse(pattern) else {
        return Vec::new();
    };
    match req(&hir) {
        Some(r) if r.lits.iter().all(|l| !l.is_empty()) => minimize(r.lits),
        _ => Vec::new(),
    }
}

/// Drop literals that contain another literal of the set (finding the
/// shorter one is implied), and collapse a large set to its longest common
/// prefix / suffix (a weaker, still necessary condition).
fn minimize(mut lits: Vec<String>) -> Vec<String> {
    lits.sort_by_key(|l| (l.len(), l.clone()));
    let mut kept: Vec<String> = Vec::new();
    for l in lits {
        if !kept.iter().any(|k| l.contains(k.as_str())) {
            kept.push(l);
        }
    }
    if kept.len() > 16 {
        let common = |rev: bool| -> String {
            let seqs: Vec<Vec<char>> = kept
                .iter()
                .map(|l| {
                    let mut v: Vec<char> = l.chars().collect();
                    if rev {
                        v.reverse();
                    }
                    v
                })
                .collect();
            let mut n = 0;
            while seqs.iter().all(|s| s.len() > n && s[n] == seqs[0][n]) {
                n += 1;
            }
            let mut c: Vec<char> = seqs[0][..n].to_vec();
            if rev {
                c.reverse();
            }
            c.into_iter().collect()
        };
        let (prefix, suffix) = (common(false), common(true));
        let best = if prefix.chars().count() >= suffix.chars().count() {
            prefix
        } else {
            suffix
        };
        if best.chars().count() >= 2 {
            return vec![best];
        }
    }
    kept
}

const fn exact(lits: Vec<String>) -> Req {
    Req { lits, exact: true }
}

fn req(hir: &Hir) -> Option<Req> {
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => Some(exact(vec![String::new()])),
        HirKind::Literal(lit) => {
            let s = std::str::from_utf8(&lit.0).ok()?;
            Some(exact(vec![s.chars().map(prefilter::fold_char).collect()]))
        }
        HirKind::Class(class) => {
            let mut chars: Vec<char> = Vec::new();
            match class {
                Class::Unicode(c) => {
                    for r in c.ranges() {
                        if (r.end() as u32 - r.start() as u32) as usize >= MAX_LITS {
                            return None;
                        }
                        chars.extend(r.start()..=r.end());
                    }
                }
                Class::Bytes(c) => {
                    for r in c.ranges() {
                        if !r.end().is_ascii() {
                            return None;
                        }
                        chars.extend((r.start()..=r.end()).map(char::from));
                    }
                }
            }
            let mut lits: Vec<String> = chars
                .into_iter()
                .map(|c| prefilter::fold_char(c).to_string())
                .collect();
            lits.sort();
            lits.dedup();
            (lits.len() <= MAX_LITS).then_some(Req { lits, exact: true })
        }
        HirKind::Capture(c) => req(&c.sub),
        HirKind::Repetition(r) => {
            if r.min == 0 {
                return None;
            }
            let sub = req(&r.sub)?;
            let once = r.min == 1 && r.max == Some(1);
            Some(Req {
                lits: sub.lits,
                exact: sub.exact && once,
            })
        }
        HirKind::Alternation(alts) => {
            let mut lits = Vec::new();
            let mut all_exact = true;
            for a in alts {
                let r = req(a)?;
                all_exact &= r.exact;
                lits.extend(r.lits);
            }
            lits.sort();
            lits.dedup();
            (lits.len() <= MAX_LITS).then_some(Req {
                lits,
                exact: all_exact,
            })
        }
        HirKind::Concat(parts) => concat_req(parts),
    }
}

/// A concatenation requires the literals of any one of its parts. Runs of
/// exact parts are joined (cross product) into longer literals first, then
/// the most selective candidate is kept.
fn concat_req(parts: &[Hir]) -> Option<Req> {
    let mut candidates: Vec<Vec<String>> = Vec::new();
    let mut run: Vec<String> = vec![String::new()];
    let mut broken = false;
    for part in parts {
        match req(part) {
            Some(r) if r.exact => {
                if run.len() * r.lits.len() <= MAX_LITS {
                    run = run
                        .iter()
                        .flat_map(|a| r.lits.iter().map(move |b| format!("{a}{b}")))
                        .collect();
                } else {
                    candidates.push(std::mem::replace(&mut run, r.lits));
                    broken = true;
                }
            }
            Some(r) => {
                candidates.push(std::mem::replace(&mut run, vec![String::new()]));
                candidates.push(r.lits);
                broken = true;
            }
            None => {
                candidates.push(std::mem::replace(&mut run, vec![String::new()]));
                broken = true;
            }
        }
    }
    if !broken {
        run.sort();
        run.dedup();
        return Some(exact(run));
    }
    candidates.push(run);
    candidates
        .into_iter()
        .filter(|c| c.iter().all(|l| !l.is_empty()))
        .max_by_key(|c| {
            let min_len = c.iter().map(|l| l.chars().count()).min().unwrap_or(0);
            (min_len, std::cmp::Reverse(c.len()))
        })
        .map(|mut lits| {
            lits.sort();
            lits.dedup();
            Req { lits, exact: false }
        })
}

fn validate_file(
    file: &str,
    stem: &str,
    contents: &str,
    errors: &mut Vec<String>,
    builtin: &mut Vec<String>,
) {
    let doc: Value = match serde_yaml::from_str(contents) {
        Ok(v) => v,
        Err(e) => {
            errors.push(format!("{file}: invalid YAML: {e}"));
            return;
        }
    };
    let Some(items) = doc.as_sequence() else {
        errors.push(format!("{file}: expected a list of checks (`- id: ...`)"));
        return;
    };
    for (i, item) in items.iter().enumerate() {
        let Some(map) = item.as_mapping() else {
            errors.push(format!("{file}: item [{i}] is not a mapping"));
            continue;
        };
        let id = map
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("<missing id>")
            .to_string();
        let at = format!("{file}: [{i}] {id}");
        if map.get("id").and_then(Value::as_str).is_some() && !is_valid_id(&id) {
            errors.push(format!(
                "{at}: id `{id}` must be `<group>:<snake_case_name>`: lowercase ASCII \
                 letters, digits and `-` before the `:`, lowercase letters, digits and `_` \
                 after it (for example `{stem}:{}`)",
                suggest_id_name(&id)
            ));
        }

        for k in map.keys() {
            let key = k.as_str().unwrap_or("<non-string key>");
            if !CHECK_KEYS.contains(&key) {
                errors.push(format!(
                    "{at}: unknown key `{key}` (valid keys: {})",
                    CHECK_KEYS.join(", ")
                ));
            }
        }
        for req in REQUIRED_KEYS {
            if map.get(*req).and_then(Value::as_str).is_none() {
                errors.push(format!("{at}: missing or non-string `{req}`"));
            }
        }
        // An empty text would ship as "Safe alternative:  (...)" or a blank
        // description.
        for key in ["description", "alternative", "alternative_info"] {
            if map
                .get(key)
                .and_then(Value::as_str)
                .is_some_and(|v| v.trim().is_empty())
            {
                errors.push(format!(
                    "{at}: `{key}` is empty; write the text or remove the key"
                ));
            }
        }
        let test = map.get("test").and_then(Value::as_str);
        let groups = match test.map(regex::Regex::new) {
            Some(Ok(re)) if test.is_some_and(|t| t.trim().is_empty()) => {
                errors.push(format!(
                    "{at}: `test` is empty, so the check would match every command; write a \
                     regex for the risky command, e.g. `(?:^|\\s)tool\\s+delete(?:\\s|$)`"
                ));
                re.captures_len().saturating_sub(1)
            }
            Some(Ok(re))
                if re.is_match("") || ["ls", "x", "true"].iter().all(|c| re.is_match(c)) =>
            {
                errors.push(format!(
                    "{at}: `test` matches every command (it matches empty text or `ls`), so \
                     every command would be challenged; anchor it on the command, e.g. \
                     `(?:^|\\s)tool\\s+delete(?:\\s|$)`"
                ));
                re.captures_len().saturating_sub(1)
            }
            Some(Ok(re)) => re.captures_len().saturating_sub(1),
            Some(Err(e)) => {
                errors.push(format!("{at}: `test` is not a valid regex: {e}"));
                usize::MAX
            }
            None => usize::MAX,
        };
        check_enum(map, "severity", SEVERITIES, &at, errors);
        check_enum(map, "challenge", CHALLENGES, &at, errors);
        if let Some(from) = map.get("from").and_then(Value::as_str) {
            if from != stem {
                errors.push(format!(
                    "{at}: `from: {from}` does not match the file name (expected `from: {stem}`)"
                ));
            }
        }
        if let Some(filters) = map.get("filters") {
            validate_filters(filters, groups, &at, errors);
        }
        builtin.push(render_check(map, &at, errors));
    }
}

/// Whether `id` has the form `<group>:<name>` (`^[a-z0-9-]+:[a-z0-9_]+$`).
/// Ids are typed in `ignores_patterns_ids`, policies and CLI flags, so they
/// must not need quoting.
fn is_valid_id(id: &str) -> bool {
    let Some((group, name)) = id.split_once(':') else {
        return false;
    };
    !group.is_empty()
        && !name.is_empty()
        && group
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// The name part of `id` rewritten as `snake_case`, for the error hint.
fn suggest_id_name(id: &str) -> String {
    let name = id.split_once(':').map_or(id, |(_, n)| n);
    let mut out = String::new();
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.is_empty() && !out.ends_with('_') {
            out.push('_');
        }
    }
    let out = out.trim_end_matches('_').to_string();
    if out.is_empty() {
        "my_check".to_string()
    } else {
        out
    }
}

/// One `BuiltinCheck { .. }` entry of `BUILTIN_CHECKS` (Rust source).
/// Values were validated above; missing ones render as defaults (the build
/// fails on those errors anyway).
fn render_check(map: &serde_yaml::Mapping, at: &str, errors: &mut Vec<String>) -> String {
    let field = |key: &str| map.get(key).and_then(Value::as_str).unwrap_or_default();
    let mut optional = |key: &str| -> String {
        match map.get(key) {
            None | Some(Value::Null) => "None".to_string(),
            Some(v) => v.as_str().map_or_else(
                || {
                    errors.push(format!("{at}: `{key}` must be a string"));
                    "None".to_string()
                },
                |s| format!("Some({s:?})"),
            ),
        }
    };
    let alternative = optional("alternative");
    let alternative_info = optional("alternative_info");
    let variant = |key: &str, ty: &str| {
        map.get(key)
            .and_then(Value::as_str)
            .map_or_else(|| "None".to_string(), |v| format!("Some({ty}::{v})"))
    };
    let mut filters = String::new();
    for f in map
        .get("filters")
        .and_then(Value::as_sequence)
        .into_iter()
        .flatten()
    {
        let ty = f.get("type").and_then(Value::as_str).unwrap_or_default();
        let value = f.get("value");
        let arg = if ty == "PathExists" {
            value
                .and_then(Value::as_u64)
                .unwrap_or_default()
                .to_string()
        } else {
            format!("{:?}", value.and_then(Value::as_str).unwrap_or_default())
        };
        if FILTER_TYPES.contains(&ty) {
            let _ = write!(filters, "BuiltinFilter::{ty}({arg}), ");
        }
    }
    let test = field("test");
    format!(
        "    BuiltinCheck {{ id: {:?}, test: {test:?}, description: {:?}, from: {:?}, \
         challenge: {}, filters: &[{filters}], alternative: {alternative}, \
         alternative_info: {alternative_info}, severity: {}, literals: &{:?} }},\n",
        field("id"),
        field("description"),
        field("from"),
        variant("challenge", "Challenge"),
        variant("severity", "Severity"),
        required_literals(test),
    )
}

fn check_enum(
    map: &serde_yaml::Mapping,
    key: &str,
    allowed: &[&str],
    at: &str,
    errors: &mut Vec<String>,
) {
    if let Some(v) = map.get(key) {
        match v.as_str() {
            Some(s) if allowed.contains(&s) => {}
            _ => errors.push(format!(
                "{at}: `{key}` must be one of {}",
                allowed.join(", ")
            )),
        }
    }
}

fn validate_filters(filters: &Value, groups: usize, at: &str, errors: &mut Vec<String>) {
    let Some(list) = filters.as_sequence() else {
        errors.push(format!("{at}: `filters` must be a list"));
        return;
    };
    for (j, f) in list.iter().enumerate() {
        let Some(m) = f.as_mapping() else {
            errors.push(format!("{at}: filters[{j}] is not a mapping"));
            continue;
        };
        for k in m.keys() {
            let key = k.as_str().unwrap_or("<non-string key>");
            if key != "type" && key != "value" {
                errors.push(format!(
                    "{at}: filters[{j}]: unknown key `{key}` (valid keys: type, value)"
                ));
            }
        }
        let ty = m.get("type").and_then(Value::as_str).unwrap_or("");
        if !FILTER_TYPES.contains(&ty) {
            errors.push(format!(
                "{at}: filters[{j}]: `type` must be one of {}",
                FILTER_TYPES.join(", ")
            ));
            continue;
        }
        let value = m.get("value");
        match ty {
            "PathExists" => match value.and_then(Value::as_u64) {
                None => errors.push(format!(
                    "{at}: filters[{j}]: PathExists needs a capture-group number"
                )),
                Some(n) if n == 0 || usize::try_from(n).map_or(true, |n| n > groups) => errors
                    .push(format!(
                        "{at}: filters[{j}]: PathExists capture group {n} does not exist \
                         (the regex has {groups})"
                    )),
                Some(_) => {}
            },
            _ => match value.and_then(Value::as_str) {
                None => errors.push(format!("{at}: filters[{j}]: {ty} needs a string value")),
                Some(s) if ty == "NotMatches" || ty == "Matches" => {
                    if let Err(e) = regex::Regex::new(s) {
                        errors.push(format!("{at}: filters[{j}]: invalid regex: {e}"));
                    }
                }
                Some(_) => {}
            },
        }
    }
}
