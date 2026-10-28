//! Manage command checks

use std::sync::{Arc, OnceLock};

use crate::error::Result;
use regex::Regex;
use serde_derive::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::{
    blast_radius::{self, BlastRadiusInfo, BlastScope},
    config::{Challenge, ResolvedSettings, Settings},
    context::{self, RuntimeContext},
    env::Environment,
    policy::{self, MergedPolicy},
    prompt::{AlternativeInfo, ChallengeResult, DisplayContext, Prompter},
};

/// Marker segment added for every `context.sensitive_paths` entry the
/// command deletes or overwrites; matched by the `fs:sensitive_path` check.
pub const SENSITIVE_PATH_MARKER: &str = "shellfirm-sensitive-path";

/// Marker segment added when `git push --force-with-lease` targets a
/// protected branch; matched by the `git:force_push_protected` check.
pub const PROTECTED_FORCE_PUSH_MARKER: &str = "shellfirm-force-push-protected";

/// Marker segment for a `--force-with-lease` push whose target is only known
/// when the line runs, in a repository with a protected branch; matched by
/// `git:force_push_unknown_target`.
pub const UNKNOWN_TARGET_FORCE_PUSH_MARKER: &str = "shellfirm-force-push-unknown-target";

/// Marker segment added for every git repository root that `rm -r`
/// deletes; matched by the `fs:delete_repository` check.
pub const REPOSITORY_DELETE_MARKER: &str = "shellfirm-delete-repository";

/// Segment marker for `mv DIR /tmp/…` of a folder of a git repository that
/// holds uncommitted or untracked work (or could not be checked in time):
/// matched by `fs:move_work_away`.
pub const WORK_MOVED_AWAY_MARKER: &str = "shellfirm-move-work-away";

/// Marker segment added for every `.git` directory of a repository that
/// `rm -r` deletes by a path other than `.git` (`projects/webapp/.git`,
/// `../.git`); matched by the `fs:delete_git_dir` check.
pub const GIT_DIR_DELETE_MARKER: &str = "shellfirm-delete-git-dir";

/// Most distinct `rm -r` operands checked for being a repository per line.
const MAX_REPOSITORY_LOOKUPS: usize = 4096;

/// Operands of local `rm -r …` segments that are the root of a git
/// repository (their `.git/HEAD`, or the `gitdir:` file of a worktree, can be
/// read). Read-only: no subprocess.
fn deleted_repositories(env: &dyn Environment, parsed: &crate::parser::Parsed) -> Vec<String> {
    let home = env.home_dir();
    let cwd = env.current_dir().ok();
    let mut out = Vec::new();
    // Each operand costs a few reads: a huge generated script is bounded.
    let mut looked_up = std::collections::HashSet::new();
    for seg in &parsed.segments {
        if !seg.starts_with("rm ") || parsed.remote_segments.binary_search(seg).is_ok() {
            continue;
        }
        if looked_up.len() > MAX_REPOSITORY_LOOKUPS {
            break;
        }
        let words: Vec<String> = seg.split(' ').map(crate::parser::desentinel).collect();
        let recursive = words.iter().skip(1).any(|w| {
            w == "--recursive"
                || (w.starts_with('-') && !w.starts_with("--") && w.contains(['r', 'R']))
        });
        if !recursive {
            continue;
        }
        for op in words
            .iter()
            .skip(1)
            .take_while(|w| !crate::parser::is_redirect_word(w))
            .filter(|w| !w.starts_with('-') && !w.contains('$'))
        {
            if !looked_up.insert(op.clone()) {
                continue;
            }
            // `rm -rf .*` / `.[a-z]*` in a repository root also deletes `.git`.
            if op.contains(['*', '?', '[']) {
                let (dir, pattern) = op.rsplit_once('/').unwrap_or((".", op.as_str()));
                if dir.contains(['*', '?', '[']) || !glob_matches(pattern, ".git") {
                    continue;
                }
                let base = match (dir.strip_prefix('~'), &home) {
                    (Some(rest), Some(h)) => h.join(rest.trim_start_matches('/')),
                    _ => cwd
                        .as_ref()
                        .map_or_else(|| std::path::PathBuf::from(dir), |c| c.join(dir)),
                };
                if env.read_file(&base.join(".git").join("HEAD")).is_ok() && !out.contains(op) {
                    out.push(op.clone());
                }
                continue;
            }
            // `.` / `..` / `~` / `/` are covered by `fs:recursively_delete`.
            if matches!(op.as_str(), "." | ".." | "~" | "/" | ".git") {
                continue;
            }
            let path = match (op.strip_prefix("~/"), &home) {
                (Some(rest), Some(h)) => h.join(rest),
                _ if op.starts_with('~') && expand_user_tilde(op).is_some() => {
                    std::path::PathBuf::from(expand_user_tilde(op).unwrap_or_default())
                }
                _ => cwd
                    .as_ref()
                    .map_or_else(|| std::path::PathBuf::from(op), |c| c.join(op)),
            };
            // `rm -rf projects/webapp/.git` / `../.git`: the git directory of
            // another repository (`.git` itself is `fs:recursively_delete`).
            if op.ends_with("/.git") {
                let marked = format!("{GIT_DIR_DELETE_MARKER} {op}");
                if env.read_file(&path.join("HEAD")).is_ok() && !out.contains(&marked) {
                    out.push(marked);
                }
                continue;
            }
            let is_repo = env.read_file(&path.join(".git").join("HEAD")).is_ok()
                || env
                    .read_file(&path.join(".git"))
                    .is_ok_and(|c| c.trim_start().starts_with("gitdir:"));
            if is_repo && !out.contains(op) {
                out.push(op.clone());
            }
        }
    }
    out
}

/// Sources of local `mv` segments that are a git repository root moved
/// into a directory that is cleared on its own (`mv ~/projects/webapp
/// /tmp/trash-me`): the repository is as good as deleted. Read-only.
fn repositories_moved_away(env: &dyn Environment, parsed: &crate::parser::Parsed) -> Vec<String> {
    const SCRATCH: &[&str] = &["/tmp", "/var/tmp", "/dev/shm", "/private/tmp", "/dev/null"];
    let home = env.home_dir();
    let cwd = env.current_dir().ok();
    let mut out = Vec::new();
    for seg in &parsed.segments {
        if !seg.starts_with("mv ") || parsed.remote_segments.binary_search(seg).is_ok() {
            continue;
        }
        let words: Vec<String> = seg.split(' ').map(crate::parser::desentinel).collect();
        let ops: Vec<&String> = words[1..]
            .iter()
            .take_while(|w| !crate::parser::is_redirect_word(w))
            .filter(|w| !w.starts_with('-'))
            .collect();
        let Some((dest, sources)) = ops.split_last() else {
            continue;
        };
        let dest = crate::parser::normalize_path(dest);
        if sources.is_empty()
            || !SCRATCH
                .iter()
                .any(|t| dest == *t || dest.starts_with(&format!("{t}/")))
        {
            continue;
        }
        for src in sources.iter().filter(|w| !w.contains(['$', '*', '?', '['])) {
            let path = match (src.strip_prefix("~/"), &home) {
                (Some(rest), Some(h)) => h.join(rest),
                _ => cwd.as_ref().map_or_else(
                    || std::path::PathBuf::from(src.as_str()),
                    |c| c.join(src.as_str()),
                ),
            };
            let is_repo = env.read_file(&path.join(".git").join("HEAD")).is_ok()
                || env
                    .read_file(&path.join(".git"))
                    .is_ok_and(|c| c.trim_start().starts_with("gitdir:"));
            if is_repo && !out.contains(*src) {
                out.push((*src).clone());
            }
        }
    }
    out
}

/// `rm -rf "$HOME/$UNSET"`: a recursive delete whose operand ends in a
/// variable that is not set here. The variable is empty when it runs, so
/// the segment is repeated with it removed (`rm -rf $HOME/`).
fn empty_variable_segments(env: &dyn Environment, parsed: &crate::parser::Parsed) -> Vec<String> {
    let mut out = Vec::new();
    for seg in &parsed.segments {
        if !seg.starts_with("rm ")
            || !seg.contains('$')
            || parsed.remote_segments.binary_search(seg).is_ok()
        {
            continue;
        }
        let words: Vec<&str> = seg.split(' ').collect();
        let recursive = words.iter().skip(1).any(|w| {
            *w == "--recursive"
                || (w.starts_with('-') && !w.starts_with("--") && w.contains(['r', 'R']))
        });
        if !recursive {
            continue;
        }
        let mut changed = false;
        let new_words: Vec<String> = words
            .iter()
            .enumerate()
            .map(|(i, w)| {
                if i == 0 || w.starts_with('-') {
                    return (*w).to_string();
                }
                let t = w.trim_end_matches('/');
                let Some((prefix, last)) = t.rsplit_once('/') else {
                    return (*w).to_string();
                };
                let name = last
                    .strip_prefix("${")
                    .and_then(|n| n.strip_suffix('}'))
                    .or_else(|| last.strip_prefix('$'))
                    .filter(|n| {
                        !n.is_empty() && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    });
                match name {
                    Some(n)
                        if prefix.is_empty()
                            || !prefix.contains('$')
                            || prefix == "$HOME"
                            || prefix == "${HOME}" =>
                    {
                        if env.var(n).is_some_and(|v| !v.is_empty()) {
                            return (*w).to_string();
                        }
                        changed = true;
                        // `~/` is the home directory itself.
                        if matches!(prefix, "~" | "$HOME" | "${HOME}") {
                            prefix.to_string()
                        } else {
                            format!("{prefix}/")
                        }
                    }
                    _ => (*w).to_string(),
                }
            })
            .collect();
        if changed {
            out.push(new_words.join(" "));
        }
    }
    out
}

/// Folder names that hold regenerable output (dependencies, build
/// artifacts, caches): deleting them loses no work, whatever git says.
const REGENERABLE_DIRS: &[&str] = &[
    "node_modules",
    "build",
    "dist",
    "target",
    "out",
    ".next",
    ".nuxt",
    ".turbo",
    ".parcel-cache",
    ".cache",
    "coverage",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "venv",
    ".gradle",
    "bin",
    "obj",
    "tmp",
];

/// Longest wait for `git status` when looking for uncommitted work. It
/// counts inside the command's time budget, but always gets at least
/// [`UNCOMMITTED_WORK_MIN_MS`] (a fast repository answers in a few ms).
const UNCOMMITTED_WORK_TIMEOUT_MS: u64 = 200;

/// Shortest wait for the uncommitted-work `git status`, even when the time
/// budget is spent (or `0`): a probe that cannot finish keeps the delete
/// High.
const UNCOMMITTED_WORK_MIN_MS: u64 = 50;

/// Most delete operands passed to the one `git status` call.
const MAX_UNCOMMITTED_WORK_PATHS: usize = 32;

/// Scratch places a folder moved there is as good as deleted.
const SCRATCH_DIRS: &[&str] = &["/tmp", "/var/tmp", "/dev/shm", "/private/tmp", "/dev/null"];

/// The folder operands a segment deletes, as written (without a trailing
/// `/*`, `/.` or `/.*`): `rm -r DIR`, `rm -r DIR/*` (also what `cd DIR &&
/// rm -rf *` becomes), `find DIR … -delete`, `mv DIR /tmp/…`.
fn deleted_folder_operands(seg: &str) -> Vec<String> {
    let words: Vec<String> = seg.split(' ').map(crate::parser::desentinel).collect();
    let Some(prog) = words.first() else {
        return Vec::new();
    };
    let args: Vec<&String> = words[1..]
        .iter()
        .take_while(|w| !crate::parser::is_redirect_word(w))
        .collect();
    let ops: Vec<String> = match prog.as_str() {
        "rm" => {
            let recursive = args.iter().any(|w| {
                *w == "--recursive"
                    || (w.starts_with('-') && !w.starts_with("--") && w.contains(['r', 'R']))
            });
            if !recursive {
                return Vec::new();
            }
            args.iter()
                .filter(|w| !w.starts_with('-'))
                .map(|w| (*w).clone())
                .collect()
        }
        // The whole tree only: `find DIR -name '*.pyc' -delete` deletes
        // some files, not the folder's work.
        "find" => {
            let start = args
                .iter()
                .position(|w| w.starts_with(['-', '(', '!']))
                .unwrap_or(args.len());
            let expr = &args[start..];
            let whole_tree = expr.iter().any(|w| *w == "-delete")
                && expr.iter().all(|w| {
                    matches!(
                        w.as_str(),
                        "-delete" | "-depth" | "-xdev" | "-mount" | "-mindepth" | "-maxdepth"
                    ) || w.chars().all(|c| c.is_ascii_digit())
                });
            if !whole_tree {
                return Vec::new();
            }
            args[..start].iter().map(|w| (*w).clone()).collect()
        }
        "mv" => {
            let ops: Vec<&String> = args
                .iter()
                .copied()
                .filter(|w| !w.starts_with('-'))
                .collect();
            let Some((dest, sources)) = ops.split_last() else {
                return Vec::new();
            };
            let dest = crate::parser::normalize_path(dest);
            if !SCRATCH_DIRS
                .iter()
                .any(|t| dest == *t || dest.starts_with(&format!("{t}/")))
            {
                return Vec::new();
            }
            sources.iter().map(|w| (*w).clone()).collect()
        }
        _ => Vec::new(),
    };
    ops.into_iter()
        .map(|op| {
            let mut op = op.as_str();
            for suffix in ["/*", "/.*", "/."] {
                if let Some(rest) = op.strip_suffix(suffix) {
                    op = if rest.is_empty() { "/" } else { rest };
                    break;
                }
            }
            op.to_string()
        })
        .filter(|op| !op.is_empty() && !op.contains(['$', '*', '?', '[', '{', '`']))
        .collect()
}

/// What the uncommitted-work probe found (see
/// [`folders_with_uncommitted_work`]): operands as written.
#[derive(Debug, Default, PartialEq, Eq)]
struct WorkFolders {
    /// Folders that hold uncommitted or untracked files.
    dirty: Vec<String>,
    /// Folders `git status` could not be asked about in time (assumed
    /// dirty: fail safe).
    unknown: Vec<String>,
}

/// The directories local deletes (`rm -r DIR`, `rm -r DIR/*`, `find DIR
/// -delete`, `mv DIR /tmp/…`) remove inside a git repository (not its root,
/// not a regenerable folder) that hold uncommitted or untracked files. One
/// `git status --porcelain` call (short timeout, inside the command budget)
/// for the first repository found; when it does not finish in time the
/// folders are reported as `unknown`.
#[allow(clippy::too_many_lines)]
fn folders_with_uncommitted_work(
    env: &dyn Environment,
    parsed: &crate::parser::Parsed,
) -> WorkFolders {
    let home = env.home_dir();
    let Ok(cwd) = env.current_dir() else {
        return WorkFolders::default();
    };
    let mut repo: Option<std::path::PathBuf> = None;
    // (operand as written, path relative to the repository)
    let mut candidates: Vec<(String, String)> = Vec::new();
    for seg in &parsed.segments {
        if parsed.remote_segments.binary_search(seg).is_ok() {
            continue;
        }
        for op in deleted_folder_operands(seg) {
            if candidates.len() >= MAX_UNCOMMITTED_WORK_PATHS {
                break;
            }
            let path = match (op.strip_prefix('~'), &home) {
                (Some(rest), Some(h)) if rest.is_empty() || rest.starts_with('/') => {
                    h.join(rest.trim_start_matches('/'))
                }
                _ => cwd.join(&op),
            };
            let path = std::path::PathBuf::from(crate::parser::normalize_path(
                &path.display().to_string(),
            ));
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if name.is_empty() || name == ".git" || REGENERABLE_DIRS.contains(&name.as_str()) {
                continue;
            }
            if !std::fs::metadata(&path).is_ok_and(|m| m.is_dir()) {
                continue;
            }
            // The repository holding the folder (not the folder itself:
            // deleting a repository root is `fs:delete_repository`).
            let Some(parent) = path.parent() else {
                continue;
            };
            let dir_repo = env
                .find_file_upward(parent, ".git/HEAD")
                .and_then(|h| h.parent()?.parent().map(std::path::Path::to_path_buf));
            // A worktree / submodule has a `.git` file.
            let file_repo = env
                .find_file_upward(parent, ".git")
                .and_then(|g| g.parent().map(std::path::Path::to_path_buf));
            // The innermost repository wins.
            let Some(root) = [dir_repo, file_repo]
                .into_iter()
                .flatten()
                .max_by_key(|r| r.components().count())
            else {
                continue;
            };
            if path.join(".git").exists() {
                continue;
            }
            match &repo {
                None => repo = Some(root.clone()),
                Some(r) if *r != root => continue,
                Some(_) => {}
            }
            if let Ok(rel) = path.strip_prefix(&root) {
                let rel = rel.display().to_string();
                if !rel.is_empty() && !candidates.iter().any(|(o, _)| *o == op) {
                    candidates.push((op.clone(), rel));
                }
            }
        }
    }
    let Some(root) = repo else {
        return WorkFolders::default();
    };
    if candidates.is_empty() {
        return WorkFolders::default();
    }
    let root_s = root.display().to_string();
    // `normal`, not `all`: an untracked folder is one line (`?? big/`), so
    // a 250,000-file folder is answered in milliseconds.
    let mut args: Vec<&str> = vec![
        "-C",
        &root_s,
        "status",
        "--porcelain",
        "--untracked-files=normal",
        "--",
    ];
    args.extend(candidates.iter().map(|(_, r)| r.as_str()));
    let status = env.run_command_outcome("git", &args, uncommitted_work_timeout_ms());
    debug!("uncommitted work: git {args:?} -> {status:?}");
    let status = match status {
        crate::env::CommandOutcome::Output(o) => o,
        crate::env::CommandOutcome::TimedOut => {
            return WorkFolders {
                dirty: Vec::new(),
                unknown: candidates.into_iter().map(|(op, _)| op).collect(),
            };
        }
        crate::env::CommandOutcome::Failed | crate::env::CommandOutcome::Skipped => {
            return WorkFolders::default();
        }
    };
    // `XY path` (`XY old -> new` for a rename): paths relative to the root.
    let changed: Vec<String> = status
        .lines()
        // The output may come trimmed (`M lib/x.js` for ` M lib/x.js`).
        .filter_map(|l| l.trim_start().split_once(' ').map(|(_, p)| p))
        .flat_map(|p| p.split(" -> "))
        .map(|p| unquote_git_path(p.trim()).trim_end_matches('/').to_string())
        .collect();
    WorkFolders {
        dirty: candidates
            .into_iter()
            .filter(|(_, rel)| {
                changed.iter().any(|p| {
                    // A change inside the folder, or the folder inside an
                    // untracked one (`?? big/` for `big/d0`).
                    p == rel
                        || p.starts_with(&format!("{rel}/"))
                        || rel.starts_with(&format!("{p}/"))
                })
            })
            .map(|(op, _)| op)
            .collect(),
        unknown: Vec::new(),
    }
}

/// A path as `git status --porcelain` prints it, unquoted: git puts a path
/// with non-ASCII or special characters in double quotes with C escapes
/// (`"\346\227\245\346\234\254/"` for `日本/`, `"a\"b"`), unless
/// `core.quotePath` is off.
fn unquote_git_path(p: &str) -> String {
    let Some(inner) = p.strip_prefix('"').and_then(|s| s.strip_suffix('"')) else {
        return p.to_string();
    };
    let bytes = inner.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'\\' || i + 1 == bytes.len() {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        let next = bytes[i + 1];
        let octal = bytes
            .get(i + 1..i + 4)
            .filter(|d| d.iter().all(|b| (b'0'..=b'7').contains(b)));
        if let Some(d) = octal {
            let v = d.iter().fold(0u32, |acc, b| acc * 8 + u32::from(b - b'0'));
            out.push(u8::try_from(v).unwrap_or(b'?'));
            i += 4;
            continue;
        }
        out.push(match next {
            b'n' => b'\n',
            b't' => b'\t',
            b'r' => b'\r',
            b'a' => 0x07,
            b'b' => 0x08,
            b'f' => 0x0c,
            b'v' => 0x0b,
            other => other,
        });
        i += 2;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// How long the uncommitted-work `git status` may take: what is left of the
/// command's time budget, between [`UNCOMMITTED_WORK_MIN_MS`] and
/// [`UNCOMMITTED_WORK_TIMEOUT_MS`].
fn uncommitted_work_timeout_ms() -> u64 {
    let budget =
        crate::env::scope_budget_ms().unwrap_or(crate::config::DEFAULT_BLAST_RADIUS_BUDGET_MS);
    let spent = crate::env::scope_start().map_or(0, |s| {
        u64::try_from(s.elapsed().as_millis()).unwrap_or(u64::MAX)
    });
    budget
        .saturating_sub(spent)
        .clamp(UNCOMMITTED_WORK_MIN_MS, UNCOMMITTED_WORK_TIMEOUT_MS)
}

/// The note added to a delete raised to High because the folder holds work
/// git cannot bring back.
const UNCOMMITTED_WORK_NOTE: &str =
    "The folder has uncommitted or untracked files: git cannot bring them back.";

/// The note added when the uncommitted-work probe did not finish in time
/// (the delete stays High: fail safe).
const UNCOMMITTED_WORK_UNKNOWN_NOTE: &str =
    "shellfirm could not check for uncommitted files in time, so it assumes there are some.";

/// Raise the file-system checks below High that match a delete of a folder
/// with uncommitted or untracked work (or one that could not be checked in
/// time) to High (see [`folders_with_uncommitted_work`]).
fn raise_for_uncommitted_work(
    folders: &WorkFolders,
    segments: &[String],
    matches: Vec<&Check>,
) -> Vec<Check> {
    let candidate = |c: &Check| {
        (c.from.starts_with("fs") && c.severity < Severity::High) || c.id == "fs:move_work_away"
    };
    if folders.dirty.is_empty() && folders.unknown.is_empty()
        || !matches.iter().any(|c| candidate(c))
    {
        return matches.into_iter().cloned().collect();
    }
    // Whether a delete segment this check matches names a folder of `list`.
    let hit = |c: &Check, list: &[String]| {
        segments.iter().any(|s| {
            c.test.is_match(s)
                && s.strip_prefix(WORK_MOVED_AWAY_MARKER).map_or_else(
                    || deleted_folder_operands(s).iter().any(|w| list.contains(w)),
                    |op| list.iter().any(|w| w == op.trim_start()),
                )
        })
    };
    matches
        .into_iter()
        .map(|c| {
            let mut c = c.clone();
            if candidate(&c) {
                let note = if hit(&c, &folders.dirty) {
                    Some(UNCOMMITTED_WORK_NOTE)
                } else if hit(&c, &folders.unknown) {
                    Some(UNCOMMITTED_WORK_UNKNOWN_NOTE)
                } else {
                    None
                };
                if let Some(note) = note {
                    c.severity = Severity::High;
                    c.description = format!("{} {note}", c.description.trim_end());
                }
            }
            c
        })
        .collect()
}

/// The paths of `git restore PATH…` / `git checkout -- PATH…` (not from
/// another commit: `--source` / `-s` / `git checkout REV -- PATH` change a
/// clean file too), or `None` when the segment is not such a restore or a
/// path is not a plain name.
fn restored_paths(seg: &str) -> Option<Vec<String>> {
    let words: Vec<String> = seg.split(' ').map(crate::parser::desentinel).collect();
    let (sub, rest) = match words.as_slice() {
        [git, sub, rest @ ..] if git == "git" => (sub.as_str(), rest),
        _ => return None,
    };
    let rest: Vec<&String> = rest
        .iter()
        .take_while(|w| !crate::parser::is_redirect_word(w))
        .collect();
    let paths: Vec<String> = match sub {
        "restore" => {
            if rest.iter().any(|w| {
                w.starts_with("--source")
                    || (w.starts_with('-') && !w.starts_with("--") && w.contains('s'))
            }) {
                return None;
            }
            rest.iter()
                .filter(|w| !w.starts_with('-'))
                .map(|w| (*w).clone())
                .collect()
        }
        "checkout" => {
            let dd = rest.iter().position(|w| *w == "--")?;
            // `git checkout REV -- PATH` writes REV's version.
            if rest[..dd].iter().any(|w| !w.starts_with('-')) {
                return None;
            }
            rest[dd + 1..].iter().map(|w| (*w).clone()).collect()
        }
        _ => return None,
    };
    let plain = |p: &String| {
        !p.is_empty()
            && !p.starts_with(':')
            && !p.contains(['$', '*', '?', '[', '{', '`'])
            && p != "."
    };
    (!paths.is_empty() && paths.iter().all(plain)).then_some(paths)
}

/// Drop `git:restore_discard_path` / `git:checkout_discard_path` when every
/// path it restores has no changes (one quick `git status`): there is
/// nothing to discard. Kept when git is slow or fails.
fn drop_restores_of_clean_paths(
    env: &dyn Environment,
    segments: &[String],
    remote: &[String],
    matches: Vec<Check>,
) -> Vec<Check> {
    const IDS: &[&str] = &["git:restore_discard_path", "git:checkout_discard_path"];
    if !matches.iter().any(|c| IDS.contains(&c.id.as_str())) {
        return matches;
    }
    let clean = |c: &Check| {
        let segs: Vec<&String> = segments
            .iter()
            .filter(|s| c.test.is_match(s) && remote.binary_search(s).is_err())
            .collect();
        !segs.is_empty()
            && segs.iter().all(|s| {
                let Some(paths) = restored_paths(s) else {
                    return false;
                };
                let mut args = vec!["status", "--porcelain", "--untracked-files=no", "--"];
                args.extend(paths.iter().map(String::as_str));
                matches!(
                    env.run_command_outcome("git", &args, uncommitted_work_timeout_ms()),
                    crate::env::CommandOutcome::Output(ref o) if o.trim().is_empty()
                )
            })
    };
    matches
        .into_iter()
        .filter(|c| !(IDS.contains(&c.id.as_str()) && clean(c)))
        .collect()
}

/// Whether a shell glob (`*`, `?`, `[…]` / `[!…]`) matches `name`. A
/// leading `*` or `?` never matches a leading dot (no `dotglob`).
fn glob_matches(pattern: &str, name: &str) -> bool {
    fn go(p: &[char], n: &[char]) -> bool {
        match p.split_first() {
            None => n.is_empty(),
            Some(('*', rest)) => (0..=n.len()).any(|k| go(rest, &n[k..])),
            Some(('?', rest)) => !n.is_empty() && go(rest, &n[1..]),
            Some(('[', rest)) => {
                let Some(close) = rest.iter().skip(1).position(|c| *c == ']').map(|p| p + 1) else {
                    return n.first() == Some(&'[') && go(rest, &n[1..]);
                };
                let Some(&c) = n.first() else { return false };
                let class = &rest[..close];
                let (negate, class) = match class.split_first() {
                    Some(('!' | '^', r)) => (true, r),
                    _ => (false, class),
                };
                let mut hit = false;
                let mut i = 0;
                while i < class.len() {
                    if i + 2 < class.len() && class[i + 1] == '-' {
                        hit |= class[i] <= c && c <= class[i + 2];
                        i += 3;
                    } else {
                        hit |= class[i] == c;
                        i += 1;
                    }
                }
                hit != negate && go(&rest[close + 1..], &n[1..])
            }
            Some((c, rest)) => n.first() == Some(c) && go(rest, &n[1..]),
        }
    }
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    if n.first() == Some(&'.') && p.first() != Some(&'.') {
        return false;
    }
    go(&p, &n)
}

/// Credential directories in the home directory (see `fs:delete_credentials`).
const HOME_CREDENTIAL_DIRS: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".aws",
    ".kube",
    ".azure",
    ".docker",
    ".password-store",
    ".config/gcloud",
];

/// Programs whose path operands are resolved against the real working
/// directory (see [`cwd_resolved_segments`]).
const RESOLVED_PROGRAMS: &[&str] = &[
    "rm", "rmdir", "unlink", "shred", "srm", "mv", "chmod", "chown", "chgrp", "find", "cp", "ln",
    "tee", "truncate",
];

/// Extra segments in which relative path operands are spelled from the home
/// directory or as absolute paths (and absolute or `~` operands inside the
/// working directory relative to it), so the path checks see the real
/// target whatever the spelling: from `~`, `rm -rf .ssh` is `rm -rf ~/.ssh`;
/// from the repository root, `rm -rf ~/projects/app/.git` is `rm -rf .git`.
///
/// Only spellings that change what a path check means are emitted: the
/// home directory and its direct children, credential directories, paths
/// outside the home directory (system paths), and `.`, `*` and `.git` of the
/// working directory.
/// Whether `name` can be an account name (`~name`).
fn is_user_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// Home directory of the account `name` from the password database (no
/// subprocess), for `~name` operands.
#[cfg(unix)]
pub(crate) fn user_home(name: &str) -> Option<String> {
    if !is_user_name(name) {
        return None;
    }
    let c_name = std::ffi::CString::new(name).ok()?;
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    // SAFETY: an all-zero passwd struct is a valid out-parameter.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the duration of the call and the
    // buffer length matches the buffer.
    let rc = unsafe {
        libc::getpwnam_r(
            c_name.as_ptr(),
            &raw mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &raw mut result,
        )
    };
    if rc != 0 || result.is_null() || pwd.pw_dir.is_null() {
        return None;
    }
    // SAFETY: getpwnam_r succeeded, so pw_dir points to a NUL-terminated
    // string inside `buf`.
    let dir = unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) }
        .to_string_lossy()
        .to_string();
    (dir.starts_with('/')).then_some(dir)
}

/// Home directory of the account `name` (not available on this platform).
#[cfg(not(unix))]
pub(crate) const fn user_home(_name: &str) -> Option<String> {
    None
}

/// `~name` / `~name/rest` → the absolute path in that account's home
/// directory (`None` for `~`, `~/…` and unknown accounts).
pub(crate) fn expand_user_tilde(word: &str) -> Option<String> {
    let rest = word.strip_prefix('~')?;
    let (name, tail) = rest.split_once('/').unwrap_or((rest, ""));
    if name.is_empty() {
        return None;
    }
    let home = user_home(name)?;
    Some(crate::parser::normalize_path(&if tail.is_empty() {
        home
    } else {
        format!("{home}/{tail}")
    }))
}

/// Programs that act on what a symbolic link operand points to (not on the
/// link itself) even without a trailing `/`.
const FOLLOW_LAST_LINK_PROGRAMS: &[&str] = &["chmod", "chown", "chgrp", "truncate", "shred"];

/// Most operands whose symlinks are resolved per command (each costs a few
/// `lstat` calls).
const MAX_SYMLINK_RESOLUTIONS: usize = 64;

/// The real location of the absolute path `abs` when a directory on the way
/// is a symbolic link (`/tmp/hl/x` with `hl → ~` is `~/x`). The last
/// component is followed too when `follow_last` (`rm -rf link/` deletes
/// what the link points to; `rm -rf link` only the link). `None` when the
/// path's directory does not exist or nothing is a link.
fn real_location(env: &dyn Environment, abs: &str, follow_last: bool) -> Option<String> {
    let path = std::path::Path::new(abs);
    let parent = path.parent()?;
    if !env.path_exists(parent) {
        return None;
    }
    let real = if follow_last && env.path_exists(path) {
        std::fs::canonicalize(path).ok()?
    } else {
        let name = path.file_name()?;
        std::fs::canonicalize(parent).ok()?.join(name)
    };
    let real = crate::parser::normalize_path(&real.display().to_string());
    // macOS: `/tmp`, `/var` and `/etc` live in `/private`.
    (real != abs && real.strip_prefix("/private") != Some(abs)).then_some(real)
}

/// Whether an operand is written with a trailing `/` (or `/.`, `/*`) in the
/// command text, so a symlink it names is followed.
fn written_with_trailing_slash(command: &str, operand: &str) -> bool {
    let last = operand.rsplit('/').next().unwrap_or(operand);
    if last.is_empty() || matches!(last, "." | ".." | "~") {
        return false;
    }
    let needle = format!("{last}/");
    command.match_indices(&needle).any(|(i, _)| {
        command[i + needle.len()..].chars().next().is_none_or(|c| {
            c.is_whitespace() || matches!(c, '\'' | '"' | '*' | '.' | ';' | '&' | '|' | ')')
        })
    })
}

#[allow(clippy::too_many_lines)]
fn cwd_resolved_segments(
    env: &dyn Environment,
    parsed: &crate::parser::Parsed,
    command: &str,
) -> Vec<String> {
    let Ok(cwd) = env.current_dir() else {
        return Vec::new();
    };
    let cwd = crate::parser::normalize_path(&cwd.display().to_string());
    let home = env
        .home_dir()
        .map(|h| crate::parser::normalize_path(&h.display().to_string()));
    let under = |p: &str, base: &str| -> Option<String> {
        if p == base {
            Some(String::new())
        } else if base == "/" {
            p.strip_prefix('/').map(str::to_string)
        } else {
            p.strip_prefix(base)
                .and_then(|r| r.strip_prefix('/'))
                .map(str::to_string)
        }
    };
    // Absolute form of an operand (`None` for variables / placeholders).
    let absolute = |w: &str| -> Option<String> {
        if w.is_empty() || w.starts_with('-') || w.contains('$') || w.contains("{}") {
            return None;
        }
        let p = if let Some(user_path) = expand_user_tilde(w) {
            user_path
        } else if let Some(rest) = w.strip_prefix('~') {
            let h = home.as_deref()?;
            if rest.is_empty() {
                h.to_string()
            } else {
                format!("{h}/{}", rest.strip_prefix('/')?)
            }
        } else if w.starts_with('/') {
            w.to_string()
        } else {
            format!("{cwd}/{w}")
        };
        Some(crate::parser::normalize_path(&p))
    };
    let home_form = |abs: &str| -> String {
        match home.as_deref().and_then(|h| under(abs, h)) {
            Some(r) if r.is_empty() => "~".to_string(),
            Some(r) => format!("~/{r}"),
            None => abs.to_string(),
        }
    };
    let interesting_home_form = |h: &str| -> bool {
        h.strip_prefix("~/").map_or_else(
            || {
                h == "~"
                    || (h.starts_with('/')
                        && !["/tmp", "/var/tmp", "/private/tmp"]
                            .iter()
                            .any(|t| h == *t || h.starts_with(&format!("{t}/"))))
            },
            |r| {
                !r.contains('/')
                    || r == "*"
                    || HOME_CREDENTIAL_DIRS
                        .iter()
                        .any(|d| r == *d || r.starts_with(&format!("{d}/")))
            },
        )
    };
    let home_real = home
        .as_deref()
        .and_then(|h| std::fs::canonicalize(h).ok())
        .map(|h| crate::parser::normalize_path(&h.display().to_string()));
    // A real location spelled from the home directory when it is inside it
    // (also when the home directory itself is reached through a link).
    let real_home_form = |real: &str| -> String {
        match home_real.as_deref().and_then(|h| under(real, h)) {
            Some(r) if r.is_empty() => "~".to_string(),
            Some(r) => format!("~/{r}"),
            None => home_form(real),
        }
    };
    let mut resolutions = 0usize;
    let mut out = Vec::new();
    for seg in &parsed.segments {
        if parsed.remote_segments.binary_search(seg).is_ok() {
            continue;
        }
        let words: Vec<&str> = seg.split(' ').collect();
        let Some(prog) = words.first().copied() else {
            continue;
        };
        let path_prog = RESOLVED_PROGRAMS.contains(&prog);
        if !path_prog && !seg.contains('>') {
            continue;
        }
        let mut as_home = words.iter().map(|w| (*w).to_string()).collect::<Vec<_>>();
        let mut as_cwd = as_home.clone();
        let (mut home_changed, mut cwd_changed) = (false, false);
        let mut seen_operand = false;
        // A bare redirection (`> .zshrc`) has no program word.
        let mut i = usize::from(!crate::parser::is_redirect_word(prog));
        while i < words.len() {
            let w = words[i];
            let target = if crate::parser::is_redirect_word(w) {
                // Input redirections and fd duplication (`2>&1`) name no file.
                if !w.contains('>') || w.ends_with('&') {
                    i += 2;
                    continue;
                }
                i += 1;
                i
            } else if !path_prog || w.starts_with('-') {
                if prog == "find" && w.starts_with('-') {
                    // Only the starting points of `find` are paths.
                    break;
                }
                i += 1;
                continue;
            } else {
                // The mode / owner of chmod / chown / chgrp is not a path.
                let skip = matches!(prog, "chmod" | "chown" | "chgrp") && !seen_operand;
                seen_operand = true;
                if skip {
                    i += 1;
                    continue;
                }
                i
            };
            let Some(word) = words.get(target) else { break };
            let text = crate::parser::desentinel(word);
            if let Some(abs) = absolute(&text) {
                // `~name/…` is spelled like a relative word: rewritten to
                // the home form or absolute path it names.
                let user_tilde = text.starts_with('~')
                    && !text.starts_with("~/")
                    && text != "~"
                    && expand_user_tilde(&text).is_some();
                let relative = user_tilde || !(text.starts_with('/') || text.starts_with('~'));
                // A symbolic link on the way: the real target (`rm -rf
                // /tmp/hl/` with `hl → ~` deletes the home directory).
                let glob_at = abs.find(['*', '?', '[']);
                let real = if path_prog && resolutions < MAX_SYMLINK_RESOLUTIONS {
                    resolutions += 1;
                    glob_at.map_or_else(
                        || {
                            let follow_last = FOLLOW_LAST_LINK_PROGRAMS.contains(&prog)
                                || written_with_trailing_slash(command, &text);
                            real_location(env, &abs, follow_last)
                        },
                        // `rm -rf /tmp/link/*` with `link → /`: the glob is
                        // expanded in the link's target (`/*`).
                        |g| {
                            abs[..g].rfind('/').and_then(|slash| {
                                let (dir, tail) = abs.split_at(slash);
                                let dir = if dir.is_empty() { "/" } else { dir };
                                real_location(env, dir, true).map(|r| {
                                    if r == "/" {
                                        tail.to_string()
                                    } else {
                                        format!("{r}{tail}")
                                    }
                                })
                            })
                        },
                    )
                } else {
                    None
                };
                if let Some(h) = real
                    .as_deref()
                    .map(real_home_form)
                    .filter(|h| *h != home_form(&abs) && interesting_home_form(h))
                {
                    as_home[target] = h.replace(' ', &crate::parser::WS_SENTINEL.to_string());
                    home_changed = true;
                } else if relative {
                    let h = home_form(&abs);
                    if interesting_home_form(&h) && h != text {
                        as_home[target] = h.replace(' ', &crate::parser::WS_SENTINEL.to_string());
                        home_changed = true;
                    }
                } else if let Some(r) = under(&abs, &cwd) {
                    let r = if r.is_empty() { ".".to_string() } else { r };
                    if r == "." || r == "*" || r == ".git" || r.starts_with(".git/") {
                        as_cwd[target] = r;
                        cwd_changed = true;
                    }
                }
            }
            i = target + 1;
        }
        if home_changed {
            out.push(as_home.join(" "));
        }
        if cwd_changed {
            out.push(as_cwd.join(" "));
        }
    }
    let existing: std::collections::HashSet<&String> = parsed.segments.iter().collect();
    let mut seen = std::collections::HashSet::new();
    out.retain(|s| !existing.contains(s) && seen.insert(s.clone()));
    out
}

/// Paths an earlier segment of the line creates (`ln -s ~ d`,
/// `mv ~/x /tmp/w`, `cp -r a b`, `git clone URL dir`): a later delete or
/// permission change of one of them that does not exist yet is not a no-op,
/// its target is unknown until the line runs. Each such segment is repeated
/// with the operand replaced by the unknown-target placeholder `{}`.
#[allow(clippy::too_many_lines)]
fn created_path_segments(env: &dyn Environment, parsed: &crate::parser::Parsed) -> Vec<String> {
    let Ok(cwd) = env.current_dir() else {
        return Vec::new();
    };
    let cwd = crate::parser::normalize_path(&cwd.display().to_string());
    let home = env
        .home_dir()
        .map(|h| crate::parser::normalize_path(&h.display().to_string()));
    let absolute = |w: &str| -> Option<String> {
        if w.is_empty() || w.starts_with('-') || w.contains(['$', '*', '?', '[']) || w == "{}" {
            return None;
        }
        let p = if let Some(rest) = w.strip_prefix('~') {
            if rest.is_empty() || rest.starts_with('/') {
                format!("{}{rest}", home.as_deref()?)
            } else {
                expand_user_tilde(w)?
            }
        } else if w.starts_with('/') {
            w.to_string()
        } else {
            format!("{cwd}/{w}")
        };
        Some(crate::parser::normalize_path(&p))
    };
    // (path, what it holds): `Some(source)` for a path `mv` filled with
    // `source`, `None` when it is unknown (a link, an unsafe copy).
    let mut created: Vec<(String, Option<String>)> = Vec::new();
    // Symbolic links made on the line (`ln -s / /tmp/q`): (link, target).
    let mut links: Vec<(String, String)> = Vec::new();
    // Directories `mkdir` made: (path, a `cd` came after it). Deleting one
    // by its own name is the clean-up idiom; deleting it after changing
    // into it (`mkdir -p d && cd d && rm -rf .`) is not known to be that.
    let mut fresh_dirs: Vec<(String, bool)> = Vec::new();
    let mut out = Vec::new();
    // A symbolic link copied as a link (`cp -r link d`, `rsync -a`) points
    // where the original did.
    // An absolute path spelled from the home directory when inside it.
    let spelled = |abs: &str| -> String {
        match home.as_deref() {
            Some(h) if abs == h => "~".to_string(),
            Some(h) => abs
                .strip_prefix(&format!("{h}/"))
                .map_or_else(|| abs.to_string(), |r| format!("~/{r}")),
            None => abs.to_string(),
        }
    };
    let is_link =
        |abs: &str| std::fs::symlink_metadata(abs).is_ok_and(|m| m.file_type().is_symlink());
    for seg in &parsed.segments {
        if parsed.remote_segments.binary_search(seg).is_ok() {
            continue;
        }
        let words: Vec<String> = seg.split(' ').map(crate::parser::desentinel).collect();
        let Some(prog) = words.first().map(String::as_str) else {
            continue;
        };
        let operands: Vec<&String> = words[1..]
            .iter()
            .take_while(|w| !crate::parser::is_redirect_word(w))
            .filter(|w| !w.starts_with('-'))
            .collect();
        match prog {
            "cd" | "pushd" => {
                for d in &mut fresh_dirs {
                    d.1 = true;
                }
            }
            "rm" | "rmdir" | "unlink" | "shred" | "chmod" | "chown" | "chgrp"
                if !created.is_empty() || !links.is_empty() || !fresh_dirs.is_empty() =>
            {
                let skip_first = matches!(prog, "chmod" | "chown" | "chgrp");
                let mut new_words = words.clone();
                let mut changed = false;
                let mut seen = 0usize;
                for (i, w) in words.iter().enumerate().skip(1) {
                    if crate::parser::is_redirect_word(w) {
                        break;
                    }
                    if w.starts_with('-') {
                        continue;
                    }
                    seen += 1;
                    if skip_first && seen == 1 {
                        continue;
                    }
                    // `rm -rf /tmp/q/*` after `ln -s / /tmp/q`: the glob
                    // expands inside the link's target.
                    if let Some(glob_at) = w.find(['*', '?', '[']) {
                        let dir_end = w[..glob_at].rfind('/');
                        let target = dir_end.and_then(|e| {
                            let dir = absolute(&w[..e])?;
                            links
                                .iter()
                                .rev()
                                .find(|(l, _)| *l == dir)
                                .map(|(_, t)| (t, e))
                        });
                        if let Some((t, e)) = target {
                            let rest = &w[e + 1..];
                            new_words[i] = if t.ends_with('/') {
                                format!("{t}{rest}")
                            } else {
                                format!("{t}/{rest}")
                            };
                            changed = true;
                        }
                        continue;
                    }
                    let Some(abs) = absolute(w) else { continue };
                    // The latest step that made this path wins.
                    let made = created
                        .iter()
                        .rev()
                        .find_map(|(c, src)| {
                            if abs == *c {
                                Some(src.clone())
                            } else {
                                abs.strip_prefix(&format!("{c}/"))
                                    .map(|rest| src.as_ref().map(|s| format!("{s}/{rest}")))
                            }
                        })
                        .or_else(|| {
                            fresh_dirs
                                .iter()
                                .any(|(d, cd)| {
                                    *cd && (abs == *d || abs.starts_with(&format!("{d}/")))
                                })
                                .then_some(None)
                        });
                    if let Some(made) = made {
                        if !env.path_exists(std::path::Path::new(&abs)) {
                            // What `mv` put there is what is deleted; anything
                            // else is unknown until the line runs.
                            new_words[i] = made.unwrap_or_else(|| "{}".to_string());
                            changed = true;
                        }
                    }
                }
                if changed {
                    out.push(
                        new_words
                            .iter()
                            .map(|w| w.replace(' ', &crate::parser::WS_SENTINEL.to_string()))
                            .collect::<Vec<_>>()
                            .join(" "),
                    );
                }
            }
            "ln" | "cp" | "mv" | "rsync" | "install" => {
                let target_dir = words
                    .iter()
                    .position(|w| w == "-t" || w == "--target-directory")
                    .and_then(|i| words.get(i + 1))
                    .or_else(|| {
                        words
                            .iter()
                            .find_map(|w| w.strip_prefix("--target-directory=").map(|_| w))
                    });
                // A copy into a fresh `mktemp` directory is the scratch idiom.
                if target_dir.is_none() && operands.len() >= 2 {
                    if let Some(a) = operands
                        .last()
                        .and_then(|w| absolute(w))
                        .filter(|a| !a.starts_with("/tmp/shellfirm-mktemp."))
                    {
                        let sources: Vec<Option<String>> = operands[..operands.len() - 1]
                            .iter()
                            .map(|w| absolute(w))
                            .collect();
                        let known = sources.iter().all(Option::is_some);
                        let flags = words[1..]
                            .iter()
                            .filter(|w| w.starts_with('-') && !w.starts_with("--"))
                            .flat_map(|w| w.chars().skip(1))
                            .collect::<String>();
                        let long = |f: &str| words.iter().any(|w| w == f);
                        let entry = match prog {
                            // `mv a b`: b now holds a.
                            "mv" if sources.len() == 1
                                && known
                                && sources.iter().flatten().all(|s| !is_link(s)) =>
                            {
                                Some(sources[0].as_deref().map(spelled))
                            }
                            // A fresh copy of real files (not of a link, not
                            // links themselves) or a fresh clone: deleting it
                            // again is the clean-up idiom.
                            "cp" | "rsync" | "install"
                                if known
                                    && !flags.contains(['s', 'l'])
                                    && !long("--symbolic-link")
                                    && !long("--link")
                                    && sources.iter().flatten().all(|s| !is_link(s)) =>
                            {
                                None
                            }
                            _ => Some(None),
                        };
                        let symbolic = prog == "ln" && (flags.contains('s') || long("--symbolic"));
                        if symbolic && sources.len() == 1 {
                            if let Some(t) = sources[0].as_deref() {
                                links.push((a.clone(), spelled(t)));
                            }
                        }
                        if let Some(src) = entry {
                            created.push((a, src));
                        }
                    }
                }
            }
            // A fresh directory (`mkdir -p build && … && rm -rf build`) is
            // empty: deleting it by name is the clean-up idiom. What is put
            // into it later (`ln -s / build/q`, `mv ~/x build/y`) is tracked
            // by that step. A scratch directory under a temp directory
            // (`mkdir -p /tmp/work && cd /tmp/work && …`) is never tracked.
            "mkdir" => fresh_dirs.extend(
                operands
                    .iter()
                    .filter_map(|w| absolute(w))
                    .filter(|a| {
                        !["/tmp/", "/var/tmp/", "/private/tmp/"]
                            .iter()
                            .any(|t| a.starts_with(t))
                    })
                    .map(|a| (a, false)),
            ),
            // A fresh clone is the clean-up idiom too (`git clone URL
            // /tmp/b && … && rm -rf /tmp/b`): nothing to track.
            _ => {}
        }
        if created.len() + links.len() + fresh_dirs.len() > 256 {
            break;
        }
    }
    out
}

/// Rewrite `../…` operands of `rm` segments that stay inside the
/// repository containing the working directory as absolute paths.
fn spell_parent_paths_in_repo(env: &dyn Environment, segments: &mut [String]) {
    if !segments
        .iter()
        .any(|s| s.starts_with("rm ") && s.contains(" ../"))
    {
        return;
    }
    let Ok(cwd) = env.current_dir() else {
        return;
    };
    // `.git/HEAD` of a repository, or the `.git` file of a worktree.
    let Some(root) = env
        .find_file_upward(&cwd, ".git/HEAD")
        .and_then(|h| {
            h.parent()
                .and_then(std::path::Path::parent)
                .map(std::path::Path::to_path_buf)
        })
        .or_else(|| {
            env.find_file_upward(&cwd, ".git")
                .and_then(|g| g.parent().map(std::path::Path::to_path_buf))
        })
    else {
        return;
    };
    let cwd_s = crate::parser::normalize_path(&cwd.display().to_string());
    let root_s = crate::parser::normalize_path(&root.display().to_string());
    if cwd_s == root_s {
        return;
    }
    for seg in segments.iter_mut().filter(|s| s.starts_with("rm ")) {
        let mut words: Vec<String> = seg.split(' ').map(str::to_string).collect();
        let mut changed = false;
        for w in words.iter_mut().skip(1) {
            if !w.starts_with("../") || w.contains(['*', '?', '[', '$', '{']) {
                continue;
            }
            let abs = crate::parser::normalize_path(&format!("{cwd_s}/{w}"));
            let inside = abs
                .strip_prefix(&root_s)
                .and_then(|r| r.strip_prefix('/'))
                .is_some_and(|r| !r.is_empty() && r != ".git" && !r.starts_with(".git/"));
            if inside {
                *w = abs;
                changed = true;
            }
        }
        if changed {
            *seg = words.join(" ");
        }
    }
}

/// Replace the owner of `chown` segments by `$USER` when it is the current
/// user (`dev`, `dev:dev`, `dev:`, by name or uid).
fn spell_own_user(env: &dyn Environment, segments: &mut [String]) {
    // `$(whoami)`, `$(id -u):$(id -g)`, `"$USER"`: the current user. A
    // substitution keeps its spaces in the segment.
    const SELF: &[&str] = &[
        "$(whoami)",
        "$(id -un)",
        "$(id -nu)",
        "$(id -u -n)",
        "$(id -u)",
        "$(logname)",
        "`whoami`",
        "`id -un`",
        "`id -u`",
        "$USER",
        "${USER}",
        "$LOGNAME",
        "${LOGNAME}",
    ];
    const GROUPS: &[&str] = &[
        "$(id -g)",
        "$(id -gn)",
        "$(id -ng)",
        "$(id -g -n)",
        "`id -g`",
        "`id -gn`",
    ];
    if !segments.iter().any(|s| s.starts_with("chown ")) {
        return;
    }
    let Some(user) = policy::current_user_name(env) else {
        return;
    };
    let root = env.effective_uid() == Some(0);
    let uid = env.effective_uid().map(|u| u.to_string());
    for seg in segments.iter_mut().filter(|s| s.starts_with("chown ")) {
        // The owner starts after `chown` and its options.
        let mut start = "chown ".len();
        while seg[start..].starts_with('-') {
            match seg[start..].find(' ') {
                Some(sp) => start += sp + 1,
                None => break,
            }
        }
        let rest = crate::parser::desentinel(&seg[start..]);
        let (name, mut after) = SELF.iter().find(|p| rest.starts_with(**p)).map_or_else(
            || {
                let end = rest.find([':', '.', ' ']).unwrap_or(rest.len());
                (rest[..end].to_string(), end)
            },
            |p| ((*p).to_string(), p.len()),
        );
        let is_self = name == user
            || (SELF.contains(&name.as_str()) && !(root && name == "$(id -u)"))
            || (uid.as_deref() == Some(name.as_str()) && name != "0");
        if !is_self {
            continue;
        }
        // `:group` / `.group` (the group may be a substitution with spaces).
        if rest[after..].starts_with([':', '.']) {
            let g = &rest[after + 1..];
            after += 1 + GROUPS
                .iter()
                .find(|p| g.starts_with(**p))
                .map_or_else(|| g.find(' ').unwrap_or(g.len()), |p| p.len());
        }
        if !(rest.len() == after || rest[after..].starts_with(' ')) {
            continue;
        }
        let group = rest[name.len()..after].replace(' ', &crate::parser::WS_SENTINEL.to_string());
        // The sentinel and a space are one byte each: positions agree.
        *seg = format!("{}$USER{group}{}", &seg[..start], &seg[start + after..]);
    }
}

/// Most candidate paths one bracket glob is expanded to.
const MAX_GLOB_CANDIDATES: usize = 128;

/// Names a bracket glob is matched against when none of its candidates
/// exists (or it has too many): the targets that make a delete critical.
const CRITICAL_GLOB_NAMES: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".aws",
    ".kube",
    ".azure",
    ".docker",
    ".password-store",
    ".config",
    ".git",
    ".bashrc",
    ".zshrc",
    ".profile",
];

/// The words a POSIX bracket glob (`.[s]sh`, `[d]ata`, `src/[a-c]*`) can
/// expand to: every combination of its `[…]` classes (`None` when the word
/// has no class or more than [`MAX_GLOB_CANDIDATES`] combinations).
fn bracket_candidates(word: &str) -> Option<Vec<String>> {
    let chars: Vec<char> = word.chars().collect();
    let mut parts: Vec<Vec<char>> = Vec::new();
    let mut has_class = false;
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '[' {
            if let Some(close) = chars[i + 1..]
                .iter()
                .skip(1)
                .position(|c| *c == ']')
                .map(|p| i + 2 + p)
            {
                let class = &chars[i + 1..close];
                let (negate, class) = match class.split_first() {
                    Some(('!' | '^', r)) => (true, r),
                    _ => (false, class),
                };
                let mut set: Vec<char> = Vec::new();
                let mut k = 0;
                while k < class.len() {
                    if k + 2 < class.len() && class[k + 1] == '-' {
                        let (a, b) = (u32::from(class[k]), u32::from(class[k + 2]));
                        if b < a || b - a > 128 {
                            return None;
                        }
                        set.extend((a..=b).filter_map(char::from_u32));
                        k += 3;
                    } else {
                        set.push(class[k]);
                        k += 1;
                    }
                }
                if negate {
                    set = (0x21u32..0x7f)
                        .filter_map(char::from_u32)
                        .filter(|c| !set.contains(c) && *c != '/')
                        .collect();
                }
                parts.push(set);
                has_class = true;
                i = close + 1;
                continue;
            }
        }
        parts.push(vec![chars[i]]);
        i += 1;
    }
    if !has_class {
        return None;
    }
    let mut out = vec![String::new()];
    for set in parts {
        if out.len().saturating_mul(set.len()) > MAX_GLOB_CANDIDATES {
            return None;
        }
        out = out
            .iter()
            .flat_map(|p| set.iter().map(move |c| format!("{p}{c}")))
            .collect();
    }
    Some(out)
}

/// Extra segments in which bracket-glob operands of path commands are
/// replaced by what they name (`rm -rf ~/.[s]sh` → `rm -rf ~/.ssh`): the
/// candidates that exist, else the critical names the glob matches
/// (credential directories, `.git`, shell startup files).
fn glob_resolved_segments(env: &dyn Environment, parsed: &crate::parser::Parsed) -> Vec<String> {
    let home = env.home_dir();
    let cwd = env.current_dir().ok();
    let resolve = |p: &str| -> std::path::PathBuf {
        match (p.strip_prefix('~'), &home) {
            (Some(rest), Some(h)) if rest.is_empty() || rest.starts_with('/') => {
                h.join(rest.trim_start_matches('/'))
            }
            _ => cwd
                .as_ref()
                .map_or_else(|| std::path::PathBuf::from(p), |c| c.join(p)),
        }
    };
    let mut out = Vec::new();
    for seg in &parsed.segments {
        if !seg.contains(['[', '*', '?']) || parsed.remote_segments.binary_search(seg).is_ok() {
            continue;
        }
        let words: Vec<&str> = seg.split(' ').collect();
        if !words.first().is_some_and(|p| RESOLVED_PROGRAMS.contains(p)) {
            continue;
        }
        let mut changed = false;
        let mut new_words: Vec<String> = Vec::with_capacity(words.len());
        for (i, w) in words.iter().enumerate() {
            let text = crate::parser::desentinel(w);
            if i == 0 || text.starts_with('-') || text.contains('$') {
                new_words.push((*w).to_string());
                continue;
            }
            if !text.contains('[') {
                // `*` / `?` globs: `~/.s*h`, `/hom?/dev`, `/home/d*`, `**/*`.
                if let Some(names) =
                    star_glob_candidates(env, &text, home.as_deref(), cwd.as_deref())
                {
                    changed = true;
                    let sentinel = crate::parser::WS_SENTINEL.to_string();
                    new_words.extend(names.iter().map(|c| c.replace(' ', &sentinel)));
                } else {
                    new_words.push((*w).to_string());
                }
                continue;
            }
            let existing: Vec<String> = bracket_candidates(&text)
                .unwrap_or_default()
                .into_iter()
                .filter(|c| !c.contains(['*', '?']) && env.path_exists(&resolve(c)))
                .collect();
            let chosen = if existing.is_empty() {
                let (dir, pattern) = text.rsplit_once('/').unwrap_or(("", text.as_str()));
                CRITICAL_GLOB_NAMES
                    .iter()
                    .filter(|n| !dir.contains(['[', '*', '?']) && glob_matches(pattern, n))
                    .map(|n| {
                        if dir.is_empty() && !text.starts_with('/') {
                            (*n).to_string()
                        } else {
                            format!("{dir}/{n}")
                        }
                    })
                    .collect()
            } else {
                existing
            };
            if chosen.is_empty() {
                new_words.push((*w).to_string());
            } else {
                changed = true;
                let sentinel = crate::parser::WS_SENTINEL.to_string();
                new_words.extend(chosen.iter().map(|c| c.replace(' ', &sentinel)));
            }
        }
        if changed {
            out.push(new_words.join(" "));
        }
    }
    out
}

/// What a `*` / `?` glob operand names: zsh's `**/` (any depth) is dropped
/// (`**/*` deletes what `*` names, and more); otherwise every component is
/// matched against the real directory entries (at most
/// [`MAX_GLOB_CANDIDATES`] results), or, when nothing exists, against the
/// critical names ([`CRITICAL_GLOB_NAMES`]). A bare `*` component as the
/// last one is left to the rules (`rm -rf *`, `~/x/*`). `None` when the word
/// is not such a glob or names nothing.
fn star_glob_candidates(
    env: &dyn Environment,
    text: &str,
    home: Option<&std::path::Path>,
    cwd: Option<&std::path::Path>,
) -> Option<Vec<String>> {
    if !text.contains(['*', '?']) || text.contains(['{', '(', '\\']) {
        return None;
    }
    if text.contains("**") {
        let mut t = text.to_string();
        while t.contains("**/") {
            t = t.replace("**/", "");
        }
        let t = t.replace("**", "*");
        let t = if t.is_empty() { "*".to_string() } else { t };
        return (t != text).then(|| vec![crate::parser::normalize_path(&t)]);
    }
    let (root, spelled, rest): (std::path::PathBuf, String, &str) =
        if let Some(r) = text.strip_prefix("~/") {
            (home?.to_path_buf(), "~".to_string(), r)
        } else if let Some(r) = text.strip_prefix('/') {
            (std::path::PathBuf::from("/"), String::new(), r)
        } else {
            (cwd?.to_path_buf(), ".".to_string(), text)
        };
    let comps: Vec<&str> = rest.split('/').filter(|c| !c.is_empty()).collect();
    let last = comps.last()?;
    // `rm -rf ~/.*`: every dot entry of the home directory (credential
    // directories, startup files), named like `~/.[!.]*` is.
    let home_dots = comps.as_slice() == [".*"] && spelled == "~";
    if !home_dots
        && matches!(*last, "*" | ".*")
        && !comps[..comps.len() - 1]
            .iter()
            .any(|c| c.contains(['*', '?']))
    {
        return None;
    }
    // (real path, spelled path)
    let mut cands: Vec<(std::path::PathBuf, String)> = vec![(root, spelled)];
    for (k, comp) in comps.iter().enumerate() {
        let mut next = Vec::new();
        for (real, shown) in &cands {
            let join = |name: &str| {
                let shown = match shown.as_str() {
                    "" => format!("/{name}"),
                    "." => name.to_string(),
                    s => format!("{s}/{name}"),
                };
                (real.join(name), shown)
            };
            if !comp.contains(['*', '?']) {
                next.push(join(comp));
                continue;
            }
            if !env.path_exists(real) {
                continue;
            }
            let Ok(entries) = std::fs::read_dir(real) else {
                continue;
            };
            for e in entries.flatten().take(4096) {
                let name = e.file_name().to_string_lossy().to_string();
                if glob_matches(comp, &name) {
                    next.push(join(&name));
                }
            }
        }
        if next.len() > MAX_GLOB_CANDIDATES {
            return None;
        }
        if next.is_empty() {
            // Nothing exists: the critical names the last component matches.
            if k + 1 != comps.len() {
                return None;
            }
            let names: Vec<String> = CRITICAL_GLOB_NAMES
                .iter()
                .filter(|n| glob_matches(comp, n))
                .flat_map(|n| {
                    cands.iter().map(move |(_, shown)| match shown.as_str() {
                        "" => format!("/{n}"),
                        "." => (*n).to_string(),
                        s => format!("{s}/{n}"),
                    })
                })
                .collect();
            return (!names.is_empty()).then_some(names);
        }
        cands = next;
    }
    Some(cands.into_iter().map(|(_, s)| s).collect())
}

/// A SQL file to read (see [`sql_file_segments`]).
struct SqlInput {
    client: String,
    file: String,
    /// Directory of the file that includes it with a relative include.
    base: Option<std::path::PathBuf>,
    /// Include depth (0: named by the command line).
    depth: usize,
    /// Directories a `cd` / `pushd` earlier on the line moves to: a relative
    /// file is also looked up there (`cd mig && psql -f up.sql`).
    cd_dirs: Vec<std::path::PathBuf>,
}

/// Deepest chain of SQL files including each other that is followed.
const MAX_SQL_INCLUDE_DEPTH: usize = 8;

/// The files a SQL script includes: psql `\i F` / `\include F` (relative
/// to the working directory) and `\ir F` / `\include_relative F` (relative
/// to the script), `MySQL` `SOURCE F` / `\. F`, sqlite3 `.read F`,
/// sqlcmd `:r F`. The flag says whether the name is relative to the
/// including file.
fn sql_includes(text: &str) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut parts = line.trim().splitn(2, char::is_whitespace);
        let (Some(cmd), Some(arg)) = (parts.next(), parts.next()) else {
            continue;
        };
        let relative = match cmd.to_ascii_lowercase().as_str() {
            "\\i" | "\\include" | "\\." | "source" | ".read" | ":r" => false,
            "\\ir" | "\\include_relative" => true,
            _ => continue,
        };
        let f = arg
            .trim()
            .trim_end_matches(';')
            .trim()
            .trim_matches(['\'', '"']);
        if !f.is_empty() && !f.starts_with('|') {
            out.push((f.to_string(), relative));
        }
    }
    out
}

/// Largest SQL file read to check the statements a client runs from it.
const MAX_SQL_FILE_BYTES: usize = 16 * 1024 * 1024;

/// SQL clients whose input files are read and checked.
const SQL_CLIENTS: &[&str] = &["psql", "mysql", "mariadb", "sqlite3", "duckdb"];

/// What reading the SQL files of a line found.
#[derive(Default)]
struct SqlFiles {
    /// Segments of the files' statements (plus `database:sql_from_file`
    /// stand-ins for input that could not be read).
    segments: Vec<String>,
    /// A file / stream was referenced.
    referenced: bool,
    /// Every referenced file was read and checked.
    all_read: bool,
    /// (segment, file it was read from), to name the file and statement
    /// behind a match.
    origins: Vec<(String, String)>,
    /// The client of the first input that was not checked (named in the
    /// `database:sql_from_file` hint).
    unchecked_client: Option<String>,
    /// A file too large to check: (name, size in bytes).
    too_large: Option<(String, u64)>,
    /// A file whose check was stopped by the time budget.
    timed_out: Option<String>,
    /// The scan stopped at the first Critical statement.
    stopped_at_critical: bool,
}

impl SqlFiles {
    /// The `database:sql_from_file` description for this line: the hint
    /// names the real client, and the reason says why a file was not
    /// checked when it was found but could not be.
    fn sql_from_file_description(&self, generic: &str, parsed_client: &str) -> String {
        let client = self.unchecked_client.as_deref().unwrap_or(parsed_client);
        if let Some((file, bytes)) = &self.too_large {
            let mib = (bytes + 512 * 1024) / (1024 * 1024);
            return format!(
                "SQL from a file is not checked here: file too large to check ({mib} MiB): \
                 review the statements in {file} before running it."
            );
        }
        let text = generic.replace("<client>", client);
        match &self.timed_out {
            Some(file) => text.replacen(
                "SQL from a file is not checked here:",
                &format!("SQL from a file is not checked here: {file} took too long to check;"),
                1,
            ),
            None => text,
        }
    }
}

/// The SQL client a line runs (for the `database:sql_from_file` hint).
fn line_sql_client(parsed: &crate::parser::Parsed) -> &'static str {
    const CLIENTS: &[&str] = &[
        "psql",
        "mysql",
        "mariadb",
        "sqlite3",
        "duckdb",
        "sqlcmd",
        "cqlsh",
        "clickhouse-client",
        "mongosh",
        "mongo",
    ];
    parsed
        .segments
        .iter()
        .chain(std::iter::once(&parsed.flat))
        .find_map(|s| {
            s.split(|c: char| c.is_whitespace() || c == '|')
                .find_map(|w| CLIENTS.iter().find(|c| **c == w).copied())
        })
        .unwrap_or("psql")
}

/// The text sqlcmd sends to the server from a script, and the shell
/// commands it runs itself: `!!cmd` / `:!! cmd` run `cmd`, a `GO` line or a
/// `:` command ends the batch (`:r` files are followed as includes).
fn sqlcmd_script(text: &str) -> (String, Vec<String>) {
    static GO: OnceLock<Option<Regex>> = OnceLock::new();
    let go = GO.get_or_init(|| Regex::new(r"(?i)^go(?:\s+\d+)?\s*;?$").ok());
    let mut sql = String::with_capacity(text.len());
    let mut shell = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        let bang = t.strip_prefix("!!").or_else(|| {
            t.strip_prefix(':')
                .and_then(|r| r.trim_start().strip_prefix("!!"))
        });
        if let Some(cmd) = bang {
            shell.extend(crate::parser::parse(cmd.trim()).segments);
            sql.push_str(";\n");
        } else if t.starts_with(':') || go.as_ref().is_some_and(|g| g.is_match(t)) {
            sql.push_str(";\n");
        } else {
            sql.push_str(line);
            sql.push('\n');
        }
    }
    (sql, shell)
}

/// The SQL files a line runs (`psql -f F`, `--file=F`, `mysql < F`,
/// `sqlite3 db .read F`, `\i F` / `source F` in `-c` / `-e` text or a heredoc)
/// are read (never executed) and their statements analyzed like `-c` SQL.
/// A decompressed or generated stream (`gunzip -c d.gz | psql`, `psql -At -c
/// … | psql`) and unreadable files get the `database:sql_from_file`
/// stand-in.
#[allow(clippy::too_many_lines)]
fn sql_file_segments(
    env: &dyn Environment,
    parsed: &crate::parser::Parsed,
    stop_at: Option<&[Check]>,
) -> SqlFiles {
    static STREAM: OnceLock<Option<Regex>> = OnceLock::new();
    let mut out = SqlFiles {
        all_read: true,
        ..SqlFiles::default()
    };
    // The scan shares the blast-radius time budget (at least the default:
    // a small or zero budget only turns the impact details off).
    let started = std::time::Instant::now();
    let budget = std::time::Duration::from_millis(
        blast_radius::budget_ms().max(crate::config::DEFAULT_BLAST_RADIUS_BUDGET_MS),
    );
    // The Critical checks a statement is matched against as it is read:
    // the first one ends the scan (the line is Critical whatever follows).
    let critical: Vec<Check> = stop_at
        .unwrap_or_default()
        .iter()
        .filter(|c| c.severity == Severity::Critical)
        .cloned()
        .collect();
    let critical_index = if critical.is_empty() {
        None
    } else {
        LiteralIndex::new(&critical)
    };
    // Shown on the terminal when reading the files takes a while.
    let mut notice: Option<blast_radius::ProgressNotice> = None;
    let home = env.home_dir();
    let cwd = env.current_dir().ok();
    let resolve = |p: &str| -> std::path::PathBuf {
        match (p.strip_prefix('~'), &home) {
            (Some(rest), Some(h)) if rest.is_empty() || rest.starts_with('/') => {
                h.join(rest.trim_start_matches('/'))
            }
            _ => cwd
                .as_ref()
                .map_or_else(|| std::path::PathBuf::from(p), |c| c.join(p)),
        }
    };
    // (client, file, directories of earlier `cd`s) triples.
    let mut files: Vec<(String, String, Vec<std::path::PathBuf>)> = Vec::new();
    // `cd DIR` / `pushd DIR` segments before the client: where it may run.
    let mut cd_dirs: Vec<std::path::PathBuf> = Vec::new();
    // A heredoc's lines come before the client's own segment: start with the
    // first client of the line.
    let mut last_client = parsed
        .segments
        .iter()
        .find_map(|s| {
            s.split(' ')
                .next()
                .filter(|p| SQL_CLIENTS.contains(p))
                .map(str::to_string)
        })
        .unwrap_or_else(|| "psql".to_string());
    for seg in &parsed.segments {
        if parsed.remote_segments.binary_search(seg).is_ok() {
            continue;
        }
        let words: Vec<String> = seg.split(' ').map(crate::parser::desentinel).collect();
        let Some(prog) = words.first().map(String::as_str) else {
            continue;
        };
        if matches!(prog, "cd" | "pushd") && words.len() == 2 {
            let d = &words[1];
            if !d.starts_with('-') && !d.contains(['$', '`', '*']) {
                let base = cd_dirs.last().cloned().or_else(|| cwd.clone());
                let dir = if d.starts_with('~') || d.starts_with('/') {
                    resolve(d)
                } else {
                    base.map_or_else(|| std::path::PathBuf::from(d), |b| b.join(d))
                };
                // A long `cd` chain (every subshell's `cd` seen as one more
                // step) would make the tracked path grow without bound.
                if dir.as_os_str().len() <= 4096 && cd_dirs.len() < 256 {
                    cd_dirs.push(dir);
                }
            }
            continue;
        }
        // `sqlcmd -i a.sql,b.sql`, `cqlsh -f F`, `clickhouse-client
        // --queries-file F`, `mongosh script.js` / `--file F`: input files.
        if matches!(
            prog,
            "sqlcmd" | "cqlsh" | "clickhouse-client" | "mongosh" | "mongo"
        ) {
            let flags: &[&str] = match prog {
                "sqlcmd" => &["-i", "--input-file"],
                "clickhouse-client" => &["--queries-file"],
                // cqlsh, mongosh, mongo
                _ => &["-f", "--file"],
            };
            let mut i = 1;
            while i < words.len() {
                let w = words[i].as_str();
                let value = if flags.contains(&w) {
                    i += 1;
                    words.get(i).cloned()
                } else {
                    flags
                        .iter()
                        .find_map(|f| w.strip_prefix(&format!("{f}=")).map(str::to_string))
                        .or_else(|| {
                            (prog == "sqlcmd" && w.len() > 2 && w.starts_with("-i"))
                                .then(|| w[2..].to_string())
                        })
                };
                if let Some(v) = value {
                    for f in v.split(',').filter(|f| !f.is_empty()) {
                        files.push((prog.to_string(), f.to_string(), cd_dirs.clone()));
                    }
                } else if matches!(prog, "mongosh" | "mongo")
                    && !w.starts_with('-')
                    && std::path::Path::new(w)
                        .extension()
                        .is_some_and(|e| e.eq_ignore_ascii_case("js"))
                {
                    files.push((prog.to_string(), w.to_string(), cd_dirs.clone()));
                }
                i += 1;
            }
            continue;
        }
        if SQL_CLIENTS.contains(&prog) {
            last_client = prog.to_string();
            let mut i = 1;
            while i < words.len() {
                let w = words[i].as_str();
                let next = words.get(i + 1).cloned();
                // The SQL after `-c` / `-e` is not options: only a leading
                // `\\i FILE` / `source FILE` names a file.
                if matches!(w, "-c" | "--command" | "-e" | "--execute") {
                    if let (Some(meta), Some(f)) = (next.as_deref(), words.get(i + 2)) {
                        if matches!(
                            meta,
                            "\\i" | "\\ir" | "\\include" | "\\include_relative" | "source" | "\\."
                        ) {
                            files.push((prog.to_string(), f.clone(), cd_dirs.clone()));
                        }
                    }
                    // psql runs every `-c` and `-f` in order: a `-f` after a
                    // `-c` is read too. Only where the `-c` text is one word
                    // (the masked form of the segment, or a one-word
                    // script followed by an option): elsewhere the SQL words
                    // follow (`WHERE a < b` is not a redirection).
                    let one_word = seg.contains(crate::parser::WS_SENTINEL)
                        || words.get(i + 2).is_some_and(|w| w.starts_with('-'));
                    if !one_word {
                        break;
                    }
                    i += 2;
                    continue;
                }
                match w {
                    "-f" | "--file" | "<" | ".read" | "-init" if next.is_some() => {
                        files.push((prog.to_string(), next.unwrap_or_default(), cd_dirs.clone()));
                        i += 1;
                    }
                    _ => {
                        if let Some(f) = w.strip_prefix("--file=").or_else(|| {
                            w.strip_prefix("-f")
                                .filter(|f| !f.is_empty() && prog == "psql")
                        }) {
                            files.push((prog.to_string(), f.to_string(), cd_dirs.clone()));
                        }
                        // `mysql --init-command="…"` runs SQL at connect.
                        if let Some(sql) = w.strip_prefix("--init-command=") {
                            out.segments
                                .extend(crate::parser::sql_text_segments(prog, sql));
                        }
                    }
                }
                i += 1;
            }
        } else if matches!(prog, ".once" | ".output" | ".import" | ".read" | ".excel")
            && words
                .get(1)
                .is_some_and(|w| w.trim_start_matches(['\'', '"']).starts_with('|'))
        {
            // sqlite3 `.once |CMD`, `.output |CMD`, `.import |CMD t`, `.read
            // '|CMD'`: CMD is a shell command.
            let rest = words[1..].join(" ");
            let cmd = rest
                .trim_matches(['\'', '"'])
                .trim_start_matches('|')
                .trim_end_matches(['\'', '"']);
            let cmd = if prog == ".import" {
                // The last word is the table name.
                cmd.rsplit_once(' ').map_or(cmd, |(c, _)| c)
            } else {
                cmd
            };
            out.segments.extend(crate::parser::parse(cmd).segments);
        } else if prog == ".read" && words.len() == 2 {
            files.push(("sqlite3".to_string(), words[1].clone(), cd_dirs.clone()));
        } else if matches!(
            prog,
            "\\i" | "\\ir" | "\\include" | "\\include_relative" | "source" | "\\."
        ) && words.len() == 2
            && (prog.starts_with('\\') || last_client != "psql")
        {
            // A meta-command line of a heredoc / `-c` script.
            files.push((
                last_client.clone(),
                words[1].trim_end_matches(';').to_string(),
                cd_dirs.clone(),
            ));
        }
    }
    let mut seen = std::collections::HashSet::new();
    // (client, file, directory of the including file, include depth)
    let mut queue: std::collections::VecDeque<SqlInput> = files
        .into_iter()
        .map(|(client, file, cd_dirs)| SqlInput {
            client,
            file,
            base: None,
            depth: 0,
            cd_dirs,
        })
        .collect();
    'files: while let Some(SqlInput {
        client,
        file,
        base,
        depth,
        cd_dirs,
    }) = queue.pop_front()
    {
        if started.elapsed() > budget {
            out.all_read = false;
            out.timed_out.get_or_insert_with(|| file.clone());
            out.unchecked_client.get_or_insert_with(|| client.clone());
            out.segments.push(format!("psql -c \\i {file}"));
            break;
        }
        // `-f -` / `/dev/stdin`: the input is the terminal or a pipe.
        if matches!(file.as_str(), "-" | "/dev/stdin") {
            continue;
        }
        out.referenced = true;
        let spelled = ["$HOME/", "${HOME}/"]
            .iter()
            .find_map(|p| file.strip_prefix(p))
            .map_or_else(|| file.clone(), |rest| format!("~/{rest}"));
        let path = match &base {
            // `\ir` is relative to the including file.
            Some(b) if !spelled.starts_with(['/', '~']) => b.join(&spelled),
            _ => resolve(&spelled),
        };
        // After `cd DIR`, a relative name is DIR's file. Where the cd may
        // not apply (a subshell, a failed cd) the working directory's file
        // is read too: either may be the one that runs.
        let mut paths = vec![path];
        if base.is_none() && !spelled.starts_with(['/', '~']) {
            paths.extend(cd_dirs.iter().map(|d| d.join(&spelled)));
        }
        paths.retain(|p| seen.insert(p.clone()));
        if paths.is_empty() {
            continue;
        }
        // Only a regular file is read: a FIFO, `/dev/tty` or `/dev/zero`
        // would block or never end.
        let read = |path: &std::path::Path| -> Option<String> {
            let regular = std::fs::metadata(path).map_or(true, |m| {
                m.is_file() && m.len() <= MAX_SQL_FILE_BYTES as u64
            });
            (!spelled.contains(['$', '`', '*']) && regular)
                .then(|| env.read_file(path).ok())
                .flatten()
                .filter(|t| t.len() <= MAX_SQL_FILE_BYTES)
        };
        if out.too_large.is_none() {
            out.too_large = paths.iter().find_map(|p| {
                std::fs::metadata(p)
                    .ok()
                    .filter(|m| m.is_file() && m.len() > MAX_SQL_FILE_BYTES as u64)
                    .map(|m| (file.clone(), m.len()))
            });
        }
        if notice.is_none() {
            notice = Some(blast_radius::start_progress_notice(format!(
                "shellfirm: checking {file}{} (Ctrl-C cancels)",
                crate::config::glyph("…", "...")
            )));
        }
        let texts: Vec<(std::path::PathBuf, String)> = paths
            .iter()
            .filter_map(|p| read(p).map(|t| (p.clone(), t)))
            .collect();
        if texts.is_empty() {
            out.all_read = false;
            out.unchecked_client.get_or_insert_with(|| client.clone());
            out.segments.push(match client.as_str() {
                "sqlite3" | "duckdb" => format!(".read {file}"),
                c @ ("mysql" | "mariadb") => format!("{c} -e source {file}"),
                _ => format!("psql -c \\i {file}"),
            });
        }
        for (path, t) in texts {
            // A mongosh script is JavaScript: its calls are matched as text.
            let mut segs: Vec<String> = if matches!(client.as_str(), "mongosh" | "mongo") {
                t.lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with("//"))
                    .take(10_000)
                    .map(|l| format!("mongosh --eval {l}"))
                    .collect()
            } else if client == "sqlcmd" {
                let (sql, mut shell) = sqlcmd_script(&t);
                shell.extend(crate::parser::sql_text_segments(&client, &sql));
                shell
            } else {
                crate::parser::sql_text_segments(&client, &t)
            };
            // Stop at the first Critical statement, or when the time
            // budget is spent (what is left is not checked: fail closed).
            let mut stop = false;
            let mut over_budget = started.elapsed() > budget;
            for (at, sg) in segs.iter().enumerate() {
                if critical_index
                    .as_ref()
                    .is_some_and(|ix| !ix.matches(sg, env, false).is_empty())
                {
                    segs.truncate(at + 1);
                    out.stopped_at_critical = true;
                    stop = true;
                    break;
                }
                if at % 4096 == 4095 && started.elapsed() > budget {
                    segs.truncate(at + 1);
                    over_budget = true;
                    break;
                }
            }
            out.origins
                .extend(segs.iter().map(|sg| (sg.clone(), file.clone())));
            out.segments.extend(segs);
            if stop {
                break 'files;
            }
            if over_budget {
                out.all_read = false;
                out.timed_out.get_or_insert_with(|| file.clone());
                out.unchecked_client.get_or_insert_with(|| client.clone());
                out.segments.push(format!("psql -c \\i {file}"));
                break 'files;
            }
            // The files it includes run too (up to eight levels).
            for (inc, relative) in sql_includes(&t) {
                if depth + 1 > MAX_SQL_INCLUDE_DEPTH {
                    out.all_read = false;
                    out.unchecked_client.get_or_insert_with(|| client.clone());
                    out.segments.push(format!("psql -c \\i {inc}"));
                    break;
                }
                queue.push_back(SqlInput {
                    client: client.clone(),
                    file: inc,
                    base: relative
                        .then(|| path.parent().map(std::path::Path::to_path_buf))
                        .flatten(),
                    depth: depth + 1,
                    cd_dirs: cd_dirs.clone(),
                });
            }
        }
    }
    // Streams: decompressed dumps and SQL generated by another query (the
    // regex is only built for a line that pipes into a SQL client).
    let pipes_sql = parsed.flat.contains('|')
        && ["psql", "mysql", "mariadb", "sqlite3"]
            .iter()
            .any(|c| parsed.flat.contains(c));
    if !pipes_sql {
        return out;
    }
    let stream = STREAM.get_or_init(|| {
        Regex::new(
            r"(?:^|\s)(?:gunzip|gzip\s+-[a-z]*d|xz\s+-[a-z]*d|zstd\s+-[a-z]*d|bunzip2|unzip\s+-p|psql|mysql|mariadb)\b[^|;&\n]*\|\s*(psql|mysql|mariadb|sqlite3)\b",
        )
        .ok()
    });
    if let Some(c) = stream.as_ref().and_then(|r| r.captures(&parsed.flat)) {
        out.referenced = true;
        out.all_read = false;
        out.unchecked_client
            .get_or_insert_with(|| c.get(1).map_or("psql", |m| m.as_str()).to_string());
        out.segments.push(format!(
            "zcat - | {}",
            c.get(1).map_or("psql", |m| m.as_str())
        ));
    }
    out
}

/// String with all checks from `checks` folder (prepared in build.rs) in YAML
/// format. The runtime uses [`BUILTIN_CHECKS`] (the same checks as static
/// data); tests check that both agree.
#[cfg(test)]
const ALL_CHECKS: &str = include_str!(concat!(env!("OUT_DIR"), "/all-checks.yaml"));

// `BUILTIN_CHECKS`: every built-in check as static data, generated by
// build.rs from `checks/*.yaml`.
include!(concat!(env!("OUT_DIR"), "/builtin-checks.rs"));

/// A built-in check as generated by build.rs (see [`BUILTIN_CHECKS`]).
/// `None` for `challenge` / `severity` means "not set" (the serde default).
struct BuiltinCheck {
    id: &'static str,
    test: &'static str,
    description: &'static str,
    from: &'static str,
    challenge: Option<Challenge>,
    filters: &'static [BuiltinFilter],
    alternative: Option<&'static str>,
    alternative_info: Option<&'static str>,
    severity: Option<Severity>,
    /// Folded literals of which one occurs in every match of `test`.
    literals: &'static [&'static str],
}

/// A [`Filter`] of a [`BuiltinCheck`].
// Mirrors every `Filter` type, whether or not a built-in check uses it yet.
#[allow(dead_code)]
enum BuiltinFilter {
    PathExists(usize),
    NotContains(&'static str),
    Contains(&'static str),
    NotMatches(&'static str),
    Matches(&'static str),
}

impl BuiltinCheck {
    fn to_check(&self) -> Check {
        let filters = self
            .filters
            .iter()
            .map(|f| match f {
                BuiltinFilter::PathExists(n) => Filter::PathExists(*n),
                BuiltinFilter::NotContains(s) => Filter::NotContains((*s).to_string()),
                BuiltinFilter::Contains(s) => Filter::Contains((*s).to_string()),
                BuiltinFilter::NotMatches(s) => Filter::NotMatches((*s).to_string()),
                BuiltinFilter::Matches(s) => Filter::Matches((*s).to_string()),
            })
            .collect();
        Check {
            id: self.id.to_string(),
            test: CheckRegex::lazy(
                self.test.to_string(),
                (!self.literals.is_empty()).then_some(self.literals),
            ),
            description: self.description.to_string(),
            from: self.from.to_string(),
            challenge: self.challenge.unwrap_or_default(),
            filters,
            alternative: self.alternative.map(str::to_string),
            alternative_info: self.alternative_info.map(str::to_string),
            severity: self.severity.unwrap_or_default(),
        }
    }
}

/// The `test` regex of a [`Check`].
///
/// Behaves like a [`Regex`] (it dereferences to one), but a built-in check's
/// regex is compiled only the first time it is needed: compiling all ~300
/// built-in regexes up front dominated the latency of every shell-hook call.
/// Built-in checks also carry a literal prefilter (derived by build.rs), so
/// a command that cannot match a check never compiles that check's regex.
///
/// Checks deserialized from user files (custom checks, policies) and checks
/// built with [`CheckRegex::new`] / `From<Regex>` are compiled eagerly, so an
/// invalid regex is still reported where the check is loaded. Clones share
/// the compiled regex.
#[derive(Clone)]
pub struct CheckRegex(Arc<CheckRegexInner>);

struct CheckRegexInner {
    source: String,
    /// Folded literals of which at least one occurs in every text the regex
    /// matches (`None`: no prefilter, always run the regex).
    prefilter: Option<&'static [&'static str]>,
    compiled: OnceLock<Regex>,
}

impl CheckRegex {
    /// Compile `pattern` now.
    ///
    /// # Errors
    /// When `pattern` is not a valid regex.
    pub fn new(pattern: &str) -> std::result::Result<Self, regex::Error> {
        Regex::new(pattern).map(Self::from)
    }

    /// A regex compiled on first use. Only for patterns already validated
    /// (built-in checks are validated by build.rs).
    fn lazy(source: String, prefilter: Option<&'static [&'static str]>) -> Self {
        Self(Arc::new(CheckRegexInner {
            source,
            prefilter,
            compiled: OnceLock::new(),
        }))
    }

    /// The regex source, without compiling it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0.source
    }

    /// The compiled regex (compiled now if this is its first use).
    ///
    /// # Panics
    /// Only if a lazily compiled built-in pattern is invalid, which build.rs
    /// rules out.
    #[must_use]
    pub fn regex(&self) -> &Regex {
        self.0.compiled.get_or_init(|| {
            Regex::new(&self.0.source).expect("built-in check regex is validated by build.rs")
        })
    }

    /// Whether the regex matches `text`; `folded` is `text` folded with
    /// [`crate::prefilter::fold`]. Checks whose required literals are
    /// all absent from `folded` are rejected without running (or compiling)
    /// the regex.
    fn is_match_prefiltered(&self, text: &str, folded: &str) -> bool {
        if let Some(lits) = self.0.prefilter {
            if !lits.iter().any(|l| folded.contains(l)) {
                return false;
            }
        }
        self.regex().is_match(text)
    }
}

impl From<Regex> for CheckRegex {
    fn from(re: Regex) -> Self {
        let compiled = OnceLock::new();
        let source = re.as_str().to_string();
        let _ = compiled.set(re);
        Self(Arc::new(CheckRegexInner {
            source,
            prefilter: None,
            compiled,
        }))
    }
}

impl std::ops::Deref for CheckRegex {
    type Target = Regex;

    fn deref(&self) -> &Regex {
        self.regex()
    }
}

impl std::fmt::Debug for CheckRegex {
    /// Same output as [`Regex`]'s `Debug`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Regex").field(&self.as_str()).finish()
    }
}

impl serde::Serialize for CheckRegex {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for CheckRegex {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        serde_regex::deserialize::<Regex, D>(deserializer).map(Self::from)
    }
}

/// Severity level of a check — determines how critical a matched pattern is.
///
/// The natural ordering (`Info < Low < Medium < High < Critical`) is used
/// for filtering: when a `min_severity` is configured, only checks at or
/// above that threshold trigger a challenge.
#[derive(Debug, Default, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    #[default]
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// A single post-match filter that gates whether a check should fire.
///
/// Filters are evaluated after the regex matches. **All** filters in the
/// list must pass (logical AND) for the check to be kept.
///
/// YAML format (adjacently tagged):
/// ```yaml
/// filters:
///   - type: PathExists
///     value: 1
///   - type: NotContains
///     value: "--dry-run"
/// ```
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(tag = "type", content = "value")]
pub enum Filter {
    /// Keep the check only if the captured path exists on disk.
    /// The value is the regex capture-group index (1-based).
    PathExists(usize),
    /// Keep the check only if the command does **not** contain this substring.
    NotContains(String),
    /// Keep the check only if the command **does** contain this substring.
    Contains(String),
    /// Keep the check only if the (normalized) command does **not** match
    /// this regex. Use it for token-aware exemptions such as
    /// `\s--dry-run(=(client|server))?(\s|$)`.
    NotMatches(String),
    /// Keep the check only if the (normalized) command **does** match this regex.
    Matches(String),
}

/// Describe single check
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Check {
    pub id: String,
    /// test is a value that we check the command.
    pub test: CheckRegex,
    /// description of what is risky in this command
    pub description: String,
    /// the group of the check see files in `checks` folder
    pub from: String,
    #[serde(default)]
    pub challenge: Challenge,
    #[serde(default)]
    pub filters: Vec<Filter>,
    /// Safer command alternative suggestion (shown to user).
    #[serde(default)]
    pub alternative: Option<String>,
    /// Explanation of why the alternative is safer.
    #[serde(default)]
    pub alternative_info: Option<String>,
    /// Severity level — determines how critical this check is.
    #[serde(default)]
    pub severity: Severity,
}

/// Return a cached reference to all built-in check patterns.
///
/// Built once (on first call) from the static [`BUILTIN_CHECKS`] table: no
/// YAML parsing, and no regex compiled until a check needs it (see
/// [`CheckRegex`]). Subsequent calls return the cached slice.
pub(crate) fn all_checks_cached() -> &'static [Check] {
    static CHECKS: OnceLock<Vec<Check>> = OnceLock::new();
    CHECKS.get_or_init(|| BUILTIN_CHECKS.iter().map(BuiltinCheck::to_check).collect())
}

/// Return all built-in shellfirm check patterns
///
/// # Errors
/// when has an error when parsing check str to [`Check`] list
pub fn get_all() -> Result<Vec<Check>> {
    Ok(all_checks_cached().to_vec())
}

/// Load custom checks from YAML files in a directory.
///
/// # Errors
/// When a file cannot be read or parsed.
pub fn load_custom_checks(checks_dir: &std::path::Path) -> Result<Vec<Check>> {
    let mut custom_checks = Vec::new();
    if !checks_dir.is_dir() {
        return Ok(custom_checks);
    }
    let entries = std::fs::read_dir(checks_dir)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "yaml" || e == "yml") {
            let content = std::fs::read_to_string(&path)?;
            let checks: Vec<Check> = serde_yaml::from_str(&content)?;
            custom_checks.extend(checks);
        }
    }
    Ok(custom_checks)
}

/// Validate check definitions and return a list of warning messages.
///
/// Currently checks:
/// - `PathExists(n)` — warns when `n` exceeds the number of capture groups
///   in the check's regex.
#[must_use]
pub fn validate_checks(checks: &[Check]) -> Vec<String> {
    let mut warnings = Vec::new();
    for check in checks {
        let num_captures = check.test.captures_len(); // group 0 + real groups
        for filter in &check.filters {
            if let Filter::PathExists(group_idx) = filter {
                if *group_idx >= num_captures {
                    warnings.push(format!(
                        "check {:?}: PathExists({}) references a capture group that \
                         does not exist (regex has {} groups including group 0)",
                        check.id, group_idx, num_captures
                    ));
                }
            }
        }
    }
    warnings
}

/// Build what the challenge prompt shows for a set of matched checks.
///
/// That is: descriptions, alternatives, deny status and reasons, and the
/// effective challenge after every escalation layer (see
/// [`context::effective_challenge`]) together with the reasons it was
/// escalated.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn build_challenge_display(
    settings: &Settings,
    resolved: &ResolvedSettings,
    checks: &[&Check],
    context: &RuntimeContext,
    merged_policy: &MergedPolicy,
    blast_radii: &[(String, BlastRadiusInfo)],
) -> DisplayContext {
    let mut descriptions: Vec<String> = Vec::new();
    let mut alternatives: Vec<AlternativeInfo> = Vec::new();
    let mut check_ids: Vec<String> = Vec::new();

    debug!(
        "list of denied pattern ids {:?}",
        settings.deny_patterns_ids
    );

    for check in checks {
        if !descriptions.contains(&check.description) {
            descriptions.push(check.description.clone());
        }
        if !check_ids.contains(&check.id) {
            check_ids.push(check.id.clone());
        }
        // Collect alternatives
        if let Some(ref alt) = check.alternative {
            let already_has = alternatives.iter().any(|a| a.suggestion == *alt);
            if !already_has {
                alternatives.push(AlternativeInfo {
                    suggestion: alt.clone(),
                    explanation: check.alternative_info.clone(),
                });
            }
        }
    }

    // Deny (global settings deny list or project policy) is absolute.
    let deny_reasons = context::deny_reasons(settings, checks, merged_policy);

    let effective =
        context::effective_challenge(settings, resolved, checks, context, merged_policy);

    // Compute highest severity for display
    let severity_label = checks
        .iter()
        .map(|c| c.severity)
        .max()
        .map(|s| format!("{s}"));

    // Build blast radius label from the highest-scope entry
    let blast_radius_label = blast_radii
        .iter()
        .max_by_key(|(_, br)| br.scope)
        .map(|(_, br)| {
            format!(
                "[{}] {} {}",
                br.scope,
                crate::config::glyph("—", "-"),
                crate::config::ascii_fallback(&context::escape_invisible(&br.description))
            )
        });

    let matched: Vec<crate::prompt::MatchedCheck> = {
        let mut seen = std::collections::HashSet::new();
        checks
            .iter()
            .filter(|c| seen.insert(c.id.as_str()))
            .map(|c| crate::prompt::MatchedCheck {
                id: c.id.clone(),
                severity: c.severity.to_string(),
                description: c.description.clone(),
            })
            .collect()
    };
    // Checks enforced by a project / org policy cannot be ignored or
    // un-denied from the personal config: say who enforces them instead.
    let enforced: Vec<&str> = check_ids
        .iter()
        .filter(|id| merged_policy.is_enforced(id))
        .map(String::as_str)
        .collect();
    let label = |id: &str| {
        merged_policy
            .label_for(id)
            .unwrap_or_else(|| "project policy (.shellfirm.yaml)".to_string())
    };
    let ignore_hint = if enforced.is_empty() {
        ignore_hint(checks, context, !deny_reasons.is_empty())
    } else if deny_reasons.is_empty() {
        Some(format!(
            "`{}` is enforced by the {}.",
            enforced.join("`, `"),
            label(enforced[0])
        ))
    } else {
        None
    };
    let deny_hint = if deny_reasons.is_empty() {
        None
    } else {
        let personal: Vec<String> = check_ids
            .iter()
            .filter(|id| settings.deny_patterns_ids.contains(id) && !merged_policy.is_denied(id))
            .cloned()
            .collect();
        let by_policy: Vec<&str> = check_ids
            .iter()
            .filter(|id| merged_policy.is_denied(id))
            .map(String::as_str)
            .collect();
        let mut parts = Vec::new();
        if !personal.is_empty() {
            parts.push(crate::prompt::personal_deny_hint(&personal));
        }
        if !by_policy.is_empty() {
            // The deny reason already names the policy: say only what to do.
            parts.push(format!(
                "Only a change to {} can allow it.",
                if by_policy.len() == 1 {
                    "that policy"
                } else {
                    "those policies"
                }
            ));
        }
        (!parts.is_empty()).then(|| parts.join(" "))
    };

    // A context escalation configured below its default weakens the
    // protection of exactly the contexts it exists for: say so.
    let mut notes = Vec::new();
    let esc = &settings.context.escalation;
    let defaults = context::EscalationConfig::default();
    match context.risk_level {
        context::RiskLevel::Critical if defaults.critical.is_stricter_than(esc.critical) => {
            notes.push(format!(
                "Note: context escalation for critical contexts is set to {} (default {}), so production / root / protected-branch commands ask less than the default.",
                esc.critical, defaults.critical
            ));
        }
        context::RiskLevel::Elevated if defaults.elevated.is_stricter_than(esc.elevated) => {
            notes.push(format!(
                "Note: context escalation for elevated contexts is set to {} (default {}).",
                esc.elevated, defaults.elevated
            ));
        }
        _ => {}
    }

    DisplayContext {
        command: None,
        matched,
        ignore_hint,
        is_denied: !deny_reasons.is_empty(),
        descriptions,
        alternatives,
        context_labels: context.labels.clone(),
        effective_challenge: effective.challenge,
        escalation_note: effective.note(),
        severity_label,
        blast_radius_label,
        check_ids,
        base_challenge: effective.base,
        escalation_reasons: effective.reasons,
        deny_reasons,
        deny_hint,
        notes,
    }
}

/// The "Not risky for you? Stop asking with …" hint for a prompt.
///
/// Not offered when the command is denied, when any matched check is
/// Critical, or when the context is Critical (production, root, protected
/// branch, sensitive path): at that point the banner must not advertise a
/// one-line way to switch the guard off. With several matched checks every
/// id has to be ignored to stop the prompt, so the hint chains one command
/// per id, most specific first (broad `*-strict:` catch-alls last, with a
/// note on what ignoring them covers).
#[must_use]
pub fn ignore_hint(checks: &[&Check], context: &RuntimeContext, denied: bool) -> Option<String> {
    if denied
        || checks.is_empty()
        || checks.iter().any(|c| c.severity >= Severity::Critical)
        || context.risk_level == context::RiskLevel::Critical
        || context.is_root
    {
        return None;
    }
    let mut ids: Vec<&Check> = Vec::new();
    for c in checks {
        if !ids.iter().any(|x| x.id == c.id) {
            ids.push(c);
        }
    }
    // Catch-alls that match a whole program (every `rm -r`, every `chmod`),
    // not the specific `*-strict` checks (`git-strict:stash_pop_drop`).
    let broad = |c: &&Check| {
        matches!(
            c.id.as_str(),
            "fs-strict:any_deletion"
                | "fs-strict:recursive_deletion"
                | "fs-strict:folder_deletion"
                | "fs-strict:change_permissions"
                | "kubernetes-strict:delete_resource"
                | "kubernetes-strict:update_resource"
        )
    };
    ids.sort_by_key(|c| (broad(c), c.severity));
    let cmds: Vec<String> = ids
        .iter()
        .map(|c| format!("shellfirm config ignore {}", c.id))
        .collect();
    let mut hint = format!(
        "Not risky for you? Stop asking with `{}`.",
        cmds.join(" && ")
    );
    let broad_ids: Vec<&str> = ids
        .iter()
        .filter(|c| broad(c))
        .map(|c| c.id.as_str())
        .collect();
    if !broad_ids.is_empty() {
        let _ = std::fmt::Write::write_fmt(
            &mut hint,
            format_args!(
                " (`{}` is a broad catch-all: ignoring it silences it for every command it matches.)",
                broad_ids.join("`, `")
            ),
        );
    }
    Some(hint)
}

/// Context-aware challenge flow using the Prompter trait.
///
/// Builds the display with [`build_challenge_display`] (all escalation
/// layers; each can only make the challenge stricter, never weaker) and
/// runs it through `prompter`.
///
/// # Errors
/// Returns an error if the prompter fails.
pub fn challenge_with_context(
    settings: &Settings,
    resolved: &ResolvedSettings,
    checks: &[&Check],
    context: &RuntimeContext,
    merged_policy: &MergedPolicy,
    prompter: &dyn Prompter,
    blast_radii: &[(String, BlastRadiusInfo)],
) -> Result<ChallengeResult> {
    let display = build_challenge_display(
        settings,
        resolved,
        checks,
        context,
        merged_policy,
        blast_radii,
    );
    Ok(prompter.run_challenge(&display))
}

/// Check if the given command matched to one of the checks.
///
/// Uses [`crate::env::RealEnvironment`] for filter evaluation (filesystem checks).
/// For testing, prefer [`run_check_on_command_with_env`] with a mock environment.
///
/// # Arguments
///
/// * `checks` - List of checks that we want to validate.
/// * `command` - Command check.
#[must_use]
pub fn run_check_on_command<'a>(checks: &'a [Check], command: &str) -> Vec<&'a Check> {
    run_check_on_command_with_env(checks, command, &crate::env::RealEnvironment)
}

/// The built-in checks that match `command` but are on the ignore list.
///
/// `pre-command --test` / `check` use it to say "matched X (ignored by your
/// settings)" instead of "nothing matched".
#[must_use]
pub fn ignored_matches(settings: &Settings, command: &str, env: &dyn Environment) -> Vec<Check> {
    let ignores = settings.effective_ignores();
    if ignores.is_empty() {
        return Vec::new();
    }
    let enabled: std::collections::HashSet<&str> =
        settings.enabled_groups.iter().map(String::as_str).collect();
    let switched_off: Vec<Check> = all_checks_cached()
        .iter()
        .filter(|c| ignores.contains(c.id.as_str()) && enabled.contains(c.from.as_str()))
        .cloned()
        .collect();
    if switched_off.is_empty() {
        return Vec::new();
    }
    let mut seen = std::collections::HashSet::new();
    run_check_on_command_with_env(&switched_off, command, env)
        .into_iter()
        .filter(|c| seen.insert(c.id.clone()))
        .cloned()
        .collect()
}

/// Like `run_check_on_command` but uses the Environment trait for filters.
///
/// The command is parsed with the shell-aware [`crate::parser`] first: each
/// normalized segment (and the operator-preserving flat form) is matched, and
/// results are de-duplicated by check id.
#[must_use]
pub fn run_check_on_command_with_env<'a>(
    checks: &'a [Check],
    command: &str,
    env: &dyn Environment,
) -> Vec<&'a Check> {
    let parsed = crate::parser::parse(command);
    let segment_matches: Vec<&Check> = parsed
        .segments
        .iter()
        .flat_map(|s| match_segment(checks, s, &parsed.remote_segments, env))
        .collect();
    let flat_matches = if parsed.flat.is_empty() {
        Vec::new()
    } else {
        match_flat(checks, &parsed.flat, env)
    };
    // All matches borrow from the same `checks` slice, so dedup by identity
    // (two distinct checks may legitimately share an id).
    let mut seen = std::collections::HashSet::new();
    segment_matches
        .into_iter()
        .chain(flat_matches)
        .filter(|c| seen.insert(std::ptr::from_ref::<Check>(c)))
        .collect()
}

/// Match checks against a single, already-normalized command text (no
/// parsing). Filters are evaluated on the same text.
#[must_use]
pub fn match_text<'a>(checks: &'a [Check], text: &str, env: &dyn Environment) -> Vec<&'a Check> {
    match_text_impl(checks, text, env, false)
}

/// Match the operator-preserving flat form of a line (for cross-operator
/// patterns such as `curl … | sh`).
///
/// A match whose text spans a command separator (`&&`, `||`, `;`, `|`, `&`,
/// newline) is only kept when the check is written for a pipeline (its regex
/// contains a literal `\|`): otherwise `git checkout main && rm -f x` would be
/// a "force checkout" because `.*-f` reached into the next command.
fn match_flat<'a>(checks: &'a [Check], flat: &str, env: &dyn Environment) -> Vec<&'a Check> {
    match_text(checks, flat, env)
        .into_iter()
        .filter(|c| {
            // A literal `\|` that is a pipe (not the `>|` clobber redirect).
            let re = c.test.as_str();
            let pipeline = re
                .match_indices("\\|")
                .any(|(i, _)| !re[..i].ends_with('>'));
            // A path check is decided on the segments, where variables and
            // the working directory are resolved (`f=$(mktemp); echo > "$f"`
            // writes a fresh file, not an unknown one).
            // So is a check whose exemption is written for a whole segment
            // (a `^`-anchored filter, e.g. `chown -R $USER .`).
            let path_check = c.filters.iter().any(|f| {
                matches!(f, Filter::PathExists(_))
                    || matches!(f, Filter::NotMatches(re) if re.starts_with('^'))
            });
            pipeline
                || (!path_check && c.test.find_iter(flat).any(|m| !spans_separator(m.as_str())))
        })
        .collect()
}

/// Whether a piece of the flat form contains a command separator word.
fn spans_separator(text: &str) -> bool {
    text.split([' ', '\n'])
        .any(|w| matches!(w, "&&" | "||" | ";" | "|" | "&" | "|&" | ";;"))
        || text.contains('\n')
}

/// Match one parsed segment. Segments that run remotely or in a container
/// (`remote`) skip local path-existence filters: their paths are assumed to
/// exist.
fn match_segment<'a>(
    checks: &'a [Check],
    text: &str,
    remote: &[String],
    env: &dyn Environment,
) -> Vec<&'a Check> {
    let is_remote = remote.binary_search_by(|r| r.as_str().cmp(text)).is_ok();
    match_text_impl(checks, text, env, is_remote)
}

/// Segment count above which [`LiteralIndex`] is built (its build costs
/// about a millisecond; a normal command line has a handful of segments).
const LITERAL_INDEX_MIN_SEGMENTS: usize = 512;

/// The prefilter literals of a check list in one Aho-Corasick automaton:
/// one pass over a segment finds every literal it contains, and a check
/// runs its regex only when one of its literals was found (the same
/// decision as [`CheckRegex::is_match_prefiltered`], in O(text) instead of
/// O(checks x literals)).
struct LiteralIndex<'a> {
    ac: aho_corasick::AhoCorasick,
    literals: usize,
    /// Per check: the ids of its literals, `None` = no prefilter.
    per_check: Vec<Option<Vec<usize>>>,
    checks: &'a [Check],
}

impl<'a> LiteralIndex<'a> {
    fn new(checks: &'a [Check]) -> Option<Self> {
        let mut lits: Vec<&'static str> = Vec::new();
        let mut ids: std::collections::HashMap<&'static str, usize> =
            std::collections::HashMap::new();
        let per_check = checks
            .iter()
            .map(|c| {
                c.test.0.prefilter.map(|ls| {
                    ls.iter()
                        .map(|l| {
                            *ids.entry(l).or_insert_with(|| {
                                lits.push(l);
                                lits.len() - 1
                            })
                        })
                        .collect()
                })
            })
            .collect();
        let ac = aho_corasick::AhoCorasick::new(&lits).ok()?;
        Some(Self {
            ac,
            literals: lits.len(),
            per_check,
            checks,
        })
    }

    fn matches(
        &self,
        text: &str,
        env: &dyn Environment,
        assume_paths_exist: bool,
    ) -> Vec<&'a Check> {
        let folded = crate::prefilter::fold(text);
        let mut hit = vec![false; self.literals];
        for m in self.ac.find_overlapping_iter(&folded) {
            hit[m.pattern().as_usize()] = true;
        }
        self.checks
            .iter()
            .zip(&self.per_check)
            .filter(|(c, lits)| {
                lits.as_ref().is_none_or(|ids| ids.iter().any(|&i| hit[i]))
                    && c.test.regex().is_match(text)
            })
            .map(|(c, _)| c)
            .filter(|c| check_filters(c, text, env, assume_paths_exist))
            .collect()
    }
}

fn match_text_impl<'a>(
    checks: &'a [Check],
    text: &str,
    env: &dyn Environment,
    assume_paths_exist: bool,
) -> Vec<&'a Check> {
    let folded = crate::prefilter::fold(text);
    checks
        .iter()
        .filter(|v| v.test.is_match_prefiltered(text, &folded))
        .filter(|v| check_filters(v, text, env, assume_paths_exist))
        .collect()
}

/// Evaluate filters using the [`Environment`] trait (testable version).
///
/// Returns `true` when the check should be kept (all filters pass).
#[cfg(test)]
fn check_custom_filter_with_env(check: &Check, command: &str, env: &dyn Environment) -> bool {
    check_filters(check, command, env, false)
}

fn check_filters(
    check: &Check,
    command: &str,
    env: &dyn Environment,
    assume_paths_exist: bool,
) -> bool {
    if check.filters.is_empty() {
        return true;
    }
    let caps = check.test.captures(command);

    for filter in &check.filters {
        debug!("filter information: command {command:?} filter: {filter:?}");

        let keep = match filter {
            Filter::PathExists(group_idx) => {
                let file_path = caps
                    .as_ref()
                    .and_then(|c| c.get(*group_idx))
                    .map_or_else(
                        || {
                            warn!(
                                "check {:?}: PathExists references capture group {} which does not exist in regex",
                                check.id, group_idx
                            );
                            ""
                        },
                        |m| m.as_str(),
                    );
                if file_path.is_empty() {
                    // No path captured → treat as "path doesn't exist" → suppress check
                    false
                } else if assume_paths_exist {
                    true
                } else {
                    filter_path_exists_with_env(file_path, env)
                }
            }
            Filter::NotContains(ref s) => !command.contains(s.as_str()),
            Filter::Contains(ref s) => command.contains(s.as_str()),
            Filter::NotMatches(ref re) => !filter_regex_matches(&check.id, re, command),
            Filter::Matches(ref re) => filter_regex_matches(&check.id, re, command),
        };

        if !keep {
            return false;
        }
    }

    true
}

/// Evaluate a regex filter, caching compiled regexes. An invalid regex is
/// reported and treated as "no match".
fn filter_regex_matches(check_id: &str, re: &str, command: &str) -> bool {
    use std::collections::HashMap;
    use std::sync::Mutex;
    static CACHE: OnceLock<Mutex<HashMap<String, Option<Regex>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let compiled = {
        let mut guard = cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard
            .entry(re.to_string())
            .or_insert_with(|| match Regex::new(re) {
                Ok(r) => Some(r),
                Err(err) => {
                    warn!("check {check_id:?}: invalid filter regex {re:?}: {err}");
                    None
                }
            })
            .clone()
    };
    compiled.is_some_and(|r| r.is_match(command))
}

/// Check whether any path operand in the captured text exists.
///
/// The capture may hold several whitespace-separated operands
/// (`rm -rf a b`). Flags (`-x`) and redirections (`> f`) are skipped. The
/// filter passes when **any** operand exists (or is a glob / variable).
fn filter_path_exists_with_env(file_path: &str, env: &dyn Environment) -> bool {
    // Looked up once: `getcwd` per operand dominated long argument lists.
    let cwd = std::cell::OnceCell::new();
    let mut tokens = file_path.split_whitespace();
    while let Some(tok) = tokens.next() {
        let bare = tok.trim_start_matches(|c: char| c.is_ascii_digit());
        if bare.starts_with('>') || bare.starts_with('<') || bare.starts_with("&>") {
            tokens.next(); // skip the redirection target
            continue;
        }
        if tok.starts_with('-') && tok != "-" {
            continue;
        }
        if single_path_exists(&crate::parser::desentinel(tok), env, &cwd) {
            return true;
        }
    }
    false
}

/// Check if a single path exists using [`Environment`] trait.
/// Expands `~`, `$HOME` and `${HOME}`.
fn single_path_exists(
    file_path: &str,
    env: &dyn Environment,
    cwd: &std::cell::OnceCell<Option<std::path::PathBuf>>,
) -> bool {
    use std::borrow::Cow;

    let trimmed = file_path.trim();
    let home_prefix = ["~", "$HOME", "${HOME}"]
        .into_iter()
        .find(|p| trimmed == *p || trimmed.starts_with(&format!("{p}/")));
    let file_path: Cow<'_, str> = if let Some(prefix) = home_prefix {
        match env.home_dir() {
            Some(home) => Cow::Owned(trimmed.replacen(prefix, &home.display().to_string(), 1)),
            None => return true,
        }
    } else if let Some(user_path) = expand_user_tilde(trimmed) {
        // `~name/…`: that account's home directory.
        Cow::Owned(user_path)
    } else {
        Cow::Borrowed(trimmed)
    };

    // A name made unique when the command runs (`out-$(date +%s).log`,
    // `/tmp/x-$RANDOM`, `$$`, `$(uuidgen)`, `$(mktemp …)`): a new file.
    if [
        "$RANDOM",
        "${RANDOM}",
        "$$",
        "${$}",
        "$(date",
        "`date",
        "$(uuidgen",
        "$(mktemp",
    ]
    .iter()
    .any(|m| file_path.contains(m))
    {
        return false;
    }
    if file_path.contains(['*', '?', '$']) {
        // Globs and unresolved variables: assume they may match something.
        return true;
    }
    if file_path.contains('[') && file_path.contains(']') {
        // A bracket glob: one of the names it can expand to must exist
        // (when there are too many to try, assume it matches something).
        return bracket_candidates(&file_path).is_none_or(|cands| {
            cands
                .iter()
                .any(|c| single_path_exists(c, env, cwd) && !c.contains('['))
        });
    }

    let Some(base) = cwd.get_or_init(|| env.current_dir().ok()) else {
        debug!("could not get current dir");
        return true;
    };
    let full_path = base.join(&*file_path);

    debug!("check if {} path exists", full_path.display());
    env.path_exists(&full_path)
}

/// Return the stricter of two challenges.
pub(crate) fn max_challenge(a: Challenge, b: Challenge) -> Challenge {
    a.stricter(b)
}

/// Merge two vectors of check references, deduplicating by check ID.
/// Primary matches are kept first; secondary matches are appended only if
/// their ID has not been seen yet.
fn dedup_check_matches<'a>(primary: Vec<&'a Check>, secondary: Vec<&'a Check>) -> Vec<&'a Check> {
    let mut seen_ids = std::collections::HashSet::new();
    let mut result = Vec::with_capacity(primary.len() + secondary.len());
    for m in primary.into_iter().chain(secondary) {
        if seen_ids.insert(m.id.as_str()) {
            result.push(m);
        }
    }
    result
}

/// The result of running the core analysis pipeline on a command.
///
/// This is the shared data structure consumed by both the terminal prompter
/// (shell hooks) and the MCP/agent JSON response path.
#[derive(Debug, Clone)]
pub struct PipelineResult {
    /// The original command after quote-stripping.
    pub stripped_command: String,
    /// The subcommand parts after splitting on shell operators.
    pub command_parts: Vec<String>,
    /// Checks that matched and are at or above `min_severity`.
    pub active_matches: Vec<Check>,
    /// Checks that matched but are below `min_severity`.
    pub skipped_matches: Vec<Check>,
    /// The detected runtime context (full — for audit logging).
    pub context: RuntimeContext,
    /// Context filtered to only signals relevant to matched check groups
    /// (for display and challenge escalation).
    pub relevant_context: RuntimeContext,
    /// The highest severity across all matches (active + skipped).
    pub max_severity: Severity,
    /// Whether any matched check is on the deny list.
    pub is_denied: bool,
    /// Safer alternative suggestions collected from matched checks.
    pub alternatives: Vec<AlternativeInfo>,
    /// The merged project policy (if any).
    pub merged_policy: MergedPolicy,
    /// Runtime-computed blast radius for matched checks (`check_id`, info).
    pub blast_radii: Vec<(String, BlastRadiusInfo)>,
    /// The widest blast scope across all computed blast radii.
    pub max_blast_scope: Option<BlastScope>,
    /// Checks that matched the command text but were skipped because the
    /// path they act on does not exist here (`rm -rf /opt/app` on a machine
    /// without `/opt/app`): (check id, path). For `check` to explain why
    /// nothing matched.
    pub skipped_missing_paths: Vec<(String, String)>,
}

/// Longest segment [`missing_path_skips`] looks at.
const MAX_EXPLAINED_SEGMENT: usize = 4096;

/// Checks whose pattern matches a local segment but whose `PathExists`
/// filter dropped it because the path does not exist: (check id, path).
fn missing_path_skips(
    checks: &[Check],
    segments: &[String],
    remote: &[String],
    env: &dyn Environment,
    matched: &[&Check],
) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for seg in segments {
        // Only for an explanation: a huge argument list is not worth a
        // second pass over every operand.
        if seg.len() > MAX_EXPLAINED_SEGMENT
            || remote.binary_search(seg).is_ok()
            || !seg
                .split(' ')
                .next()
                .is_some_and(|p| RESOLVED_PROGRAMS.contains(&p))
        {
            continue;
        }
        for c in match_text_impl(checks, seg, env, true) {
            let Some(group) = c.filters.iter().find_map(|f| match f {
                Filter::PathExists(g) => Some(*g),
                _ => None,
            }) else {
                continue;
            };
            if matched.iter().any(|m| m.id == c.id) || check_filters(c, seg, env, false) {
                continue;
            }
            let captured = c
                .test
                .captures(seg)
                .and_then(|caps| caps.get(group).map(|m| m.as_str().to_string()))
                .unwrap_or_default();
            // One entry per operand (`rm -rf /opt/a /opt/b`), never the
            // internal unknown-target placeholder `{}`.
            let cwd = std::cell::OnceCell::new();
            let mut tokens = captured.split_whitespace();
            while let Some(tok) = tokens.next() {
                if crate::parser::is_redirect_word(tok) {
                    tokens.next();
                    continue;
                }
                if tok.starts_with('-') || tok.contains("{}") {
                    continue;
                }
                let path = crate::parser::desentinel(tok);
                if single_path_exists(&path, env, &cwd)
                    || out.iter().any(|(id, p)| *id == c.id && *p == path)
                {
                    continue;
                }
                out.push((c.id.clone(), path));
            }
        }
    }
    out
}

/// Run the core shellfirm analysis pipeline on a command string.
///
/// This is the shared entry point used by both the `pre-command` CLI path
/// and the MCP server / agent guardrails path. It performs:
/// 1. Strip quoted strings
/// 2. Split on shell operators
/// 3. Pattern matching (parallelized)
/// 4. Context detection
/// 5. Policy discovery & merging
/// 6. Severity filtering
///
/// The caller is responsible for the presentation layer (terminal challenge
/// or structured JSON response).
///
/// # Errors
/// Returns an error if check loading or policy parsing fails.
#[allow(clippy::too_many_lines)]
pub fn analyze_command(
    command: &str,
    settings: &Settings,
    resolved: &ResolvedSettings,
    checks: &[Check],
    env: &dyn Environment,
    strip_quotes_re: &Regex,
) -> Result<PipelineResult> {
    // 1-2. Shell-aware parse + normalize (replaces the old quote-deletion +
    // naive operator split). `strip_quotes_re` is kept for API stability.
    let _ = strip_quotes_re;
    let mut parsed = crate::parser::parse(command);
    // `context.sensitive_paths`: a delete / overwrite under one of them is
    // reported through the `fs:sensitive_path` check (a marker segment, like
    // the nesting-limit marker), even when no other rule matches.
    let sensitive_hits =
        context::sensitive_path_hits(env, &settings.context.sensitive_paths, &parsed);
    for hit in &sensitive_hits {
        parsed
            .segments
            .push(format!("{SENSITIVE_PATH_MARKER} {hit}"));
    }
    // `chown -R dev:dev .` by dev: the owner is spelled `$USER`, so the
    // checks can tell taking ownership of your own files from giving them
    // away.
    spell_own_user(env, &mut parsed.segments);
    // `rm -rf ../x` from a subdirectory of a repository, when `../x` is still
    // inside it: a project path, spelled absolute (not "outside the
    // project").
    spell_parent_paths_in_repo(env, &mut parsed.segments);
    // Bracket globs resolved to what they name (`rm -rf ~/.[s]sh`).
    let glob_segments = glob_resolved_segments(env, &parsed);
    parsed.segments.extend(glob_segments);
    // Relative operands resolved against the real working directory (from
    // `~`, `rm -rf .ssh` is `rm -rf ~/.ssh`).
    let resolved_segments = cwd_resolved_segments(env, &parsed, command);
    parsed.segments.extend(resolved_segments);
    // Paths an earlier segment creates (`ln -s ~ d && rm -rf d/`).
    let created_segments = created_path_segments(env, &parsed);
    parsed.segments.extend(created_segments);
    // 4. Policy discovery (filesystem walk only — no subprocess spawns)
    let cwd = env.current_dir().unwrap_or_default();
    // A command aimed at another repository (`cd ../infra && …`,
    // `git -C ../infra …`, `terraform -chdir=…`) also gets that
    // repository's policy.
    let target_dirs = context::command_target_dirs(command);
    let discovery = policy::discover_for(env, &cwd, &target_dirs);
    policy::warn_policy_problems(&discovery);
    let project_policy = discovery.policy;

    // SQL files run by a client: their statements are read and checked.
    // Without deny lists or policy checks (which a later statement could
    // still hit), the first Critical statement ends the scan.
    let stop_at_critical = settings.deny_patterns_ids.is_empty()
        && project_policy
            .as_ref()
            .is_none_or(|p| p.checks.is_empty() && p.deny.is_empty());
    let sql_files = sql_file_segments(env, &parsed, stop_at_critical.then_some(checks));
    let sql_client = line_sql_client(&parsed);
    parsed.segments.extend(sql_files.segments.iter().cloned());
    // `git push --force-with-lease` to a protected branch still rewrites it.
    if let Some(branch) =
        context::protected_force_with_lease(env, &settings.context, command, &parsed)
    {
        parsed
            .segments
            .push(if branch == context::UNKNOWN_PUSH_TARGET {
                UNKNOWN_TARGET_FORCE_PUSH_MARKER.to_string()
            } else {
                format!("{PROTECTED_FORCE_PUSH_MARKER} {branch}")
            });
    }
    // `rm -rf "$HOME/$UNSET"` deletes `$HOME/` when the variable is empty.
    let empty_var = empty_variable_segments(env, &parsed);
    parsed.segments.extend(empty_var);
    // `mv ~/projects/webapp /tmp/x`: the repository lands where it is
    // cleared on its own.
    for repo in repositories_moved_away(env, &parsed) {
        parsed
            .segments
            .push(format!("{REPOSITORY_DELETE_MARKER} {repo}"));
    }
    // `rm -r <repository root>`: reported through `fs:delete_repository`.
    for repo in deleted_repositories(env, &parsed) {
        parsed
            .segments
            .push(if repo.starts_with(GIT_DIR_DELETE_MARKER) {
                repo
            } else {
                format!("{REPOSITORY_DELETE_MARKER} {repo}")
            });
    }
    let stripped = command.to_string();
    let parsed_for_work = crate::parser::Parsed {
        segments: parsed.segments.clone(),
        remote_segments: parsed.remote_segments.clone(),
        ..crate::parser::Parsed::default()
    };
    // Folders with work git cannot bring back that the line deletes (one
    // `git status`, only when the line deletes a folder).
    let work = if parsed_for_work
        .segments
        .iter()
        .any(|s| !deleted_folder_operands(s).is_empty())
    {
        folders_with_uncommitted_work(env, &parsed_for_work)
    } else {
        WorkFolders::default()
    };
    // `mv DIR /tmp/x` of such a folder: as good as deleted.
    for seg in &parsed_for_work.segments {
        if !seg.starts_with("mv ") {
            continue;
        }
        for op in deleted_folder_operands(seg) {
            if work.dirty.contains(&op) || work.unknown.contains(&op) {
                parsed
                    .segments
                    .push(format!("{WORK_MOVED_AWAY_MARKER} {op}"));
            }
        }
    }
    let command_parts = parsed.segments;
    let remote_parts = parsed.remote_segments;
    let flat = parsed.flat;

    debug!("analyze_command: parts={command_parts:?}");

    // 3. Pattern matching — each normalized segment independently.
    // Many segments (a SQL file's statements): one multi-literal scan per
    // segment instead of one substring search per check and literal.
    let index = (command_parts.len() > LITERAL_INDEX_MIN_SEGMENTS)
        .then(|| LiteralIndex::new(checks))
        .flatten();
    let segment_matches: Vec<&Check> = command_parts
        .iter()
        .flat_map(|c| {
            index.as_ref().map_or_else(
                || match_segment(checks, c, &remote_parts, env),
                |ix| {
                    let is_remote = remote_parts.binary_search_by(|r| r.as_str().cmp(c)).is_ok();
                    ix.matches(c, env, is_remote)
                },
            )
        })
        .collect();

    // Also match against the flat (operator-preserving) form for cross-operator
    // patterns (e.g. "history | bash" where the pipe is normally a split point).
    let matches = if flat.is_empty() {
        segment_matches
    } else {
        let full_matches = match_flat(checks, &flat, env);
        dedup_check_matches(segment_matches, full_matches)
    };

    // Every SQL file the line runs was read and checked: the "not checked
    // here" fallback does not apply.
    let mut matches = matches;
    if sql_files.referenced && sql_files.all_read {
        matches.retain(|c| c.id != "database:sql_from_file");
    }
    debug!("analyze_command: {} matches found", matches.len());

    // Check if policy adds extra checks that might match
    let policy_has_extra_checks = project_policy
        .as_ref()
        .is_some_and(|pp| !pp.checks.is_empty());

    // FAST PATH: no matches and no policy extra checks → skip context detection
    // entirely. This avoids spawning git/kubectl subprocesses for the common case
    // where a command (e.g. "ls", "cd", "cargo build") matches nothing.
    if matches.is_empty() && !policy_has_extra_checks {
        debug!("analyze_command: no matches and no policy checks, skipping context detection");
        let skipped_missing_paths =
            missing_path_skips(checks, &command_parts, &remote_parts, env, &[]);
        return Ok(PipelineResult {
            skipped_missing_paths,
            stripped_command: stripped,
            command_parts,
            active_matches: Vec::new(),
            skipped_matches: Vec::new(),
            context: RuntimeContext::default(),
            relevant_context: RuntimeContext::default(),
            max_severity: Severity::default(),
            is_denied: false,
            alternatives: Vec::new(),
            merged_policy: MergedPolicy::default(),
            blast_radii: Vec::new(),
            max_blast_scope: None,
        });
    }

    // 5. Context detection (only when we have matches or policy extra checks)
    // Each simple command is judged with the context in effect when it runs
    // (switches made earlier in the line apply, later ones do not).
    // A command aimed at another repository also gets the `context:` of
    // that repository's policy (protected branches, production variables,
    // escalation), exactly as when it runs inside it.
    let target_policy_context = (!target_dirs.is_empty())
        .then(|| project_policy.as_ref().and_then(|p| p.context.clone()))
        .flatten();
    let mut context_config = settings.context.clone();
    if let Some(pc) = &target_policy_context {
        let _ = pc.apply_to(&mut context_config);
    }
    let command_contexts = context::command_contexts(env, &context_config, command);
    let runtime_context = command_contexts.full(&context_config);

    // 6. Policy merging (needs git branch from context for branch-specific overrides)
    let mut merged_policy = if let Some(ref pp) = project_policy {
        policy::merge_into_settings(settings, pp, runtime_context.git_branch.as_deref())
    } else {
        MergedPolicy::default()
    };

    // Merge extra checks from project policy
    let mut all_matches: Vec<&Check> = matches;
    if !merged_policy.extra_checks.is_empty() {
        let extra_segment: Vec<&Check> = command_parts
            .iter()
            .flat_map(|c| match_segment(&merged_policy.extra_checks, c, &remote_parts, env))
            .collect();
        let extra = if flat.is_empty() {
            extra_segment
        } else {
            let extra_full = match_flat(&merged_policy.extra_checks, &flat, env);
            dedup_check_matches(extra_segment, extra_full)
        };
        all_matches.extend(extra);
    }

    // 7. Severity filtering (checks enforced by the project policy are never
    //    dropped by the user's personal `min_severity`)
    //    A command that touches a sensitive path keeps every match active.
    // A recursive delete of a folder holding uncommitted or untracked work
    // (git cannot bring it back) is High, so a relaxed `min_severity` still
    // asks.
    let all_matches: Vec<Check> = raise_for_uncommitted_work(&work, &command_parts, all_matches);
    // `git restore README.md` on a file with no changes discards nothing.
    let mut all_matches =
        drop_restores_of_clean_paths(env, &command_parts, &remote_parts, all_matches);
    // The "SQL from a file" hint names the client of this line, and why a
    // file that was found could not be checked.
    for c in &mut all_matches {
        if c.id == "database:sql_from_file" {
            c.description = sql_files.sql_from_file_description(&c.description, sql_client);
        }
    }
    let (active_matches, skipped_matches): (Vec<Check>, Vec<Check>) = if let Some(min_sev) =
        resolved.min_severity
    {
        all_matches.into_iter().partition(|c| {
            c.severity >= min_sev || merged_policy.is_enforced(&c.id) || !sensitive_hits.is_empty()
        })
    } else {
        (all_matches, Vec::new())
    };

    // Compute max severity across all matches
    let max_severity = active_matches
        .iter()
        .chain(skipped_matches.iter())
        .map(|c| c.severity)
        .max()
        .unwrap_or_default();

    // Check deny lists
    let is_denied = active_matches
        .iter()
        .any(|c| settings.deny_patterns_ids.contains(&c.id) || merged_policy.is_denied(&c.id));

    // Collect alternatives, with `<path>` / `<branch>` / ... placeholders
    // filled in from the user's own command where possible.
    let mut alternatives = Vec::new();
    for check in &active_matches {
        if let Some(ref alt) = check.alternative {
            let matching: Vec<&String> = command_parts
                .iter()
                .filter(|s| check.test.is_match(s))
                .collect();
            let is_remote = |s: &&String| remote_parts.binary_search(s).is_ok();
            // A file-system alternative (`trash /data`) would run on this
            // machine, not where a remote / container payload runs.
            if check.from.starts_with("fs")
                && !matching.is_empty()
                && matching.iter().all(is_remote)
            {
                continue;
            }
            let segment = matching
                .iter()
                .find(|s| !is_remote(s))
                .or_else(|| matching.first())
                .map_or(stripped.as_str(), |s| s.as_str());
            let alt = fill_alternative(alt, segment);
            let already_has = alternatives
                .iter()
                .any(|a: &AlternativeInfo| a.suggestion == alt);
            if !already_has {
                alternatives.push(AlternativeInfo {
                    suggestion: alt,
                    explanation: check.alternative_info.clone(),
                });
            }
        }
    }

    // 8. Blast radius computation (only for active matches, when enabled)
    let blast_radii = if settings.blast_radius {
        // `git reset --hard 2>&1`: the redirection is not a git argument
        // (not a commit to reset to, not a push target).
        let unredirected = |segs: &[String]| -> Vec<String> {
            segs.iter()
                .map(|s| {
                    if s.starts_with("git ") || s.starts_with("kubectl ") {
                        crate::parser::without_redirects(s)
                    } else {
                        s.clone()
                    }
                })
                .collect()
        };
        let br_parts = unredirected(&command_parts);
        let mut br_remote = unredirected(&remote_parts);
        br_remote.sort();
        blast_radius::compute_for_matches_remote_aware(
            &active_matches,
            &br_parts,
            &br_remote,
            &stripped,
            env,
        )
    } else {
        Vec::new()
    };
    let mut blast_radii = blast_radii;
    // A statement read from a SQL file: name it and the file (`DROP TABLE
    // users` in mig/x.sql), as `wrap` does.
    if settings.blast_radius && !sql_files.origins.is_empty() {
        for c in &active_matches {
            if blast_radii.iter().any(|(id, _)| *id == c.id) {
                continue;
            }
            let hit = sql_files.origins.iter().find(|(seg, _)| {
                !match_segment(std::slice::from_ref(c), seg, &remote_parts, env).is_empty()
            });
            if let Some((seg, file)) = hit {
                let mut stmt = crate::parser::desentinel(seg).trim().to_string();
                if stmt.chars().count() > 60 {
                    stmt = format!("{}…", stmt.chars().take(59).collect::<String>());
                }
                let stopped = if sql_files.stopped_at_critical && c.severity == Severity::Critical {
                    " (scan stopped at the first Critical statement)"
                } else {
                    ""
                };
                blast_radii.push((
                    c.id.clone(),
                    BlastRadiusInfo {
                        scope: BlastScope::Project,
                        description: format!("`{stmt}` in {file}{stopped}"),
                    },
                ));
            }
        }
    }
    let max_blast_scope = blast_radii.iter().map(|(_, br)| br.scope).max();

    // Compute context filtered to only signals relevant to matched groups
    let matched_groups: std::collections::HashSet<&str> =
        active_matches.iter().map(|c| c.from.as_str()).collect();
    // Per command: the groups of the active checks that match it.
    let groups_of = |text: &str| -> std::collections::HashSet<String> {
        let p = crate::parser::parse(text);
        active_matches
            .iter()
            .filter(|c| {
                p.segments
                    .iter()
                    .any(|s| c.test.is_match(s) && check_filters(c, s, env, true))
            })
            .map(|c| c.from.clone())
            .collect()
    };
    let relevant_context = command_contexts.relevant(&context_config, &groups_of, &matched_groups);
    // The context escalation with the target policy's context applied, as a
    // policy floor (the caller's settings do not know that policy).
    let target_floor = target_policy_context
        .as_ref()
        .and(match relevant_context.risk_level {
            context::RiskLevel::Critical => Some(context_config.escalation.critical),
            context::RiskLevel::Elevated => Some(context_config.escalation.elevated),
            context::RiskLevel::Normal => None,
        });
    if let Some(floor) = target_floor {
        for c in &active_matches {
            let e = merged_policy
                .challenge_overrides
                .entry(c.id.clone())
                .or_insert(floor);
            *e = e.stricter(floor);
        }
    }

    let matched_refs: Vec<&Check> = active_matches.iter().chain(&skipped_matches).collect();
    let skipped_missing_paths =
        missing_path_skips(checks, &command_parts, &remote_parts, env, &matched_refs);
    Ok(PipelineResult {
        skipped_missing_paths,
        stripped_command: stripped,
        command_parts,
        active_matches,
        skipped_matches,
        context: runtime_context,
        relevant_context,
        max_severity,
        is_denied,
        alternatives,
        merged_policy,
        blast_radii,
        max_blast_scope,
    })
}

/// Fill the `<placeholder>`s of an alternative with the command's arguments.
///
/// `git branch -D feature/x` → `git branch -d feature/x`, `rm -rf build` →
/// `trash build`. Placeholders that cannot be derived are kept as they are.
#[must_use]
pub fn fill_alternative(alt: &str, segment: &str) -> String {
    if !alt.contains('<') {
        return alt.to_string();
    }
    // Each word keeps its own whitespace (`rm -rf "my dir"` has the
    // operand `my dir`); operands are shell-quoted when filled in.
    let owned: Vec<String> = segment
        .split_whitespace()
        .map(crate::parser::desentinel)
        .collect();
    let words: Vec<&str> = owned.iter().map(String::as_str).collect();
    let prog = words.first().copied().unwrap_or("");
    let operands: Vec<&str> = words
        .iter()
        .skip(1)
        .take_while(|w| !crate::parser::is_redirect_word(w))
        .filter(|w| !w.starts_with('-'))
        .copied()
        .collect();
    let after = |keys: &[&str]| -> Option<&str> {
        words
            .iter()
            .position(|w| keys.contains(w))
            .and_then(|i| words.get(i + 1))
            .filter(|w| !w.starts_with('-'))
            .copied()
    };
    let path = match prog {
        "rm"
        | "rmdir"
        | "shred"
        | "unlink"
        | "srm"
        | REPOSITORY_DELETE_MARKER
        | GIT_DIR_DELETE_MARKER
        | WORK_MOVED_AWAY_MARKER
            if !operands.is_empty() =>
        {
            Some(
                operands
                    .iter()
                    .map(|o| quote_for_display(o))
                    .collect::<Vec<_>>()
                    .join(" "),
            )
        }
        _ => None,
    };
    let branch = if prog == "git" {
        after(&["-D", "-d", "--delete", "-f", "--force"])
            .or_else(|| operands.iter().skip(1).find(|w| **w != ".").copied())
            .map(str::to_string)
    } else {
        None
    };
    let namespace =
        after(&["ns", "namespace", "namespaces", "-n", "--namespace"]).map(str::to_string);
    let url = words
        .iter()
        .find(|w| w.starts_with("http://") || w.starts_with("https://"))
        .map(|w| (*w).to_string());
    let bucket = words.iter().find_map(|w| {
        w.strip_prefix("s3://")
            .or_else(|| w.strip_prefix("gs://"))
            .map(|b| {
                b.trim_end_matches('/')
                    .split('/')
                    .next()
                    .unwrap_or(b)
                    .to_string()
            })
    });
    let mut out = alt.to_string();
    for (ph, val) in [
        ("<path>", &path),
        ("<file>", &path),
        ("<branch>", &branch),
        ("<namespace>", &namespace),
        ("<url>", &url),
        ("<bucket>", &bucket),
    ] {
        if let Some(v) = val {
            if !v.is_empty() {
                out = out.replace(ph, &crate::context::escape_invisible(v));
            }
        }
    }
    out
}

/// Shell-quote an operand filled into a suggested command when it contains
/// whitespace or quote characters (`trash 'my dir'`).
fn quote_for_display(s: &str) -> String {
    if s.chars()
        .any(|c| c.is_whitespace() || matches!(c, '\'' | '"' | '\\' | ';' | '&' | '|'))
    {
        format!("'{}'", s.replace('\'', "'\\''"))
    } else {
        s.to_string()
    }
}

/// Split a command string into parts by shell operators.
/// Handles `&&`, `||`, `|`, and `;` while respecting single and double quotes.
/// Operators inside quoted strings are not treated as separators.
#[must_use]
pub fn split_command(command: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let bytes = command.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    let mut start = i;
    let mut in_single_quote = false;
    let mut in_double_quote = false;

    while i < len {
        let b = bytes[i];

        // Track quote state (all delimiters are ASCII, safe to scan bytes)
        if b == b'\'' && !in_double_quote {
            in_single_quote = !in_single_quote;
            i += 1;
        } else if b == b'"' && !in_single_quote {
            in_double_quote = !in_double_quote;
            i += 1;
        } else if !in_single_quote && !in_double_quote {
            // Check for two-character operators first
            let (is_split, advance) = if i + 1 < len
                && ((b == b'&' && bytes[i + 1] == b'&') || (b == b'|' && bytes[i + 1] == b'|'))
            {
                (true, 2)
            } else if b == b'|' || b == b';' {
                (true, 1)
            } else {
                (false, 1)
            };

            if is_split {
                parts.push(command[start..i].to_string());
                i += advance;
                start = i;
            } else {
                i += 1;
            }
        } else {
            // Inside quotes — pass through without splitting
            i += 1;
        }
    }
    if start < len {
        parts.push(command[start..].to_string());
    }
    parts
}

/// The check test files (`tests/checks/*.yaml`) with their text, for the
/// library's own tests. Hidden files (editor locks, macOS `._*` metadata on
/// exFAT / SMB volumes) are skipped, as `tests/checks.rs` skips them; a file
/// that cannot be read names itself in the panic.
#[cfg(test)]
pub(crate) fn fixture_files() -> Vec<(std::path::PathBuf, String)> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir("tests/checks").expect("tests/checks") {
        let path = entry.expect("tests/checks entry").path();
        let hidden = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_none_or(|n| n.starts_with('.'));
        if hidden || !path.extension().is_some_and(|e| e == "yaml") {
            continue;
        }
        let text =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        out.push((path, text));
    }
    out.sort();
    out
}

#[cfg(test)]
mod test_checks {
    use insta::{assert_debug_snapshot, with_settings};

    use super::*;

    #[test]
    fn challenge_with_context_uses_resolved_settings_for_shell() {
        use crate::config::{InheritOr, Mode, Settings};
        let mut settings = Settings::default();
        settings.challenge = Challenge::Math;
        settings.agent.challenge = InheritOr::Set(Challenge::Yes); // would NOT apply in shell mode
        let resolved = settings.resolved_for(Mode::Shell);
        assert_eq!(resolved.challenge, Challenge::Math);
    }

    const CHECKS: &str = r###"
- from: test-1
  test: test-(1)
  enable: true
  description: ""
  id: ""
- from: test-2
  test: test-(1|2)
  enable: true
  description: ""
  id: ""
- from: test-disabled
  test: test-disabled
  enable: true
  description: ""
  id: ""
"###;

    #[test]
    fn can_run_check_on_command() {
        let checks: Vec<Check> = serde_yaml::from_str(CHECKS).unwrap();
        with_settings!({filters => vec![
            // Normalize Regex debug format across insta/regex crate versions
            (r#"(?s)test:\s*Regex\(\s*"([^"]+)",?\s*\)"#, "test: $1"),
        ]}, {
            assert_debug_snapshot!(run_check_on_command(&checks, "test-1"));
            assert_debug_snapshot!(run_check_on_command(&checks, "unknown command"));
        });
    }

    #[test]
    fn can_check_custom_filter_with_file_exists() {
        use std::collections::HashSet;
        let filters = vec![Filter::PathExists(1)];

        let check = Check {
            id: "id".to_string(),
            test: Regex::new("(?:^|[^>])>([^>].*)").unwrap().into(),
            description: "some description".to_string(),
            from: "test".to_string(),
            challenge: Challenge::default(),
            filters,
            alternative: None,
            alternative_info: None,
            severity: Severity::default(),
        };

        // Use mock environment: file does NOT exist
        let env_no_file = crate::env::MockEnvironment {
            cwd: "/mock".into(),
            ..Default::default()
        };
        let command = "cat 'write message' > /mock/app/message.txt";
        assert_debug_snapshot!(check_custom_filter_with_env(&check, command, &env_no_file));

        // Use mock environment: file DOES exist
        let mut existing = HashSet::new();
        existing.insert(std::path::PathBuf::from("/mock/app/message.txt"));
        let env_with_file = crate::env::MockEnvironment {
            cwd: "/mock".into(),
            existing_paths: existing,
            ..Default::default()
        };
        assert_debug_snapshot!(check_custom_filter_with_env(
            &check,
            command,
            &env_with_file
        ));
    }

    #[test]
    fn can_check_custom_filter_with_str_contains() {
        let filters = vec![Filter::NotContains("--dry-run".to_string())];

        let check = Check {
            id: "id".to_string(),
            test: Regex::new("(delete)").unwrap().into(),
            description: "some description".to_string(),
            from: "test".to_string(),
            challenge: Challenge::default(),
            filters,
            alternative: None,
            alternative_info: None,
            severity: Severity::default(),
        };

        let env = crate::env::MockEnvironment::default();
        assert_debug_snapshot!(check_custom_filter_with_env(&check, "delete", &env));
        assert_debug_snapshot!(check_custom_filter_with_env(
            &check,
            "delete --dry-run",
            &env
        ));
    }

    #[test]
    fn can_check_custom_filter_with_contains() {
        let filters = vec![Filter::Contains("--force".to_string())];

        let check = Check {
            id: "id".to_string(),
            test: Regex::new("(push)").unwrap().into(),
            description: "some description".to_string(),
            from: "test".to_string(),
            challenge: Challenge::default(),
            filters,
            alternative: None,
            alternative_info: None,
            severity: Severity::default(),
        };

        let env = crate::env::MockEnvironment::default();
        // Without --force the filter suppresses the check
        assert!(!check_custom_filter_with_env(
            &check,
            "git push origin main",
            &env
        ));
        // With --force the filter keeps the check
        assert!(check_custom_filter_with_env(
            &check,
            "git push --force origin main",
            &env
        ));
    }

    #[test]
    fn can_check_custom_filter_with_missing_capture_group() {
        // PathExists references group 5, but regex only has 1 group
        let filters = vec![Filter::PathExists(5)];

        let check = Check {
            id: "test-missing-group".to_string(),
            test: Regex::new("rm (.*)").unwrap().into(),
            description: "some description".to_string(),
            from: "test".to_string(),
            challenge: Challenge::default(),
            filters,
            alternative: None,
            alternative_info: None,
            severity: Severity::default(),
        };

        let env = crate::env::MockEnvironment::default();
        // Should return false (suppress check) because group 5 doesn't exist
        assert!(!check_custom_filter_with_env(&check, "rm /tmp/foo", &env));
    }

    #[test]
    fn can_check_multiple_filters_all_must_pass() {
        let filters = vec![
            Filter::NotContains("--dry-run".to_string()),
            Filter::NotContains("--check".to_string()),
        ];

        let check = Check {
            id: "id".to_string(),
            test: Regex::new("(delete)").unwrap().into(),
            description: "some description".to_string(),
            from: "test".to_string(),
            challenge: Challenge::default(),
            filters,
            alternative: None,
            alternative_info: None,
            severity: Severity::default(),
        };

        let env = crate::env::MockEnvironment::default();
        // Both absent → check fires
        assert!(check_custom_filter_with_env(&check, "delete", &env));
        // --dry-run present → suppressed
        assert!(!check_custom_filter_with_env(
            &check,
            "delete --dry-run",
            &env
        ));
        // --check present → suppressed
        assert!(!check_custom_filter_with_env(
            &check,
            "delete --check",
            &env
        ));
        // Both present → suppressed
        assert!(!check_custom_filter_with_env(
            &check,
            "delete --dry-run --check",
            &env
        ));
    }

    #[test]
    fn can_get_all_checks() {
        assert_debug_snapshot!(get_all().is_ok());
    }

    #[test]
    fn test_split_command_and_and() {
        let parts = split_command("ls && rm -rf /");
        assert_eq!(parts, vec!["ls ", " rm -rf /"]);
    }

    #[test]
    fn test_split_command_pipe() {
        let parts = split_command("cat foo | grep bar");
        assert_eq!(parts, vec!["cat foo ", " grep bar"]);
    }

    #[test]
    fn test_split_command_mixed() {
        let parts = split_command("a && b || c; d");
        assert_eq!(parts, vec!["a ", " b ", " c", " d"]);
    }

    #[test]
    fn test_split_command_single() {
        let parts = split_command("git push -f");
        assert_eq!(parts, vec!["git push -f"]);
    }

    #[test]
    fn test_split_command_double_quoted_operator() {
        // Operators inside double quotes should NOT cause a split
        let parts = split_command(r#"echo "hello && world""#);
        assert_eq!(parts, vec![r#"echo "hello && world""#]);
    }

    #[test]
    fn test_split_command_single_quoted_pipe() {
        // Pipe inside single quotes should NOT cause a split
        let parts = split_command("echo 'a | b'");
        assert_eq!(parts, vec!["echo 'a | b'"]);
    }

    #[test]
    fn test_split_command_quoted_then_operator() {
        // Quoted section followed by a real operator
        let parts = split_command(r#"echo "safe" && rm -rf /"#);
        assert_eq!(parts, vec![r#"echo "safe" "#, " rm -rf /"]);
    }

    #[test]
    fn test_all_builtin_checks_pass_validation() {
        let checks = get_all().unwrap();
        let warnings = validate_checks(&checks);
        assert!(
            warnings.is_empty(),
            "Built-in checks have validation warnings:\n{}",
            warnings.join("\n")
        );
    }

    #[test]
    fn test_fill_alternative() {
        assert_eq!(
            fill_alternative("trash <path>", "rm -rf build dist"),
            "trash build dist"
        );
        assert_eq!(
            fill_alternative("git branch -d <branch>", "git branch -D feature/login"),
            "git branch -d feature/login"
        );
        assert_eq!(
            fill_alternative(
                "kubectl get all -n <namespace>",
                "kubectl delete ns payments"
            ),
            "kubectl get all -n payments"
        );
        assert_eq!(
            fill_alternative(
                "aws s3 ls s3://<bucket>",
                "aws s3 rb s3://my-bucket --force"
            ),
            "aws s3 ls s3://my-bucket"
        );
        // A path with spaces stays one operand and is quoted.
        assert_eq!(
            fill_alternative("trash <path>", "rm -rf my\u{1}dir other"),
            "trash 'my dir' other"
        );
        // Unknown placeholders stay.
        assert_eq!(fill_alternative("kill <pid>", "kill -9 123"), "kill <pid>");
        assert_eq!(fill_alternative("no placeholder", "rm x"), "no placeholder");
    }

    fn check_with(id: &str, sev: Severity) -> Check {
        Check {
            id: id.to_string(),
            test: Regex::new("x").unwrap().into(),
            description: String::new(),
            from: "fs".to_string(),
            challenge: Challenge::default(),
            filters: vec![],
            alternative: None,
            alternative_info: None,
            severity: sev,
        }
    }

    #[test]
    fn test_ignore_hint_rules() {
        let ctx = RuntimeContext::default();
        let a = check_with("fs:recursively_delete_outside", Severity::High);
        let b = check_with("fs-strict:recursive_deletion", Severity::Medium);
        let hint = ignore_hint(&[&b, &a], &ctx, false).unwrap();
        // Usable command for every id, specific one first, broad one noted.
        assert!(
            hint.contains("`shellfirm config ignore fs:recursively_delete_outside && shellfirm config ignore fs-strict:recursive_deletion`"),
            "{hint}"
        );
        assert!(hint.contains("broad catch-all"), "{hint}");
        assert!(!hint.contains("<check-id>"));
        // Never on Critical, denied, root or a Critical context.
        let c = check_with("fs:recursively_delete", Severity::Critical);
        assert!(ignore_hint(&[&c], &ctx, false).is_none());
        assert!(ignore_hint(&[&a], &ctx, true).is_none());
        let root = RuntimeContext {
            is_root: true,
            ..Default::default()
        };
        assert!(ignore_hint(&[&a], &root, false).is_none());
        let prod = RuntimeContext {
            risk_level: context::RiskLevel::Critical,
            ..Default::default()
        };
        assert!(ignore_hint(&[&a], &prod, false).is_none());
    }

    #[test]
    fn test_sensitive_path_and_repository_markers() {
        let mut settings = Settings::default();
        settings.context.sensitive_paths = vec!["~/.ssh".into()];
        let resolved = settings.resolved_for(crate::config::Mode::Shell);
        let checks = get_all().unwrap();
        let mut env = crate::env::MockEnvironment {
            cwd: "/home/dev/projects".into(),
            home: Some("/home/dev".into()),
            ..Default::default()
        };
        env.files.insert(
            "/home/dev/projects/webapp/.git/HEAD".into(),
            "ref: refs/heads/main".into(),
        );
        let re = Regex::new("x").unwrap();
        // A copy into a sensitive path matches nothing else but is reported.
        let p = analyze_command(
            "cp evil ~/.ssh/authorized_keys",
            &settings,
            &resolved,
            &checks,
            &env,
            &re,
        )
        .unwrap();
        let ids: Vec<&str> = p.active_matches.iter().map(|c| c.id.as_str()).collect();
        assert!(ids.contains(&"fs:sensitive_path"), "{ids:?}");
        assert_eq!(p.context.risk_level, context::RiskLevel::Critical);
        // Deleting a repository root (any spelling) is reported.
        let p = analyze_command("rm -rf webapp", &settings, &resolved, &checks, &env, &re).unwrap();
        let ids: Vec<&str> = p.active_matches.iter().map(|c| c.id.as_str()).collect();
        assert!(ids.contains(&"fs:delete_repository"), "{ids:?}");
        assert!(
            p.alternatives
                .iter()
                .any(|a| a.suggestion == "trash webapp"),
            "{:?}",
            p.alternatives
        );
        let p = analyze_command(
            "rm -rf webapp/src",
            &settings,
            &resolved,
            &checks,
            &env,
            &re,
        )
        .unwrap();
        assert!(!p
            .active_matches
            .iter()
            .any(|c| c.id == "fs:delete_repository"));
    }

    #[test]
    fn test_validate_catches_bad_capture_group() {
        let checks = vec![Check {
            id: "bad".to_string(),
            test: Regex::new("rm (.*)").unwrap().into(),
            description: "test".to_string(),
            from: "test".to_string(),
            challenge: Challenge::default(),
            filters: vec![Filter::PathExists(5)], // only 2 groups (0 + 1)
            alternative: None,
            alternative_info: None,
            severity: Severity::default(),
        }];
        let warnings = validate_checks(&checks);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("PathExists(5)"));
    }

    /// The static table generated by build.rs is exactly what deserializing
    /// the concatenated YAML gives (every field, in order).
    #[test]
    fn builtin_table_matches_yaml() {
        let from_yaml: Vec<Check> = serde_yaml::from_str(ALL_CHECKS).unwrap();
        let from_table = all_checks_cached();
        assert_eq!(from_yaml.len(), from_table.len());
        for (a, b) in from_yaml.iter().zip(from_table) {
            assert_eq!(format!("{a:?}"), format!("{b:?}"));
            assert_eq!(
                serde_yaml::to_string(a).unwrap(),
                serde_yaml::to_string(b).unwrap()
            );
        }
    }

    /// Every built-in check has a prefilter.
    #[test]
    fn builtin_checks_have_prefilters() {
        let all = all_checks_cached();
        let without: Vec<&str> = all
            .iter()
            .filter(|c| c.test.0.prefilter.is_none())
            .map(|c| c.id.as_str())
            .collect();
        assert!(
            without.is_empty(),
            "checks without a prefilter: {without:?}"
        );
    }

    /// The literal prefilter never changes a result: over every command of
    /// the check test corpus (and case / Unicode variants of it), each parsed
    /// segment and flat form gives the same answer with and without it.
    #[test]
    fn prefilter_never_changes_a_match() {
        #[derive(Deserialize)]
        struct Case {
            test: String,
        }
        let mut commands: Vec<String> = Vec::new();
        for (path, text) in fixture_files() {
            let cases: Vec<Case> =
                serde_yaml::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            commands.extend(cases.into_iter().map(|c| c.test));
        }
        assert!(commands.len() > 500, "corpus too small: {}", commands.len());
        let variants: Vec<String> = commands
            .iter()
            .flat_map(|c| {
                [
                    c.clone(),
                    c.to_uppercase(),
                    c.replace('k', "\u{212A}").replace('s', "\u{17F}"),
                    c.replace(' ', "\u{a0}"),
                ]
            })
            .collect();
        let all = all_checks_cached();
        let mut matched = 0usize;
        for cmd in &variants {
            let parsed = crate::parser::parse(cmd);
            let mut texts = parsed.segments.clone();
            texts.push(parsed.flat.clone());
            texts.push(cmd.clone());
            for text in &texts {
                let folded = crate::prefilter::fold(text);
                for c in all {
                    let full = c.test.regex().is_match(text);
                    matched += usize::from(full);
                    assert_eq!(
                        c.test.is_match_prefiltered(text, &folded),
                        full,
                        "check {} on {text:?}",
                        c.id
                    );
                }
            }
        }
        assert!(matched > 500);
    }

    #[test]
    fn check_regex_behaves_like_regex() {
        let lazy = CheckRegex::lazy("(?i)DROP\\s+(table)".to_string(), Some(&["drop"]));
        assert_eq!(lazy.as_str(), "(?i)DROP\\s+(table)");
        assert!(lazy.0.compiled.get().is_none(), "as_str must not compile");
        assert!(!lazy.is_match_prefiltered("ls", "ls"));
        assert!(
            lazy.0.compiled.get().is_none(),
            "a prefilter miss must not compile"
        );
        assert!(lazy.is_match_prefiltered("Drop  TABLE", "drop  table"));
        assert_eq!(lazy.captures_len(), 2);
        let clone = lazy.clone();
        assert!(
            clone.0.compiled.get().is_some(),
            "clones share the compiled regex"
        );
        assert_eq!(
            format!("{lazy:?}"),
            format!("{:?}", Regex::new(lazy.as_str()).unwrap())
        );
        assert_eq!(
            serde_yaml::to_string(&lazy).unwrap(),
            serde_yaml::to_string(lazy.as_str()).unwrap()
        );

        let err = serde_yaml::from_str::<CheckRegex>("\"(unclosed\"").unwrap_err();
        let want = serde_yaml::from_str::<Wrapped>("\"(unclosed\"").unwrap_err();
        assert_eq!(err.to_string(), want.to_string());

        #[derive(Debug, Deserialize)]
        struct Wrapped(
            #[serde(with = "serde_regex")]
            #[allow(dead_code)]
            Regex,
        );
    }
}

#[cfg(test)]
mod test_uncommitted_work {
    use super::*;

    #[test]
    fn deleted_folder_operands_cover_every_spelling() {
        assert_eq!(deleted_folder_operands("rm -rf docs"), vec!["docs"]);
        assert_eq!(deleted_folder_operands("rm -rf docs/*"), vec!["docs"]);
        assert_eq!(deleted_folder_operands("rm -rf docs/."), vec!["docs"]);
        assert_eq!(deleted_folder_operands("rm -r a b"), vec!["a", "b"]);
        assert!(deleted_folder_operands("rm -f docs").is_empty());
        assert!(deleted_folder_operands("rm -rf docs/*.log").is_empty());
        assert_eq!(deleted_folder_operands("find docs -delete"), vec!["docs"]);
        assert_eq!(
            deleted_folder_operands("find docs -mindepth 1 -delete"),
            vec!["docs"]
        );
        // Only some files: not the folder's work.
        assert!(deleted_folder_operands("find docs -name *.pyc -delete").is_empty());
        assert!(deleted_folder_operands("find docs -type f").is_empty());
        assert_eq!(deleted_folder_operands("mv docs /tmp/old"), vec!["docs"]);
        assert_eq!(
            deleted_folder_operands("mv -f a b /var/tmp/"),
            vec!["a", "b"]
        );
        assert!(deleted_folder_operands("mv docs docs-old").is_empty());
    }

    fn analyze(cmd: &str, env: &crate::env::MockEnvironment) -> Vec<(String, Severity, String)> {
        let mut settings = Settings::default();
        settings.min_severity = Some(Severity::High);
        let resolved = settings.resolved_for(crate::config::Mode::Shell);
        let checks = get_all().unwrap();
        let re = Regex::new("x").unwrap();
        let p = analyze_command(cmd, &settings, &resolved, &checks, env, &re).unwrap();
        p.active_matches
            .iter()
            .map(|c| (c.id.clone(), c.severity, c.description.clone()))
            .collect()
    }

    #[test]
    fn dirty_or_unchecked_folders_stay_high_in_every_spelling() {
        let tree = tree_fs::TreeBuilder::default().create().unwrap();
        let root = tree.root.clone();
        for d in ["docs", "src", "lib", "日本"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
            std::fs::write(root.join(d).join("f.txt"), "x").unwrap();
        }
        let r = root.display().to_string();
        let mut env = crate::env::MockEnvironment {
            cwd: root.clone(),
            home: Some("/home/nobody".into()),
            ..Default::default()
        };
        env.files
            .insert(root.join(".git/HEAD"), "ref: refs/heads/main".into());
        for d in ["docs", "src", "lib", "日本"] {
            env.existing_paths.insert(root.join(d));
        }
        let status =
            |p: &str| format!("git -C {r} status --porcelain --untracked-files=normal -- {p}");
        env.command_outputs
            .insert(status("docs"), "?? docs/".into());
        env.command_outputs.insert(status("lib"), String::new());
        // git quotes a non-ASCII path with octal escapes.
        env.command_outputs
            .insert(status("日本"), r#"?? "\346\227\245\346\234\254/""#.into());
        env.timed_out_commands.insert(status("src"));

        for cmd in [
            "rm -rf docs",
            "rm -rf docs/*",
            "cd docs && rm -rf *",
            "find docs -delete",
            "mv docs /tmp/docs-old",
            "rm -rf 日本",
        ] {
            let m = analyze(cmd, &env);
            assert!(
                m.iter().any(|(_, s, d)| *s == Severity::High
                    && d.contains("uncommitted or untracked files")),
                "{cmd}: {m:?}"
            );
        }
        // The probe did not finish: fail safe, and say so.
        let m = analyze("rm -rf src", &env);
        assert!(
            m.iter().any(|(_, s, d)| *s == Severity::High
                && d.contains("could not check for uncommitted files in time")),
            "{m:?}"
        );
        // A clean folder stays below High (skipped under min_severity High).
        let m = analyze("rm -rf lib", &env);
        assert!(m.is_empty(), "{m:?}");
    }

    #[test]
    fn git_quoted_paths_are_unquoted() {
        assert_eq!(unquote_git_path("docs/"), "docs/");
        assert_eq!(unquote_git_path(r#""\346\227\245\346\234\254/""#), "日本/");
        assert_eq!(unquote_git_path(r#""a\"b\\c\td""#), "a\"b\\c\td");
    }

    #[test]
    fn restoring_a_path_without_changes_is_not_asked() {
        assert_eq!(
            restored_paths("git restore src/a.js"),
            Some(vec!["src/a.js".to_string()])
        );
        assert_eq!(
            restored_paths("git checkout -- a b"),
            Some(vec!["a".to_string(), "b".to_string()])
        );
        // From another commit: a clean file changes too.
        assert!(restored_paths("git restore --source=HEAD~5 a").is_none());
        assert!(restored_paths("git restore -s HEAD~1 a").is_none());
        assert!(restored_paths("git checkout main -- a").is_none());
        assert!(restored_paths("git restore .").is_none());

        let mut env = crate::env::MockEnvironment {
            cwd: "/repo".into(),
            ..Default::default()
        };
        env.command_outputs.insert(
            "git status --porcelain --untracked-files=no -- clean.js".into(),
            String::new(),
        );
        env.command_outputs.insert(
            "git status --porcelain --untracked-files=no -- dirty.js".into(),
            " M dirty.js".into(),
        );
        let ids = |cmd: &str| -> Vec<String> {
            let settings = Settings::default();
            let resolved = settings.resolved_for(crate::config::Mode::Shell);
            let checks = get_all().unwrap();
            let re = Regex::new("x").unwrap();
            analyze_command(cmd, &settings, &resolved, &checks, &env, &re)
                .unwrap()
                .active_matches
                .iter()
                .map(|c| c.id.clone())
                .collect()
        };
        assert!(ids("git restore clean.js").is_empty());
        assert!(ids("git restore dirty.js").contains(&"git:restore_discard_path".to_string()));
        // git did not answer: still asked.
        assert!(ids("git restore unknown.js").contains(&"git:restore_discard_path".to_string()));
    }
}
