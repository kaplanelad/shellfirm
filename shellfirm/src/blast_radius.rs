//! Blast radius — runtime impact computation for matched checks.
//!
//! Severity tells users **how dangerous** a command is, but not **how wide the
//! damage spreads**. This module computes real metrics at runtime (file counts,
//! sizes, commit counts) so users see concrete impact before confirming.
//!
//! # Design principle: graceful degradation
//!
//! Blast radius must **never** interfere with the core safety flow. Every
//! computation returns `Option` — on any failure (timeout, missing command,
//! permission error, unexpected output) the result is `None`, and the user
//! simply sees the challenge prompt without the extra line.

use regex::Regex;
use serde_derive::{Deserialize, Serialize};
use tracing::debug;

use crate::env::Environment;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// The scope of potential damage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BlastScope {
    /// Single file, branch, container.
    Resource,
    /// Repository, database, application.
    Project,
    /// Kubernetes namespace, resource group.
    Namespace,
    /// Entire local host.
    Machine,
}

impl std::fmt::Display for BlastScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Resource => write!(f, "RESOURCE"),
            Self::Project => write!(f, "PROJECT"),
            Self::Namespace => write!(f, "NAMESPACE"),
            Self::Machine => write!(f, "MACHINE"),
        }
    }
}

/// Runtime-computed blast radius for a matched check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastRadiusInfo {
    pub scope: BlastScope,
    /// Human-readable impact description, e.g. "Deletes 347 files (12.4 MB) in ./src".
    pub description: String,
}

/// Timeout (ms) for each blast-radius subprocess.
///
/// Set to 3 seconds because:
/// - The user is already stopped at an interactive challenge prompt
/// - `find` on directories with many files (e.g. `node_modules`) needs time
/// - Most operations (git, du, test) complete in <100ms regardless
const TIMEOUT_MS: u64 = 3000;

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// Compute blast radius for a single matched check.
///
/// Returns `None` for checks that don't support blast radius or when
/// computation fails for any reason (timeout, missing command, etc.).
#[must_use]
pub fn compute(
    check_id: &str,
    check_regex: &Regex,
    command: &str,
    env: &dyn Environment,
) -> Option<BlastRadiusInfo> {
    let result = match check_id {
        // fs group
        "fs:recursively_delete" => compute_fs_recursive_delete(check_regex, command, env),
        "fs:move_to_dev_null" => compute_fs_move_to_dev_null(check_regex, command, env),
        "fs:flush_file_content" => compute_fs_flush_file(check_regex, command, env),
        "fs:recursively_chmod" => compute_fs_recursive_chmod(check_regex, command, env),
        "fs:delete_find_files" => compute_fs_delete_find(command, env),
        "fs-strict:any_deletion" => compute_fs_strict_any_deletion(check_regex, command, env),
        "fs-strict:folder_deletion" => compute_fs_strict_folder_deletion(check_regex, command, env),
        "fs-strict:change_permissions" => compute_fs_strict_change_permissions(command, env),
        // git group
        "git:reset" => compute_git_reset(env),
        "git:delete_all" => compute_git_delete_all(env),
        "git:clean_force" => compute_git_clean_force(env),
        "git:force_push" => compute_git_force_push(command, env),
        "git:force_delete_branch" => compute_git_force_delete_branch(command),
        "git:force_checkout" => compute_git_force_checkout(env),
        "git:filter_branch" => compute_git_filter_branch(env),
        "git-strict:add_all" => compute_git_strict_add_all(env),
        "git-strict:commit_all" => compute_git_strict_commit_all(env),
        // docker group
        "docker:system_prune_all" => compute_docker_system_prune(env),
        "docker:force_remove_all_containers" => compute_docker_force_remove_containers(env),
        "docker:volume_prune" => compute_docker_volume_prune(env),
        "docker:stop_all_containers" => compute_docker_stop_all(env),
        // kubernetes group
        "kubernetes:delete_namespace" => {
            compute_kubernetes_delete_namespace(check_regex, command, env)
        }
        _ => None,
    };

    if result.is_none() {
        debug!("blast_radius: no result for check {check_id}");
    }
    result
}

/// Compute blast radius for all matched checks in a pipeline.
///
/// Returns a vec of `(check_id, BlastRadiusInfo)` pairs for checks that have
/// computable blast radius. Checks without blast radius are silently skipped.
#[must_use]
pub fn compute_for_matches(
    checks: &[crate::checks::Check],
    command_parts: &[String],
    stripped_command: &str,
    env: &dyn Environment,
) -> Vec<(String, BlastRadiusInfo)> {
    checks
        .iter()
        .filter_map(|c| {
            let segment = command_parts
                .iter()
                .find(|seg| c.test.is_match(seg))
                .map_or(stripped_command, String::as_str);
            compute(&c.id, &c.test, segment, env).map(|br| (c.id.clone(), br))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse human-readable size from `du -sh` output (e.g. "12M\t/path" → "12M").
fn parse_du_output(output: &str) -> Option<String> {
    let first_line = output.lines().next()?;
    let size = first_line.split_whitespace().next()?;
    if size.is_empty() {
        return None;
    }
    Some(size.to_string())
}

/// Count non-empty lines in command output.
fn count_lines(output: &str) -> usize {
    output.lines().filter(|l| !l.trim().is_empty()).count()
}

/// Format a count with a noun, e.g. `format_count(1, "file")` → `"1 file"`,
/// `format_count(5629, "file")` → `"5,629 files"`.
fn format_count(n: usize, noun: &str) -> String {
    let num = format_number(n);
    if n == 1 {
        format!("{num} {noun}")
    } else {
        format!("{num} {noun}s")
    }
}

/// Format a number with comma separators, e.g. `1234567` → `"1,234,567"`.
fn format_number(n: usize) -> String {
    let s = n.to_string();
    let mut result = String::with_capacity(s.len() + s.len() / 3);
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            result.push(',');
        }
        result.push(ch);
    }
    result
}

/// Extract capture group 1 from regex match on command.
fn capture_group(regex: &Regex, command: &str, group: usize) -> Option<String> {
    let caps = regex.captures(command)?;
    let m = caps.get(group)?;
    let val = m.as_str().trim();
    if val.is_empty() {
        return None;
    }
    Some(val.to_string())
}

/// Determine blast scope for a filesystem path.
fn fs_scope_for_path(path: &str) -> BlastScope {
    if path == "/" || path == "/*" {
        BlastScope::Machine
    } else {
        BlastScope::Project
    }
}

/// Count files under a path using `find`.
fn count_files_at(env: &dyn Environment, path: &str) -> Option<usize> {
    let output = env.run_command("find", &[path, "-type", "f"], TIMEOUT_MS)?;
    Some(count_lines(&output))
}

/// Get human-readable size of a path using `du -sh`.
fn get_size(env: &dyn Environment, path: &str) -> Option<String> {
    let output = env.run_command("du", &["-sh", path], TIMEOUT_MS)?;
    parse_du_output(&output)
}

/// Check if a path is a directory.
fn is_directory(env: &dyn Environment, path: &str) -> bool {
    env.run_command("test", &["-d", path], TIMEOUT_MS).is_some()
}

// ---------------------------------------------------------------------------
// fs group computations
// ---------------------------------------------------------------------------

fn compute_fs_recursive_delete(
    regex: &Regex,
    command: &str,
    env: &dyn Environment,
) -> Option<BlastRadiusInfo> {
    let path = capture_group(regex, command, 1)?;
    let scope = fs_scope_for_path(&path);
    let file_count = count_files_at(env, &path);
    let size = get_size(env, &path);

    let description = match (file_count, size) {
        (Some(count), Some(sz)) => {
            format!("Deletes ~{} ({sz}) in {path}", format_count(count, "file"))
        }
        (Some(count), None) => format!("Deletes ~{} in {path}", format_count(count, "file")),
        (None, Some(sz)) => format!("Deletes ({sz}) in {path}"),
        (None, None) => return None,
    };

    Some(BlastRadiusInfo { scope, description })
}

fn compute_fs_move_to_dev_null(
    regex: &Regex,
    command: &str,
    env: &dyn Environment,
) -> Option<BlastRadiusInfo> {
    let path = capture_group(regex, command, 1)?;
    let size = get_size(env, &path);
    Some(BlastRadiusInfo {
        scope: BlastScope::Resource,
        description: size.map_or_else(
            || "Destroys file".to_string(),
            |sz| format!("Destroys file ({sz})"),
        ),
    })
}

fn compute_fs_flush_file(
    regex: &Regex,
    command: &str,
    env: &dyn Environment,
) -> Option<BlastRadiusInfo> {
    let path = capture_group(regex, command, 1)?;
    let size = get_size(env, path.trim());
    Some(BlastRadiusInfo {
        scope: BlastScope::Resource,
        description: size.map_or_else(
            || "Flushes 1 file".to_string(),
            |sz| format!("Flushes 1 file ({sz})"),
        ),
    })
}

fn compute_fs_recursive_chmod(
    regex: &Regex,
    command: &str,
    env: &dyn Environment,
) -> Option<BlastRadiusInfo> {
    let path = capture_group(regex, command, 2)?;
    let scope = fs_scope_for_path(&path);
    let file_count = count_files_at(env, &path)?;
    Some(BlastRadiusInfo {
        scope,
        description: format!(
            "Affects permissions on ~{}",
            format_count(file_count, "file")
        ),
    })
}

fn compute_fs_delete_find(command: &str, env: &dyn Environment) -> Option<BlastRadiusInfo> {
    // Parse the first non-flag argument after `find`
    let parts: Vec<&str> = command.split_whitespace().collect();
    let find_idx = parts.iter().position(|p| *p == "find")?;
    let search_path = parts
        .get(find_idx + 1)
        .filter(|p| !p.starts_with('-'))
        .copied()
        .unwrap_or(".");
    let file_count = count_files_at(env, search_path)?;
    Some(BlastRadiusInfo {
        scope: BlastScope::Project,
        description: format!(
            "Deletes ~{} under {search_path}",
            format_count(file_count, "file")
        ),
    })
}

fn compute_fs_strict_any_deletion(
    regex: &Regex,
    command: &str,
    env: &dyn Environment,
) -> Option<BlastRadiusInfo> {
    let path = capture_group(regex, command, 1)?;
    let path = path.trim();
    if path.is_empty() {
        return None;
    }
    let size = get_size(env, path);
    if is_directory(env, path) {
        let file_count = count_files_at(env, path);
        let desc = match (file_count, &size) {
            (Some(count), Some(sz)) => {
                format!(
                    "Deletes directory with ~{} ({sz})",
                    format_count(count, "file")
                )
            }
            (Some(count), None) => {
                format!("Deletes directory with ~{}", format_count(count, "file"))
            }
            (None, Some(sz)) => format!("Deletes directory ({sz})"),
            (None, None) => return None,
        };
        Some(BlastRadiusInfo {
            scope: BlastScope::Resource,
            description: desc,
        })
    } else {
        Some(BlastRadiusInfo {
            scope: BlastScope::Resource,
            description: size.map_or_else(
                || "Deletes file".to_string(),
                |sz| format!("Deletes file ({sz})"),
            ),
        })
    }
}

fn compute_fs_strict_folder_deletion(
    regex: &Regex,
    command: &str,
    env: &dyn Environment,
) -> Option<BlastRadiusInfo> {
    let path = capture_group(regex, command, 1)?;
    let path = path.trim();
    if path.is_empty() {
        return None;
    }
    let size = get_size(env, path);
    let file_count = count_files_at(env, path);
    let desc = match (file_count, size) {
        (Some(count), Some(sz)) => {
            format!(
                "Deletes directory with ~{} ({sz})",
                format_count(count, "file")
            )
        }
        (Some(count), None) => {
            format!("Deletes directory with ~{}", format_count(count, "file"))
        }
        (None, Some(sz)) => format!("Deletes directory ({sz})"),
        (None, None) => return None,
    };
    Some(BlastRadiusInfo {
        scope: BlastScope::Resource,
        description: desc,
    })
}

fn compute_fs_strict_change_permissions(
    command: &str,
    env: &dyn Environment,
) -> Option<BlastRadiusInfo> {
    // Parse the last argument as the target path
    let parts: Vec<&str> = command.split_whitespace().collect();
    let target = parts.last()?;
    if target.starts_with('-') || *target == "chmod" {
        return None;
    }
    if is_directory(env, target) {
        let count = count_files_at(env, target)?;
        Some(BlastRadiusInfo {
            scope: BlastScope::Resource,
            description: format!(
                "Changes permissions on ~{} in {target}",
                format_count(count, "file")
            ),
        })
    } else {
        Some(BlastRadiusInfo {
            scope: BlastScope::Resource,
            description: "Changes permissions on 1 file".to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// git group computations
// ---------------------------------------------------------------------------

fn compute_git_reset(env: &dyn Environment) -> Option<BlastRadiusInfo> {
    let unstaged = env
        .run_command("git", &["diff", "--name-only"], TIMEOUT_MS)
        .map_or(0, |o| count_lines(&o));
    let staged = env
        .run_command("git", &["diff", "--cached", "--name-only"], TIMEOUT_MS)
        .map_or(0, |o| count_lines(&o));
    let total = unstaged + staged;
    if total == 0 {
        return None;
    }
    Some(BlastRadiusInfo {
        scope: BlastScope::Project,
        description: format!("Resets {}", format_count(total, "modified file")),
    })
}

fn compute_git_delete_all(env: &dyn Environment) -> Option<BlastRadiusInfo> {
    let output = env.run_command("git", &["ls-files"], TIMEOUT_MS)?;
    let count = count_lines(&output);
    if count == 0 {
        return None;
    }
    Some(BlastRadiusInfo {
        scope: BlastScope::Project,
        description: format!("Deletes {}", format_count(count, "tracked file")),
    })
}

fn compute_git_clean_force(env: &dyn Environment) -> Option<BlastRadiusInfo> {
    let output = env.run_command("git", &["clean", "-dn"], TIMEOUT_MS)?;
    let count = count_lines(&output);
    if count == 0 {
        return None;
    }
    Some(BlastRadiusInfo {
        scope: BlastScope::Project,
        description: format!(
            "Removes {}",
            format_count(count, "untracked file/directory")
        ),
    })
}

fn compute_git_force_push(command: &str, env: &dyn Environment) -> Option<BlastRadiusInfo> {
    // Try to extract branch from command, else use current branch
    let branch = extract_git_push_branch(command)
        .or_else(|| env.run_command("git", &["rev-parse", "--abbrev-ref", "HEAD"], TIMEOUT_MS))?;

    let remote_ref = format!("origin/{branch}..HEAD");
    let output = env.run_command("git", &["rev-list", "--count", &remote_ref], TIMEOUT_MS)?;
    let count: usize = output.trim().parse().ok()?;
    if count == 0 {
        return Some(BlastRadiusInfo {
            scope: BlastScope::Project,
            description: format!("Force-pushes to origin/{branch}"),
        });
    }
    Some(BlastRadiusInfo {
        scope: BlastScope::Project,
        description: format!(
            "Force-pushes {} to origin/{branch}",
            format_count(count, "commit")
        ),
    })
}

/// Extract the branch from a `git push` command.
/// Looks for the token after a remote name (or after --force/-f).
fn extract_git_push_branch(command: &str) -> Option<String> {
    let parts: Vec<&str> = command.split_whitespace().collect();
    // Find "push" and skip flags to find remote + branch
    let push_idx = parts.iter().position(|p| *p == "push")?;
    let args: Vec<&&str> = parts[push_idx + 1..]
        .iter()
        .filter(|p| !p.starts_with('-'))
        .collect();
    // args[0] = remote, args[1] = refspec (may contain ':')
    if args.len() >= 2 {
        let refspec = args[1];
        // Handle "local:remote" refspec
        let branch = refspec.split(':').next_back().unwrap_or(refspec);
        Some(branch.to_string())
    } else {
        None
    }
}

fn compute_git_force_delete_branch(command: &str) -> Option<BlastRadiusInfo> {
    // Parse the branch name — word after -D
    let parts: Vec<&str> = command.split_whitespace().collect();
    let d_idx = parts.iter().position(|p| *p == "-D")?;
    let branch = parts.get(d_idx + 1)?;
    Some(BlastRadiusInfo {
        scope: BlastScope::Resource,
        description: format!("Deletes branch '{branch}'"),
    })
}

fn compute_git_force_checkout(env: &dyn Environment) -> Option<BlastRadiusInfo> {
    let output = env.run_command("git", &["diff", "--name-only"], TIMEOUT_MS)?;
    let count = count_lines(&output);
    if count == 0 {
        return None;
    }
    Some(BlastRadiusInfo {
        scope: BlastScope::Resource,
        description: format!("Discards changes in {}", format_count(count, "file")),
    })
}

fn compute_git_filter_branch(env: &dyn Environment) -> Option<BlastRadiusInfo> {
    let output = env.run_command("git", &["rev-list", "--count", "HEAD"], TIMEOUT_MS)?;
    let count: usize = output.trim().parse().ok()?;
    if count == 0 {
        return None;
    }
    Some(BlastRadiusInfo {
        scope: BlastScope::Project,
        description: format!("Rewrites history of {}", format_count(count, "commit")),
    })
}

fn compute_git_strict_add_all(env: &dyn Environment) -> Option<BlastRadiusInfo> {
    let output = env.run_command("git", &["status", "--short"], TIMEOUT_MS)?;
    let count = count_lines(&output);
    if count == 0 {
        return None;
    }
    Some(BlastRadiusInfo {
        scope: BlastScope::Project,
        description: format!("Stages {}", format_count(count, "file")),
    })
}

fn compute_git_strict_commit_all(env: &dyn Environment) -> Option<BlastRadiusInfo> {
    let output = env.run_command("git", &["status", "--short"], TIMEOUT_MS)?;
    let count = count_lines(&output);
    if count == 0 {
        return None;
    }
    Some(BlastRadiusInfo {
        scope: BlastScope::Project,
        description: format!("Commits all changes across {}", format_count(count, "file")),
    })
}

// ---------------------------------------------------------------------------
// docker group computations
// ---------------------------------------------------------------------------

fn compute_docker_system_prune(env: &dyn Environment) -> Option<BlastRadiusInfo> {
    let images = env
        .run_command("docker", &["images", "-q"], TIMEOUT_MS)
        .map_or(0, |o| count_lines(&o));
    let containers = env
        .run_command("docker", &["ps", "-aq"], TIMEOUT_MS)
        .map_or(0, |o| count_lines(&o));
    let volumes = env
        .run_command("docker", &["volume", "ls", "-q"], TIMEOUT_MS)
        .map_or(0, |o| count_lines(&o));
    if images == 0 && containers == 0 && volumes == 0 {
        return None;
    }
    Some(BlastRadiusInfo {
        scope: BlastScope::Machine,
        description: format!(
            "Prunes up to {}, {}, {}",
            format_count(images, "image"),
            format_count(containers, "container"),
            format_count(volumes, "volume"),
        ),
    })
}

fn compute_docker_force_remove_containers(env: &dyn Environment) -> Option<BlastRadiusInfo> {
    let output = env.run_command("docker", &["ps", "-q"], TIMEOUT_MS)?;
    let count = count_lines(&output);
    if count == 0 {
        return None;
    }
    Some(BlastRadiusInfo {
        scope: BlastScope::Machine,
        description: format!("Removes {}", format_count(count, "running container")),
    })
}

fn compute_docker_volume_prune(env: &dyn Environment) -> Option<BlastRadiusInfo> {
    let output = env.run_command("docker", &["volume", "ls", "-q"], TIMEOUT_MS)?;
    let count = count_lines(&output);
    if count == 0 {
        return None;
    }
    Some(BlastRadiusInfo {
        scope: BlastScope::Machine,
        description: format!("Prunes {}", format_count(count, "unused volume")),
    })
}

fn compute_docker_stop_all(env: &dyn Environment) -> Option<BlastRadiusInfo> {
    let output = env.run_command("docker", &["ps", "-q"], TIMEOUT_MS)?;
    let count = count_lines(&output);
    if count == 0 {
        return None;
    }
    Some(BlastRadiusInfo {
        scope: BlastScope::Machine,
        description: format!("Stops {}", format_count(count, "running container")),
    })
}

// ---------------------------------------------------------------------------
// kubernetes group computations
// ---------------------------------------------------------------------------

fn compute_kubernetes_delete_namespace(
    regex: &Regex,
    command: &str,
    env: &dyn Environment,
) -> Option<BlastRadiusInfo> {
    // Parse the namespace name — word after ns/namespace in the command
    let parts: Vec<&str> = command.split_whitespace().collect();
    let ns_idx = parts.iter().position(|p| *p == "ns" || *p == "namespace")?;
    let namespace = parts.get(ns_idx + 1)?;
    if namespace.starts_with('-') {
        return None;
    }
    let output = env.run_command(
        // Use whichever kubectl variant matched
        capture_group(regex, command, 1)
            .as_deref()
            .unwrap_or("kubectl"),
        &["get", "all", "-n", namespace, "--no-headers"],
        TIMEOUT_MS,
    )?;
    let count = count_lines(&output);
    if count == 0 {
        return Some(BlastRadiusInfo {
            scope: BlastScope::Namespace,
            description: format!("Deletes namespace '{namespace}'"),
        });
    }
    Some(BlastRadiusInfo {
        scope: BlastScope::Namespace,
        description: format!(
            "Deletes namespace '{namespace}' with {}",
            format_count(count, "resource")
        ),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::MockEnvironment;
    use std::collections::HashMap;

    fn mock_env_with_commands(commands: Vec<(&str, &str)>) -> MockEnvironment {
        let mut command_outputs = HashMap::new();
        for (cmd, output) in commands {
            command_outputs.insert(cmd.to_string(), output.to_string());
        }
        MockEnvironment {
            cwd: "/tmp/test".into(),
            command_outputs,
            ..Default::default()
        }
    }

    // -- Helper tests --

    #[test]
    fn test_parse_du_output() {
        assert_eq!(parse_du_output("12M\t/tmp/foo"), Some("12M".to_string()));
        assert_eq!(parse_du_output("4.0K /tmp/foo"), Some("4.0K".to_string()));
        assert_eq!(parse_du_output(""), None);
    }

    #[test]
    fn test_count_lines() {
        assert_eq!(count_lines("a\nb\nc"), 3);
        assert_eq!(count_lines("a\n\nb"), 2);
        assert_eq!(count_lines(""), 0);
    }

    #[test]
    fn test_format_count() {
        assert_eq!(format_count(1, "file"), "1 file");
        assert_eq!(format_count(5, "file"), "5 files");
        assert_eq!(format_count(0, "file"), "0 files");
        assert_eq!(format_count(1234, "file"), "1,234 files");
        assert_eq!(format_count(5629, "file"), "5,629 files");
        assert_eq!(format_count(47236, "file"), "47,236 files");
        assert_eq!(format_count(1234567, "commit"), "1,234,567 commits");
    }

    #[test]
    fn test_format_number() {
        assert_eq!(format_number(0), "0");
        assert_eq!(format_number(1), "1");
        assert_eq!(format_number(999), "999");
        assert_eq!(format_number(1000), "1,000");
        assert_eq!(format_number(12345), "12,345");
        assert_eq!(format_number(1000000), "1,000,000");
    }

    // -- fs group tests --

    #[test]
    fn test_fs_recursive_delete() {
        let regex = Regex::new(
            r"rm\s{1,}(?:-R|-r|-f|-fR|-fr|-Rf|-rf|-v|--force|--verbose|--preserve-root)\s*(?:-R|-r|-f|-fR|-fr|-Rf|-rf|-v|--force|--verbose|--preserve-root)?\s*(\*|\.{1,}|/)\s*$",
        ).unwrap();
        let env = mock_env_with_commands(vec![
            ("find / -type f", "file1\nfile2\nfile3"),
            ("du -sh /", "1.2G\t/"),
        ]);
        let result = compute_fs_recursive_delete(&regex, "rm -rf /", &env);
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.scope, BlastScope::Machine);
        assert!(info.description.contains("3 files"));
        assert!(info.description.contains("1.2G"));
    }

    #[test]
    fn test_fs_recursive_delete_project_scope() {
        let regex = Regex::new(
            r"rm\s{1,}(?:-R|-r|-f|-fR|-fr|-Rf|-rf|-v|--force|--verbose|--preserve-root)\s*(?:-R|-r|-f|-fR|-fr|-Rf|-rf|-v|--force|--verbose|--preserve-root)?\s*(\*|\.{1,}|/)\s*$",
        ).unwrap();
        let env = mock_env_with_commands(vec![("find . -type f", "a\nb"), ("du -sh .", "500K\t.")]);
        let result = compute_fs_recursive_delete(&regex, "rm -rf .", &env);
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.scope, BlastScope::Project);
    }

    #[test]
    fn test_fs_recursive_delete_no_match() {
        let regex = Regex::new(
            r"rm\s{1,}(?:-R|-r|-f|-fR|-fr|-Rf|-rf|-v|--force|--verbose|--preserve-root)\s*(?:-R|-r|-f|-fR|-fr|-Rf|-rf|-v|--force|--verbose|--preserve-root)?\s*(\*|\.{1,}|/)\s*$",
        ).unwrap();
        let env = MockEnvironment::default();
        let result = compute_fs_recursive_delete(&regex, "echo hello", &env);
        assert!(result.is_none());
    }

    // -- git group tests --

    #[test]
    fn test_git_reset() {
        let env = mock_env_with_commands(vec![
            ("git diff --name-only", "file1.rs\nfile2.rs"),
            ("git diff --cached --name-only", "file3.rs"),
        ]);
        let result = compute_git_reset(&env);
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.scope, BlastScope::Project);
        assert!(info.description.contains("3 modified files"));
    }

    #[test]
    fn test_git_reset_no_changes() {
        let env = mock_env_with_commands(vec![
            ("git diff --name-only", ""),
            ("git diff --cached --name-only", ""),
        ]);
        let result = compute_git_reset(&env);
        assert!(result.is_none());
    }

    #[test]
    fn test_git_force_push() {
        let env = mock_env_with_commands(vec![
            ("git rev-parse --abbrev-ref HEAD", "main"),
            ("git rev-list --count origin/main..HEAD", "5"),
        ]);
        let result = compute_git_force_push("git push --force", &env);
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.scope, BlastScope::Project);
        assert!(info.description.contains("5 commits"));
        assert!(info.description.contains("origin/main"));
    }

    #[test]
    fn test_git_force_push_with_branch() {
        let env = mock_env_with_commands(vec![("git rev-list --count origin/feature..HEAD", "3")]);
        let result = compute_git_force_push("git push -f origin feature", &env);
        assert!(result.is_some());
        let info = result.unwrap();
        assert!(info.description.contains("3 commits"));
        assert!(info.description.contains("origin/feature"));
    }

    #[test]
    fn test_git_delete_all() {
        let env = mock_env_with_commands(vec![(
            "git ls-files",
            "src/main.rs\nsrc/lib.rs\nCargo.toml",
        )]);
        let result = compute_git_delete_all(&env);
        assert!(result.is_some());
        let info = result.unwrap();
        assert!(info.description.contains("3 tracked files"));
    }

    #[test]
    fn test_git_clean_force() {
        let env = mock_env_with_commands(vec![(
            "git clean -dn",
            "Would remove foo.tmp\nWould remove bar/",
        )]);
        let result = compute_git_clean_force(&env);
        assert!(result.is_some());
        let info = result.unwrap();
        assert!(info.description.contains("2 untracked file/directorys"));
    }

    #[test]
    fn test_git_force_delete_branch() {
        let result = compute_git_force_delete_branch("git branch -D feature-x");
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.scope, BlastScope::Resource);
        assert!(info.description.contains("feature-x"));
    }

    #[test]
    fn test_git_force_checkout() {
        let env = mock_env_with_commands(vec![(
            "git diff --name-only",
            "file1.rs\nfile2.rs\nfile3.rs",
        )]);
        let result = compute_git_force_checkout(&env);
        assert!(result.is_some());
        let info = result.unwrap();
        assert!(info.description.contains("3 files"));
    }

    #[test]
    fn test_git_filter_branch() {
        let env = mock_env_with_commands(vec![("git rev-list --count HEAD", "1203")]);
        let result = compute_git_filter_branch(&env);
        assert!(result.is_some());
        let info = result.unwrap();
        assert!(info.description.contains("1,203 commits"));
    }

    #[test]
    fn test_git_strict_add_all() {
        let env = mock_env_with_commands(vec![(
            "git status --short",
            " M file1.rs\n?? file2.rs\n M file3.rs",
        )]);
        let result = compute_git_strict_add_all(&env);
        assert!(result.is_some());
        let info = result.unwrap();
        assert!(info.description.contains("3 files"));
    }

    // -- docker group tests --

    #[test]
    fn test_docker_system_prune() {
        let env = mock_env_with_commands(vec![
            ("docker images -q", "abc\ndef\nghi"),
            ("docker ps -aq", "111\n222"),
            ("docker volume ls -q", "vol1"),
        ]);
        let result = compute_docker_system_prune(&env);
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.scope, BlastScope::Machine);
        assert!(info.description.contains("3 images"));
        assert!(info.description.contains("2 containers"));
        assert!(info.description.contains("1 volume"));
    }

    #[test]
    fn test_docker_stop_all() {
        let env = mock_env_with_commands(vec![("docker ps -q", "abc\ndef")]);
        let result = compute_docker_stop_all(&env);
        assert!(result.is_some());
        let info = result.unwrap();
        assert!(info.description.contains("2 running containers"));
    }

    // -- kubernetes group tests --

    #[test]
    fn test_kubernetes_delete_namespace() {
        let regex = Regex::new(r"(kubectl|k)\s+delete\s+(ns|namespace)").unwrap();
        let env = mock_env_with_commands(vec![(
            "kubectl get all -n staging --no-headers",
            "pod/web-1\npod/web-2\nsvc/web",
        )]);
        let result = compute_kubernetes_delete_namespace(&regex, "kubectl delete ns staging", &env);
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.scope, BlastScope::Namespace);
        assert!(info.description.contains("staging"));
        assert!(info.description.contains("3 resources"));
    }

    // -- dispatch tests --

    #[test]
    fn test_unsupported_check_returns_none() {
        let regex = Regex::new("test").unwrap();
        let env = MockEnvironment::default();
        assert!(compute("base:fork_bomb", &regex, ":(){ :|:& };:", &env).is_none());
    }

    #[test]
    fn test_compute_for_matches_empty() {
        let env = MockEnvironment::default();
        let result = compute_for_matches(&[], &["echo hello".to_string()], "echo hello", &env);
        assert!(result.is_empty());
    }

    #[test]
    fn test_extract_git_push_branch() {
        assert_eq!(
            extract_git_push_branch("git push -f origin main"),
            Some("main".to_string())
        );
        assert_eq!(
            extract_git_push_branch("git push --force origin feature:feature"),
            Some("feature".to_string())
        );
        assert_eq!(extract_git_push_branch("git push --force"), None);
    }

    #[test]
    fn test_blast_scope_ordering() {
        assert!(BlastScope::Resource < BlastScope::Project);
        assert!(BlastScope::Project < BlastScope::Namespace);
        assert!(BlastScope::Namespace < BlastScope::Machine);
    }
}
