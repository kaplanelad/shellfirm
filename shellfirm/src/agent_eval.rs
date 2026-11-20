//! How an agent hook judges a tool call.
//!
//! Shared by the live hook (`shellfirm check --hook ...`) and
//! `shellfirm audit replay`: the shell
//! command with its policies, the files of an `apply_patch` it runs, the
//! shell read a file-tool read is checked as, and the decision for an agent
//! that cannot ask.

use std::borrow::Cow;
use std::path::{Path, PathBuf};

use crate::agent::{self, Decision, RiskAssessment};
use crate::checks::Check;
use crate::config::{Config, Settings};
use crate::env::Environment;
use crate::policy::PolicyLoadError;

/// Program names Codex runs a patch under.
const APPLY_PATCH_PROGRAMS: &[&str] = &["apply_patch", "applypatch"];

/// Files an `apply_patch` patch adds, updates, deletes or moves to (the
/// `*** Add File:` / `*** Update File:` / `*** Delete File:` / `*** Move to:`
/// headers of the patch grammar used by Codex, Cline and `OpenCode`).
#[must_use]
pub fn patch_paths(patch: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in patch.lines() {
        let line = line.trim_end_matches('\r');
        let named = [
            "*** Add File:",
            "*** Update File:",
            "*** Delete File:",
            "*** Move to:",
        ]
        .iter()
        .find_map(|h| line.strip_prefix(h))
        .map(str::trim);
        if let Some(p) = named.filter(|p| !p.is_empty()) {
            if !out.iter().any(|o| o == p) {
                out.push(p.to_string());
            }
        }
    }
    out
}

/// Files an `apply_patch` patch deletes (`*** Delete File:`).
#[must_use]
pub fn patch_deleted_paths(patch: &str) -> Vec<String> {
    patch
        .lines()
        .filter_map(|l| l.trim_end_matches('\r').strip_prefix("*** Delete File:"))
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect()
}

/// `true` when a shell command runs `apply_patch` (or `applypatch`) with a
/// patch, also as the script of a shell (`bash -lc "apply_patch <<'EOF' …"`,
/// the form Codex runs it in): quotes end a word too.
fn shell_patch(command: &str) -> bool {
    command.contains("*** Begin Patch")
        && command
            .split(|c: char| c.is_whitespace() || ";&|()'\"`".contains(c))
            .any(|w| APPLY_PATCH_PROGRAMS.contains(&w.rsplit('/').next().unwrap_or(w)))
}

/// `true` when a command of `command` (as the parser reads it, shell
/// scripts opened) is `apply_patch` / `applypatch`.
fn runs_apply_patch(command: &str) -> bool {
    crate::parser::parse(command).segments.iter().any(|s| {
        let s = crate::parser::desentinel(s);
        let prog = s.split_whitespace().next().unwrap_or("");
        APPLY_PATCH_PROGRAMS.contains(&prog.rsplit('/').next().unwrap_or(prog))
    })
}

/// `command` with its ANSI-C quoted words (`$'…\n…'`) decoded, so a patch
/// passed that way has its lines. A word with an escape other than
/// `\n`, `\t`, `\r`, `\\`, `\'` and `\"` is kept as written (its patch
/// is then not seen, and fails closed).
fn ansi_c_decoded(command: &str) -> Cow<'_, str> {
    if !command.contains("$'") {
        return Cow::Borrowed(command);
    }
    let mut out = String::with_capacity(command.len());
    let mut rest = command;
    while let Some(at) = rest.find("$'") {
        out.push_str(&rest[..at]);
        let body = &rest[at + 2..];
        let mut decoded = String::new();
        let mut chars = body.char_indices();
        let mut end = None;
        let mut simple = true;
        while let Some((i, c)) = chars.next() {
            match c {
                '\'' => {
                    end = Some(i);
                    break;
                }
                '\\' => match chars.next().map(|(_, e)| e) {
                    Some('n') => decoded.push('\n'),
                    Some('t') => decoded.push('\t'),
                    Some('r') => decoded.push('\r'),
                    Some(e @ ('\\' | '\'' | '"')) => decoded.push(e),
                    _ => simple = false,
                },
                c => decoded.push(c),
            }
        }
        let Some(end) = end else {
            out.push_str(&rest[at..]);
            return Cow::Owned(out);
        };
        if simple {
            out.push_str(&decoded);
        } else {
            out.push_str(&rest[at..=at + 2 + end]);
        }
        rest = &body[end + 1..];
    }
    out.push_str(rest);
    Cow::Owned(out)
}

/// The most restrictive of several assessments, carrying every matched
/// rule.
///
/// On a tie the more severe one leads, then one that is not only an
/// agent-instruction edit, so the reason names the file that matters and the
/// instruction-edit exemption applies only when every file is one.
#[must_use]
pub fn worst_of(mut all: Vec<RiskAssessment>) -> RiskAssessment {
    let rank = |a: &RiskAssessment| {
        (
            match a.decision {
                Decision::Allow => 0,
                Decision::Ask => 1,
                Decision::Deny => 2,
            },
            a.effective_severity.or(a.severity),
            !agent::only_instruction_edits(a),
        )
    };
    let Some(lead) = (0..all.len()).max_by_key(|&i| rank(&all[i])) else {
        return RiskAssessment::no_objection();
    };
    let mut worst = all.swap_remove(lead);
    for other in all {
        for r in other.matched_rules {
            if !worst.matched_rules.iter().any(|m| m.id == r.id) {
                worst.matched_rules.push(r);
            }
        }
    }
    worst
}

/// A shell command as the hooks judge it.
///
/// Its checks, the invalid project
/// policies of `cwd` (`policy_errors`) and, with `target_policies` (the
/// configuration and the policy files of `cwd`), the policy of another
/// repository it changes (`cd /other/repo && ...`).
pub fn assess_shell_command(
    command: &str,
    settings: &Settings,
    checks: &[Check],
    env: &dyn Environment,
    cwd: &Path,
    policy_errors: &[PolicyLoadError],
    target_policies: Option<(&Config, &[PathBuf])>,
) -> RiskAssessment {
    // One time budget for both evaluations (this one and the target
    // repository's policy), from the settings used here.
    let _scope = settings.command_scope();
    let mut assessment = agent::assess_command(command, settings, checks, env, &settings.agent)
        .unwrap_or_else(|e| {
            RiskAssessment::fail_closed(
                Decision::Deny,
                format!("shellfirm failed to analyze this command ({e}). Failing closed."),
            )
        });
    agent::apply_policy_errors(&mut assessment, policy_errors);
    match target_policies {
        Some((config, files)) => {
            agent::apply_target_repo_policies(assessment, command, config, env, cwd, files)
        }
        None => assessment,
    }
}

/// `assessment` of a shell command with the files of an `apply_patch` it runs.
///
/// The patch (`apply_patch '<patch>'`, `apply_patch <<'EOF'`, `$'…'`)
/// has each file judged by `assess_file(tool, path, deletes)`. A patch whose
/// content cannot
/// be seen (`apply_patch < p.diff`, a substitution, a quoting that is not
/// decoded) names no file it can be judged by: it is an `ask`.
///
/// Also returns `true` when the command itself matches nothing and the
/// patch changes only agent-instruction files: like the `apply_patch` tool,
/// it then goes ahead with a note where the agent cannot ask.
pub fn with_shell_patch(
    assessment: RiskAssessment,
    command: &str,
    assess_file: impl Fn(&str, &str, bool) -> RiskAssessment,
) -> (RiskAssessment, bool) {
    let patch = ansi_c_decoded(command);
    if !shell_patch(&patch) && !runs_apply_patch(command) {
        return (assessment, false);
    }
    let paths = patch_paths(&patch);
    let deleted = patch_deleted_paths(&patch);
    let files = if paths.is_empty() {
        RiskAssessment::fail_closed(
            Decision::Ask,
            "shellfirm could not see the patch content (it is read from a file, a command \
             substitution or a quoting shellfirm does not decode), so the files it changes \
             cannot be checked. Pass the patch inline (apply_patch <<'EOF' ... EOF).",
        )
    } else {
        worst_of(
            paths
                .iter()
                .map(|p| assess_file("apply_patch", p, deleted.contains(p)))
                .collect(),
        )
    };
    let instruction_patch = assessment.matched_rules.is_empty()
        && assessment.decision == Decision::Allow
        && agent::only_instruction_edits(&files);
    (worst_of(vec![assessment, files]), instruction_patch)
}

/// The shell read (`cat <paths>`) a file-tool read is checked as.
///
/// Each path
/// is resolved the way the write tools resolve it (`~`, `..`, `//`,
/// symlinks), and a path in `home` is also given as `~/…`, the form the
/// secret-file check knows whatever the home directory is (a path under a
/// moved agent home, `$CLAUDE_CONFIG_DIR`, also as `~/.claude/…`; `home`
/// as [`crate::env::home_dir`] gives it, no trailing `/`). A
/// directory (Gemini `read_many_files` reads every file in it) is read as
/// `<dir>/*`, and a directory or glob that holds or matches a credential
/// file ([`agent::CREDENTIAL_PATHS`]: `~`, `~/.kube`, `**/*` from home,
/// `~/.ss?`) is read as that file too.
#[must_use]
pub fn read_command(paths: &[String], cwd: Option<&Path>, home: Option<&Path>) -> String {
    let quote = |p: &str| format!("'{}'", p.replace('\'', r"'\''"));
    let home = home
        .map(|h| format!("{}/", h.display()))
        .filter(|h| h.len() > 1);
    let mut operands: Vec<String> = Vec::new();
    for path in paths {
        let dir = path.ends_with('/');
        for p in agent::resolved_tool_paths(path, cwd) {
            if let Some(h) = home.as_deref() {
                operands.extend(
                    agent::CREDENTIAL_PATHS
                        .iter()
                        .map(|e| agent::credential_sample_file(e))
                        .filter(|f| reaches(p.trim_end_matches('/'), &format!("{h}{}", &f[2..])))
                        .map(|f| format!("~/{}", quote(&f[2..]))),
                );
            }
            let p = if dir || Path::new(&p).is_dir() {
                format!("{}/*", p.trim_end_matches('/'))
            } else {
                p
            };
            let in_home = home
                .as_deref()
                .and_then(|h| p.strip_prefix(h))
                .map(|rest| format!("~/{}", quote(rest)));
            let moved = agent::moved_agent_home_alias(&p).and_then(|a| {
                a.split_once('/')
                    .map(|(head, rest)| format!("{head}/{}", quote(rest)))
            });
            operands.push(quote(&p));
            operands.extend(in_home);
            operands.extend(moved);
        }
    }
    format!("cat {}", operands.join(" "))
}

/// `true` when reading `pattern` (a path or a glob) reads `file`: the
/// pattern is `file` or one of its parent directories, or matches one.
/// `*` also matches `/` and dot files, `[…]` any one character.
fn reaches(pattern: &str, file: &str) -> bool {
    // Iterative wildcard match (linear backtracking to the last `*`).
    fn glob(p: &[u8], t: &[u8]) -> bool {
        let (mut pi, mut ti) = (0, 0);
        let mut star: Option<(usize, usize)> = None;
        while ti < t.len() {
            let class_end = (p.get(pi) == Some(&b'['))
                .then(|| p[pi..].iter().position(|&c| c == b']').map(|e| pi + e))
                .flatten();
            if p.get(pi) == Some(&b'*') {
                star = Some((pi, ti));
                pi += 1;
            } else if let Some(end) = class_end {
                pi = end + 1;
                ti += 1;
            } else if p.get(pi).is_some_and(|&c| c == b'?' || c == t[ti]) {
                pi += 1;
                ti += 1;
            } else if let Some((sp, st)) = star {
                pi = sp + 1;
                ti = st + 1;
                star = Some((sp, st + 1));
            } else {
                return false;
            }
        }
        p[pi..].iter().all(|&c| c == b'*')
    }
    let pattern = if pattern.is_empty() { "/" } else { pattern };
    let mut at = file.len();
    loop {
        let candidate = if at == 0 { "/" } else { &file[..at] };
        if glob(pattern.as_bytes(), candidate.as_bytes()) {
            return true;
        }
        match file[..at].rfind('/') {
            Some(i) => at = i,
            None => return false,
        }
    }
}

/// Turn an `ask` into a `deny` for an agent (`agent`: its name) that cannot
/// ask about a `subject` (`command`, `file read`, `file edit`), keeping the
/// matched rules and alternatives and saying why.
pub fn ask_becomes_deny(a: &mut RiskAssessment, agent: &str, subject: &str) {
    if a.decision != Decision::Ask {
        return;
    }
    a.decision = Decision::Deny;
    a.allowed = false;
    let (what, fix) = match subject {
        "command" => ("for confirmation", "run it yourself if it is intended"),
        "file read" => (
            "for confirmation",
            "read the file yourself if it is intended",
        ),
        _ => (
            "for file edits",
            "make this change yourself if it is intended",
        ),
    };
    let r = format!(
        "{} ({agent} cannot ask {what}, so shellfirm blocks it; {fix})",
        a.decision_reason.take().unwrap_or_default(),
    );
    a.denial_reason = Some(r.clone());
    a.decision_reason = Some(r);
    a.requires_human_approval = false;
}

/// A file edit for an agent that cannot ask about file edits.
///
/// An `ask` is denied, telling the user to make the change themselves, except for an
/// edit of only agent-instruction files (AGENTS.md, CLAUDE.md, Cursor
/// rules), an everyday task that stays `ask` (the edit then goes ahead).
/// Turn that off with `shellfirm config ignore
/// shellfirm-self:agent_instructions_edit`.
pub fn file_edit_cannot_ask(a: &mut RiskAssessment, agent: &str) {
    if !agent::only_instruction_edits(a) {
        ask_becomes_deny(a, agent, "file edit");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_headers_name_every_file_once() {
        let patch =
            "*** Begin Patch\n*** Update File: src/a.rs\n@@\n-x\n+y\n*** Add File: b.txt\n+hi\n\
                     *** Delete File: c.txt\n*** Update File: d.rs\n*** Move to: e.rs\n\
                     *** Update File: src/a.rs\n*** End Patch\n";
        assert_eq!(
            patch_paths(patch),
            ["src/a.rs", "b.txt", "c.txt", "d.rs", "e.rs"]
        );
        assert!(patch_paths("not a patch").is_empty());
        assert_eq!(patch_paths("*** Add File: x\r\n"), ["x"]);
    }

    #[test]
    fn shell_patches_are_recognised() {
        let p = "*** Begin Patch\n*** Delete File: a\n*** Add File: b\n*** End Patch";
        for yes in [
            format!("apply_patch <<'EOF'\n{p}\nEOF"),
            format!("applypatch <<'EOF'\n{p}\nEOF"),
            format!("cd x && /usr/bin/apply_patch '{p}'"),
            format!("bash -lc \"apply_patch <<'EOF'\n{p}\nEOF\""),
            format!("sh -c 'apply_patch \"{p}\"'"),
        ] {
            assert!(shell_patch(&yes), "{yes}");
        }
        assert!(!shell_patch("apply_patch --help"));
        assert!(!shell_patch(&format!("echo '{p}' > x.patch")));
        assert_eq!(patch_deleted_paths(p), ["a"]);
        let ansi = "bash -lc $'apply_patch <<\\'EOF\\'\\n*** Begin Patch\\n*** Add File: b\\n*** End Patch\\nEOF'";
        assert_eq!(patch_paths(&ansi_c_decoded(ansi)), ["b"]);
    }

    #[test]
    fn ask_becomes_deny_only_for_asks() {
        let mut a = RiskAssessment::fail_closed(Decision::Ask, "risky");
        ask_becomes_deny(&mut a, "Windsurf", "command");
        assert_eq!(a.decision, Decision::Deny);
        assert!(!a.allowed && !a.requires_human_approval);
        let r = a.decision_reason.as_deref().unwrap();
        assert!(
            r.starts_with("risky (Windsurf cannot ask for confirmation"),
            "{r}"
        );
        assert_eq!(a.denial_reason.as_deref(), Some(r));
        let mut allow = RiskAssessment::no_objection();
        ask_becomes_deny(&mut allow, "Codex", "command");
        assert_eq!(allow.decision, Decision::Allow);
    }
}
