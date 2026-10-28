//! Validation for a `Settings` before save.

use crate::config::Settings;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Default, Clone)]
pub struct ValidationReport {
    pub errors: Vec<ValidationError>,
}

impl ValidationReport {
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Validate a `Settings` by serializing → re-parsing.
///
/// This catches type mismatches that snuck in via direct `serde_yaml::Value`
/// edits or any other inconsistency that would prevent the saved YAML from
/// being parsed back identically. Field-level checks (regex compiles, ID
/// uniqueness, bounded numerics) are handled by the widgets themselves;
/// this is the safety-net pass run right before write.
pub fn validate(settings: &Settings) -> ValidationReport {
    let mut report = ValidationReport::default();
    let yaml = match serde_yaml::to_string(settings) {
        Ok(s) => s,
        Err(e) => {
            report.errors.push(ValidationError {
                path: "(root)".into(),
                message: format!("serialization failed: {e}"),
            });
            return report;
        }
    };
    if let Err(e) = serde_yaml::from_str::<Settings>(&yaml) {
        report.errors.push(ValidationError {
            path: "(root)".into(),
            message: format!("round-trip parse failed: {e}"),
        });
    }
    report
}

/// Like [`validate`], and also rejects unknown check ids.
///
/// Ignore/deny entries must be known check ids. A typo in the deny list would otherwise leave the user
/// unprotected while the TUI claims the configuration is valid.
pub fn validate_with_ids<S: std::hash::BuildHasher>(
    settings: &Settings,
    known: &std::collections::HashSet<String, S>,
) -> ValidationReport {
    let mut report = validate(settings);
    for (path, list) in [
        ("ignores_patterns_ids", &settings.ignores_patterns_ids),
        ("deny_patterns_ids", &settings.deny_patterns_ids),
    ] {
        for id in list {
            // `shellfirm-self:agent_instructions_edit` is a built-in agent
            // protection that may be ignored by id (not a check).
            let ignorable_builtin = path == "ignores_patterns_ids"
                && crate::config::IGNORABLE_BUILTIN_RULE_IDS.contains(&id.as_str());
            if !known.contains(id) && !ignorable_builtin {
                let suggestions = suggest_check_ids(id, known.iter().map(String::as_str), 3);
                let hint = if suggestions.is_empty() {
                    String::new()
                } else {
                    format!(" Did you mean: {}?", suggestions.join(", "))
                };
                report.errors.push(ValidationError {
                    path: path.into(),
                    message: format!(
                        "unknown check id `{id}`.{hint} Remove it in the Ignore/Deny tab."
                    ),
                });
            }
        }
    }
    report
}

/// Levenshtein distance between two strings (by character).
fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = vec![i + 1; b.len() + 1];
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != *cb);
            cur[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1);
        }
        prev = cur;
    }
    prev[b.len()]
}

/// The `limit` known check ids closest to `id`, best first. Underscores are
/// ignored when comparing, so `git:forcepush` finds `git:force_push`.
#[must_use]
pub fn suggest_check_ids<'a>(
    id: &str,
    known: impl Iterator<Item = &'a str>,
    limit: usize,
) -> Vec<String> {
    let norm = |s: &str| s.to_lowercase().replace('_', "");
    let target = norm(id);
    let mut scored: Vec<(usize, &str)> = known
        .map(|k| {
            let nk = norm(k);
            let d = if nk.contains(&target) || target.contains(&nk) {
                0
            } else {
                edit_distance(&target, &nk)
            };
            (d, k)
        })
        .filter(|(d, _)| *d <= (target.chars().count() / 3).max(2))
        .collect();
    scored.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(b.1)));
    scored
        .into_iter()
        .take(limit)
        .map(|(_, k)| k.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_deny_id_is_an_error_with_suggestion() {
        let known: std::collections::HashSet<String> = ["git:force_push", "git:reset"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let mut s = Settings::default();
        s.deny_patterns_ids = vec!["git:forcepush".into()];
        let r = validate_with_ids(&s, &known);
        assert!(!r.is_ok());
        assert!(
            r.errors[0].message.contains("git:force_push"),
            "{:?}",
            r.errors
        );
        s.deny_patterns_ids = vec!["git:force_push".into()];
        assert!(validate_with_ids(&s, &known).is_ok());
    }

    #[test]
    fn ignorable_builtin_rule_is_accepted_only_in_the_ignore_list() {
        let known = std::collections::HashSet::<String>::new();
        let id = "shellfirm-self:agent_instructions_edit".to_string();
        let mut s = Settings::default();
        s.ignores_patterns_ids = vec![id.clone()];
        assert!(validate_with_ids(&s, &known).is_ok());
        s.ignores_patterns_ids.clear();
        s.deny_patterns_ids = vec![id];
        assert!(!validate_with_ids(&s, &known).is_ok());
    }

    #[test]
    fn validate_default_settings_is_ok() {
        assert!(validate(&Settings::default()).is_ok());
    }

    #[test]
    fn validate_after_known_good_mutation_is_ok() {
        let mut s = Settings::default();
        s.challenge = crate::config::Challenge::Yes;
        s.min_severity = Some(crate::checks::Severity::Critical);
        assert!(validate(&s).is_ok());
    }
}
