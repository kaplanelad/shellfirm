//! Audit trail — optional local log of every intercepted command.
//!
//! Records timestamp, command, matched pattern IDs, challenge type,
//! and the user's decision (allowed / denied / skipped).

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

use anyhow::Result;
use serde_derive::{Deserialize, Serialize};

use crate::checks::Severity;

/// The outcome of a challenge interaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditOutcome {
    Allowed,
    Denied,
    /// The check matched but was skipped because its severity was below
    /// the configured `min_severity` threshold.
    Skipped,
}

impl std::fmt::Display for AuditOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allowed => write!(f, "ALLOWED"),
            Self::Denied => write!(f, "DENIED"),
            Self::Skipped => write!(f, "SKIPPED"),
        }
    }
}

/// A single audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: String,
    pub command: String,
    pub matched_ids: Vec<String>,
    pub challenge_type: String,
    pub outcome: AuditOutcome,
    pub context_labels: Vec<String>,
    /// The highest severity among the matched checks.
    pub severity: Severity,
}

/// Append an audit event to the log file as a JSON line.
///
/// If the file doesn't exist, it is created. Each entry is one JSON object per line.
///
/// # Errors
/// Returns an error if the file cannot be opened/created or JSON serialization fails.
pub fn log_event(audit_path: &Path, event: &AuditEvent) -> Result<()> {
    // Ensure parent directory exists
    if let Some(parent) = audit_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(audit_path)?;

    let json = serde_json::to_string(event)?;
    writeln!(file, "{json}")?;

    Ok(())
}

/// Read and return all audit log lines.
///
/// # Errors
/// Returns an error if the file cannot be read.
pub fn read_log(audit_path: &Path) -> Result<String> {
    if !audit_path.exists() {
        return Ok("No audit events recorded yet.".into());
    }
    Ok(fs::read_to_string(audit_path)?)
}

/// Clear the audit log.
///
/// # Errors
/// Returns an error if the file cannot be removed.
pub fn clear_log(audit_path: &Path) -> Result<()> {
    if audit_path.exists() {
        fs::remove_file(audit_path)?;
    }
    Ok(())
}

/// Get the current timestamp in ISO 8601 format.
#[must_use]
pub fn now_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    // Simple UTC timestamp without external crate
    let days = secs / 86400;
    let remaining = secs % 86400;
    let hours = remaining / 3600;
    let minutes = (remaining % 3600) / 60;
    let seconds = remaining % 60;

    // Approximate date from epoch days (good enough for logging)
    let (year, month, day) = epoch_days_to_date(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z"
    )
}

/// Convert epoch days to (year, month, day). Simplified algorithm.
const fn epoch_days_to_date(days: u64) -> (u64, u64, u64) {
    // Algorithm based on Howard Hinnant's civil_from_days
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_log_and_read() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("audit.log");

        let event = AuditEvent {
            timestamp: "2026-02-15T10:00:00Z".into(),
            command: "git push -f".into(),
            matched_ids: vec!["git:force_push".into()],
            challenge_type: "Math".into(),
            outcome: AuditOutcome::Allowed,
            context_labels: vec!["branch=main".into()],
            severity: Severity::High,
        };

        log_event(&path, &event).unwrap();
        let content = read_log(&path).unwrap();
        // JSON lines format: each line is a valid JSON object
        let parsed: AuditEvent = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(parsed.command, "git push -f");
        assert_eq!(parsed.outcome, AuditOutcome::Allowed);
        assert_eq!(parsed.matched_ids, vec!["git:force_push"]);
        assert_eq!(parsed.context_labels, vec!["branch=main"]);
        assert_eq!(parsed.severity, Severity::High);
    }

    #[test]
    fn test_log_command_with_pipe_characters() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("audit.log");

        let event = AuditEvent {
            timestamp: "2026-02-15T10:00:00Z".into(),
            command: "cat file | grep pattern | rm -rf /".into(),
            matched_ids: vec!["fs:recursively_delete".into()],
            challenge_type: "Math".into(),
            outcome: AuditOutcome::Allowed,
            context_labels: vec![],
            severity: Severity::Critical,
        };

        log_event(&path, &event).unwrap();
        let content = read_log(&path).unwrap();
        // JSON format correctly handles pipes in commands
        let parsed: AuditEvent = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(parsed.command, "cat file | grep pattern | rm -rf /");
    }

    #[test]
    fn test_clear_log() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("audit.log");

        let event = AuditEvent {
            timestamp: "2026-02-15T10:00:00Z".into(),
            command: "rm -rf /".into(),
            matched_ids: vec!["fs:recursively_delete".into()],
            challenge_type: "Deny".into(),
            outcome: AuditOutcome::Denied,
            context_labels: vec![],
            severity: Severity::Critical,
        };

        log_event(&path, &event).unwrap();
        assert!(path.exists());

        clear_log(&path).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn test_read_nonexistent_log() {
        let path = PathBuf::from("/tmp/nonexistent-audit-test.log");
        let result = read_log(&path).unwrap();
        assert!(result.contains("No audit events"));
    }

    #[test]
    fn test_now_timestamp_format() {
        let ts = now_timestamp();
        // Should look like "YYYY-MM-DDTHH:MM:SSZ"
        assert!(ts.contains('T'));
        assert!(ts.ends_with('Z'));
        assert_eq!(ts.len(), 20);
    }
}
