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

#[cfg(test)]
mod tests {
    use super::*;

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
