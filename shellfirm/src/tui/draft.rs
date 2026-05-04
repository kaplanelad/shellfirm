//! Mutable working copy of `Settings` for the TUI.
//!
//! The TUI mutates `current` in response to keystrokes; `original` stays
//! pinned to the on-disk state so we can compute dirty / reset / diff.

use crate::config::Settings;

#[derive(Debug, Clone)]
pub struct DraftSettings {
    pub current: Settings,
    original: Settings,
}

impl DraftSettings {
    #[must_use]
    pub fn from_settings(s: Settings) -> Self {
        Self {
            current: s.clone(),
            original: s,
        }
    }

    /// True if the current draft differs from the on-disk snapshot.
    ///
    /// Comparison is via YAML serialization to avoid implementing PartialEq
    /// on the entire Settings tree (and to ignore non-semantic differences
    /// like HashMap iteration order).
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        let a = serde_yaml::to_string(&self.current).unwrap_or_default();
        let b = serde_yaml::to_string(&self.original).unwrap_or_default();
        a != b
    }

    /// Revert all changes back to the on-disk snapshot.
    pub fn reset(&mut self) {
        self.current = self.original.clone();
    }

    /// After a successful save, pin the new content as the original so
    /// `is_dirty()` returns false again.
    pub fn pin_original(&mut self, s: Settings) {
        self.original = s.clone();
        self.current = s;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Challenge;

    #[test]
    fn fresh_draft_is_clean() {
        let d = DraftSettings::from_settings(Settings::default());
        assert!(!d.is_dirty());
    }

    #[test]
    fn mutating_marks_dirty() {
        let mut d = DraftSettings::from_settings(Settings::default());
        d.current.challenge = Challenge::Yes;
        assert!(d.is_dirty());
    }

    #[test]
    fn reset_clears_dirty() {
        let mut d = DraftSettings::from_settings(Settings::default());
        d.current.challenge = Challenge::Yes;
        d.reset();
        assert!(!d.is_dirty());
    }

    #[test]
    fn pin_original_after_save_clears_dirty() {
        let mut d = DraftSettings::from_settings(Settings::default());
        d.current.challenge = Challenge::Yes;
        let saved = d.current.clone();
        d.pin_original(saved);
        assert!(!d.is_dirty());
    }
}
