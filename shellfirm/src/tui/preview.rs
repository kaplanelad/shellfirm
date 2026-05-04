//! Render the YAML preview of `Settings` and a line-diff against the
//! on-disk file content.

use crate::config::Settings;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffLine {
    Same(String),
    Added(String),
    Removed(String),
}

/// Compute the scroll offset for rendering a diff so the first change
/// is visible.
///
/// Positions the change near the BOTTOM of the visible window —
/// preserving as much unchanged YAML *above* it as possible (since
/// users want to see their edit in context, not at the top of an
/// otherwise-empty pane).
///
/// `tail_padding` is the number of unchanged lines we try to keep
/// visible AFTER the change.
///
/// Returns 0 when there are no changes, or when the change already fits
/// in the initial visible window.
#[must_use]
pub fn first_change_offset(
    diff: &[DiffLine],
    visible_height: usize,
    tail_padding: usize,
) -> usize {
    let first_change = diff
        .iter()
        .position(|l| matches!(l, DiffLine::Added(_) | DiffLine::Removed(_)));
    let Some(idx) = first_change else { return 0 };
    let total = diff.len();

    // No need to scroll if everything fits, or if the change is already
    // in the natural top-anchored window.
    if total <= visible_height || idx < visible_height {
        return 0;
    }

    // Position the change so it sits near the bottom of the visible
    // window with a small tail of context after it. Maximises context
    // BEFORE the change.
    let preferred = (idx + tail_padding + 1).saturating_sub(visible_height);
    let max_offset = total - visible_height;
    preferred.min(max_offset)
}

/// Serialize `current` to YAML.
#[must_use]
pub fn render_yaml(current: &Settings) -> String {
    serde_yaml::to_string(current).unwrap_or_else(|e| format!("# (yaml error: {e})"))
}

/// Compute a simple line-diff between two YAML strings using LCS.
#[must_use]
pub fn line_diff(original: &str, current: &str) -> Vec<DiffLine> {
    let a: Vec<&str> = original.lines().collect();
    let b: Vec<&str> = current.lines().collect();
    let n = a.len();
    let m = b.len();
    let mut lcs = vec![vec![0u32; m + 1]; n + 1];
    for i in 0..n {
        for j in 0..m {
            lcs[i + 1][j + 1] = if a[i] == b[j] {
                lcs[i][j] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let mut out = Vec::new();
    let (mut i, mut j) = (n, m);
    while i > 0 && j > 0 {
        if a[i - 1] == b[j - 1] {
            out.push(DiffLine::Same(a[i - 1].to_string()));
            i -= 1;
            j -= 1;
        } else if lcs[i][j - 1] >= lcs[i - 1][j] {
            out.push(DiffLine::Added(b[j - 1].to_string()));
            j -= 1;
        } else {
            out.push(DiffLine::Removed(a[i - 1].to_string()));
            i -= 1;
        }
    }
    while i > 0 {
        out.push(DiffLine::Removed(a[i - 1].to_string()));
        i -= 1;
    }
    while j > 0 {
        out.push(DiffLine::Added(b[j - 1].to_string()));
        j -= 1;
    }
    out.reverse();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_identical_is_all_same() {
        let d = line_diff("a\nb\nc", "a\nb\nc");
        assert!(d.iter().all(|l| matches!(l, DiffLine::Same(_))));
    }

    #[test]
    fn diff_addition_only() {
        let d = line_diff("a\nb", "a\nb\nc");
        assert_eq!(d.last(), Some(&DiffLine::Added("c".into())));
    }

    #[test]
    fn diff_replacement() {
        let d = line_diff("challenge: Math", "challenge: Yes");
        let added: Vec<_> = d.iter().filter_map(|l| {
            if let DiffLine::Added(s) = l { Some(s.clone()) } else { None }
        }).collect();
        let removed: Vec<_> = d.iter().filter_map(|l| {
            if let DiffLine::Removed(s) = l { Some(s.clone()) } else { None }
        }).collect();
        assert_eq!(added, vec!["challenge: Yes".to_string()]);
        assert_eq!(removed, vec!["challenge: Math".to_string()]);
    }

    #[test]
    fn render_yaml_round_trips() {
        let s = Settings::default();
        let out = render_yaml(&s);
        let parsed: Settings = serde_yaml::from_str(&out).unwrap();
        let _ = parsed;
    }

    #[test]
    fn first_change_offset_no_changes_starts_at_top() {
        // No changes → start from the top so the user sees the YAML header.
        let diff = vec![
            DiffLine::Same("challenge: Math".into()),
            DiffLine::Same("min_severity: High".into()),
        ];
        assert_eq!(first_change_offset(&diff, 30, 3), 0);
    }

    #[test]
    fn first_change_offset_change_in_visible_window_is_zero() {
        // Change at line 5; visible_height 30 → already visible, no scroll.
        let mut diff: Vec<DiffLine> = (0..20).map(|i| DiffLine::Same(format!("l{i}"))).collect();
        diff[5] = DiffLine::Added("changed".into());
        assert_eq!(first_change_offset(&diff, 30, 3), 0);
    }

    #[test]
    fn first_change_offset_positions_change_near_bottom_of_window() {
        // 70-line diff, change at line 50, visible_height 28, tail 3 →
        // offset places the change near the bottom of the visible window
        // so most of the unchanged YAML BEFORE it stays visible.
        // Expected: offset = (50 + 3 + 1) - 28 = 26. Visible: rows 26..54.
        // Change at 50 is at row 24 of the visible window (4th from bottom).
        let mut diff: Vec<DiffLine> = (0..70).map(|i| DiffLine::Same(format!("l{i}"))).collect();
        diff[50] = DiffLine::Added("changed".into());
        let offset = first_change_offset(&diff, 28, 3);
        assert_eq!(offset, 26);
        // Sanity: the change must be in the visible window.
        assert!((offset..offset + 28).contains(&50),
            "change at index 50 must be visible from offset {offset} \
             with visible_height 28");
        // And there must be substantial context above the change.
        assert!(offset >= 20,
            "expected ≥20 lines of context above the change, got offset {offset}");
    }

    #[test]
    fn first_change_offset_clamps_to_max_when_change_is_near_end() {
        // Change at the very last line — offset can't exceed total-visible.
        let mut diff: Vec<DiffLine> = (0..70).map(|i| DiffLine::Same(format!("l{i}"))).collect();
        diff[69] = DiffLine::Added("last".into());
        let offset = first_change_offset(&diff, 28, 3);
        let max_offset = 70 - 28;
        assert_eq!(offset, max_offset);
    }

    #[test]
    fn settings_change_to_min_severity_is_reachable_via_auto_scroll() {
        // Regression: changing fields that come after the long enabled_groups
        // list (min_severity, audit_enabled, severity_escalation) used to
        // be invisible because the preview pane truncated. With auto-scroll,
        // the preview window snapped to the change must include those lines.
        use crate::checks::Severity;
        let mut original = Settings::default();
        original.audit_enabled = true;
        original.min_severity = Some(Severity::High);

        let mut current = original.clone();
        current.audit_enabled = false;
        current.min_severity = Some(Severity::Low);

        let original_yaml = render_yaml(&original);
        let current_yaml = render_yaml(&current);
        let diff = line_diff(&original_yaml, &current_yaml);

        // Pane shows ~28 visible rows.
        let offset = first_change_offset(&diff, 28, 3);

        // The visible slice [offset .. offset+28] must contain at least one
        // change line referencing min_severity OR audit_enabled.
        let visible: Vec<&DiffLine> = diff.iter().skip(offset).take(28).collect();
        let surfaces_change = visible.iter().any(|l| matches!(l,
            DiffLine::Added(s) | DiffLine::Removed(s)
            if s.contains("audit_enabled") || s.contains("min_severity")
        ));
        assert!(surfaces_change,
            "auto-scroll must place a change line in the visible window; \
             got offset={offset}, diff_len={}", diff.len());
    }
}
