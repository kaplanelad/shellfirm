#![cfg(feature = "tui")]

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::empty())
}

fn temp_config() -> shellfirm::Config {
    let mut p = std::env::temp_dir();
    p.push(format!("shellfirm-tui-app-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&p).unwrap();
    shellfirm::Config::new(Some(&p.display().to_string())).unwrap()
}

/// Regression: user reported that toggling Severity escalation off didn't
/// appear in the preview, and that matrix changes (e.g. medium → Yes)
/// also didn't appear. End-to-end key-flow test.
#[test]
fn escalation_toggle_off_marks_dirty_and_appears_in_diff() {
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    // Tab × 2 → Escalation tab
    app.handle_key(key(KeyCode::Tab));
    app.handle_key(key(KeyCode::Tab));
    assert_eq!(app.current_tab, 2);
    // First section is the severity-escalation toggle. Drill in.
    app.handle_key(key(KeyCode::Enter));
    // Space toggles enabled.
    let initial = app.draft.current.severity_escalation.enabled;
    app.handle_key(key(KeyCode::Char(' ')));
    let after = app.draft.current.severity_escalation.enabled;
    assert_ne!(initial, after, "Space must flip the toggle");
    // The draft must now be dirty.
    assert!(app.draft.is_dirty(),
        "toggling severity_escalation must mark the draft dirty");
    // The serialized YAML diff must contain the new value as an Added line
    // (or Removed for the old value).
    let current_yaml = shellfirm::tui::render_yaml(&app.draft.current);
    let diff = shellfirm::tui::preview::line_diff(&app.on_disk_yaml, &current_yaml);
    let has_change = diff.iter().any(|l| matches!(
        l,
        shellfirm::tui::preview::DiffLine::Added(s) | shellfirm::tui::preview::DiffLine::Removed(s)
        if s.contains("enabled:")
    ));
    assert!(has_change,
        "preview diff must surface the severity_escalation.enabled toggle. \
         Diff: {:?}", diff);
}

/// End-to-end render: drive the actual draw pipeline against TestBackend
/// and assert the diff for the toggled severity_escalation appears
/// somewhere in the rendered preview pane buffer. This catches bugs
/// downstream of `first_change_offset` (skip/take, area math, etc.).
#[test]
fn rendered_preview_buffer_contains_severity_escalation_change() {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    // Persist current YAML to disk so the diff has only the upcoming change.
    let yaml = shellfirm::tui::render_yaml(&app.draft.current);
    std::fs::write(&config.setting_file_path, &yaml).unwrap();
    app.on_disk_yaml = yaml;

    // Toggle severity_escalation off.
    app.draft.current.severity_escalation.enabled =
        !app.draft.current.severity_escalation.enabled;
    app.preview.mode = shellfirm::tui::app::PreviewMode::Open;
    app.preview.auto_scroll = true;

    // Render the whole frame at 130x32 (matches user's terminal size).
    let backend = TestBackend::new(130, 32);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| shellfirm::tui::render::draw(f, &app)).unwrap();
    let buf = terminal.backend().buffer();

    // Concatenate every cell into a single string for grep-style matching.
    let mut full = String::new();
    for y in 0..buf.area.height {
        for x in 0..buf.area.width {
            full.push_str(buf[(x, y)].symbol());
        }
        full.push('\n');
    }
    assert!(full.contains("enabled: false"),
        "rendered preview must contain the toggled value. Buffer:\n{full}");
}

/// Render-layer regression: matrix change must place an Added/Removed
/// line within the first `visible_height` rows of the rendered preview.
/// This catches bugs in `first_change_offset` or in the render loop's
/// skip/take logic — the layers downstream of the dirty draft.
#[test]
fn matrix_change_visible_in_rendered_preview_window() {
    use shellfirm::config::Challenge;
    use shellfirm::tui::preview::{first_change_offset, line_diff, render_yaml, DiffLine};
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    // Save current state to disk so on_disk_yaml is in sync with current.
    use std::fs;
    let yaml = render_yaml(&app.draft.current);
    fs::write(&config.setting_file_path, &yaml).unwrap();
    app.on_disk_yaml = yaml.clone();

    // Now mutate matrix: medium → Yes
    app.draft.current.severity_escalation.medium = Challenge::Yes;
    let new_yaml = render_yaml(&app.draft.current);
    let diff = line_diff(&app.on_disk_yaml, &new_yaml);

    // Simulate the preview pane: ~28 rows visible, 3 rows of top padding.
    let visible_height: usize = 28;
    let offset = first_change_offset(&diff, visible_height, 3);

    // Slice [offset, offset+visible_height) is what the user sees.
    let visible: Vec<&DiffLine> = diff.iter().skip(offset).take(visible_height).collect();

    let surfaces_change = visible.iter().any(|l| matches!(
        l,
        DiffLine::Added(s) | DiffLine::Removed(s) if s.contains("medium")
    ));
    assert!(surfaces_change,
        "rendered preview window must include the medium change. \
         offset={offset}, diff_len={}, visible_lines={}",
        diff.len(), visible.len());
}

/// Regression: quit dialog buttons must have a visible gap between every
/// pair (the old fixed-stride layout caused "[ Discard & quit ][ Cancel ]"
/// to render with zero space because "Discard & quit" filled its slot).
#[test]
fn quit_dialog_buttons_have_consistent_gaps() {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    // Mark dirty so 'q' opens the quit dialog.
    app.draft.current.challenge = shellfirm::config::Challenge::Yes;
    app.handle_key(key(KeyCode::Char('q')));
    assert!(matches!(
        app.modal,
        Some(shellfirm::tui::app::Modal::Quit(_))
    ));

    let backend = TestBackend::new(130, 32);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| shellfirm::tui::render::draw(f, &app)).unwrap();
    let buf = terminal.backend().buffer();

    // Find the row containing all three button labels.
    let mut row_text = None;
    for y in 0..buf.area.height {
        let mut line = String::new();
        for x in 0..buf.area.width {
            line.push_str(buf[(x, y)].symbol());
        }
        if line.contains("Save & quit")
            && line.contains("Discard & quit")
            && line.contains("Cancel")
        {
            row_text = Some(line);
            break;
        }
    }
    let row = row_text.expect("button row not found");

    // Adjacent buttons must not touch: there must be at least one space
    // between "]" of one button and "[" of the next.
    assert!(!row.contains("][") && !row.contains("] ["),
        "buttons must have ≥2 spaces between them. Row: {row:?}");
    // Stronger: enforce the explicit no-touching pattern.
    assert!(!row.contains("quit ][") ,
        "Discard & quit and Cancel must have a visible gap. Row: {row:?}");
    assert!(row.contains("]   [") || row.contains("]  ["),
        "expected at least 2 spaces between buttons. Row: {row:?}");
}

/// AUDIT: every editable TUI option must (a) map to a real Settings field
/// that gets serialized to YAML, and (b) produce a visible diff line in
/// the preview when changed. If any field is added to the UI but doesn't
/// reach the YAML, this test fails — forcing us to either wire it up or
/// remove the UI for it.
#[test]
fn every_tui_field_change_appears_in_preview_diff() {
    use shellfirm::checks::Severity;
    use shellfirm::config::{Challenge, InheritOr, LlmConfig};
    use shellfirm::tui::preview::{line_diff, render_yaml, DiffLine};

    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();

    // Snapshot the canonical baseline against current draft.
    let baseline = render_yaml(&app.draft.current);

    // Mutate one of every UI-editable field in the draft.
    let s = &mut app.draft.current;
    s.challenge = Challenge::Yes;
    s.min_severity = Some(Severity::Low);
    s.audit_enabled = !s.audit_enabled;
    s.blast_radius = !s.blast_radius;
    s.enabled_groups.push("custom_test_group".into());
    s.disabled_groups.push("aws".into());
    s.ignores_patterns_ids.push("ignore_test".into());
    s.deny_patterns_ids.push("deny_test".into());

    // context block
    s.context.protected_branches.push("audit_test_branch".into());
    s.context.production_k8s_patterns.push("audit_test_k8s".into());
    s.context.production_env_vars.insert("AUDIT_VAR".into(), "1".into());
    s.context.sensitive_paths.push("/audit/test/path".into());
    s.context.escalation.elevated = Challenge::Yes;
    s.context.escalation.critical = Challenge::Math;

    // escalation
    s.severity_escalation.enabled = !s.severity_escalation.enabled;
    s.severity_escalation.critical = Challenge::Math;
    s.severity_escalation.high = Challenge::Yes;
    s.severity_escalation.medium = Challenge::Yes;
    s.severity_escalation.low = Challenge::Yes;
    s.severity_escalation.info = Challenge::Yes;

    // agent (AI tab)
    s.agent.auto_deny_severity = Severity::Critical;
    s.agent.require_human_approval = !s.agent.require_human_approval;
    s.agent.challenge = InheritOr::Set(Challenge::Yes);
    s.agent.min_severity = InheritOr::Set(Some(Severity::Low));
    s.agent.severity_escalation = InheritOr::Set(s.severity_escalation.clone());

    // wrappers (Wrap tab)
    s.wrappers.challenge = InheritOr::Set(Challenge::Math);
    s.wrappers.min_severity = InheritOr::Set(Some(Severity::High));

    // llm (LLM tab)
    s.llm = Some(LlmConfig {
        provider: "test_provider".into(),
        model: "test_model".into(),
        base_url: Some("https://test.invalid".into()),
        timeout_ms: 12345,
        max_tokens: 999,
    });

    let after = render_yaml(&app.draft.current);
    let diff = line_diff(&baseline, &after);

    // Build a compact "change body" string of all Added/Removed lines.
    let body: String = diff.iter().filter_map(|l| match l {
        DiffLine::Added(s) | DiffLine::Removed(s) => Some(s.as_str()),
        DiffLine::Same(_) => None,
    }).collect::<Vec<_>>().join("\n");

    // For every field we mutated, assert at least one diff line mentions
    // the unique value or key we wrote. Parent keys like `enabled_groups:`
    // stay as Same when only their children change — that's correct YAML
    // diff behaviour — so we look for the unique values instead.
    let required_field_keys = [
        // global scalars
        "challenge: Yes",
        "min_severity: Low",
        "audit_enabled:", "blast_radius:",
        // unique pushed values
        "custom_test_group", "ignore_test", "deny_test",
        "audit_test_branch", "audit_test_k8s", "AUDIT_VAR",
        "/audit/test/path",
        // disabled_groups bumped from [] to ["aws"]
        "disabled_groups",
        // context.escalation
        "elevated: Yes",
        // severity_escalation
        "high: Yes", "medium: Yes", "low: Yes", "info: Yes",
        // agent
        "auto_deny_severity: Critical", "require_human_approval:",
        // llm — was None, now Some(...) with our values
        "test_provider", "test_model", "https://test.invalid",
        "timeout_ms: 12345", "max_tokens: 999",
    ];
    let mut missing: Vec<&str> = Vec::new();
    for field in required_field_keys {
        if !body.contains(field) {
            missing.push(field);
        }
    }
    assert!(missing.is_empty(),
        "fields edited in TUI must appear in preview diff. \
         Missing from diff: {missing:?}\n\nFull diff body:\n{body}");
}

/// Regression: at app init, the diff baseline (`on_disk_yaml`) must use
/// the SAME serializer as `current_yaml`. Otherwise HashMap ordering
/// differences (e.g. `production_env_vars`) appear as spurious changes,
/// and `first_change_offset` auto-scrolls past the user's actual edit.
#[test]
fn fresh_app_has_clean_preview_diff() {
    use shellfirm::tui::preview::{line_diff, render_yaml, DiffLine};
    let config = temp_config();
    // Write a file in a deliberately weird-but-valid order that diverges
    // from serde_yaml's canonical output.
    let nondeterministic_yaml = "\
context:
  production_env_vars:
    ZZZ_LAST: production
    AAA_FIRST: production
    NODE_ENV: production
challenge: Math
";
    std::fs::write(&config.setting_file_path, nondeterministic_yaml).unwrap();

    let app = shellfirm::tui::app::App::new(&config).unwrap();
    let current = render_yaml(&app.draft.current);
    let diff = line_diff(&app.on_disk_yaml, &current);

    let phantom_changes: Vec<_> = diff.iter().filter_map(|l| match l {
        DiffLine::Added(s) | DiffLine::Removed(s) => Some(s.clone()),
        DiffLine::Same(_) => None,
    }).collect();
    assert!(phantom_changes.is_empty(),
        "fresh app must have a clean diff (no spurious HashMap-ordering \
         differences). Got: {phantom_changes:?}");
}

/// Regression: user reported matrix cell changes (e.g. medium → Yes) not
/// reflecting in the preview.
#[test]
fn escalation_matrix_change_marks_dirty_and_appears_in_diff() {
    use shellfirm::config::Challenge;
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    app.handle_key(key(KeyCode::Tab));
    app.handle_key(key(KeyCode::Tab));
    assert_eq!(app.current_tab, 2);
    // Drill into the matrix section (section 1).
    app.escalation.section = 1;
    app.handle_key(key(KeyCode::Enter));
    // Down twice to row 2 (Medium), Right twice to col 2 (Yes), Space commits.
    app.handle_key(key(KeyCode::Down));
    app.handle_key(key(KeyCode::Down));
    app.handle_key(key(KeyCode::Right));
    app.handle_key(key(KeyCode::Right));
    app.handle_key(key(KeyCode::Char(' ')));
    assert_eq!(app.draft.current.severity_escalation.medium, Challenge::Yes);
    assert!(app.draft.is_dirty(),
        "matrix mutation must mark the draft dirty");
    let current_yaml = shellfirm::tui::render_yaml(&app.draft.current);
    let diff = shellfirm::tui::preview::line_diff(&app.on_disk_yaml, &current_yaml);
    let has_change = diff.iter().any(|l| matches!(
        l,
        shellfirm::tui::preview::DiffLine::Added(s) | shellfirm::tui::preview::DiffLine::Removed(s)
        if s.contains("medium:")
    ));
    assert!(has_change,
        "preview diff must surface medium: Yes. Diff: {:?}", diff);
}

#[test]
fn fresh_app_starts_on_general_tab() {
    let config = temp_config();
    let app = shellfirm::tui::app::App::new(&config).unwrap();
    assert_eq!(app.current_tab, 0);
    assert!(app.running);
}

#[test]
fn tab_key_moves_to_next_tab() {
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    assert_eq!(app.current_tab, 0);
    app.handle_key(key(KeyCode::Tab));
    assert_eq!(app.current_tab, 1);
}

#[test]
fn space_on_audit_marks_dirty() {
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    // Down twice to reach the Behavior section, Enter to drill in,
    // Space to toggle Audit, Esc to leave edit mode.
    app.handle_key(key(KeyCode::Down));
    app.handle_key(key(KeyCode::Down));
    app.handle_key(key(KeyCode::Enter));
    let initial = app.draft.is_dirty();
    app.handle_key(key(KeyCode::Char(' ')));
    app.handle_key(key(KeyCode::Esc));
    assert!(app.draft.is_dirty() && !initial);
}

#[test]
fn quit_when_clean_exits_immediately() {
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    assert!(app.running);
    app.handle_key(key(KeyCode::Char('q')));
    assert!(!app.running);
}

#[test]
fn quit_when_dirty_opens_modal() {
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    // Mutate to dirty
    // Mutate: drill into Behavior → toggle Audit
    app.handle_key(key(KeyCode::Down));
    app.handle_key(key(KeyCode::Down));
    app.handle_key(key(KeyCode::Enter));
    app.handle_key(key(KeyCode::Char(' ')));
    app.handle_key(key(KeyCode::Esc));
    assert!(app.draft.is_dirty());
    app.handle_key(key(KeyCode::Char('q')));
    assert!(matches!(
        app.modal,
        Some(shellfirm::tui::app::Modal::Quit(_))
    ));
    assert!(app.running);
}

#[test]
fn save_writes_file_and_clears_dirty() {
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    // Mutate: drill into Behavior → toggle Audit
    app.handle_key(key(KeyCode::Down));
    app.handle_key(key(KeyCode::Down));
    app.handle_key(key(KeyCode::Enter));
    app.handle_key(key(KeyCode::Char(' ')));
    app.handle_key(key(KeyCode::Esc));
    assert!(app.draft.is_dirty());
    // Save
    app.handle_key(key(KeyCode::Char('s')));
    assert!(matches!(
        app.modal,
        Some(shellfirm::tui::app::Modal::Save(_))
    ));
    app.handle_key(key(KeyCode::Enter));
    assert!(!app.draft.is_dirty());
    assert!(config.setting_file_path.exists());
}

#[test]
fn preview_pane_renders_scrollbar_when_content_overflows() {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use shellfirm::tui::app::PreviewMode;
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    app.preview.mode = PreviewMode::Open;
    // Force scroll offset > 0 so we should see the up arrow.
    app.preview.auto_scroll = false;
    app.preview.scroll = 10;

    let backend = TestBackend::new(130, 32);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| shellfirm::tui::render::draw(f, &app)).unwrap();
    let buf = terminal.backend().buffer();

    // Scrape the rightmost column of the preview pane (right 40% body).
    let mut right_col = String::new();
    for y in 0..buf.area.height {
        for x in 0..buf.area.width {
            right_col.push_str(buf[(x, y)].symbol());
        }
        right_col.push('\n');
    }
    // The default YAML is ~64 lines, way more than visible. Both arrows
    // and the thumb glyph must appear somewhere on screen.
    assert!(right_col.contains('▲'),
        "scrollbar must show ▲ when there is content above the window");
    assert!(right_col.contains('▼'),
        "scrollbar must show ▼ when there is content below the window");
    assert!(right_col.contains('█'),
        "scrollbar must show a thumb glyph (█)");
}

#[test]
fn preview_p_toggles_open_and_closed() {
    use shellfirm::tui::app::PreviewMode;
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    assert_eq!(app.preview.mode, PreviewMode::Closed);
    app.handle_key(key(KeyCode::Char('p')));
    assert_eq!(app.preview.mode, PreviewMode::Open);
    app.handle_key(key(KeyCode::Char('p')));
    assert_eq!(app.preview.mode, PreviewMode::Closed);
}

#[test]
fn preview_pagedown_scrolls_and_disables_auto_scroll() {
    use shellfirm::tui::app::PreviewMode;
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    app.preview.mode = PreviewMode::Open;
    app.preview.auto_scroll = true;
    let initial = app.preview.scroll;
    app.handle_key(key(KeyCode::PageDown));
    assert!(app.preview.scroll > initial,
        "PageDown must increment the scroll offset");
    assert!(!app.preview.auto_scroll,
        "manual scroll must disable auto-scroll-to-change");
}

#[test]
fn preview_shift_down_scrolls_one_line() {
    use crossterm::event::{KeyEvent, KeyModifiers};
    use shellfirm::tui::app::PreviewMode;
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    app.preview.mode = PreviewMode::Open;
    app.preview.auto_scroll = true;
    let initial = app.preview.scroll;
    app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::SHIFT));
    assert_eq!(app.preview.scroll, initial + 1,
        "Shift+Down must scroll preview by one line");
    assert!(!app.preview.auto_scroll);
}

#[test]
fn preview_shift_up_after_scroll_decrements() {
    use crossterm::event::{KeyEvent, KeyModifiers};
    use shellfirm::tui::app::PreviewMode;
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    app.preview.mode = PreviewMode::Open;
    app.preview.scroll = 5;
    app.preview.auto_scroll = false;
    app.handle_key(KeyEvent::new(KeyCode::Up, KeyModifiers::SHIFT));
    assert_eq!(app.preview.scroll, 4);
}

#[test]
fn preview_pageup_does_nothing_when_closed() {
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    let scroll_before = app.preview.scroll;
    let auto_before = app.preview.auto_scroll;
    app.handle_key(key(KeyCode::PageUp));
    assert_eq!(app.preview.scroll, scroll_before);
    assert_eq!(app.preview.auto_scroll, auto_before);
}

#[test]
fn save_dialog_cancel_keeps_dirty() {
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    // Mutate: navigate to Behavior section → drill in → toggle Audit
    app.handle_key(key(KeyCode::Down));
    app.handle_key(key(KeyCode::Down));
    app.handle_key(key(KeyCode::Enter));
    app.handle_key(key(KeyCode::Char(' ')));
    app.handle_key(key(KeyCode::Esc));
    assert!(app.draft.is_dirty());
    // Open save dialog
    app.handle_key(key(KeyCode::Char('s')));
    assert!(matches!(
        app.modal,
        Some(shellfirm::tui::app::Modal::Save(_))
    ));
    // Tab to Cancel button
    app.handle_key(key(KeyCode::Tab));
    // Press Enter on Cancel
    app.handle_key(key(KeyCode::Enter));
    assert!(app.modal.is_none());
    // File still does NOT exist (since save was cancelled)
    assert!(!config.setting_file_path.exists());
    assert!(app.draft.is_dirty());
}

#[test]
fn quit_modal_discard_exits() {
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    // Mutate: drill into Behavior → toggle Audit
    app.handle_key(key(KeyCode::Down));
    app.handle_key(key(KeyCode::Down));
    app.handle_key(key(KeyCode::Enter));
    app.handle_key(key(KeyCode::Char(' ')));
    app.handle_key(key(KeyCode::Esc));
    assert!(app.draft.is_dirty());
    app.handle_key(key(KeyCode::Char('q')));
    // Tab to Discard button (button 1)
    app.handle_key(key(KeyCode::Tab));
    // Enter
    app.handle_key(key(KeyCode::Enter));
    assert!(!app.running);
    assert!(!config.setting_file_path.exists());
}

#[test]
fn quit_modal_cancel_keeps_running() {
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    app.handle_key(key(KeyCode::Down));
    app.handle_key(key(KeyCode::Down));
    app.handle_key(key(KeyCode::Enter));
    app.handle_key(key(KeyCode::Char(' ')));
    app.handle_key(key(KeyCode::Esc));
    app.handle_key(key(KeyCode::Char('q')));
    // Tab twice → Cancel
    app.handle_key(key(KeyCode::Tab));
    app.handle_key(key(KeyCode::Tab));
    app.handle_key(key(KeyCode::Enter));
    assert!(app.running);
    assert!(app.modal.is_none());
}

#[test]
fn reset_dialog_resets_draft() {
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    // Mutate: navigate to Behavior section → drill in → toggle Audit
    app.handle_key(key(KeyCode::Down));
    app.handle_key(key(KeyCode::Down));
    app.handle_key(key(KeyCode::Enter));
    app.handle_key(key(KeyCode::Char(' ')));
    app.handle_key(key(KeyCode::Esc));
    assert!(app.draft.is_dirty());
    // Open reset
    app.handle_key(key(KeyCode::Char('r')));
    // Default button = Reset (0). Press Enter.
    app.handle_key(key(KeyCode::Enter));
    assert!(app.modal.is_none());
    assert!(!app.draft.is_dirty());
}

#[test]
fn help_modal_esc_closes() {
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    app.handle_key(key(KeyCode::Char('?')));
    assert!(matches!(app.modal, Some(shellfirm::tui::app::Modal::Help)));
    app.handle_key(key(KeyCode::Esc));
    assert!(app.modal.is_none());
}

#[test]
fn ai_tab_min_severity_override_set_and_reset() {
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    // Move to AI tab (5 Tab presses across the global tab bar).
    for _ in 0..5 {
        app.handle_key(key(KeyCode::Tab));
    }
    // Inside AI tab, the new model has 5 sections; OvrMinSev is section 3.
    app.ai.cursor = 3;
    // Drill in. Cursor sits on Inherit (index 0). Down → "(all)" (index 1) → Space commits.
    app.handle_key(key(KeyCode::Enter));
    app.handle_key(key(KeyCode::Down));
    app.handle_key(key(KeyCode::Char(' ')));
    assert!(matches!(
        app.draft.current.agent.min_severity,
        shellfirm::config::InheritOr::Set(_)
    ));
    // Move back up to Inherit (index 0) and Space commits — still in edit mode.
    for _ in 0..6 {
        app.handle_key(key(KeyCode::Up));
    }
    app.handle_key(key(KeyCode::Char(' ')));
    assert!(matches!(
        app.draft.current.agent.min_severity,
        shellfirm::config::InheritOr::Inherit
    ));
}

#[test]
fn custom_tab_create_check_flow() {
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    // Navigate to Custom tab (index 8)
    for _ in 0..8 {
        app.handle_key(key(KeyCode::Tab));
    }
    // Press + to open form
    app.handle_key(key(KeyCode::Char('+')));
    assert!(app.form.is_some());
    // Esc cancels
    app.handle_key(key(KeyCode::Esc));
    assert!(app.form.is_none());
}

#[test]
fn escalation_matrix_right_arrow_changes_column_not_tab() {
    use shellfirm::config::Challenge;
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    // Navigate to Escalation tab (index 2)
    app.handle_key(key(KeyCode::Tab));
    app.handle_key(key(KeyCode::Tab));
    assert_eq!(app.current_tab, 2);
    // Drill into the matrix section (section 1).
    app.escalation.section = 1;
    app.handle_key(key(KeyCode::Enter));
    // Inside the matrix: Down once to row 1 (High), then Right twice to col 2 (Yes), Space commits.
    app.handle_key(key(KeyCode::Down));
    let tab_before = app.current_tab;
    app.handle_key(key(KeyCode::Right));
    assert_eq!(app.current_tab, tab_before, "Right arrow must not switch tabs");
    app.handle_key(key(KeyCode::Right));
    app.handle_key(key(KeyCode::Char(' ')));
    assert_eq!(app.draft.current.severity_escalation.high, Challenge::Yes);
}

fn make_test_check(id: &str, from: &str) -> shellfirm::checks::Check {
    shellfirm::checks::Check {
        id: id.into(),
        test: regex::Regex::new("foo").unwrap(),
        description: "x".into(),
        from: from.into(),
        challenge: shellfirm::config::Challenge::Math,
        filters: vec![],
        alternative: None,
        alternative_info: None,
        severity: shellfirm::checks::Severity::Medium,
    }
}

#[test]
fn delete_custom_check_requires_confirmation_modal() {
    let config = temp_config();
    // Seed a custom check on disk
    let store = shellfirm::tui::CustomCheckStore::new(config.custom_checks_dir());
    store.add(&make_test_check("my:foo", "my")).unwrap();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    // Navigate to Custom tab
    for _ in 0..8 {
        app.handle_key(key(KeyCode::Tab));
    }
    assert_eq!(app.custom.checks.len(), 1);
    // Press 'd' — should open confirm modal, NOT delete
    app.handle_key(key(KeyCode::Char('d')));
    assert!(matches!(
        app.modal,
        Some(shellfirm::tui::app::Modal::DeleteCustom(_))
    ));
    assert_eq!(app.custom.checks.len(), 1, "delete must be deferred");
    // Default button is Cancel (1). Press Enter on Cancel.
    app.handle_key(key(KeyCode::Enter));
    assert!(app.modal.is_none());
    assert_eq!(app.custom.checks.len(), 1, "Cancel must keep the check");

    // Now actually delete: press 'd' → Tab to Delete (button 0) → Enter
    app.handle_key(key(KeyCode::Char('d')));
    app.handle_key(key(KeyCode::Tab));
    app.handle_key(key(KeyCode::Enter));
    assert!(app.modal.is_none());
    assert!(app.custom.checks.is_empty(), "confirmed delete must remove");
}

#[test]
fn adding_custom_check_with_new_group_appears_in_groups_tab() {
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    // Initially no custom groups
    assert!(app.groups.custom_groups.is_empty());

    // Add a check via the store + reload — same path the app uses after a
    // form save — then sync custom_groups using the helper.
    app.custom
        .store
        .add(&make_test_check("my_team:bar", "my_team"))
        .unwrap();
    app.custom.reload();

    // The fix wires this refresh into the FormOutcome::Saved handler.
    let mut groups: Vec<String> = Vec::new();
    for c in &app.custom.checks {
        if !groups.contains(&c.from) { groups.push(c.from.clone()); }
    }
    app.groups.custom_groups = groups;

    assert!(app.groups.custom_groups.iter().any(|g| g == "my_team"));
}

#[test]
fn left_right_arrows_switch_top_level_tabs() {
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    let initial_tab = app.current_tab;
    app.handle_key(key(KeyCode::Right));
    assert_eq!(app.current_tab, initial_tab + 1,
        "Right arrow should advance the top-level tab");
    app.handle_key(key(KeyCode::Left));
    assert_eq!(app.current_tab, initial_tab,
        "Left arrow should go back to the previous tab");
}
