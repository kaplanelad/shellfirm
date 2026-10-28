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
    assert!(
        app.draft.is_dirty(),
        "toggling severity_escalation must mark the draft dirty"
    );
    // The serialized YAML diff must contain the new value as an Added line
    // (or Removed for the old value).
    let current_yaml = shellfirm::tui::render_yaml(&app.draft.current);
    let diff = shellfirm::tui::preview::line_diff(&app.on_disk_yaml, &current_yaml);
    let has_change = diff.iter().any(|l| matches!(
        l,
        shellfirm::tui::preview::DiffLine::Added(s) | shellfirm::tui::preview::DiffLine::Removed(s)
        if s.contains("enabled:")
    ));
    assert!(
        has_change,
        "preview diff must surface the severity_escalation.enabled toggle. \
         Diff: {:?}",
        diff
    );
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
    app.draft.current.severity_escalation.enabled = !app.draft.current.severity_escalation.enabled;
    app.preview.mode = shellfirm::tui::app::PreviewMode::Open;
    app.preview.auto_scroll = true;

    // Render the whole frame at 130x32 (matches user's terminal size).
    let backend = TestBackend::new(130, 32);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|f| shellfirm::tui::render::draw(f, &app))
        .unwrap();
    let buf = terminal.backend().buffer();

    // Concatenate every cell into a single string for grep-style matching.
    let mut full = String::new();
    for y in 0..buf.area.height {
        for x in 0..buf.area.width {
            full.push_str(buf[(x, y)].symbol());
        }
        full.push('\n');
    }
    assert!(
        full.contains("enabled: false"),
        "rendered preview must contain the toggled value. Buffer:\n{full}"
    );
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

    let surfaces_change = visible.iter().any(|l| {
        matches!(
            l,
            DiffLine::Added(s) | DiffLine::Removed(s) if s.contains("medium")
        )
    });
    assert!(
        surfaces_change,
        "rendered preview window must include the medium change. \
         offset={offset}, diff_len={}, visible_lines={}",
        diff.len(),
        visible.len()
    );
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
    terminal
        .draw(|f| shellfirm::tui::render::draw(f, &app))
        .unwrap();
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
    assert!(
        !row.contains("][") && !row.contains("] ["),
        "buttons must have ≥2 spaces between them. Row: {row:?}"
    );
    // Stronger: enforce the explicit no-touching pattern.
    assert!(
        !row.contains("quit ]["),
        "Discard & quit and Cancel must have a visible gap. Row: {row:?}"
    );
    assert!(
        row.contains("]   [") || row.contains("]  ["),
        "expected at least 2 spaces between buttons. Row: {row:?}"
    );
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
    s.context
        .protected_branches
        .push("audit_test_branch".into());
    s.context
        .production_k8s_patterns
        .push("audit_test_k8s".into());
    s.context
        .production_env_vars
        .insert("AUDIT_VAR".into(), "1".into());
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
    let body: String = diff
        .iter()
        .filter_map(|l| match l {
            DiffLine::Added(s) | DiffLine::Removed(s) => Some(s.as_str()),
            DiffLine::Same(_) => None,
        })
        .collect::<Vec<_>>()
        .join("\n");

    // For every field we mutated, assert at least one diff line mentions
    // the unique value or key we wrote. Parent keys like `enabled_groups:`
    // stay as Same when only their children change — that's correct YAML
    // diff behaviour — so we look for the unique values instead.
    let required_field_keys = [
        // global scalars
        "challenge: Yes",
        "min_severity: Low",
        "audit_enabled:",
        "blast_radius:",
        // unique pushed values
        "custom_test_group",
        "ignore_test",
        "deny_test",
        "audit_test_branch",
        "audit_test_k8s",
        "AUDIT_VAR",
        "/audit/test/path",
        // disabled_groups bumped from [] to ["aws"]
        "disabled_groups",
        // context.escalation
        "elevated: Yes",
        // severity_escalation
        "high: Yes",
        "medium: Yes",
        "low: Yes",
        "info: Yes",
        // agent
        "auto_deny_severity: Critical",
        "require_human_approval:",
        // llm — was None, now Some(...) with our values
        "test_provider",
        "test_model",
        "https://test.invalid",
        "timeout_ms: 12345",
        "max_tokens: 999",
    ];
    let mut missing: Vec<&str> = Vec::new();
    for field in required_field_keys {
        if !body.contains(field) {
            missing.push(field);
        }
    }
    assert!(
        missing.is_empty(),
        "fields edited in TUI must appear in preview diff. \
         Missing from diff: {missing:?}\n\nFull diff body:\n{body}"
    );
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

    let phantom_changes: Vec<_> = diff
        .iter()
        .filter_map(|l| match l {
            DiffLine::Added(s) | DiffLine::Removed(s) => Some(s.clone()),
            DiffLine::Same(_) => None,
        })
        .collect();
    assert!(
        phantom_changes.is_empty(),
        "fresh app must have a clean diff (no spurious HashMap-ordering \
         differences). Got: {phantom_changes:?}"
    );
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
    assert!(
        app.draft.is_dirty(),
        "matrix mutation must mark the draft dirty"
    );
    let current_yaml = shellfirm::tui::render_yaml(&app.draft.current);
    let diff = shellfirm::tui::preview::line_diff(&app.on_disk_yaml, &current_yaml);
    let has_change = diff.iter().any(|l| matches!(
        l,
        shellfirm::tui::preview::DiffLine::Added(s) | shellfirm::tui::preview::DiffLine::Removed(s)
        if s.contains("medium:")
    ));
    assert!(
        has_change,
        "preview diff must surface medium: Yes. Diff: {:?}",
        diff
    );
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
    terminal
        .draw(|f| shellfirm::tui::render::draw(f, &app))
        .unwrap();
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
    assert!(
        right_col.contains('▲'),
        "scrollbar must show ▲ when there is content above the window"
    );
    assert!(
        right_col.contains('▼'),
        "scrollbar must show ▼ when there is content below the window"
    );
    assert!(
        right_col.contains('█'),
        "scrollbar must show a thumb glyph (█)"
    );
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
    assert!(
        app.preview.scroll > initial,
        "PageDown must increment the scroll offset"
    );
    assert!(
        !app.preview.auto_scroll,
        "manual scroll must disable auto-scroll-to-change"
    );
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
    assert_eq!(
        app.preview.scroll,
        initial + 1,
        "Shift+Down must scroll preview by one line"
    );
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
    assert_eq!(
        app.current_tab, tab_before,
        "Right arrow must not switch tabs"
    );
    app.handle_key(key(KeyCode::Right));
    app.handle_key(key(KeyCode::Char(' ')));
    assert_eq!(app.draft.current.severity_escalation.high, Challenge::Yes);
}

fn make_test_check(id: &str, from: &str) -> shellfirm::checks::Check {
    shellfirm::checks::Check {
        id: id.into(),
        test: regex::Regex::new("foo").unwrap().into(),
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
        if !groups.contains(&c.from) {
            groups.push(c.from.clone());
        }
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
    assert_eq!(
        app.current_tab,
        initial_tab + 1,
        "Right arrow should advance the top-level tab"
    );
    app.handle_key(key(KeyCode::Left));
    assert_eq!(
        app.current_tab, initial_tab,
        "Left arrow should go back to the previous tab"
    );
}

/// Global hotkeys (q/s/r/p) must not fire while typing into a text field.
#[test]
fn global_hotkeys_do_not_fire_while_typing_a_branch_name() {
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    for _ in 0..3 {
        app.handle_key(key(KeyCode::Tab));
    }
    assert_eq!(app.current_tab, 3);
    app.handle_key(key(KeyCode::Enter)); // drill into protected branches
    app.handle_key(key(KeyCode::Char('+')));
    for c in "sqrp-staging".chars() {
        app.handle_key(key(KeyCode::Char(c)));
        assert!(app.modal.is_none(), "typing {c:?} opened a modal");
        assert!(app.running);
    }
    app.handle_key(key(KeyCode::Enter));
    assert!(app
        .draft
        .current
        .context
        .protected_branches
        .contains(&"sqrp-staging".to_string()));
}

/// In the Custom tab `r` reloads (as labelled) instead of opening Reset.
#[test]
fn custom_tab_r_reloads_instead_of_reset_modal() {
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    app.current_tab = 8;
    app.handle_key(key(KeyCode::Char('r')));
    assert!(app.modal.is_none());
}

/// The TUI refuses to open (and later overwrite) an invalid settings file.
#[test]
fn tui_refuses_invalid_settings_file() {
    let config = temp_config();
    std::fs::write(&config.setting_file_path, "challenge: Banana\n").unwrap();
    assert!(shellfirm::tui::app::App::new(&config).is_err());
    assert_eq!(
        std::fs::read_to_string(&config.setting_file_path).unwrap(),
        "challenge: Banana\n"
    );
}

fn render_text(app: &shellfirm::tui::app::App, w: u16, h: u16) -> Vec<String> {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
    terminal
        .draw(|f| shellfirm::tui::render::draw(f, app))
        .unwrap();
    let buf = terminal.backend().buffer().clone();
    (0..h)
        .map(|y| (0..w).map(|x| buf[(x, y)].symbol().to_string()).collect())
        .collect()
}

/// Round-2 (Noor F3): at the advertised minimum size every tab used to be
/// blank. Each tab must now render content in its body.
#[test]
fn every_tab_renders_at_minimum_size() {
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    for (w, h) in [(60u16, 16u16), (60, 19), (80, 24)] {
        for tab in 0..shellfirm::tui::app::NUM_TABS {
            app.current_tab = tab;
            let lines = render_text(&app, w, h);
            // Body = everything between the tab bar and the 3 footer rows.
            let body: String = lines[1..lines.len() - 3].concat();
            assert!(
                body.trim().len() > 10,
                "tab {tab} is blank at {w}x{h}:\n{}",
                lines.join("\n")
            );
            // The active tab is marked without colour.
            assert!(lines[0].contains('['), "no active-tab marker: {}", lines[0]);
        }
    }
}

#[test]
fn too_small_message_fits_the_terminal() {
    let config = temp_config();
    let app = shellfirm::tui::app::App::new(&config).unwrap();
    let lines = render_text(&app, 40, 8);
    let all = lines.join(" ");
    assert!(all.contains("60"), "{all}");
    assert!(all.contains("16"), "{all}");
    assert!(all.contains("config show"), "{all}");
}

/// Round-2 (Noor F3): the help overlay was clipped at 80x24; it now wraps
/// and scrolls so every binding (down to `?`) can be reached.
#[test]
fn help_overlay_scrolls_to_the_end_at_80x24() {
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    app.handle_key(key(KeyCode::Char('?')));
    let first = render_text(&app, 80, 24).join("\n");
    assert!(first.contains("Keyboard shortcuts"));
    for _ in 0..40 {
        app.handle_key(key(KeyCode::Down));
        let _ = render_text(&app, 80, 24);
    }
    let last = render_text(&app, 80, 24).join("\n");
    assert!(last.contains("[ai]"), "{last}");
    assert!(last.contains("show or hide this help"), "{last}");
    app.handle_key(key(KeyCode::Esc));
    assert!(app.modal.is_none());
}

/// Round-2 (Noor F2, Lena N13): an unknown id in the deny list must not
/// be reported as a valid configuration.
#[test]
fn save_rejects_unknown_check_ids() {
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    app.draft.current.deny_patterns_ids = vec!["git:forcepush".into()];
    app.handle_key(key(KeyCode::Char('s')));
    match &app.modal {
        Some(shellfirm::tui::app::Modal::Save(state)) => match &state.stage {
            shellfirm::tui::app::SaveStage::Errors(errs) => {
                assert!(errs[0].message.contains("git:force_push"), "{errs:?}");
            }
            other => panic!("expected errors, got {other:?}"),
        },
        other => panic!("expected save modal, got {other:?}"),
    }
    let text = render_text(&app, 100, 30).join("\n");
    assert!(
        !text.contains("Valid configuration") || text.contains("Invalid"),
        "{text}"
    );
}

/// The Ignore/Deny picker does not offer "use as new value" for an
/// unknown id; Enter on it adds nothing.
#[test]
fn ignore_deny_picker_does_not_accept_unknown_ids() {
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    app.current_tab = 4;
    app.handle_key(key(KeyCode::Down)); // Deny section
    app.handle_key(key(KeyCode::Enter));
    for c in "git:forcepush".chars() {
        app.handle_key(key(KeyCode::Char(c)));
    }
    let text = render_text(&app, 100, 30).join("\n");
    assert!(!text.contains("as new value"), "{text}");
    assert!(text.contains("Unknown check id"), "{text}");
    app.handle_key(key(KeyCode::Enter));
    assert!(app.draft.current.deny_patterns_ids.is_empty());
}

/// Round-2 (Lena N3): saving with a custom-check group must not pin the
/// full `enabled_groups` list in the settings file.
#[test]
fn save_with_custom_group_keeps_settings_sparse() {
    let config = temp_config();
    let dir = config.custom_checks_dir();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("team.yaml"),
        "- id: team:deploy\n  from: team\n  test: tdeploy\n  description: d\n",
    )
    .unwrap();
    std::fs::write(&config.setting_file_path, "challenge: Math\n").unwrap();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    assert!(app.draft.current.enabled_groups.iter().any(|g| g == "team"));
    app.draft.current.challenge = shellfirm::config::Challenge::Yes;
    app.handle_key(key(KeyCode::Char('s')));
    app.handle_key(key(KeyCode::Enter));
    let written = std::fs::read_to_string(&config.setting_file_path).unwrap();
    assert!(written.contains("challenge: Yes"), "{written}");
    assert!(!written.contains("enabled_groups"), "{written}");
}

/// The text caret is drawn at the insertion point, and the terminal
/// cursor is placed there (Noor F5).
#[test]
fn custom_check_form_caret_follows_cursor() {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    app.current_tab = 8;
    app.handle_key(key(KeyCode::Char('+')));
    assert!(app.form.is_some());
    for c in "abcdef".chars() {
        app.handle_key(key(KeyCode::Char(c)));
    }
    for _ in 0..3 {
        app.handle_key(key(KeyCode::Left));
    }
    let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
    terminal
        .draw(|f| shellfirm::tui::render::draw(f, &app))
        .unwrap();
    let pos = terminal.get_cursor_position().unwrap();
    let buf = terminal.backend().buffer();
    assert_eq!(buf[(pos.x, pos.y)].symbol(), "d", "cursor at {pos:?}");
}

// ── Round 4 (Noor R4-1..R4-6) ──────────────────────────────────────────

fn ch(c: char) -> KeyEvent {
    key(KeyCode::Char(c))
}

/// Settings with long lists everywhere, so list editors overflow.
fn seeded_config() -> shellfirm::Config {
    let config = temp_config();
    let mut yaml = String::from("ignores_patterns_ids:\n");
    for id in [
        "git:force_push",
        "git:reset",
        "fs:recursively_delete",
        "git:delete_branch",
        "git:clean",
        "git:rebase",
        "git:checkout",
        "git:stash_drop",
    ] {
        yaml.push_str(&format!("  - {id}\n"));
    }
    yaml.push_str("context:\n  protected_branches:\n");
    for i in 0..12 {
        yaml.push_str(&format!("    - release/{i}\n"));
    }
    yaml.push_str("  production_env_vars:\n");
    for i in 0..9 {
        yaml.push_str(&format!("    VAR{i}: prod\n"));
    }
    std::fs::write(&config.setting_file_path, yaml).unwrap();
    config
}

/// Key sequences (applied to a fresh App on a given tab) that reach every
/// browse/edit/add state and every modal.
fn ui_states() -> Vec<(String, usize, Vec<KeyEvent>)> {
    let mut out = Vec::new();
    for tab in 0..shellfirm::tui::app::NUM_TABS {
        out.push((format!("tab{tab} browse"), tab, vec![]));
        for down in 0..5 {
            let mut keys: Vec<KeyEvent> = (0..down).map(|_| key(KeyCode::Down)).collect();
            keys.push(key(KeyCode::Enter));
            out.push((format!("tab{tab} section{down} edit"), tab, keys.clone()));
            // Scroll to the end of the edited list.
            let mut deep = keys.clone();
            deep.extend((0..15).map(|_| key(KeyCode::Down)));
            out.push((format!("tab{tab} section{down} edit deep"), tab, deep));
            let mut add = keys.clone();
            add.push(ch('+'));
            out.push((format!("tab{tab} section{down} add"), tab, add.clone()));
            add.extend("release/גרסה-*".chars().map(ch));
            add.push(key(KeyCode::Left));
            out.push((
                format!("tab{tab} section{down} add typed"),
                tab,
                add.clone(),
            ));
            if tab == 3 {
                // Env vars: key, Enter, then the value field.
                add.push(key(KeyCode::Enter));
                add.extend("value".chars().map(ch));
                out.push((format!("tab{tab} section{down} add value"), tab, add));
            }
            if tab != 4 {
                continue;
            }
            let mut zone = keys.clone();
            zone.extend("git".chars().map(ch));
            zone.push(key(KeyCode::Tab));
            zone.push(key(KeyCode::Down));
            out.push((format!("tab{tab} section{down} zone"), tab, zone));
        }
    }
    out.push(("help".into(), 0, vec![ch('?')]));
    out.push(("help end".into(), 0, vec![ch('?'), key(KeyCode::End)]));
    // Valid save with a diff (toggle audit in General → Behavior).
    let change = vec![
        key(KeyCode::Down),
        key(KeyCode::Down),
        key(KeyCode::Enter),
        ch(' '),
        key(KeyCode::Esc),
    ];
    let mut save = change.clone();
    save.push(ch('s'));
    out.push(("save valid".into(), 0, save.clone()));
    save.push(key(KeyCode::End));
    out.push(("save valid end".into(), 0, save));
    let mut quit = change.clone();
    quit.push(ch('q'));
    out.push(("quit dialog".into(), 0, quit));
    out.push(("reset dialog".into(), 0, vec![ch('r')]));
    out.push(("preview".into(), 0, vec![ch('p')]));
    let mut preview = change;
    preview.push(ch('p'));
    out.push(("preview dirty".into(), 0, preview));
    out
}

fn draw_once(app: &shellfirm::tui::app::App, w: u16, h: u16) {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
    terminal
        .draw(|f| shellfirm::tui::render::draw(f, app))
        .unwrap();
}

/// Noor R4-1: pressing `+` in a Context list panicked at 80x24 (the row was
/// drawn one below the buffer). Every tab, edit/add state and modal must
/// render at any terminal size without panicking.
#[test]
fn every_state_renders_at_every_size_without_panicking() {
    // Kept small enough for a debug-build CI run; the list sizes below
    // straddle the minimum size and the rows where the R4-1 panic began.
    let widths = [20u16, 60, 80, 100, 200];
    let heights = [5u16, 16, 22, 24, 25, 60];
    let mut failures = Vec::new();
    for seeded in [false, true] {
        for (name, tab, keys) in ui_states() {
            // Long lists matter for every state; the default settings only
            // for the entry points.
            if !seeded && !name.ends_with("browse") && !name.ends_with(" add") {
                continue;
            }
            let config = if seeded {
                seeded_config()
            } else {
                temp_config()
            };
            let mut app = shellfirm::tui::app::App::new(&config).unwrap();
            app.current_tab = tab;
            for k in &keys {
                app.handle_key(*k);
            }
            for &w in &widths {
                for &h in &heights {
                    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        draw_once(&app, w, h);
                    }));
                    if r.is_err() {
                        failures.push(format!("{name} (seeded={seeded}) at {w}x{h}"));
                    }
                }
            }
            // The exact sizes from the report, too.
            for (w, h) in [(60u16, 24u16), (80, 23), (40, 30), (120, 30)] {
                if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| draw_once(&app, w, h)))
                    .is_err()
                {
                    failures.push(format!("{name} (seeded={seeded}) at {w}x{h}"));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "render panicked:\n{}",
        failures.join("\n")
    );
}

fn open_context_add(app: &mut shellfirm::tui::app::App) {
    app.current_tab = 3;
    app.handle_key(key(KeyCode::Enter));
    app.handle_key(ch('+'));
}

/// Noor R4-1/R4-5: at 80x24 the New entry row is visible (the tab scrolls)
/// and no tab text is painted into the footer rows.
#[test]
fn context_add_row_is_visible_at_80x24_and_footer_is_clean() {
    let config = seeded_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    open_context_add(&mut app);
    for (w, h) in [(80u16, 24u16), (60, 16), (100, 24), (80, 22)] {
        let lines = render_text(&app, w, h);
        let all = lines.join("\n");
        assert!(all.contains("New entry"), "{w}x{h}:\n{all}");
        // Footer: field strip (2 rows) + hint bar.
        let footer = lines[lines.len() - 3..].join("\n");
        assert!(
            !footer.contains("risk level"),
            "{w}x{h} footer bleed:\n{footer}"
        );
        assert!(
            footer.matches("[all]").count() <= 1,
            "{w}x{h} footer bleed:\n{footer}"
        );
    }
}

/// Noor R4-3: Left/Right move the caret in the New entry field instead of
/// switching tabs, and the terminal cursor sits on the caret.
#[test]
fn context_new_entry_arrows_move_caret_not_tab() {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    open_context_add(&mut app);
    for c in "abcdef".chars() {
        app.handle_key(ch(c));
    }
    for _ in 0..3 {
        app.handle_key(key(KeyCode::Left));
    }
    assert_eq!(app.current_tab, 3, "Left switched the tab");
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal
        .draw(|f| shellfirm::tui::render::draw(f, &app))
        .unwrap();
    let pos = terminal.get_cursor_position().unwrap();
    assert_eq!(terminal.backend().buffer()[(pos.x, pos.y)].symbol(), "d");
    // Insert in the middle, Home/End, Right.
    app.handle_key(ch('X'));
    app.handle_key(key(KeyCode::Home));
    app.handle_key(ch('_'));
    app.handle_key(key(KeyCode::End));
    app.handle_key(key(KeyCode::Right));
    assert_eq!(app.current_tab, 3);
    app.handle_key(key(KeyCode::Enter));
    assert!(app
        .draft
        .current
        .context
        .protected_branches
        .contains(&"_abcXdef".to_string()));
}

/// Noor R4-2: in Ignore/Deny edit mode Tab switches to the entries list
/// (where `d` removes) instead of leaving the tab, and leaving the tab
/// closes the edit state.
#[test]
fn ignore_deny_tab_switches_zone_and_d_removes() {
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    app.current_tab = 4;
    app.handle_key(key(KeyCode::Down)); // Deny list
    app.handle_key(key(KeyCode::Enter));
    for c in "git:force_push".chars() {
        app.handle_key(ch(c));
    }
    app.handle_key(key(KeyCode::Enter));
    assert_eq!(app.draft.current.deny_patterns_ids, vec!["git:force_push"]);
    app.handle_key(key(KeyCode::Tab));
    assert_eq!(app.current_tab, 4, "Tab left the tab");
    assert!(
        app.focused_field.help.contains("d remove"),
        "{:?}",
        app.focused_field
    );
    app.handle_key(ch('d'));
    assert!(app.draft.current.deny_patterns_ids.is_empty());
    // Shift-Tab also stays in the tab.
    app.handle_key(key(KeyCode::BackTab));
    assert_eq!(app.current_tab, 4);
    // Esc, then leave with Tab: no hidden edit state on return.
    app.handle_key(key(KeyCode::Esc));
    app.handle_key(key(KeyCode::Tab));
    assert_eq!(app.current_tab, 5);
    app.handle_key(key(KeyCode::BackTab));
    assert_eq!(app.current_tab, 4);
    assert!(app.ignore_deny.edit.is_none());
}

/// Leaving a tab with Left/Right/Tab while a section is open closes it, so
/// browse keys on return never edit settings by accident.
#[test]
fn leaving_a_tab_closes_its_edit_state() {
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    app.current_tab = 4;
    app.handle_key(key(KeyCode::Down));
    app.handle_key(key(KeyCode::Enter)); // Deny list picker open
    app.handle_key(key(KeyCode::Right)); // picker ignores Right → next tab
    if app.current_tab == 4 {
        app.handle_key(key(KeyCode::Esc));
        app.handle_key(key(KeyCode::Right));
    }
    assert_eq!(app.current_tab, 5);
    assert!(app.ignore_deny.edit.is_none());
    app.handle_key(key(KeyCode::Left));
    app.handle_key(key(KeyCode::Down));
    app.handle_key(key(KeyCode::Enter));
    assert!(app.draft.current.deny_patterns_ids.is_empty());

    open_context_add(&mut app);
    app.handle_key(ch('z'));
    app.handle_key(key(KeyCode::Tab));
    assert_eq!(app.current_tab, 3, "Tab must stay in the open entry field");
    app.handle_key(key(KeyCode::Esc));
    app.handle_key(key(KeyCode::Tab));
    assert_eq!(app.current_tab, 4);
    assert!(app.context.edit.is_none());
}

/// Noor R4-4: the Save dialog fits a 60x16 window and its body scrolls,
/// with a `more` marker, so every error and the "did you mean" hint can be
/// reached.
#[test]
fn save_dialog_scrolls_at_60x16() {
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    app.draft.current.deny_patterns_ids = vec!["git:forcepush".into()];
    app.draft.current.ignores_patterns_ids = vec![
        "+".into(),
        "nope:one".into(),
        "nope:two".into(),
        "nope:three".into(),
    ];
    app.handle_key(ch('s'));
    let first = render_text(&app, 60, 16).join("\n");
    assert!(first.contains("Invalid configuration"), "{first}");
    assert!(first.contains("more"), "no more marker:\n{first}");
    app.handle_key(key(KeyCode::End));
    let last = render_text(&app, 60, 16).join("\n");
    assert!(last.contains("force_push"), "{last}");
    assert!(app.modal.is_some());
    app.handle_key(key(KeyCode::Esc));
    assert!(app.modal.is_none());
}

/// Noor R4-4: a valid save shows its diff at 60x16.
#[test]
fn save_dialog_shows_diff_at_60x16() {
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    app.draft.current.challenge = shellfirm::config::Challenge::Yes;
    app.handle_key(ch('s'));
    let text = render_text(&app, 60, 16).join("\n");
    assert!(text.contains("challenge: Yes"), "{text}");
    assert!(text.contains("Save ]"), "{text}");
}

/// Noor R4-6: the Behavior summary uses words, not ✓/✗.
#[test]
fn behavior_summary_uses_words() {
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    app.draft.current.audit_enabled = false;
    app.draft.current.blast_radius = true;
    let text = render_text(&app, 100, 30).join("\n");
    assert!(text.contains("Audit: off"), "{text}");
    assert!(text.contains("Blast radius: on"), "{text}");
}

// -- round 6 (Noor N5-1..N5-7, Lena: Save diff) ------------------------------

fn ctrl_c() -> KeyEvent {
    KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)
}

/// Render and also return the terminal cursor position the frame asked for.
fn render_with_cursor(
    app: &shellfirm::tui::app::App,
    w: u16,
    h: u16,
) -> (Vec<String>, Option<(u16, u16)>) {
    let lines = render_text(app, w, h);
    (lines, shellfirm::tui::a11y::requested_cursor())
}

fn save_dialog_text(app: &mut shellfirm::tui::app::App) -> String {
    app.handle_key(ch('s'));
    let text = render_text(app, 120, 50).join("\n");
    app.handle_key(key(KeyCode::Esc));
    text
}

/// Noor N5-1: while "Terminal too small" hides the editor, keys must not
/// change settings; only q / Ctrl-C (the quit flow) work.
#[test]
fn keys_do_nothing_while_the_terminal_is_too_small() {
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    for (w, h) in [(50u16, 14u16), (40, 12), (20, 6)] {
        let text = render_text(&app, w, h).join(" ");
        assert!(text.contains("Press q"), "{w}x{h}: {text}");
        for k in [
            key(KeyCode::Tab),
            key(KeyCode::Tab),
            key(KeyCode::Tab),
            key(KeyCode::Tab),
            key(KeyCode::Down),
            key(KeyCode::Enter),
            key(KeyCode::Enter),
            ch(' '),
            key(KeyCode::Right),
            ch('s'),
            key(KeyCode::Enter),
            ch('r'),
            key(KeyCode::Enter),
        ] {
            app.handle_key(k);
            let _ = render_text(&app, w, h);
        }
        assert!(
            !app.draft.is_dirty(),
            "{w}x{h}: the hidden editor changed the draft"
        );
        assert_eq!(app.current_tab, 0);
        assert!(app.modal.is_none());
        assert!(app.running);
    }
    // Enlarged again: everything works as before.
    let _ = render_text(&app, 80, 24);
    app.handle_key(key(KeyCode::Tab));
    assert_eq!(app.current_tab, 1);
    // q quits at once when nothing is unsaved.
    let _ = render_text(&app, 40, 12);
    app.handle_key(ch('q'));
    assert!(!app.running);
}

/// Noor N5-1: with unsaved changes the too-small screen asks in words;
/// `s` / Enter must not save blindly.
#[test]
fn too_small_quit_with_unsaved_changes_asks_in_words() {
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    app.draft.current.challenge = shellfirm::config::Challenge::Yes;
    let _ = render_text(&app, 40, 12);
    app.handle_key(ctrl_c());
    let text = render_text(&app, 40, 12).join(" ");
    assert!(text.contains("Unsaved changes"), "{text}");
    assert!(text.contains("d to discard"), "{text}");
    app.handle_key(key(KeyCode::Enter)); // ignored
    assert!(app.running);
    app.handle_key(key(KeyCode::Esc));
    assert!(app.modal.is_none() && app.running);
    app.handle_key(ch('q'));
    app.handle_key(ch('d'));
    assert!(!app.running);
    assert!(
        !config.setting_file_path.exists() || {
            let t = std::fs::read_to_string(&config.setting_file_path).unwrap();
            !t.contains("challenge: Yes")
        }
    );
}

/// Noor N5-2: in the Ignore/Deny picker Left/Right move the caret inside the
/// filter (they used to switch tabs and lose the text), and the terminal
/// cursor follows it.
#[test]
fn ignore_deny_filter_arrows_move_the_caret() {
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    app.current_tab = 4;
    app.handle_key(key(KeyCode::Down));
    app.handle_key(key(KeyCode::Enter));
    for c in "git:frce_push".chars() {
        app.handle_key(ch(c));
    }
    for _ in 0..8 {
        app.handle_key(key(KeyCode::Left));
    }
    assert_eq!(app.current_tab, 4, "Left switched tabs while typing");
    app.handle_key(ch('o'));
    app.handle_key(key(KeyCode::Right));
    app.handle_key(key(KeyCode::Home));
    app.handle_key(key(KeyCode::End));
    assert_eq!(app.current_tab, 4);
    let edit = app.ignore_deny.edit.as_ref().unwrap();
    assert_eq!(edit.picker.filter, "git:force_push");
    let (lines, cursor) = render_with_cursor(&app, 100, 30);
    let all = lines.join("\n");
    assert!(all.contains("Looking for: git:force_push"), "{all}");
    let (cx, cy) = cursor.expect("no hardware cursor in the filter");
    let row = &lines[cy as usize];
    let prefix: String = row.chars().take(cx as usize).collect();
    assert!(
        prefix.ends_with("git:force_push"),
        "cursor at {cx},{cy}: {row}"
    );
    app.handle_key(key(KeyCode::Enter));
    assert_eq!(app.draft.current.deny_patterns_ids, vec!["git:force_push"]);
}

/// Noor N5-6: Enter twice (or a key repeat) right after opening a list must
/// not add the first check of the picker.
#[test]
fn enter_twice_in_ignore_deny_adds_nothing() {
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    app.current_tab = 4;
    app.handle_key(key(KeyCode::Down));
    app.handle_key(key(KeyCode::Enter));
    app.handle_key(key(KeyCode::Enter));
    app.handle_key(key(KeyCode::Enter));
    assert!(app.draft.current.deny_patterns_ids.is_empty());
    assert!(!app.draft.is_dirty());
    assert!(
        app.focused_field.help.contains("Nothing chosen"),
        "{:?}",
        app.focused_field
    );
    // No row is highlighted until the user chooses one.
    let text = render_text(&app, 100, 30).join("\n");
    assert!(!text.contains("> aws:"), "{text}");
    // Down chooses the first row; Enter adds it.
    app.handle_key(key(KeyCode::Down));
    app.handle_key(key(KeyCode::Enter));
    assert_eq!(app.draft.current.deny_patterns_ids.len(), 1);
    // After an add, Enter again adds nothing more.
    app.handle_key(key(KeyCode::Enter));
    assert_eq!(app.draft.current.deny_patterns_ids.len(), 1);
}

/// Noor N5-3 / Lena: the Save diff is the exact file that will be written
/// against the file on disk: no phantom `- key: []` / `+ key: []` lines
/// for keys that are not in the file.
#[test]
fn save_diff_shows_the_bytes_that_will_be_written() {
    // No settings file, a group disabled: only the new key appears.
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    // (What the Groups tab does when `aws` is switched off.)
    app.draft.current.disabled_groups = vec!["aws".into()];
    let text = save_dialog_text(&mut app);
    assert!(text.contains("+ disabled_groups:"), "{text}");
    assert!(text.contains("+ - aws"), "{text}");
    assert!(!text.contains("- disabled_groups: []"), "{text}");
    assert!(!text.contains("enabled_groups"), "{text}");

    // Removing every entry: the keys go away, nothing is "added".
    let config = temp_config();
    std::fs::write(
        &config.setting_file_path,
        "deny_patterns_ids:\n- git:force_push\nignores_patterns_ids:\n- git:reset\n",
    )
    .unwrap();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    app.draft.current.deny_patterns_ids.clear();
    app.draft.current.ignores_patterns_ids.clear();
    let text = save_dialog_text(&mut app);
    assert!(text.contains("- deny_patterns_ids:"), "{text}");
    assert!(text.contains("- - git:force_push"), "{text}");
    assert!(!text.contains("+ ignores_patterns_ids"), "{text}");
    assert!(!text.contains("+ deny_patterns_ids"), "{text}");
    // What the dialog promised is what is written.
    let planned = app.planned_write().unwrap().1;
    app.handle_key(ch('s'));
    app.handle_key(key(KeyCode::Enter));
    assert_eq!(
        std::fs::read_to_string(&config.setting_file_path).unwrap(),
        planned
    );
}

/// Noor N5-3: a nested change is shown under its enclosing keys.
#[test]
fn save_diff_shows_parent_keys_of_nested_changes() {
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    app.draft.current.deny_patterns_ids = vec!["git:force_push".into()];
    app.draft
        .current
        .context
        .protected_branches
        .push("hotfix/*".into());
    let text = save_dialog_text(&mut app);
    let ctx = text.find("context:").expect(&text);
    let pb = text.find("protected_branches:").expect(&text);
    let add = text.find("hotfix/*").expect(&text);
    assert!(ctx < pb && pb < add, "{text}");
}

/// Noor N5-4: a status message is labelled `Note:`, disappears on the next
/// key, and never overwrites the field header at 60 columns.
#[test]
fn status_message_is_labelled_cleared_and_does_not_cover_the_header() {
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    app.draft.current.challenge = shellfirm::config::Challenge::Yes;
    app.handle_key(ch('r'));
    app.handle_key(key(KeyCode::Enter)); // reset
    assert!(app.status_message.is_some());
    let lines = render_text(&app, 60, 16);
    let strip = lines[lines.len() - 3..lines.len() - 1].join("\n");
    assert!(strip.contains("Note: reset to on-disk state"), "{strip}");
    assert!(lines[lines.len() - 3].starts_with("Selected: "), "{strip}");
    let wide = render_text(&app, 200, 60);
    assert!(
        wide[wide.len() - 3].contains("Note: reset"),
        "{}",
        wide.join("\n")
    );
    app.handle_key(key(KeyCode::Down));
    assert!(app.status_message.is_none());
    let lines = render_text(&app, 60, 16).join("\n");
    assert!(!lines.contains("Note:"), "{lines}");
}

/// Noor N5-5: Ctrl-C quits (asking first when there are unsaved changes),
/// also from a text field, and the help lists it.
#[test]
fn ctrl_c_runs_the_quit_flow() {
    let config = temp_config();
    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    app.handle_key(ctrl_c());
    assert!(!app.running, "Ctrl-C with nothing unsaved quits");

    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    app.draft.current.audit_enabled = !app.draft.current.audit_enabled;
    open_context_add(&mut app);
    app.handle_key(ch('x'));
    app.handle_key(ctrl_c());
    assert!(matches!(
        app.modal,
        Some(shellfirm::tui::app::Modal::Quit(_))
    ));
    assert!(app.running);
    // Cancel goes back to editing; nothing was typed by Ctrl-C.
    app.handle_key(key(KeyCode::Esc));
    assert!(app.modal.is_none());

    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    app.draft.current.challenge = shellfirm::config::Challenge::Yes;
    app.handle_key(ctrl_c());
    assert!(matches!(
        app.modal,
        Some(shellfirm::tui::app::Modal::Quit(_))
    ));
    app.handle_key(key(KeyCode::Right)); // Discard & quit
    app.handle_key(key(KeyCode::Enter));
    assert!(!app.running);

    let mut app = shellfirm::tui::app::App::new(&config).unwrap();
    app.handle_key(ch('?'));
    for _ in 0..40 {
        app.handle_key(key(KeyCode::Down));
        let _ = render_text(&app, 200, 60);
    }
    let help = render_text(&app, 200, 60).join("\n");
    assert!(help.contains("Ctrl-C"), "{help}");
}
