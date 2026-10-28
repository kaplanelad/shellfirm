//! Top-level TUI application.

use crate::checks::Check;
use crate::config::{Config, Settings};
use crate::error::Result;
use crate::tui::check_form::{CheckForm, FormMode, FormOutcome, IdUniquenessValidator};
use crate::tui::check_store::CustomCheckStore;
use crate::tui::draft::DraftSettings;
use crate::tui::tabs::{
    AITab, ContextTab, CustomChecksTab, EscalationTab, FieldFocus, GeneralTab, GroupsTab,
    IgnoreDenyTab, LLMTab, PendingAction, Tab, TabOutcome, WrapTab,
};
use crate::tui::widgets::PickerItem;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

pub const NUM_TABS: usize = 9;

#[derive(Debug)]
pub enum Modal {
    /// Save dialog — confirm-with-diff or show validation errors.
    Save(SaveDialogState),
    /// Quit-while-dirty dialog — Save / Discard / Cancel.
    Quit(QuitDialogState),
    /// Reset confirmation — Reset / Cancel.
    Reset(ResetDialogState),
    /// Help overlay.
    Help,
    /// Confirm-delete-custom-check dialog. Default button is Cancel
    /// (index 1) so an accidental Enter does not delete.
    DeleteCustom(DeleteCustomDialogState),
}

/// State for the delete-custom-check confirmation modal.
/// `button`: 0 = Delete, 1 = Cancel. Default = Cancel.
#[derive(Debug)]
pub struct DeleteCustomDialogState {
    pub index: usize,
    pub id: String,
    pub from: String,
    pub button: usize,
}

/// Save flow has two stages:
/// 1. Validating + showing diff (Confirm)
/// 2. Errors (one or more validation failures)
#[derive(Debug, Default)]
pub struct SaveDialogState {
    pub stage: SaveStage,
    /// Selected button index when in Confirm stage. 0 = Save, 1 = Cancel.
    pub button: usize,
    /// First visible line of the dialog body (diff or error list). The
    /// body scrolls with Up/Down/PgUp/PgDn/Home/End when it does not fit.
    pub scroll: u16,
    /// What the save would do: `(file on disk now, exact file that would be
    /// written)`, or why that could not be worked out. Computed when the
    /// dialog opens (the draft cannot change while it is open).
    pub planned: Option<std::result::Result<(String, String), String>>,
}

#[derive(Debug, Default)]
pub enum SaveStage {
    #[default]
    Confirm,
    Errors(Vec<crate::tui::validate::ValidationError>),
}

/// Quit dialog: 0 = Save & quit, 1 = Discard & quit, 2 = Cancel.
#[derive(Debug, Default)]
pub struct QuitDialogState {
    pub button: usize,
}

/// Reset confirm: 0 = Reset, 1 = Cancel.
#[derive(Debug, Default)]
pub struct ResetDialogState {
    pub button: usize,
}

/// Preview pane visibility/layout. `p` toggles between open and closed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum PreviewMode {
    #[default]
    Closed,
    /// Preview takes the right 40% of the body, tab editor on the left.
    Open,
}

/// Scroll/visibility state for the preview pane.
#[derive(Debug, Default)]
pub struct PreviewState {
    pub mode: PreviewMode,
    /// First diff-line index to render. When `auto_scroll` is true the
    /// renderer recomputes this each frame from the first changed line;
    /// once the user scrolls manually we honor their position.
    pub scroll: u16,
    pub auto_scroll: bool,
}

impl PreviewState {
    pub const fn is_open(&self) -> bool {
        matches!(self.mode, PreviewMode::Open)
    }
}

pub struct App {
    pub config_path: std::path::PathBuf,
    pub draft: DraftSettings,
    pub on_disk_yaml: String,

    // Tabs (one of each)
    pub general: GeneralTab,
    pub groups: GroupsTab,
    pub escalation: EscalationTab,
    pub context: ContextTab,
    pub ignore_deny: IgnoreDenyTab,
    pub ai: AITab,
    pub wrap: WrapTab,
    pub llm: LLMTab,
    pub custom: CustomChecksTab,

    pub current_tab: usize,
    pub preview: PreviewState,
    pub modal: Option<Modal>,
    pub form: Option<CheckForm>,
    pub focused_field: FieldFocus,
    pub status_message: Option<String>,
    pub running: bool,

    /// Cached pool of check IDs for ignore/deny pickers
    pub all_check_ids: Vec<PickerItem>,

    /// First visible line of the `?` help overlay.
    pub help_scroll: u16,
    /// Largest useful `help_scroll`, recorded by the renderer (it depends
    /// on the terminal size).
    pub help_max_scroll: std::cell::Cell<u16>,
    /// Largest useful Save-dialog body scroll, recorded by the renderer.
    pub save_max_scroll: std::cell::Cell<u16>,
    /// Custom-check groups that were added to `enabled_groups` only for
    /// display (the runtime treats custom groups as enabled unless they are
    /// disabled). They are stripped again on save so the settings file stays
    /// sparse.
    pub implicit_custom_groups: Vec<String>,
    /// The last frame was the "Terminal too small" screen (set by the
    /// renderer). While it is shown the editor is hidden, so only the quit
    /// keys work: nothing may change settings the user cannot see.
    pub too_small: std::cell::Cell<bool>,
}

/// Ctrl-C (the quit key in most terminal programs).
fn is_ctrl_c(key: &KeyEvent) -> bool {
    key.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'))
}

impl App {
    pub fn new(config: &Config) -> Result<Self> {
        // Never open (and later save over) a settings file that failed to
        // parse — that would silently replace the user's file with defaults.
        let mut settings: Settings = config.get_settings_from_file().map_err(|e| {
            crate::error::Error::Config(format!(
                "{e}\nThe file was not changed. Fix it with `shellfirm config edit`, or start \
                 over with `shellfirm config reset` (the old file is backed up)."
            ))
        })?;

        let store = CustomCheckStore::new(config.custom_checks_dir());
        let custom_report = store.list_report();
        let custom_checks: Vec<Check> = custom_report.checks.clone();
        // Show custom-check groups the same way the runtime treats them:
        // active unless explicitly disabled.
        let implicit_custom_groups =
            settings.migrate_custom_groups_into_enabled_groups(&custom_checks);
        let status_message = custom_report
            .warnings
            .first()
            .map(|w| format!("warning: {w}"));

        // The diff baseline must use the SAME serializer as `current` so
        // HashMap ordering / whitespace / formatting differences in the
        // raw file don't masquerade as real changes. Read → parse →
        // re-serialize gives a normalized form identical to what
        // `render_yaml` produces for `current`.
        let on_disk_yaml = serde_yaml::to_string(&settings).unwrap_or_default();
        let draft = DraftSettings::from_settings(settings);

        // Distinct custom group names for the Groups tab
        let mut custom_groups: Vec<String> = Vec::new();
        for c in &custom_checks {
            if !custom_groups.contains(&c.from) {
                custom_groups.push(c.from.clone());
            }
        }

        // Pool of all known check IDs for ignore/deny pickers
        let mut all_check_ids: Vec<PickerItem> = crate::checks::all_checks_cached()
            .iter()
            .map(|c| PickerItem {
                value: c.id.clone(),
                badge: Some("built-in"),
                description: Some(c.description.clone()),
            })
            .collect();
        for c in &custom_checks {
            if !all_check_ids.iter().any(|p| p.value == c.id) {
                all_check_ids.push(PickerItem {
                    value: c.id.clone(),
                    badge: Some("custom"),
                    description: Some(c.description.clone()),
                });
            }
        }

        let general = GeneralTab::default();
        let initial_focus = general.current_focus();

        Ok(Self {
            config_path: config.setting_file_path.clone(),
            draft,
            on_disk_yaml,
            general,
            groups: GroupsTab::new(custom_groups),
            escalation: EscalationTab::default(),
            context: ContextTab::default(),
            ignore_deny: IgnoreDenyTab::new(all_check_ids.clone()),
            ai: AITab::default(),
            wrap: WrapTab::default(),
            llm: LLMTab::default(),
            custom: CustomChecksTab::new(store),
            current_tab: 0,
            preview: PreviewState::default(),
            modal: None,
            form: None,
            focused_field: initial_focus,
            status_message,
            running: true,
            all_check_ids,
            help_scroll: 0,
            help_max_scroll: std::cell::Cell::new(0),
            save_max_scroll: std::cell::Cell::new(0),
            implicit_custom_groups,
            too_small: std::cell::Cell::new(false),
        })
    }

    /// Start the quit flow: quit right away when nothing is unsaved,
    /// otherwise ask (Save & quit / Discard & quit / Cancel). An open
    /// custom-check form counts as unsaved; it stays open behind the
    /// dialog, so Cancel goes back to it.
    fn request_quit(&mut self) {
        if !self.unsaved_items().is_empty() {
            self.modal = Some(Modal::Quit(QuitDialogState::default()));
        } else {
            self.running = false;
        }
    }

    /// What would be lost by quitting now, in words for the quit dialog:
    /// changed settings and / or an unfinished custom check (by id).
    #[must_use]
    pub fn unsaved_items(&self) -> Vec<String> {
        let mut items = Vec::new();
        if self.draft.is_dirty() {
            items.push("changed settings (not written to settings.yaml yet)".to_string());
        }
        if let Some(form) = self.form.as_ref().filter(|f| f.is_dirty()) {
            let id = form.id_input.value().trim();
            let id = if id.is_empty() {
                "(no id yet)".to_string()
            } else {
                crate::context::escape_invisible(id)
            };
            items.push(format!("an unfinished custom check: {id}"));
        }
        items
    }

    /// Save the open custom check (when one was typed into) the way the
    /// wizard's Save does. `false` when it is incomplete or could not be
    /// written: the wizard stays open with the problems listed, and the
    /// status line says so.
    fn save_open_form(&mut self) -> bool {
        let Some(mut form) = self.form.take() else {
            return true;
        };
        if !form.is_dirty() {
            return true;
        }
        if let FormOutcome::Saved(check) = form.try_submit() {
            if let Err(e) = self.store_form_check(&form, &check) {
                self.status_message = Some(format!("custom check not saved: {e}"));
                self.form = Some(form);
                return false;
            }
            true
        } else {
            self.status_message = Some(
                "the custom check is not complete: finish it (Ctrl-S saves) or press Esc to \
                 discard it"
                    .into(),
            );
            self.form = Some(form);
            false
        }
    }

    /// Write a check from the wizard to the custom-check store.
    fn store_form_check(
        &mut self,
        form: &CheckForm,
        check: &crate::checks::Check,
    ) -> std::result::Result<(), String> {
        let result = match &form.mode {
            FormMode::Create => self.custom.store.add(check),
            FormMode::Edit {
                original_id,
                original_from,
            } => {
                // If the id changed, treat as delete-old + add-new
                if original_id == &check.id {
                    self.custom.store.update(check, original_from)
                } else {
                    let _ = self.custom.store.delete(original_id, original_from);
                    self.custom.store.add(check)
                }
            }
        };
        result.map_err(|e| e.to_string())?;
        self.custom.reload();
        self.refresh_check_id_pool();
        self.refresh_custom_groups();
        Ok(())
    }

    /// "Save & quit": the open custom check first (an incomplete one goes
    /// back on screen instead of being dropped), then the settings.
    fn save_and_quit(&mut self) -> Option<Modal> {
        if !self.save_open_form() {
            return None;
        }
        if self.draft.is_dirty() {
            let report = self.validate_draft();
            if !report.is_ok() {
                // Switch to a Save modal showing errors.
                return Some(Modal::Save(SaveDialogState {
                    stage: SaveStage::Errors(report.errors),
                    ..SaveDialogState::default()
                }));
            }
            self.do_save();
            if self.status_message.as_deref() != Some("saved") {
                return None;
            }
        }
        self.running = false;
        None
    }

    /// Open the Save dialog: the validation errors, or the exact change to
    /// the settings file.
    fn open_save_dialog(&mut self) {
        let report = self.validate_draft();
        self.modal = Some(Modal::Save(if report.is_ok() {
            SaveDialogState {
                planned: Some(self.planned_write()),
                ..SaveDialogState::default()
            }
        } else {
            SaveDialogState {
                stage: SaveStage::Errors(report.errors),
                ..SaveDialogState::default()
            }
        }));
    }

    /// `(current file, file a save would write)`. The save is rehearsed on
    /// a private copy of the settings file, with the same writer as the real
    /// save, so the Save dialog shows exactly the bytes that will be written
    /// (sparse keys, kept comments) instead of a diff of two full
    /// serialisations.
    ///
    /// # Errors
    /// Returns a message when the rehearsal fails.
    pub fn planned_write(&self) -> std::result::Result<(String, String), String> {
        let old = std::fs::read_to_string(&self.config_path).unwrap_or_default();
        let dir = std::env::temp_dir().join(format!(
            "shellfirm-tui-save-preview-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&dir).map_err(|e| e.to_string())?;
        let name = self.config_path.file_name().map_or_else(
            || std::ffi::OsString::from("settings.yaml"),
            ToOwned::to_owned,
        );
        let path = dir.join(name);
        let res = (|| -> std::result::Result<String, String> {
            if self.config_path.exists() {
                std::fs::write(&path, &old).map_err(|e| e.to_string())?;
            }
            let cfg = crate::config::Config {
                root_folder: dir.clone(),
                setting_file_path: path.clone(),
            };
            cfg.save_settings_file_from_struct(&self.settings_to_save())
                .map_err(|e| e.to_string())?;
            std::fs::read_to_string(&path).map_err(|e| e.to_string())
        })();
        let _ = std::fs::remove_dir_all(&dir);
        res.map(|new| (old, new))
    }

    pub fn handle_key(&mut self, key: KeyEvent) {
        // A status message describes the previous action; any new key
        // makes it stale.
        self.status_message = None;

        // While the "too small" screen hides the editor, only quitting works
        // (nothing may change settings the user cannot see).
        if self.too_small.get() {
            self.handle_key_too_small(key);
            return;
        }

        // Ctrl-C: the quit flow, from anywhere (a text field included).
        if is_ctrl_c(&key) {
            if !matches!(self.modal, Some(Modal::Quit(_))) {
                self.modal = None;
                self.request_quit();
            }
            return;
        }

        // Modal takes precedence (a quit dialog may sit over an open form).
        if self.modal.is_some() {
            self.handle_modal_key(key);
            return;
        }

        // Form takes precedence over the tabs
        if let Some(mut form) = self.form.take() {
            match form.handle_key(key) {
                FormOutcome::Saved(check) => {
                    if let Err(e) = self.store_form_check(&form, &check) {
                        self.status_message = Some(format!("save failed: {e}"));
                        self.form = Some(form); // keep form open with error
                    } else {
                        self.status_message = Some("custom check saved".into());
                    }
                }
                FormOutcome::Cancelled => {
                    // form dropped; status unchanged
                }
                FormOutcome::None => {
                    self.form = Some(form);
                }
            }
            return;
        }

        // A tab with a focused text field / picker filter (or a tab-local
        // hotkey such as `r` = reload in the Custom tab) gets the key first,
        // so global hotkeys never fire while the user is typing.
        if self.current_tab_claims(&key) {
            let outcome = self.dispatch_to_tab(key);
            if matches!(outcome, TabOutcome::Mutated) {
                self.preview.auto_scroll = true;
            }
            match outcome {
                TabOutcome::FieldFocusChanged(f) => self.focused_field = f,
                TabOutcome::Mutated => self.focused_field = self.current_tab_focus(),
                _ => {}
            }
            if self.current_tab == 8 && key.code == KeyCode::Char('r') {
                self.refresh_check_id_pool();
                self.refresh_custom_groups();
                self.status_message = Some("custom checks reloaded from disk".into());
            }
            return;
        }

        // Global keys
        match key.code {
            KeyCode::Char('q') => {
                self.request_quit();
                return;
            }
            KeyCode::Char('s') => {
                self.open_save_dialog();
                return;
            }
            KeyCode::Char('r') => {
                self.modal = Some(Modal::Reset(ResetDialogState::default()));
                return;
            }
            KeyCode::Char('p') => {
                // Toggle preview open/closed.
                self.preview.mode = match self.preview.mode {
                    PreviewMode::Closed => PreviewMode::Open,
                    PreviewMode::Open => PreviewMode::Closed,
                };
                // Reset to auto-scroll behavior when (re)opening.
                self.preview.auto_scroll = true;
                self.preview.scroll = 0;
                return;
            }
            KeyCode::Char('?') => {
                self.help_scroll = 0;
                self.modal = Some(Modal::Help);
                return;
            }
            KeyCode::Tab => {
                self.switch_tab((self.current_tab + 1) % NUM_TABS);
                return;
            }
            KeyCode::BackTab => {
                self.switch_tab((self.current_tab + NUM_TABS - 1) % NUM_TABS);
                return;
            }
            _ => {}
        }

        // Preview scroll keys claimed BEFORE dispatching to the tab so that
        // Shift+↑/↓ doesn't fall through to the tab's section-navigation
        // (which uses bare ↑/↓). PageUp/PageDown are claimed only when the
        // preview is open AND we're not in an editing context that uses
        // them (the LLM stepper). Since steppers run inside an `edit` state
        // we just skip pre-claiming PageUp/PageDown — those still go through
        // the tab → fall back here only if not consumed.
        let is_shift = key.modifiers.contains(KeyModifiers::SHIFT);
        if self.preview.is_open() && is_shift && matches!(key.code, KeyCode::Up | KeyCode::Down) {
            match key.code {
                KeyCode::Up => {
                    self.preview.scroll = self.preview.scroll.saturating_sub(1);
                }
                KeyCode::Down => {
                    self.preview.scroll = self.preview.scroll.saturating_add(1);
                }
                _ => unreachable!(),
            }
            self.preview.auto_scroll = false;
            return;
        }

        let outcome = self.dispatch_to_tab(key);
        let tab_consumed = !matches!(outcome, TabOutcome::None);

        // App-level PageUp/PageDown scrolling — only when the tab didn't
        // already use them (e.g. LLM stepper).
        if !tab_consumed && self.preview.is_open() {
            let page_step: u16 = 12;
            match key.code {
                KeyCode::PageUp => {
                    self.preview.scroll = self.preview.scroll.saturating_sub(page_step);
                    self.preview.auto_scroll = false;
                    return;
                }
                KeyCode::PageDown => {
                    self.preview.scroll = self.preview.scroll.saturating_add(page_step);
                    self.preview.auto_scroll = false;
                    return;
                }
                _ => {}
            }
        }

        // After any change to the draft, snap the preview back to auto-scroll
        // so the new edit is visible without the user manually scrolling.
        if matches!(outcome, TabOutcome::Mutated) {
            self.preview.auto_scroll = true;
        }

        match outcome {
            TabOutcome::None => {
                // Tab didn't consume the key — let the App handle Left/Right
                // as top-level tab navigation (since tabs are horizontally
                // arranged at the top of the screen).
                match key.code {
                    KeyCode::Left => {
                        self.switch_tab((self.current_tab + NUM_TABS - 1) % NUM_TABS);
                    }
                    KeyCode::Right => {
                        self.switch_tab((self.current_tab + 1) % NUM_TABS);
                    }
                    _ => {}
                }
            }
            TabOutcome::FieldFocusChanged(f) => self.focused_field = f,
            TabOutcome::Mutated => self.focused_field = self.current_tab_focus(),
            TabOutcome::Consumed => {}
        }

        // Custom tab → check pending action
        if self.current_tab == 8 {
            if let Some(action) = self.custom.take_pending_action() {
                match action {
                    PendingAction::Create => {
                        let validator = IdUniquenessValidator::new(
                            crate::checks::all_checks_cached()
                                .iter()
                                .map(|c| c.id.clone())
                                .collect(),
                            self.custom.checks.iter().map(|c| c.id.clone()).collect(),
                        );
                        let custom_groups: Vec<String> = {
                            let mut g = Vec::new();
                            for c in &self.custom.checks {
                                if !g.contains(&c.from) {
                                    g.push(c.from.clone());
                                }
                            }
                            g
                        };
                        self.form = Some(CheckForm::new_create(validator, custom_groups));
                    }
                    PendingAction::Edit { index } => {
                        if let Some(c) = self.custom.checks.get(index).cloned() {
                            let validator = IdUniquenessValidator::new(
                                crate::checks::all_checks_cached()
                                    .iter()
                                    .map(|c| c.id.clone())
                                    .collect(),
                                self.custom.checks.iter().map(|c| c.id.clone()).collect(),
                            );
                            let custom_groups: Vec<String> = {
                                let mut g = Vec::new();
                                for c in &self.custom.checks {
                                    if !g.contains(&c.from) {
                                        g.push(c.from.clone());
                                    }
                                }
                                g
                            };
                            self.form = Some(CheckForm::new_edit(&c, validator, custom_groups));
                        }
                    }
                    PendingAction::ConfirmDelete { index } => {
                        if let Some(c) = self.custom.checks.get(index) {
                            self.modal = Some(Modal::DeleteCustom(DeleteCustomDialogState {
                                index,
                                id: c.id.clone(),
                                from: c.from.clone(),
                                button: 1, // default = Cancel
                            }));
                        }
                    }
                    PendingAction::OpenInEditor { path } => {
                        self.status_message = Some(format!("edit externally: {}", path.display()));
                    }
                }
            }
        }
    }

    /// Keys while the "Terminal too small" screen is shown: `q` / Ctrl-C
    /// start the quit flow. With unsaved changes the screen then asks in
    /// words (the dialog itself does not fit): `s` saves and quits, `d`
    /// discards and quits, Esc goes back. Every other key is ignored.
    fn handle_key_too_small(&mut self, key: KeyEvent) {
        if matches!(self.modal, Some(Modal::Quit(_))) {
            match key.code {
                KeyCode::Esc => self.modal = None,
                KeyCode::Char('d') => {
                    self.modal = None;
                    self.running = false;
                }
                KeyCode::Char('s') => {
                    // An incomplete custom check is kept (with a note), not
                    // dropped; invalid settings are never written.
                    self.modal = None;
                    if self.save_and_quit().is_some() {
                        self.status_message = Some(
                            "the changes are not valid; enlarge the window to fix them".into(),
                        );
                    }
                }
                _ => {}
            }
            return;
        }
        if is_ctrl_c(&key) || key.code == KeyCode::Char('q') {
            self.modal = None;
            self.request_quit();
        }
    }

    /// Move to tab `next`. Any edit state of the tab being left (an open
    /// list, picker or text field) is closed first, exactly as if the user
    /// had pressed Esc, so coming back never lands in a hidden edit state
    /// where browsing keys would change settings.
    pub fn switch_tab(&mut self, next: usize) {
        let esc = KeyEvent::new(KeyCode::Esc, KeyModifiers::empty());
        // Nested states (a text field inside a list) need one Esc each.
        for _ in 0..4 {
            if !self.current_tab_is_editing() {
                break;
            }
            let _ = self.dispatch_to_tab(esc);
        }
        self.current_tab = next % NUM_TABS;
        self.focused_field = self.current_tab_focus();
    }

    fn current_tab_is_editing(&self) -> bool {
        match self.current_tab {
            0 => self.general.is_editing(),
            1 => self.groups.is_editing(),
            2 => self.escalation.is_editing(),
            3 => self.context.is_editing(),
            4 => self.ignore_deny.is_editing(),
            5 => self.ai.is_editing(),
            6 => self.wrap.is_editing(),
            7 => self.llm.is_editing(),
            8 => self.custom.is_editing(),
            _ => false,
        }
    }

    fn dispatch_to_tab(&mut self, key: KeyEvent) -> TabOutcome {
        match self.current_tab {
            0 => self.general.handle_key(key, &mut self.draft),
            1 => self.groups.handle_key(key, &mut self.draft),
            2 => self.escalation.handle_key(key, &mut self.draft),
            3 => self.context.handle_key(key, &mut self.draft),
            4 => self.ignore_deny.handle_key(key, &mut self.draft),
            5 => self.ai.handle_key(key, &mut self.draft),
            6 => self.wrap.handle_key(key, &mut self.draft),
            7 => self.llm.handle_key(key, &mut self.draft),
            8 => self.custom.handle_key(key, &mut self.draft),
            _ => TabOutcome::None,
        }
    }

    fn current_tab_claims(&self, key: &KeyEvent) -> bool {
        match self.current_tab {
            0 => self.general.claims_key(key),
            1 => self.groups.claims_key(key),
            2 => self.escalation.claims_key(key),
            3 => self.context.claims_key(key),
            4 => self.ignore_deny.claims_key(key),
            5 => self.ai.claims_key(key),
            6 => self.wrap.claims_key(key),
            7 => self.llm.claims_key(key),
            8 => self.custom.claims_key(key),
            _ => false,
        }
    }

    fn current_tab_focus(&self) -> FieldFocus {
        match self.current_tab {
            0 => self.general.current_focus(),
            1 => self.groups.current_focus(),
            2 => self.escalation.current_focus(),
            3 => self.context.current_focus(),
            4 => self.ignore_deny.current_focus(),
            5 => self.ai.current_focus(),
            6 => self.wrap.current_focus(),
            7 => self.llm.current_focus(),
            8 => self.custom.current_focus(),
            _ => FieldFocus::default(),
        }
    }

    fn handle_modal_key(&mut self, key: KeyEvent) {
        if self.modal.is_none() {
            return;
        }

        // Take ownership so we can mutate; will reinsert if dialog stays open.
        let modal = self.modal.take().expect("checked above");
        self.modal = match modal {
            Modal::Save(state) => self.handle_save_modal(key, state),
            Modal::Quit(state) => self.handle_quit_modal(key, state),
            Modal::Reset(state) => self.handle_reset_modal(key, state),
            Modal::Help => {
                let max = self.help_max_scroll.get();
                match key.code {
                    KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q') => None,
                    KeyCode::Up | KeyCode::Char('k') => {
                        self.help_scroll = self.help_scroll.min(max).saturating_sub(1);
                        Some(Modal::Help)
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        self.help_scroll = (self.help_scroll + 1).min(max);
                        Some(Modal::Help)
                    }
                    KeyCode::PageUp => {
                        self.help_scroll = self.help_scroll.min(max).saturating_sub(8);
                        Some(Modal::Help)
                    }
                    KeyCode::PageDown | KeyCode::Char(' ') => {
                        self.help_scroll = (self.help_scroll + 8).min(max);
                        Some(Modal::Help)
                    }
                    KeyCode::Home => {
                        self.help_scroll = 0;
                        Some(Modal::Help)
                    }
                    KeyCode::End => {
                        self.help_scroll = max;
                        Some(Modal::Help)
                    }
                    _ => Some(Modal::Help),
                }
            }
            Modal::DeleteCustom(state) => self.handle_delete_custom_modal(key, state),
        };
    }

    fn handle_delete_custom_modal(
        &mut self,
        key: KeyEvent,
        mut state: DeleteCustomDialogState,
    ) -> Option<Modal> {
        match key.code {
            KeyCode::Esc => None,
            KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => {
                state.button = (state.button + 1) % 2;
                Some(Modal::DeleteCustom(state))
            }
            KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => {
                state.button = (state.button + 1) % 2;
                Some(Modal::DeleteCustom(state))
            }
            KeyCode::Enter => {
                if state.button == 0 {
                    // Delete confirmed.
                    if self.custom.store.delete(&state.id, &state.from).is_ok() {
                        self.custom.reload();
                        self.refresh_check_id_pool();
                        self.refresh_custom_groups();
                        self.status_message = Some(format!("deleted custom check: {}", state.id));
                    } else {
                        self.status_message = Some(format!("failed to delete: {}", state.id));
                    }
                }
                None
            }
            _ => Some(Modal::DeleteCustom(state)),
        }
    }

    fn handle_save_modal(&mut self, key: KeyEvent, mut state: SaveDialogState) -> Option<Modal> {
        // Body scrolling works the same in both stages.
        let max = self.save_max_scroll.get();
        let scrolled = match key.code {
            KeyCode::Up | KeyCode::Char('k') => Some(state.scroll.min(max).saturating_sub(1)),
            KeyCode::Down | KeyCode::Char('j') => Some((state.scroll + 1).min(max)),
            KeyCode::PageUp => Some(state.scroll.min(max).saturating_sub(5)),
            KeyCode::PageDown => Some((state.scroll + 5).min(max)),
            KeyCode::Home => Some(0),
            KeyCode::End => Some(max),
            _ => None,
        };
        if let Some(s) = scrolled {
            state.scroll = s;
            return Some(Modal::Save(state));
        }
        match &state.stage {
            SaveStage::Confirm => match key.code {
                KeyCode::Esc => None,
                KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => {
                    state.button = (state.button + 1) % 2;
                    Some(Modal::Save(state))
                }
                KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => {
                    state.button = if state.button == 0 { 1 } else { 0 };
                    Some(Modal::Save(state))
                }
                KeyCode::Enter | KeyCode::Char(' ') => {
                    if state.button == 1 {
                        return None; // Cancel
                    }
                    self.do_save();
                    None
                }
                _ => Some(Modal::Save(state)),
            },
            SaveStage::Errors(_) => match key.code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char(' ') => None,
                _ => Some(Modal::Save(state)),
            },
        }
    }

    fn handle_quit_modal(&mut self, key: KeyEvent, mut state: QuitDialogState) -> Option<Modal> {
        match key.code {
            KeyCode::Esc => None,
            KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => {
                state.button = (state.button + 1) % 3;
                Some(Modal::Quit(state))
            }
            KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => {
                state.button = if state.button == 0 {
                    2
                } else {
                    state.button - 1
                };
                Some(Modal::Quit(state))
            }
            // The letters shown on the buttons, as on the small-screen text.
            KeyCode::Char('s' | 'S') => self.save_and_quit(),
            KeyCode::Char('d' | 'D') => {
                self.running = false;
                None
            }
            KeyCode::Enter | KeyCode::Char(' ') => match state.button {
                0 => self.save_and_quit(),
                1 => {
                    // Discard & quit
                    self.running = false;
                    None
                }
                _ => None, // Cancel
            },
            _ => Some(Modal::Quit(state)),
        }
    }

    fn handle_reset_modal(&mut self, key: KeyEvent, mut state: ResetDialogState) -> Option<Modal> {
        match key.code {
            KeyCode::Esc => None,
            KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => {
                state.button = (state.button + 1) % 2;
                Some(Modal::Reset(state))
            }
            KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => {
                state.button = if state.button == 0 { 1 } else { 0 };
                Some(Modal::Reset(state))
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                if state.button == 0 {
                    self.draft.reset();
                    self.status_message = Some("reset to on-disk state".into());
                }
                None
            }
            _ => Some(Modal::Reset(state)),
        }
    }

    fn do_save(&mut self) {
        let report = self.validate_draft();
        if !report.is_ok() {
            // Should be caught earlier; defensive.
            self.status_message = Some(format!(
                "validation errors: {}",
                report
                    .errors
                    .iter()
                    .map(|e| format!("{}: {}", e.path, e.message))
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
            return;
        }
        let cfg = crate::config::Config {
            root_folder: self
                .config_path
                .parent()
                .unwrap_or(std::path::Path::new("."))
                .to_path_buf(),
            setting_file_path: self.config_path.clone(),
        };
        if let Err(e) = cfg.save_settings_file_from_struct(&self.settings_to_save()) {
            self.status_message = Some(format!("save failed: {e}"));
            return;
        }
        self.draft.pin_original(self.draft.current.clone());
        // Use the same serializer as `current` so the diff baseline stays
        // canonical. (Reading the raw file back would risk HashMap-ordering
        // discrepancies between writes/reads on different platforms.)
        self.on_disk_yaml = serde_yaml::to_string(&self.draft.current).unwrap_or_default();
        self.status_message = Some("saved".into());
    }

    /// The settings that are written on save: the draft, minus the custom
    /// groups that were only added to `enabled_groups` for display. Those
    /// are enabled implicitly, so writing them would pin the full group
    /// list in the file (and new built-in groups from future releases
    /// would then stay off).
    #[must_use]
    pub fn settings_to_save(&self) -> Settings {
        let mut s = self.draft.current.clone();
        s.enabled_groups
            .retain(|g| !self.implicit_custom_groups.iter().any(|i| i == g));
        s
    }

    /// Check ids the ignore/deny lists may reference (built-in + custom).
    #[must_use]
    pub fn known_check_ids(&self) -> std::collections::HashSet<String> {
        self.all_check_ids.iter().map(|p| p.value.clone()).collect()
    }

    fn validate_draft(&self) -> crate::tui::validate::ValidationReport {
        crate::tui::validate::validate_with_ids(&self.draft.current, &self.known_check_ids())
    }

    fn refresh_check_id_pool(&mut self) {
        let mut all: Vec<PickerItem> = crate::checks::all_checks_cached()
            .iter()
            .map(|c| PickerItem {
                value: c.id.clone(),
                badge: Some("built-in"),
                description: Some(c.description.clone()),
            })
            .collect();
        for c in &self.custom.checks {
            if !all.iter().any(|p| p.value == c.id) {
                all.push(PickerItem {
                    value: c.id.clone(),
                    badge: Some("custom"),
                    description: Some(c.description.clone()),
                });
            }
        }
        self.all_check_ids = all.clone();
        self.ignore_deny.all_ids = all;
    }

    /// Recompute the set of custom group names from current custom checks
    /// and push it into the Groups tab so newly-introduced groups show up
    /// without requiring a TUI restart.
    fn refresh_custom_groups(&mut self) {
        let mut groups: Vec<String> = Vec::new();
        for c in &self.custom.checks {
            if !groups.contains(&c.from) {
                groups.push(c.from.clone());
            }
        }
        self.groups.custom_groups = groups;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::empty())
    }

    fn new_app() -> (tree_fs::Tree, App) {
        let dir = tree_fs::TreeBuilder::default().create().expect("tree");
        let config =
            crate::config::Config::new(Some(&dir.root.join("cfg").display().to_string())).unwrap();
        std::fs::create_dir_all(&config.root_folder).unwrap();
        let app = App::new(&config).unwrap();
        (dir, app)
    }

    fn open_wizard_with(app: &mut App, id: &str) {
        app.form = Some(CheckForm::new_create(
            IdUniquenessValidator::new(vec![], vec![]),
            vec![],
        ));
        for c in id.chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
    }

    fn screen(app: &App, w: u16, h: u16) -> String {
        use ratatui::backend::TestBackend;
        let mut t = ratatui::Terminal::new(TestBackend::new(w, h)).unwrap();
        t.draw(|f| crate::tui::render::draw(f, app)).unwrap();
        let buf = t.backend().buffer();
        (0..h)
            .map(|y| {
                (0..w)
                    .map(|x| buf[(x, y)].symbol().to_string())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn save_and_quit_keeps_an_unfinished_check_open() {
        // "Save & quit" used to drop the half-filled wizard.
        let (_d, mut app) = new_app();
        open_wizard_with(&mut app, "mine:a");
        app.request_quit();
        assert!(matches!(app.modal, Some(Modal::Quit(_))));
        assert_eq!(
            app.unsaved_items(),
            vec!["an unfinished custom check: mine:a".to_string()]
        );
        let text = screen(&app, 60, 16);
        assert!(
            text.contains("an unfinished custom check: mine:a"),
            "{text}"
        );
        assert!(text.contains("[ s Save & quit ]"), "{text}");
        assert!(text.contains("[ d Discard & quit ]"), "{text}");
        for line in text.lines() {
            assert!(
                !line.contains("Cancel ]") || line.contains("[ Esc Cancel ]"),
                "{line}"
            );
        }
        app.handle_key(key(KeyCode::Enter)); // Save & quit is focused
        assert!(app.running, "an incomplete check must not be thrown away");
        assert!(app.modal.is_none());
        let form = app.form.as_ref().expect("wizard still open");
        assert_eq!(form.id_input.value(), "mine:a");
        assert!(form
            .error_message
            .as_deref()
            .is_some_and(|e| e == "Required: Test (regex), Description"));
        assert!(app
            .status_message
            .as_deref()
            .is_some_and(|m| m.contains("not complete")));
    }

    #[test]
    fn no_caret_in_the_wizard_behind_the_quit_dialog() {
        let (_d, mut app) = new_app();
        open_wizard_with(&mut app, "mine:a");
        let _ = screen(&app, 80, 24);
        assert!(
            crate::tui::a11y::requested_cursor().is_some(),
            "caret in the id box"
        );
        app.request_quit();
        assert!(matches!(app.modal, Some(Modal::Quit(_))));
        let text = screen(&app, 80, 24);
        assert!(text.contains("Save & quit"), "{text}");
        assert!(
            crate::tui::a11y::requested_cursor().is_none(),
            "the caret must not stay in the hidden text box"
        );
    }

    #[test]
    fn quit_dialog_accepts_s_and_d() {
        let (_d, mut app) = new_app();
        app.draft.current.audit_enabled = !app.draft.current.audit_enabled;
        app.request_quit();
        app.handle_key(key(KeyCode::Char('d')));
        assert!(!app.running, "d discards and quits");

        let (_d, mut app) = new_app();
        app.draft.current.audit_enabled = !app.draft.current.audit_enabled;
        app.request_quit();
        app.handle_key(key(KeyCode::Char('s')));
        assert!(!app.running, "s saves and quits");
        assert!(!app.draft.is_dirty());

        // An untouched wizard is nothing to lose: quit right away.
        let (_d, mut app) = new_app();
        open_wizard_with(&mut app, "");
        app.request_quit();
        assert!(!app.running);
    }

    #[test]
    fn save_and_quit_saves_a_complete_check() {
        let (_d, mut app) = new_app();
        open_wizard_with(&mut app, "mine:done");
        if let Some(f) = app.form.as_mut() {
            f.from_value = "mine".into();
            f.test_input = crate::tui::widgets::TextInput::with_value("zzqq");
            f.description_input = crate::tui::widgets::TextInput::with_value("d");
        }
        app.request_quit();
        app.handle_key(key(KeyCode::Char('s')));
        assert!(!app.running);
        assert!(app
            .custom
            .store
            .list()
            .unwrap()
            .iter()
            .any(|c| c.id == "mine:done"));
    }
}
