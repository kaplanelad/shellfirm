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
}

impl App {
    pub fn new(config: &Config) -> Result<Self> {
        let settings = config
            .get_settings_from_file()
            .unwrap_or_else(|_| Settings::default());
        // The diff baseline must use the SAME serializer as `current` so
        // HashMap ordering / whitespace / formatting differences in the
        // raw file don't masquerade as real changes. Read → parse →
        // re-serialize gives a normalized form identical to what
        // `render_yaml` produces for `current`.
        let on_disk_yaml = serde_yaml::to_string(&settings).unwrap_or_default();
        let draft = DraftSettings::from_settings(settings);

        let store = CustomCheckStore::new(config.custom_checks_dir());
        let custom_checks: Vec<Check> = store.list().unwrap_or_default();

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
            })
            .collect();
        for c in &custom_checks {
            if !all_check_ids.iter().any(|p| p.value == c.id) {
                all_check_ids.push(PickerItem {
                    value: c.id.clone(),
                    badge: Some("custom"),
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
            status_message: None,
            running: true,
            all_check_ids,
        })
    }

    pub fn handle_key(&mut self, key: KeyEvent) {
        // Form takes precedence
        if let Some(mut form) = self.form.take() {
            match form.handle_key(key) {
                FormOutcome::Saved(check) => {
                    let result = match &form.mode {
                        FormMode::Create => self.custom.store.add(&check),
                        FormMode::Edit {
                            original_id,
                            original_from,
                        } => {
                            // If the id changed, treat as delete-old + add-new
                            if original_id != &check.id {
                                let _ = self.custom.store.delete(original_id, original_from);
                                self.custom.store.add(&check)
                            } else {
                                self.custom.store.update(&check, original_from)
                            }
                        }
                    };
                    if let Err(e) = result {
                        self.status_message = Some(format!("save failed: {e}"));
                        self.form = Some(form); // keep form open with error
                    } else {
                        self.custom.reload();
                        self.refresh_check_id_pool();
                        self.refresh_custom_groups();
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

        // Modal takes precedence over tab
        if self.modal.is_some() {
            self.handle_modal_key(key);
            return;
        }

        // Global keys
        match key.code {
            KeyCode::Char('q') => {
                if self.draft.is_dirty() {
                    self.modal = Some(Modal::Quit(QuitDialogState::default()));
                } else {
                    self.running = false;
                }
                return;
            }
            KeyCode::Char('s') => {
                let report = crate::tui::validate::validate(&self.draft.current);
                if report.is_ok() {
                    self.modal = Some(Modal::Save(SaveDialogState::default()));
                } else {
                    self.modal = Some(Modal::Save(SaveDialogState {
                        stage: SaveStage::Errors(report.errors),
                        button: 0,
                    }));
                }
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
                self.modal = Some(Modal::Help);
                return;
            }
            KeyCode::Tab => {
                self.current_tab = (self.current_tab + 1) % NUM_TABS;
                self.focused_field = self.current_tab_focus();
                return;
            }
            KeyCode::BackTab => {
                self.current_tab = (self.current_tab + NUM_TABS - 1) % NUM_TABS;
                self.focused_field = self.current_tab_focus();
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
                        self.current_tab = (self.current_tab + NUM_TABS - 1) % NUM_TABS;
                        self.focused_field = self.current_tab_focus();
                    }
                    KeyCode::Right => {
                        self.current_tab = (self.current_tab + 1) % NUM_TABS;
                        self.focused_field = self.current_tab_focus();
                    }
                    _ => {}
                }
            }
            TabOutcome::FieldFocusChanged(f) => self.focused_field = f,
            TabOutcome::Mutated => {}
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
                        self.status_message =
                            Some(format!("edit externally: {}", path.display()));
                    }
                }
            }
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
            Modal::Help => match key.code {
                KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q') => None,
                _ => Some(Modal::Help),
            },
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
                        self.status_message =
                            Some(format!("deleted custom check: {}", state.id));
                    } else {
                        self.status_message =
                            Some(format!("failed to delete: {}", state.id));
                    }
                }
                None
            }
            _ => Some(Modal::DeleteCustom(state)),
        }
    }

    fn handle_save_modal(
        &mut self,
        key: KeyEvent,
        mut state: SaveDialogState,
    ) -> Option<Modal> {
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

    fn handle_quit_modal(
        &mut self,
        key: KeyEvent,
        mut state: QuitDialogState,
    ) -> Option<Modal> {
        match key.code {
            KeyCode::Esc => None,
            KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => {
                state.button = (state.button + 1) % 3;
                Some(Modal::Quit(state))
            }
            KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => {
                state.button = if state.button == 0 { 2 } else { state.button - 1 };
                Some(Modal::Quit(state))
            }
            KeyCode::Enter | KeyCode::Char(' ') => match state.button {
                0 => {
                    // Save & quit
                    let report = crate::tui::validate::validate(&self.draft.current);
                    if !report.is_ok() {
                        // Switch to a Save modal showing errors.
                        return Some(Modal::Save(SaveDialogState {
                            stage: SaveStage::Errors(report.errors),
                            button: 0,
                        }));
                    }
                    self.do_save();
                    self.running = false;
                    None
                }
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

    fn handle_reset_modal(
        &mut self,
        key: KeyEvent,
        mut state: ResetDialogState,
    ) -> Option<Modal> {
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
        let report = crate::tui::validate::validate(&self.draft.current);
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
        if let Err(e) = cfg.save_settings_file_from_struct(&self.draft.current) {
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

    fn refresh_check_id_pool(&mut self) {
        let mut all: Vec<PickerItem> = crate::checks::all_checks_cached()
            .iter()
            .map(|c| PickerItem {
                value: c.id.clone(),
                badge: Some("built-in"),
            })
            .collect();
        for c in &self.custom.checks {
            if !all.iter().any(|p| p.value == c.id) {
                all.push(PickerItem {
                    value: c.id.clone(),
                    badge: Some("custom"),
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
