//! TUI tabs.
//!
//! Each tab implements the `Tab` trait and owns its own cursor state.
//! The App manages which tab is active and dispatches `render` and
//! `handle_key` to it.

use crate::tui::draft::DraftSettings;
use crossterm::event::KeyEvent;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;

pub mod ai;
pub mod context;
pub mod custom_checks;
pub mod escalation;
pub mod general;
pub mod groups;
pub mod ignore_deny;
pub mod llm;
pub mod wrap;

pub use ai::AITab;
pub use context::ContextTab;
pub use custom_checks::{CustomChecksTab, PendingAction};
pub use escalation::EscalationTab;
pub use general::GeneralTab;
pub use groups::GroupsTab;
pub use ignore_deny::{IgnoreDenyTab, Side};
pub use llm::LLMTab;
pub use wrap::WrapTab;

/// Outcome of a key event dispatched to a tab.
#[derive(Debug, Default)]
pub enum TabOutcome {
    /// Nothing changed AND the tab did not consume the key — the App is
    /// free to handle it (e.g. ←/→ switching top-level tabs).
    #[default]
    None,
    /// The user moved focus to a different field; the App should update
    /// the focused-field strip at the bottom of the screen.
    FieldFocusChanged(FieldFocus),
    /// The user mutated `DraftSettings.current`; preview / dirty marker
    /// should refresh.
    Mutated,
    /// The tab consumed the key but didn't change anything visible (e.g.
    /// matrix cursor at boundary). The App should NOT process this key.
    Consumed,
}

/// Information about the currently focused field — used by the App to
/// render the bottom help strip ("Selected: ...").
#[derive(Debug, Clone, Default)]
pub struct FieldFocus {
    pub name: String,
    pub badges: Vec<&'static str>,
    pub help: String,
}

pub trait Tab {
    fn title(&self) -> &str;

    /// Returns Some(badge) for mode-specific tabs (AI / Wrap),
    /// None for shared tabs.
    fn mode_badge(&self) -> Option<&'static str> {
        None
    }

    fn render(&self, area: Rect, buf: &mut Buffer, draft: &DraftSettings);

    fn handle_key(&mut self, key: KeyEvent, draft: &mut DraftSettings) -> TabOutcome;

    /// Description of the currently focused field. Used by the App to
    /// render the bottom strip on a freshly-opened tab.
    fn current_focus(&self) -> FieldFocus;
}
