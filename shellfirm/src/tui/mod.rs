//! Terminal UI for `shellfirm config`.
//!
//! Built with `ratatui` + `crossterm`. Public entry point is `run`,
//! invoked from the CLI when `shellfirm config` is called with no
//! subcommand and the `tui` cargo feature is enabled.

// TUI rendering involves many small helpers, u16↔usize coords, and
// stylistic patterns that trip pedantic/nursery lints without indicating
// bugs. Allow them module-wide.
#![allow(
    elided_lifetimes_in_paths,
    clippy::unnested_or_patterns,
    clippy::many_single_char_names,
    clippy::assigning_clones,
    clippy::comparison_chain,
    clippy::explicit_iter_loop,
    clippy::format_push_string,
    clippy::used_underscore_binding,
    clippy::doc_lazy_continuation,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::missing_const_for_fn,
    clippy::option_if_let_else,
    clippy::too_many_lines,
    clippy::too_many_arguments,
    clippy::match_same_arms,
    clippy::match_wildcard_for_single_variants,
    clippy::elidable_lifetime_names,
    clippy::unnecessary_literal_bound,
    clippy::must_use_candidate,
    clippy::unused_self,
    clippy::if_not_else,
    clippy::doc_markdown,
    clippy::needless_pass_by_value,
    clippy::needless_pass_by_ref_mut,
    clippy::manual_let_else,
    clippy::bool_to_int_with_if,
    clippy::single_match_else,
    clippy::derivable_impls,
    clippy::cloned_instead_of_copied,
    clippy::implicit_saturating_sub,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::useless_format,
    clippy::redundant_closure_for_method_calls,
    clippy::similar_names,
    clippy::trivially_copy_pass_by_ref,
    clippy::ref_option,
    clippy::map_unwrap_or,
    clippy::range_plus_one,
    clippy::wildcard_imports,
    clippy::module_name_repetitions,
    clippy::struct_excessive_bools,
    clippy::fn_params_excessive_bools,
    clippy::large_enum_variant,
    clippy::redundant_else,
    clippy::items_after_statements,
    clippy::single_match,
    clippy::unnecessary_wraps,
    clippy::let_underscore_untyped,
    clippy::needless_lifetimes,
    clippy::redundant_clone,
    clippy::uninlined_format_args,
    clippy::needless_raw_string_hashes,
    clippy::default_trait_access,
    clippy::semicolon_if_nothing_returned,
    clippy::return_self_not_must_use,
    clippy::missing_safety_doc,
    clippy::manual_assert,
    clippy::cognitive_complexity,
    clippy::or_fun_call,
    clippy::needless_collect,
    clippy::ignored_unit_patterns,
    clippy::stable_sort_primitive,
    clippy::char_lit_as_u8
)]

pub mod app;
pub mod badges;
pub mod check_form;
pub mod check_store;
pub mod draft;
pub mod preview;
pub mod render;
pub mod style;
pub mod tabs;
pub mod validate;
pub mod widgets;

use crate::error::{Error, Result};
use crate::Config;
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::io;

pub use badges::badge_widget;
pub use check_form::{CheckForm, FormMode, FormOutcome, IdUniquenessValidator};
pub use check_store::CustomCheckStore;
pub use draft::DraftSettings;
pub use preview::{line_diff, render_yaml, DiffLine};
pub use validate::{validate, ValidationError, ValidationReport};

/// Launch the TUI. Blocks until the user quits.
///
/// # Errors
/// Returns an error if the terminal cannot be put into raw mode, if config
/// I/O fails, or if any internal invariant is violated.
pub fn run(config: &Config) -> Result<crate::CmdExit> {
    let mut stdout = io::stdout();
    enable_raw_mode().map_err(|e| Error::Other(e.to_string()))?;
    execute!(stdout, EnterAlternateScreen).map_err(|e| Error::Other(e.to_string()))?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(|e| Error::Other(e.to_string()))?;

    let mut app = app::App::new(config)?;
    let res = run_loop(&mut terminal, &mut app);

    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();
    res?;
    Ok(crate::CmdExit {
        code: exitcode::OK,
        message: None,
    })
}

fn run_loop<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut app::App,
) -> Result<()> {
    use crossterm::event::{self, Event};
    while app.running {
        terminal
            .draw(|f| render::draw(f, app))
            .map_err(|e| Error::Other(e.to_string()))?;
        if let Event::Key(key) =
            event::read().map_err(|e| Error::Other(e.to_string()))?
        {
            app.handle_key(key);
        }
    }
    Ok(())
}
