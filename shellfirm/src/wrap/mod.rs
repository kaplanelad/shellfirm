//! PTY proxy for wrapping interactive programs (psql, mysql, redis-cli, etc.).
//!
//! Forwards all keystrokes to the child process in real time so that echoing,
//! tab-completion and line editing work naturally. Interception happens when
//! the user presses **Enter** (CR or LF): the Enter byte is held back while the
//! statement(s) it would execute are run through
//! [`crate::checks::analyze_command`]. If the user declines the challenge (or a
//! deny rule matches) the statement is discarded in the child (Ctrl-C or
//! Ctrl-E Ctrl-U, depending on the tool) and the session stays open.
//!
//! See [`mod@line`] for how the typed line is reconstructed (line-edit model,
//! child-echo re-sync, prompt resync) and [`mod@lexer`] for the per-client
//! statement lexers and meta-commands.

mod common;
pub mod lexer;
pub mod line;
pub mod prompt;
pub mod screen;
pub mod startup;
pub use common::*;
pub use lexer::{Dialect, MetaCommand, MetaKind};
pub use line::{Interceptor, KeyEvent, StatementMode, Submission, TtyState};
pub use prompt::{PromptOutcome, WrapPrompter};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::PtyProxy;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::PtyProxy;
