//! PTY proxy for wrapping interactive programs (psql, mysql, redis-cli, etc.).
//!
//! Forwards all keystrokes to the child process in real-time so that echoing,
//! tab-completion, and line-editing work naturally. Intercepts only at the
//! statement delimiter boundary (`;` or `\n`), running the accumulated
//! statement through [`crate::checks::analyze_command`] before forwarding.

mod common;
pub use common::*;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::PtyProxy;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::PtyProxy;
