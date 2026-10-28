//! Windows ConPTY backend using `portable-pty` and `windows-sys`.

use std::{
    io::{Read, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
};

use crate::error::{Error, Result};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use tracing::warn;
use windows_sys::Win32::{
    Foundation::HANDLE,
    System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT,
        ENABLE_PROCESSED_INPUT, ENABLE_VIRTUAL_TERMINAL_INPUT, STD_INPUT_HANDLE,
    },
};

use crate::{
    checks::Check,
    config::{Config, Settings},
    env::Environment,
};

use super::{
    common::{decide_submission, CancelKind, LiveRules, ReloadFn, WrapperConfig},
    line::{Interceptor, KeyEvent},
    prompt::WrapPrompter,
};

// ---------------------------------------------------------------------------
// WinRawModeGuard — RAII helper for console raw mode
// ---------------------------------------------------------------------------

/// RAII guard that restores console mode on drop.
struct WinRawModeGuard {
    handle: HANDLE,
    original_mode: u32,
}

impl WinRawModeGuard {
    /// Enter raw mode on the console stdin handle.
    fn enter() -> Result<Self> {
        let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        if handle.is_null() || handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            return Err(Error::Wrap("GetStdHandle failed".into()));
        }

        let mut original_mode: u32 = 0;
        let ok = unsafe { GetConsoleMode(handle, &mut original_mode) };
        if ok == 0 {
            return Err(Error::Wrap("GetConsoleMode failed".into()));
        }

        let raw_mode = (original_mode
            & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT))
            | ENABLE_VIRTUAL_TERMINAL_INPUT;

        let ok = unsafe { SetConsoleMode(handle, raw_mode) };
        if ok == 0 {
            return Err(Error::Wrap("SetConsoleMode (raw) failed".into()));
        }

        Ok(Self {
            handle,
            original_mode,
        })
    }
}

// SAFETY: HANDLE is a raw pointer but Windows console handles are
// process-global and safe to send across threads.
unsafe impl Send for WinRawModeGuard {}

impl Drop for WinRawModeGuard {
    fn drop(&mut self) {
        unsafe {
            SetConsoleMode(self.handle, self.original_mode);
        }
    }
}

// ---------------------------------------------------------------------------
// PtyProxy
// ---------------------------------------------------------------------------

/// Message from the output thread to the main thread.
enum OutputMsg {
    /// The PTY read returned EOF or an error (child likely gone).
    ReadEof,
}

/// PTY proxy that wraps an interactive program (Windows implementation).
pub struct PtyProxy<'a> {
    pub wrapper_config: WrapperConfig,
    pub settings: &'a Settings,
    pub checks: &'a [Check],
    /// Every active check (shell escapes such as `\!` are checked with all).
    pub all_checks: &'a [Check],
    pub env: &'a dyn Environment,
    pub config: &'a Config,
    /// Re-reads settings and checks when a file in `watch` changes.
    pub reload: Option<&'a ReloadFn<'a>>,
    /// Files whose change triggers `reload` (settings file, custom checks).
    pub watch: Vec<std::path::PathBuf>,
}

impl PtyProxy<'_> {
    /// Spawn the wrapped program in a ConPTY and run the proxy event loop.
    ///
    /// Returns the child's exit code.
    ///
    /// # Errors
    /// Returns an error if ConPTY creation or process spawn fails.
    #[allow(clippy::too_many_lines)]
    pub fn run(&self, program: &str, args: &[String]) -> Result<i32> {
        if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            return Err(Error::Wrap(
                "stdin is not a terminal — `shellfirm wrap` proxies interactive sessions only."
                    .into(),
            ));
        }
        let pty_system = native_pty_system();

        // Get terminal size from the hosting console
        let size = PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        };

        let pair = pty_system
            .openpty(size)
            .map_err(|e| Error::Wrap(format!("failed to open ConPTY: {e}")))?;

        // Build the command
        let mut cmd = CommandBuilder::new(program);
        for arg in args {
            cmd.arg(arg);
        }

        // Spawn the child in the PTY
        let mut child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| Error::Wrap(format!("failed to spawn child: {e}")))?;

        // Get reader (child output) and writer (child input)
        let mut pty_reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| Error::Wrap(format!("failed to clone PTY reader: {e}")))?;
        let mut pty_writer = pair
            .master
            .take_writer()
            .map_err(|e| Error::Wrap(format!("failed to take PTY writer: {e}")))?;

        // Enter raw mode on the hosting console
        let guard = WinRawModeGuard::enter()
            .map_err(|e| Error::Wrap(format!("failed to enter raw mode: {e}")))?;

        // Shared flag to pause output during challenge prompts
        let output_paused = Arc::new(AtomicBool::new(false));
        let output_paused_clone = Arc::clone(&output_paused);

        let wc = &self.wrapper_config;
        let mut ic = Interceptor::new(wc.mode);
        let screen = ic.screen_handle();

        // Channel: output thread → main thread for child exit notification
        let (tx, rx) = mpsc::channel::<OutputMsg>();

        // --- Output thread: PTY reader → stdout (+ echo tracker) ---
        let output_thread = thread::spawn(move || {
            let mut stdout = std::io::stdout();
            let mut buf = [0u8; 4096];
            loop {
                match pty_reader.read(&mut buf) {
                    Ok(0) => {
                        let _ = tx.send(OutputMsg::ReadEof);
                        break;
                    }
                    Ok(n) => {
                        if let Ok(mut s) = screen.lock() {
                            s.feed(&buf[..n]);
                        }
                        if !output_paused_clone.load(Ordering::Acquire) {
                            let _ = stdout.write_all(&buf[..n]);
                            let _ = stdout.flush();
                        }
                    }
                    Err(_) => {
                        let _ = tx.send(OutputMsg::ReadEof);
                        break;
                    }
                }
            }
        });

        let prompter = WrapPrompter::new(
            &wc.display_name,
            Box::new(|| {
                let mut b = [0u8; 1];
                match std::io::stdin().read(&mut b) {
                    Ok(1) => Some(b[0]),
                    _ => None,
                }
            }),
            Box::new(std::io::stderr()),
            Box::new(|| {}),
        );
        let mut rules = LiveRules::new(self.settings, self.checks, self.all_checks, wc)
            .watching(self.watch.clone(), self.reload);

        // --- Main thread: stdin → PTY writer ---
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 4096];

        let exit_code = loop {
            // Check for child exit (non-blocking)
            match rx.try_recv() {
                Ok(OutputMsg::ReadEof) => match child.wait() {
                    Ok(status) => {
                        break status.exit_code().try_into().unwrap_or(1);
                    }
                    Err(_) => break 1,
                },
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => match child.wait() {
                    Ok(status) => {
                        break status.exit_code().try_into().unwrap_or(1);
                    }
                    Err(_) => break 1,
                },
            }

            match child.try_wait() {
                Ok(Some(status)) => {
                    break status.exit_code().try_into().unwrap_or(1);
                }
                Ok(None) => {}
                Err(_) => break 1,
            }

            // Read from stdin (blocking read with small buffer)
            let n = match stdin.read(&mut buf) {
                Ok(0) => {
                    let _ = child.kill();
                    break 0;
                }
                Ok(n) => n,
                Err(e) => {
                    warn!("[wrap] read stdin error: {e}");
                    let _ = child.kill();
                    break 1;
                }
            };
            let input = buf[..n].to_vec();
            let mut pass_through: Vec<u8> = Vec::with_capacity(n);
            let mut i = 0;
            while i < input.len() {
                let byte = input[i];
                i += 1;
                if ic.feed_key(byte) != KeyEvent::Enter {
                    pass_through.push(byte);
                    continue;
                }
                let _ = pty_writer.write_all(&pass_through);
                let _ = pty_writer.flush();
                pass_through.clear();
                // Let the output thread catch up with the echo.
                thread::sleep(std::time::Duration::from_millis(if ic.needs_echo() {
                    60
                } else {
                    10
                }));

                let sub = ic.take_submission();
                if sub.is_empty() {
                    pass_through.push(byte);
                    continue;
                }

                output_paused.store(true, Ordering::Release);
                rules.refresh();
                let ctx = rules.context(self.env, &prompter, self.config);
                let decision = decide_submission(&sub, &ctx, &|s| prompter.set_statement(s));
                output_paused.store(false, Ordering::Release);

                if decision.forward {
                    pass_through.push(byte);
                } else {
                    ic.discard();
                    pass_through.extend_from_slice(wc.cancel.bytes());
                    prompter.say(&format!(
                        "shellfirm: statement discarded; your {} session is still open.",
                        wc.display_name
                    ));
                    let _ = pty_writer.write_all(&pass_through);
                    let _ = pty_writer.flush();
                    pass_through.clear();
                    if wc.cancel == CancelKind::KillLine {
                        thread::sleep(std::time::Duration::from_millis(40));
                        if let Some(p) = ic.last_prompt().filter(|p| !p.trim().is_empty()) {
                            let mut out = std::io::stdout();
                            let _ = out.write_all(p.as_bytes());
                            let _ = out.flush();
                        }
                    }
                }
                if decision.challenged && i < input.len() {
                    break;
                }
            }
            let _ = pty_writer.write_all(&pass_through);
            let _ = pty_writer.flush();
        };

        // Cleanup
        drop(guard);
        drop(pty_writer);
        let _ = output_thread.join();

        Ok(exit_code)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_mode_calculation() {
        // Verify the bit manipulation for raw mode is correct
        let original: u32 = ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT;
        let raw = (original & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT))
            | ENABLE_VIRTUAL_TERMINAL_INPUT;

        // All input processing flags should be cleared
        assert_eq!(raw & ENABLE_ECHO_INPUT, 0);
        assert_eq!(raw & ENABLE_LINE_INPUT, 0);
        assert_eq!(raw & ENABLE_PROCESSED_INPUT, 0);
        // VT input should be set
        assert_ne!(raw & ENABLE_VIRTUAL_TERMINAL_INPUT, 0);
    }
}
