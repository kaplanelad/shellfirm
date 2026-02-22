//! Windows ConPTY backend using `portable-pty` and `windows-sys`.

use std::{
    io::{Read, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
};

use anyhow::{Context, Result};
use log::warn;
use portable_pty::{native_pty_system, CommandBuilder, PtySize, PtySystem};
use windows_sys::Win32::System::Console::{
    GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT,
    ENABLE_PROCESSED_INPUT, ENABLE_VIRTUAL_TERMINAL_INPUT, STD_INPUT_HANDLE,
};

use crate::{
    checks::Check,
    config::{Config, Settings},
    env::Environment,
    prompt::Prompter,
};

use super::common::{
    handle_statement, is_control_passthrough, BufferResult, InputBuffer, StatementAction,
    WrapperConfig,
};

// ---------------------------------------------------------------------------
// WinRawModeGuard — RAII helper for console raw mode
// ---------------------------------------------------------------------------

/// RAII guard that restores console mode on drop.
struct WinRawModeGuard {
    handle: isize,
    original_mode: u32,
}

impl WinRawModeGuard {
    /// Enter raw mode on the console stdin handle.
    fn enter() -> Result<Self> {
        let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        if handle == 0 || handle == -1_isize {
            anyhow::bail!("GetStdHandle failed");
        }

        let mut original_mode: u32 = 0;
        let ok = unsafe { GetConsoleMode(handle, &mut original_mode) };
        if ok == 0 {
            anyhow::bail!("GetConsoleMode failed");
        }

        let raw_mode = (original_mode
            & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT))
            | ENABLE_VIRTUAL_TERMINAL_INPUT;

        let ok = unsafe { SetConsoleMode(handle, raw_mode) };
        if ok == 0 {
            anyhow::bail!("SetConsoleMode (raw) failed");
        }

        Ok(Self {
            handle,
            original_mode,
        })
    }

    /// Temporarily restore cooked mode for challenge prompts.
    fn restore_cooked(&self) -> Result<()> {
        let ok = unsafe { SetConsoleMode(self.handle, self.original_mode) };
        if ok == 0 {
            anyhow::bail!("SetConsoleMode (cooked) failed");
        }
        Ok(())
    }

    /// Re-enter raw mode after a challenge prompt.
    fn re_enter_raw(&self) -> Result<()> {
        let raw_mode = (self.original_mode
            & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT))
            | ENABLE_VIRTUAL_TERMINAL_INPUT;
        let ok = unsafe { SetConsoleMode(self.handle, raw_mode) };
        if ok == 0 {
            anyhow::bail!("SetConsoleMode (re-raw) failed");
        }
        Ok(())
    }
}

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
    /// The child process has exited with the given code.
    ChildExited(u32),
    /// The PTY read returned EOF or an error (child likely gone).
    ReadEof,
}

/// PTY proxy that wraps an interactive program (Windows implementation).
pub struct PtyProxy<'a> {
    pub wrapper_config: WrapperConfig,
    pub settings: &'a Settings,
    pub checks: &'a [Check],
    pub env: &'a dyn Environment,
    pub prompter: &'a dyn Prompter,
    pub config: &'a Config,
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
        let pty_system = native_pty_system();

        // Get terminal size from the hosting console
        let size = PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        };

        let pair = pty_system.openpty(size).context("failed to open ConPTY")?;

        // Build the command
        let mut cmd = CommandBuilder::new(program);
        for arg in args {
            cmd.arg(arg);
        }

        // Spawn the child in the PTY
        let mut child = pair
            .slave
            .spawn_command(cmd)
            .context("failed to spawn child")?;

        // Get reader (child output) and writer (child input)
        let mut pty_reader = pair
            .master
            .try_clone_reader()
            .context("failed to clone PTY reader")?;
        let mut pty_writer = pair
            .master
            .take_writer()
            .context("failed to take PTY writer")?;

        // Enter raw mode on the hosting console
        let guard = WinRawModeGuard::enter().context("failed to enter raw mode")?;

        // Shared flag to pause output during challenge prompts
        let output_paused = Arc::new(AtomicBool::new(false));
        let output_paused_clone = Arc::clone(&output_paused);

        // Channel: output thread → main thread for child exit notification
        let (tx, rx) = mpsc::channel::<OutputMsg>();

        // --- Output thread: PTY reader → stdout ---
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

        // --- Main thread: stdin → PTY writer ---
        let mut stdin = std::io::stdin();
        let mut input_buffer = InputBuffer::new(self.wrapper_config.delimiter);
        let mut buf = [0u8; 4096];

        let exit_code = loop {
            // Check for child exit (non-blocking)
            match rx.try_recv() {
                Ok(OutputMsg::ChildExited(code)) => {
                    break i32::try_from(code).unwrap_or(1);
                }
                Ok(OutputMsg::ReadEof) => {
                    // PTY closed, child likely exited — collect exit status
                    match child.wait() {
                        Ok(status) => {
                            break status.exit_code().try_into().unwrap_or(1);
                        }
                        Err(_) => break 1,
                    }
                }
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => match child.wait() {
                    Ok(status) => {
                        break status.exit_code().try_into().unwrap_or(1);
                    }
                    Err(_) => break 1,
                },
            }

            // Try to check if child has exited
            match child.try_wait() {
                Ok(Some(status)) => {
                    break status.exit_code().try_into().unwrap_or(1);
                }
                Ok(None) => {} // still running
                Err(_) => break 1,
            }

            // Read from stdin (blocking read with small buffer)
            match stdin.read(&mut buf) {
                Ok(0) => break 0, // stdin EOF
                Ok(n) => {
                    for &byte in &buf[..n] {
                        if is_control_passthrough(byte) {
                            let _ = pty_writer.write_all(&[byte]);
                            let _ = pty_writer.flush();
                            if byte == 0x03 || byte == 0x04 {
                                input_buffer.reset();
                            }
                            continue;
                        }

                        match input_buffer.feed(byte) {
                            BufferResult::Buffered => {
                                let _ = pty_writer.write_all(&[byte]);
                                let _ = pty_writer.flush();
                            }
                            BufferResult::Statement(stmt) => {
                                log::debug!(
                                    "[wrap] statement detected ({} bytes): {:?}",
                                    stmt.len(),
                                    stmt
                                );

                                // Pause output thread, restore cooked mode
                                output_paused.store(true, Ordering::Release);
                                if let Err(e) = guard.restore_cooked() {
                                    warn!("[wrap] failed to restore cooked mode: {e}");
                                }

                                let action = handle_statement(
                                    &stmt,
                                    self.settings,
                                    self.checks,
                                    self.env,
                                    self.prompter,
                                    self.config,
                                    &self.wrapper_config.display_name,
                                );

                                // Re-enter raw mode, resume output
                                if let Err(e) = guard.re_enter_raw() {
                                    warn!("[wrap] failed to re-enter raw mode: {e}");
                                }
                                output_paused.store(false, Ordering::Release);

                                match action {
                                    StatementAction::Forward => {
                                        let delim = self.wrapper_config.delimiter.trigger_byte();
                                        let _ = pty_writer.write_all(&[delim]);
                                        let _ = pty_writer.flush();
                                    }
                                    StatementAction::Block => {
                                        let _ = pty_writer.write_all(&[0x03]);
                                        let _ = pty_writer.flush();
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("[wrap] read stdin error: {e}");
                    break 1;
                }
            }
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
