//! Unix PTY backend using `nix` / `libc` / `rustix`.

use std::os::{
    fd::{AsFd, BorrowedFd, OwnedFd},
    unix::process::CommandExt,
};

use crate::error::{Error, Result};
use nix::{
    poll::{PollFd, PollFlags, PollTimeout},
    pty::openpty,
    sys::termios::{self, SetArg, Termios},
    unistd::{self, Pid},
};
use tracing::warn;

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
// RawModeGuard — RAII helper for terminal raw mode
// ---------------------------------------------------------------------------

/// RAII guard that restores terminal settings on drop.
struct RawModeGuard {
    fd: OwnedFd,
    original: Termios,
}

impl RawModeGuard {
    /// Enter raw mode on stdin. Returns a guard that restores on drop.
    fn enter() -> Result<Self> {
        let fd = unistd::dup(std::io::stdin().as_fd())
            .map_err(|e| Error::Wrap(format!("dup stdin: {e}")))?;
        let original =
            termios::tcgetattr(&fd).map_err(|e| Error::Wrap(format!("tcgetattr: {e}")))?;
        let mut raw = original.clone();
        termios::cfmakeraw(&mut raw);
        termios::tcsetattr(&fd, SetArg::TCSANOW, &raw)
            .map_err(|e| Error::Wrap(format!("tcsetattr raw: {e}")))?;
        Ok(Self { fd, original })
    }

    /// Temporarily restore cooked mode for challenge prompts.
    fn restore_cooked(&self) -> Result<()> {
        termios::tcsetattr(&self.fd, SetArg::TCSANOW, &self.original)
            .map_err(|e| Error::Wrap(format!("tcsetattr cooked: {e}")))?;
        Ok(())
    }

    /// Re-enter raw mode after a challenge prompt.
    fn re_enter_raw(&self) -> Result<()> {
        let mut raw = self.original.clone();
        termios::cfmakeraw(&mut raw);
        termios::tcsetattr(&self.fd, SetArg::TCSANOW, &raw)
            .map_err(|e| Error::Wrap(format!("tcsetattr re-raw: {e}")))?;
        Ok(())
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = termios::tcsetattr(&self.fd, SetArg::TCSANOW, &self.original);
    }
}

// ---------------------------------------------------------------------------
// Sync terminal size
// ---------------------------------------------------------------------------

fn sync_term_size(master_fd: BorrowedFd<'_>) {
    if let Ok(ws) = rustix::termios::tcgetwinsize(std::io::stdin()) {
        let _ = rustix::termios::tcsetwinsize(master_fd, ws);
    }
}

// ---------------------------------------------------------------------------
// PtyProxy
// ---------------------------------------------------------------------------

/// PTY proxy that wraps an interactive program.
pub struct PtyProxy<'a> {
    pub wrapper_config: WrapperConfig,
    pub settings: &'a Settings,
    pub checks: &'a [Check],
    pub env: &'a dyn Environment,
    pub prompter: &'a dyn Prompter,
    pub config: &'a Config,
}

impl PtyProxy<'_> {
    /// Spawn the wrapped program in a PTY and run the proxy event loop.
    ///
    /// Returns the child's exit code.
    ///
    /// # Errors
    /// Returns an error if PTY creation, fork, or exec fails.
    pub fn run(&self, program: &str, args: &[String]) -> Result<i32> {
        // Open PTY pair
        let pty =
            openpty(None, None).map_err(|e| Error::Wrap(format!("failed to open PTY: {e}")))?;
        let master_fd = pty.master;
        let slave_fd = pty.slave;

        // Dup slave for stdout/stderr (stdin consumes the original)
        let slave_stdout = unistd::dup(slave_fd.as_fd())
            .map_err(|e| Error::Wrap(format!("dup slave stdout: {e}")))?;
        let slave_stderr = unistd::dup(slave_fd.as_fd())
            .map_err(|e| Error::Wrap(format!("dup slave stderr: {e}")))?;

        let mut cmd = std::process::Command::new(program);
        cmd.args(args)
            .stdin(std::process::Stdio::from(slave_fd))
            .stdout(std::process::Stdio::from(slave_stdout))
            .stderr(std::process::Stdio::from(slave_stderr));

        // SAFETY: pre_exec runs after fork in the child process.
        // setsid() creates a new session; TIOCSCTTY sets the PTY slave
        // (already dup2'd to stdin by Command) as the controlling terminal.
        // The child immediately execs the target program.
        unsafe {
            cmd.pre_exec(|| {
                unistd::setsid().map_err(std::io::Error::other)?;
                tiocsctty(libc::STDIN_FILENO, 0).map_err(std::io::Error::other)?;
                Ok(())
            });
        }

        let child = cmd
            .spawn()
            .map_err(|e| Error::Wrap(format!("failed to spawn child: {e}")))?;
        let child_pid = Pid::from_raw(
            i32::try_from(child.id()).map_err(|e| Error::Wrap(format!("invalid pid: {e}")))?,
        );

        sync_term_size(master_fd.as_fd());
        let guard = RawModeGuard::enter()
            .map_err(|e| Error::Wrap(format!("failed to enter raw mode: {e}")))?;
        let exit_code = self.event_loop(&master_fd, child_pid, &guard);
        drop(guard);

        if let Some(code) = exit_code {
            Ok(code)
        } else {
            let status = nix::sys::wait::waitpid(child_pid, None)
                .map_err(|e| Error::Wrap(format!("waitpid failed: {e}")))?;
            match status {
                nix::sys::wait::WaitStatus::Exited(_, code) => Ok(code),
                nix::sys::wait::WaitStatus::Signaled(_, sig, _) => Ok(128 + sig as i32),
                _ => Ok(1),
            }
        }
    }

    /// Main event loop: poll stdin and master PTY.
    #[allow(clippy::too_many_lines)]
    fn event_loop(&self, master_fd: &OwnedFd, child: Pid, guard: &RawModeGuard) -> Option<i32> {
        let stdin = std::io::stdin();
        let stdout = std::io::stdout();
        let stdin_fd = stdin.as_fd();
        let master_borrow = master_fd.as_fd();
        let mut input_buffer = InputBuffer::new(self.wrapper_config.delimiter);
        let mut buf = [0u8; 4096];

        loop {
            let mut poll_fds = [
                PollFd::new(stdin_fd, PollFlags::POLLIN),
                PollFd::new(master_borrow, PollFlags::POLLIN),
            ];

            match nix::poll::poll(&mut poll_fds, PollTimeout::from(100u16)) {
                Ok(0) => {
                    // Timeout — check if child is still alive
                    match nix::sys::wait::waitpid(child, Some(nix::sys::wait::WaitPidFlag::WNOHANG))
                    {
                        Ok(nix::sys::wait::WaitStatus::Exited(_, code)) => return Some(code),
                        Ok(nix::sys::wait::WaitStatus::Signaled(_, sig, _)) => {
                            return Some(128 + sig as i32);
                        }
                        _ => continue,
                    }
                }
                Ok(_) => {}
                Err(nix::errno::Errno::EINTR) => continue,
                Err(e) => {
                    warn!("[wrap] poll error: {e}");
                    return None;
                }
            }

            // Child output → user (stdout)
            if poll_fds[1]
                .revents()
                .is_some_and(|r| r.contains(PollFlags::POLLIN))
            {
                match unistd::read(master_fd.as_fd(), &mut buf) {
                    Ok(0) | Err(nix::errno::Errno::EIO) => return None,
                    Ok(n) => {
                        let _ = write_all_fd(stdout.as_fd(), &buf[..n]);
                    }
                    Err(nix::errno::Errno::EINTR) => {}
                    Err(e) => {
                        warn!("[wrap] read master error: {e}");
                        return None;
                    }
                }
            }

            // Check for hangup on master (child exited)
            if poll_fds[1]
                .revents()
                .is_some_and(|r| r.contains(PollFlags::POLLHUP))
            {
                // Drain remaining output
                loop {
                    match unistd::read(master_fd.as_fd(), &mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let _ = write_all_fd(stdout.as_fd(), &buf[..n]);
                        }
                    }
                }
                return None;
            }

            // User input → child (master)
            if poll_fds[0]
                .revents()
                .is_some_and(|r| r.contains(PollFlags::POLLIN))
            {
                match unistd::read(stdin_fd, &mut buf) {
                    Ok(0) => return None, // stdin EOF
                    Ok(n) => {
                        for &byte in &buf[..n] {
                            if is_control_passthrough(byte) {
                                // Forward control chars immediately, bypass buffer
                                let _ = write_all_fd(master_borrow, &[byte]);
                                if byte == 0x03 || byte == 0x04 {
                                    // Ctrl-C or Ctrl-D: reset buffer
                                    input_buffer.reset();
                                }
                                continue;
                            }

                            // Feed to our buffer for delimiter detection
                            match input_buffer.feed(byte) {
                                BufferResult::Buffered => {
                                    // Not a delimiter — forward to child for echoing
                                    let _ = write_all_fd(master_borrow, &[byte]);
                                }
                                BufferResult::Statement(stmt) => {
                                    tracing::debug!(
                                        "[wrap] statement detected ({} bytes): {:?}",
                                        stmt.len(),
                                        stmt
                                    );

                                    // Drain pending child output before showing challenge
                                    Self::drain_child_output(master_fd, stdout.as_fd());

                                    // Temporarily restore cooked mode for challenge
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

                                    if let Err(e) = guard.re_enter_raw() {
                                        warn!("[wrap] failed to re-enter raw mode: {e}");
                                    }

                                    match action {
                                        StatementAction::Forward => {
                                            // Forward the delimiter byte
                                            let delim =
                                                self.wrapper_config.delimiter.trigger_byte();
                                            let _ = write_all_fd(master_borrow, &[delim]);
                                        }
                                        StatementAction::Block => {
                                            // Send Ctrl-C to cancel pending input
                                            let _ = write_all_fd(master_borrow, &[0x03]);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(nix::errno::Errno::EINTR) => {}
                    Err(e) => {
                        warn!("[wrap] read stdin error: {e}");
                        return None;
                    }
                }
            }
        }
    }

    /// Drain any pending output from the child PTY before showing a challenge.
    ///
    /// This prevents psql's echo/prompt output from mixing with the challenge
    /// display.
    fn drain_child_output(master_fd: &OwnedFd, stdout_fd: BorrowedFd<'_>) {
        let mut drain_buf = [0u8; 4096];
        loop {
            let mut pfd = [PollFd::new(master_fd.as_fd(), PollFlags::POLLIN)];
            match nix::poll::poll(&mut pfd, PollTimeout::from(10u16)) {
                Ok(0) => break, // no more data
                Ok(_) => match unistd::read(master_fd.as_fd(), &mut drain_buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let _ = write_all_fd(stdout_fd, &drain_buf[..n]);
                    }
                },
                _ => break,
            }
        }
    }
}

nix::ioctl_write_int_bad!(tiocsctty, libc::TIOCSCTTY);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn write_all_fd(fd: BorrowedFd<'_>, data: &[u8]) -> Result<()> {
    let mut written = 0;
    while written < data.len() {
        match unistd::write(fd, &data[written..]) {
            Ok(n) => written += n,
            Err(nix::errno::Errno::EINTR) => {}
            Err(e) => return Err(Error::Wrap(format!("write error: {e}"))),
        }
    }
    Ok(())
}
