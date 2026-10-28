//! Unix PTY backend using `nix` / `libc` / `rustix`.

use std::{
    io::IsTerminal,
    os::{
        fd::{AsFd, BorrowedFd, OwnedFd},
        unix::process::CommandExt,
    },
    sync::atomic::{AtomicBool, AtomicI32, Ordering},
    time::{Duration, Instant},
};

use crate::error::{Error, Result};
use nix::{
    fcntl::{fcntl, FcntlArg, FdFlag},
    poll::{PollFd, PollFlags, PollTimeout},
    pty::openpty,
    sys::{
        signal::{self, SaFlags, SigAction, SigHandler, SigSet, Signal},
        termios::{self, FlushArg, LocalFlags, SetArg, Termios},
        wait::{waitpid, WaitPidFlag, WaitStatus},
    },
    unistd::{self, Pid},
};
use tracing::{debug, warn};

use crate::{
    checks::Check,
    config::{Config, Settings},
    env::Environment,
};

use super::{
    common::{decide_submission, CancelKind, LiveRules, ReloadFn, WrapperConfig},
    line::{Interceptor, KeyEvent, TtyState},
    prompt::WrapPrompter,
};

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

static WINCH: AtomicBool = AtomicBool::new(false);
static TERM_SIGNAL: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_winch(_: libc::c_int) {
    WINCH.store(true, Ordering::SeqCst);
}

extern "C" fn on_term(sig: libc::c_int) {
    TERM_SIGNAL.store(sig, Ordering::SeqCst);
}

/// Installs SIGWINCH / SIGINT / SIGTERM / SIGHUP / SIGQUIT handlers and restores the
/// previous dispositions on drop.
struct SignalGuard {
    saved: Vec<(Signal, SigAction)>,
}

impl SignalGuard {
    fn install() -> Self {
        WINCH.store(false, Ordering::SeqCst);
        TERM_SIGNAL.store(0, Ordering::SeqCst);
        let mut saved = Vec::new();
        let table: [(Signal, extern "C" fn(libc::c_int)); 5] = [
            (Signal::SIGWINCH, on_winch),
            (Signal::SIGINT, on_term),
            (Signal::SIGTERM, on_term),
            (Signal::SIGHUP, on_term),
            (Signal::SIGQUIT, on_term),
        ];
        for (sig, handler) in table {
            // No SA_RESTART: poll() returns EINTR so the loop reacts at once.
            let action = SigAction::new(
                SigHandler::Handler(handler),
                SaFlags::empty(),
                SigSet::empty(),
            );
            // SAFETY: the handlers only store into atomics (async-signal-safe).
            match unsafe { signal::sigaction(sig, &action) } {
                Ok(old) => saved.push((sig, old)),
                Err(e) => warn!("[wrap] sigaction({sig}) failed: {e}"),
            }
        }
        Self { saved }
    }
}

impl Drop for SignalGuard {
    fn drop(&mut self) {
        for (sig, old) in self.saved.drain(..) {
            // SAFETY: restoring a previously-installed disposition.
            let _ = unsafe { signal::sigaction(sig, &old) };
        }
    }
}

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
        let fd = dup_cloexec(std::io::stdin().as_fd())?;
        let original =
            termios::tcgetattr(&fd).map_err(|e| Error::Wrap(format!("tcgetattr: {e}")))?;
        let mut raw = original.clone();
        termios::cfmakeraw(&mut raw);
        termios::tcsetattr(&fd, SetArg::TCSANOW, &raw)
            .map_err(|e| Error::Wrap(format!("tcsetattr raw: {e}")))?;
        Ok(Self { fd, original })
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = termios::tcsetattr(&self.fd, SetArg::TCSAFLUSH, &self.original);
    }
}

// ---------------------------------------------------------------------------
// ChildGuard — never leave the wrapped program behind
// ---------------------------------------------------------------------------

const fn status_code(status: WaitStatus) -> Option<i32> {
    match status {
        WaitStatus::Exited(_, code) => Some(code),
        WaitStatus::Signaled(_, sig, _) => Some(128 + sig as i32),
        _ => None,
    }
}

/// Owns the child pid; terminates and reaps it on drop unless it was reaped.
struct ChildGuard {
    pid: Pid,
    code: Option<i32>,
}

impl ChildGuard {
    /// Non-blocking reap. Returns the exit code if the child is gone.
    fn try_wait(&mut self) -> Option<i32> {
        if self.code.is_none() {
            if let Ok(st) = waitpid(self.pid, Some(WaitPidFlag::WNOHANG)) {
                self.code = status_code(st);
            }
        }
        self.code
    }

    fn wait_for(&mut self, timeout: Duration) -> Option<i32> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(c) = self.try_wait() {
                return Some(c);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Hang up the child's session (like a closed terminal), escalating to
    /// SIGTERM and SIGKILL. Returns the exit code.
    fn terminate(&mut self) -> i32 {
        if let Some(c) = self.try_wait() {
            return c;
        }
        // The child is a session/process-group leader (setsid in pre_exec):
        // signal the whole group so its own children go too.
        for sig in [Signal::SIGHUP, Signal::SIGTERM, Signal::SIGKILL] {
            let _ = signal::killpg(self.pid, sig);
            let _ = signal::kill(self.pid, sig);
            let _ = signal::kill(self.pid, Signal::SIGCONT);
            if let Some(c) = self.wait_for(Duration::from_millis(700)) {
                return c;
            }
        }
        if let Ok(st) = waitpid(self.pid, None) {
            self.code = status_code(st);
        }
        self.code.unwrap_or(1)
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.code.is_none() {
            let _ = self.terminate();
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn dup_cloexec(fd: BorrowedFd<'_>) -> Result<OwnedFd> {
    let raw =
        fcntl(fd, FcntlArg::F_DUPFD_CLOEXEC(3)).map_err(|e| Error::Wrap(format!("dup: {e}")))?;
    // SAFETY: F_DUPFD_CLOEXEC returned a fresh descriptor we now own.
    Ok(unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(raw) })
}

fn set_cloexec(fd: BorrowedFd<'_>) -> Result<()> {
    fcntl(fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
        .map(|_| ())
        .map_err(|e| Error::Wrap(format!("fcntl(FD_CLOEXEC): {e}")))
}

fn sync_term_size(master_fd: BorrowedFd<'_>) -> Option<(usize, usize)> {
    let ws = rustix::termios::tcgetwinsize(std::io::stdin()).ok()?;
    // TIOCSWINSZ on the master; the kernel sends SIGWINCH to the child's
    // foreground process group.
    let _ = rustix::termios::tcsetwinsize(master_fd, ws);
    Some((usize::from(ws.ws_col), usize::from(ws.ws_row)))
}

/// The child's terminal mode (on Linux and macOS termios requests on the
/// master act on the shared tty, i.e. the slave settings the child set).
fn child_tty_state(master: BorrowedFd<'_>) -> Option<TtyState> {
    let t = termios::tcgetattr(master).ok()?;
    Some(TtyState {
        echo: t.local_flags.contains(LocalFlags::ECHO),
        icanon: t.local_flags.contains(LocalFlags::ICANON),
    })
}

/// Where challenges are drawn: the controlling terminal, so that
/// `shellfirm wrap psql 2>err.log` still shows them. Falls back to stderr.
fn challenge_output() -> Box<dyn std::io::Write> {
    std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/tty")
        .map_or_else(
            |_| Box::new(std::io::stderr()) as Box<dyn std::io::Write>,
            |f| Box::new(f) as Box<dyn std::io::Write>,
        )
}

/// A printable preview of input that is not sent to the child.
fn preview(bytes: &[u8], max: usize) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut out = String::new();
    for (n, c) in text.chars().enumerate() {
        if n >= max {
            out.push_str("...");
            break;
        }
        match c {
            '\r' | '\n' => out.push('⏎'),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

fn write_all_fd(fd: BorrowedFd<'_>, data: &[u8]) -> Result<()> {
    let mut written = 0;
    while written < data.len() {
        match unistd::write(fd, &data[written..]) {
            Ok(n) => written += n,
            Err(nix::errno::Errno::EINTR | nix::errno::Errno::EAGAIN) => {}
            Err(e) => return Err(Error::Wrap(format!("write error: {e}"))),
        }
    }
    Ok(())
}

/// Blocking single-byte read from stdin for the challenge prompt. Gives up
/// (returns `None` = cancel) on EOF, error or a termination signal.
fn read_stdin_byte() -> Option<u8> {
    let stdin = std::io::stdin();
    let fd = stdin.as_fd();
    let mut b = [0u8; 1];
    loop {
        if TERM_SIGNAL.load(Ordering::SeqCst) != 0 {
            return None;
        }
        let mut pfd = [PollFd::new(fd, PollFlags::POLLIN)];
        match nix::poll::poll(&mut pfd, PollTimeout::from(200u16)) {
            Ok(0) | Err(nix::errno::Errno::EINTR) => continue,
            Ok(_) => {}
            Err(_) => return None,
        }
        match unistd::read(fd, &mut b) {
            Ok(1) => return Some(b[0]),
            Err(nix::errno::Errno::EINTR | nix::errno::Errno::EAGAIN) => {}
            _ => return None,
        }
    }
}

nix::ioctl_write_int_bad!(tiocsctty, libc::TIOCSCTTY);

// ---------------------------------------------------------------------------
// PtyProxy
// ---------------------------------------------------------------------------

/// Why the event loop ended.
enum LoopExit {
    ChildExited(i32),
    MasterClosed,
    StdinClosed,
    Signal(i32),
    Error(String),
}

/// PTY proxy that wraps an interactive program.
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
    /// Spawn the wrapped program in a PTY and run the proxy event loop.
    ///
    /// Returns the child's exit code (`128 + signal` if it was killed).
    ///
    /// # Errors
    /// Returns an error if stdin is not a terminal, or PTY creation / spawn
    /// fails.
    pub fn run(&self, program: &str, args: &[String]) -> Result<i32> {
        if !std::io::stdin().is_terminal() {
            return Err(Error::Wrap(
                "stdin is not a terminal — `shellfirm wrap` proxies interactive sessions only. \
                 Run the program directly, or check SQL/commands with `shellfirm check`."
                    .into(),
            ));
        }

        let pty =
            openpty(None, None).map_err(|e| Error::Wrap(format!("failed to open PTY: {e}")))?;
        let master_fd = pty.master;
        let slave_fd = pty.slave;
        // Neither end may leak into the child beyond fds 0/1/2 — otherwise the
        // child holds the master open and never sees a hangup when shellfirm
        // goes away.
        set_cloexec(master_fd.as_fd())?;
        set_cloexec(slave_fd.as_fd())?;
        let slave_stdout = dup_cloexec(slave_fd.as_fd())?;
        let slave_stderr = dup_cloexec(slave_fd.as_fd())?;

        let _ = sync_term_size(master_fd.as_fd());

        let mut cmd = std::process::Command::new(program);
        cmd.args(args)
            .stdin(std::process::Stdio::from(slave_fd))
            .stdout(std::process::Stdio::from(slave_stdout))
            .stderr(std::process::Stdio::from(slave_stderr));

        // SAFETY: pre_exec runs after fork in the child process.
        // setsid() creates a new session; TIOCSCTTY sets the PTY slave
        // (already dup2'd to stdin by Command) as the controlling terminal.
        unsafe {
            cmd.pre_exec(|| {
                unistd::setsid().map_err(std::io::Error::other)?;
                tiocsctty(libc::STDIN_FILENO, 0).map_err(std::io::Error::other)?;
                Ok(())
            });
        }

        let spawned = cmd.spawn();
        // Close the parent's copies of the slave fds right away so that the
        // master reports EIO as soon as the child exits.
        drop(cmd);
        let child = spawned.map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => Error::Wrap(format!("{program}: command not found")),
            std::io::ErrorKind::PermissionDenied => {
                Error::Wrap(format!("{program}: permission denied"))
            }
            _ => Error::Wrap(format!("failed to start {program}: {e}")),
        })?;
        let pid = Pid::from_raw(
            i32::try_from(child.id()).map_err(|e| Error::Wrap(format!("invalid pid: {e}")))?,
        );
        let mut child_guard = ChildGuard { pid, code: None };

        let signals = SignalGuard::install();
        let raw_guard = RawModeGuard::enter()?;

        let exit = self.event_loop(&master_fd, &mut child_guard);

        let code = match exit {
            LoopExit::ChildExited(code) => Ok(code),
            LoopExit::MasterClosed => Ok(child_guard
                .wait_for(Duration::from_secs(2))
                .unwrap_or_else(|| child_guard.terminate())),
            LoopExit::StdinClosed => Ok(child_guard.terminate()),
            LoopExit::Signal(sig) => {
                let _ = child_guard.terminate();
                Ok(128 + sig)
            }
            LoopExit::Error(e) => {
                let _ = child_guard.terminate();
                Err(Error::Wrap(e))
            }
        };
        drop(raw_guard);
        drop(signals);
        code
    }

    /// Read whatever the child has written, show it and feed the echo
    /// tracker. Bounded so a chatty child can't stall a challenge forever.
    fn drain_child_output(master: BorrowedFd<'_>, ic: &Interceptor, wait_ms: u16) {
        let stdout = std::io::stdout();
        let mut buf = [0u8; 4096];
        let mut total = 0usize;
        loop {
            let mut pfd = [PollFd::new(master, PollFlags::POLLIN)];
            match nix::poll::poll(&mut pfd, PollTimeout::from(wait_ms)) {
                Ok(n) if n > 0 => match unistd::read(master, &mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let _ = write_all_fd(stdout.as_fd(), &buf[..n]);
                        ic.on_child_output(&buf[..n]);
                        total += n;
                        if total > 1 << 20 {
                            break;
                        }
                    }
                },
                _ => break,
            }
        }
    }

    /// Main event loop: poll stdin and master PTY.
    #[allow(clippy::too_many_lines)]
    fn event_loop(&self, master_fd: &OwnedFd, child: &mut ChildGuard) -> LoopExit {
        let stdin = std::io::stdin();
        let stdout = std::io::stdout();
        let stdin_fd = stdin.as_fd();
        let master = master_fd.as_fd();
        let wc = &self.wrapper_config;
        let mut ic = Interceptor::new(wc.mode);
        if let Some((cols, rows)) = sync_term_size(master) {
            ic.set_size(cols, rows);
        }
        let mut buf = [0u8; 4096];

        let prompter = WrapPrompter::new(
            &wc.display_name,
            Box::new(read_stdin_byte),
            challenge_output(),
            Box::new(|| {
                // Type-ahead must never answer a challenge.
                let _ = termios::tcflush(std::io::stdin().as_fd(), FlushArg::TCIFLUSH);
            }),
        );
        let mut rules = LiveRules::new(self.settings, self.checks, self.all_checks, wc)
            .watching(self.watch.clone(), self.reload);

        loop {
            let sig = TERM_SIGNAL.load(Ordering::SeqCst);
            if sig != 0 {
                return LoopExit::Signal(sig);
            }
            if WINCH.swap(false, Ordering::SeqCst) {
                if let Some((cols, rows)) = sync_term_size(master) {
                    ic.set_size(cols, rows);
                }
            }
            if let Some(code) = child.try_wait() {
                Self::drain_child_output(master, &ic, 20);
                return LoopExit::ChildExited(code);
            }

            let mut poll_fds = [
                PollFd::new(stdin_fd, PollFlags::POLLIN),
                PollFd::new(master, PollFlags::POLLIN),
            ];
            match nix::poll::poll(&mut poll_fds, PollTimeout::from(100u16)) {
                Ok(0) | Err(nix::errno::Errno::EINTR) => continue,
                Ok(_) => {}
                Err(e) => return LoopExit::Error(format!("poll error: {e}")),
            }
            let stdin_ev = poll_fds[0].revents().unwrap_or(PollFlags::empty());
            let master_ev = poll_fds[1].revents().unwrap_or(PollFlags::empty());

            // Child output → user (stdout)
            if master_ev.intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR) {
                match unistd::read(master, &mut buf) {
                    Ok(0) | Err(nix::errno::Errno::EIO) => return LoopExit::MasterClosed,
                    Ok(n) => {
                        let _ = write_all_fd(stdout.as_fd(), &buf[..n]);
                        ic.on_child_output(&buf[..n]);
                    }
                    Err(nix::errno::Errno::EINTR | nix::errno::Errno::EAGAIN) => {}
                    Err(e) => return LoopExit::Error(format!("read from child: {e}")),
                }
            }

            if stdin_ev.intersects(PollFlags::POLLHUP | PollFlags::POLLERR)
                && !stdin_ev.contains(PollFlags::POLLIN)
            {
                return LoopExit::StdinClosed;
            }
            if !stdin_ev.contains(PollFlags::POLLIN) {
                continue;
            }

            // User input → child (master)
            let n = match unistd::read(stdin_fd, &mut buf) {
                Ok(0) | Err(nix::errno::Errno::EIO) => return LoopExit::StdinClosed,
                Ok(n) => n,
                Err(nix::errno::Errno::EINTR | nix::errno::Errno::EAGAIN) => continue,
                Err(e) => return LoopExit::Error(format!("read from terminal: {e}")),
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

                // Enter: everything typed so far reaches the child first so
                // its echo is up to date, then the Enter byte is held.
                if let Err(e) = write_all_fd(master, &pass_through) {
                    return LoopExit::Error(e.to_string());
                }
                pass_through.clear();
                // After history recall / Tab the echo is the source of truth:
                // give the child a moment to finish redrawing.
                let wait = if ic.needs_echo() { 60 } else { 10 };
                Self::drain_child_output(master, &ic, wait);
                let tty = child_tty_state(master);
                if !ic.needs_echo() && !tty.is_some_and(TtyState::is_secret_prompt) {
                    // The echo should show what was typed; on a slow link
                    // (ssh, kubectl exec) wait a little longer for it.
                    let deadline = Instant::now() + Duration::from_millis(250);
                    while !ic.echo_confirms_model() && Instant::now() < deadline {
                        Self::drain_child_output(master, &ic, 25);
                    }
                }
                ic.set_tty_state(tty);

                let sub = ic.take_submission();
                debug!("[wrap] Enter: {}", sub.log_summary());
                if sub.is_empty() {
                    pass_through.push(byte);
                    continue;
                }

                if rules.refresh() {
                    prompter.say(&format!(
                        "{}",
                        console::style("shellfirm: settings changed; reloaded").dim()
                    ));
                }
                let approved_notice = rules.settings.approved_notice;
                let ctx = rules.context(self.env, &prompter, self.config);
                let decision = decide_submission(&sub, &ctx, &|s| prompter.set_statement(s));
                if decision.forward {
                    if decision.challenged && approved_notice {
                        prompter.say(&format!(
                            "{}",
                            console::style(super::common::approved_sending_line(
                                &wc.display_name,
                                sub.count
                            ))
                            .dim()
                        ));
                    }
                    pass_through.push(byte);
                } else {
                    ic.discard();
                    prompter.say(&format!(
                        "{}",
                        console::style(format!(
                            "shellfirm: statement discarded; your {} session is still open.",
                            wc.display_name
                        ))
                        .yellow()
                    ));
                    pass_through.extend_from_slice(wc.cancel.bytes());
                    if let Err(e) = write_all_fd(master, &pass_through) {
                        return LoopExit::Error(e.to_string());
                    }
                    pass_through.clear();
                    if wc.cancel == CancelKind::KillLine {
                        // Ctrl-E Ctrl-U clears the line in place without a new
                        // prompt. Let the child finish its redraw, then repaint
                        // the prompt below our message.
                        Self::drain_child_output(master, &ic, 40);
                        if let Some(p) = ic.last_prompt().filter(|p| !p.trim().is_empty()) {
                            let p = p.to_string();
                            let _ = write_all_fd(stdout.as_fd(), p.as_bytes());
                            ic.on_child_output(p.as_bytes());
                        }
                    }
                }
                if decision.challenged && i < input.len() {
                    // Type-ahead/paste after a challenged line is dropped: it
                    // was written before the user saw the warning.
                    let rest = &input[i..];
                    prompter.say(&format!(
                        "{}",
                        console::style(format!(
                            "shellfirm: the rest of the paste/type-ahead was NOT sent ({} byte(s)): {}",
                            rest.len(),
                            preview(rest, 120)
                        ))
                        .yellow()
                    ));
                    prompter.say(&format!(
                        "{}",
                        console::style(
                            "shellfirm: lines before the challenged one were already sent \
                             (e.g. BEGIN); run the rest again yourself if you still want it \
                             (e.g. COMMIT or ROLLBACK)."
                        )
                        .dim()
                    ));
                    break;
                }
            }
            if let Err(e) = write_all_fd(master, &pass_through) {
                return LoopExit::Error(e.to_string());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn status_code_mapping() {
        let pid = Pid::from_raw(1);
        assert_eq!(status_code(WaitStatus::Exited(pid, 3)), Some(3));
        assert_eq!(
            status_code(WaitStatus::Signaled(pid, Signal::SIGHUP, false)),
            Some(129)
        );
        assert_eq!(status_code(WaitStatus::StillAlive), None);
    }

    #[test]
    fn dup_cloexec_sets_flag() {
        let (r, _w) = unistd::pipe().unwrap();
        let d = dup_cloexec(r.as_fd()).unwrap();
        let flags = fcntl(d.as_fd(), FcntlArg::F_GETFD).unwrap();
        assert!(FdFlag::from_bits_truncate(flags).contains(FdFlag::FD_CLOEXEC));
        assert!(d.as_raw_fd() >= 3);
    }
}
