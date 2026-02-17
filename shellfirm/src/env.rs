//! Environment abstraction for testability.
//!
//! Provides the [`Environment`] trait to abstract all external I/O
//! (env vars, filesystem, subprocesses), enabling fully sandboxed testing.

use std::{
    collections::{HashMap, HashSet},
    io::{BufReader, Read as _},
    path::{Path, PathBuf},
    process, thread,
    time::Duration,
};

use anyhow::Result;
use wait_timeout::ChildExt;

/// Abstracts all interaction with the operating system.
///
/// The real application uses [`RealEnvironment`]; tests inject
/// [`MockEnvironment`] so that nothing touches the real system.
pub trait Environment: Send + Sync {
    /// Read an environment variable.
    fn var(&self, key: &str) -> Option<String>;

    /// Get the current working directory.
    ///
    /// # Errors
    /// Returns an error if the working directory cannot be determined.
    fn current_dir(&self) -> Result<PathBuf>;

    /// Check if a path exists (file or directory).
    fn path_exists(&self, path: &Path) -> bool;

    /// Get the user's home directory.
    fn home_dir(&self) -> Option<PathBuf>;

    /// Run a command and return its stdout, or `None` on failure/timeout.
    fn run_command(&self, cmd: &str, args: &[&str], timeout_ms: u64) -> Option<String>;

    /// Read a file's contents.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read.
    fn read_file(&self, path: &Path) -> Result<String>;

    /// Walk up directories from `start` looking for `filename`.
    /// Returns the full path to the first match, or `None`.
    fn find_file_upward(&self, start: &Path, filename: &str) -> Option<PathBuf>;
}

// ---------------------------------------------------------------------------
// Real implementation (used in production)
// ---------------------------------------------------------------------------

/// Production [`Environment`] backed by the real OS.
pub struct RealEnvironment;

impl Environment for RealEnvironment {
    fn var(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }

    fn current_dir(&self) -> Result<PathBuf> {
        std::env::current_dir().map_err(Into::into)
    }

    fn path_exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn home_dir(&self) -> Option<PathBuf> {
        dirs::home_dir()
    }

    fn run_command(&self, cmd: &str, args: &[&str], timeout_ms: u64) -> Option<String> {
        let mut child = process::Command::new(cmd)
            .args(args)
            .stdin(process::Stdio::null())
            .stdout(process::Stdio::piped())
            .stderr(process::Stdio::null())
            .spawn()
            .ok()?;

        // Read stdout in a separate thread to prevent pipe buffer deadlock.
        // Without this, processes producing >64KB of stdout (e.g. `find` on
        // large directories) block on write, causing wait_timeout to fire
        // even though the process hasn't finished computing.
        let stdout = child.stdout.take()?;
        let reader_handle = thread::spawn(move || {
            let mut output = String::new();
            let mut reader = BufReader::new(stdout);
            let _ = reader.read_to_string(&mut output);
            output
        });

        let timeout = Duration::from_millis(timeout_ms);
        match child.wait_timeout(timeout) {
            Ok(Some(status)) if status.success() => {
                reader_handle.join().ok().map(|o| o.trim().to_string())
            }
            Ok(Some(_)) => {
                // Process exited with non-success status
                None
            }
            Ok(None) => {
                // Timeout — kill the child (closes pipe, unblocks reader)
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader_handle.join();
                None
            }
            Err(_) => None,
        }
    }

    fn read_file(&self, path: &Path) -> Result<String> {
        Ok(std::fs::read_to_string(path)?)
    }

    fn find_file_upward(&self, start: &Path, filename: &str) -> Option<PathBuf> {
        let mut current = start.to_path_buf();
        loop {
            let candidate = current.join(filename);
            if candidate.is_file() {
                return Some(candidate);
            }
            if !current.pop() {
                return None;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Mock implementation (used in tests — zero real I/O)
// ---------------------------------------------------------------------------

/// A fully in-memory [`Environment`] for sandboxed testing.
///
/// Every field is public so tests can construct scenarios declaratively.
#[derive(Debug, Clone, Default)]
pub struct MockEnvironment {
    pub env_vars: HashMap<String, String>,
    pub cwd: PathBuf,
    pub existing_paths: HashSet<PathBuf>,
    pub home: Option<PathBuf>,
    /// Maps `"cmd arg1 arg2"` → stdout output.
    pub command_outputs: HashMap<String, String>,
    /// Virtual filesystem: path → file contents.
    pub files: HashMap<PathBuf, String>,
}

impl Environment for MockEnvironment {
    fn var(&self, key: &str) -> Option<String> {
        self.env_vars.get(key).cloned()
    }

    fn current_dir(&self) -> Result<PathBuf> {
        Ok(self.cwd.clone())
    }

    fn path_exists(&self, path: &Path) -> bool {
        self.existing_paths.contains(path) || self.files.contains_key(path)
    }

    fn home_dir(&self) -> Option<PathBuf> {
        self.home.clone()
    }

    fn run_command(&self, cmd: &str, args: &[&str], _timeout_ms: u64) -> Option<String> {
        let key = format!("{} {}", cmd, args.join(" "));
        self.command_outputs.get(&key).cloned()
    }

    fn read_file(&self, path: &Path) -> Result<String> {
        self.files
            .get(path)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("mock file not found: {}", path.display()))
    }

    fn find_file_upward(&self, start: &Path, filename: &str) -> Option<PathBuf> {
        let mut current = start.to_path_buf();
        loop {
            let candidate = current.join(filename);
            if self.files.contains_key(&candidate) {
                return Some(candidate);
            }
            if !current.pop() {
                return None;
            }
        }
    }
}
