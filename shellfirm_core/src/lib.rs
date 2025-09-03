//! Shellfirm Core - Platform-agnostic command validation engine
//!
//! This crate provides the core validation logic for shellfirm, designed to be
//! WASM-compatible and platform-agnostic.

pub mod checks;
pub mod command;
pub mod errors;
pub mod filters;

#[cfg(feature = "wasm")]
pub mod wasm;

pub use checks::{
    get_all_checks, run_check_on_command, Challenge, Check, FilterType, ValidationMode, ValidationResult,
};
pub use errors::{Error, Result};
pub use filters::{filter_is_command_contains_string, FilterContext};

/// Platform-agnostic validation options
#[derive(Debug, Clone, Default)]
pub struct ValidationOptions {
    /// List of pattern IDs that should be denied (blocked completely)
    pub deny_pattern_ids: Vec<String>,
    /// Custom filter context for platform-specific checks
    pub filter_context: Option<FilterContext>,
    /// List of severity levels to include in validation (empty = all severities)
    pub allowed_severities: Vec<String>,
}
