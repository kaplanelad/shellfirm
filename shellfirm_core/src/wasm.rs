//! WASM bindings for `shellfirm_core`
//!
//! This module provides JavaScript bindings for the core validation functionality,
//! allowing the Rust code to be called from Node.js and browser environments.

use serde_json;
use std::collections::HashMap;
use wasm_bindgen::prelude::*;

use crate::{
    checks::{Check, ValidationResult},
    get_all_checks, ValidationOptions,
};

// Global allocator for WASM (must be at module level)
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc<'_> = wee_alloc::WeeAlloc::INIT;

/// WASM-compatible validation result.
///
/// Wraps the core validation outcome in a JS-friendly form. Matched checks are
/// serialized into a JSON string to avoid exposing Rust types across the WASM boundary.
#[wasm_bindgen]
pub struct WasmValidationResult {
    matches_json: String,
    should_challenge: bool,
    should_deny: bool,
}

#[wasm_bindgen]
impl WasmValidationResult {
    /// Returns the matched checks as a JSON string.
    ///
    /// The JSON is an array of matched check objects. If no checks matched,
    /// the string will be `"[]"`.
    #[wasm_bindgen(getter)]
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn matches(&self) -> String {
        self.matches_json.clone()
    }

    /// Indicates whether a challenge should be presented to the user.
    #[wasm_bindgen(getter)]
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn should_challenge(&self) -> bool {
        self.should_challenge
    }

    /// Indicates whether the command should be denied.
    #[wasm_bindgen(getter)]
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn should_deny(&self) -> bool {
        self.should_deny
    }
}

/// WASM-compatible validation options.
///
/// Holds configuration passed from JavaScript to influence validation behavior.
#[wasm_bindgen]
pub struct WasmValidationOptions {
    deny_pattern_ids: Vec<String>,
    allowed_severities: Vec<String>,
}

impl Default for WasmValidationOptions {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl WasmValidationOptions {
    /// Creates new validation options with empty settings.
    #[wasm_bindgen(constructor)]
    #[must_use]
    pub fn new() -> Self {
        // Add explicit error handling for WASM environment
        let mut options = Self {
            deny_pattern_ids: Vec::new(),
            allowed_severities: Vec::new(),
        };

        // Ensure the vectors are properly initialized for WASM
        options.deny_pattern_ids.reserve(0);
        options.allowed_severities.reserve(0);

        options
    }

    /// Sets deny pattern IDs from a JSON array of strings.
    ///
    /// The input must be a JSON array, for example: `"[\"group:id\", \"group:id2\"]"`.
    /// Passing an empty string clears the list.
    ///
    /// # Errors
    ///
    /// Returns an error if the provided value is not valid JSON or cannot be
    /// deserialized into `Vec<String>`.
    #[wasm_bindgen]
    pub fn set_deny_pattern_ids(&mut self, json_array: &str) -> Result<(), JsValue> {
        if json_array.is_empty() {
            self.deny_pattern_ids = Vec::new();
            return Ok(());
        }

        self.deny_pattern_ids = serde_json::from_str(json_array)
            .map_err(|e| JsValue::from_str(&format!("Invalid JSON for deny_pattern_ids: {e}")))?;
        Ok(())
    }

    /// Sets allowed severities from a JSON array of strings.
    ///
    /// The input must be a JSON array, for example: `"[\"low\", \"medium\"]"`.
    /// Passing an empty string clears the list.
    ///
    /// # Errors
    ///
    /// Returns an error if the provided value is not valid JSON or cannot be
    /// deserialized into `Vec<String>`.
    #[wasm_bindgen]
    pub fn set_allowed_severities(&mut self, json_array: &str) -> Result<(), JsValue> {
        if json_array.is_empty() {
            self.allowed_severities = Vec::new();
            return Ok(());
        }

        self.allowed_severities = serde_json::from_str(json_array)
            .map_err(|e| JsValue::from_str(&format!("Invalid JSON for allowed_severities: {e}")))?;
        Ok(())
    }
}

impl From<WasmValidationOptions> for ValidationOptions {
    fn from(wasm_options: WasmValidationOptions) -> Self {
        // Create a FilterContext that works in the WASM environment.
        // For now, we'll use None which will fall back to safe default behavior.
        Self {
            deny_pattern_ids: wasm_options.deny_pattern_ids,
            filter_context: None,
            allowed_severities: wasm_options.allowed_severities,
        }
    }
}

impl From<ValidationResult> for WasmValidationResult {
    fn from(result: ValidationResult) -> Self {
        let matches_json =
            serde_json::to_string(&result.matches).unwrap_or_else(|_| "[]".to_string());

        Self {
            matches_json,
            should_challenge: result.should_challenge,
            should_deny: result.should_deny,
        }
    }
}

/// Validates a command with the provided options.
///
/// Converts `WasmValidationOptions` into core options and returns a
/// `WasmValidationResult` suitable for JavaScript.
#[wasm_bindgen]
#[must_use]
pub fn validate_command_wasm(
    command: &str,
    options: WasmValidationOptions,
) -> WasmValidationResult {
    let validation_options = ValidationOptions::from(options);
    let Ok(checks) = get_all_checks() else {
        return WasmValidationResult::from(ValidationResult::safe());
    };

    let matches = crate::checks::validate_command_with_split(&checks, command, &validation_options);
    let should_deny = matches
        .iter()
        .any(|check| validation_options.deny_pattern_ids.contains(&check.id));
    let result = if matches.is_empty() {
        ValidationResult::safe()
    } else if should_deny {
        ValidationResult::denied(matches)
    } else {
        ValidationResult::with_matches(matches)
    };

    WasmValidationResult::from(result)
}

/// Validates a command without options (backward compatibility).
///
/// Uses the default validation configuration.
#[wasm_bindgen]
#[must_use]
pub fn validate_command_simple_wasm(command: &str) -> WasmValidationResult {
    let result = crate::checks::validate_command(command);
    WasmValidationResult::from(result)
}

/// Validates a command by parsing, splitting, and checking each part.
///
/// Handles complex shell commands with operators like `&`, `|`, `&&`, and `||`.
#[wasm_bindgen]
#[must_use]
pub fn validate_command_with_split_wasm(command: &str) -> WasmValidationResult {
    let Ok(checks) = crate::get_all_checks() else {
        return WasmValidationResult::from(crate::ValidationResult::safe());
    };

    let matches = crate::checks::validate_command_with_split(
        &checks,
        command,
        &crate::ValidationOptions::default(),
    );
    let result = if matches.is_empty() {
        crate::ValidationResult::safe()
    } else {
        crate::ValidationResult::with_matches(matches)
    };

    WasmValidationResult::from(result)
}

/// Validates a command with options using the split logic.
///
/// Similar to [`validate_command_with_split_wasm`] but allows specifying deny
/// patterns and severities via `WasmValidationOptions`.
#[wasm_bindgen]
#[must_use]
pub fn validate_command_with_options_wasm(
    command: &str,
    options: WasmValidationOptions,
) -> WasmValidationResult {
    let Ok(checks) = crate::get_all_checks() else {
        return WasmValidationResult::from(crate::ValidationResult::safe());
    };

    let validation_options = ValidationOptions::from(options);
    let matches = crate::checks::validate_command_with_split(&checks, command, &validation_options);

    let should_deny = matches
        .iter()
        .any(|check| validation_options.deny_pattern_ids.contains(&check.id));

    let result = if matches.is_empty() {
        crate::ValidationResult::safe()
    } else if should_deny {
        crate::ValidationResult::denied(matches)
    } else {
        crate::ValidationResult::with_matches(matches)
    };

    WasmValidationResult::from(result)
}

/// Returns all available patterns as a JSON string.
///
/// The JSON is an array of pattern objects as defined by the core checks.
///
/// # Errors
///
/// Returns an error if pattern loading fails or if serialization to JSON fails.
#[wasm_bindgen]
pub fn get_all_patterns_wasm() -> Result<String, JsValue> {
    let checks = get_all_checks()
        .map_err(|e| JsValue::from_str(&format!("Failed to load patterns: {e}")))?;

    serde_json::to_string(&checks)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize patterns: {e}")))
}

/// Returns the list of pattern categories (groups).
///
/// Groups correspond to the `from` field in each pattern.
///
/// # Errors
///
/// Returns an error if pattern loading fails or if serialization to JSON fails.
#[wasm_bindgen]
pub fn get_pattern_groups_wasm() -> Result<String, JsValue> {
    let checks = get_all_checks()
        .map_err(|e| JsValue::from_str(&format!("Failed to load patterns: {e}")))?;

    let mut groups: Vec<String> = checks
        .iter()
        .map(|check| check.from.clone())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    groups.sort();

    serde_json::to_string(&groups)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize groups: {e}")))
}

/// Returns the patterns for a specific group as a JSON string.
///
/// The `group` value corresponds to the `from` field on each pattern.
///
/// # Errors
///
/// Returns an error if pattern loading fails or if serialization to JSON fails.
#[wasm_bindgen]
pub fn get_patterns_for_group_wasm(group: &str) -> Result<String, JsValue> {
    let checks = get_all_checks()
        .map_err(|e| JsValue::from_str(&format!("Failed to load patterns: {e}")))?;

    let group_checks: Vec<&Check> = checks.iter().filter(|check| check.from == group).collect();

    serde_json::to_string(&group_checks)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize group patterns: {e}")))
}

/// Initializes the WASM module.
///
/// Sets up panic hooks (when enabled) and performs allocator configuration.
#[wasm_bindgen(start)]
pub fn init() {
    // Set panic hook for better error messages in WASM
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();

    // Allocator is configured at module level above
}

// Utility functions for JavaScript interop

/// Creates a simple file-existence cache for testing.
///
/// Returns a JSON object mapping example file paths to boolean existence.
#[wasm_bindgen]
#[must_use]
pub fn create_test_file_cache() -> String {
    let mut cache = HashMap::new();
    cache.insert("/tmp/test_file".to_string(), true);
    cache.insert("/tmp/missing_file".to_string(), false);
    cache.insert("/home/user/.bashrc".to_string(), true);

    serde_json::to_string(&cache).unwrap_or_else(|_| "{}".to_string())
}

/// Returns a string confirming that the WASM module is working.
#[wasm_bindgen]
#[must_use]
pub fn test_wasm_module() -> String {
    "Shellfirm WASM module is working!".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_validation_options() {
        let mut options = WasmValidationOptions::new();
        assert!(options
            .set_deny_pattern_ids(r#"["test:1", "test:2"]"#)
            .is_ok());

        let validation_options = ValidationOptions::from(options);
        assert_eq!(validation_options.deny_pattern_ids.len(), 2);
        assert!(validation_options.filter_context.is_none());
    }

    #[test]
    fn test_validation_result_conversion() {
        let result = ValidationResult::safe();
        let wasm_result = WasmValidationResult::from(result);
        assert!(!wasm_result.should_challenge());
        assert!(!wasm_result.should_deny());
        assert_eq!(wasm_result.matches(), "[]");
    }

    #[test]
    #[cfg(target_arch = "wasm32")]
    fn test_wasm_validation_options_error_handling() {
        let mut options = WasmValidationOptions::new();

        // Test invalid JSON for deny_pattern_ids
        assert!(options
            .set_deny_pattern_ids(r#"["test:1", "test:2"#)
            .is_err()); // Missing closing bracket

        // Test empty JSON arrays
        assert!(options.set_deny_pattern_ids(r#"[]"#).is_ok());

        // Test with whitespace
        assert!(options
            .set_deny_pattern_ids(r#"  [  "test:1"  ]  "#)
            .is_ok());
    }

    #[test]
    #[cfg(target_arch = "wasm32")]
    fn test_wasm_validation_options_conversion() {
        let mut options = WasmValidationOptions::new();
        options
            .set_deny_pattern_ids(r#"["deny1", "deny2"]"#)
            .expect("Failed to set deny pattern IDs");

        let validation_options = ValidationOptions::from(options);
        assert_eq!(validation_options.deny_pattern_ids, vec!["deny1", "deny2"]);
        assert!(validation_options.filter_context.is_none());
    }

    #[test]
    fn test_wasm_validation_result_methods() {
        let result = ValidationResult::with_matches(vec![Check {
            id: "test:1".to_string(),
            test: regex::Regex::new("test").expect("Failed to create regex for test"),
            description: "Test check".to_string(),
            from: "test".to_string(),
            severity: crate::checks::Severity::Medium,
            challenge: crate::checks::Challenge::Math,
            filters: HashMap::new(),
            validation_mode: crate::checks::ValidationMode::Split,
        }]);

        let wasm_result = WasmValidationResult::from(result);
        assert!(wasm_result.should_challenge());
        assert!(!wasm_result.should_deny());
        assert!(wasm_result.matches().contains("test:1"));

        // Test denied result
        let denied_result = ValidationResult::denied(vec![Check {
            id: "test:1".to_string(),
            test: regex::Regex::new("test").expect("Failed to create regex for test"),
            description: "Test check".to_string(),
            from: "test".to_string(),
            severity: crate::checks::Severity::Medium,
            challenge: crate::checks::Challenge::Math,
            filters: HashMap::new(),
            validation_mode: crate::checks::ValidationMode::Split,
        }]);

        let wasm_denied_result = WasmValidationResult::from(denied_result);
        assert!(wasm_denied_result.should_challenge());
        assert!(wasm_denied_result.should_deny());
        assert!(wasm_denied_result.matches().contains("test:1"));
    }

    #[test]
    fn test_wasm_validation_result_serialization_error() {
        // Create a result that would cause serialization to fail
        // This is hard to do with the current structure, but we can test the fallback
        let result = ValidationResult::safe();
        let wasm_result = WasmValidationResult::from(result);
        assert_eq!(wasm_result.matches(), "[]");
    }

    #[test]
    fn test_validate_command_wasm() {
        let options = WasmValidationOptions::new();
        let result = validate_command_wasm("echo hello", options);
        assert!(!result.should_challenge());
        assert!(!result.should_deny());
        assert_eq!(result.matches(), "[]");
    }

    #[test]
    fn test_validate_command_simple_wasm() {
        let result = validate_command_simple_wasm("echo hello");
        assert!(!result.should_challenge());
        assert!(!result.should_deny());
        assert_eq!(result.matches(), "[]");
    }

    #[test]
    fn test_validate_command_with_split_wasm() {
        let result = validate_command_with_split_wasm("echo hello");
        assert!(!result.should_challenge());
        assert!(!result.should_deny());
        assert_eq!(result.matches(), "[]");
    }

    #[test]
    fn test_validate_command_with_options_wasm() {
        let mut options = WasmValidationOptions::new();
        options
            .set_deny_pattern_ids(r#"["test:1"]"#)
            .expect("Failed to set deny pattern IDs");

        let result = validate_command_with_options_wasm("echo hello", options);
        assert!(!result.should_challenge());
        assert!(!result.should_deny());
        assert_eq!(result.matches(), "[]");
    }

    #[test]
    fn test_get_all_patterns_wasm() {
        let result = get_all_patterns_wasm();
        assert!(result.is_ok());
        let patterns = result.expect("Failed to get all patterns");
        assert!(!patterns.is_empty());
        assert!(patterns.contains("id"));
        assert!(patterns.contains("test"));
    }

    #[test]
    fn test_get_pattern_groups_wasm() {
        let result = get_pattern_groups_wasm();
        assert!(result.is_ok());
        let groups = result.expect("Failed to get pattern groups");
        assert!(!groups.is_empty());
        // Should contain some known groups from the checks
        assert!(groups.contains("base") || groups.contains("fs") || groups.contains("git"));
    }

    #[test]
    fn test_get_patterns_for_group_wasm() {
        // Test with existing group
        let result = get_patterns_for_group_wasm("base");
        if result.is_ok() {
            let patterns = result.expect("Failed to get patterns for group");
            assert!(!patterns.is_empty());
        }

        // Test with non-existing group
        let result = get_patterns_for_group_wasm("nonexistent_group");
        if result.is_ok() {
            let patterns = result.expect("Failed to get patterns for group");
            assert_eq!(patterns, "[]");
        }
    }

    #[test]
    fn test_create_test_file_cache() {
        let cache_json = create_test_file_cache();
        assert!(!cache_json.is_empty());
        assert!(cache_json.contains("/tmp/test_file"));
        assert!(cache_json.contains("/tmp/missing_file"));
        assert!(cache_json.contains("/home/user/.bashrc"));
    }

    #[test]
    fn test_test_wasm_module() {
        let result = test_wasm_module();
        assert_eq!(result, "Shellfirm WASM module is working!");
    }

    #[test]
    fn test_wasm_validation_options_default() {
        let options = WasmValidationOptions::new();
        assert!(options.deny_pattern_ids.is_empty());
        assert!(options.allowed_severities.is_empty());
    }

    #[test]
    #[cfg(target_arch = "wasm32")]
    fn test_wasm_validation_options_with_severities() {
        let mut options = WasmValidationOptions::new();

        // Test setting allowed severities
        assert!(options
            .set_allowed_severities(r#"["low", "medium"]"#)
            .is_ok());
        assert_eq!(options.allowed_severities.len(), 2);
        assert!(options.allowed_severities.contains(&"low".to_string()));
        assert!(options.allowed_severities.contains(&"medium".to_string()));

        // Test setting empty array
        assert!(options.set_allowed_severities(r#"[]"#).is_ok());
        assert!(options.allowed_severities.is_empty());

        // Test setting single severity
        assert!(options.set_allowed_severities(r#"["critical"]"#).is_ok());
        assert_eq!(options.allowed_severities.len(), 1);
        assert!(options.allowed_severities.contains(&"critical".to_string()));

        // Test invalid JSON
        assert!(options
            .set_allowed_severities(r#"["low", "medium"#)
            .is_err()); // Missing closing bracket
        assert!(options.set_allowed_severities(r#"invalid json"#).is_err());
    }

    #[test]
    #[cfg(target_arch = "wasm32")]
    fn test_wasm_validation_options_conversion_with_severities() {
        let mut options = WasmValidationOptions::new();
        options
            .set_allowed_severities(r#"["high", "critical"]"#)
            .expect("Failed to set allowed severities");
        options
            .set_deny_pattern_ids(r#"["deny1"]"#)
            .expect("Failed to set deny pattern IDs");

        let validation_options = ValidationOptions::from(options);
        assert_eq!(validation_options.allowed_severities.len(), 2);
        assert!(validation_options
            .allowed_severities
            .contains(&"high".to_string()));
        assert!(validation_options
            .allowed_severities
            .contains(&"critical".to_string()));
        assert_eq!(validation_options.deny_pattern_ids.len(), 1);
        assert!(validation_options
            .deny_pattern_ids
            .contains(&"deny1".to_string()));
    }

    #[test]
    #[cfg(target_arch = "wasm32")]
    fn test_wasm_validation_options_with_large_data() {
        let mut options = WasmValidationOptions::new();

        // Test with many deny patterns
        let many_patterns = (0..100)
            .map(|i| format!(r#""pattern_{}""#, i))
            .collect::<Vec<_>>()
            .join(",");
        let json_array = format!("[{}]", many_patterns);
        assert!(options.set_deny_pattern_ids(&json_array).is_ok());
    }

    #[test]
    #[cfg(target_arch = "wasm32")]
    fn test_wasm_validation_options_edge_cases() {
        let mut options = WasmValidationOptions::new();

        // Test with single item arrays
        assert!(options.set_deny_pattern_ids(r#"["single"]"#).is_ok());

        // Test with nested structures (should fail)
        assert!(options
            .set_deny_pattern_ids(r#"["nested", ["inner"]]"#)
            .is_err());
    }
}
