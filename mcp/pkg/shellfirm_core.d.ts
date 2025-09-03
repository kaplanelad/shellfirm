/* tslint:disable */
/* eslint-disable */
/**
 * Validates a command with the provided options.
 *
 * Converts `WasmValidationOptions` into core options and returns a
 * `WasmValidationResult` suitable for JavaScript.
 */
export function validate_command_wasm(command: string, options: WasmValidationOptions): WasmValidationResult;
/**
 * Validates a command without options (backward compatibility).
 *
 * Uses the default validation configuration.
 */
export function validate_command_simple_wasm(command: string): WasmValidationResult;
/**
 * Validates a command by parsing, splitting, and checking each part.
 *
 * Handles complex shell commands with operators like `&`, `|`, `&&`, and `||`.
 */
export function validate_command_with_split_wasm(command: string): WasmValidationResult;
/**
 * Validates a command with options using the split logic.
 *
 * Similar to [`validate_command_with_split_wasm`] but allows specifying deny
 * patterns and severities via `WasmValidationOptions`.
 */
export function validate_command_with_options_wasm(command: string, options: WasmValidationOptions): WasmValidationResult;
/**
 * Returns all available patterns as a JSON string.
 *
 * The JSON is an array of pattern objects as defined by the core checks.
 *
 * # Errors
 *
 * Returns an error if pattern loading fails or if serialization to JSON fails.
 */
export function get_all_patterns_wasm(): string;
/**
 * Returns the list of pattern categories (groups).
 *
 * Groups correspond to the `from` field in each pattern.
 *
 * # Errors
 *
 * Returns an error if pattern loading fails or if serialization to JSON fails.
 */
export function get_pattern_groups_wasm(): string;
/**
 * Returns the patterns for a specific group as a JSON string.
 *
 * The `group` value corresponds to the `from` field on each pattern.
 *
 * # Errors
 *
 * Returns an error if pattern loading fails or if serialization to JSON fails.
 */
export function get_patterns_for_group_wasm(group: string): string;
/**
 * Initializes the WASM module.
 *
 * Sets up panic hooks (when enabled) and performs allocator configuration.
 */
export function init(): void;
/**
 * Creates a simple file-existence cache for testing.
 *
 * Returns a JSON object mapping example file paths to boolean existence.
 */
export function create_test_file_cache(): string;
/**
 * Returns a string confirming that the WASM module is working.
 */
export function test_wasm_module(): string;
/**
 * WASM-compatible validation options.
 *
 * Holds configuration passed from JavaScript to influence validation behavior.
 */
export class WasmValidationOptions {
  free(): void;
  /**
   * Creates new validation options with empty settings.
   */
  constructor();
  /**
   * Sets deny pattern IDs from a JSON array of strings.
   *
   * The input must be a JSON array, for example: `"[\"group:id\", \"group:id2\"]"`.
   * Passing an empty string clears the list.
   *
   * # Errors
   *
   * Returns an error if the provided value is not valid JSON or cannot be
   * deserialized into `Vec<String>`.
   */
  set_deny_pattern_ids(json_array: string): void;
  /**
   * Sets allowed severities from a JSON array of strings.
   *
   * The input must be a JSON array, for example: `"[\"low\", \"medium\"]"`.
   * Passing an empty string clears the list.
   *
   * # Errors
   *
   * Returns an error if the provided value is not valid JSON or cannot be
   * deserialized into `Vec<String>`.
   */
  set_allowed_severities(json_array: string): void;
}
/**
 * WASM-compatible validation result.
 *
 * Wraps the core validation outcome in a JS-friendly form. Matched checks are
 * serialized into a JSON string to avoid exposing Rust types across the WASM boundary.
 */
export class WasmValidationResult {
  private constructor();
  free(): void;
  /**
   * Returns the matched checks as a JSON string.
   *
   * The JSON is an array of matched check objects. If no checks matched,
   * the string will be `"[]"`.
   */
  readonly matches: string;
  /**
   * Indicates whether a challenge should be presented to the user.
   */
  readonly should_challenge: boolean;
  /**
   * Indicates whether the command should be denied.
   */
  readonly should_deny: boolean;
}
