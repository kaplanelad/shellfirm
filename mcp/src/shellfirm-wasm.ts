/**
 * TypeScript wrapper for Shellfirm WASM module
 * 
 * This module provides a clean TypeScript interface to the Rust-based
 * command validation engine compiled to WASM.
 */

import * as path from 'path';
import * as fs from 'fs';
import { error as logError } from './logger.js';
// CommonJS environment provides __dirname

// WASM module interfaces
export interface WasmValidationOptions {
  set_deny_pattern_ids(ids: string): void;
  set_allowed_severities(severities: string): void;
  free(): void;
  ptr?: number;
}

export interface WasmValidationResult {
  matches: string;
  should_challenge: boolean;
  should_deny: boolean;
  free(): void;
  ptr?: number;
}

export interface WasmModule {
  init?(): void;
  WasmValidationOptions: new () => WasmValidationOptions;
  validate_command_wasm(command: string, options: WasmValidationOptions): WasmValidationResult;
  validate_command_simple_wasm(command: string): WasmValidationResult;
  validate_command_with_split_wasm(command: string): WasmValidationResult;
  validate_command_with_options_wasm(command: string, options: WasmValidationOptions): WasmValidationResult;
  get_all_patterns_wasm(): string;
  get_pattern_groups_wasm(): string;
  get_patterns_for_group_wasm(group: string): string;
  test_wasm_module(): string;
}

// Import WASM module - we'll handle the import dynamically
let wasmModule: WasmModule | null = null;

export interface Check {
  id: string;
  test: string; // Regex pattern as string
  description: string;
  from: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  challenge: 'math' | 'enter' | 'yes' | 'block';
  filters: Record<string, string>;
}

export interface ValidationResult {
  matches: Check[];
  should_challenge: boolean;
  should_deny: boolean;
}

export interface ValidationOptions {
  deny_pattern_ids?: string[];
  allowed_severities?: string[];
}

/**
 * Initialize the WASM module
 */
export async function initShellfirmWasm(): Promise<void> {
  if (wasmModule) {
    return; // Already initialized
  }

  try {
    // Try to load from the pkg directory (relative to compiled lib folder)
    const pkgPath = path.resolve(__dirname, '..', 'pkg', 'shellfirm_core.js');

    if (fs.existsSync(pkgPath)) {
      // In CommonJS, prefer require with a filesystem path (no file:// URL)
      // @ts-ignore - require is available in CommonJS builds
      wasmModule = require(pkgPath) as WasmModule;
    } else {
      await logError('wasm', { message: 'Pkg directory not found, trying node_modules' });
      // Fallback: try from node_modules if installed as a dependency
      // @ts-ignore - require is available in CommonJS builds
      wasmModule = require('shellfirm_core') as WasmModule;
      await logError('wasm', { message: 'Initialized from node_modules', level: 'info' });
    }

    // Initialize the WASM module
    if (wasmModule.init) {
      wasmModule.init();
    }

  } catch (error) {
    await logError('wasm', { message: 'Failed to load module', error: String(error) });
    throw new Error(`Failed to initialize Shellfirm WASM module: ${error}`);
  }
}

/**
 * Validate a command using the WASM module
 */
export async function validateCommand(
  command: string,
  options: ValidationOptions = {}
): Promise<ValidationResult> {
  await initShellfirmWasm();

  if (!wasmModule) {
    throw new Error('WASM module not initialized');
  }

  try {
    // Create WASM validation options
    const wasmOptions = new wasmModule.WasmValidationOptions();

    if (options.deny_pattern_ids && options.deny_pattern_ids.length > 0) {
      wasmOptions.set_deny_pattern_ids(JSON.stringify(options.deny_pattern_ids));
    }

    if (options.allowed_severities && options.allowed_severities.length > 0) {
      wasmOptions.set_allowed_severities(JSON.stringify(options.allowed_severities));
    }

    // Validate the command
    const result = wasmModule.validate_command_wasm(command, wasmOptions);

    // Parse the matches from JSON and extract properties before freeing
    const matches = JSON.parse(result.matches);
    const should_challenge = result.should_challenge;
    const should_deny = result.should_deny;

    // Clean up WASM objects
    wasmOptions.free();
    result.free();

    return {
      matches,
      should_challenge,
      should_deny,
    };
  } catch (error) {
    await logError('wasm', { message: 'Validation error', error: String(error) });
    throw new Error(`Command validation failed: ${error}`);
  }
}

/**
 * Simple command validation without options (for backward compatibility)
 */
export async function validateCommandSimple(command: string): Promise<ValidationResult> {
  await initShellfirmWasm();

  if (!wasmModule) {
    throw new Error('WASM module not initialized');
  }

  try {
    const result = wasmModule.validate_command_simple_wasm(command);

    const matches = JSON.parse(result.matches);
    const should_challenge = result.should_challenge;
    const should_deny = result.should_deny;

    // Clean up WASM objects
    result.free();

    return {
      matches,
      should_challenge,
      should_deny,
    };
  } catch (error) {
    await logError('wasm', { message: 'Simple validation error', error: String(error) });
    throw new Error(`Command validation failed: ${error}`);
  }
}

/**
 * Validate a command by parsing, splitting, and checking each part
 * This is the recommended function for command validation as it handles
 * complex shell commands with operators like &, |, &&, ||
 */
export async function validateSplitCommand(command: string): Promise<ValidationResult> {
  await initShellfirmWasm();

  if (!wasmModule) {
    throw new Error('WASM module not initialized');
  }

  try {
    const result = wasmModule.validate_command_with_split_wasm(command);

    const matches = JSON.parse(result.matches);
    const should_challenge = result.should_challenge;
    const should_deny = result.should_deny;

    // Clean up WASM objects
    result.free();

    return {
      matches,
      should_challenge,
      should_deny,
    };
  } catch (error) {
    await logError('wasm', { message: 'Split command validation error', error: String(error) });
    throw new Error(`Command validation failed: ${error}`);
  }
}

/**
 * Validate a split command with options
 */
export async function validateSplitCommandWithOptions(
  command: string,
  options: ValidationOptions = {}
): Promise<ValidationResult> {
  await initShellfirmWasm();

  if (!wasmModule) {
    throw new Error('WASM module not initialized');
  }

  let wasmOptions: WasmValidationOptions | null = null;
  let result: WasmValidationResult | null = null;

  try {
    // Create WASM validation options
    wasmOptions = new wasmModule.WasmValidationOptions();

    if (options.deny_pattern_ids && options.deny_pattern_ids.length > 0) {
      wasmOptions.set_deny_pattern_ids(JSON.stringify(options.deny_pattern_ids));
    }

    if (options.allowed_severities && options.allowed_severities.length > 0) {
      wasmOptions.set_allowed_severities(JSON.stringify(options.allowed_severities));
    }

    // Validate the command using the split command function
    result = wasmModule.validate_command_with_options_wasm(command, wasmOptions);

    // At this point, both wasmOptions and result are guaranteed to be non-null
    if (!wasmOptions || !result) {
      throw new Error('Failed to create WASM objects');
    }

    // Parse the matches from JSON and extract properties before freeing
    const matches = JSON.parse(result.matches);
    const should_challenge = result.should_challenge;
    const should_deny = result.should_deny;

    return {
      matches,
      should_challenge,
      should_deny,
    };
  } catch (error) {
    await logError('wasm', { message: 'Split command validation with options error', error: String(error) });
    throw new Error(`Command validation failed: ${error}`);
  } finally {
    // Clean up WASM objects safely
    try {
      if (result && result.ptr && typeof result.ptr === 'number' && result.ptr !== 0) {
        result.free();
        result.ptr = 0;
      }
    } catch { }

    try {
      if (wasmOptions && wasmOptions.ptr && typeof wasmOptions.ptr === 'number' && wasmOptions.ptr !== 0) {
        wasmOptions.free();
        wasmOptions.ptr = 0;
      }
    } catch { }
  }
}

/**
 * Get all available patterns
 */
export async function getAllPatterns(): Promise<Check[]> {
  await initShellfirmWasm();

  if (!wasmModule) {
    throw new Error('WASM module not initialized');
  }

  try {
    const patternsJson = wasmModule.get_all_patterns_wasm();
    return JSON.parse(patternsJson);
  } catch (error) {
    await logError('wasm', { message: 'Get patterns error', error: String(error) });
    throw new Error(`Failed to get patterns: ${error}`);
  }
}

/**
 * Get pattern groups/categories
 */
export async function getPatternGroups(): Promise<string[]> {
  await initShellfirmWasm();

  if (!wasmModule) {
    throw new Error('WASM module not initialized');
  }

  try {
    const groupsJson = wasmModule.get_pattern_groups_wasm();
    return JSON.parse(groupsJson);
  } catch (error) {
    await logError('wasm', { message: 'Get groups error', error: String(error) });
    throw new Error(`Failed to get pattern groups: ${error}`);
  }
}

/**
 * Get patterns for a specific group
 */
export async function getPatternsForGroup(group: string): Promise<Check[]> {
  await initShellfirmWasm();

  if (!wasmModule) {
    throw new Error('WASM module not initialized');
  }

  try {
    const patternsJson = wasmModule.get_patterns_for_group_wasm(group);
    return JSON.parse(patternsJson);
  } catch (error) {
    await logError('wasm', { message: 'Get group patterns error', error: String(error) });
    throw new Error(`Failed to get patterns for group ${group}: ${error}`);
  }
}

/**
 * Create file existence cache from file system paths
 * This is a utility function to help with file existence checking in WASM
 */
export function createFileExistenceCache(filePaths: string[]): Record<string, boolean> {
  const cache: Record<string, boolean> = {};

  for (const filePath of filePaths) {
    try {
      cache[filePath] = fs.existsSync(filePath);
    } catch {
      cache[filePath] = false;
    }
  }

  return cache;
}

/**
 * Test function to verify WASM module is working
 */
export async function testWasmModule(): Promise<string> {
  await initShellfirmWasm();

  if (!wasmModule) {
    throw new Error('WASM module not initialized');
  }

  return wasmModule.test_wasm_module();
}
