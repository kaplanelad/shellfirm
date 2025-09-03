/* tslint:disable */
/* eslint-disable */
export const memory: WebAssembly.Memory;
export const __wbg_wasmvalidationresult_free: (a: number, b: number) => void;
export const wasmvalidationresult_matches: (a: number) => [number, number];
export const wasmvalidationresult_should_challenge: (a: number) => number;
export const wasmvalidationresult_should_deny: (a: number) => number;
export const __wbg_wasmvalidationoptions_free: (a: number, b: number) => void;
export const wasmvalidationoptions_new: () => number;
export const wasmvalidationoptions_set_deny_pattern_ids: (a: number, b: number, c: number) => [number, number];
export const wasmvalidationoptions_set_allowed_severities: (a: number, b: number, c: number) => [number, number];
export const validate_command_wasm: (a: number, b: number, c: number) => number;
export const validate_command_simple_wasm: (a: number, b: number) => number;
export const validate_command_with_split_wasm: (a: number, b: number) => number;
export const validate_command_with_options_wasm: (a: number, b: number, c: number) => number;
export const get_all_patterns_wasm: () => [number, number, number, number];
export const get_pattern_groups_wasm: () => [number, number, number, number];
export const get_patterns_for_group_wasm: (a: number, b: number) => [number, number, number, number];
export const create_test_file_cache: () => [number, number];
export const test_wasm_module: () => [number, number];
export const init: () => void;
export const __wbindgen_free: (a: number, b: number, c: number) => void;
export const __wbindgen_malloc: (a: number, b: number) => number;
export const __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
export const __wbindgen_export_3: WebAssembly.Table;
export const __externref_table_dealloc: (a: number) => void;
export const __wbindgen_start: () => void;
