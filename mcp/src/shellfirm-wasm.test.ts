import { describe, test, expect, beforeAll } from 'vitest';
import * as fs from 'fs';
import * as wasm from './shellfirm-wasm.js';

// These tests exercise the real WASM wrapper against the bundled pkg
// We avoid over-specifying exact contents and assert on stable properties.

beforeAll(async () => {
	// Ensure pkg exists so init uses it instead of dynamic import
	const pkgPath = new URL('../pkg/shellfirm_core.js', import.meta.url);
	expect(fs.existsSync(pkgPath)).toBeTruthy();
	await wasm.initShellfirmWasm();
});

describe('shellfirm-wasm (integration with pkg)', () => {
	test('initShellfirmWasm initializes without throwing', async () => {
		await wasm.initShellfirmWasm();
		// If no throw, pass
		expect(true).toBe(true);
	});

	test('getAllPatterns returns non-empty array with expected shape', async () => {
		const patterns = await wasm.getAllPatterns();
		expect(Array.isArray(patterns)).toBe(true);
		expect(patterns.length).toBeGreaterThan(0);
		expect(patterns[0]).toHaveProperty('id');
		expect(patterns[0]).toHaveProperty('description');
		expect(patterns[0]).toHaveProperty('severity');
	});

	test('getPatternGroups returns known groups', async () => {
		const groups = await wasm.getPatternGroups();
		expect(groups).toEqual(expect.arrayContaining(['fs', 'network']));
	});

	test('getPatternsForGroup("fs") returns patterns list', async () => {
		const patterns = await wasm.getPatternsForGroup('fs');
		expect(Array.isArray(patterns)).toBe(true);
		expect(patterns.length).toBeGreaterThan(0);
		expect(patterns[0]).toHaveProperty('description');
	});

	test('testWasmModule returns a success string', async () => {
		const res = await wasm.testWasmModule();
		expect(typeof res).toBe('string');
		expect(res.toLowerCase()).toContain('wasm');
	});

	// Smoke tests for validators: just ensure they run and return expected keys
	test('validateSplitCommand runs and returns expected keys', async () => {
		const result = await wasm.validateSplitCommand('echo hello');
		expect(result).toHaveProperty('matches');
		expect(result).toHaveProperty('should_challenge');
		expect(result).toHaveProperty('should_deny');
	});

	test('validateSplitCommandWithOptions runs with options', async () => {
		const result = await wasm.validateSplitCommandWithOptions('echo hello', {
			allowed_severities: ['low', 'medium'],
			deny_pattern_ids: [],
		});
		expect(result).toHaveProperty('matches');
		expect(result).toHaveProperty('should_challenge');
		expect(result).toHaveProperty('should_deny');
	});
});
