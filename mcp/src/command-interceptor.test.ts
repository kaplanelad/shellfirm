import { describe, test, expect, vi, beforeEach } from 'vitest';

// Mock WASM validation to mark commands as safe (no challenge, no deny)
vi.mock('./shellfirm-wasm.js', () => ({
  validateSplitCommandWithOptions: vi.fn().mockResolvedValue({
    matches: [],
    should_challenge: false,
    should_deny: false,
  })
}));

// Capture options passed to child_process.exec via promisify(exec)
let lastExecOptions: { env?: Record<string, string> } | undefined;
vi.mock('child_process', () => {
  return {
    exec: (cmd: string, options: unknown, callback: (err: unknown, stdout: string, stderr: string) => void) => {
      lastExecOptions = (options || {}) as { env?: Record<string, string> };
      callback(null, 'OUT', '');
      // The real promisified exec resolves with { stdout, stderr } from callback strings
    }
  };
});

// Mock logger to no-op
vi.mock('./logger.js', () => ({
  log: vi.fn(),
  toErrorObject: (e: unknown) => String(e)
}));

// Import after mocks are set up
import { CommandInterceptor } from './command-interceptor.js';

describe('CommandInterceptor env propagation', () => {
  beforeEach(() => {
    lastExecOptions = undefined;
  });

  test('propagates only allowlisted env vars and merges provided environment', async () => {
    // Prepare a known env in process.env
    const originalPath = process.env.PATH;
    const originalHome = process.env.HOME;
    process.env.PATH = '/test/path';
    process.env.HOME = '/home/should_not_propagate';

    try {
      const res = await CommandInterceptor.interceptCommand(
        'echo ok',
        undefined,
        'confirm',
        [],
        { CUSTOM: 'yes' },
        ['PATH', 'SSH_AUTH_SOCK']
      );

      expect(res.allowed).toBe(true);
      expect(lastExecOptions).toBeDefined();
      const env = lastExecOptions?.env || {};
      expect(env.CUSTOM).toBe('yes');
      expect(env.PATH).toBe('/test/path');
      // Not allowlisted
      expect(env.HOME).toBeUndefined();
    } finally {
      // restore
      if (originalPath !== undefined) process.env.PATH = originalPath; else delete process.env.PATH;
      if (originalHome !== undefined) process.env.HOME = originalHome; else delete process.env.HOME;
    }
  });

  test('no allowlist -> only provided environment is used', async () => {
    const originalPath = process.env.PATH;
    process.env.PATH = '/test/path';
    try {
      const res = await CommandInterceptor.interceptCommand(
        'echo ok',
        undefined,
        'confirm',
        [],
        { ONLY: 'provided' },
        []
      );

      expect(res.allowed).toBe(true);
      const env = lastExecOptions?.env || {};
      expect(env.ONLY).toBe('provided');
      expect(env.PATH).toBeUndefined();
    } finally {
      if (originalPath !== undefined) process.env.PATH = originalPath; else delete process.env.PATH;
    }
  });
});

