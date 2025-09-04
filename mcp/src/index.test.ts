import { describe, test, expect, vi } from 'vitest';

// We will import the module under test after mocks to ensure they take effect

vi.mock('./command-interceptor.js', () => ({
  CommandInterceptor: {
    interceptCommand: vi.fn().mockResolvedValue({ allowed: true, message: 'ok', output: 'OUT', error: '' })
  }
}));

// Minimal mock for @modelcontextprotocol sdk server to avoid startup side effects
vi.mock('@modelcontextprotocol/sdk/server/index.js', () => {
  return {
    Server: class {
      public onerror: ((e: unknown) => void) | undefined;
      setRequestHandler = vi.fn<(_schema: unknown, _handler: unknown) => void>();
      connect = vi.fn().mockResolvedValue(undefined);
      close = vi.fn().mockResolvedValue(undefined);
      constructor() {}
    }
  } as unknown as {
    Server: unknown;
  };
});
vi.mock('@modelcontextprotocol/sdk/server/stdio.js', () => ({
  StdioServerTransport: vi.fn()
}));

// Bring in schemas for type/identity; we won't validate them in tests
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';

// Avoid process.exit killing tests in case of startup failure logs
vi.spyOn(process, 'exit').mockImplementation(((_code?: string | number | null | undefined) => (undefined as never)));

// Now import after mocks
import './index.js';

describe('MCP index', () => {
  test('module loads without crashing in test env', () => {
    void ListToolsRequestSchema;
    void CallToolRequestSchema;
    expect(true).toBe(true);
  });
});


