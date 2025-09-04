import type { Server } from '@modelcontextprotocol/sdk/server/index.js';

export type LogLevel = 'debug' | 'info' | 'notice' | 'warning' | 'error' | 'critical' | 'alert' | 'emergency';

let serverRef: Server | null = null;
let mirrorToStderr: boolean = process.env.SHELLFIRM_LOG_STDERR !== '0';

export function setServer(server: Server): void {
  serverRef = server;
}

export function setStderrMirror(enabled: boolean): void {
  mirrorToStderr = enabled;
}

export async function log(level: LogLevel, logger?: string, data?: unknown): Promise<void> {
  try {
    const anyServer = serverRef as unknown as { sendLoggingMessage?: (params: unknown) => Promise<void> } | null;
    if (anyServer && typeof anyServer.sendLoggingMessage === 'function') {
      await anyServer.sendLoggingMessage({ level, ...(logger ? { logger } : {}), ...(data !== undefined ? { data } : {}) });
    }
  } catch {
    // ignore transport errors
  }

  if (mirrorToStderr) {
    const payload = data !== undefined ? ` ${safeStringify(data)}` : '';
    const prefix = `[Shellfirm MCP][${level}${logger ? `:${logger}` : ''}]`;
    // single stderr sink
    try { process.stderr.write(`${prefix}${payload}\n`); } catch {}
  }
}

export const debug = (logger?: string, data?: unknown) => log('debug', logger, data);
export const info = (logger?: string, data?: unknown) => log('info', logger, data);
export const notice = (logger?: string, data?: unknown) => log('notice', logger, data);
export const warning = (logger?: string, data?: unknown) => log('warning', logger, data);
export const error = (logger?: string, data?: unknown) => log('error', logger, data);
export const critical = (logger?: string, data?: unknown) => log('critical', logger, data);
export const alert = (logger?: string, data?: unknown) => log('alert', logger, data);
export const emergency = (logger?: string, data?: unknown) => log('emergency', logger, data);

export function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

export function toErrorObject(err: unknown): Record<string, unknown> {
  if (err instanceof Error) {
    return { name: err.name, message: err.message, stack: err.stack };
  }
  try {
    return JSON.parse(safeStringify(err));
  } catch {
    return { value: String(err) };
  }
}


