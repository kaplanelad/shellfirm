#!/usr/bin/env node

/**
 * Shellfirm MCP Server - WASM Edition
 * 
 * This MCP server uses the Rust-based shellfirm_core compiled to WASM
 * for consistent, high-performance command validation across all platforms.
 * 
 * Features:
 * - WASM-based validation engine (no duplicate patterns)
 * - All shellfirm CLI patterns available 
 * - Advanced filtering with file existence checks
 * - Multiple challenge types (math, confirm, word)
 * - Mandatory security validation for all commands
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import {
  type ValidateCommandResponse
} from './types.js';
import { validateSplitCommandWithOptions, getAllPatterns, initShellfirmWasm } from './shellfirm-wasm.js';
import { CommandInterceptor } from './command-interceptor.js';
import type { ChallengeType } from './types.js';
import * as fs from 'fs';
import * as path from 'path';
// Note: When compiling to CommonJS, Node provides __filename and __dirname globals.
import { program } from 'commander';
import { SetLevelRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { setServer as setLoggerServer, log as mcpLog, toErrorObject } from './logger.js';

// CommonJS environment already provides __filename and __dirname

/**
 * Read package.json to get name and version
 */
function getPackageInfo(): { name: string; version: string } {
  try {
    // For npm packages, package.json is in the same directory as the compiled index.js
    // This works both for local development and when published to npm
    const packagePath = path.resolve(__dirname, '..', 'package.json');
    const packageJson = JSON.parse(fs.readFileSync(packagePath, 'utf8'));

    return {
      name: packageJson.name,
      version: packageJson.version
    };
  } catch (error) {
    // If the above fails, try reading from the current directory (for edge cases)
    try {
      const fallbackPath = path.resolve(__dirname, 'package.json');
      const packageJson = JSON.parse(fs.readFileSync(fallbackPath, 'utf8'));

      return {
        name: packageJson.name,
        version: packageJson.version
      };
    } catch (fallbackError) {
      void mcpLog('warning', 'startup', { message: 'Could not read package.json, using fallback values', error: String(error), fallbackError: String(fallbackError) });
      // Fallback values if package.json cannot be read
      return {
        name: 'shellfirm',
        version: '0.0.0'
      };
    }
  }
}

/**
 * Shellfirm MCP Server with WASM-based validation
 * 
 * This server provides command validation using the Rust-based shellfirm_core
 * compiled to WASM for consistent and high-performance pattern matching.
 */
class ShellfirmMcpServer {
  private server: Server;
  private challengeType: ChallengeType;
  private wasmInitialized: boolean = false;
  private allowedSeverities: Set<string>;
  private propagateEnvVarNames: string[];

  constructor(challengeType: ChallengeType = 'confirm', allowedSeverities: string[] = ['critical', 'high', 'medium'], propagateEnvVarNames: string[] = []) {
    this.challengeType = challengeType;
    this.allowedSeverities = new Set(allowedSeverities.map(s => s.toLowerCase()));
    this.propagateEnvVarNames = propagateEnvVarNames;

    // Get package info from package.json
    const packageInfo = getPackageInfo();

    this.server = new Server(
      {
        name: packageInfo.name,
        version: packageInfo.version,
      },
      {
        capabilities: {
          tools: {},
          // Advertise MCP logging capability so clients can set levels and receive logs
          logging: {},
        },
      }
    );

    setLoggerServer(this.server);
    this.setupToolHandlers();
    this.setupErrorHandling();
  }

  /**
   * Send MCP logging notification to client (RFC 5424 levels) and mirror locally.
   * Falls back gracefully if transport or capability is unavailable.
   */
  // logging moved to shared logger.ts

  private setupToolHandlers(): void {
    // Allow clients to adjust logging level per MCP spec (SDK already wires it when capability present).
    this.server.setRequestHandler(SetLevelRequestSchema, async (_request) => {
      // The SDK stores the level per session and filters notifications.
      // We acknowledge with empty result per spec.
      return {} as Record<string, never>;
    });

    // List available tools - SIMPLIFIED for core functionality
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          {
            name: 'secure_shell_execute',
            description: '🛡️ MANDATORY SECURE EXECUTION - This tool has replaced the built-in terminal command execution. ALL shell commands are automatically validated through Shellfirm MCP with mandatory security validation. This is the ONLY way to execute terminal commands safely. ⚠️ WARNING: Do not use any other terminal execution methods - they bypass security!',
            inputSchema: {
              type: 'object',
              properties: {
                command: {
                  type: 'string',
                  description: 'The shell command to execute with mandatory security validation',
                },
                working_directory: {
                  type: 'string',
                  description: 'Working directory to execute the command in (optional)',
                },
                explanation: {
                  type: 'string',
                  description: 'Brief explanation of what the command does (optional)',
                },
                environment: {
                  type: 'object',
                  description: 'Environment variables to set for command execution (optional)',
                  additionalProperties: {
                    type: 'string'
                  }
                }
              },
              required: ['command'],
            },
          },
          {
            name: 'validate_shell_command',
            description: 'Command validation only - use secure_shell_execute for execution',
            inputSchema: {
              type: 'object',
              properties: {
                command: {
                  type: 'string',
                  description: 'The command to validate (no execution)',
                },
              },
              required: ['command'],
            },
          },
        ],
      };
    });

    // Handle tool calls with SIMPLIFIED routing logic
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      // Route to appropriate handler based on tool name
      if (name === 'secure_shell_execute') {
        // Primary secure execution tool
        void mcpLog('notice', 'tools', { message: 'Intercepted secure_shell_execute - enforcing mandatory security' });
        return await this.handleSecureExecution(args as Record<string, unknown> & {
          command: string;
          working_directory?: string;
          explanation?: string;
          environment?: Record<string, string>;
        });
      }

      if (name === 'validate_shell_command') {
        // Command validation only (no execution)
        return await this.handleValidateCommand(args as Record<string, unknown> & { command: string });
      }

      // 🚨 BLOCK ALL UNKNOWN TOOLS - Prevent any bypass attempts
      void mcpLog('warning', 'tools', { message: 'Unknown tool attempted', name });

      throw new Error(`🚨 SECURITY VIOLATION: Tool "${name}" is not allowed. 

🛡️ MANDATORY SECURITY ENFORCEMENT:
ALL terminal command execution is now routed through mandatory security validation.

✅ USE ONLY THIS SECURE TOOL:
- secure_shell_execute (mandatory for all terminal command execution)

❌ BLOCKED: Any other tool names are automatically intercepted and blocked.

🔒 This is automatic and transparent - your command will be executed safely after validation.
⚠️ Attempting to bypass this security will result in immediate blocking.`);
    });
  }

  private async handleSecureExecution(
    args: Record<string, unknown> & {
      command: string;
      working_directory?: string;
      explanation?: string;
      environment?: Record<string, string>;
    }
  ): Promise<{ content: Array<{ type: string; text: string }> }> {
    try {
      // Ensure WASM is initialized
      await this.ensureWasmInitialized();

      const { command, working_directory, environment } = args;

      // Clean the command by removing any trailing whitespace/newlines
      const cleanCommand = command.trim();

      // Use the command interceptor for mandatory validation and execution
      const allowedSeverities = Array.from(this.allowedSeverities);
      const result = await CommandInterceptor.interceptCommand(
        cleanCommand,
        working_directory,
        this.challengeType,
        allowedSeverities,
        environment,
        this.propagateEnvVarNames
      );

      const response = {
        allowed: result.allowed,
        message: result.message,
        output: result.output || '',
        error: result.error || '',
        command: cleanCommand,
        working_directory: working_directory || '',
        environment: environment || {}
      };

      if (result.allowed) {
        void mcpLog('info', 'execution', { message: 'Command executed successfully' });
      } else {
        void mcpLog('warning', 'execution', { message: 'Command blocked by security policy', hint: 'Manual approval required' });
      }

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(response),
          },
        ],
      };
    } catch (error: unknown) {
      void mcpLog('critical', 'execution', { message: 'Critical error in secure command execution', error: toErrorObject(error) });

      // Ensure we never crash the MCP server
      const safeErrorMessage = error instanceof Error ? error.message : 'Unknown security system error';

      const response = {
        allowed: false,
        message: `🚨 Security system error - command blocked for safety: ${safeErrorMessage}`,
        output: '',
        error: 'Security system failure - command denied',
        command: args.command || 'unknown',
        working_directory: args.working_directory || ''
      };

      try {
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(response),
            },
          ],
        };
      } catch (jsonError) {
        // Last resort - return minimal safe response
        void mcpLog('error', 'execution', { message: 'JSON serialization failed', error: toErrorObject(jsonError) });
        return {
          content: [
            {
              type: 'text',
              text: '{"allowed":false,"message":"Critical security system error - command blocked","error":"System failure"}',
            },
          ],
        };
      }
    }
  }

  private async handleValidateCommand(
    args: Record<string, unknown> & { command: string }
  ): Promise<{ content: Array<{ type: string; text: string }> }> {
    try {
      // Ensure WASM is initialized
      await this.ensureWasmInitialized();

      const { command } = args;

      // Clean the command for validation as well
      const cleanCommand = command.trim();
      void mcpLog('debug', 'validation', { message: 'Validating command with WASM engine', command: cleanCommand });

      // Use WASM-based validation with proper severity filtering
      const validationOptions = {
        allowed_severities: Array.from(this.allowedSeverities),
        deny_pattern_ids: [],
      };

      const validationResult = await validateSplitCommandWithOptions(cleanCommand, validationOptions);

      if (!validationResult.should_challenge) {
        // Command is safe
        const response: ValidateCommandResponse = {
          safe: true,
          message: 'Command is safe to execute',
        };

        void mcpLog('info', 'validation', { message: 'Command is safe' });

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(response),
            },
          ],
        };
      }

      const patterns = validationResult.matches.map(check => check.description).join(', ');
      void mcpLog('notice', 'validation', { message: 'Risky patterns detected', patterns });

      // Command denied completely
      if (validationResult.should_deny) {
        void mcpLog('warning', 'validation', { message: 'Command denied by security policy' });
        const response: ValidateCommandResponse = {
          safe: false,
          message: 'Shellfirm MCP: Command denied by security policy',
          pattern: patterns,
        };

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(response),
            },
          ],
        };
      }

      // Show captcha challenge
      void mcpLog('warning', 'validation', { message: 'Command blocked - security policy enforced', hint: 'Manual approval required' });

      // Command is blocked for security - no captcha needed
      const response: ValidateCommandResponse = {
        safe: false,
        message: 'Shellfirm MCP: Command blocked by security policy - manual approval required',
        pattern: patterns,
      };

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(response),
          },
        ],
      };
    } catch (error) {
      void mcpLog('error', 'validation', { message: 'Error validating command', error: toErrorObject(error) });
      const response: ValidateCommandResponse = {
        safe: false,
        message: `Shellfirm MCP: Error validating command: ${error instanceof Error ? error.message : 'Unknown error'}`,
      };

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(response),
          },
        ],
      };
    }
  }



  private setupErrorHandling(): void {
    this.server.onerror = (error) => {
      void mcpLog('error', 'server', { error: toErrorObject(error), message: 'Server error' });
      // Don't crash - just log the error
    };

    // Global error handlers to prevent crashes
    process.on('uncaughtException', (error) => {
      void mcpLog('alert', 'process', { error: toErrorObject(error), message: 'Uncaught exception' });
      try { process.stderr.write('[Shellfirm MCP] 🛡️ Server continuing to run for security\n'); } catch {}
      // Don't exit - keep server running for security
    });

    process.on('unhandledRejection', (reason, _promise) => {
      void mcpLog('critical', 'process', { reason: toErrorObject(reason), message: 'Unhandled promise rejection' });
      try { process.stderr.write('[Shellfirm MCP] 🛡️ Server continuing to run for security\n'); } catch {}
      // Don't exit - keep server running for security
    });

    process.on('SIGINT', async () => {
      await mcpLog('notice', 'lifecycle', { message: 'Shutting down server (SIGINT)' });
      try {
        await this.server.close();
        process.exit(0);
      } catch (error) {
        await mcpLog('error', 'lifecycle', { error: toErrorObject(error), message: 'Error during shutdown' });
        process.exit(1);
      }
    });
  }

  /**
   * Initialize the WASM module
   */
  private async initializeWasm(): Promise<void> {
    try {
      await initShellfirmWasm();
      this.wasmInitialized = true;

      // Log pattern information
      const patterns = await getAllPatterns();
      await mcpLog('info', 'wasm', { message: 'WASM initialized', patternsLoaded: patterns.length });

    } catch (error) {
      await mcpLog('error', 'wasm', { error: toErrorObject(error), message: 'Failed to initialize WASM module' });
      throw new Error(`WASM initialization failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Ensure WASM is initialized before processing commands
   */
  private async ensureWasmInitialized(): Promise<void> {
    if (!this.wasmInitialized) {
      await mcpLog('notice', 'wasm', { message: 'WASM not initialized, initializing now' });
      await this.initializeWasm();
    }
  }

  async run(): Promise<void> {
    try {
      // Initialize WASM first
      await mcpLog('info', 'lifecycle', { message: 'Starting Shellfirm MCP Server' });
      await this.initializeWasm();

      // Start MCP server
      const transport = new StdioServerTransport();
      await this.server.connect(transport);

    } catch (error) {
      await mcpLog('emergency', 'lifecycle', { error: toErrorObject(error), message: 'Server startup failed' });
      process.exit(1);
    }
  }
}

// Start the WASM-powered MCP server
async function main() {
  try { process.stderr.write('🚀 Shellfirm MCP Server\n'); } catch {}

  // Parse command line arguments with commander
  program
    .name('mcp-server-shellfirm')
    .description('Shellfirm MCP Server - secure command validation via WASM')
    .option('--challenge <type>', 'challenge type (confirm|math|word|block)', 'confirm')
    .option('--severity <levels>', 'comma-separated severity levels', 'critical,high,medium')
    .option('--propagate-env <vars>', 'comma-separated env variable names to inherit (e.g. PATH,HOME,SSH_AUTH_SOCK)', '');

  program.parse(process.argv);

  const opts = program.opts() as {
    challenge?: string;
    severity?: string;
    propagateEnv?: string; // comma-separated list of env var names
  };

  const allowed: ChallengeType[] = ['confirm', 'math', 'word'];
  let challengeType: ChallengeType = (opts.challenge as ChallengeType) ?? 'confirm';
  if (!allowed.includes(challengeType)) {
    void mcpLog('warning', 'startup', { message: 'Unsupported challenge type - fallback to confirm', given: String(challengeType) });
    challengeType = 'confirm';
  }

  let severities: string[] = (opts.severity ?? 'critical,high,medium')
    .split(',')
    .map(s => s.trim().toLowerCase())
    .filter(Boolean);
  if (severities.length === 0) {
    severities = ['critical', 'high', 'medium'];
  }

  const propagateEnvVarNames = (opts.propagateEnv ?? '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);

  // Keep initial stderr banners, functional logs go through MCP
  try { process.stderr.write(`🎯 Challenge type: ${challengeType}\n`); } catch {}
  try { process.stderr.write(`🔧 Severity levels: ${severities.join(', ')}\n`); } catch {}
  try { process.stderr.write(`🌍 Propagate env vars: ${propagateEnvVarNames.length > 0 ? propagateEnvVarNames.join(', ') : 'none'}\n`); } catch {}

  const server = new ShellfirmMcpServer(challengeType, severities, propagateEnvVarNames);
  await server.run();
}

main().catch((error: unknown) => {
  try { process.stderr.write(`Failed to start server: ${error instanceof Error ? error.message : String(error)}\n`); } catch {}
  process.exit(1);
});

// error normalization utilities moved to logger.ts
