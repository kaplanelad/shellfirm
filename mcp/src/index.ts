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
import { fileURLToPath } from 'url';

// ES module compatibility
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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
      console.error('[Shellfirm MCP] Warning: Could not read package.json, using fallback values:', error, fallbackError);
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
  private propagateProcessEnv: boolean;

  constructor(challengeType: ChallengeType = 'confirm', allowedSeverities: string[] = ['critical', 'high', 'medium'], propagateProcessEnv: boolean = true) {
    this.challengeType = challengeType;
    this.allowedSeverities = new Set(allowedSeverities.map(s => s.toLowerCase()));
    this.propagateProcessEnv = propagateProcessEnv;

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
        },
      }
    );

    this.setupToolHandlers();
    this.setupErrorHandling();
  }

  private setupToolHandlers(): void {
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
        console.error(`[Shellfirm MCP] 🎯 INTERCEPTED: ${name} called - enforcing mandatory security`);
        console.error(`[Shellfirm MCP] 🔒 This tool name has been intercepted and redirected to secure execution`);
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
      console.error(`[Shellfirm MCP] 🚨 SECURITY VIOLATION: Unknown tool "${name}" attempted`);
      console.error(`[Shellfirm MCP] 🛡️ All terminal commands MUST use 'run_terminal_cmd' with mandatory Shellfirm MCP protection`);

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
        this.propagateProcessEnv
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
        console.error('[Shellfirm MCP] ✅ Command executed successfully');
      } else {
        console.error('[Shellfirm MCP] ❌ Command blocked by security policy');
        console.error('[Shellfirm MCP] 💡 To execute this command, you must manually approve it');
        console.error('[Shellfirm MCP] 💡 Consider running it directly in your terminal if you trust it');
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
      console.error('[Shellfirm MCP] ❌ Critical error in secure command execution:', error);
      console.error('[Shellfirm MCP] 🛡️ Blocking command for security due to system error');

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
        console.error('[Shellfirm MCP] ❌ JSON serialization failed:', jsonError);
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
      console.error(`[Shellfirm MCP] 🔍 Validating command with WASM engine: ${cleanCommand}`);

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

        console.error('[Shellfirm MCP] Command is safe');

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
      console.error(`[Shellfirm MCP] Risky patterns detected: ${patterns}`);

      // Command denied completely
      if (validationResult.should_deny) {
        console.error('[Shellfirm MCP] Command is denied by security policy');
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
      console.error('[Shellfirm MCP] 🚨 Command blocked - security policy enforced');
      console.error('[Shellfirm MCP] 💡 To execute this command, you must manually approve it');
      console.error('[Shellfirm MCP] 💡 Consider running it directly in your terminal if you trust it');

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
      console.error('[Shellfirm MCP] Error validating command:', error);
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
      console.error('[Shellfirm MCP] ❌ Server error:', error);
      // Don't crash - just log the error
    };

    // Global error handlers to prevent crashes
    process.on('uncaughtException', (error) => {
      console.error('[Shellfirm MCP] 🚨 Uncaught exception:', error);
      console.error('[Shellfirm MCP] 🛡️ Server continuing to run for security');
      // Don't exit - keep server running for security
    });

    process.on('unhandledRejection', (reason, promise) => {
      console.error('[Shellfirm MCP] 🚨 Unhandled rejection at:', promise, 'reason:', reason);
      console.error('[Shellfirm MCP] 🛡️ Server continuing to run for security');
      // Don't exit - keep server running for security
    });

    process.on('SIGINT', async () => {
      console.error('[Shellfirm MCP] 🔄 Shutting down server...');
      try {
        await this.server.close();
        process.exit(0);
      } catch (error) {
        console.error('[Shellfirm MCP] ❌ Error during shutdown:', error);
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
      console.error(`[Shellfirm MCP] 📋 Loaded ${patterns.length} security patterns`);

    } catch (error) {
      console.error('[Shellfirm MCP] ❌ Failed to initialize WASM module:', error);
      throw new Error(`WASM initialization failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Ensure WASM is initialized before processing commands
   */
  private async ensureWasmInitialized(): Promise<void> {
    if (!this.wasmInitialized) {
      console.error('[Shellfirm MCP] WASM not initialized, initializing now...');
      await this.initializeWasm();
    }
  }

  async run(): Promise<void> {
    try {
      // Initialize WASM first
      console.error('[Shellfirm MCP] 🚀 Starting Shellfirm MCP Server...');
      await this.initializeWasm();

      // Start MCP server
      const transport = new StdioServerTransport();
      await this.server.connect(transport);

    } catch (error) {
      console.error('[Shellfirm MCP] 💥 Server startup failed:', error);
      process.exit(1);
    }
  }
}

// Start the WASM-powered MCP server
async function main() {
  console.error('🚀 Shellfirm MCP Server');

  // Parse command line arguments
  const args = process.argv.slice(2);
  let challengeType: ChallengeType = 'confirm'; // default
  let severities: string[] = ['critical', 'high', 'medium'];
  let propagateProcessEnv = true; // default

  // --challenge <type>
  const chalIdx = args.indexOf('--challenge');
  if (chalIdx !== -1 && args[chalIdx + 1]) {
    challengeType = (args[chalIdx + 1] as ChallengeType);
  }
  // "yes" challenge is no longer supported via flag - fall back to confirm
  // Guard: if an unsupported value is provided, fall back to confirm
  const allowed: ChallengeType[] = ['confirm', 'math', 'word'];
  if (!allowed.includes(challengeType)) {
    console.error(`[Shellfirm MCP] Unsupported challenge type "${String(challengeType)}". Falling back to 'confirm'.`);
    challengeType = 'confirm';
  }
  // --severity a,b,c
  const sevIdx = args.indexOf('--severity');
  if (sevIdx !== -1 && args[sevIdx + 1]) {
    severities = args[sevIdx + 1]
      .split(',')
      .map(s => s.trim().toLowerCase())
      .filter(Boolean);
  }

  // --no-propagate-env (boolean flag to disable env propagation)
  if (args.includes('--no-propagate-env')) {
    propagateProcessEnv = false;
  }

  console.error(`🎯 Challenge type: ${challengeType}`);
  console.error(`🔧 Severity levels: ${severities.join(', ')}`);
  console.error(`🌍 Propagate process.env: ${propagateProcessEnv}`);

  const server = new ShellfirmMcpServer(challengeType, severities, propagateProcessEnv);
  await server.run();
}

main().catch((error: unknown) => {
  console.error('Failed to start server:', error);
  process.exit(1);
});
