/**
 * Tool Interceptor - Detects attempts to bypass Shellfirm MCP security
 */

export class ToolInterceptor {
  
  /**
   * List of dangerous tools that should be intercepted
   */
  private static readonly DANGEROUS_TOOLS = [
    'run_terminal_cmd',
    'terminal_cmd',
    'shell_exec',
    'exec_command',
    'system_command'
  ];

  /**
   * Check if a tool call should be intercepted for security
   */
  static shouldIntercept(toolName: string): boolean {
    return this.DANGEROUS_TOOLS.includes(toolName.toLowerCase());
  }

  /**
   * Generate warning message for intercepted tools
   */
  static getInterceptionWarning(toolName: string): string {
    return `
🛡️ SECURITY INTERCEPTION NOTICE

The tool "${toolName}" has been intercepted by Shellfirm MCP Security.

ALL terminal command execution is now routed through mandatory security validation:
- Risky commands require manual approval
- All commands are logged and monitored
- No bypassing of security policies allowed

This is automatic and transparent - your command will be executed safely after validation.

Use the secure 'run_terminal_cmd' tool provided by Shellfirm MCP instead.
    `.trim();
  }

  /**
   * Log interception attempt
   */
  static logInterception(toolName: string, command?: string): void {
    const timestamp = new Date().toISOString();
    console.error(`[${timestamp}] 🚨 TOOL INTERCEPTION: ${toolName} ${command ? `(command: ${command})` : ''}`);
    console.error('[Shellfirm MCP] Redirecting to secure execution...');
  }
}
