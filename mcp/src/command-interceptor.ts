import { exec } from 'child_process';
import { promisify } from 'util';
import { validateSplitCommandWithOptions } from './shellfirm-wasm.js';
import { BrowserChallenge, type ChallengeData } from './browser-challenge.js';
import type { ChallengeType } from './types.js';
import { log as mcpLog, toErrorObject } from './logger.js';

const execAsync = promisify(exec);

/**
 * Command interceptor that forces ALL commands through MCP validation
 */
export class CommandInterceptor {

	/**
	 * Intercept and validate command before execution
	 */
	static async interceptCommand(
		command: string,
		workingDirectory?: string,
		challengeType: ChallengeType = 'confirm',
		allowedSeverities?: string[],
		environment?: Record<string, string>,
		propagateProcessEnv: boolean = true
	): Promise<{
		allowed: boolean;
		output?: string;
		error?: string;
		message: string;
	}> {
		void mcpLog('debug', 'interceptor', { message: 'Intercepting command', command });

		try {
			// Use WASM-based validation with options for proper severity filtering
			const validationOptions = {
				allowed_severities: allowedSeverities || [],
				deny_pattern_ids: [], // Could be extended to support denied patterns
			};

			const validationResult = await validateSplitCommandWithOptions(command, validationOptions);
			void mcpLog('debug', 'interceptor', {
				message: 'WASM validation result',
				should_challenge: validationResult.should_challenge,
				should_deny: validationResult.should_deny,
				matches: validationResult.matches.map(match => match.id)
			});

			if (!validationResult.should_challenge) {
				// Safe command - execute directly
				void mcpLog('info', 'interceptor', { message: 'Command is safe, executing' });
				return await this.executeCommand(command, workingDirectory, environment, propagateProcessEnv);
			}

			// Command denied completely
			if (validationResult.should_deny) {
				void mcpLog('warning', 'interceptor', { message: 'Command denied by security policy' });
				const descriptions = validationResult.matches.map(check => check.description).join(', ');
				return {
					allowed: false,
					message: `Shellfirm MCP: Command denied by security policy. Reasons: ${descriptions}`,
					error: 'Security policy violation'
				};
			}

			// Risky command - require browser-based challenge verification
			const descriptions = validationResult.matches.map(check => check.description).join(', ');
			void mcpLog('notice', 'interceptor', { message: 'Risky command detected', patterns: descriptions });

			// Check if this is a Block challenge - if so, block immediately
			if (challengeType === 'block') {
				void mcpLog('warning', 'interceptor', { message: 'Command blocked by security policy (Block challenge type)' });
				return {
					allowed: false,
					message: `Shellfirm MCP: Command blocked by security policy. This command cannot be executed. Reasons: ${descriptions}`,
					error: 'Command blocked by security policy'
				};
			}

			void mcpLog('notice', 'interceptor', { message: 'Opening browser challenge for user verification' });

			// Prepare challenge data
			const challengeData: ChallengeData = {
				command,
				patterns: validationResult.matches.map(check => check.description),
				severity: this.getHighestSeverity(validationResult.matches),
				matches: validationResult.matches.map(check => ({
					id: check.id,
					severity: check.severity,
					description: check.description
				}))
			};

			try {
				// Show browser challenge
				const challengeResult = await BrowserChallenge.showChallenge(
					challengeType,
					challengeData,
					60000 // 60 second timeout
				);

				if (challengeResult.approved) {
					void mcpLog('info', 'interceptor', { message: 'User approved command through browser challenge' });
					// User approved - execute the command
					return await this.executeCommand(command, workingDirectory, environment, propagateProcessEnv);
				} else {
					void mcpLog('warning', 'interceptor', { message: 'User denied command or challenge failed' });
					return {
						allowed: false,
						message: `Shellfirm MCP: Command denied by user. ${challengeResult.error || 'User chose not to approve the command.'}`,
						error: 'User denial or challenge failure'
					};
				}

			} catch (challengeError) {
				void mcpLog('error', 'interceptor', { message: 'Browser challenge system error', error: toErrorObject(challengeError) });
				return {
					allowed: false,
					message: `Shellfirm MCP: Challenge system error. Command blocked for security. Error: ${challengeError instanceof Error ? challengeError.message : 'Unknown error'}`,
					error: 'Challenge system failure'
				};
			}

		} catch (error) {
			void mcpLog('error', 'interceptor', { message: 'Error in command interception', error: toErrorObject(error) });
			return {
				allowed: false,
				message: `Command blocked due to error: ${error instanceof Error ? error.message : 'Unknown error'}`,
				error: 'Interception error'
			};
		}
	}

	/**
	 * Get the highest severity level from a list of matches
	 */
	private static getHighestSeverity(matches: Array<{ severity?: string }>): string {
		const severityOrder = ['low', 'medium', 'high', 'critical'];
		let highestSeverity = 'medium';

		for (const match of matches) {
			const severity = match.severity || 'medium';
			if (severityOrder.indexOf(severity) > severityOrder.indexOf(highestSeverity)) {
				highestSeverity = severity;
			}
		}

		return highestSeverity;
	}

	/**
	 * Execute command after validation
	 */
	private static async executeCommand(
		command: string,
		workingDirectory?: string,
		environment?: Record<string, string>,
		propagateProcessEnv: boolean = true
	): Promise<{
		allowed: boolean;
		output?: string;
		error?: string;
		message: string;
	}> {
		try {
			const options: { cwd?: string; env?: Record<string, string> } = {};
			if (workingDirectory) {
				options.cwd = workingDirectory;
			}
			// Configure environment propagation behavior
			if (propagateProcessEnv) {
				// Merge clean process.env with provided environment (if any)
				const cleanProcessEnv = Object.fromEntries(
					Object.entries(process.env).filter(([_, value]) => value !== undefined)
				) as Record<string, string>;
				options.env = { ...cleanProcessEnv, ...(environment || {}) };
			} else {
				// Do not propagate current process env; use only provided env (or empty)
				options.env = { ...(environment || {}) };
			}

			// Clean the command by removing any trailing whitespace/newlines
			const cleanCommand = command.trim();

			const { stdout, stderr } = await execAsync(cleanCommand, options);

			return {
				allowed: true,
				output: stdout.toString(),
				error: stderr ? stderr.toString() : undefined,
				message: 'Command executed successfully'
			};

		} catch (execError) {
			const errorMessage = execError instanceof Error ? execError.message : 'Unknown execution error';
			void mcpLog('error', 'interceptor', { message: 'Command execution failed', error: errorMessage });

			return {
				allowed: true, // Command was allowed but failed execution
				output: '',
				error: errorMessage,
				message: 'Command was allowed but execution failed'
			};
		}
	}
}

