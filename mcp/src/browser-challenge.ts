/**
 * Browser Challenge System
 * 
 * This module handles opening browser windows with security challenges
 * when dangerous commands are detected.
 */

import * as path from 'path';
import * as fs from 'fs';
import * as http from 'http';
import * as net from 'net';
import Handlebars from 'handlebars';
import { error as logError, info as logInfo, notice as logNotice } from './logger.js';

// CommonJS environment provides __dirname

export interface ChallengeResult {
  approved: boolean;
  type: string;
  error?: string;
}

export interface ChallengeData {
  command: string;
  patterns: string[];
  severity: string;
  matches?: Array<{ id: string; severity: string; description: string }>;
}

export class BrowserChallenge {
  private server: http.Server | null = null;
  private challengeResult: ChallengeResult | null = null;
  private challengePort: number = 0;
  private resolveChallenge: ((result: ChallengeResult) => void) | null = null;
  private sockets: Set<net.Socket> = new Set();

  /**
   * Show a challenge based on the challenge type
   */
  async showChallenge(
    challengeType: string,
    challengeData: ChallengeData,
    timeoutMs: number = 60000,
    options?: { openBrowser?: boolean }
  ): Promise<ChallengeResult> {
    try {
      await logInfo('browser-challenge', { message: 'Showing challenge', challengeType, command: challengeData.command });

      // Start a local server to serve the challenge
      await this.startChallengeServer(challengeType, challengeData);

      // Prepare promise resolver for server POST callbacks
      this.challengeResult = null;
      const challengePromise = new Promise<ChallengeResult>((resolve) => {
        this.resolveChallenge = (result: ChallengeResult) => {
          if (!this.challengeResult) {
            this.challengeResult = result;
          }
          resolve(result);
        };
      });

      // Determine whether to open the system browser (tests may disable)
      const challengeUrl = `http://127.0.0.1:${this.challengePort}`;
      if (options?.openBrowser !== false) {
        this.openInSystemBrowser(challengeUrl);
      }

      await logNotice('browser-challenge', { message: 'Challenge page opened', url: challengeUrl });

      // Set up timeout
      let timeoutId: NodeJS.Timeout | null = null;
      const timeoutPromise = new Promise<ChallengeResult>((resolve) => {
        timeoutId = setTimeout(() => {
          resolve({
            approved: false,
            type: challengeType,
            error: 'Challenge timeout - user did not respond in time'
          });
        }, timeoutMs);
      });

      // Wait for either completion or timeout
      const result = await Promise.race([challengePromise, timeoutPromise]);

      // Ensure timers are cleared after we have a result
      if (timeoutId) {
        clearTimeout(timeoutId);
        timeoutId = null;
      }

      // Clean up
      await this.stopChallengeServer();

      await logInfo('browser-challenge', { message: 'Challenge completed', approved: result.approved });

      return result;

    } catch (error) {
      await logError('browser-challenge', { message: 'Error during challenge', error: String(error) });
      await this.stopChallengeServer();

      return {
        approved: false,
        type: challengeType,
        error: `Challenge error: ${error instanceof Error ? error.message : 'Unknown error'}`
      };
    }
  }

  // Removed system browser executable lookup for simpler logic

  /**
   * Open a URL in the system default browser (macOS/Linux/Windows)
   */
  private openInSystemBrowser(url: string): void {
    try {
      const platform = process.platform;
      if (platform === 'darwin') {
        require('child_process').spawn('open', [url], { detached: true, stdio: 'ignore' }).unref();
      } else if (platform === 'win32') {
        require('child_process').spawn('cmd', ['/c', 'start', '', url], { detached: true, stdio: 'ignore' }).unref();
      } else {
        require('child_process').spawn('xdg-open', [url], { detached: true, stdio: 'ignore' }).unref();
      }
    } catch (e) {
      void logError('browser-challenge', { message: 'Failed to open system browser', error: String(e) });
    }
  }

  /**
   * Expose the current challenge URL (for tests only). Returns null if not active.
   */
  public getChallengeUrlForTests(): string | null {
    if (!this.challengePort) {
      return null;
    }
    return `http://127.0.0.1:${this.challengePort}`;
  }

  /**
   * Start a local HTTP server to serve the challenge page
   */
  private async startChallengeServer(challengeType: string, challengeData: ChallengeData): Promise<void> {
    return new Promise((resolve, reject) => {
      // Find an available port
      this.server = http.createServer((req, res) => {
        try {
          void logInfo('browser-challenge', { message: 'HTTP request', method: req.method, url: req.url });
        } catch { }
        // Handle CORS
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
        res.setHeader('Connection', 'close');

        if (req.method === 'OPTIONS') {
          res.writeHead(200);
          res.end();
          return;
        }

        if (req.url === '/' && req.method === 'GET') {
          // Serve the challenge page
          this.serveChallengeHTML(res, challengeType, challengeData);
        } else if ((req.url === '/approve' || req.url === '/approve/') && (req.method === 'POST' || req.method === 'GET')) {
          // Handle approval
          const result: ChallengeResult = { approved: true, type: challengeType };
          void logInfo('browser-challenge', { message: 'Received approve request' });
          res.writeHead(200, { 'Content-Type': 'application/json', 'Connection': 'close' });
          res.end(JSON.stringify({ status: 'approved' }));
          this.challengeResult = result;
          const resolver = this.resolveChallenge;
          this.resolveChallenge = null;
          if (resolver) {
            setImmediate(() => resolver(result));
          }
        } else if ((req.url === '/deny' || req.url === '/deny/') && (req.method === 'POST' || req.method === 'GET')) {
          // Handle denial
          const result: ChallengeResult = { approved: false, type: challengeType };
          void logInfo('browser-challenge', { message: 'Received deny request' });
          res.writeHead(200, { 'Content-Type': 'application/json', 'Connection': 'close' });
          res.end(JSON.stringify({ status: 'denied' }));
          this.challengeResult = result;
          const resolver = this.resolveChallenge;
          this.resolveChallenge = null;
          if (resolver) {
            setImmediate(() => resolver(result));
          }
        } else if (req.url === '/favicon.ico') {
          res.writeHead(204, { 'Connection': 'close' });
          res.end();
        } else {
          res.writeHead(404, { 'Connection': 'close' });
          res.end('Not found');
        }
      });

      // Tighten keep-alive and track sockets to ensure close() resolves
      this.server.keepAliveTimeout = 0;
      this.server.headersTimeout = 5000;
      this.server.on('connection', (socket: net.Socket) => {
        this.sockets.add(socket);
        try { socket.setKeepAlive(false); } catch { }
        socket.on('close', () => {
          this.sockets.delete(socket);
        });
      });

      this.server.listen(0, '127.0.0.1', () => {
        const address = this.server!.address();
        if (address && typeof address === 'object') {
          this.challengePort = address.port;
          resolve();
        } else {
          reject(new Error('Failed to get server port'));
        }
      });

      this.server.on('error', (error) => {
        reject(error);
      });
    });
  }

  /**
 * Serve the appropriate challenge HTML based on type
 */
  private serveChallengeHTML(res: http.ServerResponse, challengeType: string, challengeData: ChallengeData): void {
    try {
      const baseTemplatePath = path.join(__dirname, '..', 'templates', 'base-challenge.html');

      if (!fs.existsSync(baseTemplatePath)) {
        void logError('browser-challenge', { message: 'Base template not found', baseTemplatePath });
        res.writeHead(500, { 'Connection': 'close' });
        res.end('Base template not found');
        return;
      }

      // Read and compile the template
      const templateSource = fs.readFileSync(baseTemplatePath, 'utf8');
      const template = Handlebars.compile(templateSource);

      // Get challenge-specific configuration
      const challengeConfig = this.getChallengeConfig(challengeType, challengeData);

      // Create the complete context object for the template
      const templateContext = {
        ...challengeConfig,
        COMMAND: this.escapeHtml(challengeData.command),
        MATCHES_LIST: this.getMatchesListHTML(challengeData),
        MATCHES_COUNT: Array.isArray(challengeData.matches) ? challengeData.matches.length : (challengeData.patterns?.length || 0),
        RISK_LEVEL: challengeData.severity.toUpperCase(),
        RISK_CLASS: `risk-${challengeData.severity.toLowerCase()}`
      };

      // Render the template with the context
      const html = template(templateContext);

      res.writeHead(200, { 'Content-Type': 'text/html', 'Connection': 'close' });
      res.end(html);

    } catch (error) {
      void logError('browser-challenge', { message: 'Error serving challenge HTML', error: String(error) });
      res.writeHead(500, { 'Connection': 'close' });
      res.end('Error loading challenge');
    }
  }

  /**
   * Get challenge-specific configuration for template replacement
   */
  private getChallengeConfig(challengeType: string, challengeData: ChallengeData): Record<string, string> {
    const baseConfig = {
      COMMAND: this.escapeHtml(challengeData.command),
      DANGER_PATTERNS: this.escapeHtml(challengeData.patterns.join(', ')),
      RISK_LEVEL: challengeData.severity.toUpperCase(),
      RISK_CLASS: `risk-${challengeData.severity.toLowerCase()}`
    };

    switch (challengeType) {
      case 'math':
        return {
          ...baseConfig,
          SECURITY_ICON: '🛡️',
          CHALLENGE_TITLE: 'Security Challenge Required',
          CHALLENGE_SUBTITLE: 'A potentially dangerous command has been detected and requires verification before execution.',
          CHALLENGE_CONTENT: this.getMathChallengeContent(challengeData),
          CHALLENGE_BUTTONS: `
            <button class="btn btn-approve" id="approve-btn" type="button">
              ✓ Solve & Approve
            </button>
            <button class="btn btn-deny" onclick="denyCommand()" type="button">
              ✕ Deny Command
            </button>
          `,
          ERROR_MESSAGE: 'Incorrect answer. Please try again.',
          SUCCESS_MESSAGE: 'Correct! Approving command...',
          FOOTER_TEXT: 'Protected by Shellfirm MCP Security • Solve the math problem to approve command execution',
          CHALLENGE_SCRIPT: this.getMathChallengeScript()
        };

      case 'word':
        return {
          ...baseConfig,
          SECURITY_ICON: '🔤',
          CHALLENGE_TITLE: 'Word Verification Challenge',
          CHALLENGE_SUBTITLE: 'A potentially dangerous command has been detected and requires verification before execution.',
          CHALLENGE_CONTENT: this.getWordChallengeContent(challengeData),
          CHALLENGE_BUTTONS: `
            <button class="btn btn-approve" id="approve-btn" type="button">
              ✓ Verify & Approve
            </button>
            <button class="btn btn-deny" onclick="denyCommand()" type="button">
              ✕ Deny Command
            </button>
          `,
          ERROR_MESSAGE: 'Word doesn\'t match. Please type exactly as shown.',
          SUCCESS_MESSAGE: 'Correct! Approving command...',
          FOOTER_TEXT: 'Protected by Shellfirm MCP Security • Type the word exactly to approve command execution',
          CHALLENGE_SCRIPT: this.getWordChallengeScript()
        };

      case 'confirm':
        return {
          ...baseConfig,
          SECURITY_ICON: '⚠️',
          CHALLENGE_TITLE: 'Dangerous Command Detected',
          CHALLENGE_SUBTITLE: 'The following command contains potentially dangerous operations that could cause irreversible damage to your system.',
          CHALLENGE_CONTENT: this.getConfirmChallengeContent(challengeData),
          CHALLENGE_BUTTONS: `
            <button class="btn btn-approve" onclick="approveCommand()">
              ✓ Yes, Execute Command
            </button>
            <button class="btn btn-deny" onclick="denyCommand()">
              ✕ No, Cancel Command
            </button>
          `,
          ERROR_MESSAGE: '',
          SUCCESS_MESSAGE: '',
          FOOTER_TEXT: 'Protected by Shellfirm MCP Security • Think carefully before proceeding',
          CHALLENGE_SCRIPT: ''
        };

      case 'block':
        return {
          ...baseConfig,
          SECURITY_ICON: '🚫',
          CHALLENGE_TITLE: 'Command Blocked',
          CHALLENGE_SUBTITLE: 'This command has been blocked by security policy and cannot be executed.',
          CHALLENGE_CONTENT: this.getBlockChallengeContent(challengeData),
          CHALLENGE_BUTTONS: `
            <button class="btn btn-deny" onclick="denyCommand()" style="width: 100%; margin-top: 20px;">
              ✕ Command Blocked - Cannot Proceed
            </button>
          `,
          ERROR_MESSAGE: '',
          SUCCESS_MESSAGE: '',
          FOOTER_TEXT: 'Protected by Shellfirm MCP Security • This command is blocked by policy and cannot be executed',
          CHALLENGE_SCRIPT: ''
        };

      default:
        throw new Error(`Unknown challenge type: ${challengeType}`);
    }
  }

  /**
   * Render a unified matches list
   */
  private getMatchesListHTML(challengeData: ChallengeData): string {
    const hasMatches = Array.isArray(challengeData.matches) && challengeData.matches.length > 0;
    if (!hasMatches) {
      return `<li class="match-item sev-medium">
        <span class="match-id">patterns</span>
        <span class="match-sev">MEDIUM</span>
        <span class="match-desc">${this.escapeHtml(challengeData.patterns.join(', '))}</span>
      </li>`;
    }

    const items = challengeData.matches!.map(m => {
      const sevClass = `sev-${(m.severity || 'medium').toLowerCase()}`;
      return `<li class="match-item ${sevClass}">
        <div class="match-header">
          <span class="match-id">${this.escapeHtml(m.id)}</span>
          <span class="spacer"></span>
          <span class="match-sev">${this.escapeHtml(m.severity.toUpperCase())}</span>
        </div>
        <div class="match-desc">${this.escapeHtml(m.description)}</div>
      </li>`;
    }).join('');

    return items;
  }

  /**
   * Get math challenge content HTML
   */
  private getMathChallengeContent(challengeData: ChallengeData): string {
    const { problem, answer } = this.generateMathProblem();
    return `
      <div class="risk-level risk-${challengeData.severity.toLowerCase()}">
        ${challengeData.severity.toUpperCase()} Risk
      </div>
      <div class="math-problem" id="math-problem">
        ${problem}
      </div>
      <div class="input-group">
        <input type="number" id="answer" class="answer-input" placeholder="?" autofocus>
      </div>
      <script>
        window.correctAnswer = ${answer};
      </script>
    `;
  }

  /**
   * Get word challenge content HTML
   */
  private getWordChallengeContent(challengeData: ChallengeData): string {
    const word = this.generateSecurityWord();
    return `
      <div class="risk-level risk-${challengeData.severity.toLowerCase()}">
        ${challengeData.severity.toUpperCase()} Risk
      </div>
      <div class="word-display" id="word-display">
        ${word}
      </div>
      <div class="case-sensitive">
        ⚠️ Type the word exactly as shown (case-sensitive)
      </div>
      <div class="instruction">
        Type the security word exactly as displayed above:
      </div>
      <div class="input-group">
        <input type="text" id="answer" class="answer-input" placeholder="Type the word here..." autofocus>
      </div>
      <script>
        window.targetWord = "${word}";
      </script>
    `;
  }

  /**
   * Get confirm challenge content HTML
   */
  private getConfirmChallengeContent(challengeData: ChallengeData): string {
    return `
      <div class="risk-level risk-${challengeData.severity.toLowerCase()}">
        ${challengeData.severity.toUpperCase()} Risk
      </div>
      <div class="confirmation-message">
        <span class="emphasis">Are you absolutely certain</span> you want to execute this command?
      </div>
    `;
  }

  /**
   * Get block challenge content HTML
   */
  private getBlockChallengeContent(challengeData: ChallengeData): string {
    return `
      <div class="risk-level risk-${challengeData.severity.toLowerCase()}">
        ${challengeData.severity.toUpperCase()} Risk
      </div>
      <div class="blocked-message">
        <span class="emphasis">🚫 COMMAND BLOCKED</span>
        <br><br>
        This command has been blocked by security policy and cannot be executed.
        <br><br>
        <strong>Blocked by:</strong> Shellfirm MCP Security Policy
        <br>
        <strong>Reason:</strong> Command matches blocked security patterns
        <br><br>
        <div class="warning-box">
          ⚠️ This command is permanently blocked and cannot be bypassed.
        </div>
      </div>
    `;
  }

  /**
   * Get math challenge JavaScript
   */
  private getMathChallengeScript(): string {
    return `
      let attempts = 0;
      const maxAttempts = 3;
      let isSubmitting = false;

      function checkAnswerInternal(incrementAttempt) {
        if (isSubmitting) { return; }
        isSubmitting = true;
        const userAnswer = parseInt(document.getElementById('answer').value);
        if (incrementAttempt) { attempts++; }

        if (userAnswer === window.correctAnswer) {
          showSuccess();
          setTimeout(() => {
            approveCommand();
          }, 1000);
        } else {
          const errorMsg = document.getElementById('error-message');
          if (attempts >= maxAttempts) {
            errorMsg.textContent = 'Maximum attempts reached. Command will be denied.';
            setTimeout(() => {
              denyCommand();
            }, 2000);
          } else {
            errorMsg.textContent = \`Incorrect answer. \${maxAttempts - attempts} attempts remaining.\`;
          }
          showError();
          document.getElementById('answer').value = '';
        }
        // allow another submission after a short debounce
        setTimeout(() => { isSubmitting = false; }, 150);
      }

      // Make checkAnswer globally available
      window.checkAnswer = function() { checkAnswerInternal(true); };

      // Enter key support
      document.addEventListener('DOMContentLoaded', function() {
        if (window.__challengeEnterHandlersInstalled) { return; }
        window.__challengeEnterHandlersInstalled = true;
        const answerInput = document.getElementById('answer');
        const approveBtn = document.getElementById('approve-btn');
        if (approveBtn) {
          approveBtn.addEventListener('click', function(e) {
            e.preventDefault();
            checkAnswerInternal(true);
          });
        }
        if (answerInput) {
          let enterGuard = false;
          answerInput.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' && !e.repeat && !enterGuard) {
              enterGuard = true;
              e.preventDefault();
              checkAnswerInternal(false);
              setTimeout(() => { enterGuard = false; }, 300);
            }
          });
        }
      });
    `;
  }

  /**
   * Get word challenge JavaScript
   */
  private getWordChallengeScript(): string {
    return `
      let attempts = 0;
      const maxAttempts = 3;
      let isSubmitting = false;

      function checkAnswerInternal(incrementAttempt) {
        if (isSubmitting) { return; }
        isSubmitting = true;
        const userAnswer = document.getElementById('answer').value;
        if (incrementAttempt) { attempts++; }

        if (userAnswer === window.targetWord) {
          showSuccess();
          setTimeout(() => {
            approveCommand();
          }, 1000);
        } else {
          const errorMsg = document.getElementById('error-message');
          if (attempts >= maxAttempts) {
            errorMsg.textContent = 'Maximum attempts reached. Command will be denied.';
            setTimeout(() => {
              denyCommand();
            }, 2000);
          } else {
            errorMsg.textContent = \`Word doesn't match. \${maxAttempts - attempts} attempts remaining.\`;
          }
          showError();
          document.getElementById('answer').value = '';
        }
        // allow another submission after a short debounce
        setTimeout(() => { isSubmitting = false; }, 150);
      }

      // Make checkAnswer globally available
      window.checkAnswer = function() { checkAnswerInternal(true); };

      // Enter key support
      document.addEventListener('DOMContentLoaded', function() {
        if (window.__challengeEnterHandlersInstalled) { return; }
        window.__challengeEnterHandlersInstalled = true;
        const answerInput = document.getElementById('answer');
        const approveBtn = document.getElementById('approve-btn');
        if (approveBtn) {
          approveBtn.addEventListener('click', function(e) {
            e.preventDefault();
            checkAnswerInternal(true);
          });
        }
        if (answerInput) {
          let enterGuard = false;
          answerInput.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' && !e.repeat && !enterGuard) {
              enterGuard = true;
              e.preventDefault();
              checkAnswerInternal(false);
              setTimeout(() => { enterGuard = false; }, 300);
            }
          });
        }
      });
    `;
  }

  /**
   * Generate a math problem for the math challenge
   * Only supports addition (+) with numbers between 0-10
   */
  private generateMathProblem(): { problem: string; answer: number } {
    // Only use addition operation
    const operation = '+';

    // Generate numbers between 0-10 (inclusive)
    const num1 = Math.floor(Math.random() * 11); // 0-10
    const num2 = Math.floor(Math.random() * 11); // 0-10
    const answer = num1 + num2;

    return {
      problem: `${num1} ${operation} ${num2} = ?`,
      answer
    };
  }







  /**
   * Generate a security-related word for the word challenge
   */
  private generateSecurityWord(): string {
    const words = [
      'SECURITY', 'VERIFY', 'CONFIRM', 'APPROVE', 'ACCESS',
      'PROTECT', 'VALIDATE', 'AUTHORIZE', 'SECURE', 'TRUST',
      'SHIELD', 'GUARD', 'DEFEND', 'SAFETY', 'CHECK'
    ];
    return words[Math.floor(Math.random() * words.length)];
  }

  /**
   * Escape HTML to prevent XSS
   */
  private escapeHtml(text: string): string {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;');
  }

  /**
   * Stop the challenge server
   */
  private async stopChallengeServer(): Promise<void> {
    if (this.server) {
      return new Promise((resolve) => {
        // Force-destroy any open sockets to avoid hanging on keep-alive
        try {
          for (const socket of this.sockets) {
            try { socket.destroy(); } catch { }
          }
          this.sockets.clear();
        } catch { }

        this.server!.close(() => {
          this.server = null;
          resolve();
        });
      });
    }
  }

  /**
   * Clean up resources
   */
  async cleanup(): Promise<void> {
    try {
      await this.stopChallengeServer();

    } catch (error) {
      void logError('browser-challenge', { message: 'Error during cleanup', error: String(error) });
    }
  }

  /**
   * Static method to show a challenge with automatic cleanup
   */
  static async showChallenge(
    challengeType: string,
    challengeData: ChallengeData,
    timeoutMs: number = 60000,
    options?: { openBrowser?: boolean }
  ): Promise<ChallengeResult> {
    const challenge = new BrowserChallenge();

    try {
      const result = await challenge.showChallenge(challengeType, challengeData, timeoutMs, options);
      return result;
    } finally {
      await challenge.cleanup();
    }
  }
}
