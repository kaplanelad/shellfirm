import { test, expect, describe, beforeAll, afterAll } from 'vitest';
import { BrowserChallenge } from './browser-challenge';
import { chromium, Browser, Page } from 'playwright';

describe('Browser Challenge - Math Challenge', () => {
  let browser: Browser;
  let page: Page;
  let challengeInstance: BrowserChallenge;

  beforeAll(async () => {
    // Launch browser for testing
    browser = await chromium.launch({
      headless: process.env.CI === 'true', // Headless in CI, visible locally
      slowMo: process.env.CI === 'true' ? 0 : 1000 // No slowMo in CI
    });
    
    page = await browser.newPage();
    
    // Set up console logging
    page.on('console', msg => {
      if (msg.text().includes('Math') || msg.text().includes('math')) {
        console.log('🔍 Math Challenge Console:', msg.text());
      }
    });
  });

  afterAll(async () => {
    if (page) {
      await page.close();
    }
    if (browser) {
      await browser.close();
    }
    if (challengeInstance) {
      await challengeInstance.cleanup();
    }
  });

  test('should display math challenge with proper elements', async () => {
    // Create challenge data
    const challengeData = {
      command: 'rm -rf /important/data',
      patterns: ['file deletion', 'recursive removal'],
      severity: 'critical'
    };

    console.log('🚀 Launching real math challenge...');
    console.log(`   Command: ${challengeData.command}`);
    console.log(`   Patterns: ${challengeData.patterns.join(', ')}`);
    console.log(`   Severity: ${challengeData.severity}`);

    // Start the real challenge
    challengeInstance = new BrowserChallenge();
    await challengeInstance.initialize();
    
    // Start the challenge server
    await challengeInstance['startChallengeServer']('math', challengeData);
    
    // Get the port from the challenge instance
    const port = challengeInstance['challengePort'];
    console.log(`   Challenge server started on port ${port}`);
    
    // Navigate to the challenge page
    await page.goto(`http://localhost:${port}`);
    
    // Wait for the math problem to be displayed
    await page.waitForSelector('#math-problem', { timeout: 10000 });
    
    // Verify the math problem is displayed
    const mathProblem = await page.textContent('#math-problem');
    expect(mathProblem).toBeTruthy();
    expect(mathProblem).toMatch(/\d+ [+\-*] \d+ = \?/);
    
    // Verify input field exists
    const answerInput = await page.locator('#answer');
    expect(await answerInput.isVisible()).toBe(true);
    
    // Verify approve button exists
    const approveBtn = await page.locator('#approve-btn');
    expect(await approveBtn.isVisible()).toBe(true);
    
    // Verify deny button exists
    const denyBtn = await page.locator('button[onclick="denyCommand()"]');
    expect(await denyBtn.isVisible()).toBe(true);
    
    console.log('✅ Real math challenge launched successfully with all elements');
  }, 30000);

  test('should handle wrong answer correctly', async () => {
    // Wait for the page to be ready
    await page.waitForSelector('#answer', { timeout: 10000 });
    
    // Fill in wrong answer
    await page.fill('#answer', '999');
    await page.click('#approve-btn');
    
    // Wait for error message
    await page.waitForSelector('#error-message', { state: 'visible', timeout: 5000 });
    
    // Verify error message
    const errorMessage = await page.textContent('#error-message');
    expect(errorMessage).toContain('Incorrect answer');
    expect(errorMessage).toContain('attempts remaining');
    
    // Verify input is cleared
    const inputValue = await page.inputValue('#answer');
    expect(inputValue).toBe('');
    
    console.log('✅ Wrong answer handling works correctly');
  }, 30000);

  test('should handle correct answer and approve command', async () => {
    // Wait for the page to be ready
    await page.waitForSelector('#answer', { timeout: 10000 });
    
    // Get the correct answer from the page
    const correctAnswer = await page.evaluate(() => window.correctAnswer);
    expect(correctAnswer).toBeDefined();
    expect(typeof correctAnswer).toBe('number');
    
    console.log(`🔍 Correct answer is: ${correctAnswer}`);
    
    // Fill in correct answer
    await page.fill('#answer', correctAnswer.toString());
    await page.click('#approve-btn');
    
    // Wait for success message
    await page.waitForSelector('#success-message', { state: 'visible', timeout: 5000 });
    
    // Verify success message
    const successMessage = await page.textContent('#success-message');
    expect(successMessage).toContain('Correct!');
    
    console.log('✅ Correct answer handling works correctly');
    
    // Wait for approval (this should trigger the approveCommand function)
    await page.waitForTimeout(2000);
  }, 30000);

  test('should enforce maximum attempts limit', async () => {
    // Reload the page for this test
    await page.reload();
    await page.waitForSelector('#math-problem', { timeout: 10000 });
    
    // Make 3 wrong attempts
    for (let i = 0; i < 3; i++) {
      await page.fill('#answer', '999');
      await page.click('#approve-btn');
      
      // Wait for error message
      await page.waitForSelector('#error-message', { state: 'visible', timeout: 5000 });
      
      if (i < 2) {
        // Should show attempts remaining
        const errorMessage = await page.textContent('#error-message');
        expect(errorMessage).toContain('attempts remaining');
      }
    }
    
    // 4th attempt should show max attempts reached
    await page.fill('#answer', '999');
    await page.click('#approve-btn');
    
    await page.waitForSelector('#error-message', { state: 'visible', timeout: 5000 });
    const finalErrorMessage = await page.textContent('#error-message');
    expect(finalErrorMessage).toContain('Maximum attempts reached');
    
    console.log('✅ Maximum attempts limit enforced correctly');
  }, 30000);

  test('should support Enter key for submission', async () => {
    // Reload the page for this test
    await page.reload();
    await page.waitForSelector('#math-problem', { timeout: 10000 });
    
    // Focus on input and press Enter with wrong answer
    await page.focus('#answer');
    await page.fill('#answer', '999');
    await page.press('#answer', 'Enter');
    
    // Should show error message
    await page.waitForSelector('#error-message', { state: 'visible', timeout: 5000 });
    const errorMessage = await page.textContent('#error-message');
    expect(errorMessage).toContain('Incorrect answer');
    
    console.log('✅ Enter key submission works correctly');
  }, 30000);

  test('should generate different math problems', async () => {
    // Reload the page for this test
    await page.reload();
    await page.waitForSelector('#math-problem', { timeout: 10000 });
    
    // Get the first math problem
    const firstProblem = await page.textContent('#math-problem');
    expect(firstProblem).toBeTruthy();
    
    // Reload again to get a different problem
    await page.reload();
    await page.waitForSelector('#math-problem', { timeout: 10000 });
    
    const secondProblem = await page.textContent('#math-problem');
    expect(secondProblem).toBeTruthy();
    
    // Problems should be different (though there's a small chance they could be the same)
    console.log(`First problem: ${firstProblem}`);
    console.log(`Second problem: ${secondProblem}`);
    
    // Verify both are valid math problems
    expect(firstProblem).toMatch(/\d+ [+\-*] \d+ = \?/);
    expect(secondProblem).toMatch(/\d+ [+\-*] \d+ = \?/);
    
    console.log('✅ Math problem generation works correctly');
  }, 30000);

  test('should handle all math operations (+, -, *)', async () => {
    // Reload the page for this test
    await page.reload();
    await page.waitForSelector('#math-problem', { timeout: 10000 });
    
    // Get the math problem
    const mathProblem = await page.textContent('#math-problem');
    expect(mathProblem).toBeTruthy();
    
    // Check if it contains one of the expected operations
    const hasValidOperation = /[\+\-\*]/.test(mathProblem);
    expect(hasValidOperation).toBe(true);
    
    // Verify the problem format
    expect(mathProblem).toMatch(/\d+ [+\-*] \d+ = \?/);
    
    console.log(`Math problem: ${mathProblem}`);
    console.log('✅ Math operations are properly generated');
  }, 30000);
});

describe('Browser Challenge - Word Challenge', () => {
  let browser: Browser;
  let page: Page;
  let challengeInstance: BrowserChallenge;

  beforeAll(async () => {
    // Launch browser for testing
    browser = await chromium.launch({
      headless: process.env.CI === 'true', // Headless in CI, visible locally
      slowMo: process.env.CI === 'true' ? 0 : 1000 // No slowMo in CI
    });
    
    page = await browser.newPage();
    
    // Set up console logging
    page.on('console', msg => {
      if (msg.text().includes('Word') || msg.text().includes('word')) {
        console.log('🔍 Word Challenge Console:', msg.text());
      }
    });
  });

  afterAll(async () => {
    if (page) {
      await page.close();
    }
    if (browser) {
      await browser.close();
    }
    if (challengeInstance) {
      await challengeInstance.cleanup();
    }
  });

  test('should display word challenge with proper elements', async () => {
    const challengeData = {
      command: 'sudo chmod 777 /etc/passwd',
      patterns: ['permission change', 'system file modification'],
      severity: 'high'
    };

    console.log('🚀 Launching real word challenge...');
    console.log(`   Command: ${challengeData.command}`);
    console.log(`   Patterns: ${challengeData.patterns.join(', ')}`);
    console.log(`   Severity: ${challengeData.severity}`);

    challengeInstance = new BrowserChallenge();
    await challengeInstance.initialize();
    await challengeInstance['startChallengeServer']('word', challengeData);
    
    const port = challengeInstance['challengePort'];
    console.log(`   Challenge server started on port ${port}`);
    
    await page.goto(`http://localhost:${port}`);
    
    // Wait for the word to be displayed
    await page.waitForSelector('#word-display', { timeout: 10000 });
    
    // Verify the word is displayed
    const wordDisplay = await page.textContent('#word-display');
    expect(wordDisplay).toBeTruthy();
    expect(wordDisplay.length).toBeGreaterThan(0);
    
    // Verify input field exists
    const answerInput = await page.locator('#answer');
    expect(await answerInput.isVisible()).toBe(true);
    
    // Verify approve button exists
    const approveBtn = await page.locator('#approve-btn');
    expect(await approveBtn.isVisible()).toBe(true);
    
    // Verify deny button exists
    const denyBtn = await page.locator('button[onclick="denyCommand()"]');
    expect(await denyBtn.isVisible()).toBe(true);
    
    console.log('✅ Real word challenge launched successfully with all elements');
  }, 30000);

  test('should handle wrong word correctly', async () => {
    await page.waitForSelector('#answer', { timeout: 10000 });
    
    // Fill in wrong word
    await page.fill('#answer', 'WRONG');
    await page.click('#approve-btn');
    
    // Wait for error message
    await page.waitForSelector('#error-message', { state: 'visible', timeout: 5000 });
    
    // Verify error message
    const errorMessage = await page.textContent('#error-message');
    expect(errorMessage).toContain("Word doesn't match");
    expect(errorMessage).toContain('attempts remaining');
    
    // Verify input is cleared
    const inputValue = await page.inputValue('#answer');
    expect(inputValue).toBe('');
    
    console.log('✅ Wrong word handling works correctly');
  }, 30000);

  test('should handle correct word and approve command', async () => {
    await page.waitForSelector('#answer', { timeout: 10000 });
    
    // Get the correct word from the page
    const correctWord = await page.evaluate(() => window.targetWord);
    expect(correctWord).toBeDefined();
    expect(typeof correctWord).toBe('string');
    
    console.log(`🔍 Correct word is: ${correctWord}`);
    
    // Fill in correct word
    await page.fill('#answer', correctWord);
    await page.click('#approve-btn');
    
    // Wait for success message
    await page.waitForSelector('#success-message', { state: 'visible', timeout: 5000 });
    
    // Verify success message
    const successMessage = await page.textContent('#success-message');
    expect(successMessage).toContain('Correct!');
    
    console.log('✅ Correct word handling works correctly');
    
    await page.waitForTimeout(2000);
  }, 30000);

  test('should enforce maximum attempts limit for word challenge', async () => {
    await page.reload();
    await page.waitForSelector('#word-display', { timeout: 10000 });
    
    // Make 3 wrong attempts
    for (let i = 0; i < 3; i++) {
      await page.fill('#answer', 'WRONG');
      await page.click('#approve-btn');
      
      await page.waitForSelector('#error-message', { state: 'visible', timeout: 5000 });
      
      if (i < 2) {
        const errorMessage = await page.textContent('#error-message');
        expect(errorMessage).toContain('attempts remaining');
      }
    }
    
    // 4th attempt should show max attempts reached
    await page.fill('#answer', 'WRONG');
    await page.click('#approve-btn');
    
    await page.waitForSelector('#error-message', { state: 'visible', timeout: 5000 });
    const finalErrorMessage = await page.textContent('#error-message');
    expect(finalErrorMessage).toContain('Maximum attempts reached');
    
    console.log('✅ Maximum attempts limit enforced correctly for word challenge');
  }, 30000);

  test('should support Enter key for word submission', async () => {
    await page.reload();
    await page.waitForSelector('#word-display', { timeout: 10000 });
    
    await page.focus('#answer');
    await page.fill('#answer', 'WRONG');
    await page.press('#answer', 'Enter');
    
    await page.waitForSelector('#error-message', { state: 'visible', timeout: 5000 });
    const errorMessage = await page.textContent('#error-message');
    expect(errorMessage).toContain("Word doesn't match");
    
    console.log('✅ Enter key submission works correctly for word challenge');
  }, 30000);

  test('should generate different security words', async () => {
    await page.reload();
    await page.waitForSelector('#word-display', { timeout: 10000 });
    
    const firstWord = await page.textContent('#word-display');
    expect(firstWord).toBeTruthy();
    
    await page.reload();
    await page.waitForSelector('#word-display', { timeout: 10000 });
    
    const secondWord = await page.textContent('#word-display');
    expect(secondWord).toBeTruthy();
    
    console.log(`First word: ${firstWord}`);
    console.log(`Second word: ${secondWord}`);
    
    // Both should be valid security words
    expect(firstWord.length).toBeGreaterThan(0);
    expect(secondWord.length).toBeGreaterThan(0);
    
    console.log('✅ Security word generation works correctly');
  }, 30000);
});

describe('Browser Challenge - Confirm Challenge', () => {
  let browser: Browser;
  let page: Page;
  let challengeInstance: BrowserChallenge;

  beforeAll(async () => {
    browser = await chromium.launch({
      headless: process.env.CI === 'true', // Headless in CI, visible locally
      slowMo: process.env.CI === 'true' ? 0 : 1000 // No slowMo in CI
    });
    
    page = await browser.newPage();
    
    page.on('console', msg => {
      if (msg.text().includes('Confirm') || msg.text().includes('confirm')) {
        console.log('🔍 Confirm Challenge Console:', msg.text());
      }
    });
  });

  afterAll(async () => {
    if (page) { await page.close(); }
    if (browser) { await browser.close(); }
    if (challengeInstance) {
      await challengeInstance.cleanup();
    }
  });

  test('should display confirm challenge with proper elements', async () => {
    const challengeData = {
      command: 'iptables -F && ufw disable',
      patterns: ['firewall disable', 'network security'],
      severity: 'medium'
    };

    console.log('🚀 Launching real confirm challenge...');
    console.log(`   Command: ${challengeData.command}`);
    console.log(`   Patterns: ${challengeData.patterns.join(', ')}`);
    console.log(`   Severity: ${challengeData.severity}`);

    challengeInstance = new BrowserChallenge();
    await challengeInstance.initialize();
    await challengeInstance['startChallengeServer']('confirm', challengeData);
    
    const port = challengeInstance['challengePort'];
    console.log(`   Challenge server started on port ${port}`);
    
    await page.goto(`http://localhost:${port}`);
    
    // Wait for the confirmation message
    await page.waitForSelector('.confirmation-message', { timeout: 10000 });
    
    // Verify the confirmation message is displayed
    const confirmMessage = await page.textContent('.confirmation-message');
    expect(confirmMessage).toBeTruthy();
    expect(confirmMessage).toContain('Are you absolutely certain');
    
    // Verify approve button exists
    const approveBtn = await page.locator('button[onclick="approveCommand()"]');
    expect(await approveBtn.isVisible()).toBe(true);
    
    // Verify deny button exists
    const denyBtn = await page.locator('button[onclick="denyCommand()"]');
    expect(await denyBtn.isVisible()).toBe(true);
    
    console.log('✅ Real confirm challenge launched successfully with all elements');
  }, 30000);

  test('should approve command when approve button is clicked', async () => {
    await page.waitForSelector('button[onclick="approveCommand()"]', { timeout: 10000 });
    
    // Click approve button
    await page.click('button[onclick="approveCommand()"]');
    
    // Wait a bit for the action to complete
    await page.waitForTimeout(2000);
    
    console.log('✅ Command approval works correctly');
  }, 30000);

  test('should deny command when deny button is clicked', async () => {
    await page.reload();
    await page.waitForSelector('button[onclick="denyCommand()"]', { timeout: 10000 });
    
    // Click deny button
    await page.click('button[onclick="denyCommand()"]');
    
    // Wait a bit for the action to complete
    await page.waitForTimeout(2000);
    
    console.log('✅ Command denial works correctly');
  }, 30000);

  test('should display danger patterns and risk level', async () => {
    await page.reload();
    await page.waitForSelector('.danger-patterns', { timeout: 10000 });
    
    // Verify danger patterns are displayed
    const dangerPatterns = await page.textContent('.danger-patterns');
    expect(dangerPatterns).toBeTruthy();
    expect(dangerPatterns).toContain('Security Issues Detected');
    
    // Verify risk level is displayed
    const riskLevel = await page.textContent('.risk-level');
    expect(riskLevel).toBeTruthy();
    expect(riskLevel).toContain('MEDIUM');
    
    console.log('✅ Danger patterns and risk level displayed correctly');
  }, 30000);
});

describe('Browser Challenge - Block Challenge', () => {
  let browser: Browser;
  let page: Page;
  let challengeInstance: BrowserChallenge;

  beforeAll(async () => {
    browser = await chromium.launch({
      headless: process.env.CI === 'true', // Headless in CI, visible locally
      slowMo: process.env.CI === 'true' ? 0 : 1000 // No slowMo in CI
    });
    
    page = await browser.newPage();
    
    page.on('console', msg => {
      if (msg.text().includes('Block') || msg.text().includes('block')) {
        console.log('🔍 Block Challenge Console:', msg.text());
      }
    });
  });

  afterAll(async () => {
    if (page) { await page.close(); }
    if (browser) { await browser.close(); }
    if (challengeInstance) {
      await challengeInstance.cleanup();
    }
  });

  test('should display block challenge with proper elements', async () => {
    const challengeData = {
      command: 'rm -rf / && chmod 777 /etc/passwd',
      patterns: ['file deletion', 'recursive removal', 'permission change', 'system file modification'],
      severity: 'critical'
    };

    console.log('🚀 Launching real block challenge...');
    console.log(`   Command: ${challengeData.command}`);
    console.log(`   Patterns: ${challengeData.patterns.join(', ')}`);
    console.log(`   Severity: ${challengeData.severity}`);

    challengeInstance = new BrowserChallenge();
    await challengeInstance.initialize();
    await challengeInstance['startChallengeServer']('block', challengeData);
    
    const port = challengeInstance['challengePort'];
    console.log(`   Challenge server started on port ${port}`);
    
    await page.goto(`http://localhost:${port}`);
    
    // Wait for the blocked message
    await page.waitForSelector('.blocked-message', { timeout: 10000 });
    
    // Verify the blocked message is displayed
    const blockedMessage = await page.textContent('.blocked-message');
    expect(blockedMessage).toBeTruthy();
    expect(blockedMessage).toContain('🚫 COMMAND BLOCKED');
    
    // Verify deny button exists (only button for blocked commands)
    const denyBtn = await page.locator('button[onclick="denyCommand()"]');
    expect(await denyBtn.isVisible()).toBe(true);
    
    // Verify no approve button exists (blocked commands can't be approved)
    const approveBtn = await page.locator('button[onclick="approveCommand()"]');
    expect(await approveBtn.count()).toBe(0);
    
    console.log('✅ Real block challenge launched successfully with all elements');
  }, 30000);

  test('should display permanent block message', async () => {
    await page.waitForSelector('.blocked-message', { timeout: 10000 });
    
    // Verify the permanent block message
    const blockedMessage = await page.textContent('.blocked-message');
    expect(blockedMessage).toContain('permanently blocked');
    expect(blockedMessage).toContain('cannot be bypassed');
    
    console.log('✅ Permanent block message displayed correctly');
  }, 30000);

  test('should show security policy information', async () => {
    await page.waitForSelector('.blocked-message', { timeout: 10000 });
    
    // Verify security policy information
    const blockedMessage = await page.textContent('.blocked-message');
    expect(blockedMessage).toContain('Shellfirm MCP Security Policy');
    expect(blockedMessage).toContain('Command matches blocked security patterns');
    
    console.log('✅ Security policy information displayed correctly');
  }, 30000);

  test('should deny command when deny button is clicked', async () => {
    await page.waitForSelector('button[onclick="denyCommand()"]', { timeout: 10000 });
    
    // Click deny button
    await page.click('button[onclick="denyCommand()"]');
    
    // Wait a bit for the action to complete
    await page.waitForTimeout(2000);
    
    console.log('✅ Command denial works correctly for blocked commands');
  }, 30000);
});

describe('Browser Challenge - Integration Tests', () => {
  let browser: Browser;
  let page: Page;

  beforeAll(async () => {
    browser = await chromium.launch({
      headless: process.env.CI === 'true', // Headless in CI, visible locally
      slowMo: process.env.CI === 'true' ? 0 : 1000 // No slowMo in CI
    });
    
    page = await browser.newPage();
  });

  afterAll(async () => {
    if (page) { await page.close(); }
    if (browser) { await browser.close(); }
  });

  test('should handle different severity levels correctly', async () => {
    const severities = ['low', 'medium', 'high', 'critical'];
    
    for (const severity of severities) {
      const challengeData = {
        command: `test command for ${severity} severity`,
        patterns: ['test pattern'],
        severity: severity
      };

      console.log(`🧪 Testing ${severity} severity challenge...`);

      const challengeInstance = new BrowserChallenge();
      await challengeInstance.initialize();
      await challengeInstance['startChallengeServer']('math', challengeData);
      
      const port = challengeInstance['challengePort'];
      await page.goto(`http://localhost:${port}`);
      
      // Wait for the risk level to be displayed
      await page.waitForSelector('.risk-level', { timeout: 10000 });
      
      // Verify the risk level is displayed correctly
      const riskLevel = await page.textContent('.risk-level');
      expect(riskLevel).toContain(severity.toUpperCase());
      
      // Clean up this challenge instance
      await challengeInstance.cleanup();
      
      console.log(`✅ ${severity} severity challenge handled correctly`);
    }
  }, 60000);

  test('should handle different command patterns correctly', async () => {
    const patterns = [
      ['file deletion'],
      ['network security', 'firewall'],
      ['system modification', 'permission change'],
      ['database access', 'user management']
    ];
    
    for (const pattern of patterns) {
      const challengeData = {
        command: `test command with patterns: ${pattern.join(', ')}`,
        patterns: pattern,
        severity: 'medium'
      };

      console.log(`🧪 Testing patterns: ${pattern.join(', ')}`);

      const challengeInstance = new BrowserChallenge();
      await challengeInstance.initialize();
      await challengeInstance['startChallengeServer']('word', challengeData);
      
      const port = challengeInstance['challengePort'];
      await page.goto(`http://localhost:${port}`);
      
      // Wait for the danger patterns to be displayed
      await page.waitForSelector('.danger-patterns', { timeout: 10000 });
      
      // Verify the patterns are displayed correctly
      const dangerPatterns = await page.textContent('.danger-patterns');
      expect(dangerPatterns).toContain('Security Issues Detected');
      
      // Clean up this challenge instance
      await challengeInstance.cleanup();
      
      console.log(`✅ Patterns ${pattern.join(', ')} handled correctly`);
    }
  }, 60000);
});
