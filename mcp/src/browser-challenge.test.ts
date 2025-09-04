import * as http from 'http';
import { describe, it, expect } from 'vitest';
import { BrowserChallenge } from './browser-challenge';

async function waitForServer(urlGetter: () => string | null, timeoutMs = 5000): Promise<string> {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    const interval = setInterval(() => {
      const url = urlGetter();
      if (url) {
        clearInterval(interval);
        resolve(url);
      } else if (Date.now() - start > timeoutMs) {
        clearInterval(interval);
        reject(new Error('Server URL not available in time'));
      }
    }, 25);
  });
}

function httpRequest(method: 'GET' | 'POST', url: string): Promise<{ statusCode: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(url, { method }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        resolve({ statusCode: res.statusCode || 0, body: data });
      });
    });
    req.on('error', reject);
    req.end();
  });
}

const baseChallengeData = {
  command: 'rm -rf /tmp/*',
  patterns: ['recursive deletion'],
  severity: 'high',
  matches: [
    { id: 'fs_recursive_delete', severity: 'critical', description: 'Recursive delete pattern' }
  ]
};

describe('BrowserChallenge server flows', () => {
  it('approves via /approve for math', async () => {
    const challenge = new BrowserChallenge();
    const promise = challenge.showChallenge('math', baseChallengeData, 5000, { openBrowser: false });
    const url = await waitForServer(() => challenge.getChallengeUrlForTests());
    // Warm GET /
    await httpRequest('GET', `${url}/`);
    // Approve
    await httpRequest('GET', `${url}/approve`);
    const result = await promise;
    expect(result.approved).toBe(true);
    expect(result.type).toBe('math');
  });

  it('denies via /deny for word', async () => {
    const challenge = new BrowserChallenge();
    const promise = challenge.showChallenge('word', baseChallengeData, 5000, { openBrowser: false });
    const url = await waitForServer(() => challenge.getChallengeUrlForTests());
    await httpRequest('GET', `${url}/`);
    await httpRequest('GET', `${url}/deny`);
    const result = await promise;
    expect(result.approved).toBe(false);
    expect(result.type).toBe('word');
  });

  it('times out when no action for confirm', async () => {
    const challenge = new BrowserChallenge();
    const promise = challenge.showChallenge('confirm', baseChallengeData, 200, { openBrowser: false });
    const url = await waitForServer(() => challenge.getChallengeUrlForTests());
    // let it time out without hitting approve/deny
    expect(url).toContain('127.0.0.1');
    const result = await promise;
    expect(result.approved).toBe(false);
    expect(result.type).toBe('confirm');
    expect(result.error).toContain('timeout');
  });
});

 