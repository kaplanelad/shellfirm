import * as http from 'http';
import { describe, it, expect } from 'vitest';
import { BrowserChallenge } from './browser-challenge';

async function request(path: string, baseUrl: string): Promise<{ status: number; body: string }> {
  const url = baseUrl + path;
  return new Promise((resolve, reject) => {
    const req = http.request(url, { method: 'GET' }, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => resolve({ status: res.statusCode || 0, body: data }));
    });
    req.on('error', reject);
    req.end();
  });
}

async function start(type: 'math' | 'word' | 'confirm' | 'block') {
  const data = {
    command: 'echo test',
    patterns: ['sample'],
    severity: 'high',
  } satisfies Parameters<BrowserChallenge['showChallenge']>[1];
  const instance = new BrowserChallenge();
  const p = instance.showChallenge(type, data, 3000, { openBrowser: false });
  const startAt = Date.now();
  let base: string | null = null;
  while (!base && Date.now() - startAt < 2000) {
    base = instance.getChallengeUrlForTests();
    if (!base) await new Promise(r => setTimeout(r, 25));
  }
  if (!base) throw new Error('server not ready');
  return { instance, p, base };
}

describe('BrowserChallenge HTML content', () => {
  it('math page includes problem and correctAnswer', async () => {
    const { base, p } = await start('math');
    const res = await request('/', base);
    expect(res.status).toBe(200);
    expect(res.body).toContain('class="math-problem"');
    expect(res.body).toContain('window.correctAnswer');
    await request('/deny', base); // close
    await p;
  });

  it('word page includes word display and targetWord', async () => {
    const { base, p } = await start('word');
    const res = await request('/', base);
    expect(res.status).toBe(200);
    expect(res.body).toContain('class="word-display"');
    expect(res.body).toContain('window.targetWord');
    await request('/deny', base);
    await p;
  });

  it('confirm page includes two buttons', async () => {
    const { base, p } = await start('confirm');
    const res = await request('/', base);
    expect(res.status).toBe(200);
    expect(res.body).toContain('Yes, Execute Command');
    expect(res.body).toContain('No, Cancel Command');
    await request('/deny', base);
    await p;
  });
});


