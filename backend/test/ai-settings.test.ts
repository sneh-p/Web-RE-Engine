import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'http';
import type { AddressInfo } from 'net';
import { db } from '../src/queue/jobQueue.js';
import { saveAiConfig, getAiConfig, getAiConfigPublic, clearAiConfig, validateAiUpdate } from '../src/services/settings.js';
import { testAiProvider, isAiConfigured } from '../src/services/ai.js';

const KEY = 'sk-test-0123456789abcdefWXYZ';
let mock: http.Server;
let baseUrl = '';
let lastAuth = '';
let lastBody: any = null;

// Minimal OpenAI-compatible /chat/completions that streams two chunks
before(async () => {
  mock = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      lastAuth = req.headers.authorization ?? '';
      lastBody = JSON.parse(body || '{}');
      if (lastAuth !== `Bearer ${KEY}`) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: { message: 'Incorrect API key provided' } }));
      }
      res.writeHead(200, { 'Content-Type': 'text/event-stream' });
      const chunk = (content: string, finish: string | null = null) =>
        `data: ${JSON.stringify({ model: 'mock-model-1', choices: [{ delta: { content }, finish_reason: finish }] })}\n\n`;
      res.write(chunk('O'));
      res.write(chunk('K', 'stop'));
      res.end('data: [DONE]\n\n');
    });
  });
  await new Promise<void>((r) => mock.listen(0, '127.0.0.1', r));
  baseUrl = `http://127.0.0.1:${(mock.address() as AddressInfo).port}/v1`;
});

after(() => {
  clearAiConfig();
  mock.close();
});

test('settings: validation rejects bad providers, model ids and URLs', () => {
  assert.match(validateAiUpdate({ provider: 'x', model: 'm' })!, /provider/);
  assert.match(validateAiUpdate({ provider: 'openai', model: 'bad model!' })!, /model/);
  assert.match(validateAiUpdate({ provider: 'openai', model: 'm', baseUrl: 'file:///etc' })!, /http/);
  assert.match(validateAiUpdate({ provider: 'openai', model: 'm' })!, /base URL/);
  assert.equal(validateAiUpdate({ provider: 'anthropic', model: 'claude-opus-5-5' }), null);
});

test('settings: the API key is encrypted at rest and never exposed publicly', () => {
  saveAiConfig({ provider: 'openai', model: 'mock-model-1', baseUrl: `${baseUrl}/`, apiKey: KEY });
  const raw = (db.prepare("SELECT value FROM settings WHERE key = 'ai'").get() as { value: string }).value;
  assert.ok(!raw.includes(KEY) && !raw.includes('0123456789'));

  const pub = getAiConfigPublic();
  assert.equal(pub.configured, true);
  assert.equal(pub.keyHint, '…WXYZ');
  assert.equal(pub.baseUrl, baseUrl, 'trailing slash is trimmed');
  assert.ok(!JSON.stringify(pub).includes(KEY));
  assert.equal(getAiConfig()!.apiKey, KEY);

  // Saving again without a key keeps the stored one
  saveAiConfig({ provider: 'openai', model: 'mock-model-2', baseUrl });
  assert.equal(getAiConfig()!.apiKey, KEY);
  assert.equal(isAiConfigured(), true);
});

test('OpenAI-compatible provider: streams the reply with the bearer key', async () => {
  const res = await testAiProvider({ provider: 'openai', model: 'mock-model-1', baseUrl, apiKey: KEY, source: 'portal' });
  assert.deepEqual(res, { ok: true, model: 'mock-model-1', reply: 'OK' });
  assert.equal(lastAuth, `Bearer ${KEY}`);
  assert.equal(lastBody.stream, true);
  assert.equal(lastBody.messages[0].role, 'system');
});

test('OpenAI-compatible provider: a rejected key gives a readable error', async () => {
  const res = await testAiProvider({ provider: 'openai', model: 'mock-model-1', baseUrl, apiKey: 'wrong', source: 'portal' });
  assert.equal(res.ok, false);
  assert.match(res.error!, /rejected the API key.*Incorrect API key/);
});

test('settings: clearing falls back to "not configured" when no env key exists', () => {
  clearAiConfig();
  assert.equal(getAiConfigPublic().source, 'none');
  assert.equal(isAiConfigured(), false);
});
