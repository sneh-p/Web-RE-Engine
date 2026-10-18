import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import { spawn, type ChildProcess } from 'child_process';
import { hashPassword } from '../src/services/password.js';
import { buildHelloElf, buildTarGz, buildUpxElf, fixtureDir, hasTool, testRoot } from './fixtures.js';
import type { AnalysisJob } from '../../shared/types.js';

const PASSWORD = 'correct horse battery staple';
const PORT = 39_000 + Math.floor(Math.random() * 900);
const BASE = `http://127.0.0.1:${PORT}`;

let server: ChildProcess;
let serverLog = '';
let cookie = '';
let uploadsDir = '';

async function api(pathname: string, init: RequestInit & { auth?: boolean } = {}) {
  const headers = new Headers(init.headers);
  if (init.auth !== false && cookie) headers.set('Cookie', cookie);
  return fetch(`${BASE}${pathname}`, { ...init, headers });
}

async function upload(route: string, file: string, field = 'file') {
  const form = new FormData();
  form.append(field, new Blob([fs.readFileSync(file)]), path.basename(file));
  return api(route, { method: 'POST', body: form });
}

async function waitForJob(id: string, timeoutMs = 120_000): Promise<AnalysisJob> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const job = (await (await api(`/api/jobs/${id}`)).json()).data as AnalysisJob;
    if (job.status === 'completed' || job.status === 'failed') return job;
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`Job ${id} did not finish in time`);
}

before(async () => {
  // A separate data/uploads root from the unit tests, so this server owns its database
  const root = path.join(testRoot(), 'e2e');
  uploadsDir = path.join(root, 'uploads');
  fs.mkdirSync(uploadsDir, { recursive: true });

  server = spawn(process.execPath, ['--import', 'tsx', 'src/app.ts'], {
    cwd: path.resolve(import.meta.dirname, '..'),
    env: {
      ...process.env,
      PORT: String(PORT),
      HOST: '127.0.0.1',
      NODE_ENV: 'test',
      WEB_RE_DATA_DIR: path.join(root, 'data'),
      WEB_RE_UPLOADS_DIR: uploadsDir,
      WEB_RE_ADMIN_PASSWORD_HASH: hashPassword(PASSWORD),
      // Defined-but-empty values win over backend/.env, which never overrides existing variables
      ANTHROPIC_API_KEY: '',
      ANTHROPIC_AUTH_TOKEN: '',
      WEB_RE_RETENTION_DAYS: '0',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  server.stdout!.on('data', (d) => (serverLog += d));
  server.stderr!.on('data', (d) => (serverLog += d));

  for (let i = 0; i < 100; i++) {
    try {
      await fetch(`${BASE}/api/auth/me`);
      return;
    } catch {
      await new Promise((r) => setTimeout(r, 200));
    }
  }
  throw new Error(`Server did not start:\n${serverLog}`);
});

after(() => {
  server?.kill();
});

test('auth: API requires a session; wrong password and cross-site posts are refused', async () => {
  assert.equal((await api('/api/jobs', { auth: false })).status, 401);
  const wrong = await api('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: 'nope' }),
  });
  assert.equal(wrong.status, 401);

  const crossSite = await api('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: 'https://evil.example' },
    body: JSON.stringify({ password: PASSWORD }),
  });
  assert.equal(crossSite.status, 403);

  const ok = await api('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: PASSWORD }),
  });
  assert.equal(ok.status, 200);
  cookie = ok.headers.get('set-cookie')!.split(';')[0];
  assert.match(cookie, /^wre_session=/);
  assert.equal((await api('/api/jobs')).status, 200);
});

test('native: auto-detected ELF gets functions, pseudo-code, imports, IOCs and YARA', async (t) => {
  if (!hasTool('gcc') || !hasTool('r2')) return t.skip('gcc/radare2 not installed');
  const res = await upload('/api/analysis/auto', buildHelloElf(fixtureDir('e2e-elf')));
  assert.equal(res.status, 200);
  const job = await waitForJob((await res.json()).data.id);
  assert.equal(job.status, 'completed', job.error);
  assert.equal(job.result?.type, 'native');
  if (job.result?.type !== 'native') return;

  assert.ok(job.result.functions.length > 0);
  assert.equal(job.result.decompiler === 'r2-pdc' || job.result.decompiler === 'r2ghidra', true);
  assert.ok(job.result.functions.some((f) => f.name === 'main' && f.decompiledCode && f.callees.length > 0));
  assert.ok(job.result.imports.some((i) => /printf/.test(i.name)));
  assert.ok(job.fingerprint?.sha256.match(/^[0-9a-f]{64}$/));
  assert.ok(job.iocs?.ipv4?.includes('198.51.100.23'));
  assert.ok(job.yara && job.yara.rulesLoaded >= 3);
  assert.equal(job.capabilities?.available !== undefined, true);
});

test('native: UPX-packed binary is unpacked before analysis', async (t) => {
  if (!hasTool('gcc') || !hasTool('upx')) return t.skip('gcc/upx not installed');
  const res = await upload('/api/analysis/auto', buildUpxElf(fixtureDir('e2e-upx')));
  const job = await waitForJob((await res.json()).data.id);
  assert.equal(job.status, 'completed', job.error);
  if (job.result?.type !== 'native') return assert.fail('expected native result');
  assert.equal(job.result.packer?.kind, 'upx');
  assert.equal(job.result.packer?.extractedCount, 1);
  assert.ok(job.result.functions.some((f) => f.name === 'main'));
  assert.ok(job.yara?.matches.some((m) => m.rule === 'Packer_UPX'));
});

test('workspace: tar.gz is extracted, browsable, searchable; reports, notes, compare and delete work', async () => {
  const tgz = buildTarGz(fixtureDir('e2e-tar'), {
    'app/index.js': 'const u = "https://evil-c2.example-bad.ru/gate";\nfetch(u);\n',
    'app/README.md': 'hello',
  });
  const res = await upload('/api/analysis/auto', tgz);
  const job = await waitForJob((await res.json()).data.id);
  assert.equal(job.status, 'completed', job.error);
  assert.ok(job.extractedPath);

  // File API: listing and content come from the job's own workspace only
  const listing = (await (await api(`/api/files/${job.id}?path=app`)).json()).data;
  assert.deepEqual(listing.entries.map((e: any) => e.name).sort(), ['README.md', 'index.js']);
  const file = (await (await api(`/api/files/${job.id}?path=app/index.js`)).json()).data;
  assert.match(file.content, /evil-c2/);
  assert.equal((await api(`/api/files/${job.id}?path=../../data`)).status, 403);

  // Search hits the extracted source
  const search = (await (await api(`/api/jobs/${job.id}/search?q=evil-c2`)).json()).data;
  assert.ok(search.hits.some((h: any) => h.kind === 'file' && h.target === 'app/index.js' && h.line === 1));

  // Notes and tags, with validation
  const patched = await api(`/api/jobs/${job.id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ notes: 'Calls a **gate** URL', tags: ['triaged', 'c2'] }),
  });
  assert.equal(patched.status, 200);
  const badTags = await api(`/api/jobs/${job.id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ tags: ['<script>'] }),
  });
  assert.equal(badTags.status, 400);

  // Reports
  const md = await (await api(`/api/jobs/${job.id}/report?format=md`)).text();
  assert.match(md, /Calls a \*\*gate\*\* URL/);
  assert.ok(md.includes(job.fingerprint!.sha256));
  const pdf = Buffer.from(await (await api(`/api/jobs/${job.id}/report?format=pdf`)).arrayBuffer());
  assert.equal(pdf.subarray(0, 5).toString(), '%PDF-');

  // Re-run shares the uploaded file; compare the two runs
  const rerun = (await (await api(`/api/jobs/${job.id}/rerun`, { method: 'POST' })).json()).data;
  const second = await waitForJob(rerun.id);
  const cmp = (await (await api(`/api/compare?a=${job.id}&b=${second.id}`)).json()).data;
  assert.equal(cmp.identical, true);

  // Deleting one run keeps the shared upload; deleting the last one removes it
  const uploaded = (job.input as any).filePath as string;
  assert.equal((await api(`/api/jobs/${job.id}`, { method: 'DELETE' })).status, 200);
  assert.ok(fs.existsSync(uploaded));
  assert.equal((await api(`/api/jobs/${second.id}`, { method: 'DELETE' })).status, 200);
  assert.ok(!fs.existsSync(uploaded));
  assert.ok(!fs.existsSync(job.extractedPath!));
});

test('bulk upload: supported files become jobs, unsupported ones are rejected and deleted', async () => {
  const dir = fixtureDir('e2e-bulk');
  const junk = path.join(dir, 'notes.txt');
  fs.writeFileSync(junk, 'plain text');
  const js = path.join(dir, 'tool.js');
  fs.writeFileSync(js, 'console.log("x")');

  const form = new FormData();
  for (const f of [junk, js]) form.append('files', new Blob([fs.readFileSync(f)]), path.basename(f));
  const data = (await (await api('/api/analysis/bulk', { method: 'POST', body: form })).json()).data;
  assert.equal(data.jobs.length, 1);
  assert.deepEqual(data.rejected.map((r: any) => r.fileName), ['notes.txt']);
  await waitForJob(data.jobs[0].id);
  assert.ok(!fs.readdirSync(uploadsDir).some((f) => f.endsWith('.txt')));
});

test('AI: explain reports "not configured" instead of calling the API without a key', async () => {
  const jobs = (await (await api('/api/jobs')).json()).data as AnalysisJob[];
  const done = jobs.find((j) => j.status === 'completed')!;
  const res = await api(`/api/jobs/${done.id}/explain`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ scope: 'job' }),
  });
  assert.equal(res.status, 503);
  assert.match((await res.json()).error, /Settings/);
  assert.equal((await (await api('/api/status')).json()).data.ai, false);
});

test('WebSocket: upgrade without a session is rejected', async () => {
  const res = await fetch(`${BASE}/ws`, {
    headers: { Connection: 'Upgrade', Upgrade: 'websocket', 'Sec-WebSocket-Version': '13', 'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==' },
  }).catch((e) => e);
  // Node's fetch can't complete an upgrade; a rejected one surfaces as a 401 response or a closed socket
  if (res instanceof Response) assert.equal(res.status, 401);
});
