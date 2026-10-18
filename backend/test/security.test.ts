import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import { isBlockedIp } from '../src/services/ssrf.js';
import { renderSafeMarkdown } from '../src/lib/markdown.js';
import { createIocCollector, extractIocsFromText } from '../src/services/ioc.js';
import { detectFileType } from '../src/services/detector.js';
import { runYaraScan, isYaraAvailable } from '../src/services/yara.js';
import { buildMarkdownReport } from '../src/services/report.js';
import { fixtureDir, buildHelloElf } from './fixtures.js';
import type { AnalysisJob } from '../../shared/types.js';

test('SSRF: private, loopback, link-local and mapped addresses are blocked', () => {
  for (const ip of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.40.61', '169.254.169.254', '0.0.0.0', '::1', 'fe80::1', 'fd00::5', '::ffff:10.0.0.1']) {
    assert.equal(isBlockedIp(ip), true, ip);
  }
  for (const ip of ['8.8.8.8', '93.184.216.34', '2606:4700::1111']) {
    assert.equal(isBlockedIp(ip), false, ip);
  }
});

test('Markdown: raw HTML, script URLs and images never become markup', () => {
  // Literal text like "javascript:" is harmless; what must never appear is real markup
  const noMarkup = (html: string) => !/<(script|img|iframe|div)\b|href="(?!https?:)/i.test(html);
  for (const input of [
    '<script>alert(1)</script>',
    'text <img src=x onerror=alert(1)> inline',
    '<div onclick="x">block\n\nhtml</div>',
    'see [x](javascript:alert(1)) here',
    'image ![i](https://e/x.png) here',
  ]) {
    const html = renderSafeMarkdown(input);
    assert.ok(noMarkup(html), `${input} -> ${html}`);
  }
  assert.ok(renderSafeMarkdown('[ok](https://example.org)').includes('<a href="https://example.org"'));
});

test('Reports wrap sample-controlled names so they cannot inject markup', () => {
  const job = {
    id: 'j1',
    type: 'native',
    status: 'completed',
    createdAt: 'now',
    updatedAt: 'now',
    input: { type: 'native', fileName: 'evil`</code><script>x</script>.exe', fileSize: 1 },
  } as unknown as AnalysisJob;
  const html = renderSafeMarkdown(buildMarkdownReport(job));
  assert.ok(!html.includes('<script>'));
});

test('IOCs: version numbers and code references are not reported as IPs/domains', () => {
  const c = createIocCollector();
  extractIocsFromText('FileVersion 1.0.0.0 v2.96.2.1 this.id java.io com.phonegap.app call 45.33.32.156 at evil-c2.ru', c);
  assert.deepEqual([...c.ipv4], ['45.33.32.156']);
  assert.ok(c.domains.has('evil-c2.ru'));
  assert.ok(!c.domains.has('this.id') && !c.domains.has('java.io') && !c.domains.has('com.phonegap.app'));
});

test('Detector: recognizes ELF, tar archives and rejects unknown data', () => {
  const dir = fixtureDir('detector');
  assert.equal(detectFileType(buildHelloElf(dir), 'hello'), 'native');
  const junk = path.join(dir, 'junk.bin');
  fs.writeFileSync(junk, Buffer.from('just some text, nothing executable'));
  assert.equal(detectFileType(junk, 'junk.bin'), null);
  const tgz = path.join(dir, 'x.tar.gz');
  fs.writeFileSync(tgz, Buffer.from([0x1f, 0x8b, 8, 0]));
  assert.equal(detectFileType(tgz, 'x.tar.gz'), 'javascript');
});

test('YARA: built-in rules flag injection APIs and encoded PowerShell, not innocent text', async (t) => {
  if (!(await isYaraAvailable())) return t.skip('yara not installed');
  const dir = fixtureDir('yara');
  const bad = path.join(dir, 'bad.bin');
  fs.writeFileSync(
    bad,
    'VirtualAllocEx WriteProcessMemory CreateRemoteThread\n' + 'cmd /c powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA\n'
  );
  const good = path.join(dir, 'good.txt');
  fs.writeFileSync(good, 'PowerShell documentation: use -Encoding utf8 to write files.\n');

  const badRules = (await runYaraScan(bad, 'bad.bin')).matches.map((m) => m.rule);
  assert.ok(badRules.includes('Capability_Process_Injection'), badRules.join());
  assert.ok(badRules.includes('Capability_PowerShell_Encoded'), badRules.join());

  const goodRes = await runYaraScan(good, 'good.txt');
  assert.equal(goodRes.matches.length, 0, goodRes.matches.map((m) => m.rule).join());
  assert.ok(goodRes.rulesLoaded >= 3);
});
