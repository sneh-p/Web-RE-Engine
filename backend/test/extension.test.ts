import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'path';
import fs from 'fs';
import { runExtensionAnalysis, stripJsonComments, crxZipOffset } from '../src/services/extension.js';
import { parseStoreRef } from '../src/services/extensionStore.js';
import { detectFileType } from '../src/services/detector.js';
import { buildCrx, buildXpi, fixtureDir, maliciousExtensionFiles, benignExtensionFiles } from './fixtures.js';

async function analyze(file: string, name: string) {
  const dir = path.join(fixtureDir('ext-uploads'), name);
  fs.mkdirSync(dir, { recursive: true });
  const copy = path.join(dir, path.basename(file));
  fs.copyFileSync(file, copy);
  return runExtensionAnalysis({ type: 'extension', fileName: path.basename(file), fileSize: 0, filePath: copy }, () => {});
}

test('extension: malicious CRX3 is unpacked, scored critical, and every behaviour is found', async () => {
  const crx = buildCrx(fixtureDir('ext-bad'), maliciousExtensionFiles);
  assert.equal(detectFileType(crx, 'ext.crx'), 'extension');

  const { result: r, extractedPath } = await analyze(crx, 'bad');
  assert.ok(extractedPath && fs.existsSync(path.join(extractedPath, 'content.js')));
  assert.equal(r.packageFormat, 'crx3');
  assert.equal(r.browser, 'chrome');
  assert.equal(r.name, 'Super PDF Helper', 'i18n name resolved');
  assert.equal(r.riskLevel, 'critical');
  assert.ok(r.riskScore >= 70);

  const ids = Object.fromEntries(r.findings.map((f) => [f.id, f]));
  for (const id of ['keylogging', 'password-fields', 'cookie-access', 'remote-code-eval', 'disable-extensions', 'off-store-updates', 'open-messaging', 'obfuscated-code', 'beacon-exfil']) {
    assert.ok(ids[id], `missing finding ${id}; got ${Object.keys(ids)}`);
  }
  assert.equal(ids['keylogging'].severity, 'critical', 'keylogging on every site escalates');
  assert.deepEqual(ids['keylogging'].locations[0], { file: 'content.js', line: 1, snippet: ids['keylogging'].locations[0].snippet });

  assert.equal(r.hostPermissions.find((h) => h.name === '<all_urls>')?.risk, 'critical');
  assert.equal(r.permissions.find((p) => p.name === 'management')?.risk, 'high');
  assert.ok(r.apiUsage.some((a) => a.api === 'cookies.getAll' && a.files.includes('bg.js')));
  assert.deepEqual(r.obfuscatedFiles.map((o) => o.file), ['lib/o.js']);
  assert.ok(r.offStoreUpdates);
});

test('extension: benign Firefox XPI scores low with no findings', async () => {
  const xpi = buildXpi(fixtureDir('ext-good'), benignExtensionFiles);
  assert.equal(detectFileType(xpi, 'ext.xpi'), 'extension');
  const { result: r } = await analyze(xpi, 'good');
  assert.equal(r.browser, 'firefox');
  assert.equal(r.extensionId, 'hello-badge@example.org');
  assert.equal(r.riskLevel, 'low');
  assert.equal(r.findings.length, 0);
  assert.ok(r.limitations.some((l) => l.includes('Manifest V2')));
});

test('extension: a zipped unpacked folder is found one level down', async () => {
  const zip = buildXpi(fixtureDir('ext-folder'), benignExtensionFiles, { subfolder: 'hello-badge' });
  assert.equal(detectFileType(zip, 'ext-folder.zip'), 'extension');
  const { result: r } = await analyze(zip, 'folder');
  assert.equal(r.name, 'Hello Badge');
  assert.ok(r.limitations.some((l) => l.includes('subfolder hello-badge')));
});

test('extension: helpers parse comments, CRX headers and store links', () => {
  assert.deepEqual(JSON.parse(stripJsonComments('{ // a\n "a": "x//y", /* b */ "b": 1 }')), { a: 'x//y', b: 1 });
  const head = Buffer.alloc(16);
  head.write('Cr24', 0, 'latin1');
  head.writeUInt32LE(3, 4);
  head.writeUInt32LE(100, 8);
  assert.deepEqual(crxZipOffset(head), { format: 'crx3', offset: 112 });

  const id = 'aapbdbdomjkkjkaonfhkkikfgjllcleb';
  assert.deepEqual(parseStoreRef(`https://chromewebstore.google.com/detail/google-translate/${id}?hl=en`), { browser: 'chrome', id });
  assert.deepEqual(parseStoreRef(id), { browser: 'chrome', id });
  assert.deepEqual(parseStoreRef('https://addons.mozilla.org/en-US/firefox/addon/ublock-origin/'), { browser: 'firefox', id: 'ublock-origin' });
  assert.deepEqual(parseStoreRef('ublock-origin', 'firefox'), { browser: 'firefox', id: 'ublock-origin' });
  assert.equal(parseStoreRef('https://evil.example/detail/x/' + id), null);
  assert.equal(parseStoreRef('not-an-id'), null);
});
