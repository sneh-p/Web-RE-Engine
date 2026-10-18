import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import { execFileSync } from 'child_process';
import { extractAsar, extractTar, extractWith7z } from '../src/services/archive.js';
import { extractPyz, isStdlibModule } from '../src/services/pyz.js';
import { buildAsar, buildPyz, buildTarGz, buildZip, fixtureDir } from './fixtures.js';

const listFiles = (dir: string) =>
  fs.existsSync(dir) ? fs.readdirSync(dir, { recursive: true, withFileTypes: true }).filter((e) => !e.isDirectory()) : [];

test('asar: extracts nested files, skips links, unpacked entries and ".." names', () => {
  const dir = fixtureDir('asar');
  const out = path.join(dir, 'out');
  const res = extractAsar(buildAsar(dir), out);
  assert.equal(res.extractedCount, 2);
  assert.equal(fs.readFileSync(path.join(out, 'lib/util.js'), 'utf8'), 'module.exports = "https://updates.example-c2.net/check"\n');
  assert.ok(res.limitations.some((l) => l.includes('unsafe names')));
  assert.ok(res.limitations.some((l) => l.includes('app.asar.unpacked')));
  assert.ok(!fs.existsSync(path.join(dir, 'lnk')));
});

test('tar: extracts a normal archive', async () => {
  const dir = fixtureDir('tar-good');
  const out = path.join(dir, 'out');
  const res = await extractTar(buildTarGz(dir, { 'app/index.js': 'require("./x")', 'app/x.js': '1' }), out);
  assert.equal(res.extractedCount, 2);
  assert.ok(fs.existsSync(path.join(out, 'app/index.js')));
});

test('tar: refuses entries escaping with ".."', async () => {
  const dir = fixtureDir('tar-dotdot');
  const res = await extractTar(buildTarGz(dir, { 'ok.js': '1' }, { evil: 'dotdot' }), path.join(dir, 'out'));
  assert.equal(res.extractedCount, 0);
  assert.ok(res.limitations[0].includes('escapes the target directory'));
  assert.ok(!fs.existsSync(path.join(dir, 'escaped.js')));
});

test('tar: refuses symlinks', async () => {
  const dir = fixtureDir('tar-link');
  const res = await extractTar(buildTarGz(dir, { 'ok.js': '1' }, { evil: 'symlink' }), path.join(dir, 'out'));
  assert.equal(res.extractedCount, 0);
  assert.ok(res.limitations[0].includes('link or special file'));
});

test('zip: never leaves a symlink on disk', async () => {
  const dir = fixtureDir('zip-link');
  const out = path.join(dir, 'out');
  await extractWith7z(buildZip(dir, 'link.zip', { 'a.js': '1' }, { symlink: true }), out);
  assert.ok(listFiles(out).every((e) => !e.isSymbolicLink()));
  assert.ok(fs.existsSync(path.join(out, 'a.js')));
});

test('zip: a decompression bomb is rejected from its listing before extraction', async () => {
  const dir = fixtureDir('zip-bomb');
  const out = path.join(dir, 'out');
  const res = await extractWith7z(buildZip(dir, 'bomb.zip', {}, { bigZeroesMb: 210 }), out);
  assert.equal(res.extractedCount, 0);
  assert.ok(res.limitations[0].startsWith('Extraction skipped'));
  assert.equal(listFiles(out).length, 0);
});

test('pyz: reads a real Python-marshalled TOC and writes loadable .pyc files', () => {
  const dir = fixtureDir('pyz');
  const out = path.join(dir, 'out');
  const res = extractPyz(buildPyz(dir), out);
  assert.deepEqual(res.modules.map((m) => m.name).sort(), ['evilpkg', 'evilpkg.beacon', 'json']);
  assert.ok(fs.existsSync(path.join(out, 'evilpkg/__init__.pyc')));

  // The .pyc must round-trip through this machine's Python
  const pyc = path.join(out, 'evilpkg/beacon.pyc');
  const consts = execFileSync('python3', [
    '-I',
    '-c',
    'import sys,marshal,importlib.util;d=open(sys.argv[1],"rb").read();assert d[:4]==importlib.util.MAGIC_NUMBER;print(marshal.loads(d[16:]).co_consts)',
    pyc,
  ]).toString();
  assert.match(consts, /203\.0\.113\.9/);

  assert.equal(isStdlibModule('json'), true);
  assert.equal(isStdlibModule('evilpkg.beacon'), false);
});
