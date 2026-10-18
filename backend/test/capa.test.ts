import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseCapaJson } from '../src/services/capa.js';

// Shape taken from real `capa -j` 10.0 output
const sample = {
  meta: { version: '10.0.0' },
  rules: {
    'link function at runtime on Windows': {
      meta: {
        name: 'link function at runtime on Windows',
        namespace: 'linking/runtime-linking',
        attack: [{ parts: ['Execution', 'Shared Modules'], tactic: 'Execution', technique: 'Shared Modules', subtechnique: '', id: 'T1129' }],
        mbc: [],
        lib: false,
        is_subscope_rule: false,
      },
    },
    'create process suspended': {
      meta: {
        name: 'create process suspended',
        namespace: 'host-interaction/process/create',
        attack: [],
        mbc: [{ objective: 'Process', behavior: 'Create Process', method: 'Create Suspended Process', id: 'C0017.003' }],
        lib: false,
      },
    },
    'contain loop': { meta: { name: 'contain loop', namespace: 'lib', attack: [], mbc: [], lib: true } },
  },
};

test('capa: parses capabilities with ATT&CK/MBC ids and drops library rules', () => {
  const caps = parseCapaJson(JSON.stringify(sample));
  assert.deepEqual(
    caps.map((c) => c.name),
    ['create process suspended', 'link function at runtime on Windows']
  );
  assert.deepEqual(caps[1].attack, ['T1129 Shared Modules']);
  assert.deepEqual(caps[0].mbc, ['C0017.003 Process::Create Process::Create Suspended Process']);
});

import fs from 'fs';
import path from 'path';
import { planCapa } from '../src/services/capa.js';
import { fixtureDir } from './fixtures.js';

test('capa plan: installers use the main program inside, PyInstaller and oversized files are skipped', () => {
  const dir = fixtureDir('capa-plan');
  const installer = path.join(dir, 'setup.exe');
  fs.writeFileSync(installer, Buffer.concat([Buffer.from('MZ'), Buffer.alloc(1000)]));
  const unpacked = path.join(dir, 'unpacked');
  fs.mkdirSync(path.join(unpacked, 'app'), { recursive: true });
  fs.writeFileSync(path.join(unpacked, 'app/Main App.exe'), Buffer.concat([Buffer.from('MZ'), Buffer.alloc(5000)]));
  fs.writeFileSync(path.join(unpacked, 'app/bigger-helper.dll'), Buffer.concat([Buffer.from('MZ'), Buffer.alloc(9000)]));
  fs.writeFileSync(path.join(unpacked, 'app/readme.txt'), 'not a program');

  assert.equal(planCapa(installer, 'inno', unpacked).label, 'app/Main App.exe', '.exe preferred over a larger DLL');
  assert.match(planCapa(installer, 'pyinstaller', unpacked).skipped!, /PyInstaller/);
  assert.equal(planCapa(installer, undefined, undefined).label, 'setup.exe');

  const huge = path.join(dir, 'huge.exe');
  fs.writeFileSync(huge, 'MZ');
  fs.truncateSync(huge, 25 * 1024 * 1024);
  assert.match(planCapa(huge, undefined, undefined).skipped!, /limited to 24 MB/);
});
