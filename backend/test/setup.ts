// Loaded with --import before any test file, so every module that opens the
// database or uploads folder sees throwaway locations instead of the real ones.
import fs from 'fs';
import os from 'os';
import path from 'path';

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'web-re-test-'));
process.env.WEB_RE_DATA_DIR = path.join(root, 'data');
process.env.WEB_RE_UPLOADS_DIR = path.join(root, 'uploads');
process.env.WEB_RE_TEST_ROOT = root;
fs.mkdirSync(process.env.WEB_RE_UPLOADS_DIR, { recursive: true });

const real = path.resolve(import.meta.dirname, '..');
for (const dir of [process.env.WEB_RE_DATA_DIR, process.env.WEB_RE_UPLOADS_DIR]) {
  if (path.resolve(dir).startsWith(real)) throw new Error(`Refusing to run tests against ${dir}`);
}

// AI tests must never spend money or depend on a key being present
delete process.env.ANTHROPIC_API_KEY;
delete process.env.ANTHROPIC_AUTH_TOKEN;

process.on('exit', () => fs.rmSync(root, { recursive: true, force: true }));
