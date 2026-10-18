import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { execFile } from 'child_process';
import { promisify } from 'util';
import type { YaraMatch, YaraResult } from '../../../shared/types.js';
import { runTool } from './sandbox.js';

const execFileAsync = promisify(execFile);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const rulesDir = path.resolve(__dirname, '../../rules');

const MAX_MATCHES = 300;
const MAX_STRINGS_PER_MATCH = 10;
const MAX_STRING_DATA = 120;

let yaraAvailable: boolean | null = null;

export async function isYaraAvailable(): Promise<boolean> {
  if (yaraAvailable !== null) return yaraAvailable;
  try {
    await execFileAsync('yara', ['--version'], { timeout: 5000 });
    yaraAvailable = true;
  } catch {
    yaraAvailable = false;
  }
  return yaraAvailable;
}

function listRuleFiles(): string[] {
  const files: string[] = [];
  for (const sub of ['builtin', 'custom']) {
    const dir = path.join(rulesDir, sub);
    if (!fs.existsSync(dir)) continue;
    for (const name of fs.readdirSync(dir).sort()) {
      if (/\.(yar|yara)$/i.test(name)) files.push(path.join(dir, name));
    }
  }
  return files;
}

// A broken custom rule file must not disable every other rule, so check each one alone
async function compilableRuleFiles(errors: string[]): Promise<string[]> {
  const ok: string[] = [];
  for (const file of listRuleFiles()) {
    try {
      await execFileAsync('yara', ['-w', file, '/dev/null'], { timeout: 15000 });
      ok.push(file);
    } catch (err: any) {
      const detail = String(err.stderr || err.message || '').split('\n')[0];
      errors.push(`Skipped rule file ${path.relative(rulesDir, file)}: ${detail}`);
    }
  }
  return ok;
}

// yara -m -s output:
//   RuleName [key="value",key2="value"] /path/to/file
//   0x1a2b:$id: matched data
function parseYaraOutput(stdout: string, displayPath: (p: string) => string): YaraMatch[] {
  const matches: YaraMatch[] = [];
  let current: YaraMatch | null = null;

  for (const line of stdout.split('\n')) {
    if (!line.trim()) continue;
    const str = line.match(/^0x([0-9a-f]+):(\$[\w]*):\s?(.*)$/i);
    if (str && current) {
      if (current.strings.length < MAX_STRINGS_PER_MATCH) {
        current.strings.push({
          offset: parseInt(str[1], 16),
          identifier: str[2],
          data: str[3].slice(0, MAX_STRING_DATA),
        });
      }
      continue;
    }

    const head = line.match(/^(\w+)\s+\[(.*)\]\s+(\/.+)$/);
    if (head) {
      const meta: Record<string, string> = {};
      for (const m of head[2].matchAll(/(\w+)=(?:"((?:[^"\\]|\\.)*)"|([^,]+))/g)) {
        meta[m[1]] = (m[2] ?? m[3] ?? '').replace(/\\(.)/g, '$1');
      }
      current = { rule: head[1], meta, file: displayPath(head[3]), strings: [] };
      if (matches.length < MAX_MATCHES) matches.push(current);
    }
  }
  return matches;
}

export async function runYaraScan(
  filePath: string,
  fileName: string,
  extractedPath?: string
): Promise<YaraResult> {
  const errors: string[] = [];
  if (!(await isYaraAvailable())) {
    return { matches: [], rulesLoaded: 0, errors: ['yara is not installed'] };
  }

  const ruleFiles = await compilableRuleFiles(errors);
  if (ruleFiles.length === 0) {
    return { matches: [], rulesLoaded: 0, errors: [...errors, 'No YARA rule files found'] };
  }

  const targets: { target: string; display: (p: string) => string; recursive: boolean }[] = [
    { target: filePath, display: () => fileName, recursive: false },
  ];
  if (extractedPath && fs.existsSync(extractedPath)) {
    targets.push({
      target: extractedPath,
      display: (p) => path.relative(extractedPath, p) || path.basename(p),
      recursive: true,
    });
  }

  const matches: YaraMatch[] = [];
  for (const t of targets) {
    // -N: never follow symlinks; -a: per-scan timeout in seconds
    const args = ['-w', '-m', '-s', '-N', '-a', '100', ...(t.recursive ? ['-r'] : []), ...ruleFiles, t.target];
    try {
      const { stdout } = await runTool('yara', args, {
        readPaths: [rulesDir, t.target],
        timeoutMs: 120_000,
        maxBuffer: 50 * 1024 * 1024,
      });
      matches.push(...parseYaraOutput(stdout, t.display));
    } catch (err: any) {
      // yara exits non-zero on scan timeouts/unreadable files but may still have printed matches
      if (err.stdout) matches.push(...parseYaraOutput(String(err.stdout), t.display));
      errors.push(`YARA scan of ${t.recursive ? 'extracted files' : 'uploaded file'} incomplete: ${String(err.stderr || err.message).split('\n')[0]}`);
    }
  }

  return { matches: matches.slice(0, MAX_MATCHES), rulesLoaded: ruleFiles.length, errors };
}
