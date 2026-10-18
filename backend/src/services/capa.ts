import fs from 'fs';
import path from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';
import type { CapaCapability, CapaResult } from '../../../shared/types.js';
import { runTool } from './sandbox.js';

const execFileAsync = promisify(execFile);

let capaAvailable: boolean | null = null;
let checkedAt = 0;

// A negative result is re-checked after 5 minutes, so installing capa doesn't need a restart
export async function isCapaAvailable(): Promise<boolean> {
  if (capaAvailable === true || (capaAvailable === false && Date.now() - checkedAt < 5 * 60_000)) return capaAvailable;
  try {
    await execFileAsync('capa', ['--version'], { timeout: 15000 });
    capaAvailable = true;
  } catch {
    capaAvailable = false;
  }
  checkedAt = Date.now();
  return capaAvailable;
}

// capa -j output: { rules: { "<rule name>": { meta: { name, namespace, attack: [...], mbc: [...] } } } }
export function parseCapaJson(raw: string): CapaCapability[] {
  const doc = JSON.parse(raw);
  const rules = doc?.rules && typeof doc.rules === 'object' ? doc.rules : {};
  const caps: CapaCapability[] = [];

  for (const [ruleName, rule] of Object.entries<any>(rules)) {
    const meta = rule?.meta ?? {};
    // Library rules are building blocks for other rules, not findings
    if (meta.lib === true || meta.is_subscope_rule === true) continue;

    caps.push({
      name: meta.name || ruleName,
      namespace: meta.namespace,
      attack: (meta.attack ?? []).map((a: any) =>
        [a.id, [a.technique, a.subtechnique].filter(Boolean).join('::')].filter(Boolean).join(' ')
      ),
      mbc: (meta.mbc ?? []).map((m: any) =>
        [m.id, [m.objective, m.behavior, m.method].filter(Boolean).join('::')].filter(Boolean).join(' ')
      ),
    });
  }
  return caps.sort((a, b) => (a.namespace ?? '').localeCompare(b.namespace ?? '') || a.name.localeCompare(b.name));
}

// capa's memory and time grow steeply with code size: a 34 MB program needed over 2 GB and 8+ minutes.
// Defaults suit a 4 GB server; raise them on bigger machines.
const envNumber = (name: string, fallback: number) => {
  const v = Number(process.env[name]);
  return Number.isFinite(v) && v > 0 ? v : fallback;
};
export const CAPA_MAX_BYTES = envNumber('WEB_RE_CAPA_MAX_MB', 24) * 1024 * 1024;
const CAPA_MEMORY_MB = envNumber('WEB_RE_CAPA_MEMORY_MB', 3072);
const CAPA_TIMEOUT_MS = envNumber('WEB_RE_CAPA_TIMEOUT_MIN', 15) * 60_000;

export async function runCapa(filePath: string): Promise<CapaResult> {
  if (!(await isCapaAvailable())) {
    return { available: false, capabilities: [] };
  }
  try {
    const { stdout } = await runTool('capa', ['-j', '-q', filePath], {
      readPaths: [filePath],
      // Large PE files (e.g. PyInstaller bootloaders) take several minutes and ~1 GB
      timeoutMs: CAPA_TIMEOUT_MS,
      memoryMaxMB: CAPA_MEMORY_MB,
      maxBuffer: 100 * 1024 * 1024,
    });
    return { available: true, capabilities: parseCapaJson(stdout) };
  } catch (err: any) {
    // Both kinds of kill report only the command line, which says nothing useful.
    // Our timeout sends SIGTERM (err.killed); the kernel OOM killer inside the systemd scope sends SIGKILL.
    if (err.killed) {
      return { available: true, capabilities: [], error: `capa did not finish within ${CAPA_TIMEOUT_MS / 60_000} minutes on this file and was stopped.` };
    }
    if (err.signal === 'SIGKILL') {
      return {
        available: true,
        capabilities: [],
        error: `capa ran out of memory (limit ${(CAPA_MEMORY_MB / 1024).toFixed(1)} GB) on this file. Raise WEB_RE_CAPA_MEMORY_MB on a server with more RAM.`,
      };
    }
    const detail = String(err.stderr || '').split('\n').filter(Boolean).pop();
    return { available: true, capabilities: [], error: `capa failed${detail ? `: ${detail}` : ` (exit code ${err.code ?? 'unknown'})`}` };
  }
}

// One capa run at a time: each can use a gigabyte of memory
let capaChain: Promise<unknown> = Promise.resolve();

export function queueCapa(filePath: string): Promise<CapaResult> {
  const run = capaChain.then(() => runCapa(filePath));
  capaChain = run.catch(() => undefined);
  return run;
}

const isExecutable = (file: string): boolean => {
  try {
    const fd = fs.openSync(file, 'r');
    const head = Buffer.alloc(4);
    fs.readSync(fd, head, 0, 4, 0);
    fs.closeSync(fd);
    return (head[0] === 0x4d && head[1] === 0x5a) || head.toString('latin1') === '\x7fELF';
  } catch {
    return false;
  }
};

// Programs inside an unpacked installer: .exe files before libraries, then largest first
// (the main application is usually the biggest .exe)
function executablesIn(dir: string): string[] {
  const found: { file: string; size: number }[] = [];
  const walk = (d: string, depth: number) => {
    if (depth > 8 || found.length > 500) return;
    for (const ent of fs.readdirSync(d, { withFileTypes: true })) {
      const abs = path.join(d, ent.name);
      if (ent.isDirectory()) walk(abs, depth + 1);
      else if (ent.isFile() && /\.(exe|dll|sys|so|bin)$|^[^.]+$/i.test(ent.name) && isExecutable(abs)) {
        found.push({ file: abs, size: fs.statSync(abs).size });
      }
    }
  };
  walk(dir, 0);
  const isProgram = (f: string) => /\.exe$|^[^.]+$/i.test(path.basename(f));
  return found.sort((a, b) => Number(isProgram(b.file)) - Number(isProgram(a.file)) || b.size - a.size).map((f) => f.file);
}

export interface CapaPlan {
  target?: string;
  // Shown to the user, relative to the job workspace when inside it
  label?: string;
  skipped?: string;
}

// Decide which file capa should look at for a native job
export function planCapa(inputPath: string, packerKind: string | undefined, extractedPath: string | undefined): CapaPlan {
  const tooBig = (f: string) => fs.statSync(f).size > CAPA_MAX_BYTES;
  const mb = (f: string) => `${(fs.statSync(f).size / 1048576).toFixed(0)} MB`;
  const limit = `${CAPA_MAX_BYTES / 1048576} MB`;

  if (packerKind === 'pyinstaller') {
    return { skipped: 'This is a PyInstaller app: the executable is only the Python bootloader, and capa cannot analyze Python code. See the extracted modules instead.' };
  }
  if (packerKind && ['inno', 'nsis', 'sfx-7z', 'sfx-zip', 'upx'].includes(packerKind) && extractedPath && fs.existsSync(extractedPath)) {
    // Analyze the main program or nothing: capa on some small helper DLL would misrepresent the app
    const main = executablesIn(extractedPath)[0];
    if (main && !tooBig(main)) return { target: main, label: path.relative(extractedPath, main) };
    if (main) {
      return {
        skipped: `The main program ${path.relative(extractedPath, main)} is ${mb(main)}; capa is limited to ${limit} (WEB_RE_CAPA_MAX_MB) because larger programs need more memory and time than this server allows.`,
      };
    }
    if (packerKind !== 'upx') return { skipped: 'No executable was found inside the installer.' };
  }
  if (tooBig(inputPath)) {
    return { skipped: `The file is ${mb(inputPath)}; capa is limited to ${limit} (WEB_RE_CAPA_MAX_MB) because larger programs need more memory and time than this server allows.` };
  }
  return { target: inputPath, label: path.basename(inputPath) };
}
