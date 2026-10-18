import fs from 'fs';
import path from 'path';
import zlib from 'zlib';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { createRequire } from 'module';
import { runTool } from './sandbox.js';
import { MAX_ENTRY_BYTES, MAX_EXTRACTED_FILES, MAX_TOTAL_BYTES } from './archive.js';

const execFileAsync = promisify(execFile);
const require = createRequire(import.meta.url);
// Generated from Python 3.13's sys.stdlib_module_names, plus modules added in 3.14
const STDLIB = new Set<string>([
  ...require('./python-stdlib.json'),
  'annotationlib',
  'compression',
  '_ast_unparse',
  '_py_warnings',
  '_pyrepl',
  '_colorize',
  '_zstd',
]);

const MAX_DECOMPILE = 200;

// ---- Minimal Python marshal reader (enough for PyInstaller PYZ tables of contents) ----

type MarshalValue = null | boolean | number | bigint | string | Buffer | MarshalValue[] | Map<MarshalValue, MarshalValue>;

class MarshalReader {
  private pos = 0;
  private refs: MarshalValue[] = [];

  constructor(private buf: Buffer) {}

  private u8() {
    if (this.pos >= this.buf.length) throw new Error('marshal: unexpected end of data');
    return this.buf[this.pos++];
  }
  private i32() {
    const v = this.buf.readInt32LE(this.pos);
    this.pos += 4;
    return v;
  }
  private bytes(n: number) {
    if (n < 0 || this.pos + n > this.buf.length) throw new Error('marshal: bad length');
    const b = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return b;
  }

  read(): MarshalValue {
    const code = this.u8();
    const flag = (code & 0x80) !== 0;
    const type = String.fromCharCode(code & 0x7f);
    // Containers must reserve their ref slot before reading children
    const slot = flag ? this.refs.push(null) - 1 : -1;
    const keep = (v: MarshalValue) => {
      if (slot >= 0) this.refs[slot] = v;
      return v;
    };

    switch (type) {
      case 'N':
        return keep(null);
      case 'F':
        return keep(false);
      case 'T':
        return keep(true);
      case 'i':
        return keep(this.i32());
      case 'l': {
        // Arbitrary-precision int: signed digit count, then 15-bit digits, least significant first
        const n = this.i32();
        let value = 0n;
        for (let i = 0; i < Math.abs(n); i++) value |= BigInt(this.bytes(2).readUInt16LE(0)) << BigInt(15 * i);
        return keep(n < 0 ? -value : value);
      }
      case 's':
        return keep(Buffer.from(this.bytes(this.i32())));
      case 'u':
      case 't':
        return keep(this.bytes(this.i32()).toString('utf8'));
      case 'a':
      case 'A':
        return keep(this.bytes(this.i32()).toString('latin1'));
      case 'z':
      case 'Z':
        return keep(this.bytes(this.u8()).toString('latin1'));
      case '(':
      case '[':
      case '<':
      case '>': {
        const n = this.i32();
        if (n < 0 || n > 10_000_000) throw new Error('marshal: bad container size');
        const arr: MarshalValue[] = [];
        keep(arr);
        for (let i = 0; i < n; i++) arr.push(this.read());
        return arr;
      }
      case ')': {
        const n = this.u8();
        const arr: MarshalValue[] = [];
        keep(arr);
        for (let i = 0; i < n; i++) arr.push(this.read());
        return arr;
      }
      case '{': {
        const map = new Map<MarshalValue, MarshalValue>();
        keep(map);
        while (this.buf[this.pos] !== '0'.charCodeAt(0)) {
          const k = this.read();
          map.set(k, this.read());
        }
        this.pos++;
        return map;
      }
      case 'r': {
        const idx = this.i32();
        if (idx < 0 || idx >= this.refs.length) throw new Error('marshal: bad reference');
        return this.refs[idx];
      }
      default:
        throw new Error(`marshal: unsupported type '${type}' at offset ${this.pos - 1}`);
    }
  }
}

// ---- PYZ extraction ----

export interface PyzModule {
  name: string;
  isPackage: boolean;
  file: string;
}

export interface PyzResult {
  modules: PyzModule[];
  pycMagic: Buffer;
  limitations: string[];
}

const safeModuleName = (name: string) => name.split('.').every((seg) => /^[A-Za-z0-9_\-]+$/.test(seg));

// 16-byte header for Python 3.7+: magic, flags, then 8 bytes of (mtime, size) we leave zero
export function pycHeader(magic: Buffer): Buffer {
  return Buffer.concat([magic, Buffer.alloc(12)]);
}

export function extractPyz(pyzPath: string, outDir: string): PyzResult {
  const limitations: string[] = [];
  const data = fs.readFileSync(pyzPath);
  if (data.subarray(0, 4).toString('latin1') !== 'PYZ\0') throw new Error('Not a PYZ archive');

  const pycMagic = Buffer.from(data.subarray(4, 8));
  const tocOffset = data.readInt32BE(8);
  if (tocOffset <= 12 || tocOffset >= data.length) throw new Error('Bad PYZ table-of-contents offset');

  const toc = new MarshalReader(data.subarray(tocOffset)).read();
  // Older PyInstaller stores a dict, newer a list of (name, (typecode, offset, length)) pairs
  const entries: [MarshalValue, MarshalValue][] = toc instanceof Map ? [...toc.entries()] : Array.isArray(toc) ? (toc as any) : [];

  const modules: PyzModule[] = [];
  let total = 0;
  for (const entry of entries) {
    const [name, info] = entry as [MarshalValue, MarshalValue];
    if (typeof name !== 'string' || !Array.isArray(info) || info.length < 3) continue;
    const [typeCode, offset, length] = info.map(Number);
    // 0 = module, 1 = package, 2 = data, 3 = namespace package
    if (typeCode !== 0 && typeCode !== 1) continue;
    if (!safeModuleName(name)) {
      if (!limitations.some((l) => l.startsWith('Skipped modules with unsafe names'))) limitations.push(`Skipped modules with unsafe names (e.g. "${name}")`);
      continue;
    }
    if (modules.length >= MAX_EXTRACTED_FILES) {
      limitations.push(`PYZ extraction capped at ${MAX_EXTRACTED_FILES} modules`);
      break;
    }
    if (offset < 12 || offset + length > data.length) continue;

    let code: Buffer;
    try {
      code = zlib.inflateSync(data.subarray(offset, offset + length), { maxOutputLength: MAX_ENTRY_BYTES });
    } catch {
      continue;
    }
    if (total + code.length > MAX_TOTAL_BYTES) {
      limitations.push('PYZ extraction capped at 500MB total written');
      break;
    }

    const parts = name.split('.');
    const rel = typeCode === 1 ? path.join(...parts, '__init__.pyc') : path.join(...parts.slice(0, -1), `${parts[parts.length - 1]}.pyc`);
    const dest = path.join(outDir, rel);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, Buffer.concat([pycHeader(pycMagic), code]));
    total += code.length;
    modules.push({ name, isPackage: typeCode === 1, file: dest });
  }

  return { modules, pycMagic, limitations };
}

export const isStdlibModule = (name: string) => STDLIB.has(name.split('.')[0]);

// ---- Optional decompilation with pycdc / pycdas ----

let pycdcTools: { pycdc: boolean; pycdas: boolean } | null = null;

async function detectPycdc() {
  if (pycdcTools) return pycdcTools;
  const has = async (cmd: string) => {
    try {
      await execFileAsync('which', [cmd], { timeout: 3000 });
      return true;
    } catch {
      return false;
    }
  };
  pycdcTools = { pycdc: await has('pycdc'), pycdas: await has('pycdas') };
  return pycdcTools;
}

export interface DecompileSummary {
  tool: 'pycdc' | 'pycdas' | 'none';
  decompiled: number;
  disassembled: number;
  failed: number;
}

// Writes <file>.py (pycdc) or <file>.pycdas.txt (pycdas) next to each .pyc
export async function decompilePycFiles(files: string[], limitations: string[]): Promise<DecompileSummary> {
  const tools = await detectPycdc();
  const summary: DecompileSummary = { tool: tools.pycdc ? 'pycdc' : tools.pycdas ? 'pycdas' : 'none', decompiled: 0, disassembled: 0, failed: 0 };
  if (summary.tool === 'none') {
    limitations.push('Python bytecode was extracted as .pyc but not decompiled: pycdc/pycdas are not installed.');
    return summary;
  }

  const targets = files.slice(0, MAX_DECOMPILE);
  if (files.length > MAX_DECOMPILE) limitations.push(`Decompiled the first ${MAX_DECOMPILE} of ${files.length} Python modules.`);

  // pycdc rejects bytecode from Python versions it doesn't know yet with "Bad MAGIC"
  const unsupported = (out: string) => /Bad MAGIC|Unsupported (Python|bytecode) version/i.test(out);
  let versionUnsupported = false;

  for (const file of targets) {
    const opts = { readPaths: [file], timeoutMs: 20_000, maxBuffer: 20 * 1024 * 1024 };
    if (tools.pycdc) {
      try {
        const { stdout, stderr } = await runTool('pycdc', [file], opts);
        if (unsupported(stdout + stderr)) {
          versionUnsupported = true;
          break;
        }
        if (stdout.trim()) {
          fs.writeFileSync(file.replace(/\.pyc$/, '.py'), stdout);
          summary.decompiled++;
          continue;
        }
      } catch (err: any) {
        if (unsupported(String(err.stdout ?? '') + String(err.stderr ?? ''))) {
          versionUnsupported = true;
          break;
        }
        // otherwise fall through to disassembly: pycdc gives up on some constructs it can still disassemble
      }
    }
    if (tools.pycdas) {
      try {
        const { stdout } = await runTool('pycdas', [file], opts);
        if (unsupported(stdout)) {
          versionUnsupported = true;
          break;
        }
        fs.writeFileSync(file.replace(/\.pyc$/, '.pycdas.txt'), stdout);
        summary.disassembled++;
        continue;
      } catch {
        // counted below
      }
    }
    summary.failed++;
  }

  if (versionUnsupported) {
    limitations.push(
      'pycdc does not support this Python version yet, so the bytecode was not decompiled. The modules are available as .pyc files, and the strings of the entry-point scripts are in *.strings.txt.'
    );
    if (summary.decompiled === 0 && summary.disassembled === 0) summary.tool = 'none';
  }
  if (summary.failed > 0) {
    limitations.push(`${summary.failed} Python modules could not be decompiled (pycdc may not support this Python version).`);
  }
  return summary;
}
