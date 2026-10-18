import { execFile } from 'child_process';
import { promisify } from 'util';
import path from 'path';
import fs from 'fs';
import type {
  NativeInput,
  NativeResult,
  NativeFunction,
  DisassemblyLine,
  BinarySection,
  Evidence,
  FileTreeNode,
  NativeImport,
  NativeExport,
  PackerInfo,
} from '../../../shared/types.js';

import { calculateBufferEntropy } from './fingerprint.js';
import { detectPacker } from './packer.js';
import { extractPyInstaller } from './pyinstaller.js';
import { buildFileTree } from './fileTree.js';
import { runTool } from './sandbox.js';
import { extractWith7z, extractInno, type ExtractResult } from './archive.js';
import { extractPyz, pycHeader, isStdlibModule, decompilePycFiles, type PyzModule } from './pyz.js';

const execFileAsync = promisify(execFile);
type ProgressCallback = (msg: string, pct?: number) => void;

export async function runNativeAnalysis(
  input: NativeInput,
  onProgress: ProgressCallback
): Promise<{ result: NativeResult; fileTree?: FileTreeNode[]; extractedPath?: string }> {
  onProgress('Reading binary file...', 10);

  if (!input.filePath || !fs.existsSync(input.filePath)) {
    throw new Error(`File not found: ${input.filePath}`);
  }

  const fileBuffer = fs.readFileSync(input.filePath);
  const format = detectBinaryFormat(fileBuffer);
  const architecture = detectArchitecture(fileBuffer, format);

  onProgress(`Detected ${format} binary (${architecture})`, 20);

  let result: NativeResult;

  // If ELF/PE and objdump/readelf/r2 are available, extract full functions & disassembly
  if (format === 'ELF' || format === 'PE' || format === 'Mach-O') {
    onProgress('Analyzing binary with radare2 & binutils decompiler engine...', 30);
    try {
      const r2Available = await checkCommand('r2', '-v');
      if (r2Available) {
        onProgress('Performing deep control-flow & procedure analysis (r2)...', 40);
        result = await disassembleBinaryWithR2(input.filePath, format, architecture, fileBuffer, onProgress);
      } else {
        result = await disassembleBinaryWithBinutils(input.filePath, format as any, architecture, fileBuffer, onProgress);
      }
    } catch (e: any) {
      onProgress(`Decompilation warning: ${e.message}, falling back to binutils...`, 50);
      try {
        result = await disassembleBinaryWithBinutils(input.filePath, format as any, architecture, fileBuffer, onProgress);
      } catch {
        result = basicBinaryAnalysis(input, fileBuffer, format, architecture);
      }
    }
  } else {
    result = basicBinaryAnalysis(input, fileBuffer, format, architecture);
  }

  // Enrich PE sections if none were discovered
  if (result.sections.length === 0 && format === 'PE') {
    result.sections = parsePESections(fileBuffer);
  }

  // Compute per-section entropy where missing
  for (const s of result.sections) {
    if (s.entropy === undefined && s.offset !== undefined && s.size > 0 && s.offset + s.size <= fileBuffer.length) {
      s.entropy = calculateBufferEntropy(fileBuffer.subarray(s.offset, s.offset + s.size));
    }
  }

  // Populate callers reciprocal to callees
  populateCallers(result.functions);

  // Check packed / encrypted criteria
  checkPackedEvidence(result, fileBuffer);

  // Automatic packer detection & unpacking
  onProgress('Inspecting executable container & packer signatures...', 92);
  let fileTree: FileTreeNode[] | undefined;
  let extractedPath: string | undefined;

  try {
    const packer = await detectPacker(input.filePath);
    if (packer.kind !== 'none') {
      const base = path.basename(input.filePath);
      const unpackedDir = path.join(path.dirname(input.filePath), `unpacked_${base}`);

      if (packer.kind === 'pyinstaller') {
        onProgress('Unpacking PyInstaller executable...', 95);
        try {
          const pyiRes = await extractPyInstaller(input.filePath, unpackedDir);
          packer.entryPoints = pyiRes.entryPoints;
          packer.extractedCount = pyiRes.extractedCount;
          if (pyiRes.pythonVersion) {
            packer.version = pyiRes.pythonVersion;
          }
          if (pyiRes.limitations.length > 0) {
            result.limitations.push(...pyiRes.limitations);
          }

          onProgress('Extracting Python modules from PYZ archive...', 96);
          await unpackPythonBytecode(unpackedDir, pyiRes.entryPoints, packer, result.limitations);

          extractedPath = unpackedDir;
          fileTree = buildFileTree(unpackedDir, unpackedDir);

          result.evidence.push({
            kind: 'pattern',
            description: `PyInstaller package detected (${packer.version ? `Python ${packer.version}` : 'Python'}). Extracted ${pyiRes.extractedCount} files with entry points: ${pyiRes.entryPoints.join(', ')}`,
            confidence: 'high',
            snippet: `Entry points: ${pyiRes.entryPoints.join(', ')}`,
          });
        } catch (pyiErr: any) {
          result.limitations.push(`Failed to extract PyInstaller archive: ${pyiErr.message}`);
        }
      } else if (
        packer.kind === 'nsis' ||
        packer.kind === 'inno' ||
        packer.kind === 'sfx-7z' ||
        packer.kind === 'sfx-zip'
      ) {
        onProgress(`Extracting ${packer.kind.toUpperCase()} installer...`, 95);
        let res7z: ExtractResult;
        if (packer.kind === 'inno') {
          try {
            res7z = await extractInno(input.filePath, unpackedDir);
          } catch (innoErr: any) {
            // innoextract missing or an unsupported Inno version: 7z at least yields the setup stub's resources
            res7z = await extractWith7z(input.filePath, unpackedDir);
            res7z.limitations.unshift(`${innoErr.message}. Fell back to 7z, which only extracts the setup program, not the installed files.`);
          }
        } else {
          res7z = await extractWith7z(input.filePath, unpackedDir);
        }
        packer.extractedCount = res7z.extractedCount;
        if (res7z.limitations.length > 0) {
          result.limitations.push(...res7z.limitations);
        }
        if (res7z.extractedCount > 0) {
          extractedPath = unpackedDir;
          fileTree = buildFileTree(unpackedDir, unpackedDir);
        }
        result.evidence.push({
          kind: 'pattern',
          description: `Extracted ${packer.details}: ${res7z.extractedCount} files unpacked`,
          confidence: 'high',
        });
      } else if (packer.kind === 'upx') {
        onProgress('Unpacking UPX-compressed binary...', 94);
        const unpackedFile = path.join(unpackedDir, path.basename(input.fileName || base).replace(/[^\w.-]/g, '_'));
        try {
          fs.mkdirSync(unpackedDir, { recursive: true });
          await runTool('upx', ['-d', '-q', '-o', unpackedFile, input.filePath], {
            readPaths: [input.filePath],
            writePaths: [unpackedDir],
            timeoutMs: 120_000,
          });
          const unpackedBuf = fs.readFileSync(unpackedFile);
          const unpacked = await disassembleBinaryWithR2(
            unpackedFile,
            detectBinaryFormat(unpackedBuf),
            detectArchitecture(unpackedBuf, detectBinaryFormat(unpackedBuf)),
            unpackedBuf,
            onProgress
          );
          populateCallers(unpacked.functions);
          // The packed image only holds the UPX stub; everything useful comes from the unpacked one
          result = {
            ...unpacked,
            evidence: [
              ...result.evidence,
              {
                kind: 'pattern',
                description: 'UPX unpacked successfully; functions, imports, sections and strings are from the unpacked image',
                confidence: 'high',
                snippet: packer.details,
              },
              ...unpacked.evidence,
            ],
            limitations: unpacked.limitations,
          };
          packer.extractedCount = 1;
          extractedPath = unpackedDir;
          fileTree = buildFileTree(unpackedDir, unpackedDir);
        } catch (upxErr: any) {
          result.evidence.push({
            kind: 'pattern',
            description: 'Binary is packed with UPX compression',
            confidence: 'high',
            snippet: packer.details,
          });
          result.limitations.push(`UPX unpacking failed (possibly a modified/scrambled UPX header): ${upxErr.message}`);
        }
      }

      result.packer = packer;
    }
  } catch (packerErr: any) {
    result.limitations.push(`Packer detection/unpacking error: ${packerErr.message}`);
  }

  return { result, fileTree, extractedPath };
}

// Turn PyInstaller's PYZ modules and entry-point code objects into .pyc files, then
// decompile the interesting ones (entry points + third-party modules) when pycdc is installed
async function unpackPythonBytecode(
  unpackedDir: string,
  entryPoints: string[],
  packer: PackerInfo,
  limitations: string[]
): Promise<void> {
  const pyzFiles = fs.readdirSync(unpackedDir).filter((f) => /\.pyz$/i.test(f));
  let pycMagic: Buffer | undefined;
  const thirdParty: PyzModule[] = [];
  let stdlibCount = 0;

  for (const pyz of pyzFiles) {
    try {
      const res = extractPyz(path.join(unpackedDir, pyz), path.join(unpackedDir, 'pyz'));
      pycMagic ??= res.pycMagic;
      limitations.push(...res.limitations);
      for (const mod of res.modules) {
        if (isStdlibModule(mod.name)) stdlibCount++;
        else thirdParty.push(mod);
      }
    } catch (err: any) {
      limitations.push(`Could not read ${pyz}: ${err.message}`);
    }
  }

  // Entry-point scripts are bare code objects; a pyc header makes them loadable by decompilers
  const entryPycs: string[] = [];
  if (pycMagic) {
    for (const ep of entryPoints) {
      const raw = path.join(unpackedDir, ep);
      if (!fs.existsSync(raw) || !fs.statSync(raw).isFile()) continue;
      const pyc = `${raw}.pyc`;
      fs.writeFileSync(pyc, Buffer.concat([pycHeader(pycMagic), fs.readFileSync(raw)]));
      entryPycs.push(pyc);
    }
  } else if (pyzFiles.length === 0) {
    limitations.push('No PYZ archive found; Python modules could not be listed.');
  }

  packer.pythonModules = { thirdParty: thirdParty.map((m) => m.name).sort(), stdlibCount };

  // PyInstaller's own bootstrap modules are not the application's code
  const ownEntryPycs = entryPycs.filter((f) => !/[\\/]pyi(boot|_rth_)[^\\/]*$/.test(f.replace(/\.pyc$/, '')));
  const summary = await decompilePycFiles([...ownEntryPycs, ...thirdParty.filter((m) => !/^(PyInstaller|pyimod|_pyi)/.test(m.name)).map((m) => m.file)], limitations);
  packer.pythonDecompiler = summary.tool;
}

async function checkCommand(cmd: string, ...args: string[]): Promise<boolean> {
  try {
    await execFileAsync(cmd, args, { timeout: 3000 });
    return true;
  } catch {
    return false;
  }
}

const MAX_R2_FUNCTIONS = 150;
const R2_MARK = 'WRE_MARK_';

let r2ghidraAvailable: boolean | null = null;
let sleighHome: string | undefined;

// r2ghidra's processor specs; distro packages put radare2 under a multiarch lib dir that its
// default lookup (and the sandbox, which hides ~/.local) can miss, so pass the path explicitly
function findSleighHome(): string | undefined {
  const candidates = [
    process.env.R2GHIDRA_SLEIGH_HOME,
    ...['/usr/lib/x86_64-linux-gnu/radare2', '/usr/lib/aarch64-linux-gnu/radare2', '/usr/lib/radare2', '/usr/local/lib/radare2', '/usr/share/radare2']
      .filter((base) => fs.existsSync(base))
      .flatMap((base) => fs.readdirSync(base).map((ver) => path.join(base, ver, 'r2ghidra_sleigh'))),
  ];
  return candidates.find((dir) => dir && fs.existsSync(dir));
}

// r2ghidra registers as a core plugin; check once per process
let r2ghidraCheckedAt = 0;

// A negative result is re-checked after 5 minutes, so installing the plugin doesn't need a restart
export async function hasR2Ghidra(): Promise<boolean> {
  if (r2ghidraAvailable === true || (r2ghidraAvailable === false && Date.now() - r2ghidraCheckedAt < 5 * 60_000)) {
    return r2ghidraAvailable;
  }
  r2ghidraCheckedAt = Date.now();
  try {
    const { stdout } = await execFileAsync('r2', ['-qc', 'Lc', '--'], { timeout: 5000 });
    sleighHome = findSleighHome();
    r2ghidraAvailable = /r2ghidra/i.test(stdout) && !!sleighHome;
  } catch {
    r2ghidraAvailable = false;
  }
  return r2ghidraAvailable;
}

// Run several r2 commands in one process and split the output by marker lines
async function runR2Sections(
  filePath: string,
  sections: { key: string; cmd: string }[],
  timeoutMs: number
): Promise<Map<string, string>> {
  // 'aac' turns call targets into functions; plain 'aa' misses most of a stripped binary
  const script = ['aa', 'aac', ...sections.flatMap((s) => [`?e ${R2_MARK}${s.key}`, s.cmd])].join('; ');
  const ghidraArgs = sleighHome ? ['-e', `r2ghidra.sleighhome=${sleighHome}`] : [];
  const { stdout } = await runTool('r2', ['-e', 'scr.color=0', '-e', 'scr.interactive=false', ...ghidraArgs, '-qc', script, filePath], {
    readPaths: [filePath, ...(sleighHome ? [sleighHome] : [])],
    timeoutMs,
    maxBuffer: 200 * 1024 * 1024,
  });

  const out = new Map<string, string>();
  let currentKey: string | null = null;
  let buffer: string[] = [];
  for (const line of stdout.split('\n')) {
    if (line.startsWith(R2_MARK)) {
      if (currentKey !== null) out.set(currentKey, buffer.join('\n'));
      currentKey = line.slice(R2_MARK.length).trim();
      buffer = [];
    } else if (currentKey !== null) {
      buffer.push(line);
    }
  }
  if (currentKey !== null) out.set(currentKey, buffer.join('\n'));
  return out;
}

function parseJson<T>(text: string | undefined, fallback: T): T {
  if (!text) return fallback;
  try {
    return JSON.parse(text.trim()) as T;
  } catch {
    return fallback;
  }
}

const cleanSymbol = (name: string) => name.replace(/^sym\.imp\./, '').replace(/^sym\./, '').replace(/^imp\./, '');

async function disassembleBinaryWithR2(
  filePath: string,
  format: NativeResult['format'],
  architecture: string,
  buf: Buffer,
  onProgress: ProgressCallback
): Promise<NativeResult> {
  onProgress('Analyzing binary with radare2 (aa)...', 50);
  const evidence: Evidence[] = [];
  const limitations: string[] = [];

  // Pass 1: metadata and the function list
  const meta = await runR2Sections(
    filePath,
    [
      { key: 'entries', cmd: 'iej' },
      { key: 'imports', cmd: 'iij' },
      { key: 'exports', cmd: 'iEj' },
      { key: 'sections', cmd: 'iSj' },
      { key: 'functions', cmd: 'aflj' },
    ],
    120_000
  );

  const entries = parseJson<any[]>(meta.get('entries'), []);
  const entryPoint = entries.length > 0 && typeof entries[0].vaddr === 'number' ? `0x${entries[0].vaddr.toString(16)}` : undefined;

  const imports: NativeImport[] = parseJson<any[]>(meta.get('imports'), []).map((imp) => ({
    library: imp.libname || imp.lib || '',
    name: imp.name || '',
    address: typeof imp.plt === 'number' && imp.plt > 0 ? `0x${imp.plt.toString(16)}` : undefined,
  }));

  const exports: NativeExport[] = parseJson<any[]>(meta.get('exports'), []).map((exp) => ({
    name: exp.name || exp.realname || '',
    address: `0x${(exp.vaddr || 0).toString(16)}`,
    ordinal: typeof exp.ordinal === 'number' ? exp.ordinal : undefined,
  }));

  const sections: BinarySection[] = parseJson<any[]>(meta.get('sections'), []).map((s) => {
    const offset = typeof s.paddr === 'number' ? s.paddr : undefined;
    const size = s.size || s.vsize || 0;
    return {
      name: s.name || 'unnamed',
      address: `0x${(s.vaddr || s.paddr || 0).toString(16)}`,
      size,
      permissions: s.perm || 'r-x',
      offset,
      entropy:
        offset !== undefined && size > 0 && offset + size <= buf.length
          ? calculateBufferEntropy(buf.subarray(offset, offset + size))
          : undefined,
    };
  });

  const allFunctions = parseJson<any[]>(meta.get('functions'), []);
  if (allFunctions.length === 0) {
    throw new Error('radare2 found no functions');
  }

  // Import thunks are not interesting code; put entry/main first, then the rest in address order
  const priority = (name: string) => (/^(entry0|main|sym\.main|sym\._main|WinMain)$/i.test(name) ? 0 : 1);
  const candidates = allFunctions
    .filter((f) => typeof f.offset === 'number' && !/^(sym\.)?imp\./.test(f.name || ''))
    .sort((a, b) => priority(a.name) - priority(b.name) || a.offset - b.offset);
  const selected = candidates.slice(0, MAX_R2_FUNCTIONS);
  if (candidates.length > MAX_R2_FUNCTIONS) {
    limitations.push(`Disassembly and pseudo-code shown for ${MAX_R2_FUNCTIONS} of ${candidates.length} functions (entry/main first).`);
  }

  // Pass 2: disassembly + decompiled/pseudo code for the selected functions
  const useGhidra = await hasR2Ghidra();
  const decompiler: NativeResult['decompiler'] = useGhidra ? 'r2ghidra' : 'r2-pdc';
  const decompCmd = useGhidra ? 'pdg' : 'pdc';
  onProgress(`Disassembling and decompiling ${selected.length} functions (${decompiler})...`, 70);

  let code = new Map<string, string>();
  try {
    code = await runR2Sections(
      filePath,
      selected.flatMap((f) => {
        const addr = `0x${f.offset.toString(16)}`;
        return [
          { key: `dis_${addr}`, cmd: `pdfj @ ${addr}` },
          { key: `dec_${addr}`, cmd: `${decompCmd} @ ${addr}` },
        ];
      }),
      240_000
    );
  } catch (err: any) {
    limitations.push(`Per-function disassembly failed or timed out: ${err.message}`);
  }

  const functions: NativeFunction[] = selected.map((f) => {
    const addr = `0x${f.offset.toString(16)}`;
    const pdf = parseJson<any>(code.get(`dis_${addr}`), null);
    const ops: any[] = pdf && Array.isArray(pdf.ops) ? pdf.ops : [];
    const callees: string[] = [];

    const disassembly: DisassemblyLine[] = ops.map((op) => {
      const dis = (op.disasm || '').trim();
      if (op.type === 'call' || op.type === 'ucall' || dis.startsWith('call')) {
        // Indirect calls (call qword [rax+8]) have no static target
        const target = cleanSymbol(dis.split(/\s+/)[1] || '');
        if (target && !/^(qword|dword|word|byte|\[)/.test(target) && !callees.includes(target)) callees.push(target);
      }
      return {
        address: `0x${(op.offset || 0).toString(16)}`,
        bytes: op.bytes || '',
        mnemonic: dis.split(' ')[0] || op.type || 'nop',
        operands: dis.split(' ').slice(1).join(' '),
        comment: op.comment,
      };
    });

    const decompiled = (code.get(`dec_${addr}`) || '').trim();
    const header = useGhidra ? '// r2ghidra decompiler output' : '// radare2 pdc pseudo-code (approximate)';

    return {
      address: addr,
      name: cleanSymbol(f.name || addr),
      size: f.size || 0,
      disassembly,
      decompiledCode: decompiled ? `${header}\n${decompiled}` : undefined,
      callers: [],
      callees,
    };
  });

  onProgress('Extracting strings...', 90);
  const strings = extractStrings(buf);

  evidence.push({
    kind: 'code',
    description: `radare2 recovered ${allFunctions.length} functions, ${imports.length} imports and ${exports.length} exports; ${functions.length} disassembled with ${useGhidra ? 'the Ghidra decompiler (r2ghidra)' : 'radare2 pdc pseudo-code'}`,
    confidence: 'high',
  });
  if (!useGhidra) {
    limitations.push('Pseudo-code is radare2 pdc output (approximate). Install the r2ghidra plugin for real decompilation.');
  }

  return {
    type: 'native',
    format,
    architecture,
    provider: 'radare2',
    entryPoint,
    functions,
    imports,
    exports,
    strings: strings.slice(0, 500),
    sections,
    evidence,
    limitations,
    decompiler,
  };
}

function detectBinaryFormat(buf: Buffer): NativeResult['format'] {
  if (buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) return 'ELF';
  if (buf[0] === 0x4d && buf[1] === 0x5a) return 'PE';
  const magic = buf.readUInt32LE(0);
  if (magic === 0xfeedface || magic === 0xfeedfacf || magic === 0xcefaedfe || magic === 0xcffaedfe)
    return 'Mach-O';
  return 'unknown';
}

function detectArchitecture(buf: Buffer, format: NativeResult['format']): string {
  if (format === 'ELF') {
    const machine = buf.readUInt16LE(18);
    if (machine === 0x3e) return 'x86_64';
    if (machine === 0x28) return 'ARM';
    if (machine === 0xb7) return 'AArch64';
    if (machine === 0x03) return 'x86';
    return `unknown (0x${machine.toString(16)})`;
  }
  if (format === 'PE') {
    const peOffset = buf.readUInt32LE(0x3c);
    if (peOffset + 6 <= buf.length) {
      const machine = buf.readUInt16LE(peOffset + 4);
      if (machine === 0x8664) return 'x86_64';
      if (machine === 0x14c) return 'x86';
      if (machine === 0xaa64) return 'AArch64';
    }
    return 'unknown';
  }
  return 'unknown';
}

async function disassembleBinaryWithBinutils(
  filePath: string,
  format: 'ELF' | 'PE',
  architecture: string,
  buf: Buffer,
  onProgress: ProgressCallback
): Promise<NativeResult> {
  const functions: NativeFunction[] = [];
  const sections: BinarySection[] = [];
  const evidence: Evidence[] = [];
  let entryPoint = '0x0';

  // 1. Get Entry point & Sections via readelf
  if (format === 'ELF') {
    onProgress('Parsing ELF header & section headers...', 45);
    try {
      const { stdout: headerOut } = await runTool('readelf', ['-h', filePath], {
        readPaths: [filePath],
      });
      const entryMatch = headerOut.match(/Entry point address:\s+(0x[0-9a-fA-F]+)/);
      if (entryMatch) entryPoint = entryMatch[1];

      const { stdout: secOut } = await runTool('readelf', ['-S', '--wide', filePath], {
        readPaths: [filePath],
      });
      const secLines = secOut.split('\n');
      for (const line of secLines) {
        const match = line.match(/\[\s*\d+\]\s+(\.\S+)\s+(\S+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+\S+\s+(\S+)/);
        if (match) {
          const offset = parseInt(match[4], 16);
          const size = parseInt(match[5], 16);
          const secEntropy =
            offset >= 0 && size > 0 && offset + size <= buf.length
              ? calculateBufferEntropy(buf.subarray(offset, offset + size))
              : undefined;
          sections.push({
            name: match[1],
            address: `0x${match[3]}`,
            size,
            permissions: match[6],
            offset,
            entropy: secEntropy,
          });
        }
      }
    } catch {
      // ignore
    }
  } else if (format === 'PE') {
    sections.push(...parsePESections(buf));
  }

  // 2. Disassemble functions using objdump
  onProgress('Disassembling procedures & instructions with objdump...', 60);
  const { stdout: disasmOut } = await runTool(
    'objdump',
    ['-d', '-M', 'intel', '--no-show-raw-insn', filePath],
    { readPaths: [filePath], maxBuffer: 150 * 1024 * 1024, timeoutMs: 60_000 }
  );

  onProgress('Parsing functions and basic blocks...', 80);
  const lines = disasmOut.split('\n');
  let currentFunc: NativeFunction | null = null;
  const funcRegex = /^([0-9a-fA-F]+)\s+<([^>]+)>:$/;
  const insnRegex = /^\s*([0-9a-fA-F]+):\s+([a-z0-9_]+)(?:\s+(.*))?$/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const funcMatch = line.match(funcRegex);
    if (funcMatch) {
      if (currentFunc) {
        functions.push(currentFunc);
      }
      currentFunc = {
        address: `0x${funcMatch[1]}`,
        name: funcMatch[2],
        size: 0,
        disassembly: [],
        callers: [],
        callees: [],
      };
      continue;
    }

    if (currentFunc) {
      const insnMatch = line.match(insnRegex);
      if (insnMatch) {
        const addr = `0x${insnMatch[1]}`;
        const mnemonic = insnMatch[2];
        const operands = insnMatch[3] ? insnMatch[3].trim() : '';

        // Extract call targets
        if (mnemonic === 'call' && operands) {
          const target = operands.match(/<([^>]+)>/);
          if (target && !currentFunc.callees.includes(target[1])) {
            currentFunc.callees.push(target[1]);
          }
        }

        currentFunc.disassembly?.push({
          address: addr,
          bytes: '',
          mnemonic,
          operands,
        });
      }
    }
  }

  if (currentFunc) {
    functions.push(currentFunc);
  }

  onProgress('Scanning strings and references...', 90);
  const strings = extractStrings(buf);

  evidence.push({
    kind: 'code',
    description: `Disassembled ${functions.length} functions across ${sections.length} sections`,
    confidence: 'high',
  });

  if (strings.length > 0) {
    evidence.push({
      kind: 'string',
      description: `Identified ${strings.length} cross-referenced strings`,
      confidence: 'high',
    });
  }

  onProgress('Analysis complete.', 100);

  return {
    type: 'native',
    format,
    architecture,
    provider: 'objdump',
    decompiler: 'none',
    entryPoint,
    functions: functions.slice(0, 800), // cap for UI performance
    imports: [],
    exports: [],
    strings: strings.slice(0, 500),
    sections,
    evidence,
    limitations:
      functions.length > 800
        ? ['Function list capped at 800 for web UI performance. Full binary was disassembled.']
        : [],
  };
}

function basicBinaryAnalysis(
  input: NativeInput,
  buf: Buffer,
  format: NativeResult['format'],
  architecture: string
): NativeResult {
  const strings = extractStrings(buf);
  const sections = format === 'PE' ? parsePESections(buf) : [];
  return {
    type: 'native',
    format,
    architecture,
    provider: 'Static Parser',
    decompiler: 'none',
    functions: [],
    imports: [],
    exports: [],
    strings: strings.slice(0, 500),
    sections,
    evidence: [],
    limitations: ['Binary disassembly unavailable for this format.'],
  };
}

function parsePESections(buf: Buffer): BinarySection[] {
  if (buf.length < 0x40) return [];
  const peOffset = buf.readUInt32LE(0x3c);
  if (peOffset + 24 > buf.length) return [];
  if (buf.readUInt32LE(peOffset) !== 0x00004550) return []; // 'PE\0\0'

  const numSections = buf.readUInt16LE(peOffset + 6);
  const optHeaderSize = buf.readUInt16LE(peOffset + 20);
  let secHeaderOffset = peOffset + 24 + optHeaderSize;

  const sections: BinarySection[] = [];
  for (let i = 0; i < numSections; i++) {
    if (secHeaderOffset + 40 > buf.length) break;
    const name = buf.subarray(secHeaderOffset, secHeaderOffset + 8).toString('utf8').replace(/\0.*$/, '').trim();
    const virtualSize = buf.readUInt32LE(secHeaderOffset + 8);
    const virtualAddress = buf.readUInt32LE(secHeaderOffset + 12);
    const rawSize = buf.readUInt32LE(secHeaderOffset + 16);
    const rawOffset = buf.readUInt32LE(secHeaderOffset + 20);
    const characteristics = buf.readUInt32LE(secHeaderOffset + 36);

    let perms = '';
    if (characteristics & 0x40000000) perms += 'r';
    if (characteristics & 0x80000000) perms += 'w';
    if (characteristics & 0x20000000) perms += 'x';

    const size = rawSize > 0 ? rawSize : virtualSize;
    let entropy: number | undefined;
    if (rawOffset >= 0 && rawSize > 0 && rawOffset + rawSize <= buf.length) {
      entropy = calculateBufferEntropy(buf.subarray(rawOffset, rawOffset + rawSize));
    }

    sections.push({
      name: name || `section_${i}`,
      address: `0x${virtualAddress.toString(16)}`,
      size,
      permissions: perms || 'r-x',
      offset: rawOffset,
      entropy,
    });

    secHeaderOffset += 40;
  }
  return sections;
}

function populateCallers(functions: NativeFunction[]): void {
  const funcMap = new Map<string, NativeFunction>();
  for (const fn of functions) {
    funcMap.set(fn.name, fn);
    funcMap.set(fn.address, fn);
  }

  for (const fn of functions) {
    for (const callee of fn.callees) {
      const target = funcMap.get(callee);
      if (target && !target.callers.includes(fn.name)) {
        target.callers.push(fn.name);
      }
    }
  }
}

function checkPackedEvidence(result: NativeResult, buf: Buffer): void {
  const wholeFileEntropy = calculateBufferEntropy(buf);
  const knownPackers = ['upx0', 'upx1', '.aspack', '.mpress1', '.themida'];
  const hasPackerSection = result.sections.some((s) =>
    knownPackers.some((p) => s.name.toLowerCase().includes(p))
  );

  if (wholeFileEntropy > 7.2 || hasPackerSection) {
    const reasons: string[] = [];
    if (wholeFileEntropy > 7.2) {
      reasons.push(`Whole-file entropy (${wholeFileEntropy.toFixed(2)}) > 7.2`);
    }
    if (hasPackerSection) {
      const detected = result.sections
        .filter((s) => knownPackers.some((p) => s.name.toLowerCase().includes(p)))
        .map((s) => s.name);
      reasons.push(`Known packer section(s): ${detected.join(', ')}`);
    }

    result.evidence.push({
      kind: 'pattern',
      description: 'Possibly packed/encrypted',
      confidence: 'medium',
      snippet: reasons.join('; '),
    });
  }
}

function extractStrings(buf: Buffer, minLength = 5): NativeResult['strings'] {
  const results: NativeResult['strings'] = [];
  let current = '';
  let start = 0;

  for (let i = 0; i < buf.length; i++) {
    const b = buf[i];
    const isPrintable = b >= 0x20 && b < 0x7f;
    if (isPrintable) {
      if (current.length === 0) start = i;
      current += String.fromCharCode(b);
    } else {
      if (current.length >= minLength) {
        results.push({
          value: current,
          address: `0x${start.toString(16)}`,
          encoding: 'ascii',
        });
      }
      current = '';
    }
  }
  return results;
}
