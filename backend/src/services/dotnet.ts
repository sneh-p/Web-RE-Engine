import { execFile } from 'child_process';
import { promisify } from 'util';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { fileURLToPath } from 'url';
import type { DotNetInput, DotNetResult, DotNetNamespace, DotNetType, Evidence, FileTreeNode } from '../../../shared/types.js';
import { runTool } from './sandbox.js';
import { buildFileTree } from './fileTree.js';
import { enforceExtractionLimits } from './archive.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const nodeModulesDir = path.resolve(__dirname, '../../node_modules');
const reaAgentsBin = path.join(nodeModulesDir, '.bin/rea-agents');

const execFileAsync = promisify(execFile);
type ProgressCallback = (msg: string, pct?: number) => void;

export async function runDotNetAnalysis(
  input: DotNetInput,
  onProgress: ProgressCallback
): Promise<{ result: DotNetResult; fileTree?: FileTreeNode[]; extractedPath?: string }> {
  onProgress('Reading .NET assembly...', 10);

  if (!input.filePath || !fs.existsSync(input.filePath)) {
    throw new Error(`File not found: ${input.filePath}`);
  }

  // Try ilspy first (ilspycmd)
  onProgress('Checking for ilspycmd...', 20);
  const ilspyAvailable = await checkTool('ilspycmd', '--version');

  if (ilspyAvailable) {
    return runIlspyAnalysis(input, onProgress);
  }

  // Try rea-agents managed tools
  onProgress('Trying rea-agents managed code tools...', 30);
  try {
    const { stdout } = await runTool(
      reaAgentsBin,
      ['inspect-managed-artifact', input.filePath, '--json'],
      {
        readPaths: [input.filePath, nodeModulesDir],
        timeoutMs: 120_000,
        maxBuffer: 50 * 1024 * 1024,
      }
    );
    const parsed = JSON.parse(stdout) as Record<string, unknown>;
    return { result: mapReaDotNetOutput(parsed, input.fileName) };
  } catch {
    onProgress('rea-agents managed tools unavailable — running basic PE/.NET header analysis...', 50);
    return { result: basicDotNetAnalysis(input, onProgress) };
  }
}

async function checkTool(cmd: string, ...args: string[]): Promise<boolean> {
  try {
    await execFileAsync(cmd, args, { timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

// ilspycmd is a .NET global tool living under ~/.dotnet/tools, which the sandbox hides by default
const dotnetToolsDir = path.join(os.homedir(), '.dotnet', 'tools');

const ILSPY_KINDS: Record<string, DotNetType['kind']> = {
  Class: 'class',
  Interface: 'interface',
  Struct: 'struct',
  Delegate: 'delegate',
  Enum: 'enum',
};

async function runIlspyAnalysis(
  input: DotNetInput,
  onProgress: ProgressCallback
): Promise<{ result: DotNetResult; fileTree?: FileTreeNode[]; extractedPath?: string }> {
  const filePath = input.filePath!;
  const readPaths = [filePath, ...(fs.existsSync(dotnetToolsDir) ? [dotnetToolsDir] : [])];
  const evidence: Evidence[] = [];
  const limitations: string[] = [];

  // One listing for all kinds; lines look like "Class Namespace.Type". The update check needs the
  // network (the sandbox has none) and prints a notice into stdout, so it is turned off.
  onProgress('Listing types with ILSpy...', 40);
  const nsMap = new Map<string, DotNetType[]>();
  let typeCount = 0;
  try {
    const { stdout } = await runTool('ilspycmd', ['--disable-updatecheck', '-l', 'cisde', filePath], {
      readPaths,
      timeoutMs: 120_000,
      maxBuffer: 20 * 1024 * 1024,
    });
    for (const raw of stdout.split('\n')) {
      const m = raw.trim().match(/^(Class|Interface|Struct|Delegate|Enum)\s+(.+)$/);
      if (!m) continue;
      const fullName = m[2];
      const parts = fullName.split('.');
      const name = parts.pop()!;
      const ns = parts.join('.') || '(global)';
      if (!nsMap.has(ns)) nsMap.set(ns, []);
      nsMap.get(ns)!.push({ name, fullName, kind: ILSPY_KINDS[m[1]], methods: [], fields: [], properties: [], interfaces: [] });
      typeCount++;
    }
  } catch (err: any) {
    limitations.push(`ILSpy could not list types: ${String(err.stderr || err.message).split('\n')[0]}`);
  }

  // Whole-assembly decompilation into a browsable C# project
  onProgress('Decompiling assembly to C# project with ILSpy...', 70);
  const outDir = path.join(path.dirname(filePath), `decompiled_${path.basename(filePath)}`);
  let extractedPath: string | undefined;
  let fileTree: FileTreeNode[] | undefined;
  try {
    fs.mkdirSync(outDir, { recursive: true });
    await runTool('ilspycmd', ['--disable-updatecheck', '-p', '-o', outDir, filePath], {
      readPaths,
      writePaths: [outDir],
      timeoutMs: 300_000,
      memoryMaxMB: 2048,
    });
    const fileCount = enforceExtractionLimits(outDir, limitations);
    if (fileCount > 0) {
      extractedPath = outDir;
      fileTree = buildFileTree(outDir, outDir);
      evidence.push({ kind: 'code', description: `ILSpy decompiled the assembly into ${fileCount} C# project files`, confidence: 'high' });
    }
  } catch (err: any) {
    limitations.push(`ILSpy project decompilation failed: ${String(err.stderr || err.message).split('\n')[0]}`);
  }

  if (typeCount === 0 && !extractedPath) {
    throw new Error(`ILSpy analysis failed: ${limitations.join('; ')}`);
  }

  evidence.push({ kind: 'code', description: `Found ${typeCount} types across ${nsMap.size} namespaces`, confidence: 'high' });
  return {
    result: {
      type: 'dotnet',
      targetFramework: 'unknown',
      namespaces: [...nsMap].map(([name, types]) => ({ name, types })),
      evidence,
      limitations,
    },
    fileTree,
    extractedPath,
  };
}

function mapReaDotNetOutput(raw: Record<string, unknown>, fileName: string): DotNetResult {
  return {
    type: 'dotnet',
    targetFramework: String(raw.targetFramework ?? 'unknown'),
    namespaces: (raw.namespaces as DotNetNamespace[]) ?? [],
    evidence: (raw.evidence as Evidence[]) ?? [],
    limitations: (raw.limitations as string[]) ?? [],
  };
}

function basicDotNetAnalysis(
  input: DotNetInput,
  onProgress: ProgressCallback
): DotNetResult {
  onProgress('Reading PE/.NET headers...', 60);

  const buf = fs.readFileSync(input.filePath!);
  const evidence: Evidence[] = [];

  // Check PE magic
  const isMz = buf[0] === 0x4d && buf[1] === 0x5a;

  if (!isMz) {
    throw new Error('Not a valid PE file');
  }

  // Read PE offset
  const peOffset = buf.readUInt32LE(0x3c);
  const isPe = buf.readUInt32LE(peOffset) === 0x00004550;

  if (!isPe) {
    throw new Error('Not a valid PE executable');
  }

  // Check for .NET CLR header (IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR at index 14)
  const optHeaderOffset = peOffset + 24;
  const magic = buf.readUInt16LE(optHeaderOffset);
  const isPE32Plus = magic === 0x20b;
  const clrRvaOffset = optHeaderOffset + (isPE32Plus ? 112 + 14 * 8 : 96 + 14 * 8);

  const clrRva = buf.readUInt32LE(clrRvaOffset);
  const clrSize = buf.readUInt32LE(clrRvaOffset + 4);
  const isDotNet = clrRva !== 0 && clrSize > 0;

  if (isDotNet) {
    evidence.push({
      kind: 'pattern',
      description: 'CLR header found — confirmed .NET assembly',
      confidence: 'high',
    });
  }

  onProgress('Done.', 100);

  return {
    type: 'dotnet',
    targetFramework: isDotNet ? '.NET (version unknown)' : 'unknown',
    namespaces: [],
    evidence,
    limitations: [
      'ILSpy (ilspycmd) is not installed, so types and C# source could not be recovered.',
      'Install it with `dotnet tool install -g ilspycmd` for full analysis.',
    ],
  };
}
