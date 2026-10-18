import { execFile } from 'child_process';
import { promisify } from 'util';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import type { JavaScriptInput, JavaScriptResult, JsModule, ImportEdge, Evidence, FileTreeNode } from '../../../shared/types.js';
import { buildFileTree } from './fileTree.js';
import { runTool } from './sandbox.js';
import { extractAsar, extractTar, extractWith7z } from './archive.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const nodeModulesDir = path.resolve(__dirname, '../../node_modules');
const reaAgentsBin = path.join(nodeModulesDir, '.bin/rea-agents');

const execFileAsync = promisify(execFile);

type ProgressCallback = (msg: string, pct?: number) => void;

export async function runJavaScriptAnalysis(
  input: JavaScriptInput,
  onProgress: ProgressCallback
): Promise<{ result: JavaScriptResult; fileTree?: any[]; extractedPath?: string }> {
  onProgress('Locating input file...', 10);

  if (!input.filePath || !fs.existsSync(input.filePath)) {
    throw new Error(`File not found: ${input.filePath}`);
  }

  // Archives get extracted into a private workspace; a single script is its own one-file tree
  const lowerName = input.fileName.toLowerCase();
  const archiveKind = lowerName.endsWith('.asar')
    ? 'asar'
    : /\.(tar\.gz|tgz|tar\.bz2|tar\.xz|tar)$/.test(lowerName)
      ? 'tar'
      : lowerName.endsWith('.zip')
        ? 'zip'
        : null;

  let extractedPath: string | undefined;
  let fileTree: FileTreeNode[] = [{ name: input.fileName, path: input.fileName, type: 'file', size: input.fileSize }];
  const extractionLimitations: string[] = [];

  if (archiveKind) {
    onProgress(`Extracting ${archiveKind} archive for workspace exploration...`, 15);
    const extractDir = path.join(path.dirname(input.filePath), `extracted_${path.basename(input.filePath)}`);
    try {
      const res =
        archiveKind === 'asar'
          ? extractAsar(input.filePath, extractDir)
          : archiveKind === 'tar'
            ? await extractTar(input.filePath, extractDir)
            : await extractWith7z(input.filePath, extractDir);
      extractionLimitations.push(...res.limitations);
      if (res.extractedCount > 0) {
        extractedPath = extractDir;
        fileTree = buildFileTree(extractDir, extractDir);
      }
    } catch (err: any) {
      extractionLimitations.push(`Archive extraction failed: ${err.message}`);
    }
  }

  onProgress('Running rea-agents JavaScript analysis...', 20);

  let rawOutput: string;
  try {
    // Use rea-agents CLI to analyze the JS/ASAR file
    const { stdout } = await runTool(
      reaAgentsBin,
      ['analyze-javascript-application', input.filePath, '--json'],
      {
        readPaths: [input.filePath, nodeModulesDir],
        timeoutMs: 120_000,
        maxBuffer: 50 * 1024 * 1024,
      }
    );
    rawOutput = stdout;
  } catch (err: unknown) {
    // If rea-agents isn't available, do basic analysis
    onProgress('rea-agents not available — running basic JS analysis...', 30);
    const fb = await fallbackJsAnalysis(input, onProgress);
    fb.limitations.push(...extractionLimitations);
    return { result: fb, fileTree, extractedPath };
  }

  onProgress('Parsing results...', 80);

  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(rawOutput) as Record<string, unknown>;
  } catch {
    throw new Error('Failed to parse rea-agents output');
  }

  onProgress('Building result...', 95);

  const res = mapReaOutput(parsed, input.fileName);
  res.limitations.push(...extractionLimitations);
  return { result: res, fileTree, extractedPath };
}


function mapReaOutput(raw: Record<string, unknown>, fileName: string): JavaScriptResult {
  const modules: JsModule[] = [];
  const imports: ImportEdge[] = [];
  const evidence: Evidence[] = [];

  // Map from rea-agents' output format
  const rawModules = Array.isArray(raw.modules) ? raw.modules : [];
  for (const m of rawModules as Record<string, unknown>[]) {
    modules.push({
      id: String(m.id ?? m.path ?? ''),
      path: String(m.path ?? ''),
      size: Number(m.size ?? 0),
      exports: Array.isArray(m.exports) ? m.exports.map(String) : [],
      isEntry: Boolean(m.isEntry ?? m.isEntryPoint),
      isElectronMain: Boolean(m.isElectronMain),
      isElectronRenderer: Boolean(m.isElectronRenderer),
    });
  }

  const rawImports = Array.isArray(raw.imports) ? raw.imports : [];
  for (const imp of rawImports as Record<string, unknown>[]) {
    imports.push({
      from: String(imp.from ?? ''),
      to: String(imp.to ?? ''),
      isDynamic: Boolean(imp.isDynamic),
    });
  }

  const rawEvidence = Array.isArray(raw.evidence) ? raw.evidence : [];
  for (const ev of rawEvidence as Record<string, unknown>[]) {
    evidence.push({
      kind: (ev.kind as Evidence['kind']) ?? 'code',
      description: String(ev.description ?? ''),
      confidence: (ev.confidence as Evidence['confidence']) ?? 'medium',
      snippet: ev.snippet ? String(ev.snippet) : undefined,
    });
  }

  const entryPoints = modules.filter((m) => m.isEntry).map((m) => m.path);

  return {
    type: 'javascript',
    summary: String(raw.summary ?? `Analyzed ${fileName}: ${modules.length} modules found`),
    modules,
    entryPoints,
    imports,
    evidence,
    limitations: Array.isArray(raw.limitations) ? raw.limitations.map(String) : [],
  };
}

async function fallbackJsAnalysis(
  input: JavaScriptInput,
  onProgress: ProgressCallback
): Promise<JavaScriptResult> {
  onProgress('Reading file...', 40);
  const content = fs.readFileSync(input.filePath!, 'utf-8');
  const lines = content.split('\n');

  onProgress('Scanning for imports and exports...', 60);

  // Basic regex-based import/export detection
  const requireRegex = /require\(['"`]([^'"`]+)['"`]\)/g;
  const importRegex = /import\s+(?:.+?\s+from\s+)?['"`]([^'"`]+)['"`]/g;
  const exportRegex = /(?:module\.)?exports(?:\.\w+)?\s*=/g;
  const dynamicImportRegex = /import\(['"`]([^'"`]+)['"`]\)/g;

  const deps = new Set<string>();
  const dynamicDeps = new Set<string>();
  let exportCount = 0;

  for (const match of content.matchAll(requireRegex)) deps.add(match[1]);
  for (const match of content.matchAll(importRegex)) deps.add(match[1]);
  for (const match of content.matchAll(dynamicImportRegex)) dynamicDeps.add(match[1]);
  for (const _ of content.matchAll(exportRegex)) exportCount++;

  const mainModule: JsModule = {
    id: 'main',
    path: input.fileName,
    size: input.fileSize,
    exports: [],
    isEntry: true,
  };

  const modules: JsModule[] = [mainModule];
  const imports: ImportEdge[] = [];

  for (const dep of deps) {
    const mod: JsModule = { id: dep, path: dep, size: 0, exports: [], isEntry: false };
    modules.push(mod);
    imports.push({ from: input.fileName, to: dep, isDynamic: false });
  }
  for (const dep of dynamicDeps) {
    if (!deps.has(dep)) {
      const mod: JsModule = { id: dep, path: dep, size: 0, exports: [], isEntry: false };
      modules.push(mod);
    }
    imports.push({ from: input.fileName, to: dep, isDynamic: true });
  }

  const evidence: Evidence[] = [];
  const isElectron =
    content.includes('electron') ||
    content.includes('ipcMain') ||
    content.includes('ipcRenderer');

  if (isElectron) {
    evidence.push({
      kind: 'pattern',
      description: 'Electron API usage detected (ipcMain/ipcRenderer/electron imports)',
      confidence: 'high',
    });
    mainModule.isElectronMain =
      content.includes('ipcMain') || content.includes('app.on(');
    mainModule.isElectronRenderer = content.includes('ipcRenderer');
  }

  if (deps.size > 0) {
    evidence.push({
      kind: 'code',
      description: `Found ${deps.size} static import(s) and ${dynamicDeps.size} dynamic import(s)`,
      confidence: 'high',
    });
  }

  onProgress('Done.', 100);

  return {
    type: 'javascript',
    summary: `Basic analysis of ${input.fileName}: ${modules.length} modules, ${imports.length} imports, ${exportCount} exports`,
    modules,
    entryPoints: [input.fileName],
    imports,
    evidence,
    limitations: [
      'Full rea-agents CLI not available. Install rea-agents for complete analysis.',
      'Only regex-based static analysis performed — no AST or bundler awareness.',
    ],
  };
}
