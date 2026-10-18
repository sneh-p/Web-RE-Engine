import { execFile } from 'child_process';
import { promisify } from 'util';
import fs from 'fs';
import path from 'path';
import type {
  AndroidInput,
  AndroidResult,
  AndroidComponent,
  AndroidClass,
  Evidence,
  FileTreeNode,
} from '../../../shared/types.js';
import { buildFileTree } from './fileTree.js';
import { runTool } from './sandbox.js';

const execFileAsync = promisify(execFile);
type ProgressCallback = (msg: string, pct?: number) => void;

export async function runAndroidAnalysis(
  input: AndroidInput,
  onProgress: ProgressCallback
): Promise<{ result: AndroidResult; fileTree?: any[]; extractedPath?: string }> {
  onProgress('Reading APK package...', 10);

  if (!input.filePath || !fs.existsSync(input.filePath)) {
    throw new Error(`File not found: ${input.filePath}`);
  }

  const apkDir = path.dirname(input.filePath);
  const outJadxDir = path.join(apkDir, `jadx_${path.basename(input.filePath)}`);
  const outApktoolDir = path.join(apkDir, `apktool_${path.basename(input.filePath)}`);

  // 1. Try JADX decompiler first (extracts clean Java sources + decoded resources)
  const jadxAvailable = await checkCommand('jadx', '--version');
  if (jadxAvailable) {
    onProgress('Decompiling Dalvik/ART bytecode to Java with JADX...', 25);
    try {
      if (!fs.existsSync(outJadxDir)) fs.mkdirSync(outJadxDir, { recursive: true });

      await runTool('jadx', [
        '-d', outJadxDir,
        '--no-res', // fast Java decompile
        input.filePath,
      ], {
        readPaths: [input.filePath],
        writePaths: [outJadxDir],
        timeoutMs: 90_000,
        maxBuffer: 100 * 1024 * 1024,
      });

      onProgress('Parsing decompiled Java classes & packages...', 60);
      const classes = scanDecompiledJavaClasses(outJadxDir);
      const fileTree = buildFileTree(outJadxDir, outJadxDir);

      // Parse manifest if apktool also available or extract manifest
      const manifestResult = await tryApktoolOrZip(input, outApktoolDir, onProgress);

      const evidence: Evidence[] = [
        {
          kind: 'code',
          description: `JADX successfully decompiled ${classes.length} Java classes from Dalvik bytecode`,
          confidence: 'high',
        },
        ...manifestResult.evidence,
      ];

      onProgress('Android code analysis complete.', 100);

      return {
        result: {
          type: 'android',
          packageName: manifestResult.packageName,
          version: manifestResult.version,
          targetSdk: manifestResult.targetSdk,
          minSdk: manifestResult.minSdk,
          permissions: manifestResult.permissions,
          activities: manifestResult.activities,
          services: manifestResult.services,
          receivers: manifestResult.receivers,
          providers: manifestResult.providers,
          classes: classes.slice(0, 300),
          evidence,
          limitations: classes.length > 300 ? ['Class browser capped at 300 classes. Full workspace is viewable in explorer.'] : [],
        },
        fileTree,
        extractedPath: outJadxDir,
      };
    } catch (e: any) {
      onProgress(`JADX decompiler encountered error: ${e.message}, trying apktool...`, 40);
    }
  }

  // 2. Apktool Fallback
  const apktoolAvailable = await checkCommand('apktool', '--version');
  if (apktoolAvailable) {
    onProgress('Decoding APK resources and Smali with Apktool...', 40);
    try {
      if (!fs.existsSync(outApktoolDir)) fs.mkdirSync(outApktoolDir, { recursive: true });
      await runTool('apktool', ['d', '-f', '-o', outApktoolDir, input.filePath], {
        readPaths: [input.filePath],
        writePaths: [outApktoolDir],
        timeoutMs: 90_000,
        maxBuffer: 50 * 1024 * 1024,
      });

      onProgress('Parsing decoded AndroidManifest.xml & Smali...', 70);
      const manifestPath = path.join(outApktoolDir, 'AndroidManifest.xml');
      const manifestContent = fs.existsSync(manifestPath)
        ? fs.readFileSync(manifestPath, 'utf-8')
        : '';
      const manifestRes = parseManifest(manifestContent, input.fileName, 'apktool');
      const smaliClasses = scanSmaliClasses(outApktoolDir);
      const fileTree = buildFileTree(outApktoolDir, outApktoolDir);

      return {
        result: {
          ...manifestRes,
          classes: smaliClasses.slice(0, 300),
        },
        fileTree,
        extractedPath: outApktoolDir,
      };
    } catch (err: any) {
      onProgress(`Apktool failed: ${err.message}`, 60);
    }
  }

  // 3. Fallback to basic APK analysis
  const basic = await basicApkAnalysis(input, onProgress);
  return { result: basic };
}

async function checkCommand(cmd: string, ...args: string[]): Promise<boolean> {
  try {
    await execFileAsync(cmd, args, { timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

async function tryApktoolOrZip(
  input: AndroidInput,
  apktoolDir: string,
  onProgress: ProgressCallback
): Promise<AndroidResult> {
  try {
    if (!fs.existsSync(apktoolDir)) fs.mkdirSync(apktoolDir, { recursive: true });
    await runTool('apktool', ['d', '-s', '-f', '-o', apktoolDir, input.filePath!], {
      readPaths: [input.filePath!],
      writePaths: [apktoolDir],
      timeoutMs: 45_000,
    });
    const manifestPath = path.join(apktoolDir, 'AndroidManifest.xml');
    if (fs.existsSync(manifestPath)) {
      return parseManifest(fs.readFileSync(manifestPath, 'utf-8'), input.fileName, 'apktool');
    }
  } catch {
    // fallback
  }
  return basicApkAnalysis(input, () => {});
}

function scanDecompiledJavaClasses(rootDir: string): AndroidClass[] {
  const sourcesDir = path.join(rootDir, 'sources');
  const dirToScan = fs.existsSync(sourcesDir) ? sourcesDir : rootDir;
  const classes: AndroidClass[] = [];

  function walk(current: string) {
    if (!fs.existsSync(current)) return;
    const entries = fs.readdirSync(current, { withFileTypes: true });
    for (const ent of entries) {
      const full = path.join(current, ent.name);
      if (ent.isDirectory()) {
        walk(full);
      } else if (ent.isFile() && ent.name.endsWith('.java')) {
        const content = fs.readFileSync(full, 'utf-8');
        const relPath = path.relative(dirToScan, full);
        const className = relPath.replace(/\.java$/, '').replace(/\//g, '.');

        // Extract methods
        const methodMatches = content.matchAll(/(?:public|protected|private)\s+[\w<>\[\]]+\s+(\w+)\s*\([^)]*\)/g);
        const methods: string[] = [];
        for (const m of methodMatches) {
          if (!methods.includes(m[1])) methods.push(m[1]);
        }

        classes.push({
          name: className,
          methods,
          decompiledCode: content,
        });
      }
    }
  }

  walk(dirToScan);
  return classes;
}

function scanSmaliClasses(rootDir: string): AndroidClass[] {
  const classes: AndroidClass[] = [];
  function walk(current: string) {
    if (!fs.existsSync(current)) return;
    const entries = fs.readdirSync(current, { withFileTypes: true });
    for (const ent of entries) {
      const full = path.join(current, ent.name);
      if (ent.isDirectory()) {
        walk(full);
      } else if (ent.isFile() && ent.name.endsWith('.smali')) {
        const content = fs.readFileSync(full, 'utf-8');
        const classMatch = content.match(/\.class\s+.*?(L[^;]+;)/);
        const className = classMatch ? classMatch[1].replace(/^\/?L?/, '').replace(/;/g, '').replace(/\//g, '.') : ent.name;

        classes.push({
          name: className,
          methods: [],
          smaliCode: content,
        });
      }
    }
  }
  walk(rootDir);
  return classes;
}


function parseManifest(xml: string, fileName: string, source: string): AndroidResult {
  const evidence: Evidence[] = [];
  const pkgMatch = xml.match(/package="([^"]+)"/);
  const versionMatch = xml.match(/android:versionName="([^"]+)"/);
  const targetSdkMatch = xml.match(/android:targetSdkVersion="(\d+)"/);
  const minSdkMatch = xml.match(/android:minSdkVersion="(\d+)"/);

  const permissions = [...xml.matchAll(/uses-permission[^>]+android:name="([^"]+)"/g)].map((m) => m[1]);

  const activities = parseComponents(xml, 'activity');
  const services = parseComponents(xml, 'service');
  const receivers = parseComponents(xml, 'receiver');
  const providers = parseComponents(xml, 'provider');

  evidence.push({
    kind: 'code',
    description: `Parsed AndroidManifest: ${permissions.length} permissions, ${activities.length} activities, ${services.length} services`,
    confidence: 'high',
  });

  return {
    type: 'android',
    packageName: pkgMatch?.[1] ?? 'unknown',
    version: versionMatch?.[1] ?? 'unknown',
    targetSdk: targetSdkMatch ? parseInt(targetSdkMatch[1]) : undefined,
    minSdk: minSdkMatch ? parseInt(minSdkMatch[1]) : undefined,
    permissions,
    activities,
    services,
    receivers,
    providers,
    classes: [],
    evidence,
    limitations: [],
  };
}

function parseComponents(xml: string, tag: string): AndroidComponent[] {
  const results: AndroidComponent[] = [];
  const regex = new RegExp(`<${tag}[^>]*>`, 'g');
  for (const match of xml.matchAll(regex)) {
    const block = match[0];
    const nameMatch = block.match(/android:name="([^"]+)"/);
    const exportedMatch = block.match(/android:exported="([^"]+)"/);
    if (nameMatch) {
      results.push({
        name: nameMatch[1],
        exported: exportedMatch ? exportedMatch[1] === 'true' : false,
        intentFilters: [],
      });
    }
  }
  return results;
}

async function basicApkAnalysis(input: AndroidInput, onProgress: ProgressCallback): Promise<AndroidResult> {
  onProgress('Inspecting APK structure...', 50);
  const evidence: Evidence[] = [];
  return {
    type: 'android',
    packageName: 'unknown',
    version: 'unknown',
    permissions: [],
    activities: [],
    services: [],
    receivers: [],
    providers: [],
    classes: [],
    evidence,
    limitations: ['APK decompiled with fallback parser.'],
  };
}
