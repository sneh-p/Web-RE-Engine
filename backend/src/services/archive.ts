import fs from 'fs';
import path from 'path';
import { runTool } from './sandbox.js';

// Shared limits for every extractor, so one hostile archive cannot fill the disk
export const MAX_EXTRACTED_FILES = 2000;
export const MAX_TOTAL_BYTES = 500 * 1024 * 1024;
export const MAX_ENTRY_BYTES = 200 * 1024 * 1024;

export interface ExtractResult {
  extractedCount: number;
  limitations: string[];
}

function addOnce(limitations: string[], message: string) {
  if (!limitations.includes(message)) limitations.push(message);
}

// Remove symlinks and anything over the limits after an external tool has extracted
export function enforceExtractionLimits(outDir: string, limitations: string[]): number {
  let count = 0;
  let totalBytes = 0;

  function walk(dir: string) {
    if (!fs.existsSync(dir)) return;
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, ent.name);
      if (ent.isSymbolicLink()) {
        // Archive symlinks could point outside the workspace and be read via /api/files
        fs.rmSync(full, { force: true });
        addOnce(limitations, 'Removed symbolic links from extracted archive');
      } else if (ent.isDirectory()) {
        walk(full);
      } else if (ent.isFile()) {
        const size = fs.statSync(full).size;
        if (size > MAX_ENTRY_BYTES) {
          fs.rmSync(full, { force: true });
          limitations.push(`Removed "${ent.name}": size (${size} bytes) exceeds 200MB limit`);
        } else if (count >= MAX_EXTRACTED_FILES) {
          fs.rmSync(full, { force: true });
          addOnce(limitations, `Extraction capped at ${MAX_EXTRACTED_FILES} files`);
        } else if (totalBytes + size > MAX_TOTAL_BYTES) {
          fs.rmSync(full, { force: true });
          addOnce(limitations, 'Extraction capped at 500MB total written');
        } else {
          count++;
          totalBytes += size;
        }
      } else {
        // FIFOs, devices, sockets
        fs.rmSync(full, { force: true });
      }
    }
  }

  walk(outDir);
  return count;
}

function exceedsLimits(entryCount: number, sizes: number[]): boolean {
  const total = sizes.reduce((a, b) => a + b, 0);
  return entryCount > MAX_EXTRACTED_FILES || total > MAX_TOTAL_BYTES || sizes.some((s) => s > MAX_ENTRY_BYTES);
}

// 7z handles zip, 7z, NSIS, Inno-style installers and SFX archives
export async function extractWith7z(filePath: string, outDir: string): Promise<ExtractResult> {
  const limitations: string[] = [];
  fs.mkdirSync(outDir, { recursive: true });

  // Check declared sizes before writing anything, so a decompression bomb never hits the disk
  try {
    const { stdout: listing } = await runTool('7z', ['l', '-slt', filePath], {
      readPaths: [filePath],
      timeoutMs: 60_000,
      maxBuffer: 100 * 1024 * 1024,
    });
    // The first "Path = " belongs to the archive itself; entries follow the "----------" separator
    const body = listing.split(/^-{10}\s*$/m).slice(1).join('\n');
    const sizes = [...body.matchAll(/^Size = (\d+)$/gm)].map((m) => Number(m[1]));
    const entryCount = (body.match(/^Path = /gm) ?? []).length;
    if (exceedsLimits(entryCount, sizes)) {
      limitations.push(
        `Extraction skipped: archive declares ${entryCount} entries / ${sizes.reduce((a, b) => a + b, 0)} bytes, exceeding limits (2000 files, 500MB total, 200MB per file)`
      );
      return { extractedCount: 0, limitations };
    }
  } catch (err: any) {
    limitations.push(`Archive listing failed, extraction skipped: ${err.message || 'unknown error'}`);
    return { extractedCount: 0, limitations };
  }

  try {
    await runTool('7z', ['x', '-y', '-snl-', `-o${outDir}`, filePath], {
      readPaths: [filePath],
      writePaths: [outDir],
      timeoutMs: 120_000,
      maxBuffer: 100 * 1024 * 1024,
    });
  } catch (err: any) {
    limitations.push(`7z extraction warning: ${err.message || 'extraction incomplete'}`);
  }

  return { extractedCount: enforceExtractionLimits(outDir, limitations), limitations };
}

// GNU tar auto-detects gzip/bzip2/xz compression when reading
export async function extractTar(filePath: string, outDir: string): Promise<ExtractResult> {
  const limitations: string[] = [];
  fs.mkdirSync(outDir, { recursive: true });

  let listing: string;
  try {
    ({ stdout: listing } = await runTool('tar', ['-tvf', filePath], {
      readPaths: [filePath],
      timeoutMs: 60_000,
      maxBuffer: 100 * 1024 * 1024,
    }));
  } catch (err: any) {
    limitations.push(`tar listing failed, extraction skipped: ${err.message || 'unknown error'}`);
    return { extractedCount: 0, limitations };
  }

  // "-rw-r--r-- user/group 1234 2026-01-01 12:00 path/to/file"
  const sizes: number[] = [];
  let entryCount = 0;
  for (const line of listing.split('\n')) {
    if (!line.trim()) continue;
    const m = line.match(/^(\S)\S*\s+\S+\s+(\d+)\s+\S+\s+\S+\s+(.*)$/);
    if (!m) continue;
    const [, type, size, name] = m;
    if (type !== '-' && type !== 'd') {
      limitations.push(`Extraction refused: archive contains a link or special file (${name})`);
      return { extractedCount: 0, limitations };
    }
    if (name.startsWith('/') || name.split('/').includes('..')) {
      limitations.push(`Extraction refused: archive entry escapes the target directory (${name})`);
      return { extractedCount: 0, limitations };
    }
    entryCount++;
    sizes.push(Number(size));
  }
  if (exceedsLimits(entryCount, sizes)) {
    limitations.push(`Extraction skipped: archive declares ${entryCount} entries, exceeding limits (2000 files, 500MB total, 200MB per file)`);
    return { extractedCount: 0, limitations };
  }

  try {
    await runTool('tar', ['-xf', filePath, '-C', outDir, '--no-same-owner', '--no-same-permissions'], {
      readPaths: [filePath],
      writePaths: [outDir],
      timeoutMs: 120_000,
    });
  } catch (err: any) {
    limitations.push(`tar extraction warning: ${err.message || 'extraction incomplete'}`);
  }

  return { extractedCount: enforceExtractionLimits(outDir, limitations), limitations };
}

interface AsarEntry {
  files?: Record<string, AsarEntry>;
  size?: number;
  offset?: string;
  unpacked?: boolean;
  link?: string;
}

const safeSegment = (name: string) => name !== '' && name !== '.' && name !== '..' && !/[\\/\0]/.test(name);

// Electron .asar: uint32 4, uint32 headerPickleSize, then a pickle holding the JSON
// header (uint32 payloadSize, uint32 jsonLength, json). File data starts at 8 + headerPickleSize.
export function extractAsar(filePath: string, outDir: string): ExtractResult {
  const limitations: string[] = [];
  const fd = fs.openSync(filePath, 'r');
  try {
    const fileSize = fs.fstatSync(fd).size;
    const head = Buffer.alloc(16);
    fs.readSync(fd, head, 0, 16, 0);
    const headerPickleSize = head.readUInt32LE(4);
    const jsonLength = head.readUInt32LE(12);
    if (head.readUInt32LE(0) !== 4 || jsonLength > 64 * 1024 * 1024 || 16 + jsonLength > fileSize) {
      throw new Error('Not a valid asar archive');
    }

    const jsonBuf = Buffer.alloc(jsonLength);
    fs.readSync(fd, jsonBuf, 0, jsonLength, 16);
    const header = JSON.parse(jsonBuf.toString('utf8')) as AsarEntry;
    const dataStart = 8 + headerPickleSize;

    let count = 0;
    let total = 0;
    let skippedUnpacked = 0;
    let skippedLinks = 0;
    let stop = false;

    const walk = (entry: AsarEntry, rel: string[]) => {
      for (const [name, child] of Object.entries(entry.files ?? {})) {
        if (stop) return;
        if (!safeSegment(name)) {
          addOnce(limitations, `Skipped entries with unsafe names (e.g. "${name}")`);
          continue;
        }
        const parts = [...rel, name];
        if (child.files) {
          fs.mkdirSync(path.join(outDir, ...parts), { recursive: true });
          walk(child, parts);
        } else if (child.link !== undefined) {
          skippedLinks++;
        } else if (child.unpacked) {
          // Stored next to the archive in app.asar.unpacked/, which was not uploaded
          skippedUnpacked++;
        } else {
          const size = child.size ?? 0;
          const offset = Number(child.offset ?? NaN);
          if (!Number.isFinite(offset) || dataStart + offset + size > fileSize) {
            addOnce(limitations, 'Skipped entries pointing outside the archive');
            continue;
          }
          if (size > MAX_ENTRY_BYTES) {
            limitations.push(`Skipped "${parts.join('/')}": size (${size} bytes) exceeds 200MB limit`);
            continue;
          }
          if (count >= MAX_EXTRACTED_FILES || total + size > MAX_TOTAL_BYTES) {
            addOnce(limitations, 'Extraction capped (2000 files / 500MB total)');
            stop = true;
            return;
          }
          const dest = path.join(outDir, ...parts);
          fs.mkdirSync(path.dirname(dest), { recursive: true });
          const buf = Buffer.alloc(size);
          if (size > 0) fs.readSync(fd, buf, 0, size, dataStart + offset);
          fs.writeFileSync(dest, buf);
          count++;
          total += size;
        }
      }
    };

    fs.mkdirSync(outDir, { recursive: true });
    walk(header, []);
    if (skippedUnpacked > 0) {
      limitations.push(`${skippedUnpacked} files are stored outside the archive (app.asar.unpacked) and were not uploaded`);
    }
    if (skippedLinks > 0) limitations.push(`Skipped ${skippedLinks} symbolic links`);
    return { extractedCount: count, limitations };
  } finally {
    fs.closeSync(fd);
  }
}

const SIZE_UNITS: Record<string, number> = { B: 1, KiB: 1024, MiB: 1024 ** 2, GiB: 1024 ** 3 };

// Inno Setup installers: 7z only sees the setup stub's PE sections, innoextract reads the real payload
export async function extractInno(filePath: string, outDir: string): Promise<ExtractResult> {
  const limitations: string[] = [];
  fs.mkdirSync(outDir, { recursive: true });

  // Listing lines look like:  - "app/main.exe" (2.5 MiB)
  let listing: string;
  try {
    ({ stdout: listing } = await runTool('innoextract', ['--list', '--color=off', filePath], {
      readPaths: [filePath],
      timeoutMs: 120_000,
      maxBuffer: 50 * 1024 * 1024,
    }));
  } catch (err: any) {
    throw new Error(`innoextract could not read the installer: ${String(err.stderr || err.message).split('\n').filter(Boolean).pop()}`);
  }

  const sizes: number[] = [];
  for (const m of listing.matchAll(/^ - "(.+)" \(([\d.]+) (B|KiB|MiB|GiB)\)/gm)) {
    const name = m[1];
    if (name.startsWith('/') || name.split(/[\\/]/).includes('..')) {
      limitations.push(`Extraction refused: installer entry escapes the target directory (${name})`);
      return { extractedCount: 0, limitations };
    }
    sizes.push(Math.round(Number(m[2]) * SIZE_UNITS[m[3]]));
  }
  if (exceedsLimits(sizes.length, sizes)) {
    limitations.push(
      `Extraction skipped: installer contains ${sizes.length} files / ${sizes.reduce((a, b) => a + b, 0)} bytes, exceeding limits (2000 files, 500MB total, 200MB per file)`
    );
    return { extractedCount: 0, limitations };
  }

  try {
    await runTool('innoextract', ['--extract', '--silent', '--collisions=rename', '--output-dir', outDir, filePath], {
      readPaths: [filePath],
      writePaths: [outDir],
      timeoutMs: 300_000,
    });
  } catch (err: any) {
    limitations.push(`innoextract warning: ${String(err.stderr || err.message).split('\n').filter(Boolean).pop()}`);
  }

  return { extractedCount: enforceExtractionLimits(outDir, limitations), limitations };
}
