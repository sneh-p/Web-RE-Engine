import fs from 'fs';
import path from 'path';
import zlib from 'zlib';

const PYI_MAGIC = Buffer.from([0x4d, 0x45, 0x49, 0x0c, 0x0b, 0x0a, 0x0b, 0x0e]);

export interface PyInstallerExtractResult {
  entryPoints: string[];
  modules: string[];
  extractedCount: number;
  totalSize: number;
  pythonVersion?: string;
  limitations: string[];
}

const MAX_EXTRACTED_FILES = 2000;
const MAX_TOTAL_WRITTEN = 500 * 1024 * 1024; // 500MB
const MAX_ENTRY_DECOMPRESSED = 200 * 1024 * 1024; // 200MB

function sanitizePath(rawName: string, outDir: string): string | null {
  // Normalize slashes
  let clean = rawName.replace(/\\/g, '/').trim();
  // Remove drive letters like C:
  clean = clean.replace(/^[a-zA-Z]:/, '');
  // Remove leading slashes
  clean = clean.replace(/^\/+/, '');
  const parts = clean.split('/').filter((p) => p !== '' && p !== '.');
  if (parts.length === 0 || parts.some((p) => p === '..')) return null;

  const resolvedOut = path.resolve(outDir);
  const resolvedDest = path.resolve(resolvedOut, ...parts);
  if (!resolvedDest.startsWith(resolvedOut + path.sep)) return null;

  return resolvedDest;
}

function extractPrintableStrings(buf: Buffer, minLen = 6): string {
  const strings: string[] = [];
  let current = '';
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i];
    if (b >= 0x20 && b <= 0x7e) {
      current += String.fromCharCode(b);
    } else {
      if (current.length >= minLen) {
        strings.push(current);
      }
      current = '';
    }
  }
  if (current.length >= minLen) {
    strings.push(current);
  }
  return strings.join('\n');
}

/**
 * Extracts a PyInstaller CArchive from an executable file.
 */
export async function extractPyInstaller(
  filePath: string,
  outDir: string
): Promise<PyInstallerExtractResult> {
  const limitations: string[] = [];
  const entryPoints: string[] = [];
  const modules: string[] = [];
  let extractedCount = 0;
  let totalSize = 0;
  let pythonVersion: string | undefined;

  if (!fs.existsSync(filePath)) {
    throw new Error(`File not found: ${filePath}`);
  }

  const stat = fs.statSync(filePath);
  const fileSize = stat.size;

  if (!fs.existsSync(outDir)) {
    fs.mkdirSync(outDir, { recursive: true });
  }

  const fd = fs.openSync(filePath, 'r');
  try {
    // 1. Locate cookie near end of file
    const searchLen = Math.min(1024 * 1024, fileSize);
    const searchStart = fileSize - searchLen;
    const searchBuf = Buffer.alloc(searchLen);
    fs.readSync(fd, searchBuf, 0, searchLen, searchStart);

    const magicIdx = searchBuf.lastIndexOf(PYI_MAGIC);
    if (magicIdx === -1) {
      throw new Error('PyInstaller cookie signature not found');
    }

    const cookieOffset = searchStart + magicIdx;
    const cookieDataLen = Math.min(88, fileSize - cookieOffset);
    const cookieBuf = Buffer.alloc(cookieDataLen);
    fs.readSync(fd, cookieBuf, 0, cookieDataLen, cookieOffset);

    if (cookieDataLen < 24) {
      throw new Error('PyInstaller cookie truncated');
    }

    const pkgLen = cookieBuf.readUInt32BE(8);
    const tocPos = cookieBuf.readUInt32BE(12);
    const tocLen = cookieBuf.readUInt32BE(16);
    const pyvers = cookieBuf.readUInt32BE(20);

    // Determine cookie size: 88 bytes for PyInstaller 2.1+, 24 bytes for older
    const is88ByteCookie = cookieDataLen >= 88 && cookieOffset + 88 <= fileSize;
    const cookieSize = is88ByteCookie ? 88 : 24;

    if (pyvers > 0) {
      if (pyvers >= 100) {
        pythonVersion = `${Math.floor(pyvers / 100)}.${pyvers % 100}`;
      } else {
        pythonVersion = `${Math.floor(pyvers / 10)}.${pyvers % 10}`;
      }
    }

    if (is88ByteCookie) {
      const pylib = cookieBuf.subarray(24, 88).toString('latin1').replace(/\0.*$/, '').trim();
      const m = pylib.match(/python(\d+)\.dll/i);
      if (m && m[1].length >= 2) {
        pythonVersion = `${m[1][0]}.${m[1].slice(1)}`;
      }
    }

    // 2. Locate CArchive beginning
    // In PyInstaller: archiveOffset = cookieOffset + cookieSize - pkgLen
    let archiveOffset = cookieOffset + cookieSize - pkgLen;
    if (archiveOffset < 0 || archiveOffset >= fileSize) {
      archiveOffset = Math.max(0, fileSize - pkgLen);
    }

    // 3. Read TOC
    const tocAbsoluteOffset = archiveOffset + tocPos;
    if (tocAbsoluteOffset < 0 || tocAbsoluteOffset + tocLen > fileSize) {
      throw new Error(`Invalid PyInstaller TOC offset: ${tocAbsoluteOffset} (file size ${fileSize})`);
    }

    const tocBuf = Buffer.alloc(tocLen);
    fs.readSync(fd, tocBuf, 0, tocLen, tocAbsoluteOffset);

    // 4. Parse TOC entries
    let ptr = 0;
    while (ptr < tocLen) {
      if (ptr + 18 > tocLen) break;

      const structLen = tocBuf.readInt32BE(ptr);
      if (structLen <= 0 || ptr + structLen > tocLen) break;

      const dpos = tocBuf.readInt32BE(ptr + 4);
      const dlen = tocBuf.readInt32BE(ptr + 8);
      const ulen = tocBuf.readInt32BE(ptr + 12);
      const flag = tocBuf.readUInt8(ptr + 16);
      const typeCode = String.fromCharCode(tocBuf.readUInt8(ptr + 17));

      const rawNameBuf = tocBuf.subarray(ptr + 18, ptr + structLen);
      const nullIdx = rawNameBuf.indexOf(0);
      const rawName = (nullIdx !== -1 ? rawNameBuf.subarray(0, nullIdx) : rawNameBuf)
        .toString('utf8')
        .trim();

      ptr += structLen;

      // Classify type
      if (typeCode === 's') {
        entryPoints.push(rawName);
      } else if (typeCode === 'm') {
        modules.push(rawName);
      } else if (typeCode === 'z') {
        modules.push(rawName);
      }

      // Check option / directory markers
      if (typeCode === 'o' || dlen <= 0) {
        continue;
      }

      // Check safe destination path
      const destPath = sanitizePath(rawName, outDir);
      if (!destPath) {
        continue;
      }

      // Safety checks:
      if (extractedCount >= MAX_EXTRACTED_FILES) {
        limitations.push(`Extraction limit reached: maximum ${MAX_EXTRACTED_FILES} files extracted`);
        break;
      }

      if (ulen > MAX_ENTRY_DECOMPRESSED) {
        limitations.push(`Skipped entry "${rawName}": decompressed size (${ulen} bytes) exceeds 200MB limit`);
        continue;
      }

      if (totalSize + (ulen > 0 ? ulen : dlen) > MAX_TOTAL_WRITTEN) {
        limitations.push(`Extraction limit reached: maximum 500MB total written limit exceeded`);
        break;
      }

      // Read entry data
      const entryAbsolutePos = archiveOffset + dpos;
      if (entryAbsolutePos < 0 || entryAbsolutePos + dlen > fileSize) {
        continue;
      }

      const compressedBuf = Buffer.alloc(dlen);
      fs.readSync(fd, compressedBuf, 0, dlen, entryAbsolutePos);

      let outBuffer: Buffer;
      if (flag & 1) {
        try {
          outBuffer = zlib.inflateSync(compressedBuf);
        } catch {
          try {
            outBuffer = zlib.inflateRawSync(compressedBuf);
          } catch {
            outBuffer = compressedBuf;
          }
        }
      } else {
        outBuffer = compressedBuf;
      }

      // Write extracted file
      fs.mkdirSync(path.dirname(destPath), { recursive: true });
      fs.writeFileSync(destPath, outBuffer);
      extractedCount++;
      totalSize += outBuffer.length;

      // For entry-point scripts: extract printable strings (min length 6) as <name>.strings.txt
      if (typeCode === 's') {
        const strings = extractPrintableStrings(outBuffer, 6);
        const stringsFileName = `${path.basename(destPath)}.strings.txt`;
        const stringsPath = path.join(path.dirname(destPath), stringsFileName);
        fs.writeFileSync(stringsPath, strings, 'utf8');
        extractedCount++;
        totalSize += Buffer.byteLength(strings, 'utf8');
      }
    }

    // Write a manifest summary for CodeExplorer
    const manifestLines = [
      `PyInstaller CArchive Manifest`,
      `Python Version: ${pythonVersion || 'Unknown'}`,
      `Total Extracted Files: ${extractedCount}`,
      `Entry-point scripts:`,
      ...entryPoints.map((e) => `  - ${e}`),
      `Modules & Libraries:`,
      ...modules.map((m) => `  - ${m}`),
    ];
    fs.writeFileSync(path.join(outDir, 'pyinstaller_manifest.txt'), manifestLines.join('\n'), 'utf8');
    extractedCount++;
  } finally {
    fs.closeSync(fd);
  }

  return {
    entryPoints,
    modules,
    extractedCount,
    totalSize,
    pythonVersion,
    limitations,
  };
}
