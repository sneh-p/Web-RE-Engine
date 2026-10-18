import fs from 'fs';
import zlib from 'zlib';

export type DetectedAnalysisType = 'android' | 'dotnet' | 'native' | 'javascript' | 'extension';

export function detectFileType(filePath: string, originalName: string): DetectedAnalysisType | null {
  let fd: number | undefined;
  try {
    fd = fs.openSync(filePath, 'r');
    const stat = fs.fstatSync(fd);
    const headBuf = Buffer.alloc(Math.min(stat.size, 4096));
    fs.readSync(fd, headBuf, 0, headBuf.length, 0);

    // 1. Check ZIP format (PK\x03\x04 or PK\x05\x06 or PK\x07\x08)
    if (
      headBuf.length >= 4 &&
      headBuf[0] === 0x50 &&
      headBuf[1] === 0x4b &&
      (headBuf[2] === 0x03 || headBuf[2] === 0x05 || headBuf[2] === 0x07)
    ) {
      const entries = readZipEntries(fd, stat.size);
      if (entries.some((e) => e.name === 'AndroidManifest.xml' || e.name.endsWith('/AndroidManifest.xml'))) {
        return 'android';
      }
      // XPI / zipped extension: manifest.json at the root or inside one top-level folder, with manifest_version
      const manifest = entries.find((e) => /^([^/]+\/)?manifest\.json$/.test(e.name));
      if (manifest && /"manifest_version"\s*:/.test(readZipEntryText(fd, manifest) ?? '')) {
        return 'extension';
      }
      return 'javascript';
    }

    // Chrome/Edge extension package (CRX2/CRX3)
    if (headBuf.length >= 4 && headBuf.toString('latin1', 0, 4) === 'Cr24') {
      return 'extension';
    }

    // 2. Check PE format (MZ header and PE signature)
    if (headBuf.length >= 64 && headBuf[0] === 0x4d && headBuf[1] === 0x5a) {
      const e_lfanew = headBuf.readUInt32LE(0x3c);
      let peBuf = headBuf;
      if (e_lfanew + 264 > headBuf.length && stat.size > headBuf.length) {
        peBuf = Buffer.alloc(Math.min(stat.size, e_lfanew + 512));
        fs.readSync(fd, peBuf, 0, peBuf.length, 0);
      }
      if (e_lfanew + 24 <= peBuf.length && peBuf.readUInt32LE(e_lfanew) === 0x00004550) {
        const optHeaderOffset = e_lfanew + 24;
        const magic = peBuf.readUInt16LE(optHeaderOffset);
        let rvaCountOffset = 0;
        let dataDirsOffset = 0;
        if (magic === 0x10b) {
          // PE32
          rvaCountOffset = optHeaderOffset + 92;
          dataDirsOffset = optHeaderOffset + 96;
        } else if (magic === 0x20b) {
          // PE32+
          rvaCountOffset = optHeaderOffset + 108;
          dataDirsOffset = optHeaderOffset + 112;
        }
        if (dataDirsOffset > 0 && rvaCountOffset + 4 <= peBuf.length) {
          const rvaCount = peBuf.readUInt32LE(rvaCountOffset);
          if (rvaCount > 14) {
            const cliDirOffset = dataDirsOffset + 14 * 8;
            if (cliDirOffset + 8 <= peBuf.length) {
              const va = peBuf.readUInt32LE(cliDirOffset);
              const sz = peBuf.readUInt32LE(cliDirOffset + 4);
              if (va !== 0 || sz !== 0) {
                return 'dotnet';
              }
            }
          }
        }
        return 'native';
      }
    }

    // 3. Check ELF format (\x7fELF)
    if (
      headBuf.length >= 4 &&
      headBuf[0] === 0x7f &&
      headBuf[1] === 0x45 &&
      headBuf[2] === 0x4c &&
      headBuf[3] === 0x46
    ) {
      return 'native';
    }

    // 4. Check Mach-O format
    if (headBuf.length >= 4) {
      const m = headBuf.readUInt32BE(0);
      if (
        m === 0xfeedface ||
        m === 0xfeedfacf ||
        m === 0xcafebabe ||
        m === 0xcafebabf ||
        m === 0xcefaedfe ||
        m === 0xcffaedfe ||
        m === 0xbebafeca ||
        m === 0xbfbafeca
      ) {
        return 'native';
      }
    }

    // 5. Check ASAR
    if (originalName.toLowerCase().endsWith('.asar')) {
      return 'javascript';
    }
    if (
      headBuf.length >= 16 &&
      headBuf.readUInt32LE(0) === 4 &&
      headBuf.toString('utf8', 0, 100).includes('"files":')
    ) {
      return 'javascript';
    }

    // 6. Tar archives (plain 'ustar' header, or gzip/bzip2/xz with a tar extension)
    if (headBuf.length >= 262 && headBuf.toString('latin1', 257, 262) === 'ustar') {
      return 'javascript';
    }
    if (/\.(tar\.gz|tgz|tar\.bz2|tar\.xz)$/i.test(originalName)) {
      return 'javascript';
    }

    // 7. Check JS/TS extensions or node shebang
    if (/\.(js|mjs|cjs|ts)$/i.test(originalName)) {
      return 'javascript';
    }
    const headText = headBuf.toString('utf8');
    if (headText.startsWith('#!') && headText.slice(0, 100).includes('node')) {
      return 'javascript';
    }

    return null;
  } finally {
    if (fd !== undefined) {
      fs.closeSync(fd);
    }
  }
}

interface ZipEntry {
  name: string;
  method: number;
  compressedSize: number;
  localHeaderOffset: number;
}

// Read the central directory without extracting anything
function readZipEntries(fd: number, fileSize: number): ZipEntry[] {
  const readSize = Math.min(fileSize, 65557);
  const buf = Buffer.alloc(readSize);
  fs.readSync(fd, buf, 0, readSize, fileSize - readSize);
  let eocdOffset = -1;
  for (let i = buf.length - 22; i >= 0; i--) {
    if (buf[i] === 0x50 && buf[i + 1] === 0x4b && buf[i + 2] === 0x05 && buf[i + 3] === 0x06) {
      eocdOffset = i;
      break;
    }
  }
  if (eocdOffset === -1) return [];
  const cdOffset = buf.readUInt32LE(eocdOffset + 16);
  const cdSize = buf.readUInt32LE(eocdOffset + 12);
  // Malformed/hostile archives can declare a central directory larger than the file
  if (cdSize === 0 || cdOffset + cdSize > fileSize) return [];
  const cdBuf = Buffer.alloc(cdSize);
  fs.readSync(fd, cdBuf, 0, cdSize, cdOffset);

  const entries: ZipEntry[] = [];
  let pos = 0;
  while (pos + 46 <= cdBuf.length) {
    if (cdBuf.readUInt32LE(pos) !== 0x02014b50) break;
    const nameLen = cdBuf.readUInt16LE(pos + 28);
    const extraLen = cdBuf.readUInt16LE(pos + 30);
    const commentLen = cdBuf.readUInt16LE(pos + 32);
    entries.push({
      name: cdBuf.toString('utf8', pos + 46, pos + 46 + nameLen),
      method: cdBuf.readUInt16LE(pos + 10),
      compressedSize: cdBuf.readUInt32LE(pos + 20),
      localHeaderOffset: cdBuf.readUInt32LE(pos + 42),
    });
    pos += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

// Decompress one small entry (stored or deflated), e.g. manifest.json; null if unreadable or too big
function readZipEntryText(fd: number, entry: ZipEntry): string | null {
  if (entry.compressedSize > 1024 * 1024 || (entry.method !== 0 && entry.method !== 8)) return null;
  const local = Buffer.alloc(30);
  fs.readSync(fd, local, 0, 30, entry.localHeaderOffset);
  if (local.readUInt32LE(0) !== 0x04034b50) return null;
  const dataOffset = entry.localHeaderOffset + 30 + local.readUInt16LE(26) + local.readUInt16LE(28);
  const data = Buffer.alloc(entry.compressedSize);
  fs.readSync(fd, data, 0, data.length, dataOffset);
  try {
    const raw = entry.method === 0 ? data : zlib.inflateRawSync(data, { maxOutputLength: 4 * 1024 * 1024 });
    return raw.toString('utf8');
  } catch {
    return null;
  }
}
