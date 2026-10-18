import fs from 'fs';
import type { PackerInfo } from '../../../shared/types.js';

const PYI_MAGIC = Buffer.from([0x4d, 0x45, 0x49, 0x0c, 0x0b, 0x0a, 0x0b, 0x0e]); // MEI\x0c\x0b\x0a\x0b\x0e
const SEVEN_ZIP_MAGIC = Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]); // 7z\xBC\xAF\x27\x1C
const ZIP_MAGIC = Buffer.from([0x50, 0x4b, 0x03, 0x04]); // PK\x03\x04
const UPX_MAGIC = Buffer.from('UPX!');
const INNO_SIG = Buffer.from('Inno Setup Setup Data');
const NSIS_SIG1 = Buffer.from('Nullsoft.NSIS');
const NSIS_SIG2 = Buffer.from('NullsoftInst');

interface PeInfo {
  isPe: boolean;
  sections: Array<{ name: string; rawOffset: number; rawSize: number }>;
  lastSectionEnd: number;
  hasOverlay: boolean;
  overlayOffset: number;
  overlaySize: number;
  hasUpxSection: boolean;
}

/**
 * Parses PE headers and section headers from the file head without loading the whole file.
 */
function inspectPe(fd: number, fileSize: number): PeInfo {
  const defaultRes: PeInfo = {
    isPe: false,
    sections: [],
    lastSectionEnd: 0,
    hasOverlay: false,
    overlayOffset: 0,
    overlaySize: 0,
    hasUpxSection: false,
  };

  if (fileSize < 0x100) return defaultRes;

  const headBuf = Buffer.alloc(Math.min(65536, fileSize));
  fs.readSync(fd, headBuf, 0, headBuf.length, 0);

  if (headBuf[0] !== 0x4d || headBuf[1] !== 0x5a) return defaultRes; // Not MZ

  const peOffset = headBuf.readUInt32LE(0x3c);
  if (peOffset + 24 > headBuf.length) return defaultRes;
  if (headBuf.readUInt32LE(peOffset) !== 0x00004550) return defaultRes; // Not PE\0\0

  const numSections = headBuf.readUInt16LE(peOffset + 6);
  const optHeaderSize = headBuf.readUInt16LE(peOffset + 20);
  let secHeaderOffset = peOffset + 24 + optHeaderSize;

  // If section table extends beyond headBuf, read more
  const neededBytes = secHeaderOffset + numSections * 40;
  let secBuf = headBuf;
  if (neededBytes > headBuf.length && neededBytes <= fileSize) {
    secBuf = Buffer.alloc(neededBytes);
    fs.readSync(fd, secBuf, 0, secBuf.length, 0);
  }

  const sections: Array<{ name: string; rawOffset: number; rawSize: number }> = [];
  let lastSectionEnd = 0;
  let hasUpxSection = false;

  for (let i = 0; i < numSections; i++) {
    if (secHeaderOffset + 40 > secBuf.length) break;
    const name = secBuf.subarray(secHeaderOffset, secHeaderOffset + 8).toString('utf8').replace(/\0.*$/, '').trim();
    const rawSize = secBuf.readUInt32LE(secHeaderOffset + 16);
    const rawOffset = secBuf.readUInt32LE(secHeaderOffset + 20);

    if (name.toUpperCase().includes('UPX')) {
      hasUpxSection = true;
    }

    if (rawOffset > 0 && rawSize > 0) {
      const end = rawOffset + rawSize;
      if (end > lastSectionEnd) {
        lastSectionEnd = end;
      }
    }

    sections.push({ name, rawOffset, rawSize });
    secHeaderOffset += 40;
  }

  const hasOverlay = fileSize > lastSectionEnd && lastSectionEnd > 0;
  const overlayOffset = lastSectionEnd;
  const overlaySize = hasOverlay ? fileSize - lastSectionEnd : 0;

  return {
    isPe: true,
    sections,
    lastSectionEnd,
    hasOverlay,
    overlayOffset,
    overlaySize,
    hasUpxSection,
  };
}

/**
 * Searches for a sequence of bytes in a region of a file using chunked reads.
 */
function searchInFile(
  fd: number,
  target: Buffer,
  start: number,
  length: number,
  chunkSize = 65536
): number {
  if (length <= 0 || target.length === 0) return -1;
  const overlap = target.length - 1;
  let currentPos = start;
  const endPos = start + length;

  let prevOverlapBuf = Buffer.alloc(0);

  while (currentPos < endPos) {
    const toRead = Math.min(chunkSize, endPos - currentPos);
    const chunkBuf = Buffer.alloc(toRead);
    const bytesRead = fs.readSync(fd, chunkBuf, 0, toRead, currentPos);
    if (bytesRead === 0) break;

    const actualChunk = bytesRead < toRead ? chunkBuf.subarray(0, bytesRead) : chunkBuf;
    const searchBuf = prevOverlapBuf.length > 0 ? Buffer.concat([prevOverlapBuf, actualChunk]) : actualChunk;

    const idx = searchBuf.indexOf(target);
    if (idx !== -1) {
      // Calculate file offset
      const matchOffset = currentPos - prevOverlapBuf.length + idx;
      return matchOffset;
    }

    if (actualChunk.length >= overlap) {
      prevOverlapBuf = actualChunk.subarray(actualChunk.length - overlap);
    } else {
      prevOverlapBuf = actualChunk;
    }

    currentPos += actualChunk.length;
  }

  return -1;
}

/**
 * Detects whether an executable is packed or a self-extracting container.
 */
export async function detectPacker(filePath: string): Promise<PackerInfo> {
  if (!fs.existsSync(filePath)) {
    return { kind: 'none', details: 'File not found' };
  }

  const stat = fs.statSync(filePath);
  const fileSize = stat.size;

  if (fileSize < 64) {
    return { kind: 'none', details: 'File too small' };
  }

  const fd = fs.openSync(filePath, 'r');
  try {
    const pe = inspectPe(fd, fileSize);

    // 1. PyInstaller: 'MEI\x0c\x0b\x0a\x0b\x0e' cookie near end of file
    const tailSearchLen = Math.min(256 * 1024, fileSize);
    const tailStart = fileSize - tailSearchLen;
    const pyiOffset = searchInFile(fd, PYI_MAGIC, tailStart, tailSearchLen);

    if (pyiOffset !== -1) {
      // Read cookie data (88 bytes max)
      const cookieBuf = Buffer.alloc(88);
      const readBytes = fs.readSync(fd, cookieBuf, 0, 88, pyiOffset);
      let version: string | undefined;

      if (readBytes >= 24) {
        const pyvers = cookieBuf.readUInt32BE(20);
        if (pyvers > 0) {
          if (pyvers >= 100) {
            version = `${Math.floor(pyvers / 100)}.${pyvers % 100}`;
          } else {
            version = `${Math.floor(pyvers / 10)}.${pyvers % 10}`;
          }
        }
      }

      if (readBytes >= 88) {
        const pylib = cookieBuf.subarray(24, 88).toString('latin1').replace(/\0.*$/, '').trim();
        const m = pylib.match(/python(\d+)\.dll/i);
        if (m) {
          const num = m[1];
          if (num.length >= 2) {
            version = `${num[0]}.${num.slice(1)}`;
          }
        }
      }

      return {
        kind: 'pyinstaller',
        details: `PyInstaller executable archive${version ? ` (Python ${version})` : ''}`,
        version,
      };
    }

    // 2. UPX: section names UPX0/UPX1 or 'UPX!' magic
    if (pe.hasUpxSection) {
      return {
        kind: 'upx',
        details: 'UPX-packed executable (detected section name)',
      };
    }

    const upxMagicOffset = searchInFile(fd, UPX_MAGIC, 0, Math.min(131072, fileSize));
    if (upxMagicOffset !== -1) {
      return {
        kind: 'upx',
        details: 'UPX-packed executable (UPX! signature)',
      };
    }

    // 3. NSIS: 'Nullsoft.NSIS' / 'NullsoftInst' strings
    // Typically in installer stub (first 2MB)
    const nsisSearchLen = Math.min(2 * 1024 * 1024, fileSize);
    const nsisOffset1 = searchInFile(fd, NSIS_SIG1, 0, nsisSearchLen);
    const nsisOffset2 = nsisOffset1 === -1 ? searchInFile(fd, NSIS_SIG2, 0, nsisSearchLen) : nsisOffset1;

    if (nsisOffset1 !== -1 || nsisOffset2 !== -1) {
      let version: string | undefined;
      const targetOff = nsisOffset1 !== -1 ? nsisOffset1 : nsisOffset2;
      const ctxBuf = Buffer.alloc(512);
      const readLen = fs.readSync(fd, ctxBuf, 0, 512, Math.max(0, targetOff - 100));
      const str = ctxBuf.subarray(0, readLen).toString('latin1');
      const vMatch = str.match(/Nullsoft Install System v([0-9.]+)/i) || str.match(/NSIS v([0-9.]+)/i);
      if (vMatch) {
        version = vMatch[1];
      }

      return {
        kind: 'nsis',
        details: `Nullsoft Scriptable Install System (NSIS) installer${version ? ` (v${version})` : ''}`,
        version,
      };
    }

    // 4. Inno Setup: 'Inno Setup Setup Data'
    // Search in first 2MB or overlay start
    const innoOffsetHead = searchInFile(fd, INNO_SIG, 0, Math.min(2 * 1024 * 1024, fileSize));
    let innoOffset = innoOffsetHead;
    if (innoOffset === -1 && pe.hasOverlay) {
      innoOffset = searchInFile(fd, INNO_SIG, pe.overlayOffset, Math.min(512 * 1024, pe.overlaySize));
    }

    if (innoOffset !== -1) {
      let version: string | undefined;
      const ctxBuf = Buffer.alloc(128);
      const readLen = fs.readSync(fd, ctxBuf, 0, 128, innoOffset);
      const str = ctxBuf.subarray(0, readLen).toString('latin1');
      const vMatch = str.match(/Inno Setup Setup Data \(([0-9.]+)\)/i);
      if (vMatch) {
        version = vMatch[1];
      }

      return {
        kind: 'inno',
        details: `Inno Setup installer${version ? ` (${version})` : ''}`,
        version,
      };
    }

    // 5. 7z SFX: '7z\xBC\xAF\x27\x1C' signature inside a PE
    if (pe.isPe) {
      // Check overlay first if present
      let sevenZipOffset = -1;
      if (pe.hasOverlay) {
        sevenZipOffset = searchInFile(fd, SEVEN_ZIP_MAGIC, pe.overlayOffset, Math.min(1024 * 1024, pe.overlaySize));
      }
      if (sevenZipOffset === -1) {
        sevenZipOffset = searchInFile(fd, SEVEN_ZIP_MAGIC, 0, Math.min(2 * 1024 * 1024, fileSize));
      }

      if (sevenZipOffset !== -1) {
        return {
          kind: 'sfx-7z',
          details: '7-Zip Self-Extracting Archive (7z SFX)',
        };
      }
    }

    // 6. zip SFX: (PK\x03\x04 inside a PE overlay)
    if (pe.isPe && pe.hasOverlay) {
      const zipOffset = searchInFile(fd, ZIP_MAGIC, pe.overlayOffset, Math.min(64 * 1024, pe.overlaySize));
      if (zipOffset !== -1) {
        return {
          kind: 'sfx-zip',
          details: 'ZIP Self-Extracting Archive (zip SFX in PE overlay)',
        };
      }
    }

    return {
      kind: 'none',
      details: 'No known packer detected',
    };
  } finally {
    fs.closeSync(fd);
  }
}
