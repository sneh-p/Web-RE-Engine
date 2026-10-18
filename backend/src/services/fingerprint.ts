import crypto from 'crypto';
import fs from 'fs';
import type { FileFingerprint } from '../../../shared/types.js';

/**
 * Calculates the Shannon entropy of a buffer in bits per byte (0.0 to 8.0).
 */
export function calculateBufferEntropy(buf: Buffer): number {
  if (buf.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < buf.length; i++) {
    counts[buf[i]]++;
  }

  let entropy = 0;
  const total = buf.length;
  for (let i = 0; i < 256; i++) {
    if (counts[i] > 0) {
      const p = counts[i] / total;
      entropy -= p * Math.log2(p);
    }
  }

  return Math.round(entropy * 10000) / 10000;
}

/**
 * Computes md5, sha1, sha256 hashes (streaming), file size, and Shannon entropy for a file.
 */
export async function computeFileFingerprint(filePath: string): Promise<FileFingerprint> {
  return new Promise((resolve, reject) => {
    const md5 = crypto.createHash('md5');
    const sha1 = crypto.createHash('sha1');
    const sha256 = crypto.createHash('sha256');
    const counts = new Uint32Array(256);
    let size = 0;

    const stream = fs.createReadStream(filePath);

    stream.on('data', (chunk: Buffer | string) => {
      const buf = typeof chunk === 'string' ? Buffer.from(chunk) : chunk;
      size += buf.length;
      md5.update(buf);
      sha1.update(buf);
      sha256.update(buf);
      for (let i = 0; i < buf.length; i++) {
        counts[buf[i]]++;
      }
    });

    stream.on('end', () => {
      let entropy = 0;
      if (size > 0) {
        for (let i = 0; i < 256; i++) {
          if (counts[i] > 0) {
            const p = counts[i] / size;
            entropy -= p * Math.log2(p);
          }
        }
      }

      resolve({
        md5: md5.digest('hex'),
        sha1: sha1.digest('hex'),
        sha256: sha256.digest('hex'),
        size,
        entropy: Math.round(entropy * 10000) / 10000,
      });
    });

    stream.on('error', (err) => reject(err));
  });
}
