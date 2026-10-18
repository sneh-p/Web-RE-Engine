import fs from 'fs';
import path from 'path';
import { uploadsDir } from '../middleware/upload.js';

let cachedUploadsBytes = 0;
let lastComputedTime = 0;
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes

function computeDirectorySize(dir: string): number {
  let total = 0;
  try {
    if (!fs.existsSync(dir)) return 0;
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      try {
        if (entry.isSymbolicLink()) continue;
        if (entry.isDirectory()) {
          total += computeDirectorySize(full);
        } else if (entry.isFile()) {
          total += fs.statSync(full).size;
        }
      } catch {
        // ignore transient errors
      }
    }
  } catch {
    // ignore
  }
  return total;
}

export function getUploadsBytes(): number {
  const now = Date.now();
  if (now - lastComputedTime < CACHE_TTL_MS && lastComputedTime !== 0) {
    return cachedUploadsBytes;
  }
  cachedUploadsBytes = computeDirectorySize(uploadsDir);
  lastComputedTime = now;
  return cachedUploadsBytes;
}
