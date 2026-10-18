import fs from 'fs';
import path from 'path';
import type { FileTreeNode } from '../../../shared/types.js';

export function buildFileTree(
  dir: string,
  base: string = dir,
  depth = 0,
  maxDepth = 6
): FileTreeNode[] {
  if (depth > maxDepth) return [];
  if (!fs.existsSync(dir)) return [];

  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });

    // Sort directories first, then alphabetical
    entries.sort((a, b) => {
      if (a.isDirectory() && !b.isDirectory()) return -1;
      if (!a.isDirectory() && b.isDirectory()) return 1;
      return a.name.localeCompare(b.name);
    });

    return entries.map((e) => {
      const full = path.join(dir, e.name);
      const rel = path.relative(base, full);
      if (e.isDirectory()) {
        return {
          name: e.name,
          path: rel,
          type: 'directory',
          children: buildFileTree(full, base, depth + 1, maxDepth),
        };
      }
      let size: number | undefined;
      try {
        size = fs.statSync(full).size;
      } catch {
        // ignore
      }
      return {
        name: e.name,
        path: rel,
        type: 'file',
        size,
      };
    });
  } catch {
    return [];
  }
}
