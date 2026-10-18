import { Router, type Response } from 'express';
import path from 'path';
import fs from 'fs';
import { getJob } from '../queue/jobQueue.js';

export const filesRouter = Router();

const TEXT_WINDOW = 1024 * 1024; // 1MB of text per request
const HEX_WINDOW = 64 * 1024; // 64KB of binary per request (~4K hex lines)

function readRange(fd: number, offset: number, length: number): Buffer {
  const buf = Buffer.alloc(length);
  const bytesRead = fs.readSync(fd, buf, 0, length, offset);
  return buf.subarray(0, bytesRead);
}

// xxd-style: offset, 16 hex bytes, ASCII column
function hexDump(buf: Buffer, baseOffset: number): string {
  const lines: string[] = [];
  for (let i = 0; i < buf.length; i += 16) {
    const row = buf.subarray(i, i + 16);
    const hex = [...row].map((b) => b.toString(16).padStart(2, '0'));
    const hexCol = (hex.slice(0, 8).join(' ') + '  ' + hex.slice(8).join(' ')).padEnd(48);
    const ascii = [...row].map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.')).join('');
    lines.push(`${(baseOffset + i).toString(16).padStart(8, '0')}  ${hexCol}  |${ascii}|`);
  }
  return lines.join('\n');
}

// Serve one window of a file so large files never get loaded whole
function sendFileWindow(res: Response, filePath: string, displayPath: string, size: number, rawOffset: unknown) {
  let fd: number | undefined;
  try {
    fd = fs.openSync(filePath, 'r');
    const isBinary = readRange(fd, 0, Math.min(size, 8192)).includes(0);
    const window = isBinary ? HEX_WINDOW : TEXT_WINDOW;

    let offset = Math.max(0, Math.floor(Number(rawOffset) || 0));
    if (offset >= size) offset = Math.max(0, size - 1);
    if (isBinary) offset -= offset % 16;

    const buf = readRange(fd, offset, Math.min(window, size - offset));
    const content = isBinary ? hexDump(buf, offset) : buf.toString('utf-8');

    return res.json({
      success: true,
      data: {
        path: displayPath,
        content,
        size,
        isBinary,
        offset,
        length: buf.length,
        truncated: offset > 0 || offset + buf.length < size,
        windowSize: window,
      },
    });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: 'Failed to read file: ' + err.message });
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

// GET /api/files/:jobId?path=...
filesRouter.get('/:jobId', (req, res) => {
  const job = getJob(req.params.jobId);
  if (!job) {
    return res.status(404).json({ success: false, error: 'Job not found' });
  }

  const requestedRelPath = (req.query.path as string) || '';

  // Determine root directory to serve from
  let rootDir = job.extractedPath;
  if (!rootDir && job.input && 'filePath' in job.input && job.input.filePath) {
    const stat = fs.existsSync(job.input.filePath) ? fs.statSync(job.input.filePath) : null;
    if (stat?.isDirectory()) {
      rootDir = job.input.filePath;
    } else if (stat?.isFile()) {
      // If it's a single file and the user didn't specify path or specified the filename
      const targetPath = path.resolve(job.input.filePath);
      const fileName = job.input.fileName || path.basename(targetPath);
      return sendFileWindow(res, targetPath, fileName, stat.size, req.query.offset);
    }
  }

  if (!rootDir || !fs.existsSync(rootDir)) {
    return res.status(404).json({ success: false, error: 'No extracted workspace files available for this job' });
  }

  // Prevent directory traversal
  const isInside = (root: string, p: string) => p === root || p.startsWith(root + path.sep);
  const targetPath = path.resolve(rootDir, requestedRelPath);
  if (!isInside(path.resolve(rootDir), targetPath)) {
    return res.status(403).json({ success: false, error: 'Access denied: outside directory boundary' });
  }

  if (!fs.existsSync(targetPath)) {
    return res.status(404).json({ success: false, error: 'File not found' });
  }

  // Extracted archives may contain symlinks; check the real location too
  if (!isInside(fs.realpathSync(rootDir), fs.realpathSync(targetPath))) {
    return res.status(403).json({ success: false, error: 'Access denied: outside directory boundary' });
  }

  const stat = fs.statSync(targetPath);
  if (stat.isDirectory()) {
    // List directory
    const entries = fs.readdirSync(targetPath, { withFileTypes: true }).map((ent) => ({
      name: ent.name,
      path: path.relative(rootDir, path.join(targetPath, ent.name)),
      type: ent.isDirectory() ? 'directory' : 'file',
      size: ent.isFile() ? fs.statSync(path.join(targetPath, ent.name)).size : undefined,
    }));
    return res.json({ success: true, data: { isDirectory: true, entries } });
  }

  return sendFileWindow(res, targetPath, requestedRelPath, stat.size, req.query.offset);
});
