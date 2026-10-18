import { Router } from 'express';
import { execFile } from 'child_process';
import { promisify } from 'util';
import type { EngineStatus } from '../../../shared/types.js';
import { isSandboxAvailable } from '../services/sandbox.js';
import { getUploadsBytes } from '../services/disk.js';

import { hasR2Ghidra } from '../services/native.js';
import { isAiConfigured } from '../services/ai.js';

export const statusRouter = Router();
const execFileAsync = promisify(execFile);

async function checkCommand(cmd: string, ...args: string[]): Promise<boolean> {
  try {
    await execFileAsync(cmd, args, { timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

// GET /api/status
statusRouter.get('/', async (_req, res) => {
  const [ghidra, analyzeHeadless, r2, radare2, playwright, adb, ilspy, apktool, yara, upx, capa, pycdc, r2ghidra] =
    await Promise.all([
      checkCommand('ghidra', '--help'),
      checkCommand('analyzeHeadless', '--help'),
      checkCommand('r2', '-v'),
      checkCommand('radare2', '-v'),
      checkCommand('npx', 'playwright', '--version'),
      checkCommand('adb', 'version'),
      checkCommand('ilspycmd', '--version'),
      checkCommand('apktool', '--version'),
      checkCommand('yara', '--version'),
      checkCommand('upx', '--version'),
      checkCommand('capa', '--version'),
      // pycdc has no version flag; finding it on PATH is enough
      checkCommand('which', 'pycdc'),
      hasR2Ghidra(),
    ]);

  const status: EngineStatus = {
    javascript: true,  // always available
    ghidra: ghidra || analyzeHeadless,
    radare2: r2 || radare2,
    hopper: false,     // macOS only
    ida: false,        // requires license check
    playwright,
    adb,
    ilspy,
    apktool,
    yara,
    upx,
    capa,
    pycdc,
    r2ghidra,
    ai: isAiConfigured(),
    sandbox: isSandboxAvailable(),
    uploadsBytes: getUploadsBytes(),
  };

  res.json({ success: true, data: status });
});
