import { execFile, execFileSync } from 'child_process';
import fs from 'fs';
import path from 'path';

export interface RunToolOptions {
  readPaths?: string[];
  writePaths?: string[];
  cwd?: string;
  timeoutMs?: number;
  memoryMaxMB?: number;
  maxBuffer?: number;
}

let sandboxAvailable: boolean | null = null;

export function isSandboxAvailable(): boolean {
  if (sandboxAvailable !== null) return sandboxAvailable;

  if (process.env.WEB_RE_SANDBOX === 'off') {
    sandboxAvailable = false;
    return false;
  }

  try {
    execFileSync('which', ['systemd-run'], { stdio: 'ignore' });
    execFileSync('which', ['bwrap'], { stdio: 'ignore' });
    execFileSync(
      'systemd-run',
      [
        '--scope',
        '--quiet',
        '--collect',
        '-p',
        'MemoryMax=256M',
        '--',
        'bwrap',
        '--unshare-all',
        '--ro-bind',
        '/usr',
        '/usr',
        '--symlink',
        'usr/lib',
        '/lib',
        '--symlink',
        'usr/lib64',
        '/lib64',
        '--symlink',
        'usr/bin',
        '/bin',
        '--proc',
        '/proc',
        '--dev',
        '/dev',
        '--tmpfs',
        '/tmp',
        '--chdir',
        '/tmp',
        '--',
        'true',
      ],
      { timeout: 5000, stdio: 'ignore' }
    );
    sandboxAvailable = true;
  } catch (err: any) {
    console.warn(
      `[Sandbox] Sandbox unavailable (${err?.message || String(err)}), falling back to unsandboxed execution.`
    );
    sandboxAvailable = false;
  }

  return sandboxAvailable;
}

// Perform initial availability check once on module load
isSandboxAvailable();

function addMount(
  mountArgs: string[],
  flag: '--ro-bind' | '--bind',
  targetPath: string,
  bound: Set<string>
) {
  if (!targetPath) return;
  const abs = path.resolve(targetPath);
  if (!bound.has(abs) && fs.existsSync(abs)) {
    mountArgs.push(flag, abs, abs);
    bound.add(abs);
  }
  try {
    if (fs.existsSync(abs)) {
      const real = fs.realpathSync(abs);
      if (!bound.has(real)) {
        mountArgs.push(flag, real, real);
        bound.add(real);
      }
    }
  } catch {
    // ignore
  }
}

export function runTool(
  cmd: string,
  args: string[],
  opts: RunToolOptions = {}
): Promise<{ stdout: string; stderr: string }> {
  const timeoutMs = opts.timeoutMs ?? 120_000;
  const maxBuffer = opts.maxBuffer ?? 50 * 1024 * 1024;
  const cwd = opts.cwd || '/tmp';

  if (!isSandboxAvailable()) {
    return new Promise((resolve, reject) => {
      execFile(
        cmd,
        args,
        { cwd, timeout: timeoutMs, maxBuffer },
        (error, stdout, stderr) => {
          if (error) {
            (error as any).stdout = stdout;
            (error as any).stderr = stderr;
            return reject(error);
          }
          resolve({ stdout, stderr });
        }
      );
    });
  }

  const mem = opts.memoryMaxMB ?? 1536;
  const bound = new Set<string>();
  const mountArgs: string[] = [];

  // Write paths (mkdir -p first)
  for (const wp of opts.writePaths || []) {
    try {
      if (!fs.existsSync(wp)) {
        fs.mkdirSync(wp, { recursive: true });
      }
    } catch {
      // ignore
    }
    addMount(mountArgs, '--bind', wp, bound);
  }

  // Read paths
  for (const rp of opts.readPaths || []) {
    addMount(mountArgs, '--ro-bind', rp, bound);
  }

  // Bound cwd if outside /tmp
  if (cwd !== '/tmp' && fs.existsSync(cwd)) {
    addMount(mountArgs, '--bind', cwd, bound);
  }

  // If command is absolute path and exists, bind it
  if (path.isAbsolute(cmd) && fs.existsSync(cmd)) {
    addMount(mountArgs, '--ro-bind', cmd, bound);
  }

  const bwrapArgs: string[] = [
    '--scope',
    '--quiet',
    '--collect',
    '-p',
    `MemoryMax=${mem}M`,
    '-p',
    'CPUQuota=200%',
    '-p',
    'TasksMax=512',
    '--',
    'bwrap',
    '--unshare-all',
    '--die-with-parent',
    '--new-session',
    '--ro-bind',
    '/usr',
    '/usr',
    '--ro-bind',
    '/etc',
    '/etc',
    '--ro-bind-try',
    '/opt',
    '/opt',
    '--symlink',
    'usr/lib',
    '/lib',
    '--symlink',
    'usr/lib64',
    '/lib64',
    '--symlink',
    'usr/bin',
    '/bin',
    '--symlink',
    'usr/sbin',
    '/sbin',
    '--proc',
    '/proc',
    '--dev',
    '/dev',
    '--tmpfs',
    '/tmp',
    '--setenv',
    'HOME',
    '/tmp',
    ...mountArgs,
    '--chdir',
    cwd,
    '--',
    cmd,
    ...args,
  ];

  return new Promise((resolve, reject) => {
    execFile(
      'systemd-run',
      bwrapArgs,
      { timeout: timeoutMs, maxBuffer },
      (error, stdout, stderr) => {
        if (error) {
          (error as any).stdout = stdout;
          (error as any).stderr = stderr;
          return reject(error);
        }
        resolve({ stdout, stderr });
      }
    );
  });
}
