import { v4 as uuidv4 } from 'uuid';
import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import type { AnalysisJob, AnalysisInput, AnalysisResult } from '../../../shared/types.js';
import { broadcast } from '../websocket/server.js';
import { runJavaScriptAnalysis } from '../services/javascript.js';
import { runNativeAnalysis } from '../services/native.js';
import { runBrowserAnalysis } from '../services/browser.js';
import { runDotNetAnalysis } from '../services/dotnet.js';
import { runAndroidAnalysis } from '../services/android.js';
import { runEvmAnalysis } from '../services/evm.js';
import { runExtensionAnalysis } from '../services/extension.js';
import { uploadsDir } from '../middleware/upload.js';
import { computeFileFingerprint } from '../services/fingerprint.js';
import { extractJobIocs } from '../services/ioc.js';
import { runYaraScan } from '../services/yara.js';
import { isCapaAvailable, queueCapa, planCapa } from '../services/capa.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Overridable so tests can run against a throwaway database
export const dataDir = process.env.WEB_RE_DATA_DIR ?? path.join(__dirname, '../../data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}
const dbPath = path.join(dataDir, 'rea.db');
export const db = new Database(dbPath);

// Initialize jobs table
db.exec(`
  CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    status TEXT NOT NULL,
    createdAt TEXT NOT NULL,
    updatedAt TEXT NOT NULL,
    json TEXT NOT NULL
  );
`);

const upsertJobStmt = db.prepare(`
  INSERT INTO jobs (id, type, status, createdAt, updatedAt, json)
  VALUES (@id, @type, @status, @createdAt, @updatedAt, @json)
  ON CONFLICT(id) DO UPDATE SET
    type = excluded.type,
    status = excluded.status,
    createdAt = excluded.createdAt,
    updatedAt = excluded.updatedAt,
    json = excluded.json
`);

const deleteJobStmt = db.prepare(`
  DELETE FROM jobs WHERE id = ?
`);

const jobs = new Map<string, AnalysisJob>();

function saveJobToDb(job: AnalysisJob) {
  upsertJobStmt.run({
    id: job.id,
    type: job.type,
    status: job.status,
    createdAt: job.createdAt,
    updatedAt: job.updatedAt,
    json: JSON.stringify(job),
  });
}

// Load existing jobs on startup; mark running/queued as failed
function initJobs() {
  const rows = db.prepare('SELECT id, type, status, createdAt, updatedAt, json FROM jobs').all() as Array<{
    id: string;
    type: string;
    status: string;
    createdAt: string;
    updatedAt: string;
    json: string;
  }>;

  for (const row of rows) {
    try {
      const job = JSON.parse(row.json) as AnalysisJob;
      if (job.capabilities?.pending) {
        job.capabilities = { available: true, capabilities: [], error: 'capa was interrupted by a server restart; re-run the job' };
        saveJobToDb(job);
      }
      if (job.status === 'running' || job.status === 'queued') {
        job.status = 'failed';
        job.error = 'Interrupted by server restart';
        job.updatedAt = new Date().toISOString();
        saveJobToDb(job);
      }
      jobs.set(job.id, job);
    } catch (err) {
      console.error(`Failed to load job ${row.id}:`, err);
    }
  }
}

initJobs();

// Concurrency queue
const MAX_CONCURRENCY = (() => {
  const envVal = process.env.REA_MAX_CONCURRENCY;
  if (envVal) {
    const val = parseInt(envVal, 10);
    if (!isNaN(val) && val > 0) return val;
  }
  return 2;
})();

const queue: AnalysisJob[] = [];
let runningCount = 0;

function processQueue() {
  while (runningCount < MAX_CONCURRENCY && queue.length > 0) {
    const nextJob = queue.shift();
    if (!nextJob) break;
    if (!jobs.has(nextJob.id)) continue;

    runningCount++;
    executeJob(nextJob).finally(() => {
      runningCount--;
      processQueue();
    });
  }
}

export function getJob(id: string): AnalysisJob | undefined {
  return jobs.get(id);
}

export function listJobs(): AnalysisJob[] {
  return [...jobs.values()].sort(
    (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
  );
}

export function createJob(input: AnalysisInput): AnalysisJob {
  const job: AnalysisJob = {
    id: uuidv4(),
    type: input.type,
    status: 'queued',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    input,
    logs: [],
  };
  jobs.set(job.id, job);
  saveJobToDb(job);

  queue.push(job);
  processQueue();
  return job;
}

// Persist user-editable or post-analysis fields (notes, tags, AI explanations) on an existing job
export function patchJob(
  id: string,
  patch: Partial<Pick<AnalysisJob, 'notes' | 'tags' | 'explanations'>>
): AnalysisJob | undefined {
  const job = jobs.get(id);
  if (!job) return undefined;
  updateJob(job, patch);
  return job;
}

export function deleteJob(id: string): boolean {
  const job = jobs.get(id);
  if (!job) return false;

  // Remove from queue if pending
  const qIdx = queue.findIndex((j) => j.id === id);
  if (qIdx !== -1) {
    queue.splice(qIdx, 1);
  }

  // Remove files strictly inside uploadsDir
  const resolvedUploadsDir = path.resolve(uploadsDir);
  const isInsideUploads = (p: string) => {
    const resolved = path.resolve(p);
    return resolved.startsWith(resolvedUploadsDir + path.sep) && resolved !== resolvedUploadsDir;
  };

  const safeRemove = (p: string) => {
    try {
      if (isInsideUploads(p) && fs.existsSync(p)) {
        fs.rmSync(p, { recursive: true, force: true });
      }
    } catch (e) {
      console.error(`Failed to delete path ${p}:`, e);
    }
  };

  const fp = job.input && 'filePath' in job.input ? job.input.filePath : undefined;

  const isReferencedByOtherJob = fp
    ? Array.from(jobs.values()).some(
        (other) =>
          other.id !== id &&
          other.input &&
          'filePath' in other.input &&
          other.input.filePath === fp
      )
    : false;

  if (fp && !isReferencedByOtherJob) {
    safeRemove(fp);
    const base = path.basename(fp);
    safeRemove(path.join(resolvedUploadsDir, `extracted_${base}`));
    safeRemove(path.join(resolvedUploadsDir, `jadx_${base}`));
    safeRemove(path.join(resolvedUploadsDir, `apktool_${base}`));
    safeRemove(path.join(resolvedUploadsDir, `unpacked_${base}`));
    safeRemove(path.join(resolvedUploadsDir, `decompiled_${base}`));
  }

  if (job.extractedPath) {
    const isExtractedPathShared = Array.from(jobs.values()).some(
      (other) => other.id !== id && other.extractedPath === job.extractedPath
    );
    if (!isReferencedByOtherJob && !isExtractedPathShared) {
      safeRemove(job.extractedPath);
    }
  }

  jobs.delete(id);
  deleteJobStmt.run(id);

  return true;
}

function updateJob(job: AnalysisJob, patch: Partial<AnalysisJob>) {
  if (!jobs.has(job.id)) return;
  Object.assign(job, { ...patch, updatedAt: new Date().toISOString() });
  jobs.set(job.id, job);
  saveJobToDb(job);
}

function log(job: AnalysisJob, message: string, progress?: number) {
  if (!jobs.has(job.id)) return;
  job.logs ??= [];
  job.logs.push(`[${new Date().toISOString()}] ${message}`);
  if (progress !== undefined) job.progress = progress;
  job.updatedAt = new Date().toISOString();
  saveJobToDb(job);
  broadcast(job.id, { event: 'job:progress', jobId: job.id, progress: progress ?? job.progress ?? 0, log: message });
}

async function executeJob(job: AnalysisJob) {
  if (!jobs.has(job.id)) return;
  updateJob(job, { status: 'running' });
  broadcast(job.id, { event: 'job:started', jobId: job.id });
  log(job, `Starting ${job.type} analysis...`, 5);

  // Compute file fingerprint before running analyzer for any file-based input
  if ('filePath' in job.input && job.input.filePath && fs.existsSync(job.input.filePath)) {
    try {
      const fp = await computeFileFingerprint(job.input.filePath);
      job.fingerprint = fp;
      updateJob(job, { fingerprint: fp });
    } catch (fpErr) {
      console.error(`Failed to compute fingerprint for job ${job.id}:`, fpErr);
    }
  }

  try {
    let result: AnalysisResult;
    let fileTree: any[] | undefined;
    let extractedPath: string | undefined;

    switch (job.input.type) {
      case 'javascript': {
        const jsRes = await runJavaScriptAnalysis(job.input, (msg, pct) => log(job, msg, pct));
        result = jsRes.result;
        fileTree = jsRes.fileTree;
        extractedPath = jsRes.extractedPath;
        break;
      }
      case 'native': {
        const natRes = await runNativeAnalysis(job.input, (msg, pct) => log(job, msg, pct));
        result = natRes.result;
        fileTree = natRes.fileTree;
        extractedPath = natRes.extractedPath;
        break;
      }
      case 'browser':
        result = await runBrowserAnalysis(job.input, (msg, pct) => log(job, msg, pct));
        break;
      case 'dotnet': {
        const dotnetRes = await runDotNetAnalysis(job.input, (msg, pct) => log(job, msg, pct));
        result = dotnetRes.result;
        fileTree = dotnetRes.fileTree;
        extractedPath = dotnetRes.extractedPath;
        break;
      }
      case 'android': {
        const androidRes = await runAndroidAnalysis(job.input, (msg, pct) => log(job, msg, pct));
        result = androidRes.result;
        fileTree = androidRes.fileTree;
        extractedPath = androidRes.extractedPath;
        break;
      }
      case 'evm':
        result = await runEvmAnalysis(job.input, (msg, pct) => log(job, msg, pct));
        break;
      case 'extension': {
        const extRes = await runExtensionAnalysis(job.input, (msg, pct) => log(job, msg, pct));
        result = extRes.result;
        fileTree = extRes.fileTree;
        extractedPath = extRes.extractedPath;
        break;
      }
    }

    if (!jobs.has(job.id)) return;

    // Compute IOCs after analyzer finishes
    let iocs: Record<string, string[]> | undefined;
    try {
      iocs = await extractJobIocs(job, result, extractedPath);
      job.iocs = iocs;
    } catch (iocErr) {
      console.error(`Failed to extract IOCs for job ${job.id}:`, iocErr);
    }

    // Signature scanning: YARA on the upload and anything we unpacked; capa on native binaries
    let capaTarget: string | undefined;
    const inputPath = 'filePath' in job.input ? job.input.filePath : undefined;
    if (inputPath && fs.existsSync(inputPath)) {
      log(job, 'Scanning with YARA rules...', 97);
      try {
        job.yara = await runYaraScan(inputPath, 'fileName' in job.input ? job.input.fileName : path.basename(inputPath), extractedPath);
      } catch (yaraErr) {
        console.error(`YARA scan failed for job ${job.id}:`, yaraErr);
      }

      if (result.type === 'native' && result.format !== 'unknown') {
        if (await isCapaAvailable()) {
          // Installers and packers: analyze the program inside, not the wrapper
          const plan = planCapa(inputPath, result.packer?.kind, extractedPath);
          if (plan.target) {
            job.capabilities = { available: true, capabilities: [], pending: true, target: plan.label };
            capaTarget = plan.target;
          } else {
            job.capabilities = { available: true, capabilities: [], skipped: plan.skipped };
          }
        } else {
          job.capabilities = { available: false, capabilities: [] };
        }
      }
    }

    updateJob(job, {
      status: 'completed',
      result,
      fileTree,
      extractedPath,
      iocs,
      yara: job.yara,
      capabilities: job.capabilities,
      progress: 100,
    });
    broadcast(job.id, {
      event: 'job:completed',
      jobId: job.id,
      result,
      fingerprint: job.fingerprint,
      iocs: job.iocs,
      yara: job.yara,
      capabilities: job.capabilities,
    });
    log(job, 'Analysis complete.', 100);

    if (capaTarget) {
      const target = capaTarget;
      const targetLabel = job.capabilities?.target;
      void queueCapa(target).then((res) => {
        if (!jobs.has(job.id)) return;
        const capabilities = { ...res, target: targetLabel };
        updateJob(job, { capabilities });
        broadcast(job.id, { event: 'job:updated', jobId: job.id, patch: { capabilities } });
      });
    }
  } catch (err) {
    if (!jobs.has(job.id)) return;
    const error = err instanceof Error ? err.message : String(err);
    updateJob(job, { status: 'failed', error });
    broadcast(job.id, { event: 'job:failed', jobId: job.id, error });
    log(job, `Error: ${error}`);
  }
}

export function cleanupOldJobs() {
  const envVal = process.env.WEB_RE_RETENTION_DAYS;
  const retentionDays = envVal !== undefined && envVal !== '' ? parseInt(envVal, 10) : 30;
  if (isNaN(retentionDays) || retentionDays <= 0) return;

  const cutoffTime = Date.now() - retentionDays * 24 * 60 * 60 * 1000;
  for (const job of Array.from(jobs.values())) {
    const createdTime = new Date(job.createdAt).getTime();
    if (!isNaN(createdTime) && createdTime < cutoffTime) {
      deleteJob(job.id);
    }
  }
}

const retentionVal = process.env.WEB_RE_RETENTION_DAYS;
const configuredRetention = retentionVal !== undefined && retentionVal !== '' ? parseInt(retentionVal, 10) : 30;
if (!isNaN(configuredRetention) && configuredRetention > 0) {
  setTimeout(cleanupOldJobs, 60_000).unref();
  setInterval(cleanupOldJobs, 60 * 60_000).unref();
}

