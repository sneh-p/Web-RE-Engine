import { Router } from 'express';
import fs from 'fs';
import { upload, uploadsDir } from '../middleware/upload.js';
import { parseStoreRef, downloadFromStore } from '../services/extensionStore.js';
import { createJob } from '../queue/jobQueue.js';
import { detectFileType } from '../services/detector.js';
import { validateBrowserUrl } from '../services/ssrf.js';
import type {
  AnalysisInput,
  AnalysisJob,
  JavaScriptInput,
  NativeInput,
  BrowserInput,
  DotNetInput,
  AndroidInput,
  EvmInput,
  ExtensionInput,
} from '../../../shared/types.js';

export const analysisRouter = Router();

const UNSUPPORTED_TYPE_ERROR =
  'Could not auto-detect file type. Supported: APK (Android), .NET assembly, native binary (PE/ELF/Mach-O), or JavaScript/archive (zip/asar/tar/js/mjs/cjs/ts).';

// Detect the analyzer for an uploaded file and queue a job; unknown files are deleted
function createAutoJob(file: Express.Multer.File): { job?: AnalysisJob; error?: string } {
  let detected: ReturnType<typeof detectFileType> = null;
  try {
    detected = detectFileType(file.path, file.originalname);
  } catch {
    detected = null;
  }
  if (!detected) {
    try {
      if (fs.existsSync(file.path)) fs.unlinkSync(file.path);
    } catch {}
    return { error: UNSUPPORTED_TYPE_ERROR };
  }

  const base = { fileName: file.originalname, fileSize: file.size, filePath: file.path };
  const input: AnalysisInput =
    detected === 'native' ? { type: 'native', ...base, provider: 'auto' } : { type: detected, ...base };
  return { job: createJob(input) };
}

// POST /api/analysis/auto (multipart: file)
analysisRouter.post('/auto', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ success: false, error: 'No file uploaded' });
  const { job, error } = createAutoJob(req.file);
  if (!job) return res.status(400).json({ success: false, error });
  res.json({ success: true, data: job });
});

// POST /api/analysis/bulk (multipart: files[]) — one auto-detected job per file
analysisRouter.post('/bulk', upload.array('files', 50), (req, res) => {
  const files = (req.files as Express.Multer.File[] | undefined) ?? [];
  if (files.length === 0) return res.status(400).json({ success: false, error: 'No files uploaded' });

  const jobs: AnalysisJob[] = [];
  const rejected: { fileName: string; error: string }[] = [];
  for (const file of files) {
    const { job, error } = createAutoJob(file);
    if (job) jobs.push(job);
    else rejected.push({ fileName: file.originalname, error: error ?? 'Rejected' });
  }
  res.json({ success: true, data: { jobs, rejected } });
});

// POST /api/analysis/extension  (multipart: file — .crx, .xpi or zipped unpacked extension)
analysisRouter.post('/extension', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ success: false, error: 'No file uploaded' });
  const input: ExtensionInput = { type: 'extension', fileName: req.file.originalname, fileSize: req.file.size, filePath: req.file.path };
  res.json({ success: true, data: createJob(input) });
});

// POST /api/analysis/extension/store  { ref: store URL or id, browser?: 'chrome' | 'firefox' }
analysisRouter.post('/extension/store', async (req, res) => {
  const { ref: raw, browser } = req.body ?? {};
  const ref = typeof raw === 'string' ? parseStoreRef(raw, browser === 'firefox' ? 'firefox' : browser === 'chrome' ? 'chrome' : undefined) : null;
  if (!ref) {
    return res.status(400).json({
      success: false,
      error: 'Enter a Chrome Web Store / Edge Add-ons URL or 32-letter id, or an addons.mozilla.org URL or slug (with Firefox selected)',
    });
  }
  try {
    const { filePath, fileName, size } = await downloadFromStore(ref, uploadsDir);
    const input: ExtensionInput = { type: 'extension', fileName, fileSize: size, filePath, store: ref };
    res.json({ success: true, data: createJob(input) });
  } catch (err: any) {
    res.status(502).json({ success: false, error: `Download failed: ${err.message}` });
  }
});

// POST /api/analysis/javascript  (multipart: file)
analysisRouter.post('/javascript', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ success: false, error: 'No file uploaded' });
  const input: JavaScriptInput = {
    type: 'javascript',
    fileName: req.file.originalname,
    fileSize: req.file.size,
    filePath: req.file.path,
  };
  const job = createJob(input);
  res.json({ success: true, data: job });
});

// POST /api/analysis/native  (multipart: file)
analysisRouter.post('/native', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ success: false, error: 'No file uploaded' });
  const input: NativeInput = {
    type: 'native',
    fileName: req.file.originalname,
    fileSize: req.file.size,
    filePath: req.file.path,
    provider: (req.body.provider as NativeInput['provider']) ?? 'auto',
  };
  const job = createJob(input);
  res.json({ success: true, data: job });
});

// POST /api/analysis/browser  (JSON)
analysisRouter.post('/browser', async (req, res) => {
  const { url, captureNetworkTraffic = true, captureScreenshot = true } = req.body as BrowserInput;
  if (!url) return res.status(400).json({ success: false, error: 'url is required' });

  const ssrfError = await validateBrowserUrl(url);
  if (ssrfError) {
    return res.status(400).json({ success: false, error: ssrfError });
  }

  const input: BrowserInput = { type: 'browser', url, captureNetworkTraffic, captureScreenshot };
  const job = createJob(input);
  res.json({ success: true, data: job });
});

// POST /api/analysis/dotnet  (multipart: file)
analysisRouter.post('/dotnet', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ success: false, error: 'No file uploaded' });
  const input: DotNetInput = {
    type: 'dotnet',
    fileName: req.file.originalname,
    fileSize: req.file.size,
    filePath: req.file.path,
  };
  const job = createJob(input);
  res.json({ success: true, data: job });
});

// POST /api/analysis/android  (multipart: file)
analysisRouter.post('/android', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ success: false, error: 'No file uploaded' });
  const input: AndroidInput = {
    type: 'android',
    fileName: req.file.originalname,
    fileSize: req.file.size,
    filePath: req.file.path,
    useAdb: req.body.useAdb === 'true',
    deviceId: req.body.deviceId,
  };
  const job = createJob(input);
  res.json({ success: true, data: job });
});

// POST /api/analysis/evm  (JSON)
analysisRouter.post('/evm', (req, res) => {
  const { source, value, network } = req.body as EvmInput;
  if (!source || !value) return res.status(400).json({ success: false, error: 'source and value are required' });
  const input: EvmInput = { type: 'evm', source, value, network };
  const job = createJob(input);
  res.json({ success: true, data: job });
});
