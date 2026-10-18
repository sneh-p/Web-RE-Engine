import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import type { ExplainScope } from '../../../shared/types.js';
import { getJob, listJobs, deleteJob, createJob, patchJob } from '../queue/jobQueue.js';
import { searchJob } from '../services/search.js';
import { buildMarkdownReport, buildHtmlReport, buildPdfReport } from '../services/report.js';
import { isAiConfigured, streamExplanation, explanationKey, describeAiError } from '../services/ai.js';

export const jobsRouter = Router();

// GET /api/jobs
jobsRouter.get('/', (_req, res) => {
  res.json({ success: true, data: listJobs() });
});

// GET /api/jobs/:id
jobsRouter.get('/:id', (req, res) => {
  const job = getJob(req.params.id);
  if (!job) return res.status(404).json({ success: false, error: 'Job not found' });
  res.json({ success: true, data: job });
});

// POST /api/jobs/:id/rerun
jobsRouter.post('/:id/rerun', (req, res) => {
  const job = getJob(req.params.id);
  if (!job) return res.status(404).json({ success: false, error: 'Job not found' });
  const inputCopy = JSON.parse(JSON.stringify(job.input));
  const newJob = createJob(inputCopy);
  res.status(201).json({ success: true, data: newJob });
});

// DELETE /api/jobs/:id
jobsRouter.delete('/:id', (req, res) => {
  const deleted = deleteJob(req.params.id);
  if (!deleted) return res.status(404).json({ success: false, error: 'Job not found' });
  res.json({ success: true, message: 'Job deleted' });
});

const TAG_RE = /^[\w .:+#@-]{1,40}$/;

// PATCH /api/jobs/:id  { notes?, tags? }
jobsRouter.patch('/:id', (req, res) => {
  const { notes, tags } = req.body ?? {};
  const patch: Parameters<typeof patchJob>[1] = {};

  if (notes !== undefined) {
    if (typeof notes !== 'string' || notes.length > 20_000) {
      return res.status(400).json({ success: false, error: 'notes must be a string of at most 20000 characters' });
    }
    patch.notes = notes;
  }
  if (tags !== undefined) {
    if (!Array.isArray(tags) || tags.length > 20 || !tags.every((t) => typeof t === 'string' && TAG_RE.test(t.trim()))) {
      return res.status(400).json({ success: false, error: 'tags must be up to 20 short labels (letters, digits, space, . : + # @ - _)' });
    }
    patch.tags = [...new Set(tags.map((t: string) => t.trim()))];
  }

  const job = patchJob(req.params.id, patch);
  if (!job) return res.status(404).json({ success: false, error: 'Job not found' });
  res.json({ success: true, data: job });
});

// GET /api/jobs/:id/search?q=
jobsRouter.get('/:id/search', (req, res) => {
  const job = getJob(req.params.id);
  if (!job) return res.status(404).json({ success: false, error: 'Job not found' });
  const q = String(req.query.q ?? '').trim();
  if (q.length < 2 || q.length > 200) return res.status(400).json({ success: false, error: 'Query must be 2-200 characters' });
  res.json({ success: true, data: searchJob(job, q) });
});

// GET /api/jobs/:id/report?format=md|html|pdf
jobsRouter.get('/:id/report', async (req, res) => {
  const job = getJob(req.params.id);
  if (!job) return res.status(404).json({ success: false, error: 'Job not found' });
  const format = String(req.query.format ?? 'md');
  const base = `web-re-report-${job.id.slice(0, 8)}`;
  try {
    if (format === 'md') {
      res.setHeader('Content-Disposition', `attachment; filename="${base}.md"`);
      return res.type('text/markdown').send(buildMarkdownReport(job));
    }
    if (format === 'html') {
      // Served as a download, never rendered inline from our origin
      res.setHeader('Content-Disposition', `attachment; filename="${base}.html"`);
      return res.type('text/html').send(buildHtmlReport(job));
    }
    if (format === 'pdf') {
      const pdf = await buildPdfReport(job);
      res.setHeader('Content-Disposition', `attachment; filename="${base}.pdf"`);
      return res.type('application/pdf').send(pdf);
    }
    res.status(400).json({ success: false, error: 'format must be md, html or pdf' });
  } catch (err: any) {
    res.status(500).json({ success: false, error: `Report generation failed: ${err.message}` });
  }
});

// AI calls cost money; cap them even for the single admin user
const explainLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { success: false, error: 'Too many AI explanation requests; try again in a few minutes' },
});

// POST /api/jobs/:id/explain  { scope: 'job' } | { scope: 'function', address } | { scope: 'file', path }
// Streams server-sent events: {type:'text',text} ... then {type:'done',explanation} or {type:'error',error}
jobsRouter.post('/:id/explain', explainLimiter, async (req, res) => {
  const job = getJob(req.params.id);
  if (!job) return res.status(404).json({ success: false, error: 'Job not found' });
  if (job.status !== 'completed') return res.status(409).json({ success: false, error: 'The analysis has not completed yet' });
  if (!isAiConfigured()) {
    return res.status(503).json({ success: false, error: 'AI explanations are not configured. Open Settings to choose a provider and add an API key.' });
  }

  const body = req.body ?? {};
  let scope: ExplainScope;
  if (body.scope === 'function' && typeof body.address === 'string') scope = { scope: 'function', address: body.address };
  else if (body.scope === 'file' && typeof body.path === 'string') scope = { scope: 'file', path: body.path };
  else if (body.scope === 'job') scope = { scope: 'job' };
  else return res.status(400).json({ success: false, error: 'Invalid scope' });

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  const send = (event: Record<string, unknown>) => res.write(`data: ${JSON.stringify(event)}\n\n`);

  // Stop paying for tokens nobody will read
  const abort = new AbortController();
  res.on('close', () => abort.abort());

  try {
    const outcome = await streamExplanation(job, scope, (text) => send({ type: 'text', text }), abort.signal);
    const explanation = { ...outcome, createdAt: new Date().toISOString() };
    patchJob(job.id, { explanations: { ...(job.explanations ?? {}), [explanationKey(scope)]: explanation } });
    send({ type: 'done', key: explanationKey(scope), explanation });
  } catch (err) {
    if (!abort.signal.aborted) send({ type: 'error', error: describeAiError(err) });
  } finally {
    res.end();
  }
});
