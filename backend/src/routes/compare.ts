import { Router } from 'express';
import { getJob } from '../queue/jobQueue.js';
import { compareJobs } from '../services/compare.js';

export const compareRouter = Router();

// GET /api/compare?a=<jobId>&b=<jobId>
compareRouter.get('/', (req, res) => {
  const a = getJob(String(req.query.a ?? ''));
  const b = getJob(String(req.query.b ?? ''));
  if (!a || !b) return res.status(404).json({ success: false, error: 'Both jobs must exist' });
  if (!a.result || !b.result) return res.status(409).json({ success: false, error: 'Both jobs must have completed' });
  res.json({ success: true, data: compareJobs(a, b) });
});
