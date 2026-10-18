import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import {
  getAiConfig,
  getAiConfigPublic,
  saveAiConfig,
  clearAiConfig,
  validateAiUpdate,
  type AiConfig,
} from '../services/settings.js';
import { testAiProvider } from '../services/ai.js';

export const settingsRouter = Router();

// GET /api/settings/ai — never includes the key, only its last 4 characters
settingsRouter.get('/ai', (_req, res) => {
  res.json({ success: true, data: getAiConfigPublic() });
});

// PUT /api/settings/ai { provider, model, baseUrl?, apiKey? }  (omit apiKey to keep the stored one)
settingsRouter.put('/ai', (req, res) => {
  const error = validateAiUpdate(req.body);
  if (error) return res.status(400).json({ success: false, error });
  saveAiConfig(req.body);
  res.json({ success: true, data: getAiConfigPublic() });
});

// DELETE /api/settings/ai — falls back to ANTHROPIC_API_KEY in backend/.env, if any
settingsRouter.delete('/ai', (_req, res) => {
  clearAiConfig();
  res.json({ success: true, data: getAiConfigPublic() });
});

const testLimiter = rateLimit({ windowMs: 10 * 60 * 1000, limit: 20, standardHeaders: 'draft-7', legacyHeaders: false });

// POST /api/settings/ai/test — tries the submitted settings (or the saved ones) without saving
settingsRouter.post('/ai/test', testLimiter, async (req, res) => {
  let cfg: AiConfig | null;
  if (req.body?.provider) {
    const error = validateAiUpdate(req.body);
    if (error) return res.status(400).json({ success: false, error });
    const saved = getAiConfig();
    cfg = {
      provider: req.body.provider,
      model: req.body.model.trim(),
      baseUrl: req.body.baseUrl ? String(req.body.baseUrl).trim().replace(/\/+$/, '') : undefined,
      // A blank key field means "use the saved key" when testing edits to the same provider
      apiKey: req.body.apiKey || (saved && saved.provider === req.body.provider ? saved.apiKey : undefined),
      source: 'portal',
    };
  } else {
    cfg = getAiConfig();
  }
  if (!cfg) return res.status(400).json({ success: false, error: 'No AI provider configured' });
  res.json({ success: true, data: await testAiProvider(cfg) });
});
