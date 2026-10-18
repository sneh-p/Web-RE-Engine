import type { Request, Response, NextFunction } from 'express';
import { isAuthConfigured, parseCookies, validateSession } from '../services/auth.js';

export function csrfProtection(req: Request, res: Response, next: NextFunction) {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
    return next();
  }

  const origin = req.headers.origin;
  if (origin) {
    try {
      const originHost = new URL(origin).host;
      const host = req.headers.host;
      const forwardedHost = req.headers['x-forwarded-host'] as string | undefined;

      if (originHost !== host && originHost !== forwardedHost) {
        return res.status(403).json({ error: 'Forbidden: CSRF check failed' });
      }
    } catch {
      return res.status(403).json({ error: 'Forbidden: Invalid Origin header' });
    }
  }

  next();
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  if (!isAuthConfigured()) {
    return res.status(503).json({
      error: 'Authentication not configured. Run: cd backend && npm run set-password',
    });
  }

  const cookies = parseCookies(req.headers.cookie);
  const token = cookies['wre_session'];

  if (!token || !validateSession(token)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  next();
}
