import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import {
  isAuthConfigured,
  verifyPassword,
  createSession,
  deleteSession,
  validateSession,
  parseCookies,
} from '../services/auth.js';

export const authRouter = Router();

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many login attempts, please try again later' },
});

// POST /api/auth/login
authRouter.post('/login', loginLimiter, (req, res) => {
  if (!isAuthConfigured()) {
    return res.status(503).json({
      error: 'Authentication not configured. Run: cd backend && npm run set-password',
    });
  }

  const { password } = req.body ?? {};
  if (!password || typeof password !== 'string') {
    return res.status(401).json({ error: 'Invalid password' });
  }

  const storedHash = process.env.WEB_RE_ADMIN_PASSWORD_HASH;
  const isValid = verifyPassword(password, storedHash);

  if (!isValid) {
    return res.status(401).json({ error: 'Invalid password' });
  }

  const token = createSession();

  res.cookie('wre_session', token, {
    httpOnly: true,
    sameSite: 'strict',
    path: '/',
    secure: req.secure,
    maxAge: 12 * 60 * 60 * 1000,
  });

  return res.json({ success: true, authenticated: true });
});

// POST /api/auth/logout
authRouter.post('/logout', (req, res) => {
  const cookies = parseCookies(req.headers.cookie);
  const token = cookies['wre_session'];
  if (token) {
    deleteSession(token);
  }

  res.clearCookie('wre_session', {
    httpOnly: true,
    sameSite: 'strict',
    path: '/',
    secure: req.secure,
  });

  return res.json({ success: true });
});

// GET /api/auth/me -> {authenticated, authConfigured}
authRouter.get('/me', (req, res) => {
  const configured = isAuthConfigured();
  const cookies = parseCookies(req.headers.cookie);
  const token = cookies['wre_session'];
  const authenticated = Boolean(configured && token && validateSession(token));

  return res.json({
    success: true,
    authenticated,
    authConfigured: configured,
    data: {
      authenticated,
      authConfigured: configured,
    },
  });
});
