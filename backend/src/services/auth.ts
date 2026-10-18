import crypto from 'crypto';
import { db } from '../queue/jobQueue.js';

// Ensure sessions table exists
db.exec(`
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    createdAt TEXT NOT NULL,
    expiresAt TEXT NOT NULL
  );
`);

const insertSessionStmt = db.prepare(`
  INSERT INTO sessions (token_hash, createdAt, expiresAt)
  VALUES (?, ?, ?)
`);

const getSessionStmt = db.prepare(`
  SELECT token_hash FROM sessions
  WHERE token_hash = ? AND expiresAt > ?
`);

const deleteSessionStmt = db.prepare(`
  DELETE FROM sessions
  WHERE token_hash = ?
`);

export { hashPassword, verifyPassword } from './password.js';

export function isAuthConfigured(): boolean {
  return Boolean(process.env.WEB_RE_ADMIN_PASSWORD_HASH && process.env.WEB_RE_ADMIN_PASSWORD_HASH.trim().length > 0);
}

export function createSession(): string {
  const token = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const createdAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + 12 * 60 * 60 * 1000).toISOString();
  insertSessionStmt.run(tokenHash, createdAt, expiresAt);
  return token;
}

export function validateSession(token: string): boolean {
  if (!token) return false;
  try {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const now = new Date().toISOString();
    const row = getSessionStmt.get(tokenHash, now);
    return Boolean(row);
  } catch {
    return false;
  }
}

export function deleteSession(token: string): void {
  if (!token) return;
  try {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    deleteSessionStmt.run(tokenHash);
  } catch {
    // ignore
  }
}

export function parseCookies(header?: string): Record<string, string> {
  if (!header) return {};
  const cookies: Record<string, string> = {};
  const items = header.split(';');
  for (const item of items) {
    const idx = item.indexOf('=');
    if (idx > 0) {
      const key = item.substring(0, idx).trim();
      const val = item.substring(idx + 1).trim();
      try {
        cookies[key] = decodeURIComponent(val);
      } catch {
        cookies[key] = val;
      }
    }
  }
  return cookies;
}
