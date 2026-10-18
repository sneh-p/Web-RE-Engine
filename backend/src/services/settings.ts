import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { db, dataDir } from '../queue/jobQueue.js';

export type AiProvider = 'anthropic' | 'openai';

export interface AiConfig {
  provider: AiProvider;
  model: string;
  baseUrl?: string;
  apiKey?: string;
  source: 'portal' | 'env';
}

// What the browser may see: never the key itself
export interface AiConfigPublic {
  configured: boolean;
  source: 'portal' | 'env' | 'none';
  provider?: AiProvider;
  model?: string;
  baseUrl?: string;
  keyHint?: string;
}

export const DEFAULT_ANTHROPIC_MODEL = 'claude-opus-5-5';

db.exec(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)`);

// ---- Secret storage: API keys are encrypted with a per-server key kept beside the database ----

let secretKey: Buffer | null = null;

function getSecretKey(): Buffer {
  if (secretKey) return secretKey;
  if (process.env.WEB_RE_SECRET_KEY) {
    secretKey = crypto.createHash('sha256').update(process.env.WEB_RE_SECRET_KEY).digest();
    return secretKey;
  }
  const keyFile = path.join(dataDir, 'secret.key');
  if (!fs.existsSync(keyFile)) {
    fs.writeFileSync(keyFile, crypto.randomBytes(32).toString('hex'), { mode: 0o600 });
  }
  secretKey = Buffer.from(fs.readFileSync(keyFile, 'utf8').trim(), 'hex');
  return secretKey;
}

function encrypt(plain: string): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', getSecretKey(), iv);
  const data = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  return [iv, cipher.getAuthTag(), data].map((b) => b.toString('base64')).join('.');
}

function decrypt(blob: string): string {
  const [iv, tag, data] = blob.split('.').map((p) => Buffer.from(p, 'base64'));
  const decipher = crypto.createDecipheriv('aes-256-gcm', getSecretKey(), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
}

// ---- AI provider configuration ----

interface StoredAiConfig {
  provider: AiProvider;
  model: string;
  baseUrl?: string;
  apiKeyEnc?: string;
}

function readStored(): StoredAiConfig | null {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get('ai') as { value: string } | undefined;
  if (!row) return null;
  try {
    return JSON.parse(row.value) as StoredAiConfig;
  } catch {
    return null;
  }
}

export function getAiConfig(): AiConfig | null {
  const stored = readStored();
  if (stored) {
    let apiKey: string | undefined;
    if (stored.apiKeyEnc) {
      try {
        apiKey = decrypt(stored.apiKeyEnc);
      } catch {
        // secret.key changed or the row was tampered with: treat as no key
        apiKey = undefined;
      }
    }
    return { provider: stored.provider, model: stored.model, baseUrl: stored.baseUrl, apiKey, source: 'portal' };
  }
  // Backwards compatible: a key in backend/.env still works
  if (process.env.ANTHROPIC_API_KEY || process.env.ANTHROPIC_AUTH_TOKEN) {
    return {
      provider: 'anthropic',
      model: process.env.WEB_RE_AI_MODEL || DEFAULT_ANTHROPIC_MODEL,
      apiKey: process.env.ANTHROPIC_API_KEY || undefined,
      source: 'env',
    };
  }
  return null;
}

// Local OpenAI-compatible servers (Ollama, LM Studio) don't need a key; hosted providers do
export function isAiUsable(cfg: AiConfig | null): cfg is AiConfig {
  if (!cfg || !cfg.model) return false;
  if (cfg.provider === 'anthropic') return !!cfg.apiKey || cfg.source === 'env';
  return !!cfg.baseUrl && (!!cfg.apiKey || /^https?:\/\/(localhost|127\.|\[::1\]|host\.docker\.internal)/i.test(cfg.baseUrl));
}

export function getAiConfigPublic(): AiConfigPublic {
  const cfg = getAiConfig();
  if (!cfg) return { configured: false, source: 'none' };
  const key = cfg.apiKey ?? '';
  return {
    configured: isAiUsable(cfg),
    source: cfg.source,
    provider: cfg.provider,
    model: cfg.model,
    baseUrl: cfg.baseUrl,
    keyHint: key ? `…${key.slice(-4)}` : undefined,
  };
}

export interface AiConfigUpdate {
  provider: AiProvider;
  model: string;
  baseUrl?: string;
  // undefined keeps the stored key, '' removes it
  apiKey?: string;
}

export function validateAiUpdate(u: any): string | null {
  if (u?.provider !== 'anthropic' && u?.provider !== 'openai') return 'provider must be "anthropic" or "openai"';
  if (typeof u.model !== 'string' || !/^[\w.:/@+-]{1,120}$/.test(u.model.trim())) return 'model must be a model id (letters, digits, . : / @ + - _)';
  if (u.baseUrl !== undefined && u.baseUrl !== '') {
    if (typeof u.baseUrl !== 'string') return 'baseUrl must be a URL';
    try {
      const url = new URL(u.baseUrl);
      if (url.protocol !== 'https:' && url.protocol !== 'http:') return 'baseUrl must be http(s)';
    } catch {
      return 'baseUrl must be a valid URL';
    }
  }
  if (u.provider === 'openai' && !u.baseUrl) return 'An OpenAI-compatible provider needs a base URL';
  if (u.apiKey !== undefined && (typeof u.apiKey !== 'string' || u.apiKey.length > 500)) return 'apiKey must be a string';
  return null;
}

export function saveAiConfig(u: AiConfigUpdate): void {
  const previous = readStored();
  const keepKey = u.apiKey === undefined && previous?.provider === u.provider;
  const stored: StoredAiConfig = {
    provider: u.provider,
    model: u.model.trim(),
    baseUrl: u.baseUrl ? u.baseUrl.trim().replace(/\/+$/, '') : undefined,
    apiKeyEnc: keepKey ? previous?.apiKeyEnc : u.apiKey ? encrypt(u.apiKey.trim()) : undefined,
  };
  db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(
    'ai',
    JSON.stringify(stored)
  );
}

export function clearAiConfig(): void {
  db.prepare('DELETE FROM settings WHERE key = ?').run('ai');
}
