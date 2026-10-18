import express from 'express';
import cors from 'cors';
import { createServer } from 'http';
import { WebSocketServer } from 'ws';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

import { analysisRouter } from './routes/analysis.js';
import { jobsRouter } from './routes/jobs.js';
import { statusRouter } from './routes/status.js';
import { filesRouter } from './routes/files.js';
import { compareRouter } from './routes/compare.js';
import { settingsRouter } from './routes/settings.js';
import { authRouter } from './routes/auth.js';
import { setupWebSocket } from './websocket/server.js';
import { uploadsDir } from './middleware/upload.js';
import { csrfProtection, requireAuth } from './middleware/auth.js';
import { isAuthConfigured, parseCookies, validateSession } from './services/auth.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Load environment variables from backend/.env if present
try {
  process.loadEnvFile(path.resolve(__dirname, '../.env'));
} catch (e: any) {
  if (e?.code !== 'ENOENT') {
    // Ignore ENOENT (missing .env), rethrow other fatal syntax errors if any
  }
}

const app = express();
const server = createServer(app);

const isProd = process.env.NODE_ENV === 'production';
const HOST = process.env.HOST ?? (isProd ? '127.0.0.1' : '0.0.0.0');
const PORT = parseInt(process.env.PORT ?? '3001', 10);

app.set('trust proxy', 'loopback');

// Ensure uploads dir exists
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

// CORS only in non-production
if (!isProd) {
  app.use(cors({ origin: process.env.FRONTEND_URL ?? 'http://localhost:5173', credentials: true }));
}

app.use(express.json());

// CSRF protection for non-GET/HEAD API requests
app.use('/api', csrfProtection);

// Public auth routes
app.use('/api/auth', authRouter);

// Protected API routes
app.use('/api', requireAuth);
app.use('/api/analysis', analysisRouter);
app.use('/api/jobs', jobsRouter);
app.use('/api/status', statusRouter);
app.use('/api/files', filesRouter);
app.use('/api/compare', compareRouter);
app.use('/api/settings', settingsRouter);

// Static frontend serving in production
if (isProd) {
  const distDir = path.resolve(__dirname, '../../frontend/dist');
  app.use(express.static(distDir));
  app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api')) return next();
    res.sendFile(path.join(distDir, 'index.html'));
  });
}

// WebSocket setup with authentication and CSRF origin verification on upgrade
const wss = new WebSocketServer({ noServer: true });
setupWebSocket(wss);

server.on('upgrade', (req, socket, head) => {
  // CSRF Origin verification on upgrade
  const origin = req.headers.origin;
  if (origin) {
    try {
      const originHost = new URL(origin).host;
      const host = req.headers.host;
      const forwardedHost = req.headers['x-forwarded-host'] as string | undefined;

      if (originHost !== host && originHost !== forwardedHost) {
        socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
        socket.destroy();
        return;
      }
    } catch {
      socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
  }

  // Session cookie authentication
  const cookies = parseCookies(req.headers.cookie);
  const token = cookies['wre_session'];

  if (!isAuthConfigured() || !token || !validateSession(token)) {
    socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
    socket.destroy();
    return;
  }

  wss.handleUpgrade(req, socket, head, (ws) => {
    wss.emit('connection', ws, req);
  });
});

server.listen(PORT, HOST, () => {
  console.log(`\n🔬 Web RE Engine backend running at http://${HOST}:${PORT}`);
  console.log(`📡 WebSocket ready`);
});

export { wss };
