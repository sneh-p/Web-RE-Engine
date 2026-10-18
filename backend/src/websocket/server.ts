import type { WebSocket, WebSocketServer } from 'ws';
import type { WsMessage } from '../../../shared/types.js';

// Map from jobId -> Set of subscribed WebSocket clients
const subscriptions = new Map<string, Set<WebSocket>>();

export function setupWebSocket(wss: WebSocketServer) {
  wss.on('connection', (ws) => {
    ws.on('message', (raw) => {
      try {
        const msg = JSON.parse(raw.toString());
        if (msg.type === 'subscribe' && msg.jobId) {
          if (!subscriptions.has(msg.jobId)) {
            subscriptions.set(msg.jobId, new Set());
          }
          subscriptions.get(msg.jobId)!.add(ws);
        }
        if (msg.type === 'unsubscribe' && msg.jobId) {
          subscriptions.get(msg.jobId)?.delete(ws);
        }
      } catch {
        // ignore malformed messages
      }
    });

    ws.on('close', () => {
      // Remove this client from all subscriptions
      for (const clients of subscriptions.values()) {
        clients.delete(ws);
      }
    });
  });
}

export function broadcast(jobId: string, message: WsMessage) {
  const clients = subscriptions.get(jobId);
  if (!clients) return;
  const payload = JSON.stringify(message);
  for (const ws of clients) {
    if (ws.readyState === 1 /* OPEN */) {
      ws.send(payload);
    }
  }
}
