import { useEffect, useRef, useState, useCallback } from 'react';
import type { WsMessage } from '@shared/types.js';

export function useWebSocket(jobId?: string) {
  const [lastMessage, setLastMessage] = useState<WsMessage | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const socketRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    // Same origin in production; Vite proxies /ws to the backend in dev
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    const ws = new WebSocket(wsUrl);
    socketRef.current = ws;

    ws.onopen = () => {
      setIsConnected(true);
      if (jobId) {
        ws.send(JSON.stringify({ type: 'subscribe', jobId }));
      }
    };

    ws.onclose = () => {
      setIsConnected(false);
    };

    ws.onmessage = (event) => {
      try {
        const msg: WsMessage = JSON.parse(event.data);
        setLastMessage(msg);
      } catch (e) {
        console.error('Failed to parse WebSocket message', e);
      }
    };

    return () => {
      if (jobId && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'unsubscribe', jobId }));
      }
      ws.close();
    };
  }, [jobId]);

  const subscribe = useCallback((id: string) => {
    if (socketRef.current && socketRef.current.readyState === WebSocket.OPEN) {
      socketRef.current.send(JSON.stringify({ type: 'subscribe', jobId: id }));
    }
  }, []);

  return { isConnected, lastMessage, subscribe };
}
