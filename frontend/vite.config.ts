import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
      '@shared': path.resolve(__dirname, '../shared'),
    },
  },
  server: {
    port: 5173,
    proxy: {
      // Keep the browser's Host header so the backend's Origin/Host CSRF check matches
      '/api': {
        target: 'http://localhost:3001',
        changeOrigin: false,
      },
      '/ws': {
        target: 'http://localhost:3001',
        changeOrigin: false,
        ws: true,
      },
    },
  },
});
