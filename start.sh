#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

echo "🚀 Starting Web RE Engine Backend on port 3001..."
cd "$DIR/backend"
npm run dev &
BACKEND_PID=$!

echo "✨ Starting Web RE Engine Frontend on port 5173..."
cd "$DIR/frontend"
npm run dev -- --host &
FRONTEND_PID=$!

trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null" EXIT

echo "Web RE Engine is running:"
echo "👉 Frontend: http://localhost:5173"
echo "👉 Backend API: http://localhost:3001"
echo "Press Ctrl+C to terminate."

wait
