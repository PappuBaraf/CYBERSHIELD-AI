#!/bin/bash
export PORT=3001

# Start backend
npx tsx server/index.ts &

# Wait a moment
sleep 2

# Start vite with local config to ignore .local directory
exec npx vite --config vite.config.local.ts --port 5000 --host 0.0.0.0
