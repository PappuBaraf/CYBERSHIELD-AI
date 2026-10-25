#!/bin/bash
while true; do
  echo "$(date): Starting backend server..."
  PORT=3001 npx tsx server/index.ts
  echo "$(date): Backend server exited, restarting in 2 seconds..."
  sleep 2
done
