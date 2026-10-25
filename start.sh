#!/bin/bash
set -e

export NODE_ENV=production

npm run build
npx tsx server/index.ts
