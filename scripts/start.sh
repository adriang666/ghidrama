#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ ! -x .venv/bin/python ]]; then
  echo "Create .venv and install the Python dependencies first; see README.md." >&2
  exit 1
fi
if [[ ! -f frontend/dist/index.html ]]; then
  echo "Build the web interface first: cd frontend && pnpm install && pnpm build" >&2
  exit 1
fi
exec .venv/bin/python scripts/serve.py
