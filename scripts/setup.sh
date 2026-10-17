#!/usr/bin/env bash
# Reproducible environment setup (macOS / Linux / Git Bash). Run from the repo root:
#   bash scripts/setup.sh
set -euo pipefail
PY=${PYTHON:-python3.11}
if [ ! -d .venv ]; then
  "$PY" -m venv .venv
fi
if [ -f .venv/Scripts/python.exe ]; then VPY=.venv/Scripts/python.exe; else VPY=.venv/bin/python; fi
"$VPY" -m pip install --upgrade pip
"$VPY" -m pip install -r requirements.lock.txt
"$VPY" -m pip install -e . --no-deps
"$VPY" scripts/download_models.py
[ -f .env ] || cp .env.example .env
echo "Done. Activate with: source .venv/bin/activate (or .venv/Scripts/activate on Git Bash), then run: pytest"
