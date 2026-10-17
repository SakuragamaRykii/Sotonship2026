# Reproducible environment setup (Windows PowerShell). Run from the repo root:
#   powershell -ExecutionPolicy Bypass -File scripts/setup.ps1
$ErrorActionPreference = "Stop"
if (-not (Test-Path .venv)) {
    py -3.11 -m venv .venv
}
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.lock.txt
.\.venv\Scripts\python.exe -m pip install -e . --no-deps
.\.venv\Scripts\python.exe scripts/download_models.py
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
Write-Host "Done. Activate with: .\.venv\Scripts\Activate.ps1   then run: pytest"
