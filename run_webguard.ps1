$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
# venv312 already has Flask, torch (CUDA) and transformers installed; a fresh
# .venv only gets requirements.txt, which leaves the ML model switched off.
$Python = Join-Path $Root "venv312\Scripts\python.exe"

if (-not (Test-Path $Python)) {
    $Python = Join-Path $Root ".venv\Scripts\python.exe"
    if (-not (Test-Path $Python)) {
        Write-Host "Creating virtual environment..."
        python -m venv (Join-Path $Root ".venv")
    }

    Write-Host "Installing dependencies..."
    & $Python -m pip install --upgrade pip
    & $Python -m pip install -r (Join-Path $Root "requirements-ml.txt")
}

$EnvFile = Join-Path $Root "webguard\.env"
$EnvExample = Join-Path $Root "webguard\.env.example"
if (-not (Test-Path $EnvFile)) {
    Copy-Item $EnvExample $EnvFile
    Write-Host "Created webguard\.env from example. Edit it to change the login password."
}

Write-Host ""
Write-Host "Starting WebGuard..."
# Use 127.0.0.1 (not localhost): the extension talks to 127.0.0.1, and the
# login cookie only applies to the exact host you log in on.
Write-Host "Open http://127.0.0.1:5000  (not localhost - the extension needs this exact address)"
Write-Host "Default login: admin / admin123"
Write-Host ""

& $Python (Join-Path $Root "webguard\backend.py")
