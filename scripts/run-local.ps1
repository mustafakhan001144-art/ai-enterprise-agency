# Start the AI Audit Agency locally on Windows and open the dashboard.
# Usage (from the repository root):
#   powershell -ExecutionPolicy Bypass -File scripts\run-local.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\run-local.ps1 -Reinstall   # re-run pip install
#
# What it does, in order:
#   1. creates .venv with Python 3.12 or 3.11 if it does not exist, and installs requirements.lock
#   2. creates .env from .env.example if there is no .env (an existing .env is never changed)
#   3. creates a demo account with 500 credits the first time, and saves its key to storage\demo-key.txt
#   4. opens the API and the worker in two new PowerShell windows, then opens the dashboard
# Stop everything by closing the two windows (or Ctrl+C in each).
param([switch]$Reinstall, [int]$Port = 8000)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    $version = $null
    foreach ($candidate in @("3.12", "3.11")) {
        & py "-$candidate" -c "import sys" 2>$null
        if ($LASTEXITCODE -eq 0) { $version = $candidate; break }
    }
    if (-not $version) { throw "Python 3.12 or 3.11 is required. Install it from python.org, then run this script again." }
    Write-Host "Creating .venv with Python $version"
    & py "-$version" -m venv .venv
    $Reinstall = $true
}
if ($Reinstall) {
    Write-Host "Installing dependencies from requirements.lock"
    & $python -m pip install --upgrade pip
    & $python -m pip install -r requirements.lock
    if ($LASTEXITCODE -ne 0) { throw "pip install failed" }
}

if (-not (Test-Path ".env")) {
    Copy-Item .env.example .env
    Write-Host "Created .env from .env.example (placeholder Stripe test values are fine for a local demo)."
}

New-Item -ItemType Directory -Force storage | Out-Null
$keyFile = Join-Path $root "storage\demo-key.txt"
if (-not (Test-Path $keyFile)) {
    Write-Host "Creating a demo account"
    $demo = & $python -m api.admin demo | Out-String | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or -not $demo.api_key) { throw "Could not create the demo account. Check the AGENCY_ settings in .env." }
    Set-Content -Path $keyFile -Value $demo.api_key -NoNewline -Encoding ascii
}
$key = Get-Content $keyFile -Raw

$activate = ". '$root\.venv\Scripts\Activate.ps1'; Set-Location '$root'"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "$activate; `$host.UI.RawUI.WindowTitle = 'Agency API'; uvicorn api.main:create_app --factory --host 127.0.0.1 --port $Port"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "$activate; `$host.UI.RawUI.WindowTitle = 'Agency worker'; python -m core.worker"

Write-Host "Waiting for the API on port $Port"
$ready = $false
for ($i = 0; $i -lt 30; $i++) {
    try {
        $r = Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:$Port/readyz" -TimeoutSec 2
        if ($r.StatusCode -eq 200) { $ready = $true; break }
    } catch { Start-Sleep -Seconds 1 }
}
if (-not $ready) { throw "The API did not start. Read the error in the 'Agency API' window." }

Set-Clipboard -Value $key
Write-Host ""
Write-Host "Dashboard: http://127.0.0.1:$Port/"
Write-Host "Your demo API key is in storage\demo-key.txt and has been copied to the clipboard."
Write-Host "Paste it into the API key box and press Connect."
Start-Process "http://127.0.0.1:$Port/"
