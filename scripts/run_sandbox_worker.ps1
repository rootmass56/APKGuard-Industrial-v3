$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Backend = Join-Path $ProjectRoot "backend"
$Python = Join-Path $Backend ".venv\Scripts\python.exe"

if (-not (Test-Path $Python)) {
    throw "Backend virtual environment was not found at $Python"
}

Push-Location $Backend
try {
    & $Python -m app.sandbox_preflight
    if ($LASTEXITCODE -ne 0) {
        throw "Sandbox preflight is blocked. Do not start the dynamic worker until every control is satisfied."
    }

    Write-Host "[APKGuard] Starting dedicated sandbox worker"
    & $Python -m app.worker
    if ($LASTEXITCODE -ne 0) {
        throw "Sandbox worker exited with code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}
