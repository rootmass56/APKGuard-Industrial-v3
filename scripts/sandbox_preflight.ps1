$ErrorActionPreference = "Stop"
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
        throw "Sandbox preflight is not ready. Review the JSON blockers above."
    }
}
finally {
    Pop-Location
}
