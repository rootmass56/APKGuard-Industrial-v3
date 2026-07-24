$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot

Write-Host "[APKGuard] Backend verification" -ForegroundColor Cyan
Push-Location "$Root\backend"
try {
    python -m compileall .
    python -m pytest -q
    ruff check .
    bandit -r . -x .\.venv,.\tests
    python -c "import main; print('Backend version:', main.APP_VERSION)"
}
finally {
    Pop-Location
}

Write-Host "[APKGuard] Frontend verification" -ForegroundColor Cyan
Push-Location "$Root\frontend"
try {
    npm ci
    npm run lint
    npm run build
    npm audit --audit-level=low
}
finally {
    Pop-Location
}

Write-Host "[APKGuard] Repository status" -ForegroundColor Cyan
git -C $Root status --short
Write-Host "Phase 1 verification complete." -ForegroundColor Green
