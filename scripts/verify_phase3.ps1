$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Invoke-Required {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Label,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Action
    )

    Write-Host "[APKGuard] $Label"
    & $Action

    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE"
    }
}

$Root = Split-Path -Parent $PSScriptRoot
$Backend = Join-Path $Root "backend"
$Frontend = Join-Path $Root "frontend"

Push-Location $Backend
try {
    Invoke-Required "Python compilation" {
        python -m compileall .
    }

    Invoke-Required "Backend tests" {
        python -m pytest -q
    }

    Invoke-Required "Ruff" {
        ruff check .
    }

    Invoke-Required "Bandit" {
        bandit -r . -x .\.venv,.\tests
    }

    Invoke-Required "Backend version" {
        python -c "from app.core.config import get_settings; settings = get_settings(); assert settings.app_version == '3.2.0-phase3'; print(settings.app_version)"
    }

    Invoke-Required "Static rule metadata" {
        python -c "from app.static_analysis.rules import CODE_RULES; assert len(CODE_RULES) >= 10; print(len(CODE_RULES))"
    }
}
finally {
    Pop-Location
}

Push-Location $Frontend
try {
    Invoke-Required "Frontend install" {
        npm ci
    }

    Invoke-Required "Frontend lint" {
        npm run lint
    }

    Invoke-Required "Frontend build" {
        npm run build
    }

    Invoke-Required "Frontend audit" {
        npm audit --audit-level=low
    }
}
finally {
    Pop-Location
}

Write-Host "[APKGuard] Repository sample safety"

$UnsafeExtensions = @(
    "*.apk",
    "*.aab",
    "*.dex",
    "*.exe",
    "*.dll"
)

$UnsafeFiles = foreach ($Pattern in $UnsafeExtensions) {
    Get-ChildItem `
        -Path $Root `
        -Recurse `
        -File `
        -Filter $Pattern `
        -ErrorAction SilentlyContinue |
        Where-Object {
            $_.FullName -notmatch "[\\/]backend[\\/]\.venv[\\/]" -and
            $_.FullName -notmatch "[\\/]frontend[\\/]node_modules[\\/]" -and
            $_.FullName -notmatch "[\\/]frontend[\\/]dist[\\/]"
        }
}

if ($UnsafeFiles) {
    $UnsafeFiles | ForEach-Object {
        Write-Host $_.FullName
    }

    throw "Live or executable sample files are present in the repository checkpoint."
}

Write-Host "[APKGuard] Repository status"
git -C $Root status --short

if ($LASTEXITCODE -ne 0) {
    throw "Repository status check failed with exit code $LASTEXITCODE"
}

Write-Host "Phase 3 verification complete: ALL REQUIRED CHECKS PASSED."
