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
$MigrationRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("apkguard-phase4-" + [guid]::NewGuid())
$MigrationDatabase = Join-Path $MigrationRoot "migration.db"
$OriginalDatabaseUrl = $env:APKGUARD_DATABASE_URL

New-Item -ItemType Directory -Path $MigrationRoot -Force | Out-Null

Push-Location $Backend
try {
    $MigrationDatabaseUri = $MigrationDatabase.Replace("\", "/")
    $env:APKGUARD_DATABASE_URL = "sqlite:///$MigrationDatabaseUri"

    Invoke-Required "Alembic Phase 4 migration" {
        alembic upgrade head
    }

    Invoke-Required "Migration schema" {
        python -c "from sqlalchemy import create_engine, inspect; import os; tables=set(inspect(create_engine(os.environ['APKGUARD_DATABASE_URL'])).get_table_names()); required={'alembic_version','artifacts','scan_events','scan_jobs','scan_results','sandbox_sessions','sandbox_events'}; assert required <= tables, sorted(required-tables); print(sorted(tables))"
    }

    Invoke-Required "Python compilation" {
        python -m compileall -q -x "(^|[\/])(.venv|cache|data|__pycache__)([\/]|$)" .
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

    Invoke-Required "Backend version and fail-closed policy" {
        python -c "from app.core.config import Settings, get_settings; from app.dynamic_analysis.policy import SandboxPolicy; assert get_settings().app_version == '4.0.0-phase4'; test=Settings(); assert not SandboxPolicy(test).execution_permitted; print(get_settings().app_version)"
    }

    Invoke-Required "Dynamic analysis API contracts" {
        python -c "from app.main import create_app; paths=create_app().openapi()['paths']; required={'/api/v1/dynamic-analysis/capabilities','/api/v1/dynamic-analysis/policy','/api/v1/dynamic-analysis/sessions/{scan_id}','/api/v1/dynamic-analysis/sessions/{scan_id}/events'}; assert required <= set(paths), sorted(required-set(paths)); print(len(required))"
    }
}
finally {
    if ($null -eq $OriginalDatabaseUrl) {
        Remove-Item Env:APKGUARD_DATABASE_URL -ErrorAction SilentlyContinue
    }
    else {
        $env:APKGUARD_DATABASE_URL = $OriginalDatabaseUrl
    }
    Pop-Location
    Remove-Item $MigrationRoot -Recurse -Force -ErrorAction SilentlyContinue
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

if (Get-Command docker -ErrorAction SilentlyContinue) {
    Invoke-Required "Docker Compose syntax" {
        docker compose -f (Join-Path $Root "docker-compose.yml") config --quiet
    }
}
else {
    Write-Warning "Docker is unavailable; Docker Compose runtime validation was skipped."
}

Write-Host "[APKGuard] Repository tracked-file safety"
$TrackedFiles = git -C $Root ls-files
if ($LASTEXITCODE -ne 0) {
    throw "git ls-files failed with exit code $LASTEXITCODE"
}

$UnsafeTracked = $TrackedFiles | Select-String -Pattern "(^|/)\.env$|(^|/)(data|quarantine|sandbox_sessions)/|\.(apk|aab|dex|exe|dll|db|sqlite|pyc)$|(^|/)node_modules/|(^|/)dist/|(^|/)__pycache__/"
if ($UnsafeTracked) {
    $UnsafeTracked | ForEach-Object { Write-Host $_.Line }
    throw "Generated, sensitive, executable, or sample files are tracked."
}

Write-Host "[APKGuard] Credential-shaped literal safety"
$GoogleStyle = git -C $Root grep -n -E "AIza[A-Za-z0-9_-]{35}" -- . 2>$null
if ($LASTEXITCODE -eq 0 -and $GoogleStyle) {
    $GoogleStyle | ForEach-Object { Write-Host $_ }
    throw "A Google API-key-shaped literal is tracked."
}
if ($LASTEXITCODE -notin @(0, 1)) {
    throw "Credential-shaped literal scan failed with exit code $LASTEXITCODE"
}

Write-Host "[APKGuard] Repository status"
git -C $Root status --short
if ($LASTEXITCODE -ne 0) {
    throw "Repository status check failed with exit code $LASTEXITCODE"
}

Write-Host "Phase 4 verification complete: ALL REQUIRED CHECKS PASSED."
