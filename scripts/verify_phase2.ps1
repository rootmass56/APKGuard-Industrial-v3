Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot

function Invoke-CheckedCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Command
    )

    $global:LASTEXITCODE = 0
    & $Command

    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE."
    }
}

try {
    Write-Host "[APKGuard] Phase 2 backend verification"
    Push-Location "$root\backend"
    try {
        Write-Host "[APKGuard] Applying local database migrations"
        Invoke-CheckedCommand "Alembic upgrade" { alembic upgrade head }
        Invoke-CheckedCommand "Python compilation" { python -m compileall . }
        Invoke-CheckedCommand "Backend tests" { python -m pytest -q }
        Invoke-CheckedCommand "Ruff" { ruff check . }
        Invoke-CheckedCommand "Bandit" { bandit -r . -x ".\.venv,.\tests,.\migrations" }
        Invoke-CheckedCommand "Backend version and database check" {
            python -c "from app.core.config import get_settings; from app.db.session import get_database; get_database().initialize(); print('Backend version:', get_settings().app_version); print('Database:', get_database().ping())"
        }

        Write-Host "[APKGuard] Alembic migration smoke test"
        $migrationDb = Join-Path $env:TEMP "apkguard-phase2-migration-$([guid]::NewGuid().ToString('N')).db"
        $oldDatabaseUrl = $env:APKGUARD_DATABASE_URL
        $oldAutoCreate = $env:APKGUARD_AUTO_CREATE_DATABASE

        try {
            $env:APKGUARD_DATABASE_URL = "sqlite:///$($migrationDb.Replace('\', '/'))"
            $env:APKGUARD_AUTO_CREATE_DATABASE = "false"

            Invoke-CheckedCommand "Temporary Alembic migration" { alembic upgrade head }
            Invoke-CheckedCommand "Migration table verification" {
                python -c "from sqlalchemy import create_engine, inspect; import os; engine=create_engine(os.environ['APKGUARD_DATABASE_URL']); expected={'artifacts','scan_jobs','scan_events','scan_results','alembic_version'}; actual=set(inspect(engine).get_table_names()); assert expected <= actual, (expected, actual); print('Migration tables:', sorted(actual))"
            }
        }
        finally {
            if ($null -eq $oldDatabaseUrl) {
                Remove-Item Env:APKGUARD_DATABASE_URL -ErrorAction SilentlyContinue
            }
            else {
                $env:APKGUARD_DATABASE_URL = $oldDatabaseUrl
            }

            if ($null -eq $oldAutoCreate) {
                Remove-Item Env:APKGUARD_AUTO_CREATE_DATABASE -ErrorAction SilentlyContinue
            }
            else {
                $env:APKGUARD_AUTO_CREATE_DATABASE = $oldAutoCreate
            }

            Remove-Item $migrationDb -Force -ErrorAction SilentlyContinue
        }
    }
    finally {
        Pop-Location
    }

    Write-Host "[APKGuard] Phase 2 frontend verification"
    Push-Location "$root\frontend"
    try {
        Invoke-CheckedCommand "Frontend dependency installation" { npm ci }
        Invoke-CheckedCommand "Frontend lint" { npm run lint }
        Invoke-CheckedCommand "Frontend production build" { npm run build }
        Invoke-CheckedCommand "Frontend dependency audit" { npm audit }
    }
    finally {
        Pop-Location
    }

    if (Get-Command docker -ErrorAction SilentlyContinue) {
        Write-Host "[APKGuard] Docker Compose syntax"
        Invoke-CheckedCommand "Docker Compose validation" {
            docker compose -f "$root\docker-compose.yml" config --quiet
        }
    }
    else {
        Write-Warning "Docker is not installed; Compose runtime verification was skipped."
    }

    Write-Host "[APKGuard] Repository status"
    Push-Location $root
    try {
        Invoke-CheckedCommand "Git status" { git status --short }
    }
    finally {
        Pop-Location
    }

    Write-Host "Phase 2 verification complete: ALL REQUIRED CHECKS PASSED."
}
catch {
    Write-Error "Phase 2 verification failed: $($_.Exception.Message)"
    exit 1
}
