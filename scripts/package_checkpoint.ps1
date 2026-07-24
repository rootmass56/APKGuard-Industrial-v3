$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$destination = "D:\projects\APKGuard-checkpoints\APKGuard-Phase3-complete.zip"
New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
Push-Location (Split-Path -Parent $root)
tar -a -c -f $destination `
    --exclude="APKGuard-Ai-working/.git" `
    --exclude="APKGuard-Ai-working/backend/.venv" `
    --exclude="APKGuard-Ai-working/backend/.env" `
    --exclude="*/__pycache__" `
    --exclude="*.pyc" `
    --exclude="*/.pytest_cache" `
    --exclude="*/.ruff_cache" `
    --exclude="APKGuard-Ai-working/backend/cache" `
    --exclude="APKGuard-Ai-working/backend/data" `
    --exclude="APKGuard-Ai-working/backend/quarantine" `
    --exclude="APKGuard-Ai-working/frontend/node_modules" `
    --exclude="APKGuard-Ai-working/frontend/dist" `
    --exclude="APKGuard-Ai-working/frontend/.env" `
    "APKGuard-Ai-working"
Pop-Location
Get-Item $destination | Select-Object Name, Length, LastWriteTime
