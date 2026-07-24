$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$destination = "D:\projects\APKGuard-checkpoints\APKGuard-Phase2-complete.zip"
New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
Push-Location (Split-Path -Parent $root)
tar -a -c -f $destination `
    --exclude="APKGuard-Ai-working/.git" `
    --exclude="APKGuard-Ai-working/backend/.venv" `
    --exclude="APKGuard-Ai-working/backend/.env" `
    --exclude="APKGuard-Ai-working/backend/__pycache__" `
    --exclude="APKGuard-Ai-working/backend/.pytest_cache" `
    --exclude="APKGuard-Ai-working/backend/.ruff_cache" `
    --exclude="APKGuard-Ai-working/backend/cache" `
    --exclude="APKGuard-Ai-working/backend/data" `
    --exclude="APKGuard-Ai-working/frontend/node_modules" `
    --exclude="APKGuard-Ai-working/frontend/dist" `
    --exclude="APKGuard-Ai-working/frontend/.env" `
    "APKGuard-Ai-working"
Pop-Location
Get-Item $destination | Select-Object Name, Length, LastWriteTime
