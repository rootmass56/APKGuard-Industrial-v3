param(
    [string]$Destination = "D:\projects\APKGuard-checkpoints\APKGuard-Phase1-complete.zip"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Parent = Split-Path -Parent $Root
$FolderName = Split-Path -Leaf $Root

New-Item -ItemType Directory -Path (Split-Path -Parent $Destination) -Force | Out-Null

Push-Location $Parent
try {
    tar -a -c -f $Destination `
        --exclude="$FolderName/.git" `
        --exclude="$FolderName/backend/.venv" `
        --exclude="$FolderName/backend/.env" `
        --exclude="$FolderName/backend/__pycache__" `
        --exclude="$FolderName/backend/.pytest_cache" `
        --exclude="$FolderName/backend/.ruff_cache" `
        --exclude="$FolderName/backend/cache" `
        --exclude="$FolderName/frontend/node_modules" `
        --exclude="$FolderName/frontend/dist" `
        --exclude="$FolderName/frontend/.env" `
        $FolderName
}
finally {
    Pop-Location
}

Get-Item $Destination | Select-Object Name, Length, LastWriteTime
