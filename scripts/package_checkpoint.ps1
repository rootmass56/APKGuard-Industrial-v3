$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = Split-Path -Parent $PSScriptRoot
$Destination = "D:\projects\APKGuard-checkpoints\APKGuard-Phase4-complete.zip"
New-Item -ItemType Directory -Path (Split-Path -Parent $Destination) -Force | Out-Null

$Status = git -C $Root status --porcelain
if ($LASTEXITCODE -ne 0) {
    throw "Unable to read repository status."
}
if ($Status) {
    throw "Create release checkpoints only from a clean committed tree."
}

if (Test-Path $Destination) {
    Remove-Item $Destination -Force
}

git -C $Root archive `
    --format=zip `
    --prefix=APKGuard-Ai-working/ `
    --output=$Destination `
    HEAD

if ($LASTEXITCODE -ne 0) {
    throw "git archive failed with exit code $LASTEXITCODE"
}

Get-Item $Destination | Select-Object Name, Length, LastWriteTime
