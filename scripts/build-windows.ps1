$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    py -3 -m venv .venv
}

& ".venv\Scripts\python.exe" -m pip install --upgrade pip
& ".venv\Scripts\python.exe" -m pip install -e . pyinstaller

if (Test-Path "build") {
    Remove-Item -Recurse -Force "build"
}

if (Test-Path "dist\PacketScrubber.exe") {
    Remove-Item -Force "dist\PacketScrubber.exe"
}

& ".venv\Scripts\python.exe" -m PyInstaller --clean --noconfirm PacketScrubber.spec

$ExePath = Join-Path $ProjectRoot "dist\PacketScrubber.exe"
if (-not (Test-Path $ExePath)) {
    throw "Build completed without creating $ExePath"
}

Write-Host ""
Write-Host "Portable executable created:"
Write-Host $ExePath
