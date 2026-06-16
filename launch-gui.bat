@echo off
setlocal

cd /d "%~dp0"

if exist ".venv\Scripts\packetscrubber.exe" (
    ".venv\Scripts\packetscrubber.exe"
    exit /b %errorlevel%
)

if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -m packetscrubber.gui
    exit /b %errorlevel%
)

echo Creating Windows virtual environment...
py -3 -m venv .venv
if errorlevel 1 exit /b %errorlevel%

echo Installing PacketScrubber dependencies...
".venv\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 exit /b %errorlevel%
".venv\Scripts\python.exe" -m pip install -e .
if errorlevel 1 exit /b %errorlevel%

".venv\Scripts\python.exe" -m packetscrubber.gui
