@echo off
REM Build the Browser Traffic Firewall userscript from build\ blocks.
REM Double-click this file, or run `build.bat` from a terminal.

setlocal
cd /d "%~dp0"

where node >nul 2>nul
if errorlevel 1 (
    echo [build] ERROR: Node.js was not found on PATH. Install it from https://nodejs.org/
    pause
    exit /b 1
)

node "%~dp0build\build.js"
set "RC=%errorlevel%"

if not "%RC%"=="0" (
    echo [build] FAILED with exit code %RC%.
) else (
    echo [build] OK.
)

REM Keep the window open when double-clicked from Explorer.
if /i "%~1"=="" pause
exit /b %RC%
