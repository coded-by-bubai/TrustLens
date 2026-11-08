@echo off
setlocal enabledelayedexpansion

echo ===================================================
echo   TrustLens - Starting React Frontend Dashboard
echo ===================================================

:: 1. Check if Node.js / npm is installed
where npm >nul 2>&1
if errorlevel 1 (
    echo [TrustLens ERROR] 'npm' was not found in your system PATH.
    echo Please install Node.js (version 18 or newer) from https://nodejs.org
    pause
    exit /b 1
)

cd frontend

:: 2. Check if node_modules exists, install if missing
if not exist node_modules (
    echo [TrustLens] 'node_modules' directory not found.
    echo [TrustLens] Running 'npm install' to fetch dependencies...
    call npm install
    if errorlevel 1 (
        echo [TrustLens ERROR] Failed to install frontend dependencies.
        pause
        exit /b 1
    )
    echo [TrustLens] Frontend packages installed successfully.
) else (
    echo [TrustLens] Frontend dependencies verified.
)

:: 3. Launch Vite development server
echo ===================================================
echo [TrustLens] Launching Vite Dashboard on http://localhost:5173
echo ===================================================
call npm run dev

pause
