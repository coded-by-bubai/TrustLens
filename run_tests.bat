@echo off
setlocal enabledelayedexpansion

echo ===================================================
echo   TrustLens - Running Automated Pytest Suite
echo ===================================================

:: 1. Check if venv exists, create if missing
if not exist .\venv\Scripts\python.exe (
    echo [TrustLens] Virtual environment not detected.
    echo [TrustLens] Creating virtual environment 'venv'...
    python -m venv venv
    if errorlevel 1 (
        echo [TrustLens WARNING] Could not create virtual environment.
        echo [TrustLens] Falling back to system Python...
        set "PYTHON_EXE=python"
    ) else (
        echo [TrustLens] Virtual environment created successfully.
        set "PYTHON_EXE=.\venv\Scripts\python.exe"
    )
) else (
    set "PYTHON_EXE=.\venv\Scripts\python.exe"
)

:: 2. Check if required packages are installed
echo [TrustLens] Verifying test dependencies...
!PYTHON_EXE! -c "import pytest, fastapi, uvicorn" >nul 2>&1
if errorlevel 1 (
    echo [TrustLens] Test dependencies not found.
    echo [TrustLens] Installing dependencies from backend\requirements.txt...
    !PYTHON_EXE! -m pip install -r backend\requirements.txt
    if errorlevel 1 (
        echo [TrustLens ERROR] Failed to install dependencies.
        pause
        exit /b 1
    )
    echo [TrustLens] Dependencies installed successfully.
) else (
    echo [TrustLens] All test dependencies verified.
)

:: 3. Execute Pytest
echo ===================================================
echo [TrustLens] Executing pytest on backend/tests...
echo ===================================================
set "PYTHONPATH=backend"
!PYTHON_EXE! -m pytest backend/tests -v

pause
