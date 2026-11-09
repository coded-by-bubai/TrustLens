@echo off
setlocal enabledelayedexpansion

echo ===================================================
echo   TrustLens - Starting FastAPI Backend Server
echo ===================================================

:: Ensure working directory is repo root
cd /d "%~dp0"

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
echo [TrustLens] Verifying backend dependencies...
!PYTHON_EXE! -c "import fastapi, uvicorn, pydantic, dns, cryptography" >nul 2>&1
if errorlevel 1 (
    echo [TrustLens] Required packages not found.
    echo [TrustLens] Installing dependencies from backend\requirements.txt...
    !PYTHON_EXE! -m pip install -r backend\requirements.txt
    if errorlevel 1 (
        echo [TrustLens ERROR] Failed to install dependencies.
        pause
        exit /b 1
    )
    echo [TrustLens] Dependencies installed successfully.
) else (
    echo [TrustLens] All backend dependencies verified.
)

:: 3. Launch the FastAPI server
echo ===================================================
echo [TrustLens] Launching backend server on http://127.0.0.1:8000
echo [TrustLens] Interactive Swagger Docs: http://127.0.0.1:8000/docs
echo ===================================================
set "PYTHONPATH=backend"
!PYTHON_EXE! -m uvicorn app.main:app --host 127.0.0.1 --port 8000

pause
