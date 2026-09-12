@echo off
cd /d "%~dp0"
echo =======================================================
echo Recon ^& Exploit Mapper - FastAPI Backend Server
echo =======================================================

if not exist "venv\Scripts\python.exe" (
    echo [*] Virtual environment not found. Creating venv...
    python -m venv venv
    echo [*] Installing dependencies...
    venv\Scripts\pip install -r requirements.txt
)

if not exist ".env" (
    echo [*] Creating .env configuration file...
    copy .env.example .env
)

echo [*] Starting Uvicorn development server...
echo [*] Dashboard: http://127.0.0.1:8000
echo [*] API Docs:  http://127.0.0.1:8000/docs
echo =======================================================
venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
pause

