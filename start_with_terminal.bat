@echo off
title AI Exploit Chain Mapper - Multi-Window Launcher
echo =========================================================================
echo       AI Exploit Chain Mapper - Launching Server ^& Live Terminal
echo =========================================================================
echo.
echo [*] Launching Backend API Server in Window 1...
start "AI Exploit Mapper - Backend Server" cmd /k "%~dp0start_dashboard.bat"

timeout /t 2 /nobreak >nul

echo [*] Launching Real-Time Cyber Terminal Monitor in Window 2...
start "AI Exploit Mapper - Live Terminal Monitor" cmd /k "%~dp0live_terminal.bat"

echo.
echo =========================================================================
echo [*] Both windows are running:
echo     - Window 1: FastAPI Server (http://127.0.0.1:8000)
echo     - Window 2: Live Tool Execution ^& Terminal Telemetry Stream
echo =========================================================================
timeout /t 5
