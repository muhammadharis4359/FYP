@echo off
title AI Exploit Chain Mapper - Live Terminal Monitor
color 0A
cd /d "%~dp0backend"

echo =========================================================================
echo Starting Real-Time Cyber Terminal Monitor...
echo =========================================================================

if exist "venv\Scripts\python.exe" (
    venv\Scripts\python.exe live_monitor.py
) else (
    python live_monitor.py
)
pause
