@echo off
title AI Exploit Chain Mapper - Push to GitHub
cd /d "%~dp0"
echo =========================================================================
echo Pushing project to https://github.com/muhammadharis4359/FYP.git
echo =========================================================================
echo.
echo If prompted, authenticate via GitHub in the browser window.
echo.
git push -u origin main
echo.
pause
