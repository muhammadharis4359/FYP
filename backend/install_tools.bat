@echo off
setlocal enabledelayedexpansion

echo =========================================================================
echo AI Exploit Chain Mapper - CLI Security Tools Downloader
echo =========================================================================
echo This script downloads official Windows 64-bit releases of:
echo   - subfinder (Passive Subdomain Enumeration)
echo   - httpx (Live Host Probing & Tech Fingerprinting)
echo   - nuclei (Vulnerability Template Scanner)
echo into the local 'bin' directory.
echo =========================================================================

set "BIN_DIR=%~dp0bin"
if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"
cd /d "%BIN_DIR%"

echo.
echo [1/3] Downloading Subfinder...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "try { $url = 'https://github.com/projectdiscovery/subfinder/releases/download/v2.6.8/subfinder_2.6.8_windows_amd64.zip'; [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri $url -OutFile subfinder.zip -UseBasicParsing; Expand-Archive -Path subfinder.zip -DestinationPath . -Force; Remove-Item subfinder.zip -Force; Write-Host 'Subfinder installed successfully.' -ForegroundColor Green } catch { Write-Host 'Subfinder download failed, continuing...' -ForegroundColor Yellow }"

echo.
echo [2/3] Downloading HTTPX...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "try { $url = 'https://github.com/projectdiscovery/httpx/releases/download/v1.6.8/httpx_1.6.8_windows_amd64.zip'; [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri $url -OutFile httpx.zip -UseBasicParsing; Expand-Archive -Path httpx.zip -DestinationPath . -Force; Remove-Item httpx.zip -Force; Write-Host 'HTTPX installed successfully.' -ForegroundColor Green } catch { Write-Host 'HTTPX download failed, continuing...' -ForegroundColor Yellow }"

echo.
echo [3/3] Downloading Nuclei...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "try { $url = 'https://github.com/projectdiscovery/nuclei/releases/download/v3.3.2/nuclei_3.3.2_windows_amd64.zip'; [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri $url -OutFile nuclei.zip -UseBasicParsing; Expand-Archive -Path nuclei.zip -DestinationPath . -Force; Remove-Item nuclei.zip -Force; Write-Host 'Nuclei installed successfully.' -ForegroundColor Green } catch { Write-Host 'Nuclei download failed, continuing...' -ForegroundColor Yellow }"

echo.
echo =========================================================================
echo Tools installation complete.
echo Binaries present in: %BIN_DIR%
echo =========================================================================
pause
