@echo off
cd /d "%~dp0"
echo Running safe-mode-cleanup.ps1 ...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0safe-mode-cleanup.ps1"
echo.
echo The log is saved next to this script.
pause
