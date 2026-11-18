@echo off
rem Builds SecHUD, runs the tests and makes a zip to upload as a GitHub release.
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\make-release.ps1"
echo.
pause
