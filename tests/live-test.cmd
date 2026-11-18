@echo off
rem Runs the SecHUD live test. Right-click and choose "Run as administrator" to include the account test.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0live-test.ps1"
