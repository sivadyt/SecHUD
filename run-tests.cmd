@echo off
rem Builds and runs SecHUD's tests. They use a temporary folder and never touch your real data.
cd /d "%~dp0"
echo Building tests...
dotnet build tests\SecHUD.Tests.csproj -c Release -nologo > tests\build-log.txt 2>&1
if errorlevel 1 (
  echo BUILD FAILED. The full output is in tests\build-log.txt
  findstr /i /c:"error" tests\build-log.txt
  pause
  exit /b 1
)
tests\bin\Release\SecHUD.Tests.exe > tests\test-results.txt
type tests\test-results.txt
echo.
echo Results were also saved to tests\test-results.txt
pause
