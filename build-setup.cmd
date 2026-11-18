@echo off
rem Builds SecHUD-Setup.exe, the installer people download. It does not run it.
cd /d "%~dp0"
echo Building the installer...
dotnet build setup\SecHUD.Setup.csproj -c Release -nologo > setup\build-log.txt 2>&1
if errorlevel 1 (
  echo.
  echo BUILD FAILED. The full output is in setup\build-log.txt
  echo.
  findstr /i /c:"error" setup\build-log.txt
  echo.
  pause
  exit /b 1
)
echo Build OK: setup\bin\Release\SecHUD-Setup.exe
echo.
echo Double-click that file to try it. It installs the newest PUBLISHED release,
echo not the build on this PC.
explorer "setup\bin\Release"
pause
