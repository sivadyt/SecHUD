@echo off
rem Builds SecHUD.exe and starts it. Needs the .NET SDK that comes with Visual Studio.
cd /d "%~dp0"

rem A running copy locks the exe, so close it before rebuilding.
taskkill /im SecHUD.exe /f >nul 2>&1
timeout /t 1 /nobreak >nul

echo Building SecHUD...
dotnet build SecHUD.csproj -c Release -nologo > build-log.txt 2>&1
if errorlevel 1 (
  echo.
  echo BUILD FAILED. The full output is in build-log.txt
  echo.
  findstr /i /c:"error" build-log.txt
  echo.
  pause
  exit /b 1
)
echo Build OK: bin\Release\SecHUD.exe
start "" "bin\Release\SecHUD.exe"
