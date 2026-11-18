@echo off
rem Tries the one-click update for real, on a copy of your build so your own files are left alone.
cd /d "%~dp0.."
if not exist "bin\Release\SecHUD.exe" (
  echo Run build.cmd first.
  pause
  exit /b 1
)

set "COPYDIR=%TEMP%\SecHUD-update-test"
taskkill /im SecHUD.exe /f >nul 2>&1
timeout /t 1 /nobreak >nul
if exist "%COPYDIR%" rmdir /s /q "%COPYDIR%"
mkdir "%COPYDIR%"
copy /y "bin\Release\SecHUD.exe" "%COPYDIR%\" >nul
if exist "bin\Release\SecHUD.exe.config" copy /y "bin\Release\SecHUD.exe.config" "%COPYDIR%\" >nul

echo SecHUD update test
echo.
echo A copy of your build is starting from:
echo   %COPYDIR%
echo It has been told to offer the newest release on GitHub, whatever version it is.
echo.
echo   1. Wait a few seconds for the yellow UPDATE AVAILABLE button at the top.
echo   2. Click it and answer Yes.
echo   3. SecHUD should close and open again by itself within a few seconds.
echo   4. Open Settings and scroll to UPDATES. The version shown there should be
echo      the one that was on the button.
echo.
echo When you have seen it: right-click the SecHUD icon near the clock, choose Exit,
echo then start your own SecHUD again (build.cmd does that).
echo.
start "" "%COPYDIR%\SecHUD.exe" --test-update
pause
