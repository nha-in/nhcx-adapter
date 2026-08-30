@echo off
rem Upgrade or downgrade nhcx-adapter from the GitHub releases.
rem   update.bat              pick a version from a menu
rem   update.bat --latest -y  newest release, no questions
rem   update.bat --to v1.2.0  a specific version (older = downgrade)
rem   update.bat --list       show what is available
rem   update.bat --check      exit code 1 when a newer release exists
setlocal
cd /d "%~dp0"

"%~dp0nhcx-adapter.exe" update %*
set RC=%errorlevel%
if not "%RC%"=="0" exit /b %RC%

if exist nhcx-adapter.pid (
  set /p PID=<nhcx-adapter.pid
  tasklist /FI "PID eq %PID%" 2>nul | find "nhcx-adapter" >nul && (
    echo.
    echo The running server ^(PID %PID%^) still uses the previous version.
    echo Run stop.bat and then serve-hidden.bat to switch.
  )
)
exit /b 0
