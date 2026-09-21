@echo off
rem Start nhcx-adapter in the background with no window.
rem   logs  -> logs\nhcx-adapter.log  (previous run kept as logs\nhcx-adapter.prev.log)
rem   pid   -> nhcx-adapter.pid
rem   stop  -> stop.bat
rem Runs "serve --no-tui": setup problems are written to the log and the
rem process exits, so check the log if nothing is listening.
setlocal
cd /d "%~dp0"

if exist nhcx-adapter.pid (
  set /p OLDPID=<nhcx-adapter.pid
  tasklist /FI "PID eq %OLDPID%" 2>nul | find "nhcx-adapter" >nul && (
    echo nhcx-adapter is already running ^(PID %OLDPID%^). Run stop.bat first.
    exit /b 1
  )
  del nhcx-adapter.pid
)

if not exist logs mkdir logs
if exist logs\nhcx-adapter.log (
  if exist logs\nhcx-adapter.prev.log del /q logs\nhcx-adapter.prev.log
  move /y logs\nhcx-adapter.log logs\nhcx-adapter.prev.log >nul
)

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$p = Start-Process -FilePath '%~dp0nhcx-adapter.exe' -ArgumentList @('serve','--no-tui') -WorkingDirectory '%~dp0' -WindowStyle Hidden -RedirectStandardError '%~dp0logs\nhcx-adapter.log' -RedirectStandardOutput '%~dp0logs\nhcx-adapter.out.log' -PassThru; Set-Content -Path '%~dp0nhcx-adapter.pid' -Value $p.Id -Encoding ascii; exit 0"
if errorlevel 1 (
  echo could not start nhcx-adapter.exe
  exit /b 1
)

rem Give the startup checks a moment, then report.
timeout /t 3 /nobreak >nul
set /p NEWPID=<nhcx-adapter.pid
tasklist /FI "PID eq %NEWPID%" 2>nul | find "nhcx-adapter" >nul
if errorlevel 1 (
  echo nhcx-adapter exited during startup. Last log lines:
  echo.
  powershell -NoProfile -Command "Get-Content -Tail 20 '%~dp0logs\nhcx-adapter.log'"
  del nhcx-adapter.pid
  exit /b 1
)
echo nhcx-adapter started ^(PID %NEWPID%^) - logs in logs\nhcx-adapter.log
exit /b 0
