@echo off
rem Start nhcx-gateway in the background with no window.
rem   logs  -> logs\nhcx-gateway.log  (previous run kept as logs\nhcx-gateway.prev.log)
rem   pid   -> nhcx-gateway.pid
rem   stop  -> stop.bat
rem Runs "serve --no-tui": setup problems are written to the log and the
rem process exits, so check the log if nothing is listening.
setlocal
cd /d "%~dp0"

if exist nhcx-gateway.pid (
  set /p OLDPID=<nhcx-gateway.pid
  tasklist /FI "PID eq %OLDPID%" 2>nul | find "nhcx-gateway" >nul && (
    echo nhcx-gateway is already running ^(PID %OLDPID%^). Run stop.bat first.
    exit /b 1
  )
  del nhcx-gateway.pid
)

if not exist logs mkdir logs
if exist logs\nhcx-gateway.log (
  if exist logs\nhcx-gateway.prev.log del /q logs\nhcx-gateway.prev.log
  move /y logs\nhcx-gateway.log logs\nhcx-gateway.prev.log >nul
)

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$p = Start-Process -FilePath '%~dp0nhcx-gateway.exe' -ArgumentList @('serve','--no-tui') -WorkingDirectory '%~dp0' -WindowStyle Hidden -RedirectStandardError '%~dp0logs\nhcx-gateway.log' -RedirectStandardOutput '%~dp0logs\nhcx-gateway.out.log' -PassThru; Set-Content -Path '%~dp0nhcx-gateway.pid' -Value $p.Id -Encoding ascii; exit 0"
if errorlevel 1 (
  echo could not start nhcx-gateway.exe
  exit /b 1
)

rem Give the startup checks a moment, then report.
timeout /t 3 /nobreak >nul
set /p NEWPID=<nhcx-gateway.pid
tasklist /FI "PID eq %NEWPID%" 2>nul | find "nhcx-gateway" >nul
if errorlevel 1 (
  echo nhcx-gateway exited during startup. Last log lines:
  echo.
  powershell -NoProfile -Command "Get-Content -Tail 20 '%~dp0logs\nhcx-gateway.log'"
  del nhcx-gateway.pid
  exit /b 1
)
echo nhcx-gateway started ^(PID %NEWPID%^) - logs in logs\nhcx-gateway.log
exit /b 0
