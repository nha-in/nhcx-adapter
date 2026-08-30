@echo off
rem Stop the nhcx-gateway started by serve-hidden.bat.
rem Asks it to shut down (in-flight requests drain for up to 30 s), then
rem forces it if it is still there.
setlocal
cd /d "%~dp0"

set PID=
if exist nhcx-gateway.pid set /p PID=<nhcx-gateway.pid
if "%PID%"=="" (
  taskkill /IM nhcx-gateway.exe >nul 2>&1 && echo nhcx-gateway stopped || echo nhcx-gateway is not running
  exit /b 0
)

tasklist /FI "PID eq %PID%" 2>nul | find "nhcx-gateway" >nul
if errorlevel 1 (
  echo nhcx-gateway is not running ^(stale pid %PID%^)
  del nhcx-gateway.pid
  exit /b 0
)

taskkill /PID %PID% >nul 2>&1
for /l %%i in (1,1,30) do (
  tasklist /FI "PID eq %PID%" 2>nul | find "nhcx-gateway" >nul || goto stopped
  timeout /t 1 /nobreak >nul
)
echo still running after 30 s - forcing
taskkill /F /PID %PID% >nul 2>&1

:stopped
del nhcx-gateway.pid
echo nhcx-gateway stopped
exit /b 0
