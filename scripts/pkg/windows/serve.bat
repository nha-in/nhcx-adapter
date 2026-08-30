@echo off
rem Run nhcx-gateway in this window. Ctrl+C stops it.
rem Extra arguments are passed through, e.g. serve.bat --skip-checks
setlocal
cd /d "%~dp0"
"%~dp0nhcx-gateway.exe" serve %*
exit /b %errorlevel%
