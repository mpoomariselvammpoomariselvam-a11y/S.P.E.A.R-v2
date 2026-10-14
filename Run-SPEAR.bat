@echo off
title S.P.E.A.R launcher
setlocal
cd /d "%~dp0"

rem ---- find Python ----
set "PY="
py -3 --version >nul 2>nul && set "PY=py -3"
if not defined PY ( python --version >nul 2>nul && set "PY=python" )
if not defined PY (
  echo Python 3.10 or newer was not found. Install Python from python.org
  echo and tick "Add Python to PATH", then run this file again.
  pause
  exit /b 1
)

rem ---- free ports 8000 and 5500 if an old server is still running ----
for %%P in (8000 5500) do (
  for /f "tokens=5" %%A in ('netstat -ano ^| findstr /R /C:":%%P .*LISTENING"') do taskkill /F /PID %%A >nul 2>nul
)

rem ---- cmd /k keeps each window open so any error stays visible ----
start "S.P.E.A.R Backend" /D "%~dp0SPEAR-backend" cmd /k %PY% server.py
start "S.P.E.A.R Website" /D "%~dp0SPEAR-frontend" cmd /k %PY% -m http.server 5500 --bind 127.0.0.1

timeout /t 3 /nobreak >nul
start "" http://127.0.0.1:5500
echo.
echo S.P.E.A.R is running. Keep both server windows open while using it.
echo ALWAYS open:  http://127.0.0.1:5500   (not localhost, not index.html)
endlocal
