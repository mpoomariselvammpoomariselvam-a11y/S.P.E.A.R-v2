@echo off
title S.P.E.A.R Backend
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 (
  echo Python launcher 'py' was not found. Install Python 3.10 or newer, then try again.
  pause
  exit /b 1
)
echo Starting S.P.E.A.R backend on http://127.0.0.1:8000
echo Keep this window open while using the website.
py -3 server.py
echo Backend stopped.
pause
