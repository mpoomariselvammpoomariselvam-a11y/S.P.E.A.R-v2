@echo off
title S.P.E.A.R Website
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 (
  echo Python launcher 'py' was not found. Install Python 3.10 or newer, then try again.
  pause
  exit /b 1
)
echo Starting the website on http://127.0.0.1:5500
echo Keep this window open. Opening the site in your browser...
start "" http://127.0.0.1:5500
py -3 -m http.server 5500 --bind 127.0.0.1
echo Website server stopped.
pause
