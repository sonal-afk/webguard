@echo off
setlocal

cd /d "%~dp0"

rem Starts everything needed for a WebGuard demo:
rem   1. the WebGuard backend + dashboard   http://127.0.0.1:5000
rem   2. the local practice target          http://127.0.0.1:9000
rem The practice target only simulates vulnerable responses and listens on
rem 127.0.0.1, so nothing outside this laptop can reach it.

set "PY=venv312\Scripts\python.exe"
if not exist "%PY%" (
    echo venv312 not found. Run run_webguard.bat once first to set up Python.
    pause
    exit /b 1
)

echo Starting practice target on http://127.0.0.1:9000 ...
start "WebGuard practice target (port 9000)" "%PY%" "webguard\vulnerable_test_server.py"

echo Starting WebGuard on http://127.0.0.1:5000 ...
start "WebGuard backend (port 5000)" "%PY%" "webguard\backend.py"

rem Give the backend a few seconds to start before opening the browser.
timeout /t 6 /nobreak >nul
start "" "http://127.0.0.1:5000"

echo.
echo Both servers are running in their own windows. Close those windows to stop them.
echo Demo steps: see DEMO.md
echo.
pause
