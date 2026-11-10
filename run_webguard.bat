@echo off
setlocal

cd /d "%~dp0"

rem venv312 already has Flask, torch (CUDA) and transformers installed; a fresh
rem .venv only gets the listed requirements, so prefer venv312 when it exists.
set "PY=venv312\Scripts\python.exe"
if exist "%PY%" goto have_python

set "PY=.venv\Scripts\python.exe"
if not exist "%PY%" (
    echo Creating virtual environment...
    python -m venv .venv
    if errorlevel 1 (
        echo Failed to create virtual environment. Make sure Python is installed and added to PATH.
        pause
        exit /b 1
    )
)

echo Installing dependencies...
"%PY%" -m pip install --upgrade pip
"%PY%" -m pip install -r requirements-ml.txt
if errorlevel 1 (
    echo Dependency installation failed.
    pause
    exit /b 1
)

:have_python
if not exist "webguard\.env" (
    copy "webguard\.env.example" "webguard\.env" >nul
    echo Created webguard\.env from webguard\.env.example
)

echo.
echo Starting WebGuard...
rem Use 127.0.0.1 (not localhost): the extension talks to 127.0.0.1, and the
rem login cookie only applies to the exact host you log in on.
echo Open http://127.0.0.1:5000  (not localhost - the extension needs this exact address)
echo Default login: admin / admin123
echo.

"%PY%" "webguard\backend.py"
pause
