@echo off
setlocal

for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":5000" ^| findstr "LISTENING"') do (
    echo Stopping WebGuard process %%a...
    taskkill /PID %%a /F >nul 2>&1
)

echo Done.
pause
