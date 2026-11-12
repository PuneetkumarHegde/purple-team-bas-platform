@echo off
setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

echo ================================================================
echo  Starting Unified API Security Scanner ^& AI Threat Platform
echo ================================================================
echo.

echo [1/3] Launching FastAPI Backend (Port 8000)...
start "API Security Backend" cmd /k "cd /d "%SCRIPT_DIR%backend" && "%SCRIPT_DIR%.venv\Scripts\python.exe" -m uvicorn main:app --reload --host 127.0.0.1 --port 8000"

timeout /t 2 /nobreak >nul

echo [2/3] Launching Vite Frontend (Port 5173)...
start "API Security Frontend" cmd /k "cd /d "%SCRIPT_DIR%frontend" && npm run dev"

timeout /t 3 /nobreak >nul

echo [3/3] Opening Dashboard in browser...
start http://localhost:5173

echo.
echo ================================================================
echo  Both servers are running in dedicated command windows!
echo  - Web Dashboard:     http://localhost:5173
echo  - Swagger API Docs:  http://127.0.0.1:8000/docs
echo  - Default Login:     admin@example.com / AdminPassword123
echo ================================================================
echo.
echo Leave those server windows open while using the platform.
pause
