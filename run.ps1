# PowerShell runner for OWASP API Security Scanner
$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Starting OWASP API Security Scanner (Backend & Frontend)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Start Backend in separate window
Write-Host "[1/2] Launching Backend on http://127.0.0.1:8000..." -ForegroundColor Green
$backendCmd = "cd '$scriptDir\backend'; & '..\.venv\Scripts\python.exe' -m uvicorn main:app --reload --host 127.0.0.1 --port 8000"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $backendCmd

Start-Sleep -Seconds 2

# 2. Start Frontend in separate window
Write-Host "[2/2] Launching Frontend on http://localhost:5173..." -ForegroundColor Green
$frontendCmd = "cd '$scriptDir\frontend'; npm run dev"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $frontendCmd

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Yellow
Write-Host " Both servers are launching in dedicated windows!" -ForegroundColor Yellow
Write-Host " - Backend API:  http://127.0.0.1:8000" -ForegroundColor White
Write-Host " - Swagger Docs: http://127.0.0.1:8000/docs" -ForegroundColor White
Write-Host " - Web UI:       http://localhost:5173" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Yellow

