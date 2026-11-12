#!/usr/bin/env bash

# Exit immediately if an unhandled error occurs
set -e

# Resolve current script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="$SCRIPT_DIR"

if [ -d "$SCRIPT_DIR/PROJECTS/intermediate/api-security-scanner" ]; then
    TARGET_DIR="$SCRIPT_DIR/PROJECTS/intermediate/api-security-scanner"
fi

cd "$TARGET_DIR"

echo "=========================================================="
echo " Starting OWASP API Security Scanner (Backend & Frontend)"
echo "=========================================================="

# Locate Python in virtual environment
if [ -f "$TARGET_DIR/.venv/Scripts/python.exe" ]; then
    PYTHON_CMD="$TARGET_DIR/.venv/Scripts/python.exe"
elif [ -f "$TARGET_DIR/.venv/bin/python" ]; then
    PYTHON_CMD="$TARGET_DIR/.venv/bin/python"
else
    PYTHON_CMD="python"
fi

# Cleanup child processes on exit
cleanup() {
    echo ""
    echo "Stopping all processes..."
    kill $(jobs -p) 2>/dev/null || true
    wait 2>/dev/null || true
    echo "All processes stopped."
}
trap cleanup SIGINT SIGTERM EXIT

# 1. Start Backend
echo "[1/2] Starting Backend (FastAPI on http://127.0.0.1:8000)..."
cd "$TARGET_DIR/backend"
"$PYTHON_CMD" -m uvicorn main:app --reload --host 127.0.0.1 --port 8000 &
BACKEND_PID=$!

# Brief pause to let backend bind port
sleep 2

# 2. Start Frontend
echo "[2/2] Starting Frontend (Vite on http://localhost:5173)..."
cd "$TARGET_DIR/frontend"
npm run dev &
FRONTEND_PID=$!

echo ""
echo "=========================================================="
echo " Both servers are running!"
echo " - Backend API:      http://127.0.0.1:8000"
echo " - Swagger Docs:     http://127.0.0.1:8000/docs"
echo " - Web UI:           http://localhost:5173"
echo " Press Ctrl+C in this terminal to stop both servers."
echo "=========================================================="

wait

