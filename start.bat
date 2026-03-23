@echo off
echo ============================================
echo   IDS - Intrusion Detection System Launcher
echo ============================================
echo.
echo [IMPORTANT] For Live Packet Capture:
echo   - This script must be run AS ADMINISTRATOR
echo   - Npcap must be installed: https://npcap.com/
echo   - Right-click this file and select "Run as administrator"
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found! Please install Python 3.8+ and add to PATH.
    pause
    exit /b 1
)

:: Check Node
node --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Node.js not found! Please install Node.js 18+ from https://nodejs.org
    pause
    exit /b 1
)

echo [1/4] Installing Python backend dependencies...
cd /d "%~dp0backend"
pip install -r requirements.txt -q
if errorlevel 1 (
    echo [ERROR] Failed to install Python packages.
    pause
    exit /b 1
)

echo [2/4] Installing frontend dependencies...
cd /d "%~dp0"
if not exist "node_modules" (
    npm install
) else (
    echo      node_modules already exists, skipping npm install.
)

echo [3/4] Starting Flask backend on port 5000...
echo      NOTE: Live capture requires Admin privileges ^& Npcap installed.
cd /d "%~dp0backend"
start "IDS Backend (Flask)" cmd /k "python app.py"

:: Give Flask time to start
timeout /t 3 /nobreak >nul

echo [4/4] Starting Vite frontend on port 5173...
cd /d "%~dp0"
start "IDS Frontend (Vite)" cmd /k "npm run dev"

timeout /t 3 /nobreak >nul

echo.
echo ============================================
echo   Project is running!
echo   Frontend     : http://localhost:5173
echo   Backend API  : http://localhost:5000/api/health
echo   Live Monitor : http://localhost:5173/live
echo ============================================
echo.
echo   [Live Capture Setup Checklist]
echo   1. Install Npcap: https://npcap.com/
echo   2. Run this .bat as Administrator
echo   3. Navigate to /live in the frontend
echo.

:: Open browser
start http://localhost:5173

echo Both servers are running in separate windows.
echo Close those windows to stop the servers.
pause
