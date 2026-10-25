@echo off
setlocal
cd /d "%~dp0"
where node >nul 2>nul || (echo [ERROR] Node.js not found. Install Node 20.6+ from https://nodejs.org & pause & exit /b 1)
where npm  >nul 2>nul || (echo [ERROR] npm not found. & pause & exit /b 1)
if not exist node_modules (
  echo Installing dependencies...
  call npm install || (echo [ERROR] npm install failed. & pause & exit /b 1)
)
if not exist .env if exist .env.example copy /y .env.example .env >nul
echo.
echo  Frontend: http://127.0.0.1:5000
echo  API:      http://127.0.0.1:3001/api/health
echo.
call npm run dev
echo.
echo Server stopped. Press any key to close.
pause >nul
