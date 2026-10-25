@echo off
setlocal
cd /d "%~dp0"

where node >nul 2>&1
if errorlevel 1 (
  echo ERROR: Node.js was not found. Install Node.js 20.19 or later and reopen this terminal.
  exit /b 1
)
where npm >nul 2>&1
if errorlevel 1 (
  echo ERROR: npm was not found. Install npm with Node.js and reopen this terminal.
  exit /b 1
)

node -e "const [major,minor]=process.versions.node.split('.').map(Number); process.exit(major > 20 || (major === 20 && minor >= 19) ? 0 : 1)"
if errorlevel 1 (
  echo ERROR: Node.js 20.19 or later is required. Current version:
  node --version
  exit /b 1
)

if not exist "node_modules\concurrently" (
  echo Installing root dependencies...
  call npm install
  if errorlevel 1 (
    echo ERROR: Root dependency installation failed.
    exit /b 1
  )
)
if not exist "client\node_modules\vite" (
  echo Installing frontend dependencies...
  call npm install --prefix client
  if errorlevel 1 (
    echo ERROR: Frontend dependency installation failed.
    exit /b 1
  )
)

echo Starting CyberShield AI at http://127.0.0.1:5173
call npm run dev
set "APP_EXIT=%ERRORLEVEL%"
if not "%APP_EXIT%"=="0" (
  echo ERROR: CyberShield AI stopped with exit code %APP_EXIT%.
  exit /b %APP_EXIT%
)
endlocal
