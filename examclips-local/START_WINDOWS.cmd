@echo off
setlocal
cd /d "%~dp0"
where node >nul 2>&1
if errorlevel 1 (
  echo Node.js 22 or newer is required. Install from https://nodejs.org
  pause
  exit /b 1
)
if not exist "node_modules\vite" (
  echo Installing ExamClips app dependencies, not uploading any video...
  call npm install --ignore-scripts --no-audit --no-fund
  if errorlevel 1 (
    echo npm install failed
    pause
    exit /b 1
  )
)
echo Starting ExamClips on http://localhost:5173
start "" cmd /c "timeout /t 4 >nul && start http://localhost:5173"
call npm run dev -- --host 127.0.0.1
pause
