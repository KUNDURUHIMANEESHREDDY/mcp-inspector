@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"
title MCP Inspector - Local Verification
set "EXIT_CODE=0"

echo ============================================================
echo  MCP Inspector - local install and verification
echo ============================================================
echo.

where node >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Node.js is missing. Install Node.js 22 or newer from https://nodejs.org/
  set "EXIT_CODE=2"
  goto failed
)
for /f "tokens=1 delims=." %%V in ('node -v') do set "NODE_MAJOR=%%V"
set "NODE_MAJOR=!NODE_MAJOR:~1!"
if not defined NODE_MAJOR (
  echo [ERROR] Could not determine Node.js version.
  call node -v
  set "EXIT_CODE=2"
  goto failed
)
if !NODE_MAJOR! LSS 22 (
  echo [ERROR] Node.js 22 or newer is required. Detected major version !NODE_MAJOR!.
  echo Install a supported version, reopen the terminal, and rerun this file.
  set "EXIT_CODE=2"
  goto failed
)
where npm.cmd >nul 2>&1
if errorlevel 1 (
  echo [ERROR] npm.cmd was not found. Repair or reinstall Node.js from https://nodejs.org/
  set "EXIT_CODE=2"
  goto failed
)
for /f "tokens=1 delims=." %%V in ('call npm.cmd -v') do set "NPM_MAJOR=%%V"
if not defined NPM_MAJOR (
  echo [ERROR] Could not determine npm version.
  call npm.cmd -v
  set "EXIT_CODE=2"
  goto failed
)
if !NPM_MAJOR! LSS 10 (
  echo [ERROR] npm 10 or newer is required. Detected major version !NPM_MAJOR!.
  set "EXIT_CODE=2"
  goto failed
)

echo [1/5] Installing dependencies and generating package-lock.json...
call npm.cmd install --no-audit --no-fund
if errorlevel 1 (
  echo [ERROR] npm install failed. Check the npm error above.
  set "EXIT_CODE=3"
  goto failed
)

echo.
echo [2/5] Running static checks...
call npm.cmd run check
if errorlevel 1 (
  echo [ERROR] Static checks failed.
  set "EXIT_CODE=4"
  goto failed
)

echo.
echo [3/5] Running the complete test suite...
call npm.cmd test
if errorlevel 1 (
  echo [ERROR] One or more tests failed.
  set "EXIT_CODE=5"
  goto failed
)

echo.
echo [4/5] Running dependency security audit...
call npm.cmd audit --audit-level=high
if errorlevel 1 (
  echo [ERROR] npm audit failed or the registry could not be reached. Review the output above.
  set "EXIT_CODE=6"
  goto failed
)

echo.
echo [5/5] Generating local benchmark evidence...
call node.exe .\bench\framer.js > mcp-inspector-framer-benchmark.json
if errorlevel 1 (
  echo [ERROR] Framing benchmark failed.
  set "EXIT_CODE=7"
  goto failed
)
call node.exe .\bench\mcp-roundtrip.js > mcp-inspector-benchmark.json
if errorlevel 1 (
  echo [ERROR] MCP round-trip benchmark failed.
  set "EXIT_CODE=7"
  goto failed
)

echo.
echo [SUCCESS] Local checks completed. Benchmark JSON files are in this folder.
echo To publish, authenticate with GitHub CLI using: gh auth login
echo Then run PUSH_TO_GITHUB.bat.
echo.
pause
exit /b 0

:failed
echo.
echo [STOPPED] Local verification failed with exit code !EXIT_CODE!.
echo This window will remain open so you can read the failure.
echo.
pause
exit /b !EXIT_CODE!
