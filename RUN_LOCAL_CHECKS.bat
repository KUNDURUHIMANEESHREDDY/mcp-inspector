@echo off
setlocal EnableExtensions DisableDelayedExpansion
cd /d "%~dp0"
title MCP Inspector - Local Verification

call :main
set "RESULT=%ERRORLEVEL%"
echo.
if "%RESULT%"=="0" (
  echo [SUCCESS] Local verification completed.
) else (
  echo [STOPPED] Local verification failed with exit code %RESULT%.
  echo This window will remain open so you can read the failure.
  echo Copy the error output if you need help fixing it.
)
echo.
pause
exit /b %RESULT%

:main
echo ============================================================
echo  MCP Inspector - local install and verification
echo ============================================================
echo.

where node >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Node.js is missing. Install Node.js 22 or newer from https://nodejs.org/
  exit /b 2
)
for /f "tokens=1 delims=." %%V in ('node -v') do set "NODE_MAJOR=%%V"
set "NODE_MAJOR=%NODE_MAJOR:~1%"
if not defined NODE_MAJOR (
  echo [ERROR] Could not determine Node.js version.
  node -v
  exit /b 2
)
if %NODE_MAJOR% LSS 22 (
  echo [ERROR] Node.js 22 or newer is required. Detected major version %NODE_MAJOR%.
  echo Install a supported version, reopen the terminal, and rerun this file.
  exit /b 2
)
where npm >nul 2>&1
if errorlevel 1 (
  echo [ERROR] npm was not found. Repair or reinstall Node.js from https://nodejs.org/
  exit /b 2
)
for /f "tokens=1 delims=." %%V in ('call npm.cmd -v') do set "NPM_MAJOR=%%V"
if not defined NPM_MAJOR (
  echo [ERROR] Could not determine npm version.
  call npm.cmd -v
  exit /b 2
)
if %NPM_MAJOR% LSS 10 (
  echo [ERROR] npm 10 or newer is required. Detected major version %NPM_MAJOR%.
  exit /b 2
)

echo [1/5] Installing dependencies. Internet access to the npm registry is required...
call npm.cmd install --no-audit --no-fund
if errorlevel 1 (
  echo [ERROR] npm install failed. Check network access, proxy, and the npm error above.
  exit /b 3
)

echo.
echo [2/5] Running static checks...
call npm.cmd run check
if errorlevel 1 (
  echo [ERROR] Static checks failed.
  exit /b 4
)

echo.
echo [3/5] Running the complete test suite...
call npm.cmd test
if errorlevel 1 (
  echo [ERROR] One or more tests failed.
  exit /b 5
)

echo.
echo [4/5] Running dependency security audit...
call npm.cmd audit --audit-level=high
if errorlevel 1 (
  echo [ERROR] npm audit failed or the registry could not be reached. Review the output above.
  exit /b 6
)

echo.
echo [5/5] Generating local benchmark evidence...
node .\bench\framer.js > mcp-inspector-framer-benchmark.json
if errorlevel 1 (
  echo [ERROR] Framing benchmark failed.
  exit /b 7
)
node .\bench\mcp-roundtrip.js > mcp-inspector-benchmark.json
if errorlevel 1 (
  echo [ERROR] MCP round-trip benchmark failed.
  exit /b 7
)

echo.
echo All local checks completed. Benchmark JSON files are in this folder.
echo To publish, authenticate with GitHub CLI using: gh auth login
echo Then run PUSH_TO_GITHUB.bat.
exit /b 0
