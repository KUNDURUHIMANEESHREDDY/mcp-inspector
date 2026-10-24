@echo off
setlocal
title MCP Inspector - Dashboard
cd /d "%~dp0"

echo.
echo  MCP Inspector - Local Dashboard
echo  --------------------------------
echo  HTTP proxy:  http://127.0.0.1:9900
echo  Dashboard:  http://127.0.0.1:9911
echo.

where node >nul 2>nul
if errorlevel 1 (
  echo ERROR: Node.js was not found on PATH.
  echo Install Node.js 22 or newer, then reopen this window.
  pause
  exit /b 1
)

if not exist "node_modules\@modelcontextprotocol\client\package.json" (
  echo Dependencies are missing. Run RUN_LOCAL_CHECKS.bat first.
  pause
  exit /b 1
)

set "UPSTREAM=http://127.0.0.1:3000"
set /p "UPSTREAM=Enter upstream MCP Streamable HTTP URL [%UPSTREAM%]: "
if not defined UPSTREAM set "UPSTREAM=http://127.0.0.1:3000"

echo.
echo Starting the inspector proxy and light dashboard...
echo Keep this window open while using the dashboard.
echo Configure your MCP client to use http://127.0.0.1:9900 with the upstream MCP path.
echo.

node ".\src\cli.js" dashboard --upstream "%UPSTREAM%" --proxy-listen 127.0.0.1:9900 --dashboard-listen 127.0.0.1:9911
set "EXIT_CODE=%ERRORLEVEL%"
echo.
if not "%EXIT_CODE%"=="0" echo MCP Inspector exited with an error. Review the message above.
pause
exit /b %EXIT_CODE%
