@echo off
setlocal EnableExtensions DisableDelayedExpansion
cd /d "%~dp0"
title MCP Inspector - Fix OpenTelemetry Dependency

echo ============================================================
echo  MCP Inspector - fix OpenTelemetry dependency conflict
echo ============================================================
echo.
where powershell.exe >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Windows PowerShell was not found. Edit package.json manually:
  echo Change "@opentelemetry/api": "1.10.0" to "@opentelemetry/api": "1.9.1"
  goto :failed
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\fix-otel-dependency.ps1"
if errorlevel 1 goto :failed

echo.
echo Installing compatible dependencies now...
call npm.cmd install --no-audit --no-fund
if errorlevel 1 (
  echo [ERROR] Dependency resolution progressed, but npm install still failed.
  echo Review the npm error above; this may be a separate registry or dependency issue.
  goto :failed
)
echo.
echo [SUCCESS] Dependency installation finished.
echo Next, run RUN_LOCAL_CHECKS.bat to execute the full local verification.
echo.
pause
exit /b 0

:failed
echo.
echo [STOPPED] No force flags were used. The window will remain open.
echo.
pause
exit /b 1
