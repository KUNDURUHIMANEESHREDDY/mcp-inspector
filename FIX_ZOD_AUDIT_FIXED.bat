@echo off
setlocal EnableExtensions DisableDelayedExpansion
cd /d "%~dp0"
title MCP Inspector - Repair Zod audit finding

echo ============================================================
echo  MCP Inspector - repair Zod dependency and verify
echo ============================================================
echo.

where node.exe >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Node.js is not installed or not on PATH.
  echo Install Node.js 22 or newer, reopen this window, and retry.
  goto failed
)
where npm.cmd >nul 2>&1
if errorlevel 1 (
  echo [ERROR] npm.cmd was not found. Repair or reinstall Node.js.
  goto failed
)
if not exist "package.json" (
  echo [ERROR] package.json was not found. Run this from the mcp-inspector root folder.
  goto failed
)

echo [1/5] Updating the manifest to use patched Zod 4.6.7...
call node.exe -e "const fs=require('node:fs'); const path='package.json'; const p=JSON.parse(fs.readFileSync(path,'utf8')); p.dependencies=p.dependencies||{}; p.devDependencies=p.devDependencies||{}; delete p.dependencies.zod; p.devDependencies.zod='4.6.7'; if(Object.keys(p.dependencies).length===0) delete p.dependencies; fs.writeFileSync(path,JSON.stringify(p,null,2)+'\n'); console.log('Set devDependencies.zod=4.6.7 and removed any conflicting dependencies.zod pin.');"
if errorlevel 1 (
  echo [ERROR] Could not update package.json.
  goto failed
)

echo.
echo [2/5] Refreshing node_modules and package-lock.json...
call npm.cmd install --no-audit --no-fund
if errorlevel 1 (
  echo [ERROR] npm install failed. Review npm's output above.
  goto failed
)

echo.
echo [3/5] Confirming the installed Zod version...
call node.exe -e "const v=require('./node_modules/zod/package.json').version; const a=v.split('.').map(Number); if(a[0]<4||(a[0]===4&&(a[1]<6||(a[1]===6&&a[2]<6)))) { console.error('Vulnerable Zod version still installed:',v); process.exit(1); } console.log('Installed Zod:',v,'(meets the >=4.6.6 advisory fix floor).');"
if errorlevel 1 (
  echo [ERROR] Installed Zod is still below the fixed version. Do not publish.
  call npm.cmd ls zod --all
  goto failed
)
call npm.cmd ls zod --all
if errorlevel 1 (
  echo [ERROR] npm reports an invalid Zod dependency tree. Do not publish.
  goto failed
)

echo.
echo [4/5] Running the high-severity dependency audit...
call npm.cmd audit --audit-level=high
if errorlevel 1 (
  echo [ERROR] Audit still reports a high-severity finding or the registry is unreachable.
  echo Read the full advisory output above. Do not bypass it with --force.
  goto failed
)

echo.
echo [5/5] Running static checks and the full test suite...
call npm.cmd run check
if errorlevel 1 (
  echo [ERROR] Static checks failed.
  goto failed
)
call npm.cmd test
if errorlevel 1 (
  echo [ERROR] Tests failed.
  goto failed
)

echo.
echo [SUCCESS] Zod version, audit, static checks, and tests passed.
echo Next: run RUN_LOCAL_CHECKS.bat, then PUSH_TO_GITHUB.bat.
echo.
pause
exit /b 0

:failed
echo.
echo [STOPPED] Zod repair did not complete. Copy the complete output above.
echo.
pause
exit /b 1
