@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"
title MCP Inspector - Verify and Publish

call :main
set "RESULT=%ERRORLEVEL%"
echo.
if "%RESULT%"=="0" (
  echo [DONE] The publishing script finished successfully.
) else (
  echo [STOPPED] The script exited with code %RESULT%.
  echo The window will remain open so you can read the error above.
  echo If needed, copy the complete error text and send it for diagnosis.
)
echo.
pause
exit /b %RESULT%

:main
echo ============================================================
echo  MCP Inspector - local verification and GitHub publication
echo ============================================================
echo.

where node >nul 2>&1 || (echo [ERROR] Node.js 22 or newer is required. Install from https://nodejs.org/ & exit /b 2)
for /f "tokens=1 delims=." %%V in ('node -v') do set "NODE_MAJOR=%%V"
set "NODE_MAJOR=%NODE_MAJOR:~1%"
if not defined NODE_MAJOR (
  echo [ERROR] Could not determine Node.js version.
  node -v
  exit /b 2
)
if %NODE_MAJOR% LSS 22 (
  echo [ERROR] Node.js 22 or newer is required. Detected major version %NODE_MAJOR%.
  echo Update Node.js, reopen this terminal, and rerun this script.
  exit /b 2
)
where git >nul 2>&1 || (echo [ERROR] Git is required. Install from https://git-scm.com/ & exit /b 2)
where gh >nul 2>&1 || (
  echo [ERROR] GitHub CLI is missing.
  echo Install it from https://cli.github.com/ then run: gh auth login
  exit /b 2
)
gh auth status >nul 2>&1 || (
  echo [ERROR] GitHub CLI is not authenticated.
  echo Run: gh auth login
  exit /b 2
)

echo [1/8] Installing pinned dependencies and generating package-lock.json...
call npm.cmd install --no-audit --no-fund
if errorlevel 1 (echo [ERROR] Dependency installation failed; no repository was published. & exit /b 3)

echo.
echo [2/8] Static checks...
call npm.cmd run check
if errorlevel 1 (echo [ERROR] Static checks failed; no repository was published. & exit /b 4)

echo.
echo [3/8] Tests...
call npm.cmd test
if errorlevel 1 (echo [ERROR] Tests failed; no repository was published. & exit /b 5)

echo.
echo [4/8] Dependency audit...
call npm.cmd audit --audit-level=high
if errorlevel 1 (
  echo [ERROR] npm audit did not pass. Review the report before publishing.
  echo No repository was published.
  exit /b 6
)

echo.
echo [5/8] Running and recording performance benchmarks...
node ./bench/framer.js > mcp-inspector-framer-benchmark.json
if errorlevel 1 (echo [ERROR] Framing benchmark failed; no repository was published. & exit /b 7)
node ./bench/mcp-roundtrip.js > mcp-inspector-benchmark.json
if errorlevel 1 (echo [ERROR] MCP SDK benchmark failed; no repository was published. & exit /b 7)

echo.
echo [6/8] Generating CycloneDX SBOM...
call npm.cmd sbom --sbom-format=cyclonedx > mcp-inspector.cdx.json
if errorlevel 1 (echo [ERROR] SBOM generation failed; no repository was published. & exit /b 8)

for /f "delims=" %%U in ('gh api user --jq .login') do set GH_USER=%%U
if not defined GH_USER (echo [ERROR] Could not determine the authenticated GitHub username. & exit /b 8)

if not exist ".git" git init -b main
if errorlevel 1 (echo [ERROR] Git initialization failed. & exit /b 9)
git branch -M main
if errorlevel 1 (echo [ERROR] Could not set the main branch. & exit /b 9)

for /f "delims=" %%N in ('git config user.name 2^>nul') do set GIT_NAME=%%N
if not defined GIT_NAME set GIT_NAME=%GH_USER%
for /f "delims=" %%E in ('git config user.email 2^>nul') do set GIT_EMAIL=%%E
if not defined GIT_EMAIL set GIT_EMAIL=%GH_USER%@users.noreply.github.com
git config user.name "%GIT_NAME%"
git config user.email "%GIT_EMAIL%"

echo.
echo [7/8] Staging verified source, generated lockfile, SBOM and benchmark evidence...
git add -A
if errorlevel 1 (echo [ERROR] Git staging failed. & exit /b 10)
git diff --cached --quiet
if errorlevel 1 (
  git commit -m "feat: bootstrap MCP Inspector protocol observability suite"
  if errorlevel 1 (echo [ERROR] Git commit failed. Configure git identity and retry. & exit /b 11)
) else (
  echo No new file changes to commit.
)

echo.
echo [8/8] Publishing GitHub repository...
gh repo view "%GH_USER%/mcp-inspector" >nul 2>&1
if errorlevel 1 (
  git remote get-url origin >nul 2>&1
  if not errorlevel 1 (echo [ERROR] An origin remote already exists but %GH_USER%/mcp-inspector was not found. Review the remote before publishing. & exit /b 12)
  echo A new repository will be created under %GH_USER%.
  set /p VISIBILITY="Choose visibility: P = public, N = private [N]: "
  if /I "!VISIBILITY!"=="P" (
    gh repo create mcp-inspector --public --source=. --remote=origin --push
  ) else (
    gh repo create mcp-inspector --private --source=. --remote=origin --push
  )
  if errorlevel 1 (echo [ERROR] Repository creation/push failed. Check GitHub permissions and repository settings. & exit /b 12)
) else (
  git remote get-url origin >nul 2>&1
  if errorlevel 1 git remote add origin https://github.com/%GH_USER%/mcp-inspector.git
  if errorlevel 1 (echo [ERROR] Could not configure origin. & exit /b 13)
  for /f "delims=" %%R in ('git remote get-url origin 2^>nul') do set ORIGIN_URL=%%R
  echo !ORIGIN_URL! | findstr /I /C:"%GH_USER%" >nul
  if errorlevel 1 (echo [ERROR] Origin does not appear to belong to %GH_USER%. Review it before pushing. & exit /b 13)
  echo !ORIGIN_URL! | findstr /I /C:"mcp-inspector" >nul
  if errorlevel 1 (echo [ERROR] Origin is not the mcp-inspector repository. Review it before pushing. & exit /b 13)
  git push -u origin main
  if errorlevel 1 (echo [ERROR] Push failed. Check origin, permissions, and branch protection. & exit /b 14)
)

echo.
echo [SUCCESS] Source, lockfile, tests, audit, and SBOM have been committed.
echo Repository: https://github.com/%GH_USER%/mcp-inspector
echo Note: GitHub Actions runs after the push; inspect its actual status before calling the project production-ready.
echo.
exit /b 0
