@echo off
setlocal enabledelayedexpansion

echo ============================================================
echo   MIRAGE Junior + Shield - Clean Reset & Deploy
echo ============================================================
echo.

set "SRC_DIR=%~dp0"
if "%SRC_DIR:~-1%"=="\" set "SRC_DIR=%SRC_DIR:~0,-1%"
set "SYNC_DIR=%TEMP%\mirage-junior-sync"

echo [1/5] Purging any old fake/demo SQLite database locally...
if exist "%SRC_DIR%\database\mirage_junior.db" del /f /q "%SRC_DIR%\database\mirage_junior.db"
if exist "%SRC_DIR%\database\geo_cache.json" del /f /q "%SRC_DIR%\database\geo_cache.json"
python -c "import sys; sys.path.insert(0, r'%SRC_DIR%'); from database.db_setup import init_db; init_db()" 2>nul

if exist "%SYNC_DIR%" (
    rmdir /s /q "%SYNC_DIR%"
)

echo [2/5] Cloning existing GitHub repo (preserving contributor history)...
git clone https://github.com/Jaskaranbandral-07/mirage-junior.git "%SYNC_DIR%"
if errorlevel 1 (
    echo ERROR: Failed to clone repository. Check internet / git login.
    pause
    exit /b 1
)

echo [3/5] Syncing live-capture codebase (excluding stale DBs & caches)...
robocopy "%SRC_DIR%" "%SYNC_DIR%" /E /XD .git __pycache__ .pytest_cache cloned_sites /XF mirage_junior.db geo_cache.json
if %ERRORLEVEL% GEQ 8 (
    echo ERROR: File sync failed with code %ERRORLEVEL%.
    pause
    exit /b 1
)

cd /d "%SYNC_DIR%"
git config user.name "Jaskaran Bandral"
git config user.email "144834411+Jaskaranbandral-07@users.noreply.github.com"

echo [4/5] Removing any old tracked fake DB / pycache from GitHub & committing...
git rm -f --cached --ignore-unmatch database/mirage_junior.db database/geo_cache.json >nul 2>&1
for /f "delims=" %%F in ('git ls-files "*__pycache__*"') do git rm -f --cached --ignore-unmatch "%%F" >nul 2>&1
if exist "%SYNC_DIR%\database\mirage_junior.db" del /f /q "%SYNC_DIR%\database\mirage_junior.db"
set "COMMIT_MSG=%~1"
if "%COMMIT_MSG%"=="" set "COMMIT_MSG=chore: sync MIRAGE Junior updates"

git add -A
git diff --cached --quiet
if errorlevel 1 (
    git commit -m "%COMMIT_MSG%"
) else (
    echo Nothing new to commit - already up to date.
)

echo [5/5] Pushing to GitHub (Vercel will auto-deploy clean live capture)...
git push origin main
if errorlevel 1 (
    echo ERROR: git push failed.
    pause
    exit /b 1
)

cd /d "%SRC_DIR%"
rmdir /s /q "%SYNC_DIR%"

echo.
echo ============================================================
echo   SUCCESS! Old fake data wiped and live capture pushed!
echo   Check live site: https://mirage-junior.vercel.app
echo ============================================================
pause
