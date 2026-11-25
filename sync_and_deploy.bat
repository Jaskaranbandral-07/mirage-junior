@echo off
setlocal enabledelayedexpansion

echo ============================================================
echo   MIRAGE Junior + Shield - GitHub & Vercel Auto-Deploy
echo ============================================================
echo.

set "SRC_DIR=%~dp0"
if "%SRC_DIR:~-1%"=="\" set "SRC_DIR=%SRC_DIR:~0,-1%"
set "SYNC_DIR=%TEMP%\mirage-junior-sync"

if exist "%SYNC_DIR%" (
    echo Cleaning previous temp sync folder...
    rmdir /s /q "%SYNC_DIR%"
)

echo [1/4] Cloning existing GitHub repo (preserving contributor history)...
git clone https://github.com/Jaskaranbandral-07/mirage-junior.git "%SYNC_DIR%"
if errorlevel 1 (
    echo ERROR: Failed to clone repository. Check internet / git login.
    pause
    exit /b 1
)

echo [2/4] Syncing latest MIRAGE Shield & Chrome Extension files...
robocopy "%SRC_DIR%" "%SYNC_DIR%" /E /XD .git __pycache__ .pytest_cache cloned_sites /XF mirage_junior.db
if %ERRORLEVEL% GEQ 8 (
    echo ERROR: File sync failed with code %ERRORLEVEL%.
    pause
    exit /b 1
)

cd /d "%SYNC_DIR%"
git config user.name "Jaskaran Bandral"
git config user.email "144834411+Jaskaranbandral-07@users.noreply.github.com"

echo [3/4] Committing changes...
git add -A
git diff --cached --quiet
if errorlevel 1 (
    git commit -m "feat: add MIRAGE Shield reverse proxy, website cloner, and Chrome extension"
) else (
    echo Nothing new to commit - already up to date.
)

echo [4/4] Pushing to GitHub (Vercel will auto-deploy in ~60 seconds)...
git push origin main
if errorlevel 1 (
    echo ERROR: git push failed. Make sure gh / git is authenticated.
    pause
    exit /b 1
)

cd /d "%SRC_DIR%"
rmdir /s /q "%SYNC_DIR%"

echo.
echo ============================================================
echo   SUCCESS! GitHub updated and Vercel deploy triggered!
echo   Check live site: https://mirage-junior.vercel.app/shield
echo ============================================================
pause
