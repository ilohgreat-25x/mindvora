@echo off
setlocal

set REPO_DIR=c:\Users\GREAT\Downloads\mindvora-main\mindvora-main
cd /d "%REPO_DIR%"

echo === Mindvora GitHub Push ===

:: Configure git identity
git config user.email "ilohgreat25@gmail.com"
git config user.name "Mindvora"

:: Set up remote
git remote remove origin 2>nul
git remote add origin https://github.com/ilohgreat-25x/mindvora.git

:: Stage all files
git add -A

:: Commit
git commit -m "feat: CRLF defense, WebSocket+WebRTC, new icon, security hardening"

:: Push frontend
git branch -M main
git push -u origin main --force

echo.
echo === Frontend pushed successfully! ===

:: ----- BACKEND REPO -----
set BACK_DIR=c:\Users\GREAT\Downloads\mindvora-backend-tmp
if exist "%BACK_DIR%" rmdir /s /q "%BACK_DIR%"
mkdir "%BACK_DIR%"
mkdir "%BACK_DIR%\CRLF"

copy "%REPO_DIR%\server.js"          "%BACK_DIR%\server.js"
copy "%REPO_DIR%\package.json"       "%BACK_DIR%\package.json"
copy "%REPO_DIR%\CRLF\defense.evi"   "%BACK_DIR%\CRLF\defense.evi"
copy "%REPO_DIR%\CRLF\ws-server.evi" "%BACK_DIR%\CRLF\ws-server.evi"

echo node_modules/ > "%BACK_DIR%\.gitignore"
echo .env >> "%BACK_DIR%\.gitignore"

cd /d "%BACK_DIR%"

git init
git config user.email "ilohgreat25@gmail.com"
git config user.name "Mindvora"
git remote add origin https://github.com/ilohgreat-25x/mindvora-backend.git
git add -A
git commit -m "feat: secure backend v2 - CRLF defense, WebSocket, WebRTC signaling"
git branch -M main
git push -u origin main --force

echo.
echo === Backend pushed successfully! ===
echo.
echo All done! Both repos updated on GitHub.
pause
