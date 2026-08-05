# Mindvora — Full GitHub Push Script
# Run this file in PowerShell: .\deploy.ps1

$FrontendDir = "c:\Users\GREAT\Downloads\mindvora-main\mindvora-main"
Set-Location $FrontendDir

Write-Host "=== Mindvora Auto-Deploy ===" -ForegroundColor Green

# Configure git identity
git config user.email "ilohgreat25@gmail.com"
git config user.name "Mindvora"

# ── FRONTEND PUSH ─────────────────────────────────────────────────────
Write-Host "`n[1/4] Setting up frontend git..." -ForegroundColor Cyan

# Remove old remote if exists
git remote remove origin 2>$null

# Add new remote
git remote add origin "https://github.com/ilohgreat-25x/mindvora.git"

Write-Host "[2/4] Staging all changes..." -ForegroundColor Cyan
git add -A

Write-Host "[3/4] Committing..." -ForegroundColor Cyan
git commit -m "feat: CRLF defense, WebSocket+WebRTC live streaming, new icon`n`n- New M-logo icon across all PWA sizes`n- CRLF/defense.evi: injection defense, auto-ban after 5 strikes, rate limiting`n- CRLF/ws-server.evi: WebSocket room manager for live streaming`n- server.js: full security hardening (no X-Powered-By, no stack traces)`n- script.js: WebRTC live streaming engine with follower notifications`n- vercel.json: CSP, HSTS, X-Frame-Options headers`n- manifest.json: clean icon paths"

Write-Host "[4/4] Pushing to GitHub (frontend)..." -ForegroundColor Cyan
git branch -M main
git push -u origin main --force

Write-Host "`n=== Frontend pushed to ilohgreat-25x/mindvora ===" -ForegroundColor Green

# ── BACKEND PUSH ──────────────────────────────────────────────────────
# The backend files (server.js, package.json, CRLF/) need to go to ilohgreat-25x/mindvora-backend
# Create a temp directory to hold just the backend files

Write-Host "`nSetting up backend push..." -ForegroundColor Cyan

$BackendTemp = "c:\Users\GREAT\Downloads\mindvora-backend-deploy"
if (Test-Path $BackendTemp) { Remove-Item $BackendTemp -Recurse -Force }
New-Item -ItemType Directory -Path $BackendTemp | Out-Null

# Copy backend files
Copy-Item "$FrontendDir\server.js"    $BackendTemp
Copy-Item "$FrontendDir\package.json" $BackendTemp
Copy-Item "$FrontendDir\CRLF"         "$BackendTemp\CRLF" -Recurse

# Create backend .gitignore
@"
node_modules/
.env
*.log
"@ | Out-File "$BackendTemp\.gitignore" -Encoding UTF8

Set-Location $BackendTemp

git init
git config user.email "ilohgreat25@gmail.com"
git config user.name "Mindvora"
git remote add origin "https://github.com/ilohgreat-25x/mindvora-backend.git"
git add -A
git commit -m "feat: secure backend v2.0 — CRLF defense + WebSocket server`n`n- CRLF/defense.evi: injection guard, auto-ban, rate limit, security headers`n- CRLF/ws-server.evi: live stream room manager with WebRTC signaling`n- server.js: hardened Express + WebSocket server`n- package.json: ws@8 dependency added"
git branch -M main
git push -u origin main --force

Write-Host "`n=== Backend pushed to ilohgreat-25x/mindvora-backend ===" -ForegroundColor Green
Write-Host "`n✅ All done! Both repos updated." -ForegroundColor Green

Set-Location $FrontendDir
