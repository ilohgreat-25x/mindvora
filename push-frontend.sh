#!/usr/bin/env bash
# Mindvora — auto push to both GitHub repos

set -e
FRONTEND_DIR="c:/Users/GREAT/Downloads/mindvora-main/mindvora-main"
cd "$FRONTEND_DIR"

# Configure git identity
git config user.email "ilohgreat25@gmail.com"
git config user.name "Mindvora"

# ── FRONTEND REPO ──────────────────────────────────────────────────────
git init
git remote remove origin 2>/dev/null || true
git remote add origin "https://github.com/ilohgreat-25x/mindvora.git"

# Files to exclude from frontend push (backend-only)
echo "node_modules/" > .gitignore
echo ".env" >> .gitignore
echo "*.log" >> .gitignore

git add -A
git commit -m "feat: new icon, CRLF defense system, WebSocket+WebRTC live streaming

- Updated app icon (new M-logo) across all PWA sizes
- Added CRLF/defense.evi — CRLF injection defense with auto-IP-ban after 5 strikes
- Added CRLF/ws-server.evi — WebSocket room manager for live streaming
- Rewrote server.js with full security hardening (rate limiting, header sanitization)
- Added WebRTC live streaming to script.js with follower notifications
- Hardened vercel.json with CSP, HSTS, X-Frame-Options headers
- Updated manifest.json with clean icon paths"

git branch -M main
git push -u origin main --force

echo "✅ Frontend pushed to ilohgreat-25x/mindvora"
