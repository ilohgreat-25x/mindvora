const fs = require('fs');
const path = require('path');

// ── 1. Fix index.html ──────────────────────────────────────────────────────────
const htmlPath = path.join(__dirname, 'index.html');
let html = fs.readFileSync(htmlPath, 'utf8');

// Remove any raw base64 data that leaked outside of href/src attributes.
// These blobs start with "AAD" (PNG base64 header) and contain only
// base64 characters, appearing immediately after a closing ">" on the same line.
html = html.replace(/>(?:AAD|iVBOR)[A-Za-z0-9+/=\r\n]+/g, '>');

// Fix the apple-touch-icon that still has a data: URI as its href
html = html.replace(
  /(<link\s+rel="apple-touch-icon"[^>]*href=")data:[^"]*"/,
  '$1/icons/icon-192.png"'
);

fs.writeFileSync(htmlPath, html, 'utf8');
console.log('✅ index.html fixed');

// ── 2. Rename icon files ───────────────────────────────────────────────────────
const iconsDir = path.join(__dirname, 'icons');
const files = fs.readdirSync(iconsDir);

const renames = [
  ['icon-72 (1).png',          'icon-72.png'],
  ['icon-96 (1).png',          'icon-96.png'],
  ['icon-128 (1).png',         'icon-128.png'],
  ['icon-144 (1).png',         'icon-144.png'],
  ['icon-152 (1).png',         'icon-152.png'],
  ['icon-192 (1).png',         'icon-192.png'],
  ['icon-192 (2).png',         'icon-192.png'],
  ['icon-384 (1).png',         'icon-384.png'],
  ['icon-512 (1).png',         'icon-512.png'],
];

for (const [from, to] of renames) {
  const src = path.join(iconsDir, from);
  const dst = path.join(iconsDir, to);
  if (fs.existsSync(src) && !fs.existsSync(dst)) {
    fs.renameSync(src, dst);
    console.log(`✅ Renamed: ${from} → ${to}`);
  } else if (fs.existsSync(src) && fs.existsSync(dst)) {
    // destination already exists – just remove the duplicate
    fs.unlinkSync(src);
    console.log(`🗑  Removed duplicate: ${from} (${to} already exists)`);
  } else if (!fs.existsSync(src)) {
    console.log(`⚠️  Not found (skipped): ${from}`);
  }
}

// List what's in icons/ now
console.log('\nIcons directory now contains:');
fs.readdirSync(iconsDir).forEach(f => console.log(' ', f));
