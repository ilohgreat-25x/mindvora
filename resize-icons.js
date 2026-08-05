/**
 * Mindvora Icon Generator
 * Run: node resize-icons.js
 * Requires: npm install jimp
 * Place your source icon as: icons/icon-source.png (1024x1024 or larger)
 */

const Jimp = require('jimp');
const path = require('path');
const fs   = require('fs');

const SIZES = [72, 96, 128, 144, 152, 192, 384, 512];
const SRC   = path.join(__dirname, 'icons', 'icon-source.png');
const OUT   = path.join(__dirname, 'icons');

async function generate() {
  if (!fs.existsSync(SRC)) {
    console.error('❌ Source icon not found: icons/icon-source.png');
    console.error('   Please save the Mindvora M-logo as icons/icon-source.png (1024x1024+)');
    process.exit(1);
  }

  console.log('🎨 Generating Mindvora icons from source...');
  const img = await Jimp.read(SRC);

  for (const size of SIZES) {
    const outFile = path.join(OUT, `icon-${size}.png`);
    await img.clone().resize(size, size).writeAsync(outFile);
    console.log(`  ✅ icon-${size}.png`);
  }

  // Maskable versions (192 and 512) — add 20% padding (safe zone)
  for (const size of [192, 512]) {
    const padded   = Math.round(size * 0.8);
    const offset   = Math.round(size * 0.1);
    const canvas   = new Jimp(size, size, 0x0a1a0fff); // dark green bg
    const resized  = await img.clone().resize(padded, padded);
    canvas.composite(resized, offset, offset);
    const outFile  = path.join(OUT, `icon-${size}-maskable.png`);
    await canvas.writeAsync(outFile);
    console.log(`  ✅ icon-${size}-maskable.png`);
  }

  // Remove old icon files with spaces/parentheses
  const oldFiles = fs.readdirSync(OUT).filter(f =>
    f.includes(' ') || f.includes('(') || f.includes(')')
  );
  for (const f of oldFiles) {
    fs.unlinkSync(path.join(OUT, f));
    console.log(`  🗑  Removed old: ${f}`);
  }

  console.log('\n✅ All icons generated successfully!');
  console.log('   Next: commit & push to GitHub.');
}

generate().catch(err => {
  console.error('Error:', err.message);
  process.exit(1);
});
