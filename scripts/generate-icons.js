/**
 * Simple SVG Icon Generator (No Dependencies Required!)
 * Creates SVG icons that Chrome can use directly
 * 
 * This script creates simple red/white alert icons.
 * For production, replace these with professionally designed icons.
 * 
 * Usage: node scripts/generate-icons.js
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('🎨 Icon Generator for AI Risk Intelligence Extension\n');
console.log('✅ No external dependencies required!\n');

const iconsDir = path.join(__dirname, '..', 'src', 'icons');

// Create icons directory if it doesn't exist
if (!fs.existsSync(iconsDir)) {
  fs.mkdirSync(iconsDir, { recursive: true });
}

console.log('📁 Icons directory:', iconsDir);

// Icon sizes
const sizes = [16, 48, 128];

// Generate SVG icon template
function createSVG(size) {
  const strokeWidth = Math.max(1, size / 8);
  const fontSize = size * 0.7;
  const circleRadius = size * 0.35;
  
  return `<?xml version="1.0" encoding="UTF-8"?>
<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" xmlns="http://www.w3.org/2000/svg">
  <!-- Background -->
  <rect width="${size}" height="${size}" fill="#ef4444" rx="${size * 0.1}"/>
  
  <!-- White circle -->
  <circle cx="${size / 2}" cy="${size / 2}" r="${circleRadius}" fill="#ffffff"/>
  
  <!-- Red exclamation mark -->
  <g transform="translate(${size / 2}, ${size / 2})">
    <rect x="${-strokeWidth / 2}" y="${-size * 0.2}" width="${strokeWidth}" height="${size * 0.25}" fill="#ef4444" rx="${strokeWidth / 2}"/>
    <circle cx="0" cy="${size * 0.15}" r="${strokeWidth * 0.8}" fill="#ef4444"/>
  </g>
</svg>`;
}

// Save SVG files
sizes.forEach(size => {
  const filename = `icon${size}.svg`;
  const filepath = path.join(iconsDir, filename);
  const svgContent = createSVG(size);
  
  fs.writeFileSync(filepath, svgContent, 'utf8');
  console.log(`✅ Created ${filename} (${size}x${size})`);
});

console.log('\n✨ SVG icon generation complete!');
console.log('\n📝 Chrome supports SVG icons directly (Manifest V3)');
console.log('   These will work perfectly in your extension.\n');
console.log('💡 Alternative: Use free PNG icons from:');
console.log('   - https://www.flaticon.com/free-icons/security');
console.log('   - https://icons8.com/icons/set/shield');
console.log('   - https://www.iconfinder.com/\n');
console.log('Next steps:');
console.log('  1. Update manifest.json to use .svg icons (or keep as-is)');
console.log('  2. npm run build');
console.log('  3. Load dist/ folder in Chrome\n');
