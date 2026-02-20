import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');
const manifestPath = path.join(root, 'dist-manifest.json');

if (!fs.existsSync(manifestPath)) {
  console.error('Missing dist-manifest.json. Run: npm run build');
  process.exit(1);
}

const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
for (const [name, rel] of Object.entries(manifest)) {
  const abs = path.resolve(root, '../html', rel.replace(/^external\//, 'external/'));
  if (!fs.existsSync(abs)) {
    console.error(`Missing bundle for ${name}: ${abs}`);
    process.exit(1);
  }
}

console.log('Vendor bundles look good.');
