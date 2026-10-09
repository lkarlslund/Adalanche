import { build, context } from 'esbuild';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');
const outdir = path.resolve(root, '../html/external/vendor');
const watch = process.argv.includes('--watch');
const cleanOnly = process.argv.includes('--clean');

const entries = {
  'ui-core': path.resolve(root, 'src/entries/ui-core.js'),
  'graph-core': path.resolve(root, 'src/entries/graph-core.js'),
  'bootstrap': path.resolve(root, 'src/entries/bootstrap.js'),
  // Loaded as a classic script: the graph scripts read window.Sigma.
  'sigma': path.resolve(root, 'src/entries/sigma.js')
};
const classicScripts = new Set(['sigma']);

if (cleanOnly) {
  fs.rmSync(outdir, { recursive: true, force: true });
  console.log('Cleaned', outdir);
  process.exit(0);
}

fs.mkdirSync(outdir, { recursive: true });

const bootstrapOutDir = path.join(outdir, 'bootstrap');
const bootstrapIconsOutDir = path.join(outdir, 'bootstrap-icons');
fs.mkdirSync(bootstrapOutDir, { recursive: true });
fs.mkdirSync(path.join(bootstrapIconsOutDir, 'fonts'), { recursive: true });

const shared = {
  bundle: true,
  format: 'esm',
  platform: 'browser',
  target: ['es2020'],
  sourcemap: true,
  minify: false,
  legalComments: 'none',
};

const manifest = {};

for (const [name, entry] of Object.entries(entries)) {
  const outfile = path.join(outdir, `${name}.bundle.js`);
  const options = { ...shared, entryPoints: [entry], outfile, ...(classicScripts.has(name) ? { format: 'iife', minify: true } : {}) };
  if (watch) {
    const ctx = await context(options);
    await ctx.watch();
    console.log(`Watching ${name} -> ${outfile}`);
  } else {
    await build(options);
    console.log(`Built ${name} -> ${outfile}`);
  }
  manifest[name] = `external/vendor/${name}.bundle.js`;
}

// Copy vendor CSS/font assets that are consumed directly by templates.
const bootstrapCssSrc = path.resolve(root, 'node_modules/bootstrap/dist/css/bootstrap.min.css');
const bootstrapCssDst = path.join(bootstrapOutDir, 'bootstrap.min.css');
fs.copyFileSync(bootstrapCssSrc, bootstrapCssDst);

const bootstrapIconsCssSrc = path.resolve(root, 'node_modules/bootstrap-icons/font/bootstrap-icons.css');
const bootstrapIconsCssDst = path.join(bootstrapIconsOutDir, 'bootstrap-icons.css');
fs.copyFileSync(bootstrapIconsCssSrc, bootstrapIconsCssDst);

const bootstrapIconsFontsSrc = path.resolve(root, 'node_modules/bootstrap-icons/font/fonts');
const bootstrapIconsFontsDst = path.join(bootstrapIconsOutDir, 'fonts');
fs.cpSync(bootstrapIconsFontsSrc, bootstrapIconsFontsDst, { recursive: true });

const tippyCssSrc = path.resolve(root, 'node_modules/tippy.js/dist/tippy.css');
const tippyCssDst = path.join(outdir, 'tippy.css');
fs.copyFileSync(tippyCssSrc, tippyCssDst);

fs.writeFileSync(path.join(root, 'dist-manifest.json'), JSON.stringify(manifest, null, 2) + '\n');

if (!watch) {
  console.log('Wrote manifest:', path.join(root, 'dist-manifest.json'));
}
