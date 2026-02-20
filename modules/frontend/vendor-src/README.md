# Frontend Vendor Workspace

This folder is the source-of-truth for third-party frontend dependencies.

## Goals

- Keep raw npm source and build tooling out of browser-served `html/` paths.
- Produce coarse domain bundles:
- `ui-core` for UI/runtime framework dependencies.
- `graph-core` for graph engine dependencies.
- Make upgrades explicit and reproducible via lockfile changes.

## Layout

- `src/entries/ui-core.js` entry for UI dependencies.
- `src/entries/graph-core.js` entry for graph dependencies.
- `scripts/build.mjs` builds bundles into `../html/external/vendor/`.
- `dist-manifest.json` maps logical bundle names to output files.

## Commands

Run from this directory:

- `npm ci`
- `npm run build`
- `npm run build:watch`
- `npm run check`

## Upgrade workflow

1. Update dependency versions in `package.json`.
2. Run `npm install` (or `npm update <pkg>`).
3. Run `npm run build`.
4. Verify UI/graph smoke tests.
5. Commit `package.json`, lockfile, `dist-manifest.json`, and generated bundles.

## Integration status

This workspace is active.

- `html/index.html` loads `external/vendor/bootstrap.bundle.js` as a module.
- `bootstrap` initializes graph dependencies first, waits for `ensurePrefsLoaded()`, then starts Alpine UI.
- Legacy direct script includes for Alpine/Cytoscape core/layout/d3-force sampled chain have been removed.

## d3-force sampled bridge

The graph bundle uses `cytoscape-d3-force` together with `d3-force-sampled`.

- Bridge file: `src/vendor/d3-force-bridge.cjs`
- Build wiring: `scripts/build.mjs` plugin `alias-d3-force-exact`

Behavior:

- Only imports that are exactly `d3-force` are redirected to the bridge.
- The bridge exports normal `d3-force` API, but overrides `forceManyBody` with sampled implementation (`forceManyBodySampled`) when available.

Why:

- Keeps graph runtime behavior close to prior sampled setup.
- Avoids broad aliasing that can accidentally rewrite imports like `d3-force-sampled` itself.
