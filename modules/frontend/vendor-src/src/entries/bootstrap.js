import { initGraphCore } from './graph-core.js';
import { initUICore } from './ui-core.js';

async function boot() {
  try {
    initGraphCore();
  } catch (err) {
    console.error('Failed to initialize graph vendor bundle', err);
  }
  try {
    if (typeof window.ensurePrefsLoaded === 'function') {
      await window.ensurePrefsLoaded();
    }
  } catch (err) {
    console.error('Failed to preload preferences before Alpine startup', err);
  }
  initUICore();
}

boot();
