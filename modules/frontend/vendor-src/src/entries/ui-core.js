import Alpine from 'alpinejs';
import persist from '@alpinejs/persist';
import tooltip from '@ryangjchandler/alpine-tooltip';
import * as bootstrap from 'bootstrap/dist/js/bootstrap.bundle.min.js';

// Expose Bootstrap JS API immediately so legacy scripts using `bootstrap.*`
// during DOMContentLoaded can run before Alpine startup.
window.bootstrap = bootstrap;

export function initUICore() {
  if (window.__adalancheAlpineStarted) {
    return;
  }
  Alpine.plugin(persist);
  Alpine.plugin(tooltip);
  window.Alpine = Alpine;
  window.__adalancheAlpineStarted = true;
  Alpine.start();
}
