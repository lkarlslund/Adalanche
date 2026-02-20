import cytoscape from 'cytoscape';
import popper from 'cytoscape-popper';
import contextMenus from 'cytoscape-context-menus';
import expandCollapse from 'cytoscape-expand-collapse';
import fcose from 'cytoscape-fcose';
import coseBilkent from 'cytoscape-cose-bilkent';
import d3Force from 'cytoscape-d3-force';
import dagre from 'cytoscape-dagre';
import { createPopper } from '@popperjs/core';

export function initGraphCore() {
  if (window.__adalancheGraphCoreInitialized) {
    return;
  }
  cytoscape.use(popper(createPopper));
  cytoscape.use(contextMenus);
  cytoscape.use(expandCollapse);
  cytoscape.use(fcose);
  cytoscape.use(coseBilkent);
  cytoscape.use(d3Force);
  cytoscape.use(dagre);
  window.cytoscape = cytoscape;
  window.__adalancheGraphCoreInitialized = true;
}
