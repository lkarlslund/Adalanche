// Sigma for the page's classic scripts: the renderer as window.Sigma, with
// its rendering helpers on Sigma.rendering and the node layers from the
// companion packages, as sigma's own browser bundle lays them out. Bundled
// here so the companion packages share one copy of sigma.
import Sigma, * as sigmaExports from 'sigma';
import * as rendering from 'sigma/rendering';
import * as utils from 'sigma/utils';
import { layerImage } from '@sigma/node-image';
import { layerBorder } from '@sigma/node-border';

// Named exports, such as DEFAULT_STYLES and Camera, become statics.
for (const [name, value] of Object.entries(sigmaExports)) {
  if (name !== 'default' && !(name in Sigma)) Sigma[name] = value;
}
Sigma.rendering = rendering;
Sigma.utils = utils;
Sigma.layers = { layerImage, layerBorder };
window.Sigma = Sigma;
