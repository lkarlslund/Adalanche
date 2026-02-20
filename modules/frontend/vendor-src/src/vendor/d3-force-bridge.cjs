const d3force = require('d3-force');
const sampled = require('d3-force-sampled');

const forceManyBodySampled = sampled.forceManyBodySampled ||
  (sampled.default && sampled.default.forceManyBodySampled);

function forceManyBodyCompat() {
  const force = forceManyBodySampled ? forceManyBodySampled() : d3force.forceManyBody();

  // cytoscape-d3-force expects the standard d3-force API, including theta().
  // d3-force-sampled does not expose theta(), so provide a compatible shim.
  if (typeof force.theta !== 'function') {
    let theta = 0.9;
    force.theta = function(value) {
      if (!arguments.length) {
        return theta;
      }
      theta = +value;
      return force;
    };
  }

  return force;
}

module.exports = {
  ...d3force,
  forceManyBody: forceManyBodyCompat,
};
