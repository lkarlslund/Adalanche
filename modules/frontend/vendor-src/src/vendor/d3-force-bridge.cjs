const d3force = require('d3-force');
const sampled = require('d3-force-sampled');

const forceManyBodySampled = sampled.forceManyBodySampled ||
  (sampled.default && sampled.default.forceManyBodySampled);

module.exports = {
  ...d3force,
  forceManyBody: forceManyBodySampled || d3force.forceManyBody,
};
