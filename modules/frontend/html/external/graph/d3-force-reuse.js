// Copyright 2018 Two Six Labs, LLC. v1.0.1 d3-force-reuse https://github.com/twosixlabs/d3-force-reuse/
(function (global, factory) {
	typeof exports === 'object' && typeof module !== 'undefined' ? factory(exports, require('d3-quadtree')) :
	typeof define === 'function' && define.amd ? define(['exports', 'd3-quadtree'], factory) :
	(factory((global.d3 = global.d3 || {}),global.d3));
}(this, (function (exports,d3Quadtree) { 'use strict';

var constant = function(x) {
  return function() {
    return x;
  };
};

var manyBodyReuse = function() {
  var nodes,
      node,
      alpha,
      iter = 0,
      tree,
      updateClosure,
      updateBH,
      strength = constant(-30),
      strengths,
      distanceMin2 = 1,
      distanceMax2 = Infinity,
      theta2 = 0.81;

  function jiggle() {
    return (Math.random() - 0.5) * 1e-6;
  }

  function x(d) {
    return d.x;
  }

  function y(d) {
    return d.y;
  }

  updateClosure = function () {
    return function (i) {
      if (i % 13 === 0) {
        return true;
      } else {
        return false;
      }
    };
  };

  function force(_) {
    var i, n = nodes.length;
    if (!tree || updateBH(iter, nodes)) {
      tree = d3Quadtree.quadtree(nodes, x, y).visitAfter(accumulate);
      nodes.update.push(iter);
    }
    for (alpha = _, i = 0; i < n; ++i) node = nodes[i], tree.visit(apply);
    ++iter;
  }

  function initialize() {
    if (!nodes) return;
    iter = 0;
    nodes.update = [];
    updateBH = updateClosure();
    tree = null;
    var i, n = nodes.length, node;
    strengths = new Array(n);
    for (i = 0; i < n; ++i) node = nodes[i], strengths[node.index] = +strength(node, i, nodes);
  }

  function accumulate(quad) {
    var strength = 0, q, c, weight = 0, x, y, i;

    // For internal nodes, accumulate forces from child quadrants.
    if (quad.length) {
      for (x = y = i = 0; i < 4; ++i) {
        if ((q = quad[i]) && (c = Math.abs(q.value))) {
          strength += q.value, weight += c, x += c * q.x, y += c * q.y;
        }
      }
      quad.x = x / weight;
      quad.y = y / weight;
    }

    // For leaf nodes, accumulate forces from coincident quadrants.
    else {
      q = quad;
      q.x = q.data.x;
      q.y = q.data.y;
      do strength += strengths[q.data.index];
      while (q = q.next);
    }

    quad.value = strength;
  }

  function apply(quad, x1, _, x2) {
    if (!quad.value) return true;

    var x = quad.x - node.x,
        y = quad.y - node.y,
        w = x2 - x1,
        l = x * x + y * y;

    // Apply the Barnes-Hut approximation if possible.
    // Limit forces for very close nodes; randomize direction if coincident.
    if (w * w / theta2 < l) {
      if (l < distanceMax2) {
        if (x === 0) x = jiggle(), l += x * x;
        if (y === 0) y = jiggle(), l += y * y;
        if (l < distanceMin2) l = Math.sqrt(distanceMin2 * l);
        node.vx += x * quad.value * alpha / l;
        node.vy += y * quad.value * alpha / l;
      }
      return true;
    }

    // Otherwise, process points directly.
    else if (quad.length || l >= distanceMax2) return;

    // Limit forces for very close nodes; randomize direction if coincident.
    if (quad.data !== node || quad.next) {
      if (x === 0) x = jiggle(), l += x * x;
      if (y === 0) y = jiggle(), l += y * y;
      if (l < distanceMin2) l = Math.sqrt(distanceMin2 * l);
    }

    do if (quad.data !== node) {
      // Use the coordinates of the node and not the quad region.
      x = quad.data.x - node.x;
      y = quad.data.y - node.y;
      l = x * x + y * y;

      // Limit forces for very close nodes; randomize direction if coincident.
      if (x === 0) x = jiggle(), l += x * x;
      if (y === 0) y = jiggle(), l += y * y;
      if (l < distanceMin2) l = Math.sqrt(distanceMin2 * l);

      w = strengths[quad.data.index] * alpha / l;

      node.vx += x * w;
      node.vy += y * w;
    } while (quad = quad.next);
  }

  force.initialize = function(_) {
    nodes = _;
    initialize();
  };

  force.strength = function(_) {
    return arguments.length ? (strength = typeof _ === "function" ? _ : constant(+_), initialize(), force) : strength;
  };

  force.distanceMin = function(_) {
    return arguments.length ? (distanceMin2 = _ * _, force) : Math.sqrt(distanceMin2);
  };

  force.distanceMax = function(_) {
    return arguments.length ? (distanceMax2 = _ * _, force) : Math.sqrt(distanceMax2);
  };

  force.theta = function(_) {
    return arguments.length ? (theta2 = _ * _, force) : Math.sqrt(theta2);
  };

  force.update = function(_) {
    return arguments.length ? (updateClosure = _, updateBH = updateClosure(), force) : updateClosure;
  };

  return force;
};

exports.forceManyBodyReuse = manyBodyReuse;

Object.defineProperty(exports, '__esModule', { value: true });

})));
