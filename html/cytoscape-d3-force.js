(function webpackUniversalModuleDefinition(root, factory) {
	if(typeof exports === 'object' && typeof module === 'object')
		module.exports = factory(require("d3-force"));
	else if(typeof define === 'function' && define.amd)
		define(["d3-force"], factory);
	else if(typeof exports === 'object')
		exports["cytoscapeD3Force"] = factory(require("d3-force"));
	else
		root["cytoscapeD3Force"] = factory(root["d3-force"]);
})(this, function(__WEBPACK_EXTERNAL_MODULE_4__) {
return /******/ (function(modules) { // webpackBootstrap
/******/ 	// The module cache
/******/ 	var installedModules = {};
/******/
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/
/******/ 		// Check if module is in cache
/******/ 		if(installedModules[moduleId]) {
/******/ 			return installedModules[moduleId].exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = installedModules[moduleId] = {
/******/ 			i: moduleId,
/******/ 			l: false,
/******/ 			exports: {}
/******/ 		};
/******/
/******/ 		// Execute the module function
/******/ 		modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/
/******/ 		// Flag the module as loaded
/******/ 		module.l = true;
/******/
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/
/******/
/******/ 	// expose the modules object (__webpack_modules__)
/******/ 	__webpack_require__.m = modules;
/******/
/******/ 	// expose the module cache
/******/ 	__webpack_require__.c = installedModules;
/******/
/******/ 	// identity function for calling harmony imports with the correct context
/******/ 	__webpack_require__.i = function(value) { return value; };
/******/
/******/ 	// define getter function for harmony exports
/******/ 	__webpack_require__.d = function(exports, name, getter) {
/******/ 		if(!__webpack_require__.o(exports, name)) {
/******/ 			Object.defineProperty(exports, name, {
/******/ 				configurable: false,
/******/ 				enumerable: true,
/******/ 				get: getter
/******/ 			});
/******/ 		}
/******/ 	};
/******/
/******/ 	// getDefaultExport function for compatibility with non-harmony modules
/******/ 	__webpack_require__.n = function(module) {
/******/ 		var getter = module && module.__esModule ?
/******/ 			function getDefault() { return module['default']; } :
/******/ 			function getModuleExports() { return module; };
/******/ 		__webpack_require__.d(getter, 'a', getter);
/******/ 		return getter;
/******/ 	};
/******/
/******/ 	// Object.prototype.hasOwnProperty.call
/******/ 	__webpack_require__.o = function(object, property) { return Object.prototype.hasOwnProperty.call(object, property); };
/******/
/******/ 	// __webpack_public_path__
/******/ 	__webpack_require__.p = "";
/******/
/******/ 	// Load entry module and return exports
/******/ 	return __webpack_require__(__webpack_require__.s = 3);
/******/ })
/************************************************************************/
/******/ ([
/* 0 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

/**
* cytoscape-d3-force
*/

var defaults = __webpack_require__(2);
var d3 = __webpack_require__(4);
var assign = __webpack_require__(1);

var ContinuousLayout = function () {
  function ContinuousLayout(options) {
    _classCallCheck(this, ContinuousLayout);

    var o = this.options = assign({}, defaults, options);
    this.state = assign({}, o, {
      layout: this,
      nodes: o.eles.nodes(),
      edges: o.eles.edges(),
      progress: 0,
      iterations: 0,
      startTime: 0
    });
    this.simulation = null;
    this.removeCytoscapeEvents = null;
    this.destroyedEvent = null;
  }

  _createClass(ContinuousLayout, [{
    key: 'makeBoundingBox',
    value: function makeBoundingBox(bb, cy) {
      if (bb == null) {
        bb = { x1: 0, y1: 0, w: cy.width(), h: cy.height() };
      } else {
        bb = { x1: bb.x1, x2: bb.x2, y1: bb.y1, y2: bb.y2, w: bb.w, h: bb.h };
      }
      if (bb.x2 == null) {
        bb.x2 = bb.x1 + bb.w;
      }
      if (bb.w == null) {
        bb.w = bb.x2 - bb.x1;
      }
      if (bb.y2 == null) {
        bb.y2 = bb.y1 + bb.h;
      }
      if (bb.h == null) {
        bb.h = bb.y2 - bb.y1;
      }

      return bb;
    }
  }, {
    key: 'setInitialPositionState',
    value: function setInitialPositionState(node, state) {
      var p = node.position();
      var bb = state.currentBoundingBox;
      var scratch = node.scratch(state.name);

      if (scratch == null) {
        scratch = {};

        node.scratch(state.name, scratch);
      }

      assign(scratch, state.randomize ? {
        x: bb.x1 + Math.round(Math.random() * bb.w),
        y: bb.y1 + Math.round(Math.random() * bb.h)
      } : {
        x: p.x,
        y: p.y
      });
      if (node.locked()) {
        assign(scratch, {
          fx: p.x,
          fy: p.y
        });
      }
    }
  }, {
    key: 'refreshPositions',
    value: function refreshPositions(nodes, state, fit) {
      nodes.positions(function (node) {
        var scratch = node.scratch(state.name);
        return {
          x: scratch.x,
          y: scratch.y
        };
      });
      fit && state.cy.fit(state.padding);
    }
  }, {
    key: 'getScratch',
    value: function getScratch(el) {
      var name = this.state.name;
      var scratch = el.scratch(name);

      if (!scratch) {
        scratch = {};

        el.scratch(name, scratch);
      }
      return scratch;
    }
  }, {
    key: 'ungrabify',
    value: function ungrabify(nodes) {
      var _this = this;

      if (!this.state.ungrabifyWhileSimulating) {
        return;
      }
      nodes.filter(function (node) {
        var nodeGrabbable = _this.getScratch(node).grabbable = node.grabbable();
        return nodeGrabbable;
      });
      nodes.ungrabify();
    }
  }, {
    key: 'regrabify',
    value: function regrabify(nodes) {
      var _this2 = this;

      if (!this.state.ungrabifyWhileSimulating) {
        return;
      }
      nodes.filter(function (node) {
        var nodeGrabbable = _this2.getScratch(node).grabbable;
        return nodeGrabbable;
      });
      nodes.grabify();
    }
  }, {
    key: 'tick',
    value: function tick() {
      var s = this.state;
      s.progress += 1 / Math.ceil(Math.log(this.simulation.alphaMin()) / Math.log(1 - this.simulation.alphaDecay()));
      s.iterations++;
      var _iterations = s.maxIterations && !s.infinite ? s.iterations / s.maxIterations : 0;
      var _timeRunning = Date.now() - s.startTime;
      var _timeIterations = s.maxSimulationTime && !s.infinite ? _timeRunning / s.maxSimulationTime : 0;
      var _progress = Math.max(_iterations, _timeIterations, s.progress);
      _progress = _progress > 1 ? 1 : _progress;
      if (_progress >= 1) {
        this.end(!s.infinite);
        return;
      }
      s.tick && s.tick(_progress);
      if (s.animate) {
        this.refreshPositions(s.nodes, s, s.fit);
      }
    }
  }, {
    key: 'end',
    value: function end(destroyed) {
      var s = this.state;
      this.refreshPositions(s.nodes, s, s.fit);
      this.emit('layoutstop', s.cy);
      this.reset(destroyed);
    }
  }, {
    key: 'reset',
    value: function reset(destroyed) {
      this.simulation && this.simulation.stop();
      var s = this.state;
      this.destroyedEvent && this.destroyedEvent();
      (destroyed || !s.infinite) && this.removeCytoscapeEvents && this.removeCytoscapeEvents();
      s.animate && this.regrabify(s.nodes);
      return this;
    }
  }, {
    key: 'run',
    value: function run() {
      var _this3 = this;

      this.reset();
      var l = this;
      var s = this.state;
      var ready = false;
      s.currentBoundingBox = this.makeBoundingBox(s.boundingBox, s.cy);
      if (s.ready) {
        l.one('layoutready', s.ready);
      }
      if (s.stop) {
        l.one('layoutstop', s.stop);
      }
      s.nodes.forEach(function (n) {
        return _this3.setInitialPositionState(n, s);
      });
      if (!ready) {
        ready = true;
        l.emit('layoutready');
      }

      if (!l.simulation) {
        var _forcenodes = s.nodes.map(function (n) {
          return assign(l.getScratch(n), n.data());
        });
        var _forceedges = s.edges.map(function (e) {
          return assign({}, e.data());
        });
        l.simulation = d3.forceSimulation(_forcenodes);
        s.alpha && l.simulation.alpha(s.alpha);
        s.alphaMin && l.simulation.alphaMin(s.alphaMin);
        s.alphaDecay && l.simulation.alphaDecay(s.alphaDecay);
        s.alphaTarget && l.simulation.alphaTarget(s.alphaTarget);
        s.velocityDecay && l.simulation.velocityDecay(s.velocityDecay);
        var _collide = d3.forceCollide();
        s.collideRadius && _collide.radius(s.collideRadius);
        s.collideStrength && _collide.strength(s.collideStrength);
        s.collideIterations && _collide.iterations(s.collideIterations);
        var _link = d3.forceLink(_forceedges);
        s.linkId && _link.id(s.linkId);
        s.linkDistance && _link.distance(s.linkDistance);
        s.linkStrength && _link.strength(s.linkStrength);
        s.linkIterations && _link.iterations(s.linkIterations);
        var _manyBody = d3.forceManyBody();
        s.manyBodyStrength && _manyBody.strength(s.manyBodyStrength);
        s.manyBodyTheta && _manyBody.theta(s.manyBodyTheta);
        s.manyBodyDistanceMin && _manyBody.distanceMin(s.manyBodyDistanceMin);
        s.manyBodyDistanceMax && _manyBody.distanceMax(s.manyBodyDistanceMax);
        var _x = d3.forceX();
        s.xX && _x.x(s.xX);
        s.xStrength && _x.strength(s.xStrength);
        var _y = d3.forceY();
        s.yY && _y.y(s.yY);
        s.yStrength && _y.strength(s.yStrength);
        var _radius = null;
        if (s.radialRadius || s.radialStrength || s.radialX || s.radialY) {
          _radius = d3.forceRadial();
          s.radialRadius && _radius.radius(s.radialRadius);
          s.radialStrength && _radius.strength(s.radialStrength);
          s.radialX && _radius.x(s.radialX);
          s.radialY && _radius.y(s.radialY);
        }
        var _center = d3.forceCenter(s.currentBoundingBox.w / 2, s.currentBoundingBox.h / 2);
        l.simulation.force('collide', _collide).force('link', _link).force('many-body', _manyBody).force('x', _x).force('y', _y).force("center", _center);
        _radius && l.simulation.force('radius', _radius);
        l.simulation.on("tick", function () {
          l.tick();
        }).on("end", function () {
          l.end();
        });
      }
      if (!l.destroyedEvent) {
        var destroyHandler = void 0;
        s.cy.one('destroy', destroyHandler = function destroyHandler() {
          l.stop();
        });
        l.destroyedEvent = function () {
          s.cy.off('destroy', destroyHandler);
          l.destroyedEvent = null;
        };
      }
      l.prerun(s);
      l.emit('layoutstart');
      s.progress = 0;
      s.iterations = 0;
      s.startTime = Date.now();

      if (s.animate) {
        var restartAlphaTarget = Math.abs((s.alpha || 1) - (s.alphaTarget || 0)) / 3;
        if (!l.removeCytoscapeEvents) {
          var _cytoscapeEvent = function _cytoscapeEvent(e) {
            var node = this;
            var pos = node.position();
            var nodeIsTarget = e.cyTarget === node || e.target === node;
            if (!nodeIsTarget) {
              return;
            }
            var _scratch = l.getScratch(node);
            s.progress = 0;
            s.iterations = 0;
            s.startTime = Date.now();
            _scratch.x = pos.x;
            _scratch.y = pos.y;
            if (e.type === 'grab') {
              l.simulation.alphaTarget(restartAlphaTarget).restart();
            } else if (e.type === 'unlock' || e.type === 'free') {
              if (!s.fixedAfterDragging) {
                delete _scratch.fx;
                delete _scratch.fy;
              } else {
                _scratch.fx = pos.x;
                _scratch.fy = pos.y;
              }
              l.simulation.alphaTarget(restartAlphaTarget).restart();
            } else {
              _scratch.fx = pos.x;
              _scratch.fy = pos.y;
            }
          };
          l.removeCytoscapeEvents = function () {
            s.nodes.off('grab free drag lock unlock', _cytoscapeEvent);
            l.removeCytoscapeEvents = null;
          };
          s.nodes.on('grab free drag lock unlock', _cytoscapeEvent);
        }
        l.ungrabify(s.nodes);
      }
      l.postrun(s);
      return this;
    }
  }, {
    key: 'prerun',
    value: function prerun() {}
  }, {
    key: 'postrun',
    value: function postrun() {}
  }, {
    key: 'stop',
    value: function stop() {
      return this.reset(true);
    }
  }]);

  return ContinuousLayout;
}();

module.exports = ContinuousLayout;

/***/ }),
/* 1 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


// Simple, internal Object.assign() polyfill for options objects etc.

module.exports = Object.assign != null ? Object.assign.bind(Object) : function (tgt) {
  for (var _len = arguments.length, srcs = Array(_len > 1 ? _len - 1 : 0), _key = 1; _key < _len; _key++) {
    srcs[_key - 1] = arguments[_key];
  }

  srcs.forEach(function (src) {
    Object.keys(src).forEach(function (k) {
      return tgt[k] = src[k];
    });
  });

  return tgt;
};

/***/ }),
/* 2 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


module.exports = Object.freeze({
  animate: true, // whether to show the layout as it's running; special 'end' value makes the layout animate like a discrete layout
  maxIterations: 0, // max iterations before the layout will bail out
  maxSimulationTime: 0, // max length in ms to run the layout
  ungrabifyWhileSimulating: false, // so you can't drag nodes during layout
  fixedAfterDragging: false, // fixed node after dragging
  fit: false, // on every layout reposition of nodes, fit the viewport
  padding: 30, // padding around the simulation
  boundingBox: undefined, // constrain layout bounds; { x1, y1, x2, y2 } or { x1, y1, w, h }
  /**d3-force API**/
  alpha: undefined, // sets the current alpha to the specified number in the range [0,1]
  alphaMin: undefined, // sets the minimum alpha to the specified number in the range [0,1]
  alphaDecay: undefined, // sets the alpha decay rate to the specified number in the range [0,1]
  alphaTarget: undefined, // sets the current target alpha to the specified number in the range [0,1]
  velocityDecay: undefined, // sets the velocity decay factor to the specified number in the range [0,1]
  collideRadius: undefined, // sets the radius accessor to the specified number or function
  collideStrength: undefined, // sets the force strength to the specified number in the range [0,1]
  collideIterations: undefined, // sets the number of iterations per application to the specified number
  linkId: undefined, // sets the node id accessor to the specified function
  linkDistance: 30, // sets the distance accessor to the specified number or function
  linkStrength: undefined, // sets the strength accessor to the specified number or function
  linkIterations: undefined, // sets the number of iterations per application to the specified number
  manyBodyStrength: undefined, // sets the strength accessor to the specified number or function
  manyBodyTheta: undefined, // sets the Barnes–Hut approximation criterion to the specified number
  manyBodyDistanceMin: undefined, // sets the minimum distance between nodes over which this force is considered
  manyBodyDistanceMax: undefined, // sets the maximum distance between nodes over which this force is considered
  xStrength: undefined, // sets the strength accessor to the specified number or function
  xX: undefined, // sets the x-coordinate accessor to the specified number or function
  yStrength: undefined, // sets the strength accessor to the specified number or function
  yY: undefined, // sets the y-coordinate accessor to the specified number or function
  radialStrength: undefined, // sets the strength accessor to the specified number or function
  radialRadius: undefined, // sets the circle radius to the specified number or function
  radialX: undefined, // sets the x-coordinate of the circle center to the specified number
  radialY: undefined, // sets the y-coordinate of the circle center to the specified number
  // layout event callbacks
  ready: function ready() {}, // on layoutready
  stop: function stop() {}, // on layoutstop
  tick: function tick() {}, // on every iteration
  // positioning options
  randomize: false, // use random node positions at beginning of layout
  // infinite layout options
  infinite: false // overrides all other options for a forces-all-the-time mode
});

/***/ }),
/* 3 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var impl = __webpack_require__(0);

// registers the extension on a cytoscape lib ref
var register = function register(cytoscape) {
  if (!cytoscape) {
    return;
  } // can't register if cytoscape unspecified

  cytoscape('layout', 'd3-force', impl); // register with cytoscape.js
};

if (typeof cytoscape !== 'undefined') {
  // expose to global cytoscape (i.e. window.cytoscape)
  register(cytoscape);
}

module.exports = register;

/***/ }),
/* 4 */
/***/ (function(module, exports) {

module.exports = __WEBPACK_EXTERNAL_MODULE_4__;

/***/ })
/******/ ]);
});