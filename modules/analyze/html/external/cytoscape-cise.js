(function webpackUniversalModuleDefinition(root, factory) {
    if (typeof exports === 'object' && typeof module === 'object')
        module.exports = factory(require("avsdf-base"), require("cose-base"));
    else if (typeof define === 'function' && define.amd)
        define(["avsdf-base", "cose-base"], factory);
    else if (typeof exports === 'object')
        exports["cytoscapeCise"] = factory(require("avsdf-base"), require("cose-base"));
    else
        root["cytoscapeCise"] = factory(root["avsdfBase"], root["coseBase"]);
})(this, function(__WEBPACK_EXTERNAL_MODULE_0__, __WEBPACK_EXTERNAL_MODULE_3__) {
    return /******/ (function(modules) { // webpackBootstrap
            /******/ // The module cache
            /******/
            var installedModules = {};
            /******/
            /******/ // The require function
            /******/
            function __webpack_require__(moduleId) {
                /******/
                /******/ // Check if module is in cache
                /******/
                if (installedModules[moduleId]) {
                    /******/
                    return installedModules[moduleId].exports;
                    /******/
                }
                /******/ // Create a new module (and put it into the cache)
                /******/
                var module = installedModules[moduleId] = {
                    /******/
                    i: moduleId,
                    /******/
                    l: false,
                    /******/
                    exports: {}
                    /******/
                };
                /******/
                /******/ // Execute the module function
                /******/
                modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);
                /******/
                /******/ // Flag the module as loaded
                /******/
                module.l = true;
                /******/
                /******/ // Return the exports of the module
                /******/
                return module.exports;
                /******/
            }
            /******/
            /******/
            /******/ // expose the modules object (__webpack_modules__)
            /******/
            __webpack_require__.m = modules;
            /******/
            /******/ // expose the module cache
            /******/
            __webpack_require__.c = installedModules;
            /******/
            /******/ // identity function for calling harmony imports with the correct context
            /******/
            __webpack_require__.i = function(value) { return value; };
            /******/
            /******/ // define getter function for harmony exports
            /******/
            __webpack_require__.d = function(exports, name, getter) {
                /******/
                if (!__webpack_require__.o(exports, name)) {
                    /******/
                    Object.defineProperty(exports, name, {
                        /******/
                        configurable: false,
                        /******/
                        enumerable: true,
                        /******/
                        get: getter
                            /******/
                    });
                    /******/
                }
                /******/
            };
            /******/
            /******/ // getDefaultExport function for compatibility with non-harmony modules
            /******/
            __webpack_require__.n = function(module) {
                /******/
                var getter = module && module.__esModule ?
                    /******/
                    function getDefault() { return module['default']; } :
                    /******/
                    function getModuleExports() { return module; };
                /******/
                __webpack_require__.d(getter, 'a', getter);
                /******/
                return getter;
                /******/
            };
            /******/
            /******/ // Object.prototype.hasOwnProperty.call
            /******/
            __webpack_require__.o = function(object, property) { return Object.prototype.hasOwnProperty.call(object, property); };
            /******/
            /******/ // __webpack_public_path__
            /******/
            __webpack_require__.p = "";
            /******/
            /******/ // Load entry module and return exports
            /******/
            return __webpack_require__(__webpack_require__.s = 15);
            /******/
        })
        /************************************************************************/
        /******/
        ([
            /* 0 */
            /***/
            (function(module, exports) {

                module.exports = __WEBPACK_EXTERNAL_MODULE_0__;

                /***/
            }),
            /* 1 */
            /***/
            (function(module, exports, __webpack_require__) {

                "use strict";


                /**
                 * This class maintains the constants used by CiSE layout.
                 *
                 *
                 * Copyright: i-Vis Research Group, Bilkent University, 2007 - present
                 */

                var FDLayoutConstants = __webpack_require__(0).layoutBase.FDLayoutConstants;

                function CiSEConstants() {}

                for (var prop in FDLayoutConstants) {
                    CiSEConstants[prop] = FDLayoutConstants[prop];
                }

                // -----------------------------------------------------------------------------
                // Section: CiSE layout user options
                // -----------------------------------------------------------------------------

                CiSEConstants.DEFAULT_SPRING_STRENGTH = 1.5 * FDLayoutConstants.DEFAULT_SPRING_STRENGTH;

                // Amount of separation of nodes on the associated circle
                CiSEConstants.DEFAULT_NODE_SEPARATION = FDLayoutConstants.DEFAULT_EDGE_LENGTH / 4;

                // Inter-cluster edge length factor (2.0 means inter-cluster edges should be
                // twice as long as intra-cluster edges)
                CiSEConstants.DEFAULT_IDEAL_INTER_CLUSTER_EDGE_LENGTH_COEFF = 1.4;

                // Whether to enable pulling nodes inside of the circles
                CiSEConstants.DEFAULT_ALLOW_NODES_INSIDE_CIRCLE = false;

                // Max percentage of the nodes in a circle that can be inside the circle
                CiSEConstants.DEFAULT_MAX_RATIO_OF_NODES_INSIDE_CIRCLE = 0.1;

                // -----------------------------------------------------------------------------
                // Section: CiSE layout remaining constants
                // -----------------------------------------------------------------------------

                // Ideal length of an edge incident with an inner-node
                CiSEConstants.DEFAULT_INNER_EDGE_LENGTH = FDLayoutConstants.DEFAULT_EDGE_LENGTH / 3;

                // Maximum rotation angle
                CiSEConstants.MAX_ROTATION_ANGLE = Math.PI / 36.0;

                // Minimum rotation angle
                CiSEConstants.MIN_ROTATION_ANGLE = -CiSEConstants.MAX_ROTATION_ANGLE;

                // Number of iterations without swap or swap prepartion
                CiSEConstants.SWAP_IDLE_DURATION = 45;

                // Number of iterations required for collecting information about swapping
                CiSEConstants.SWAP_PREPERATION_DURATION = 5;

                // Number of iterations that should be done in between two swaps.
                CiSEConstants.SWAP_PERIOD = CiSEConstants.SWAP_IDLE_DURATION + CiSEConstants.SWAP_PREPERATION_DURATION;

                // Number of iterations during which history (of pairs swapped) kept
                CiSEConstants.SWAP_HISTORY_CLEARANCE_PERIOD = 6 * CiSEConstants.SWAP_PERIOD;

                // Buffer for swapping
                CiSEConstants.MIN_DISPLACEMENT_FOR_SWAP = 6;

                // Number of iterations that should be done in between two flips.
                CiSEConstants.REVERSE_PERIOD = 25;

                module.exports = CiSEConstants;

                /***/
            }),
            /* 2 */
            /***/
            (function(module, exports, __webpack_require__) {

                "use strict";


                // Simple, internal Object.assign() polyfill for options objects etc.

                module.exports = Object.assign != null ? Object.assign.bind(Object) : function(tgt) {
                    for (var _len = arguments.length, srcs = Array(_len > 1 ? _len - 1 : 0), _key = 1; _key < _len; _key++) {
                        srcs[_key - 1] = arguments[_key];
                    }

                    srcs.forEach(function(src) {
                        Object.keys(src).forEach(function(k) {
                            return tgt[k] = src[k];
                        });
                    });

                    return tgt;
                };

                /***/
            }),
            /* 3 */
            /***/
            (function(module, exports) {

                module.exports = __WEBPACK_EXTERNAL_MODULE_3__;

                /***/
            }),
            /* 4 */
            /***/
            (function(module, exports, __webpack_require__) {

                "use strict";


                /**
                 *
                 * Choose the type of layout that best suits your usecase as a starting point.
                 *
                 * A discrete layout is one that algorithmically sets resultant positions.  It
                 * does not have intermediate positions.
                 *
                 * A continuous layout is one that updates positions continuously, like a force-
                 * directed / physics simulation layout.
                 */
                module.exports = __webpack_require__(16);

                /***/
            }),
            /* 5 */
            /***/
            (function(module, exports, __webpack_require__) {

                "use strict";


                /**
                 * This class implements data and functionality required for CiSE layout per
                 * cluster.
                 *
                 *
                 * Copyright: i-Vis Research Group, Bilkent University, 2007 - present
                 */

                var LGraph = __webpack_require__(0).layoutBase.LGraph;
                var IGeometry = __webpack_require__(0).layoutBase.IGeometry;
                var NeedlemanWunsch = __webpack_require__(0).layoutBase.NeedlemanWunsch;
                var CircularForce = __webpack_require__(14);
                var CiSEConstants = __webpack_require__(1);
                var CiSEInterClusterEdgeInfo = __webpack_require__(8);
                var CiSEInterClusterEdgeSort = __webpack_require__(9);

                function CiSECircle(parent, graphMgr, vNode) {
                    LGraph.call(this, parent, graphMgr, vNode);

                    // Holds the intra-cluster edges of this circle, initially it is null. It
                    // will be calculated and stored when getIntraClusterEdges method is first
                    // called.
                    this.intraClusterEdges = null;

                    // Holds the inter-cluster edges of this circle, initially it is null. It
                    // will be calculated and stored when getInterClusterEdges method is first
                    // called.
                    this.interClusterEdges = null;

                    // Holds the nodes which don't have neighbors outside this circle
                    this.inNodes = [];

                    // Holds the nodes which have neighbors outside this circle
                    this.outNodes = [];

                    // Holds the nodes which are on the circle
                    this.onCircleNodes = [];

                    // Holds the nodes which are inside the circle
                    this.inCircleNodes = [];

                    // The radius of this circle, calculated with respect to the dimensions of
                    // the nodes on this circle and node separation options
                    this.radius = 0;

                    // Holds the pairwise ordering of on-circle nodes computed in earlier stages
                    // of layout. Value at i,j means the following assuming u and v are
                    // on-circle nodes with orderIndex i and j, respectively. Value at i,j is
                    // true (false) if u and v are closer when we go from u to v in clockwise
                    // (counter-clockwise) direction. Here we base distance on the angles of the
                    // two nodes as opposed to their order indices (this might make a difference
                    // due to non-uniform node sizes).
                    this.orderMatrix = null;

                    // Whether or not this circle may be reserved for the purpose of improving
                    // inter-cluster edge crossing number as we do not want to redundantly
                    // reverse clusters and end up in oscillating situtations. Clusters with
                    // special circumstances (e.g. less than two inter-cluster edge) are set as
                    // may not be reversed as well.
                    this.mayBeReversed = true;
                }

                CiSECircle.prototype = Object.create(LGraph.prototype);

                for (var prop in LGraph) {
                    CiSECircle[prop] = LGraph[prop];
                }

                // -----------------------------------------------------------------------------
                // Section: Accessors and mutators
                // -----------------------------------------------------------------------------
                // This method returns the radius of this circle.
                CiSECircle.prototype.setRadius = function(radius) {
                    this.radius = radius;
                };

                // This method sets the radius of this circle.
                CiSECircle.prototype.getRadius = function() {
                    return this.radius;
                };

                // This method returns nodes that don't have neighbors outside this circle.
                CiSECircle.prototype.getInNodes = function() {
                    return this.inNodes;
                };

                // This method returns nodes that have neighbors outside this circle.
                CiSECircle.prototype.getOutNodes = function() {
                    return this.outNodes;
                };

                // This method returns nodes that don't have neighbors outside this circle.
                CiSECircle.prototype.getOnCircleNodes = function() {
                    return this.onCircleNodes;
                };

                // This method returns nodes that don't have neighbors outside this circle.
                CiSECircle.prototype.getInCircleNodes = function() {
                    return this.inCircleNodes;
                };

                CiSECircle.prototype.setMayNotBeReversed = function() {
                    this.mayBeReversed = false;
                };

                // This method returns whether or not this circle has been reversed.
                CiSECircle.prototype.getMayBeReversed = function() {
                    return this.mayBeReversed;
                };

                // This method downcasts and returns the child at given index.
                CiSECircle.prototype.getChildAt = function(index) {
                    return this.onCircleNodes[index];
                };

                /**
                 * This method returns the inter-cluster edges whose one end is in this
                 * cluster.
                 */
                CiSECircle.prototype.getInterClusterEdges = function() {
                    var self = this;

                    if (this.interClusterEdges === null) //If this is called the first time
                    {
                        this.interClusterEdges = [];
                        this.outNodes.forEach(function(node) {
                            var edgesToAdd = node.getOnCircleNodeExt().getInterClusterEdges();
                            for (var i = 0; i < edgesToAdd.length; i++) {
                                self.interClusterEdges.push(edgesToAdd[i]);
                            }
                        });
                    }

                    return this.interClusterEdges;
                };

                /**
                 * This method returns the intra cluster edges of this circle
                 */
                CiSECircle.prototype.getIntraClusterEdges = function() {
                    var self = this;

                    if (this.intraClusterEdges === null) //If this is called the first time
                    {
                        this.intraClusterEdges = [];
                        var allEdges = this.getEdges();
                        allEdges.forEach(function(edge) {
                            if (edge.isIntraEdge()) self.intraClusterEdges.push(edge);
                        });
                    }

                    return this.intraClusterEdges;
                };

                // -----------------------------------------------------------------------------
                // Section: Other methods
                // -----------------------------------------------------------------------------

                // This method calculates and sets dimensions of the parent node of this
                // circle. Parent node is centered to be at the same location of the
                // associated circle but its dimensions are larger than the circle by a
                // factor (must be >= 1 to ensure all nodes are enclosed within its
                // rectangle) of the largest dimension (width or height) of on-circle nodes
                // so that it completely encapsulates the nodes on this circle.
                CiSECircle.prototype.calculateParentNodeDimension = function() {
                    var self = this;

                    var maxOnCircleNodeDimension = Number.MIN_SAFE_INTEGER;

                    for (var i = 0; i < this.onCircleNodes.length; i++) {
                        var node = this.onCircleNodes[i];

                        if (node.getWidth() > maxOnCircleNodeDimension) {
                            maxOnCircleNodeDimension = node.getWidth();
                        }
                        if (node.getHeight() > maxOnCircleNodeDimension) {
                            maxOnCircleNodeDimension = node.getHeight();
                        }
                    }

                    var dimension = 2.0 * (self.radius + self.margin) + maxOnCircleNodeDimension;
                    var parentNode = self.getParent();
                    parentNode.setHeight(dimension);
                    parentNode.setWidth(dimension);
                };

                /*
                 * This method computes the order matrix of this circle. This should be
                 * called only once at early stages of layout and is used to hold the order
                 * of on-circle nodes as specified.
                 */
                CiSECircle.prototype.computeOrderMatrix = function() {
                    var N = this.onCircleNodes.length;

                    // 'Two Dimensional array' (array of arrays in JS) with bool cell values
                    this.orderMatrix = new Array(N);
                    for (var i = 0; i < this.orderMatrix.length; i++) {
                        this.orderMatrix[i] = new Array(N);
                    }

                    for (var _i = 0; _i < N; _i++) {
                        for (var j = 0; j < N; j++) {
                            if (j > _i) {
                                var angleDiff = this.onCircleNodes[j].getOnCircleNodeExt().getAngle() - this.onCircleNodes[_i].getOnCircleNodeExt().getAngle();

                                if (angleDiff < 0) {
                                    angleDiff += IGeometry.TWO_PI;
                                }

                                if (angleDiff <= Math.PI) {
                                    this.orderMatrix[_i][j] = true;
                                    this.orderMatrix[j][_i] = false;
                                } else {
                                    this.orderMatrix[_i][j] = false;
                                    this.orderMatrix[j][_i] = true;
                                }
                            }
                        }
                    }
                };

                /**
                 * This method rotates this circle by iterating over and adjusting the
                 * relative positioning of all nodes on this circle by the calculated angle
                 * with respect to the rotation amount of the owner node.
                 */
                CiSECircle.prototype.rotate = function() {
                    // Take size into account when reflecting total force into rotation!
                    var parentNode = this.getParent();
                    var noOfNodes = this.getOnCircleNodes().length;
                    var rotationAmount = parentNode.rotationAmount / noOfNodes; // Think about the momentum
                    var layout = this.getGraphManager().getLayout();

                    if (rotationAmount !== 0.0) {
                        // The angle (θ) of rotation applied to each node
                        var theta = rotationAmount / this.radius;

                        if (theta > CiSEConstants.MAX_ROTATION_ANGLE) theta = CiSEConstants.MAX_ROTATION_ANGLE;
                        else if (theta < CiSEConstants.MIN_ROTATION_ANGLE) theta = CiSEConstants.MIN_ROTATION_ANGLE;

                        for (var i = 0; i < noOfNodes; i++) {
                            var onCircleNode = this.getChildAt(i);
                            var onCircleNodeExt = onCircleNode.getOnCircleNodeExt();
                            onCircleNodeExt.setAngle(onCircleNodeExt.getAngle() + theta); // Change the angle
                            onCircleNodeExt.updatePosition(); // Apply the above angle change to its position
                        }

                        // Update CiSELayout displacement
                        layout.totalDisplacement += parentNode.rotationAmount;

                        // Reset rotationAmount
                        parentNode.rotationAmount = 0.0;
                    }
                };

                /**
                 * This method returns the pairwise order of the input nodes as computed and
                 * held in orderMatrix.
                 */
                CiSECircle.prototype.getOrder = function(nodeA, nodeB) {
                    return this.orderMatrix[nodeA.getOnCircleNodeExt().getIndex()][nodeB.getOnCircleNodeExt().getIndex()];
                };

                /**
                 * This method gets the end node of the input inter-cluster edge in this
                 * cluster.
                 */
                CiSECircle.prototype.getThisEnd = function(edge) {
                    var sourceNode = edge.getSource();
                    var targetNode = edge.getTarget();

                    if (sourceNode.getOwner() === this) return sourceNode;
                    else return targetNode;
                };

                /**
                 * This method gets the end node of the input inter-cluster edge not in this
                 * cluster.
                 */
                CiSECircle.prototype.getOtherEnd = function(edge) {
                    var sourceNode = edge.getSource();
                    var targetNode = edge.getTarget();

                    if (sourceNode.getOwner() === this) return targetNode;
                    else return sourceNode;
                };

                /**
                 * This method calculates and returns rotational and translational parts of
                 * the total force calculated for the given node. The translational part is
                 * composed of components in x and y directions.
                 */
                CiSECircle.prototype.decomposeForce = function(node) {
                    var circularForce = void 0;

                    if (node.displacementX !== 0.0 || node.displacementY !== 0.0) {
                        var ownerNode = this.getParent();

                        var Cx = ownerNode.getCenterX();
                        var Cy = ownerNode.getCenterY();
                        var Nx = node.getCenterX();
                        var Ny = node.getCenterY();
                        var Fx = node.displacementX;
                        var Fy = node.displacementY;

                        var C_angle = IGeometry.angleOfVector(Cx, Cy, Nx, Ny);
                        var F_angle = IGeometry.angleOfVector(0.0, 0.0, Fx, Fy);
                        var C_rev_angle = C_angle + Math.PI;

                        // Check whether F lies between C and its opposite angle C-reverse;
                        // if so, rotation is +ve (clockwise); otherwise, it's -ve.
                        // We handle angles greater than 360 specially in the else part.
                        var isRotationClockwise = void 0;
                        if (Math.PI <= C_rev_angle && C_rev_angle < IGeometry.TWO_PI) {
                            isRotationClockwise = C_angle <= F_angle && F_angle < C_rev_angle;
                        } else {
                            C_rev_angle -= IGeometry.TWO_PI;

                            isRotationClockwise = !(C_rev_angle <= F_angle && F_angle < C_angle);
                        }

                        var angle_diff = Math.abs(C_angle - F_angle);
                        var F_magnitude = Math.sqrt(Fx * Fx + Fy * Fy);
                        var R_magnitude = Math.abs(Math.sin(angle_diff) * F_magnitude);

                        if (!isRotationClockwise) {
                            R_magnitude = -R_magnitude;
                        }

                        circularForce = new CircularForce(R_magnitude, Fx, Fy);
                    } else {
                        circularForce = new CircularForce(0.0, 0.0, 0.0);
                    }

                    return circularForce;
                };

                /**
                 * This method swaps the nodes given as parameter and make necessary angle
                 * and positioning updates.
                 */
                CiSECircle.prototype.swapNodes = function(first, second) {
                    // Determine which node has smaller index
                    var smallIndexNode = first;
                    var bigIndexNode = second;
                    var firstExt = first.getOnCircleNodeExt();
                    var secondExt = second.getOnCircleNodeExt();

                    if (smallIndexNode.getOnCircleNodeExt().getIndex() > second.getOnCircleNodeExt().getIndex()) {
                        smallIndexNode = second;
                        bigIndexNode = first;
                    }

                    // Check the exceptional case where the small index node is at 0 index
                    // and the big index node is at the last index of the circle. In this
                    // case, we treat smaller index node as bigger index node and vice versa
                    if (smallIndexNode.getOnCircleNodeExt().getPrevNode() === bigIndexNode) {
                        var tempNode = bigIndexNode;
                        bigIndexNode = smallIndexNode;
                        smallIndexNode = tempNode;
                    }

                    var smallIndexNodeExt = smallIndexNode.getOnCircleNodeExt();
                    var bigIndexNodeExt = bigIndexNode.getOnCircleNodeExt();

                    // Calculate the angle for the big index node
                    var smallIndexPrevNode = smallIndexNodeExt.getPrevNode();

                    var layout = this.getGraphManager().getLayout();
                    var nodeSeparation = layout.getNodeSeparation();

                    var angle = (smallIndexPrevNode.getOnCircleNodeExt().getAngle() + (smallIndexPrevNode.getHalfTheDiagonal() + bigIndexNode.getHalfTheDiagonal() + nodeSeparation) / this.radius) % (2 * Math.PI);

                    bigIndexNodeExt.setAngle(angle);

                    // Calculate the angle for the small index node
                    angle = (bigIndexNodeExt.getAngle() + (bigIndexNode.getHalfTheDiagonal() + smallIndexNode.getHalfTheDiagonal() + nodeSeparation) / this.radius) % (2 * Math.PI);

                    smallIndexNodeExt.setAngle(angle);

                    smallIndexNodeExt.updatePosition();
                    bigIndexNodeExt.updatePosition();

                    var tempIndex = firstExt.getIndex();
                    firstExt.setIndex(secondExt.getIndex());
                    secondExt.setIndex(tempIndex);
                    this.getOnCircleNodes()[firstExt.getIndex()] = first;
                    this.getOnCircleNodes()[secondExt.getIndex()] = second;

                    firstExt.updateSwappingConditions();
                    secondExt.updateSwappingConditions();

                    if (firstExt.getNextNode() === second) {
                        firstExt.getPrevNode().getOnCircleNodeExt().updateSwappingConditions();
                        secondExt.getNextNode().getOnCircleNodeExt().updateSwappingConditions();
                    } else {
                        firstExt.getNextNode().getOnCircleNodeExt().updateSwappingConditions();
                        secondExt.getPrevNode().getOnCircleNodeExt().updateSwappingConditions();
                    }
                };

                /*
                 * This method checks to see for each cluster (in no particular order)
                 * whether or not reversing the order of the cluster would reduce
                 * inter-cluster edge crossings. The decision is based on global sequence
                 * alignment of the order of the nodes in the cluster vs. the order of their
                 * neighbors in other clusters. A cluster that was reversed earlier is not
                 * reversed again to avoid oscillations. It returns true if reverse order
                 * is adapted.
                 */
                CiSECircle.prototype.checkAndReverseIfReverseIsBetter = function() {
                    // First form the list of inter cluster edges of this cluster
                    var interClusterEdges = this.getInterClusterEdges();
                    var interClusterEdgeInfos = new Array(interClusterEdges.length);

                    // Now form the info array that contains not only the inter-cluster
                    // edges but also other information such as the angle they make w.r.t.
                    // the cluster center and neighboring node center.
                    // In the meantime, calculate how many inter-cluster edge each on-circle
                    // node is incident with. This information will be used to duplicate
                    // char codes of those nodes with 2 or more inter-graph edge.
                    var angle = void 0;
                    var clusterCenter = this.getParent().getCenter();
                    var interClusterEdge = void 0;
                    var endInThisCluster = void 0;
                    var endInOtherCluster = void 0;
                    var centerOfEndInOtherCluster = void 0;
                    var nodeCount = this.onCircleNodes.length;
                    var interClusterEdgeDegree = new Array(nodeCount);

                    for (var i = 0; i < nodeCount; i++) {
                        interClusterEdgeDegree[i] = 0;
                    }

                    var noOfOnCircleNodesToBeRepeated = 0;

                    for (var _i2 = 0; _i2 < interClusterEdges.length; _i2++) {
                        interClusterEdge = interClusterEdges[_i2];
                        endInOtherCluster = this.getOtherEnd(interClusterEdge);
                        centerOfEndInOtherCluster = endInOtherCluster.getCenter();
                        angle = IGeometry.angleOfVector(clusterCenter.x, clusterCenter.y, centerOfEndInOtherCluster.x, centerOfEndInOtherCluster.y);
                        interClusterEdgeInfos[_i2] = new CiSEInterClusterEdgeInfo(interClusterEdge, angle);

                        endInThisCluster = this.getThisEnd(interClusterEdge);
                        interClusterEdgeDegree[endInThisCluster.getOnCircleNodeExt().getIndex()]++;

                        if (interClusterEdgeDegree[endInThisCluster.getOnCircleNodeExt().getIndex()] > 1) {
                            noOfOnCircleNodesToBeRepeated++;
                        }
                    }

                    // On circle nodes will be ordered by their indices in this array
                    var onCircleNodes = this.onCircleNodes;

                    // Form arrays for current and reversed order of nodes of this cluster
                    // Take any repetitions into account (if node with char code 'b' is
                    // incident with 3 inter-cluster edges, then repeat 'b' 2 times)
                    var nodeCountWithRepetitions = nodeCount + noOfOnCircleNodesToBeRepeated;
                    var clusterNodes = new Array(2 * nodeCountWithRepetitions);
                    var reversedClusterNodes = new Array(2 * nodeCountWithRepetitions);
                    var node = void 0;
                    var index = -1;

                    for (var _i3 = 0; _i3 < nodeCount; _i3++) {
                        node = onCircleNodes[_i3];

                        // on circle nodes with no inter-cluster edges are also considered
                        if (interClusterEdgeDegree[_i3] === 0) interClusterEdgeDegree[_i3] = 1;

                        for (var j = 0; j < interClusterEdgeDegree[_i3]; j++) {
                            index++;

                            clusterNodes[index] = clusterNodes[nodeCountWithRepetitions + index] = reversedClusterNodes[nodeCountWithRepetitions - 1 - index] = reversedClusterNodes[2 * nodeCountWithRepetitions - 1 - index] = node.getOnCircleNodeExt().getCharCode();
                        }
                    }

                    // Now sort the inter-cluster edges w.r.t. their angles
                    var edgeSorter = new CiSEInterClusterEdgeSort(this, interClusterEdgeInfos);

                    // Form an array for order of neighboring nodes of this cluster
                    var neighborNodes = new Array(interClusterEdgeInfos.length);

                    for (var _i4 = 0; _i4 < interClusterEdgeInfos.length; _i4++) {
                        interClusterEdge = interClusterEdgeInfos[_i4].getEdge();
                        endInThisCluster = this.getThisEnd(interClusterEdge);
                        neighborNodes[_i4] = endInThisCluster.getOnCircleNodeExt().getCharCode();
                    }

                    // Now calculate a score for the alignment of the current order of the
                    // nodes of this cluster w.r.t. to their neighbors order

                    var alignmentScoreCurrent = this.computeAlignmentScore(clusterNodes, neighborNodes);

                    // Then calculate a score for the alignment of the reversed order of the
                    // nodes of this cluster w.r.t. to their neighbors order

                    if (alignmentScoreCurrent !== -1) {
                        var alignmentScoreReversed = this.computeAlignmentScore(reversedClusterNodes, neighborNodes);

                        // Check if reversed order is *substantially* better aligned with
                        // the order of the neighbors of this cluster around the cluster; if
                        // so, reverse the order

                        if (alignmentScoreReversed !== -1) {
                            if (alignmentScoreReversed > alignmentScoreCurrent) {
                                this.reverseNodes();
                                this.setMayNotBeReversed();
                                return true;
                            }
                        }
                    }

                    return false;
                };

                /**
                 * This method computes an alignment for the two input char arrays and
                 * returns the alignment amount. If alignment is unsuccessful for some
                 * reason, it returns -1.
                 */
                CiSECircle.prototype.computeAlignmentScore = function(charArrayReader1, charArrayReader2) {
                    var aligner = new NeedlemanWunsch(charArrayReader1, charArrayReader2, 20, -1, -2);
                    return aligner.getScore();
                };

                /**
                 * This method reverses the nodes on this circle.
                 */
                CiSECircle.prototype.reverseNodes = function() {
                    var onCircleNodes = this.getOnCircleNodes();
                    var noOfNodesOnCircle = this.getOnCircleNodes().length;

                    for (var i = 0; i < noOfNodesOnCircle; i++) {
                        var node = onCircleNodes[i];
                        var nodeExt = node.getOnCircleNodeExt();

                        nodeExt.setIndex((noOfNodesOnCircle - nodeExt.getIndex()) % noOfNodesOnCircle);
                    }

                    this.reCalculateNodeAnglesAndPositions();
                };

                /**
                 * This method removes given on-circle node from the circle and calls
                 * reCalculateCircleSizeAndRadius and  reCalculateNodeAnglesAndPositions.
                 * This method should be called when an inner node is found and to be moved
                 * inside the circle.
                 * @param node
                 */
                CiSECircle.prototype.moveOnCircleNodeInside = function(node) {

                    // Remove the node from on-circle nodes list and add it to in-circle
                    // nodes list
                    // Make sure it has not been already moved to the out node list
                    var index = this.onCircleNodes.indexOf(node);
                    if (index > -1) {
                        this.onCircleNodes.splice(index, 1);
                    }

                    this.inCircleNodes.push(node);

                    // Re-adjust all order indexes of remaining on circle nodes.
                    for (var i = 0; i < this.onCircleNodes.length; i++) {
                        var onCircleNode = this.onCircleNodes[i];

                        onCircleNode.getOnCircleNodeExt().setIndex(i);
                    }

                    // De-register extension
                    node.setAsNonOnCircleNode();

                    // calculateRadius
                    this.reCalculateCircleSizeAndRadius();

                    //calculateNodePositions
                    this.reCalculateNodeAnglesAndPositions();

                    node.setCenter(this.getParent().getCenterX(), this.getParent().getCenterY());
                };

                /**
                 * This method calculates the size and radius of this circle with respect
                 * to the sizes of the vertices and the node separation parameter.
                 */
                CiSECircle.prototype.reCalculateCircleSizeAndRadius = function() {
                    var totalDiagonal = 0;
                    var onCircleNodes = this.getOnCircleNodes();

                    for (var i = 0; i < onCircleNodes.length; i++) {
                        var node = onCircleNodes[i];

                        var temp = node.getWidth() * node.getWidth() + node.getHeight() * node.getHeight();
                        totalDiagonal += Math.sqrt(temp);
                    }

                    var layout = this.getGraphManager().getLayout();
                    var nodeSeparation = layout.getNodeSeparation();

                    var perimeter = totalDiagonal + this.getOnCircleNodes().length * nodeSeparation;
                    this.radius = perimeter / (2 * Math.PI);
                    this.calculateParentNodeDimension();
                };

                /**
                 * This method goes over all on-circle nodes and re-calculates their angles
                 * and corresponding positions. This method should be called when on-circle
                 * nodes (content or order) have been changed for this circle.
                 */
                CiSECircle.prototype.reCalculateNodeAnglesAndPositions = function() {
                    var layout = this.getGraphManager().getLayout();
                    var nodeSeparation = layout.getNodeSeparation();

                    // It is important that we sort these on-circle nodes in place.
                    var inOrderCopy = this.onCircleNodes;
                    inOrderCopy.sort(function(a, b) {
                        return a.getOnCircleNodeExt().getIndex() - b.getOnCircleNodeExt().getIndex();
                    });

                    var parentCenterX = this.getParent().getCenterX();
                    var parentCenterY = this.getParent().getCenterY();

                    for (var i = 0; i < inOrderCopy.length; i++) {
                        var node = inOrderCopy[i];
                        var angle = void 0;

                        if (i === 0) {
                            angle = 0.0;
                        } else {
                            var previousNode = inOrderCopy[i - 1];

                            // => angle in radian = (2*PI)*(circular distance/(2*PI*r))
                            angle = previousNode.getOnCircleNodeExt().getAngle() + (node.getHalfTheDiagonal() + nodeSeparation + previousNode.getHalfTheDiagonal()) / this.radius;
                        }

                        node.getOnCircleNodeExt().setAngle(angle);
                        node.setCenter(parentCenterX + this.radius * Math.cos(angle), parentCenterY + this.radius * Math.sin(angle));
                    }
                };

                module.exports = CiSECircle;

                /***/
            }),
            /* 6 */
            /***/
            (function(module, exports, __webpack_require__) {

                "use strict";


                /**
                 * This class implements data and functionality required for CiSE layout per
                 * edge.
                 *
                 *
                 * Copyright: i-Vis Research Group, Bilkent University, 2007 - present
                 */

                var FDLayoutEdge = __webpack_require__(0).layoutBase.FDLayoutEdge;

                // -----------------------------------------------------------------------------
                // Section: Constructors and initialization
                // -----------------------------------------------------------------------------

                // Constructor
                function CiSEEdge(source, target, vEdge) {
                    FDLayoutEdge.call(this, source, target, vEdge);

                    /**
                     * Flag for inter-graph edges in the base is not good enough. So we define
                     * this one to mean: a CiSE edge is intra-cluster only if both its ends are
                     * on a common circle; not intra-cluster, otherwise!
                     */
                    this.isIntraCluster = true;
                }

                CiSEEdge.prototype = Object.create(FDLayoutEdge.prototype);

                for (var property in FDLayoutEdge) {
                    CiSEEdge[property] = FDLayoutEdge[property];
                }

                CiSEEdge.prototype.isIntraEdge = function() {
                    return this.isIntraCluster;
                };

                // -----------------------------------------------------------------------------
                // Section: Remaining methods
                // -----------------------------------------------------------------------------

                /**
                 * This method checks whether this edge crosses with the input edge. It
                 * returns false, if any of the vertices those edges are incident to are
                 * not yet placed on the circle.
                 */
                CiSEEdge.prototype.crossesWithEdge = function(other) {
                    var result = false;
                    var sourceExt = this.getSource().getOnCircleNodeExt();
                    var targetExt = this.getTarget().getOnCircleNodeExt();
                    var otherSourceExt = other.getSource().getOnCircleNodeExt();
                    var otherTargetExt = other.getTarget().getOnCircleNodeExt();
                    var sourcePos = -1;
                    var targetPos = -1;
                    var otherSourcePos = -1;
                    var otherTargetPos = -1;

                    if (sourceExt !== null) sourcePos = sourceExt.getIndex();

                    if (targetExt !== null) targetPos = targetExt.getIndex();

                    if (otherSourceExt !== null) otherSourcePos = otherSourceExt.getIndex();

                    if (otherTargetExt !== null) otherTargetPos = otherTargetExt.getIndex();

                    if (!this.isInterGraph && !other.isInterGraph) {
                        if (this.source.getOwner() !== this.target.getOwner()) result = false;
                        else {
                            // if any of the vertices those two edges are not yet placed
                            if (sourcePos === -1 || targetPos === -1 || otherSourcePos === -1 || otherTargetPos === -1) result = false;

                            var otherSourceDist = otherSourceExt.getCircDistWithTheNode(sourceExt);
                            var otherTargetDist = otherTargetExt.getCircDistWithTheNode(sourceExt);
                            var thisTargetDist = targetExt.getCircDistWithTheNode(sourceExt);

                            if (thisTargetDist < Math.max(otherSourceDist, otherTargetDist) && thisTargetDist > Math.min(otherSourceDist, otherTargetDist) && otherTargetDist !== 0 && otherSourceDist !== 0) {
                                result = true;
                            }
                        }
                    } else {
                        result = true;
                    }

                    return result;
                };

                /**
                 * This method calculates the total number of crossings of this edge with
                 * all the edges given in the input list.
                 */
                CiSEEdge.prototype.calculateTotalCrossingWithList = function(edgeList) {
                    var totalCrossing = 0;
                    for (var i = 0; i < edgeList.length; i++) {
                        totalCrossing += this.crossingWithEdge(edgeList[i]);
                    }
                    return totalCrossing;
                };

                /**
                 * This method returns 1 if this edge crosses with the input edge, 0
                 * otherwise.
                 */
                CiSEEdge.prototype.crossingWithEdge = function(other) {
                    var crosses = this.crossesWithEdge(other);
                    var result = 0;

                    if (crosses) result = 1;

                    return result;
                };

                module.exports = CiSEEdge;

                /***/
            }),
            /* 7 */
            /***/
            (function(module, exports, __webpack_require__) {

                "use strict";


                /**
                 * This class implements a graph-manager for CiSE layout specific data and
                 * functionality.
                 *
                 *
                 * Copyright: i-Vis Research Group, Bilkent University, 2007 - present
                 */

                var LGraphManager = __webpack_require__(0).layoutBase.LGraphManager;

                // -----------------------------------------------------------------------------
                // Section: Constructors and initialization
                // -----------------------------------------------------------------------------

                function CiSEGraphManager(layout) {
                    LGraphManager.call(this, layout);

                    /**
                     * All on-circle and other nodes (unclustered nodes and nodes representing
                     * each cluster/circle) in this graph manager. For efficiency purposes we
                     * hold references of these nodes that we operate on in arrays.
                     */

                    this.onCircleNodes = [];
                    this.inCircleNodes = [];
                    this.nonOnCircleNodes = [];
                }

                CiSEGraphManager.prototype = Object.create(LGraphManager.prototype);

                for (var property in LGraphManager) {
                    CiSEGraphManager[property] = LGraphManager[property];
                }

                // -----------------------------------------------------------------------------
                // Section: Accessors
                // -----------------------------------------------------------------------------

                // This method returns an array of all on-circle nodes.
                CiSEGraphManager.prototype.getOnCircleNodes = function() {
                    return this.onCircleNodes;
                };

                // This method returns an array of all in-circle nodes.
                CiSEGraphManager.prototype.getInCircleNodes = function() {
                    return this.inCircleNodes;
                };

                // This method returns an array of all nodes other than on-circle nodes.
                CiSEGraphManager.prototype.getNonOnCircleNodes = function() {
                    return this.nonOnCircleNodes;
                };

                // This method sets the array of all on-circle nodes.
                CiSEGraphManager.prototype.setOnCircleNodes = function(nodes) {
                    this.onCircleNodes = nodes;
                };

                // This method sets the array of all in-circle nodes.
                CiSEGraphManager.prototype.setInCircleNodes = function(nodes) {
                    this.inCircleNodes = nodes;
                };

                // This method sets the array of all nodes other than on-circle nodes.
                CiSEGraphManager.prototype.setNonOnCircleNodes = function(nodes) {
                    this.nonOnCircleNodes = nodes;
                };

                module.exports = CiSEGraphManager;

                /***/
            }),
            /* 8 */
            /***/
            (function(module, exports, __webpack_require__) {

                "use strict";


                /**
                 * This class keeps the information of each inter-cluster edge of the associated
                 * circle. It is to be used for sorting inter-cluster edges based on this info.
                 *
                 *
                 * Copyright: i-Vis Research Group, Bilkent University, 2007 - present
                 */

                function CiSEInterClusterEdgeInfo(edge, angle) {
                    // Inter-cluster edge
                    this.edge = edge;

                    // Angle in radians (in clockwise direction from the positive x-axis) that
                    // is computed for this inter-cluster edge based on the line segment with
                    // one end as the center of the associated cluster and the other end being
                    // the center of the source/target node of this inter-cluster edge that is
                    // not in this cluster.
                    this.angle = angle;
                }

                CiSEInterClusterEdgeInfo.prototype = Object.create(null);

                CiSEInterClusterEdgeInfo.prototype.getEdge = function() {
                    return this.edge;
                };

                CiSEInterClusterEdgeInfo.prototype.getAngle = function() {
                    return this.angle;
                };

                module.exports = CiSEInterClusterEdgeInfo;

                /***/
            }),
            /* 9 */
            /***/
            (function(module, exports, __webpack_require__) {

                "use strict";


                var _createClass = function() {
                    function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i];
                            descriptor.enumerable = descriptor.enumerable || false;
                            descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true;
                            Object.defineProperty(target, descriptor.key, descriptor); } } return function(Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

                function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

                /**
                 * This class sorts the array of input edges based on the associated angles. If
                 * angles turn out to be the same, then we sort the edges based on their
                 * in-cluster end nodes' orders in clockwise direction. This information is
                 * calculated beforehand and stored in a matrix in each associated circle.
                 *
                 */

                var CiSEInterClusterEdgeSort = function() {
                    function CiSEInterClusterEdgeSort(ownerCircle, A) {
                        _classCallCheck(this, CiSEInterClusterEdgeSort);

                        this.ownerCircle = ownerCircle;
                        this._quicksort(A, 0, A.length - 1);
                    }

                    _createClass(CiSEInterClusterEdgeSort, [{
                        key: "compareFunction",
                        value: function compareFunction(a, b) {
                            if (b.getAngle() > a.getAngle()) return true;
                            else if (b.getAngle() === a.getAngle()) {
                                if (a === b) {
                                    return false;
                                } else {
                                    return this.ownerCircle.getOrder(this.ownerCircle.getThisEnd(a.getEdge()), this.ownerCircle.getThisEnd(b.getEdge()));
                                }
                            } else {
                                return false;
                            }
                        }
                    }, {
                        key: "_quicksort",
                        value: function _quicksort(A, p, r) {
                            if (p < r) {
                                var q = this._partition(A, p, r);
                                this._quicksort(A, p, q);
                                this._quicksort(A, q + 1, r);
                            }
                        }
                    }, {
                        key: "_partition",
                        value: function _partition(A, p, r) {
                            var x = this._get(A, p);
                            var i = p;
                            var j = r;
                            while (true) {
                                while (this.compareFunction(x, this._get(A, j))) {
                                    j--;
                                }
                                while (this.compareFunction(this._get(A, i), x)) {
                                    i++;
                                }
                                if (i < j) {
                                    this._swap(A, i, j);
                                    i++;
                                    j--;
                                } else return j;
                            }
                        }
                    }, {
                        key: "_get",
                        value: function _get(object, index) {
                            return object[index];
                        }
                    }, {
                        key: "_set",
                        value: function _set(object, index, value) {
                            object[index] = value;
                        }
                    }, {
                        key: "_swap",
                        value: function _swap(A, i, j) {
                            var temp = this._get(A, i);
                            this._set(A, i, this._get(A, j));
                            this._set(A, j, temp);
                        }
                    }]);

                    return CiSEInterClusterEdgeSort;
                }();

                module.exports = CiSEInterClusterEdgeSort;

                /***/
            }),
            /* 10 */
            /***/
            (function(module, exports, __webpack_require__) {

                "use strict";


                /**
                 * This class implements a Circular Spring Embedder (CiSE) layout algortithm.
                 * The algorithm is used for layout of clustered nodes where nodes in each
                 * cluster is drawn around a circle. The basic steps of the algorithm follows:
                 * - Step 1: each cluster is laid out with AVSDF circular layout algorithm;
                 * - Step 2: cluster graph (quotient graph of the clustered graph, where nodes
                 *   correspond to clusters and edges correspond to inter-cluster edges) is laid
                 *   out with a spring embedder to determine the initial layout;
                 * - Steps 3-5: the cluster graph is laid out with a modified spring embedder,
                 *   where the nodes corresponding to clusters are also allowed to rotate,
                 *   indirectly affecting the layout of the nodes inside the clusters. In Step
                 *   3, we allow flipping of clusters, whereas in Step 4, we allow swapping of
                 *   neighboring node pairs in a cluster to improve inter-cluster edge crossings
                 *   without increasing intra-cluster crossings.
                 *
                 *   The input view aspect of GraphManager is inherited from Java version of
                 *   CiSE (Chilay) as a side effect. Ignore any references to 'view' elements.
                 *
                 *
                 * Copyright: i-Vis Research Group, Bilkent University, 2007 - present
                 */

                // -----------------------------------------------------------------------------
                // Section: Initializations
                // -----------------------------------------------------------------------------

                var Layout = __webpack_require__(0).layoutBase.FDLayout;
                var HashMap = __webpack_require__(0).layoutBase.HashMap;
                var PointD = __webpack_require__(0).layoutBase.PointD;
                var DimensionD = __webpack_require__(0).layoutBase.DimensionD;
                var AVSDFConstants = __webpack_require__(0).AVSDFConstants;
                var AVSDFLayout = __webpack_require__(0).AVSDFLayout;
                var CoSELayout = __webpack_require__(3).CoSELayout;
                var CoSEConstants = __webpack_require__(3).CoSEConstants;
                var CiSEConstants = __webpack_require__(1);
                var CiSEGraphManager = __webpack_require__(7);
                var CiSECircle = __webpack_require__(5);
                var CiSENode = __webpack_require__(11);
                var CiSEEdge = __webpack_require__(6);
                var CiSEOnCircleNodePair = __webpack_require__(13);

                // Constructor
                function CiSELayout() {
                    Layout.call(this);

                    /**
                     * Whether it is incremental
                     */
                    this.incremental = CiSEConstants.INCREMENTAL;

                    /**
                     * Separation of the nodes on each circle customizable by the user
                     */
                    this.nodeSeparation = CiSEConstants.DEFAULT_NODE_SEPARATION;

                    /**
                     * Ideal edge length coefficient for inter-cluster edges
                     */
                    this.idealInterClusterEdgeLengthCoefficient = CiSEConstants.DEFAULT_IDEAL_INTER_CLUSTER_EDGE_LENGTH_COEFF;

                    /**
                     * Decides whether pull on-circle nodes inside of the circle.
                     */
                    this.allowNodesInsideCircle = CiSEConstants.DEFAULT_ALLOW_NODES_INSIDE_CIRCLE;

                    /**
                     * Max percentage of the nodes in a circle that can move inside the circle
                     */
                    this.maxRatioOfNodesInsideCircle = CiSEConstants.DEFAULT_MAX_RATIO_OF_NODES_INSIDE_CIRCLE;

                    /**
                     * Current step of the layout process
                     */
                    this.step = CiSELayout.STEP_NOT_STARTED;

                    /**
                     * Current phase of current step
                     */
                    this.phase = CiSELayout.PHASE_NOT_STARTED;

                    /**
                     * Holds the set of pairs swapped in the last swap phase.
                     */
                    this.swappedPairsInLastIteration = [];

                    /**
                     * Iterations in the runSpringEmbedderTicl function
                     */
                    this.iterations = 0;

                    this.oldTotalDisplacement = 0.0;

                    /**
                     * Cooling Factor Variables
                     */
                    this.coolingCycle = 0;
                    this.maxCoolingCycle = this.maxIterations / CiSEConstants.CONVERGENCE_CHECK_PERIOD;
                }

                CiSELayout.prototype = Object.create(Layout.prototype);

                for (var property in Layout) {
                    CiSELayout[property] = Layout[property];
                }

                // -----------------------------------------------------------------------------
                // Section: Class constants
                // -----------------------------------------------------------------------------
                /**
                 * Steps of layout
                 */
                CiSELayout.STEP_NOT_STARTED = 0;
                CiSELayout.STEP_1 = 1;
                CiSELayout.STEP_2 = 2;
                CiSELayout.STEP_3 = 3;
                CiSELayout.STEP_4 = 4;
                CiSELayout.STEP_5 = 5;

                /**
                 * Phases of a step
                 */
                CiSELayout.PHASE_NOT_STARTED = 0;
                CiSELayout.PHASE_SWAP_PREPERATION = 1;
                CiSELayout.PHASE_PERFORM_SWAP = 2;
                CiSELayout.PHASE_OTHER = 3;

                // -----------------------------------------------------------------------------
                // Section: Class methods
                // -----------------------------------------------------------------------------

                /**
                 * This method creates a new graph manager associated with this layout.
                 */
                CiSELayout.prototype.newGraphManager = function() {
                    this.graphManager = new CiSEGraphManager(this);
                    return this.graphManager;
                };

                /**
                 * This method creates a new graph(CiSECircle) associated with the input view graph.
                 */
                CiSELayout.prototype.newCircleLGraph = function(vGraph) {
                    return new CiSECircle(null, this.graphManager, vGraph);
                };

                /**
                 * This method creates a new node associated with the input view node.
                 */
                CiSELayout.prototype.newNode = function(loc, size) {
                    return new CiSENode(this.graphManager, loc, size, null);
                };

                /**
                 * This method creates a new on-circle CiSE node associated with the input
                 * view node.
                 */
                CiSELayout.prototype.newCiSEOnCircleNode = function(loc, size) {
                    var newNode = this.newNode(loc, size);
                    newNode.setAsOnCircleNode();

                    return newNode;
                };

                /**
                 * This method creates a new edge associated with the input view edge.
                 */
                CiSELayout.prototype.newEdge = function(source, target, vEdge) {
                    return new CiSEEdge(source, target, vEdge);
                };

                /**
                 * This method returns the node separation amount for this layout.
                 */
                CiSELayout.prototype.getNodeSeparation = function() {
                    return this.nodeSeparation;
                };

                /**
                 * This method establishes the GraphManager object related to this layout. Each compound(LGraph) is CiSECircle except
                 * for the root.
                 * @param nodes: All nodes in the graph
                 * @param edges: All edges in the graph
                 * @param clusters: Array of cluster ID arrays. Each array represents a cluster where ID ∈ {0,1,2,..,n(# of clusters)}
                 *
                 * Notes:
                 * -> For unclustered nodes, their clusterID is -1.
                 * -> CiSENode that corresponds to a cluster has no ID property.
                 */
                CiSELayout.prototype.convertToClusteredGraph = function(nodes, edges, clusters) {
                    var _this = this;

                    var self = this;
                    var idToLNode = {};
                    var rootGraph = this.graphManager.getRoot();

                    // Firstly, lets create a HashMap to get node properties easier
                    var idToCytoscapeNode = new HashMap();
                    for (var i = 0; i < nodes.length; i++) {
                        idToCytoscapeNode.put(nodes[i].data('id'), nodes[i]);
                    }

                    // If it is a function just change it
                    if (typeof clusters === "function") {
                        var cIDs = [];
                        var temp = [];

                        for (var _i = 0; _i < nodes.length; _i++) {
                            var cID = clusters(nodes[_i]);
                            if (cID > 0 && cID !== null && cID !== undefined) {
                                var index = cIDs.indexOf(cID);
                                if (index > -1) {
                                    temp[index].push(nodes[_i].data('id'));
                                } else {
                                    cIDs.push(cID);
                                    temp.push([nodes[_i].data('id')]);
                                }
                            }
                        }
                        clusters = temp;
                    }

                    // lets add the nodes in clusters to the GraphManager

                    var _loop = function _loop(_i2) {
                        if (clusters[_i2].length === 0) return 'continue';

                        // Create a CiSENode for the cluster
                        var clusterNode = _this.newNode(null);

                        // ClusterID ∈ {0,1,2,..,n(# of clusters)}
                        clusterNode.setClusterId(_i2);

                        // Add it rootGraph
                        rootGraph.add(clusterNode);

                        // Create the associated Circle representing the cluster and link them together
                        var circle = _this.newCircleLGraph(null);
                        _this.graphManager.add(circle, clusterNode);

                        // Set bigger margins so clusters are spaced out nicely
                        circle.margin = circle.margin + 15;

                        // Move each node of the cluster into this circle
                        clusters[_i2].forEach(function(nodeID) {
                            var cytoNode = idToCytoscapeNode.get(nodeID);
                            var dimensions = cytoNode.layoutDimensions({
                                nodeDimensionsIncludeLabels: false
                            });
                            // Adding a node into the circle
                            var ciseNode = self.newCiSEOnCircleNode(new PointD(cytoNode.position('x') - dimensions.w / 2, cytoNode.position('y') - dimensions.h / 2), new DimensionD(parseFloat(dimensions.w), parseFloat(dimensions.h)));
                            ciseNode.setId(nodeID);
                            ciseNode.setClusterId(_i2);
                            circle.getOnCircleNodes().push(ciseNode);
                            circle.add(ciseNode);

                            // Initially all on-circle nodes are assumed to be in-nodes
                            circle.getInNodes().push(ciseNode);

                            // Map the node
                            idToLNode[ciseNode.getId()] = ciseNode;
                        });
                    };

                    for (var _i2 = 0; _i2 < clusters.length; _i2++) {
                        var _ret = _loop(_i2);

                        if (_ret === 'continue') continue;
                    }

                    // Now, add unclustered nodes to the GraphManager

                    var _loop2 = function _loop2(_i3) {
                        var clustered = false;

                        clusters.forEach(function(cluster) {
                            if (cluster.includes(nodes[_i3].data('id'))) clustered = true;
                        });

                        if (!clustered) {
                            var cytoNode = nodes[_i3];
                            var dimensions = cytoNode.layoutDimensions({
                                nodeDimensionsIncludeLabels: false
                            });
                            var _CiSENode = _this.newNode(new PointD(cytoNode.position('x') - dimensions.w / 2, cytoNode.position('y') - dimensions.h / 2), new DimensionD(parseFloat(dimensions.w), parseFloat(dimensions.h)));
                            _CiSENode.setClusterId(-1);
                            _CiSENode.setId(nodes[_i3].data('id'));
                            rootGraph.add(_CiSENode);

                            // Map the node
                            idToLNode[_CiSENode.getId()] = _CiSENode;
                        }
                    };

                    for (var _i3 = 0; _i3 < nodes.length; _i3++) {
                        _loop2(_i3);
                    }

                    // Lastly, add all edges
                    for (var _i4 = 0; _i4 < edges.length; _i4++) {
                        var e = edges[_i4];
                        var sourceNode = idToLNode[e.data("source")];
                        var targetNode = idToLNode[e.data("target")];
                        var sourceClusterID = sourceNode.getClusterId();
                        var targetClusterID = targetNode.getClusterId();

                        if (sourceNode === targetNode) continue;

                        var ciseEdge = self.newEdge(sourceNode, targetNode, null);

                        // Edge is intracluster
                        // Remember: If source or target is unclustered then edge is Not intracluster
                        if (sourceClusterID === targetClusterID && sourceClusterID !== -1 && targetClusterID !== -1) {
                            ciseEdge.isIntraCluster = true;
                            ciseEdge.getSource().getOwner().add(ciseEdge, ciseEdge.getSource(), ciseEdge.getTarget());
                        } else {
                            ciseEdge.isIntraCluster = false;
                            this.graphManager.add(ciseEdge, ciseEdge.getSource(), ciseEdge.getTarget());
                        }
                    }

                    // Populate the references of GraphManager
                    var onCircleNodes = [];
                    var nonOnCircleNodes = [];
                    var allNodes = this.graphManager.getAllNodes();
                    for (var _i5 = 0; _i5 < allNodes.length; _i5++) {
                        if (allNodes[_i5].getOnCircleNodeExt()) {
                            onCircleNodes.push(allNodes[_i5]);
                        } else {
                            nonOnCircleNodes.push(allNodes[_i5]);
                        }
                    }

                    this.graphManager.setOnCircleNodes(onCircleNodes);
                    this.graphManager.setNonOnCircleNodes(nonOnCircleNodes);

                    // Deternine out-nodes of each circle
                    this.graphManager.edges.forEach(function(e) {
                        var sourceNode = e.getSource();
                        var targetNode = e.getTarget();
                        var sourceClusterID = sourceNode.getClusterId();
                        var targetClusterID = targetNode.getClusterId();

                        // If an on-circle node is an out-node, then remove it from the
                        // in-node list and add it to out-node list of the associated
                        // circle. Notice that one or two ends of an inter-graph edge will
                        // be out-node(s).
                        if (sourceClusterID !== -1) {
                            var _circle = sourceNode.getOwner();

                            // Make sure it has not been already moved to the out node list
                            var _index = _circle.getInNodes().indexOf(sourceNode);
                            if (_index > -1) {
                                _circle.getInNodes().splice(_index, 1);
                                _circle.getOutNodes().push(sourceNode);
                            }
                        }

                        if (targetClusterID !== -1) {
                            var _circle2 = targetNode.getOwner();

                            // Make sure it has not been already moved to the out node list
                            var _index2 = _circle2.getInNodes().indexOf(targetNode);
                            if (_index2 > -1) {
                                _circle2.getInNodes().splice(_index2, 1);
                                _circle2.getOutNodes().push(targetNode);
                            }
                        }
                    });

                    return idToLNode;
                };

                /**
                 * This method runs AVSDF layout for each cluster.
                 */
                CiSELayout.prototype.doStep1 = function() {
                    this.step = CiSELayout.STEP_1;
                    this.phase = CiSELayout.PHASE_OTHER;

                    // Mapping for transferring positions and dimensions back
                    var ciseToAvsdf = new HashMap();

                    var allGraphs = this.graphManager.getGraphs();
                    for (var i = 0; i < allGraphs.length; i++) {
                        var graph = allGraphs[i];

                        // Skip the root graph which is a normal LGraph
                        if (graph instanceof CiSECircle) {
                            // Create the AVSDF layout objects
                            AVSDFConstants.DEFAULT_NODE_SEPARATION = this.nodeSeparation;
                            var avsdfLayout = new AVSDFLayout();
                            var avsdfCircle = avsdfLayout.graphManager.addRoot();
                            var clusteredNodes = graph.getOnCircleNodes();

                            // Create corresponding AVSDF nodes in current cluster
                            for (var _i6 = 0; _i6 < clusteredNodes.length; _i6++) {
                                var ciseOnCircleNode = clusteredNodes[_i6];

                                var avsdfNode = avsdfLayout.newNode(null);
                                var loc = ciseOnCircleNode.getLocation();
                                avsdfNode.setLocation(loc.x, loc.y);
                                avsdfNode.setWidth(ciseOnCircleNode.getWidth());
                                avsdfNode.setHeight(ciseOnCircleNode.getHeight());
                                avsdfCircle.add(avsdfNode);

                                ciseToAvsdf.put(ciseOnCircleNode, avsdfNode);
                            }

                            // For each edge, create a corresponding AVSDF edge if its both ends
                            // are in this cluster.
                            var allEdges = this.getAllEdges();
                            for (var _i7 = 0; _i7 < allEdges.length; _i7++) {
                                var edge = allEdges[_i7];

                                if (clusteredNodes.includes(edge.getSource()) && clusteredNodes.includes(edge.getTarget())) {
                                    var avsdfSource = ciseToAvsdf.get(edge.getSource());
                                    var avsdfTarget = ciseToAvsdf.get(edge.getTarget());
                                    var avsdfEdge = avsdfLayout.newEdge("");

                                    avsdfCircle.add(avsdfEdge, avsdfSource, avsdfTarget);
                                }
                            }

                            // Run AVSDF layout
                            avsdfLayout.layout();

                            // Do post-processing
                            var sortedByDegreeList = avsdfLayout.initPostProcess();
                            for (var _i8 = 0; _i8 < sortedByDegreeList.length; _i8++) {
                                avsdfLayout.oneStepPostProcess(sortedByDegreeList[_i8]);
                            }
                            avsdfLayout.updateNodeAngles();
                            avsdfLayout.updateNodeCoordinates();

                            // Reflect changes back to CiSENode's
                            for (var _i9 = 0; _i9 < clusteredNodes.length; _i9++) {
                                var _ciseOnCircleNode = clusteredNodes[_i9];
                                var _avsdfNode = ciseToAvsdf.get(_ciseOnCircleNode);
                                var _loc = _avsdfNode.getLocation();
                                _ciseOnCircleNode.setLocation(_loc.x, _loc.y);
                                _ciseOnCircleNode.getOnCircleNodeExt().setIndex(_avsdfNode.getIndex());
                                _ciseOnCircleNode.getOnCircleNodeExt().setAngle(_avsdfNode.getAngle());
                            }

                            // Sort nodes of this ciseCircle according to circle indexes of
                            // ciseOnCircleNodes.
                            clusteredNodes.sort(function(a, b) {
                                return a.getOnCircleNodeExt().getIndex() - b.getOnCircleNodeExt().getIndex();
                            });

                            // Assign width and height of the AVSDF circle containing the nodes
                            // above to the corresponding cise-circle.
                            if (avsdfCircle.getNodes().length > 0) {
                                var parentCiSE = graph.getParent();
                                var parentAVSDF = avsdfCircle.getParent();
                                parentCiSE.setLocation(parentAVSDF.getLocation().x, parentAVSDF.getLocation().y);
                                graph.setRadius(avsdfCircle.getRadius());
                                graph.calculateParentNodeDimension();
                            }
                        }
                    }
                };

                /**
                 * This method runs a spring embedder on the cluster-graph (quotient graph
                 * of the clustered graph) to determine initial layout.
                 */
                CiSELayout.prototype.doStep2 = function() {
                    this.step = CiSELayout.STEP_2;
                    this.phase = CiSELayout.PHASE_OTHER;
                    var newCoSENodes = [];
                    var newCoSEEdges = [];

                    // Used for holding conversion mapping between cise and cose nodes.
                    var ciseNodeToCoseNode = new HashMap();

                    // Used for reverse mapping between cose and cise edges while sorting
                    // incident edges.
                    var coseEdgeToCiseEdges = new HashMap();

                    // Create a CoSE layout object
                    var coseLayout = new CoSELayout();
                    coseLayout.isSubLayout = false;
                    coseLayout.useMultiLevelScaling = false;
                    coseLayout.useFRGridVariant = true;
                    coseLayout.springConstant *= 1.5;

                    var gm = coseLayout.newGraphManager();
                    var coseRoot = gm.addRoot();

                    // Traverse through all nodes and create new CoSENode's.
                    // !WARNING! = REMEMBER to set unique "id" properties to CoSENodes!!!!
                    var nonOnCircleNodes = this.graphManager.getNonOnCircleNodes();
                    for (var i = 0; i < nonOnCircleNodes.length; i++) {
                        var ciseNode = nonOnCircleNodes[i];

                        var newNode = coseLayout.newNode(null);
                        var loc = ciseNode.getLocation();
                        newNode.setLocation(loc.x, loc.y);
                        newNode.setWidth(ciseNode.getWidth());
                        newNode.setHeight(ciseNode.getHeight());

                        // Set nodes corresponding to circles to be larger than original, so
                        // inter-cluster edges end up longer.
                        if (ciseNode.getChild() != null) {
                            newNode.setWidth(1.2 * newNode.getWidth());
                            newNode.setHeight(1.2 * newNode.getHeight());
                        }

                        // !WARNING! = CoSE EXPECTS "id" PROPERTY IMPLICITLY, REMOVING IT WILL CAUSE TILING TO OCCUR ON THE WHOLE GRAPH
                        newNode.id = i;

                        coseRoot.add(newNode);
                        newCoSENodes.push(newNode);
                        ciseNodeToCoseNode.put(ciseNode, newNode);
                    }

                    // Used for preventing duplicate edge creation between two cose nodes
                    var nodePairs = new Array(newCoSENodes.length);
                    for (var _i10 = 0; _i10 < nodePairs.length; _i10++) {
                        nodePairs[_i10] = new Array(newCoSENodes.length);
                    }

                    // Traverse through edges and create cose edges for inter-cluster ones.
                    var allEdges = this.graphManager.getAllEdges();
                    for (var _i11 = 0; _i11 < allEdges.length; _i11++) {
                        var ciseEdge = allEdges[_i11];
                        var sourceCise = ciseEdge.getSource();
                        var targetCise = ciseEdge.getTarget();

                        // Determine source and target nodes for current edge
                        if (sourceCise.getOnCircleNodeExt() != null) {
                            // Source node is an on-circle node, take its parent as source node
                            sourceCise = ciseEdge.getSource().getOwner().getParent();
                        }
                        if (targetCise.getOnCircleNodeExt() != null) {
                            // Target node is an on-circle node, take its parent as target node
                            targetCise = ciseEdge.getTarget().getOwner().getParent();
                        }

                        var sourceCose = ciseNodeToCoseNode.get(sourceCise);
                        var targetCose = ciseNodeToCoseNode.get(targetCise);
                        var sourceIndex = newCoSENodes.indexOf(sourceCose);
                        var targetIndex = newCoSENodes.indexOf(targetCose);

                        var newEdge = void 0;
                        if (sourceIndex !== targetIndex) {
                            // Make sure it's an inter-cluster edge

                            if (nodePairs[sourceIndex][targetIndex] == null && nodePairs[targetIndex][sourceIndex] == null) {
                                newEdge = coseLayout.newEdge(null);
                                coseRoot.add(newEdge, sourceCose, targetCose);
                                newCoSEEdges.push(newEdge);

                                coseEdgeToCiseEdges.put(newEdge, []);

                                nodePairs[sourceIndex][targetIndex] = newEdge;
                                nodePairs[targetIndex][sourceIndex] = newEdge;
                            } else {
                                newEdge = nodePairs[sourceIndex][targetIndex];
                            }

                            coseEdgeToCiseEdges.get(newEdge).push(ciseEdge);
                        }
                    }

                    // Run CoSELayout
                    coseLayout.runLayout();

                    // Reflect changes back to cise nodes
                    // First update all non-on-circle nodes.
                    for (var _i12 = 0; _i12 < nonOnCircleNodes.length; _i12++) {
                        var _ciseNode = nonOnCircleNodes[_i12];
                        var coseNode = ciseNodeToCoseNode.get(_ciseNode);
                        var _loc2 = coseNode.getLocation();
                        _ciseNode.setLocation(_loc2.x, _loc2.y);
                    }

                    // Then update all cise on-circle nodes, since their parents have
                    // changed location.

                    var onCircleNodes = this.graphManager.getOnCircleNodes();

                    for (var _i13 = 0; _i13 < onCircleNodes.length; _i13++) {
                        var _ciseNode2 = onCircleNodes[_i13];
                        var _loc3 = _ciseNode2.getLocation();
                        var parentLoc = _ciseNode2.getOwner().getParent().getLocation();
                        _ciseNode2.setLocation(_loc3.x + parentLoc.x, _loc3.y + parentLoc.y);
                    }
                };

                /**
                 * This method runs a modified spring embedder as described by the CiSE
                 * layout algorithm where the on-circle nodes are fixed (pinned down to
                 * the location on their owner circle). Circles, however, are allowed to be
                 * flipped (i.e. nodes are re-ordered in the reverse direction) if reversal
                 * yields a better aligned neighborhood (w.r.t. its inter-graph edges).
                 */
                CiSELayout.prototype.step3Init = function() {
                    this.step = CiSELayout.STEP_3;
                    this.phase = CiSELayout.PHASE_OTHER;
                    this.initSpringEmbedder();
                    this.coolingCycle = 0;
                };

                /**
                 * This method runs a modified spring embedder as described by the CiSE
                 * layout algorithm where the neighboring on-circle nodes are allowed to
                 * move by swapping without increasing crossing number but circles are not
                 * allowed to be flipped.
                 */
                CiSELayout.prototype.step4Init = function() {
                    this.step = CiSELayout.STEP_4;
                    this.phase = CiSELayout.PHASE_OTHER;
                    this.initSpringEmbedder();
                    for (var i = 0; i < this.graphManager.getOnCircleNodes().length; i++) {
                        this.graphManager.getOnCircleNodes()[i].getOnCircleNodeExt().updateSwappingConditions();
                    }
                    this.coolingCycle = 0;
                };

                /**
                 * This method runs a modified spring embedder as described by the CiSE
                 * layout algorithm where the on-circle nodes are fixed (pinned down to
                 * the location on their owner circle) and circles are not allowed to be
                 * flipped.
                 */
                CiSELayout.prototype.step5Init = function() {
                    this.step = CiSELayout.STEP_5;
                    this.phase = CiSELayout.PHASE_OTHER;
                    this.initSpringEmbedder();
                    this.coolingCycle = 0;
                };

                /**
                 * This method implements a spring embedder used by steps 3 thru 5 with
                 * potentially different parameters.
                 *
                 */
                CiSELayout.prototype.runSpringEmbedderTick = function() {
                    // This function uses iterations but FDLayout uses this.totalIterations
                    this.iterations++;
                    this.totalIterations = this.iterations;

                    if (this.iterations % CiSEConstants.CONVERGENCE_CHECK_PERIOD === 0) {
                        // In step 4 make sure at least a 1/4 of max iters take place
                        var notTooEarly = this.step !== CiSELayout.STEP_4 || this.iterations > this.maxIterations / 4;

                        if (notTooEarly && this.isConverged()) {
                            return true;
                        }

                        // Cooling factor descend function
                        //this.coolingFactor = this.initialCoolingFactor * Math.pow( 1 - 0.005 , this.iterations) ;

                        this.coolingFactor = this.initialCoolingFactor * ((this.maxIterations - this.iterations) / this.maxIterations);
                    }

                    this.totalDisplacement = 0;

                    if (this.step === CiSELayout.STEP_3) {
                        if (this.iterations % CiSEConstants.REVERSE_PERIOD === 0) {
                            this.checkAndReverseIfReverseIsBetter();
                        }
                    } else if (this.step === CiSELayout.STEP_4) {
                        // clear history every now and then
                        if (this.iterations % CiSEConstants.SWAP_HISTORY_CLEARANCE_PERIOD === 0) {
                            this.swappedPairsInLastIteration = [];
                        }

                        // no of iterations in this swap period
                        var iterationInPeriod = this.iterations % CiSEConstants.SWAP_PERIOD;

                        if (iterationInPeriod >= CiSEConstants.SWAP_IDLE_DURATION) {
                            this.phase = CiSELayout.PHASE_SWAP_PREPERATION;
                        } else if (iterationInPeriod === 0) {
                            this.phase = CiSELayout.PHASE_PERFORM_SWAP;
                        } else {
                            this.phase = CiSELayout.PHASE_OTHER;
                        }
                    }

                    this.calcSpringForces();
                    this.calcRepulsionForces();
                    this.calcGravitationalForces();
                    this.calcTotalForces();
                    this.moveNodes();

                    return this.iterations >= this.maxIterations;
                };

                /**
                 * This method prepares circles for possible reversal by computing the order
                 * matrix of each circle. It also determines any circles that should never
                 * be reversed (e.g. when it has no more than 1 inter-cluster edge).
                 */

                CiSELayout.prototype.prepareCirclesForReversal = function() {
                    var nodes = this.graphManager.getRoot().getNodes();
                    nodes.forEach(function(node) {
                        var circle = node.getChild();
                        if (circle !== null && circle !== undefined) {
                            //It is a circle
                            if (circle.getInterClusterEdges().length < 2) circle.setMayNotBeReversed();

                            circle.computeOrderMatrix();
                        }
                    });
                };

                /**
                 * This method calculates the ideal edge length of each edge. Here we relax
                 * edge lengths in the polishing step and keep the edge lengths of the edges
                 * incident with inner-nodes very short to avoid overlaps.
                 */
                CiSELayout.prototype.calcIdealEdgeLengths = function(isPolishingStep) {
                    var lEdges = this.graphManager.getAllEdges();
                    for (var i = 0; i < lEdges.length; i++) {
                        var edge = lEdges[i];

                        // Loosen in the polishing step to avoid overlaps
                        if (isPolishingStep) edge.idealLength = 1.5 * this.idealEdgeLength * this.idealInterClusterEdgeLengthCoefficient;
                        else edge.idealLength = this.idealEdgeLength * this.idealInterClusterEdgeLengthCoefficient;
                    }

                    // Update in-nodes edge's lengths
                    var lNodes = this.graphManager.getInCircleNodes();
                    for (var _i14 = 0; _i14 < lNodes.length; _i14++) {
                        var node = lNodes[_i14];

                        node.getEdges().forEach(function(edge) {
                            edge.idealLength = CiSEConstants.DEFAULT_INNER_EDGE_LENGTH;
                        });
                    }
                };

                /**
                 * This method calculates the spring forces applied to end nodes of each
                 * edge. In steps 3 & 5, where on-circle nodes are not allowed to move,
                 * intra-cluster edges are ignored (as their total will equal zero and won't
                 * have an affect on the owner circle).
                 */
                CiSELayout.prototype.calcSpringForces = function() {
                    var lEdges = this.graphManager.getAllEdges();
                    for (var i = 0; i < lEdges.length; i++) {
                        var edge = lEdges[i];
                        var source = edge.getSource();
                        var target = edge.getTarget();

                        // Ignore intra-cluster edges (all steps 3 thru 5) except for those
                        // incident w/ any inner-nodes
                        if (edge.isIntraCluster && source.getOnCircleNodeExt() != null && target.getOnCircleNodeExt() != null) {
                            continue;
                        }

                        this.calcSpringForce(edge, edge.idealLength);
                    }
                };

                /**
                 * This method calculates the repulsion forces for each pair of nodes.
                 * Repulsions need not be calculated for on-circle nodes.
                 */
                CiSELayout.prototype.calcRepulsionForces = function() {
                    var lNodes = this.graphManager.getNonOnCircleNodes();
                    for (var i = 0; i < lNodes.length; i++) {
                        var nodeA = lNodes[i];
                        for (var j = i + 1; j < lNodes.length; j++) {
                            var nodeB = lNodes[j];

                            this.calcRepulsionForce(nodeA, nodeB);
                        }
                    }

                    // We need the calculate repulsion forces for in-circle nodes as well
                    // to keep them inside circle.
                    var inCircleNodes = this.graphManager.getInCircleNodes();
                    for (var _i15 = 0; _i15 < inCircleNodes.length; _i15++) {
                        var inCircleNode = inCircleNodes[_i15];
                        var ownerCircle = inCircleNode.getOwner();

                        //TODO: inner nodes repulse on-circle nodes as well, not desired!
                        // Calculate repulsion forces with all nodes inside the owner circle
                        // of this inner node.

                        var childNodes = ownerCircle.getNodes();
                        for (var _i16 = 0; _i16 < childNodes.length; _i16++) {
                            var childCiSENode = childNodes[_i16];

                            if (childCiSENode !== inCircleNode) {
                                this.calcRepulsionForce(inCircleNode, childCiSENode);
                            }
                        }
                    }
                };

                /**
                 * This method calculates the gravitational forces for each node. On-circle
                 * nodes move with their owner; thus they are not applied separate gravity.
                 */
                CiSELayout.prototype.calcGravitationalForces = function() {
                    if (!this.graphManager.rootGraph.isConnected) {
                        var _lNodes = this.graphManager.getNonOnCircleNodes();

                        for (var i = 0; i < _lNodes.length; i++) {
                            var node = _lNodes[i];
                            this.calcGravitationalForce(node);
                        }
                    }

                    // Calculate gravitational forces to keep in-circle nodes in the center
                    // TODO: is this really helping or necessary?
                    var lNodes = this.graphManager.getInCircleNodes();

                    for (var _i17 = 0; _i17 < lNodes.length; _i17++) {
                        var _node = lNodes[_i17];
                        this.calcGravitationalForce(_node);
                    }
                };

                /**
                 * This method adds up all the forces calculated earlier transferring forces
                 * of on-circle nodes to their owner node (as regular and rotational forces)
                 * when they are not allowed to move. When they are allowed to move,
                 * on-circle nodes will partially contribute to the forces of their owner
                 * circle (no rotational contribution).
                 */
                CiSELayout.prototype.calcTotalForces = function() {
                    var allNodes = this.graphManager.getAllNodes();

                    for (var i = 0; i < allNodes.length; i++) {
                        var node = allNodes[i];

                        node.displacementX = this.coolingFactor * (node.springForceX + node.repulsionForceX + node.gravitationForceX);
                        node.displacementY = this.coolingFactor * (node.springForceY + node.repulsionForceY + node.gravitationForceY);

                        node.rotationAmount = 0.0;

                        node.springForceX = 0.0;
                        node.springForceY = 0.0;
                        node.repulsionForceX = 0.0;
                        node.repulsionForceY = 0.0;
                        node.gravitationForceX = 0.0;
                        node.gravitationForceY = 0.0;
                    }

                    var onCircleNodes = this.graphManager.getOnCircleNodes();
                    for (var _i18 = 0; _i18 < onCircleNodes.length; _i18++) {
                        var _node2 = onCircleNodes[_i18];
                        var parentNode = _node2.getOwner().getParent();
                        var values = _node2.getOwner().decomposeForce(_node2);

                        if (this.phase === CiSELayout.PHASE_SWAP_PREPERATION) {
                            _node2.getOnCircleNodeExt().addDisplacementForSwap(values.getRotationAmount());
                        }

                        parentNode.displacementX += values.getDisplacementX();
                        parentNode.displacementY += values.getDisplacementY();
                        _node2.displacementX = 0.0;
                        _node2.displacementY = 0.0;

                        parentNode.rotationAmount += values.getRotationAmount();
                        _node2.rotationAmount = 0.0;
                    }
                };

                /**
                 * This method updates positions of each node at the end of an iteration.
                 * Also, it deals with swapping of two consecutive nodes on a circle in
                 * step 4.
                 */
                CiSELayout.prototype.moveNodes = function() {
                    if (this.phase !== CiSELayout.PHASE_PERFORM_SWAP) {
                        var nonOnCircleNodes = this.graphManager.getNonOnCircleNodes();

                        // Simply move all non-on-circle nodes.
                        for (var i = 0; i < nonOnCircleNodes.length; i++) {
                            nonOnCircleNodes[i].move();

                            // Also make required rotations for circles
                            if (nonOnCircleNodes[i].getChild() !== null && nonOnCircleNodes[i].getChild() !== undefined) {
                                nonOnCircleNodes[i].getChild().rotate();
                            }
                        }

                        // Also move all in-circle nodes. Note that in-circle nodes will be
                        // empty if this option is not set, hence no negative effect on
                        // performance

                        var inCircleNodes = this.graphManager.getInCircleNodes();
                        var inCircleNode = void 0;

                        for (var _i19 = 0; _i19 < inCircleNodes.length; _i19++) {
                            inCircleNode = inCircleNodes[_i19];
                            // TODO: workaround to force inner nodes to stay inside
                            inCircleNode.displacementX /= 20.0;
                            inCircleNode.displacementY /= 20.0;
                            inCircleNode.move();
                        }
                    } else {
                        // If in perform-swap phase of step 4, we have to look for swappings
                        // that do not increase edge crossings and is likely to decrease total
                        // energy.
                        var ciseOnCircleNodes = this.graphManager.getOnCircleNodes();
                        var size = ciseOnCircleNodes.length;

                        // Both nodes of a pair are out-nodes, not necessarilly safe due to
                        // inter-cluster edge crossings
                        // TODO It should be a max heap structure
                        var nonSafePairs = [];

                        // Pairs where one of the on circle nodes is an in-node; no problem
                        // swapping these
                        var safePairs = [];

                        // Nodes swapped in this round
                        var swappedNodes = [];

                        // Pairs swapped or prevented from being swapped in this round
                        var swappedPairs = [];

                        var firstNode = void 0;
                        var secondNode = void 0;
                        var firstNodeExt = void 0;
                        var secondNodeExt = void 0;
                        var firstNodeDisp = void 0;
                        var secondNodeDisp = void 0;
                        var discrepancy = void 0;
                        var inSameDirection = void 0;

                        // Check each node with its next node for swapping
                        for (var _i20 = 0; _i20 < size; _i20++) {
                            firstNode = ciseOnCircleNodes[_i20];
                            secondNode = firstNode.getOnCircleNodeExt().getNextNode();
                            firstNodeExt = firstNode.getOnCircleNodeExt();
                            secondNodeExt = secondNode.getOnCircleNodeExt();

                            // Ignore if the swap is to introduce new intra-edge crossings
                            if (!firstNodeExt.canSwapWithNext || !secondNodeExt.canSwapWithPrev) continue;

                            firstNodeDisp = firstNodeExt.getDisplacementForSwap();
                            secondNodeDisp = secondNodeExt.getDisplacementForSwap();
                            discrepancy = firstNodeDisp - secondNodeDisp;

                            // Pulling in reverse directions, no swap
                            if (discrepancy < 0.0) continue;

                            // Might swap, create safe or nonsafe node pairs
                            inSameDirection = firstNodeDisp > 0 && secondNodeDisp > 0 || firstNodeDisp < 0 && secondNodeDisp < 0;
                            var pair = new CiSEOnCircleNodePair(firstNode, secondNode, discrepancy, inSameDirection);

                            // When both are out-nodes, nonsafe; otherwise, safe
                            if (firstNodeDisp === 0.0 || secondNodeDisp === 0.0) safePairs.push(pair);
                            else nonSafePairs.push(pair);
                        }

                        var nonSafePair = void 0;
                        var lookForSwap = true;
                        var rollback = void 0;

                        // TODO max heap -> extractMax
                        nonSafePairs.sort(function(a, b) {
                            return a.getDiscrepancy() - b.getDiscrepancy();
                        });

                        // Look for a nonsafe pair until we swap one
                        while (lookForSwap && nonSafePairs.length > 0) {
                            // Pick the non safe pair that has the maximum discrepancy.
                            nonSafePair = nonSafePairs[nonSafePairs.length - 1];
                            firstNode = nonSafePair.getFirstNode();
                            secondNode = nonSafePair.getSecondNode();
                            firstNodeExt = firstNode.getOnCircleNodeExt();
                            secondNodeExt = secondNode.getOnCircleNodeExt();

                            // If this pair is swapped in previous swap phase, don't allow
                            // this swap. Also save it for the future as if it is actually
                            // swapped in order to prevent future oscilations
                            if (this.isSwappedPreviously(nonSafePair)) {
                                nonSafePairs.pop();
                                swappedPairs.push(nonSafePair);
                                continue;
                            }

                            // Check for inter-cluster edge crossings before swapping.
                            var int1 = firstNodeExt.getInterClusterIntersections(secondNodeExt);

                            // Try a swap
                            nonSafePair.swap();
                            rollback = false;

                            // Then re-compute crossings
                            var int2 = firstNodeExt.getInterClusterIntersections(secondNodeExt);

                            // Possible cases regarding discrepancy:
                            // first  second  action
                            // +      +       both clockwise: might swap if disp > 0
                            // +      -       disp > 0: might swap
                            // -      -       both counter-clockwise: might swap if disp > 0
                            // -      +       disp <= 0: no swap

                            // Under following conditions roll swap back:
                            // - swap increases inter-cluster edge crossings
                            // - inter-cluster edge number is the same but pulling in the
                            // same direction or discrepancy is below pre-determined
                            // threshold (not enough for swap)

                            rollback = int2 > int1;

                            if (!rollback && int2 === int1) {
                                rollback = nonSafePair.inSameDirection() || nonSafePair.getDiscrepancy() < CiSEConstants.MIN_DISPLACEMENT_FOR_SWAP;
                            }

                            if (rollback) {
                                nonSafePair.swap();
                                nonSafePairs.pop();
                                continue;
                            }

                            swappedNodes.push(nonSafePair.getFirstNode());
                            swappedNodes.push(nonSafePair.getSecondNode());
                            swappedPairs.push(nonSafePair);

                            // Swap performed, do not look for another nonsafe pair
                            lookForSwap = false;
                        }

                        // Now process all safe pairs
                        for (var _i21 = 0; _i21 < safePairs.length; _i21++) {
                            var safePair = safePairs[_i21];

                            // Check if discrepancy is above the threshold (enough to swap)
                            if (safePair.inSameDirection() || safePair.getDiscrepancy() < CiSEConstants.MIN_DISPLACEMENT_FOR_SWAP) {
                                continue;
                            }

                            // Check if they were already involved in a swap in this phase
                            if (swappedNodes.includes(safePair.getFirstNode()) || swappedNodes.includes(safePair.getSecondNode())) {
                                continue;
                            }

                            // Should be swapped if not previously swapped; so
                            // Check if they were previously swapped
                            if (!this.isSwappedPreviously(safePair)) {
                                safePair.swap();
                                swappedNodes.push(safePair.getFirstNode());
                                swappedNodes.push(safePair.getSecondNode());
                            }

                            // Mark swapped (even if not) to prevent future oscillations
                            swappedPairs.push(safePair);
                        }

                        // Update swap history
                        this.swappedPairsInLastIteration = [];
                        for (var _i22 = 0; _i22 < swappedPairs.length; _i22++) {
                            this.swappedPairsInLastIteration.push(swappedPairs[_i22]);
                        }

                        // Reset all discrepancy values of on circle nodes.
                        var node = void 0;

                        for (var _i23 = 0; _i23 < size; _i23++) {
                            node = ciseOnCircleNodes[_i23];
                            node.getOnCircleNodeExt().setDisplacementForSwap(0.0);
                        }
                    }
                };

                /*
                 * This method returns whether or not the input node pair was previously
                 * swapped.
                 */
                CiSELayout.prototype.isSwappedPreviously = function(pair) {
                    for (var i = 0; i < this.swappedPairsInLastIteration.length; i++) {
                        var swappedPair = this.swappedPairsInLastIteration[i];

                        if (swappedPair.getFirstNode() === pair.getFirstNode() && swappedPair.getSecondNode() === pair.getSecondNode() || swappedPair.getSecondNode() === pair.getFirstNode() && swappedPair.getFirstNode() === pair.getSecondNode()) {
                            return true;
                        }
                    }

                    return false;
                };

                /**
                 * This method tries to improve the edge crossing number by reversing a
                 * cluster (i.e., the order of the nodes in the cluster such as C,B,A
                 * instead of A,B,C). No more than one reversal is performed with each
                 * execution. The decision is based on the global sequence alignment
                 * heuristic (typically used in biological sequence alignment). A cluster
                 * that was previsouly reversed is not a candidate for reversal to avoid
                 * oscillations. It returns true if a reversal has been performed.
                 */
                CiSELayout.prototype.checkAndReverseIfReverseIsBetter = function() {
                    var gm = this.getGraphManager();

                    // For each cluster (in no particular order) check to see whether
                    // reversing the order of the nodes on the cluster could improve on
                    // inter-graph edge crossing number of that cluster.

                    var nodeIterator = gm.getRoot().getNodes();
                    var node = void 0;
                    var circle = void 0;

                    for (var i = 0; i < nodeIterator.length; i++) {
                        node = nodeIterator[i];
                        circle = node.getChild();

                        if (circle != null && circle.getMayBeReversed() && circle.getNodes().length <= 52) {
                            if (circle.checkAndReverseIfReverseIsBetter()) {
                                return true;
                            }
                        }
                    }

                    return false;
                };

                /**
                 * This method goes over all circles and tries to find nodes that can be
                 * moved inside the circle. Inner nodes are found and moved inside one at a
                 * time. This process continues for a circle until either there is no inner
                 * node or reached max inner nodes for that circle.
                 */
                CiSELayout.prototype.findAndMoveInnerNodes = function() {
                    if (!this.allowNodesInsideCircle) {
                        return;
                    }

                    var graphs = this.graphManager.getGraphs();
                    for (var i = 0; i < graphs.length; i++) {
                        var ciseCircle = graphs[i];

                        // Count inner nodes not to exceed user defined maximum
                        var innerNodeCount = 0;

                        if (ciseCircle !== this.getGraphManager().getRoot()) {
                            // It is a user parameter, retrieve it.
                            var maxInnerNodes = ciseCircle.getNodes().length * this.maxRatioOfNodesInsideCircle;

                            // Look for an inner node and move it inside
                            var innerNode = this.findInnerNode(ciseCircle);

                            while (innerNode !== null && innerNode !== undefined && innerNodeCount < maxInnerNodes) {
                                this.moveInnerNode(innerNode);
                                innerNodeCount++;

                                if (innerNodeCount < maxInnerNodes) {
                                    innerNode = this.findInnerNode(ciseCircle);
                                }
                            }
                        }
                    }
                };

                /**
                 * This method finds an inner node (if any) in the given circle.
                 */
                CiSELayout.prototype.findInnerNode = function(ciseCircle) {
                    var innerNode = null;
                    var onCircleNodeCount = ciseCircle.getOnCircleNodes().length;

                    // First sort the nodes in the circle according to their degrees.
                    var sortedNodes = ciseCircle.getOnCircleNodes();
                    sortedNodes.sort(function(a, b) {
                        return a.getEdges().length - b.getEdges().length;
                    });

                    // Evaluate each node as possible candidate
                    for (var i = onCircleNodeCount - 1; i >= 0 && innerNode == null; i--) {
                        var candidateNode = sortedNodes[i];

                        // Out nodes cannot be moved inside, so just skip them
                        if (candidateNode.getOnCircleNodeExt().getInterClusterEdges().length !== 0) {
                            continue;
                        }

                        var circleSegment = this.findMinimalSpanningSegment(candidateNode);

                        // Skip nodes with no neighbors (circle segment will be empty)
                        if (circleSegment.length === 0) {
                            continue;
                        }

                        // For all nodes in the spanning circle segment, check if that node
                        // is connected to another node on the circle with an index diff of
                        // greater than 1 (i.e. connected to a non-immediate neighbor)

                        var connectedToNonImmediate = false;

                        for (var _i24 = 0; _i24 < circleSegment.length; _i24++) {
                            var spanningNode = circleSegment[_i24];

                            // Performance improvement: stop iteration if this cannot be
                            // an inner node.
                            if (connectedToNonImmediate) {
                                break;
                            }

                            // Look for neighbors of this spanning node.
                            var neighbors = spanningNode.getNeighborsList();
                            for (var j = 0; j < neighbors.length; j++) {
                                var neighborOfSpanningNode = neighbors[j];

                                // In some case we don't need to look at the neighborhood
                                // relationship. We won't care the neighbor of spanning node
                                // if:
                                // - It is the candidate node
                                // - It is on another circle
                                // - It is already an inner node.
                                if (neighborOfSpanningNode !== candidateNode && neighborOfSpanningNode.getOwner() === ciseCircle && neighborOfSpanningNode.getOnCircleNodeExt() != null && neighborOfSpanningNode.getOnCircleNodeExt() != undefined) {

                                    var spanningIndex = spanningNode.getOnCircleNodeExt().getIndex();
                                    var neighborOfSpanningIndex = neighborOfSpanningNode.getOnCircleNodeExt().getIndex();

                                    // Calculate the index difference between spanning node
                                    // and its neighbor
                                    var indexDiff = spanningIndex - neighborOfSpanningIndex;
                                    indexDiff += onCircleNodeCount; // Get rid of neg. index
                                    indexDiff %= onCircleNodeCount; // Mod it

                                    // Give one more chance, try reverse order of nodes
                                    // just in case.
                                    if (indexDiff > 1) {
                                        indexDiff = neighborOfSpanningIndex - spanningIndex;
                                        indexDiff += onCircleNodeCount; // Get rid of neg.
                                        indexDiff %= onCircleNodeCount; // Mod it
                                    }

                                    // If the diff is still greater 1, this spanning node
                                    // has a non-immediate neighbor. Sorry but you cannot
                                    // be an inner node. Poor candidate node !!!
                                    if (indexDiff > 1) {
                                        connectedToNonImmediate = true;
                                        // stop computation.
                                        break;
                                    }
                                }
                            }
                        }

                        // If neighbors of candidate node is not connect to a non-immediate
                        // neighbor that this can be an inner node.
                        if (!connectedToNonImmediate) {
                            innerNode = candidateNode;
                        }
                    }

                    return innerNode;
                };

                /**
                 * This method safely removes inner node from circle perimeter (on-circle)
                 * and moves them inside their owner circles (as in-circle nodes)
                 */
                CiSELayout.prototype.moveInnerNode = function(innerNode) {
                    var ciseCircle = innerNode.getOwner();

                    // Remove the node from the circle first. This forces circle to
                    // re-adjust its geometry. A costly operation indeed...
                    ciseCircle.moveOnCircleNodeInside(innerNode);

                    // We need to also remove the inner node from on-circle nodes list
                    // of the associated graph manager
                    var onCircleNodesList = this.graphManager.getOnCircleNodes();
                    var index = onCircleNodesList.indexOf(innerNode);
                    if (index > -1) {
                        onCircleNodesList.splice(index, 1);
                    }

                    this.graphManager.inCircleNodes.push(innerNode);
                };

                /**
                 * This method returns a circular segment (ordered array of nodes),
                 * which is the smallest segment that spans neighbors of the given node.
                 */
                CiSELayout.prototype.findMinimalSpanningSegment = function(node) {
                    var segment = [];

                    // First create an ordered neighbors list which includes given node and
                    // its neighbors and ordered according to their indexes in this circle.
                    var orderedNeigbors = node.getOnCircleNeighbors();

                    if (orderedNeigbors.length === 0) {
                        return segment;
                    }

                    orderedNeigbors.sort(function(a, b) {
                        return a.getOnCircleNodeExt().getIndex() - b.getOnCircleNodeExt().getIndex();
                    });

                    // According to the order found, find the start and end nodes of the
                    // segment by testing each (order adjacent) neighbor pair.
                    var orderedNodes = node.getOwner().getOnCircleNodes();
                    orderedNodes.sort(function(a, b) {
                        return a.getOnCircleNodeExt().getIndex() - b.getOnCircleNodeExt().getIndex();
                    });

                    var shortestSegmentStartNode = null;
                    var shortestSegmentEndNode = null;
                    var shortestSegmentLength = orderedNodes.length;
                    var segmentLength = orderedNodes.length;
                    var neighSize = orderedNeigbors.length;
                    var i = void 0;
                    var j = void 0;
                    var tempSegmentStartNode = void 0;
                    var tempSegmentEndNode = void 0;
                    var tempSegmentLength = void 0;

                    for (i = 0; i < neighSize; i++) {
                        j = (i - 1 + neighSize) % neighSize;

                        tempSegmentStartNode = orderedNeigbors[i];
                        tempSegmentEndNode = orderedNeigbors[j];

                        tempSegmentLength = (tempSegmentEndNode.getOnCircleNodeExt().getIndex() - tempSegmentStartNode.getOnCircleNodeExt().getIndex() + segmentLength) % segmentLength + 1;

                        if (tempSegmentLength < shortestSegmentLength) {
                            shortestSegmentStartNode = tempSegmentStartNode;
                            shortestSegmentEndNode = tempSegmentEndNode;
                            shortestSegmentLength = tempSegmentLength;
                        }
                    }

                    // After finding start and end nodes for the segment, simply go over
                    // ordered nodes and create an ordered list of nodes in the segment

                    var segmentEndReached = false;
                    var currentNode = shortestSegmentStartNode;

                    while (!segmentEndReached) {
                        if (currentNode !== node) {
                            segment.push(currentNode);
                        }

                        if (currentNode === shortestSegmentEndNode) {
                            segmentEndReached = true;
                        } else {
                            var nextIndex = currentNode.getOnCircleNodeExt().getIndex() + 1;

                            if (nextIndex === orderedNodes.length) {
                                nextIndex = 0;
                            }

                            currentNode = orderedNodes[nextIndex];
                        }
                    }

                    return segment;
                };

                module.exports = CiSELayout;

                /***/
            }),
            /* 11 */
            /***/
            (function(module, exports, __webpack_require__) {

                "use strict";


                /**
                 * This class implements data and functionality required for CiSE layout per
                 * node.
                 *
                 *
                 * Copyright: i-Vis Research Group, Bilkent University, 2007 - present
                 */

                var FDLayoutNode = __webpack_require__(0).layoutBase.FDLayoutNode;
                var IMath = __webpack_require__(0).layoutBase.IMath;
                var CiSEConstants = __webpack_require__(1);
                var CiSEOnCircleNodeExt = __webpack_require__(12);

                function CiSENode(gm, loc, size, vNode) {
                    // the constructor of LNode handles alternative constructors
                    FDLayoutNode.call(this, gm, loc, size, vNode);

                    // Amount by which this node will be rotated in this iteration. Note that
                    // clockwise rotation is positive and counter-clockwise is negative.
                    this.rotationAmount = null;

                    // Extension for on-circle nodes
                    this.onCircleNodeExt = null; //Extension for on-circle nodes

                    // Cluster ID which the node belongs to
                    this.clusterID = null;

                    // Cytoscape node ID for transforming between layout and cytoscape
                    this.ID = null;
                }

                CiSENode.prototype = Object.create(FDLayoutNode.prototype);

                for (var prop in FDLayoutNode) {
                    CiSENode[prop] = FDLayoutNode[prop];
                }

                // -----------------------------------------------------------------------------
                // Section: Accessors and mutators
                // -----------------------------------------------------------------------------

                CiSENode.prototype.setClusterId = function(cID) {
                    this.clusterID = cID;
                };

                CiSENode.prototype.getClusterId = function() {
                    return this.clusterID;
                };

                CiSENode.prototype.setId = function(ID) {
                    this.ID = ID;
                };

                CiSENode.prototype.getId = function() {
                    return this.ID;
                };

                /**
                 * This method sets this node as an on-circle node by creating an extension for it.
                 */
                CiSENode.prototype.setAsOnCircleNode = function() {
                    this.onCircleNodeExt = new CiSEOnCircleNodeExt(this);
                    return this.onCircleNodeExt;
                };

                /**
                 * This method sets this node as an non on-circle node by deleting the
                 * extension for it.
                 */
                CiSENode.prototype.setAsNonOnCircleNode = function() {
                    this.onCircleNodeExt = null;
                };

                /**
                 * This method returns the extension of this node for on-circle nodes. This
                 * extension is null if this node is a non-on-circle node.
                 */
                CiSENode.prototype.getOnCircleNodeExt = function() {
                    return this.onCircleNodeExt;
                };

                /**
                 * This method limits the input displacement with the maximum possible.
                 */
                CiSENode.prototype.getLimitedDisplacement = function(displacement) {
                    if (Math.abs(displacement) > CiSEConstants.MAX_NODE_DISPLACEMENT) displacement = CiSEConstants.MAX_NODE_DISPLACEMENT * IMath.sign(displacement);

                    return displacement;
                };

                /**
                 * This method returns neighbors of this node which are on-circle, not
                 * in-circle.
                 */
                CiSENode.prototype.getOnCircleNeighbors = function() {
                    var neighbors = Array.from(this.getNeighborsList());
                    var onCircleNeighbors = [];

                    for (var i = 0; i < neighbors.length; i++) {
                        var node = neighbors[i];

                        if (node.getOnCircleNodeExt() !== null && node.getClusterId() === this.getClusterId()) onCircleNeighbors.push(node);
                    }

                    return onCircleNeighbors;
                };

                /**
                 * This method returns the number of children (weight) of this node.
                 * If it is a compound, then return the number of simple nodes inside,
                 * otherwise return 1.
                 */
                CiSENode.prototype.getNoOfChildren = function() {
                    if (this.getChild() === null || this.getChild() === undefined) return 1;
                    else return this.getChild().getNodes().length;
                };

                // -----------------------------------------------------------------------------
                // Section: Remaining methods
                // -----------------------------------------------------------------------------

                /**
                 * This method moves this node as a result of the computations at the end of
                 * this iteration.
                 */
                CiSENode.prototype.move = function() {
                    var layout = this.getOwner().getGraphManager().getLayout();

                    this.displacementX = this.getLimitedDisplacement(this.displacementX);
                    this.displacementY = this.getLimitedDisplacement(this.displacementY);

                    // First propagate movement to children if it's a circle
                    if (this.getChild() !== null && this.getChild() !== undefined) {
                        // Take size into account when reflecting total force into movement!
                        var noOfNodesOnCircle = this.getChild().getNodes().length;
                        this.displacementX /= noOfNodesOnCircle;
                        this.displacementY /= noOfNodesOnCircle;

                        var children = this.getChild().getNodes();

                        for (var i = 0; i < children.length; i++) {
                            var node = children[i];

                            node.moveBy(this.displacementX, this.displacementY);
                            layout.totalDisplacement += Math.abs(this.displacementX) + Math.abs(this.displacementY);
                        }
                    }

                    this.moveBy(this.displacementX, this.displacementY);
                    layout.totalDisplacement += Math.abs(this.displacementX) + Math.abs(this.displacementY);

                    if (this.getChild() !== null && this.getChild() !== undefined) {
                        this.getChild().updateBounds(true);
                    }
                };

                /**
                 * This method resets displacement values
                 */
                CiSENode.prototype.reset = function() {
                    this.displacementX = 0.0;
                    this.displacementY = 0.0;
                };

                module.exports = CiSENode;

                /***/
            }),
            /* 12 */
            /***/
            (function(module, exports, __webpack_require__) {

                "use strict";


                /**
                /**
                 * This class implements data and functionality required for CiSE layout per
                 * on-circle node. In other words, it is an extension to CiSENode class for
                 * on-circle nodes.
                 *
                 *
                 * Copyright: i-Vis Research Group, Bilkent University, 2007 - present
                 */

                var IGeometry = __webpack_require__(0).layoutBase.IGeometry;

                // -----------------------------------------------------------------------------
                // Section: Constructors and initializations
                // -----------------------------------------------------------------------------


                function CiSEOnCircleNodeExt(ciseNode) {
                    // Associated CiSE node
                    this.ciseNode = ciseNode;

                    // Holds the intra-cluster edges of this node, initially it is null. It
                    // will be calculated and stored when getIntraClusterEdges method is first
                    // called.
                    this.intraClusterEdges = null;

                    // Holds the inter-cluster edges of this node, initially it is null. It
                    // will be calculated and stored when getInterClusterEdges method is first
                    // called.
                    this.interClusterEdges = null;

                    // Holds relative position of this node with respect to its owner circle
                    // It is less than 0 (=-1) only if not assigned. Its unit is radian.
                    this.angle = -1;

                    // Holds current index of this node within its owner circle; it is -1 if not
                    // assigned.
                    this.orderIndex = -1;

                    // Indicates whether a swapping with next node in the owner circle order
                    // will cause no additional crossings or not.
                    this.canSwapWithNext = null;

                    // Indicates whether a swapping with previous node in the owner circle order
                    // will cause no additional crossings or not.
                    this.canSwapWithPrevious = null;

                    // Holds the total weighted displacement value calculated over a constant
                    // number of iterations used for deciding whether two nodes should be
                    // swapped.
                    this.displacementForSwap = null;
                }

                CiSEOnCircleNodeExt.prototype = Object.create(null);

                // -----------------------------------------------------------------------------
                // Section: Accessors and mutators
                // -----------------------------------------------------------------------------


                // This function returns the associated CiSENode
                CiSEOnCircleNodeExt.prototype.getCiseNode = function() {
                    return this.ciseNode;
                };

                // This function returns the relative position of this node
                // within it's owner circle
                CiSEOnCircleNodeExt.prototype.getAngle = function() {
                    return this.angle;
                };

                // This function sets the relative position of this node within its owner
                // circle. We keep the angle positive for easy debugging.
                CiSEOnCircleNodeExt.prototype.setAngle = function(angle) {
                    this.angle = angle % IGeometry.TWO_PI;
                    if (this.angle < 0) {
                        this.angle += IGeometry.TWO_PI;
                    }
                };

                // This function returns current index of this in it's owner circle
                CiSEOnCircleNodeExt.prototype.getIndex = function() {
                    return this.orderIndex;
                };

                // This function sets current index of this node in its owner circle.
                CiSEOnCircleNodeExt.prototype.setIndex = function(index) {
                    this.orderIndex = index;
                };

                /**
                 * This method returns the char code of this node based on the node index.
                 * First node of the cluster is 'a', second one is 'b", and so on. We only
                 * guarentee a unique char code up to 52 nodes in a cluster.
                 *
                 * Remember in ASCII, 'a' is 97 and 'A' is 65. In Unicode, 'A' has a bigger decimal value
                 */
                CiSEOnCircleNodeExt.prototype.getCharCode = function() {
                    var charCode = void 0;

                    if (this.orderIndex < 26) charCode = String.fromCharCode(97 + this.orderIndex);
                    else if (this.orderIndex < 52) charCode = String.fromCharCode(65 + this.orderIndex);
                    else charCode = '?';

                    return charCode;
                };

                /**
                 * This method returns the next node according to current ordering of the
                 * owner circle.
                 */
                CiSEOnCircleNodeExt.prototype.getNextNode = function() {
                    var circle = this.ciseNode.getOwner();
                    var totalNodes = circle.getOnCircleNodes().length;
                    var nextNodeIndex = this.orderIndex + 1;

                    if (nextNodeIndex === totalNodes) nextNodeIndex = 0;

                    return circle.getOnCircleNodes()[nextNodeIndex];
                };

                /**
                 * This method returns the previous node according to current ordering of
                 * the owner circle.
                 */
                CiSEOnCircleNodeExt.prototype.getPrevNode = function() {
                    var circle = this.ciseNode.getOwner();
                    var nextNodeIndex = this.orderIndex - 1;

                    if (nextNodeIndex === -1) {
                        nextNodeIndex = circle.getOnCircleNodes().length - 1;
                    }

                    return circle.getOnCircleNodes()[nextNodeIndex];
                };

                /**
                 * This method returns the extension of the next node according to current
                 * ordering of the owner circle.
                 */
                CiSEOnCircleNodeExt.prototype.getNextNodeExt = function() {
                    return this.getNextNode().getOnCircleNodeExt();
                };

                /**
                 * This method returns the extension of the previous node according to
                 * current ordering of the owner circle.
                 */
                CiSEOnCircleNodeExt.prototype.prevNextNodeExt = function() {
                    return this.getPrevNode().getOnCircleNodeExt();
                };

                CiSEOnCircleNodeExt.prototype.canSwapWithNext = function() {
                    return this.canSwapWithNext;
                };

                CiSEOnCircleNodeExt.prototype.canSwapWithPrev = function() {
                    return this.canSwapWithPrev;
                };

                CiSEOnCircleNodeExt.prototype.getDisplacementForSwap = function() {
                    return this.displacementForSwap;
                };

                CiSEOnCircleNodeExt.prototype.setDisplacementForSwap = function(displacementForSwap) {
                    this.displacementForSwap = displacementForSwap;
                };

                CiSEOnCircleNodeExt.prototype.addDisplacementForSwap = function(displacementIncrForSwap) {
                    this.displacementForSwap = displacementIncrForSwap;
                    // This is what we intended (but above seems to work better):
                    //		this.displacementForSwap = (this.displacementForSwap +
                    //			displacementIncrForSwap) / 2.0;
                };

                // -----------------------------------------------------------------------------
                // Section: Remaining methods
                // -----------------------------------------------------------------------------

                /**
                 * This method updates the absolute position of this node with respect to
                 * its angle and the position of node that owns the owner circle.
                 */
                CiSEOnCircleNodeExt.prototype.updatePosition = function() {
                    var ownerGraph = this.ciseNode.getOwner();
                    var parentNode = ownerGraph.getParent();

                    var parentX = parentNode.getCenterX();
                    var parentY = parentNode.getCenterY();

                    var xDifference = ownerGraph.getRadius() * Math.cos(this.angle);
                    var yDifference = ownerGraph.getRadius() * Math.sin(this.angle);

                    this.ciseNode.setCenter(parentX + xDifference, parentY + yDifference);
                };

                /**
                 * This method returns the index difference of this node with the input
                 * node. Note that the index difference cannot be negative if both nodes are
                 * placed on the circle. Here -1 means at least one of the nodes are not yet
                 * placed on the circle.
                 */
                CiSEOnCircleNodeExt.prototype.getCircDistWithTheNode = function(refNode) {
                    var otherIndex = refNode.getIndex();

                    if (otherIndex === -1 || this.getIndex() === -1) {
                        return -1;
                    }

                    var diff = this.getIndex() - otherIndex;

                    if (diff < 0) {
                        diff += this.ciseNode.getOwner().getOnCircleNodes().length;
                    }

                    return diff;
                };

                /**
                 * This method calculates the total number of crossings the edges of this
                 * node cause.
                 */
                CiSEOnCircleNodeExt.prototype.calculateTotalCrossing = function() {
                    var intraEdges = this.getIntraClusterEdges();
                    var count = 0;
                    var temp = [];

                    this.ciseNode.getOwner().getIntraClusterEdges().forEach(function(edge) {
                        temp.push(edge);
                    });

                    this.ciseNode.getEdges().forEach(function(edge) {
                        var index = temp.indexOf(edge);
                        if (index > -1) {
                            temp.splice(index, 1);
                        }
                    });

                    intraEdges.forEach(function(edge) {
                        count += edge.calculateTotalCrossingWithList(temp);
                    });

                    return count;
                };

                /**
                 * This method updates the conditions for swapping of this node with its
                 * previous and next neighbors on the associated circle.
                 */
                CiSEOnCircleNodeExt.prototype.updateSwappingConditions = function() {
                    // Current values
                    var currentCrossingNumber = this.calculateTotalCrossing();
                    var currentNodeIndex = this.orderIndex;

                    // What will happen if node is swapped with next
                    var nextNodeExt = this.getNextNode().getOnCircleNodeExt();
                    this.orderIndex = nextNodeExt.getIndex();
                    nextNodeExt.setIndex(currentNodeIndex);

                    var tempCrossingNumber = this.calculateTotalCrossing();
                    this.canSwapWithNext = tempCrossingNumber <= currentCrossingNumber;

                    // Reset indices
                    nextNodeExt.setIndex(this.orderIndex);
                    this.setIndex(currentNodeIndex);

                    // What will happen if node is swapped with prev
                    var prevNodeExt = this.getPrevNode().getOnCircleNodeExt();
                    this.orderIndex = prevNodeExt.getIndex();
                    prevNodeExt.setIndex(currentNodeIndex);

                    tempCrossingNumber = this.calculateTotalCrossing();
                    this.canSwapWithPrevious = tempCrossingNumber <= currentCrossingNumber;

                    // Reset indices
                    prevNodeExt.setIndex(this.orderIndex);
                    this.setIndex(currentNodeIndex);
                };

                /**
                 * This method swaps this node with the specified neighbor (prev or next).
                 */
                CiSEOnCircleNodeExt.prototype.swapWith = function(neighborExt) {
                    this.ciseNode.getOwner().swapNodes(this.ciseNode, neighborExt.ciseNode);
                };

                /**
                 * This method finds the number of crossings of inter cluster edges of this
                 * node with the inter cluster edges of the other node.
                 */
                CiSEOnCircleNodeExt.prototype.getInterClusterIntersections = function(other) {
                    var count = 0;

                    var thisInterClusterEdges = this.getInterClusterEdges();
                    var otherInterClusterEdges = other.getInterClusterEdges();

                    for (var i = 0; i < thisInterClusterEdges.length; i++) {
                        var edge = thisInterClusterEdges[i];

                        var point1 = this.ciseNode.getCenter();
                        var point2 = edge.getOtherEnd(this.ciseNode).getCenter();

                        for (var j = 0; j < otherInterClusterEdges.length; j++) {
                            var otherEdge = otherInterClusterEdges[j];
                            var point3 = other.ciseNode.getCenter();
                            var point4 = otherEdge.getOtherEnd(other.ciseNode).getCenter();

                            if (edge.getOtherEnd(this.ciseNode) !== otherEdge.getOtherEnd(other.ciseNode)) {
                                var result = IGeometry.doIntersect(point1, point2, point3, point4);

                                if (result) count++;
                            }
                        }
                    }

                    return count;
                };

                /**
                 * This method returns the inter cluster edges of the associated node.
                 */
                CiSEOnCircleNodeExt.prototype.getInterClusterEdges = function() {
                    if (this.interClusterEdges === null) {
                        //first time accessing
                        this.interClusterEdges = [];
                        var edgesOfNode = this.ciseNode.getEdges();
                        for (var i = 0; i < edgesOfNode.length; i++) {
                            var edge = edgesOfNode[i];
                            if (!edge.isIntraCluster) {
                                this.interClusterEdges.push(edge);
                            }
                        }
                    }

                    return this.interClusterEdges;
                };

                /**
                 * This method returns the intra cluster edges of the associated node.
                 */
                CiSEOnCircleNodeExt.prototype.getIntraClusterEdges = function() {
                    if (this.intraClusterEdges === null) {
                        //first time accessing
                        this.intraClusterEdges = [];
                        var edgesOfNode = this.ciseNode.getEdges();
                        for (var i = 0; i < edgesOfNode.length; i++) {
                            var edge = edgesOfNode[i];
                            if (edge.isIntraCluster) {
                                this.intraClusterEdges.push(edge);
                            }
                        }
                    }

                    return this.intraClusterEdges;
                };

                module.exports = CiSEOnCircleNodeExt;

                /***/
            }),
            /* 13 */
            /***/
            (function(module, exports, __webpack_require__) {

                "use strict";


                /**
                 * This class implements a pair of on-circle nodes used for swapping in phase 4.
                 *
                 */

                // -----------------------------------------------------------------------------
                // Section: Constructors and initializations
                // -----------------------------------------------------------------------------

                function CiSEOnCircleNodePair(first, second, displacement, inSameDirection) {
                    // The node of the pair which comes first in the ordering of its owner
                    // circle.
                    this.firstNode = first;

                    // The node of the pair which comes second in the ordering of its owner
                    // circle.
                    this.secondNode = second;

                    // The discrepancy of the displacement values of two nodes, indicating the
                    // swapping potential of the two nodes. Higher value means that nodes are
                    // more inclined to swap.
                    this.discrepancy = displacement;

                    // Whether or not the two nodes are pulling in the same direction
                    this.inSameDir = inSameDirection;
                }

                CiSEOnCircleNodePair.prototype = Object.create;

                // -----------------------------------------------------------------------------
                // Section: Accessors
                // -----------------------------------------------------------------------------

                CiSEOnCircleNodePair.prototype.getDiscrepancy = function() {
                    return this.discrepancy;
                };

                CiSEOnCircleNodePair.prototype.inSameDirection = function() {
                    return this.inSameDir;
                };

                CiSEOnCircleNodePair.prototype.getFirstNode = function() {
                    return this.firstNode;
                };

                CiSEOnCircleNodePair.prototype.getSecondNode = function() {
                    return this.secondNode;
                };

                // -----------------------------------------------------------------------------
                // Section: Remaining methods
                // -----------------------------------------------------------------------------

                CiSEOnCircleNodePair.prototype.compareTo = function(other) {
                    return this.getDiscrepancy() - other.getDiscrepancy();
                };

                CiSEOnCircleNodePair.prototype.swap = function() {
                    this.getFirstNode().getOnCircleNodeExt().swapWith(this.getSecondNode().getOnCircleNodeExt());
                };

                CiSEOnCircleNodePair.prototype.equals = function(other) {
                    var result = other instanceof CiSEOnCircleNodePair;

                    if (result) {
                        var pair = other;

                        result &= this.firstNode.equals(pair.getFirstNode()) && this.secondNode.equals(pair.getSecondNode()) || this.secondNode.equals(pair.getFirstNode()) && this.firstNode.equals(pair.getSecondNode());
                    }

                    return result;
                };

                CiSEOnCircleNodePair.prototype.hashCode = function() {
                    return this.firstNode.hashCode() + this.secondNode.hashCode();
                };

                CiSEOnCircleNodePair.prototype.toString = function() {
                    var result = "Swap: " + this.getFirstNode().label;
                    result += "<->" + this.getSecondNode().label;
                    result += ", " + this.getDiscrepancy();

                    return result;
                };

                module.exports = CiSEOnCircleNodePair;

                /***/
            }),
            /* 14 */
            /***/
            (function(module, exports, __webpack_require__) {

                "use strict";


                /**
                 * This class is a utility class that is used to store the rotation amount,
                 * x-axis displacement and y-axis displacement components of a force that act
                 * upon an on-circle node. The calculation for this is done in CiSECircle for
                 * specified on-circle node. Here we assume that forces on on-circle nodes can
                 * be modelled with forces acting upon the perimeter of a circular flat, rigid
                 * object sitting on a 2-dimensional surface, free to move in a direction
                 * without any friction. Thus, such an object is assumed to move and rotate on
                 * this force in amounts proportional to the total force (not just the vertical
                 * component of the force!) and the component of the force that is tangential to
                 * the circular shape of the object, respectively.
                 *
                 *
                 * Copyright: i-Vis Research Group, Bilkent University, 2007 - present
                 */

                // -----------------------------------------------------------------------------
                // Section: Constructors and initializations
                // -----------------------------------------------------------------------------

                function CircularForce(rotationAmount, displacementX, displacementY) {
                    // This is the rotation amount that is to be assigned to the rotationAmount
                    // of a CiSENode
                    this.rotationAmount = rotationAmount;

                    // This is the x-axis displacement value that is to be assigned to the displacementX
                    // of a CiSENode
                    this.displacementX = displacementX;

                    // This is the y-axis displacement value that is to be assigned to the displacementY
                    // of a CiSENode
                    this.displacementY = displacementY;
                }

                // -----------------------------------------------------------------------------
                // Section: Accessors and mutators
                // -----------------------------------------------------------------------------

                CircularForce.prototype.getRotationAmount = function() {
                    return this.rotationAmount;
                };

                CircularForce.prototype.setRotationAmount = function(rotationAmount) {
                    this.rotationAmount = rotationAmount;
                };

                CircularForce.prototype.getDisplacementX = function() {
                    return this.displacementX;
                };

                CircularForce.prototype.setDisplacementX = function(displacementX) {
                    this.displacementX = displacementX;
                };

                CircularForce.prototype.getDisplacementY = function() {
                    return this.displacementY;
                };

                CircularForce.prototype.setDisplacementY = function(displacementY) {
                    this.displacementY = displacementY;
                };

                module.exports = CircularForce;

                /***/
            }),
            /* 15 */
            /***/
            (function(module, exports, __webpack_require__) {

                "use strict";


                var impl = __webpack_require__(4);

                // registers the extension on a cytoscape lib ref
                var register = function register(cytoscape) {
                    if (!cytoscape) {
                        return;
                    } // can't register if cytoscape unspecified

                    cytoscape('layout', 'cise', impl); // register with cytoscape.js
                };

                if (typeof cytoscape !== 'undefined') {
                    // expose to global cytoscape (i.e. window.cytoscape)
                    register(cytoscape);
                }

                module.exports = register;

                /***/
            }),
            /* 16 */
            /***/
            (function(module, exports, __webpack_require__) {

                "use strict";


                var _createClass = function() {
                    function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i];
                            descriptor.enumerable = descriptor.enumerable || false;
                            descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true;
                            Object.defineProperty(target, descriptor.key, descriptor); } } return function(Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

                var _get = function get(object, property, receiver) { if (object === null) object = Function.prototype; var desc = Object.getOwnPropertyDescriptor(object, property); if (desc === undefined) { var parent = Object.getPrototypeOf(object); if (parent === null) { return undefined; } else { return get(parent, property, receiver); } } else if ("value" in desc) { return desc.value; } else { var getter = desc.get; if (getter === undefined) { return undefined; } return getter.call(receiver); } };

                function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

                function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

                function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); }
                    subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

                /**
                 * This class builds the required connection between CiSE elements and Cytoscape extension elements
                 *
                 *
                 * Copyright: i-Vis Research Group, Bilkent University, 2007 - present
                 */

                var CiSELayout = __webpack_require__(10);
                var CiSEConstants = __webpack_require__(1);
                var FDLayoutConstants = __webpack_require__(0).layoutBase.FDLayoutConstants;

                var ContinuousLayout = __webpack_require__(18);
                var defaults = ContinuousLayout.defaults;
                var assign = __webpack_require__(2);
                var isFn = function isFn(fn) {
                    return typeof fn === 'function';
                };

                var optFn = function optFn(opt, ele) {
                    if (isFn(opt)) {
                        return opt(ele);
                    } else {
                        return opt;
                    }
                };

                var Layout = function(_ContinuousLayout) {
                    _inherits(Layout, _ContinuousLayout);

                    function Layout(options) {
                        _classCallCheck(this, Layout);

                        //Changing CiSEConstants if there is a particular option defined in 'options' part of Layout call
                        var _this = _possibleConstructorReturn(this, (Layout.__proto__ || Object.getPrototypeOf(Layout)).call(this, assign({}, defaults, options)));

                        if (options.nodeSeparation !== null && options.nodeSeparation !== undefined) CiSEConstants.DEFAULT_NODE_SEPARATION = options.nodeSeparation;
                        else CiSEConstants.DEFAULT_NODE_SEPARATION = FDLayoutConstants.DEFAULT_EDGE_LENGTH / 4;

                        if (options.idealInterClusterEdgeLengthCoefficient !== null && options.idealInterClusterEdgeLengthCoefficient !== undefined) CiSEConstants.DEFAULT_IDEAL_INTER_CLUSTER_EDGE_LENGTH_COEFF = options.idealInterClusterEdgeLengthCoefficient;
                        else CiSEConstants.DEFAULT_IDEAL_INTER_CLUSTER_EDGE_LENGTH_COEFF = 1.4;

                        if (options.allowNodesInsideCircle !== null && options.allowNodesInsideCircle !== undefined) CiSEConstants.DEFAULT_ALLOW_NODES_INSIDE_CIRCLE = options.allowNodesInsideCircle;
                        else CiSEConstants.DEFAULT_ALLOW_NODES_INSIDE_CIRCLE = false;

                        if (options.maxRatioOfNodesInsideCircle !== null && options.maxRatioOfNodesInsideCircle !== undefined) CiSEConstants.DEFAULT_MAX_RATIO_OF_NODES_INSIDE_CIRCLE = options.maxRatioOfNodesInsideCircle;
                        else CiSEConstants.DEFAULT_MAX_RATIO_OF_NODES_INSIDE_CIRCLE = 0.1;

                        if (options.springCoeff !== null && options.springCoeff !== undefined) CiSEConstants.DEFAULT_SPRING_STRENGTH = options.springCoeff;
                        else CiSEConstants.DEFAULT_SPRING_STRENGTH = 1.5 * FDLayoutConstants.DEFAULT_SPRING_STRENGTH;

                        if (options.nodeRepulsion != null) CiSEConstants.DEFAULT_REPULSION_STRENGTH = FDLayoutConstants.DEFAULT_REPULSION_STRENGTH = options.nodeRepulsion;

                        if (options.gravity != null) CiSEConstants.DEFAULT_GRAVITY_STRENGTH = FDLayoutConstants.DEFAULT_GRAVITY_STRENGTH = options.gravity;

                        if (options.gravityRange != null) CiSEConstants.DEFAULT_GRAVITY_RANGE_FACTOR = FDLayoutConstants.DEFAULT_GRAVITY_RANGE_FACTOR = options.gravityRange;

                        if (options.maxRatioOfNodesInsideCircle !== null && options.maxRatioOfNodesInsideCircle !== undefined) CiSEConstants.DEFAULT_MAX_RATIO_OF_NODES_INSIDE_CIRCLE = options.maxRatioOfNodesInsideCircle;
                        else CiSEConstants.DEFAULT_MAX_RATIO_OF_NODES_INSIDE_CIRCLE = 0.1;
                        return _this;
                    }

                    _createClass(Layout, [{
                        key: 'prerun',
                        value: function prerun() {
                            var state = this.state;

                            //Get the graph information from Cytoscape
                            var clusters = [
                                []
                            ];
                            if (this.options.clusters !== null && this.options.clusters !== undefined) clusters = this.options.clusters;
                            var nodes = state.nodes;
                            var edges = state.edges;

                            //Initialize CiSE elements
                            var ciseLayout = this.ciseLayout = new CiSELayout();
                            var graphManager = this.graphManager = ciseLayout.newGraphManager();
                            var root = this.root = graphManager.addRoot();

                            // Construct the GraphManager according to the graph from Cytoscape
                            this.idToLNode = ciseLayout.convertToClusteredGraph(nodes, edges, clusters);

                            //This method updates whether this graph is connected or not
                            root.updateConnected();
                            // This method calculates and returns the estimated size of this graph
                            root.calcEstimatedSize();
                            ciseLayout.calcNoOfChildrenForAllNodes();

                            ciseLayout.doStep1();
                            ciseLayout.doStep2();

                            root.updateBounds(true);
                            root.estimatedSize = Math.max(root.right - root.left, root.bottom - root.top);
                            ciseLayout.prepareCirclesForReversal();
                            ciseLayout.calcIdealEdgeLengths(false);

                            // ------------------------------------------
                            // The variables to maintain the spring steps
                            // ------------------------------------------
                            // Index is there to iterate over steps
                            this.initializerIndex = 0;

                            // If the whole algorithm is finished
                            this.isDone = false;

                            // If the current step is finished
                            this.isStepDone = false;

                            // when to change to next step
                            this.timeToSwitchNextStep = true;
                        }

                        // run this each iteraction

                    }, {
                        key: 'tick',
                        value: function tick() {
                            var _this2 = this;

                            // Getting References
                            var self = this;
                            var state = this.state;

                            // Update Each Node Locations
                            state.nodes.forEach(function(n) {
                                var s = _this2.getScratch(n);

                                var location = self.idToLNode[n.data('id')];
                                s.x = location.getCenterX();
                                s.y = location.getCenterY();
                            });

                            if (this.timeToSwitchNextStep) {
                                switch (this.initializerIndex) {
                                    case 0:
                                        this.ciseLayout.step5Init();
                                        break;
                                    case 1:
                                        this.ciseLayout.step3Init();
                                        break;
                                    case 2:
                                        this.ciseLayout.step5Init();
                                        break;
                                    case 3:
                                        this.ciseLayout.step4Init();
                                        break;
                                    case 4:
                                        this.ciseLayout.findAndMoveInnerNodes();
                                        this.ciseLayout.calcIdealEdgeLengths(true);
                                        this.ciseLayout.step5Init();
                                        break;
                                }

                                this.initializerIndex++;
                                this.ciseLayout.iterations = 0;
                                this.ciseLayout.totalDisplacement = 1000;
                                this.timeToSwitchNextStep = false;
                            }

                            // Run one spring iteration
                            this.isStepDone = this.ciseLayout.runSpringEmbedderTick();

                            if (this.isStepDone && this.initializerIndex < 5) {
                                this.timeToSwitchNextStep = true;
                            }

                            if (this.isStepDone && this.timeToSwitchNextStep === false) {
                                this.isDone = true;
                            }

                            return this.isDone;
                        }

                        // run this function after the layout is done ticking

                    }, {
                        key: 'postrun',
                        value: function postrun() {}

                        // clean up any object refs that could prevent garbage collection, etc.

                    }, {
                        key: 'destroy',
                        value: function destroy() {
                            _get(Layout.prototype.__proto__ || Object.getPrototypeOf(Layout.prototype), 'destroy', this).call(this);

                            return this;
                        }
                    }]);

                    return Layout;
                }(ContinuousLayout);

                module.exports = Layout;

                /***/
            }),
            /* 17 */
            /***/
            (function(module, exports, __webpack_require__) {

                "use strict";


                // general default options for force-directed layout

                module.exports = Object.freeze({
                    animate: false, // whether to show the layout as it's running; special 'end' value makes the layout animate like a discrete layout
                    refresh: 10, // number of ticks per frame; higher is faster but more jerky
                    maxIterations: 2500, // max iterations before the layout will bail out
                    maxSimulationTime: 5000, // max length in ms to run the layout
                    ungrabifyWhileSimulating: false, // so you can't drag nodes during layout
                    fit: true, // on every layout reposition of nodes, fit the viewport
                    padding: 30, // padding around the simulation
                    boundingBox: undefined, // constrain layout bounds; { x1, y1, x2, y2 } or { x1, y1, w, h }

                    // layout event callbacks
                    ready: function ready() {}, // on layoutready
                    stop: function stop() {}, // on layoutstop

                    // positioning options
                    randomize: false, // use random node positions at beginning of layout

                    // infinite layout options
                    infinite: false // overrides all other options for a forces-all-the-time mode
                });

                /***/
            }),
            /* 18 */
            /***/
            (function(module, exports, __webpack_require__) {

                "use strict";


                var _createClass = function() {
                    function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i];
                            descriptor.enumerable = descriptor.enumerable || false;
                            descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true;
                            Object.defineProperty(target, descriptor.key, descriptor); } } return function(Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

                function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

                /**
                A generic continuous layout class
                */

                var assign = __webpack_require__(2);
                var defaults = __webpack_require__(17);
                var makeBoundingBox = __webpack_require__(19);

                var _require = __webpack_require__(20),
                    setInitialPositionState = _require.setInitialPositionState,
                    refreshPositions = _require.refreshPositions,
                    getNodePositionData = _require.getNodePositionData;

                var _require2 = __webpack_require__(21),
                    multitick = _require2.multitick;

                var Layout = function() {
                    function Layout(options) {
                        _classCallCheck(this, Layout);

                        var o = this.options = assign({}, defaults, options);

                        var s = this.state = assign({}, o, {
                            layout: this,
                            nodes: o.eles.nodes(),
                            edges: o.eles.edges(),
                            tickIndex: 0,
                            firstUpdate: true
                        });

                        s.animateEnd = o.animate && o.animate === 'end';
                        s.animateContinuously = o.animate && !s.animateEnd;
                    }

                    _createClass(Layout, [{
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
                        key: 'run',
                        value: function run() {
                            var l = this;
                            var s = this.state;

                            s.tickIndex = 0;
                            s.firstUpdate = true;
                            s.startTime = Date.now();
                            s.running = true;

                            s.currentBoundingBox = makeBoundingBox(s.boundingBox, s.cy);

                            if (s.ready) {
                                l.one('ready', s.ready);
                            }
                            if (s.stop) {
                                l.one('stop', s.stop);
                            }

                            s.nodes.forEach(function(n) {
                                return setInitialPositionState(n, s);
                            });

                            l.prerun(s);

                            if (s.animateContinuously) {
                                var ungrabify = function ungrabify(node) {
                                    if (!s.ungrabifyWhileSimulating) {
                                        return;
                                    }

                                    var grabbable = getNodePositionData(node, s).grabbable = node.grabbable();

                                    if (grabbable) {
                                        node.ungrabify();
                                    }
                                };

                                var regrabify = function regrabify(node) {
                                    if (!s.ungrabifyWhileSimulating) {
                                        return;
                                    }

                                    var grabbable = getNodePositionData(node, s).grabbable;

                                    if (grabbable) {
                                        node.grabify();
                                    }
                                };

                                var updateGrabState = function updateGrabState(node) {
                                    return getNodePositionData(node, s).grabbed = node.grabbed();
                                };

                                var onGrab = function onGrab(_ref) {
                                    var target = _ref.target;

                                    updateGrabState(target);
                                };

                                var onFree = onGrab;

                                var onDrag = function onDrag(_ref2) {
                                    var target = _ref2.target;

                                    var p = getNodePositionData(target, s);
                                    var tp = target.position();

                                    p.x = tp.x;
                                    p.y = tp.y;
                                };

                                var listenToGrab = function listenToGrab(node) {
                                    node.on('grab', onGrab);
                                    node.on('free', onFree);
                                    node.on('drag', onDrag);
                                };

                                var unlistenToGrab = function unlistenToGrab(node) {
                                    node.removeListener('grab', onGrab);
                                    node.removeListener('free', onFree);
                                    node.removeListener('drag', onDrag);
                                };

                                var fit = function fit() {
                                    if (s.fit && s.animateContinuously) {
                                        s.cy.fit(s.padding);
                                    }
                                };

                                var onNotDone = function onNotDone() {
                                    refreshPositions(s.nodes, s);
                                    fit();

                                    requestAnimationFrame(_frame);
                                };

                                var _frame = function _frame() {
                                    multitick(s, onNotDone, _onDone);
                                };

                                var _onDone = function _onDone() {
                                    refreshPositions(s.nodes, s);
                                    fit();

                                    s.nodes.forEach(function(n) {
                                        regrabify(n);
                                        unlistenToGrab(n);
                                    });

                                    s.running = false;

                                    l.emit('layoutstop');
                                };

                                l.emit('layoutstart');

                                s.nodes.forEach(function(n) {
                                    ungrabify(n);
                                    listenToGrab(n);
                                });

                                _frame(); // kick off
                            } else {
                                var done = false;
                                var _onNotDone = function _onNotDone() {};
                                var _onDone2 = function _onDone2() {
                                    return done = true;
                                };

                                while (!done) {
                                    multitick(s, _onNotDone, _onDone2);
                                }

                                s.eles.layoutPositions(this, s, function(node) {
                                    var pd = getNodePositionData(node, s);

                                    return { x: pd.x, y: pd.y };
                                });
                            }

                            l.postrun(s);

                            return this; // chaining
                        }
                    }, {
                        key: 'prerun',
                        value: function prerun() {}
                    }, {
                        key: 'postrun',
                        value: function postrun() {}
                    }, {
                        key: 'tick',
                        value: function tick() {}
                    }, {
                        key: 'stop',
                        value: function stop() {
                            this.state.running = false;

                            return this; // chaining
                        }
                    }, {
                        key: 'destroy',
                        value: function destroy() {
                            return this; // chaining
                        }
                    }]);

                    return Layout;
                }();

                module.exports = Layout;

                /***/
            }),
            /* 19 */
            /***/
            (function(module, exports, __webpack_require__) {

                "use strict";


                module.exports = function(bb, cy) {
                    if (bb == null) {
                        bb = { x1: 0, y1: 0, w: cy.width(), h: cy.height() };
                    } else {
                        // copy
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
                };

                /***/
            }),
            /* 20 */
            /***/
            (function(module, exports, __webpack_require__) {

                "use strict";


                var assign = __webpack_require__(2);

                var setInitialPositionState = function setInitialPositionState(node, state) {
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

                    scratch.locked = node.locked();
                };

                var getNodePositionData = function getNodePositionData(node, state) {
                    return node.scratch(state.name);
                };

                var refreshPositions = function refreshPositions(nodes, state) {
                    nodes.positions(function(node) {
                        var scratch = node.scratch(state.name);

                        return {
                            x: scratch.x,
                            y: scratch.y
                        };
                    });
                };

                module.exports = { setInitialPositionState: setInitialPositionState, getNodePositionData: getNodePositionData, refreshPositions: refreshPositions };

                /***/
            }),
            /* 21 */
            /***/
            (function(module, exports, __webpack_require__) {

                "use strict";


                var nop = function nop() {};

                var tick = function tick(state) {
                    var s = state;
                    var l = state.layout;

                    var tickIndicatesDone = l.tick(s);

                    if (s.firstUpdate) {
                        if (s.animateContinuously) {
                            // indicate the initial positions have been set
                            s.layout.emit('layoutready');
                        }
                        s.firstUpdate = false;
                    }

                    s.tickIndex++;

                    // || s.tickIndex >= s.maxIterations || duration >= s.maxSimulationTime -> This depends on # of nodes
                    return !s.infinite && tickIndicatesDone;
                };

                var multitick = function multitick(state) {
                    var onNotDone = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : nop;
                    var onDone = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : nop;

                    var done = false;
                    var s = state;

                    for (var i = 0; i < s.refresh; i++) {
                        done = !s.running || tick(s);

                        if (done) {
                            break;
                        }
                    }

                    if (!done) {
                        onNotDone();
                    } else {
                        onDone();
                    }
                };

                module.exports = { tick: tick, multitick: multitick };

                /***/
            })
            /******/
        ]);
});