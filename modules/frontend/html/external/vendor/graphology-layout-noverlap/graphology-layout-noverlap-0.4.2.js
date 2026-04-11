(function () {
  function isGraph(value) {
    return !!value && typeof value.forEachNode === "function" && typeof value.mergeNodeAttributes === "function" && typeof value.order === "number";
  }

  var DEFAULT_SETTINGS = {
    gridSize: 20,
    margin: 5,
    expansion: 1.1,
    ratio: 1.0,
    speed: 3,
  };

  var DEFAULT_MAX_ITERATIONS = 500;
  var PPN = 3;
  var NODE_X = 0;
  var NODE_Y = 1;
  var NODE_SIZE = 2;

  function validateSettings(settings) {
    if ((typeof settings.gridSize !== "number") || settings.gridSize <= 0) return { message: "the `gridSize` setting should be a positive number." };
    if ((typeof settings.margin !== "number") || settings.margin < 0) return { message: "the `margin` setting should be 0 or a positive number." };
    if ((typeof settings.expansion !== "number") || settings.expansion <= 0) return { message: "the `expansion` setting should be a positive number." };
    if ((typeof settings.ratio !== "number") || settings.ratio <= 0) return { message: "the `ratio` setting should be a positive number." };
    if ((typeof settings.speed !== "number") || settings.speed <= 0) return { message: "the `speed` setting should be a positive number." };
    return null;
  }

  function graphToByteArray(graph, reducer) {
    var matrix = new Float32Array(graph.order * PPN);
    var j = 0;
    graph.forEachNode(function (node, attr) {
      if (typeof reducer === "function") attr = reducer(node, attr);
      matrix[j] = Number(attr && attr.x) || 0;
      matrix[j + 1] = Number(attr && attr.y) || 0;
      matrix[j + 2] = Number(attr && attr.size) || 1;
      j += PPN;
    });
    return matrix;
  }

  function assignLayoutChanges(graph, NodeMatrix, reducer) {
    var i = 0;
    graph.forEachNode(function (node) {
      var pos = {
        x: NodeMatrix[i],
        y: NodeMatrix[i + 1],
      };
      if (typeof reducer === "function") pos = reducer(node, pos);
      graph.mergeNodeAttributes(node, pos);
      i += PPN;
    });
  }

  function collectLayoutChanges(graph, NodeMatrix, reducer) {
    var positions = {};
    var i = 0;
    graph.forEachNode(function (node) {
      var pos = {
        x: NodeMatrix[i],
        y: NodeMatrix[i + 1],
      };
      if (typeof reducer === "function") pos = reducer(node, pos);
      positions[node] = pos;
      i += PPN;
    });
    return positions;
  }

  function hashPair(a, b) {
    return a + "§" + b;
  }

  function jitter() {
    return 0.01 * (0.5 - Math.random());
  }

  function iterate(options, NodeMatrix) {
    var margin = options.margin;
    var ratio = options.ratio;
    var expansion = options.expansion;
    var gridSize = options.gridSize;
    var speed = options.speed;
    var i, j, x, y, l, size;
    var converged = true;
    var length = NodeMatrix.length;
    var order = (length / PPN) | 0;
    var deltaX = new Float32Array(order);
    var deltaY = new Float32Array(order);
    var xMin = Infinity;
    var yMin = Infinity;
    var xMax = -Infinity;
    var yMax = -Infinity;

    for (i = 0; i < length; i += PPN) {
      x = NodeMatrix[i + NODE_X];
      y = NodeMatrix[i + NODE_Y];
      size = NodeMatrix[i + NODE_SIZE] * ratio + margin;
      xMin = Math.min(xMin, x - size);
      xMax = Math.max(xMax, x + size);
      yMin = Math.min(yMin, y - size);
      yMax = Math.max(yMax, y + size);
    }

    var width = xMax - xMin;
    var height = yMax - yMin;
    var xCenter = (xMin + xMax) / 2;
    var yCenter = (yMin + yMax) / 2;
    xMin = xCenter - (expansion * width) / 2;
    xMax = xCenter + (expansion * width) / 2;
    yMin = yCenter - (expansion * height) / 2;
    yMax = yCenter + (expansion * height) / 2;

    var grid = new Array(gridSize * gridSize);
    for (var c = 0; c < grid.length; c++) grid[c] = [];

    var nxMin, nxMax, nyMin, nyMax, xMinBox, xMaxBox, yMinBox, yMaxBox, col, row;
    for (i = 0; i < length; i += PPN) {
      x = NodeMatrix[i + NODE_X];
      y = NodeMatrix[i + NODE_Y];
      size = NodeMatrix[i + NODE_SIZE] * ratio + margin;
      nxMin = x - size;
      nxMax = x + size;
      nyMin = y - size;
      nyMax = y + size;
      xMinBox = Math.floor((gridSize * (nxMin - xMin)) / (xMax - xMin));
      xMaxBox = Math.floor((gridSize * (nxMax - xMin)) / (xMax - xMin));
      yMinBox = Math.floor((gridSize * (nyMin - yMin)) / (yMax - yMin));
      yMaxBox = Math.floor((gridSize * (nyMax - yMin)) / (yMax - yMin));
      for (col = xMinBox; col <= xMaxBox; col++) {
        for (row = yMinBox; row <= yMaxBox; row++) {
          grid[col * gridSize + row].push(i);
        }
      }
    }

    var collisions = new Set();
    var n1, n2, x1, x2, y1, y2, s1, s2, h, xDist, yDist, dist, collision;
    for (c = 0; c < grid.length; c++) {
      var cell = grid[c];
      for (i = 0, l = cell.length; i < l; i++) {
        n1 = cell[i];
        x1 = NodeMatrix[n1 + NODE_X];
        y1 = NodeMatrix[n1 + NODE_Y];
        s1 = NodeMatrix[n1 + NODE_SIZE];
        for (j = i + 1; j < l; j++) {
          n2 = cell[j];
          h = hashPair(n1, n2);
          if (grid.length > 1 && collisions.has(h)) continue;
          if (grid.length > 1) collisions.add(h);
          x2 = NodeMatrix[n2 + NODE_X];
          y2 = NodeMatrix[n2 + NODE_Y];
          s2 = NodeMatrix[n2 + NODE_SIZE];
          xDist = x2 - x1;
          yDist = y2 - y1;
          dist = Math.sqrt((xDist * xDist) + (yDist * yDist));
          collision = dist < s1 * ratio + margin + (s2 * ratio + margin);
          if (collision) {
            converged = false;
            n2 = (n2 / PPN) | 0;
            if (dist > 0) {
              deltaX[n2] += (xDist / dist) * (1 + s1);
              deltaY[n2] += (yDist / dist) * (1 + s1);
            } else {
              deltaX[n2] += width * jitter();
              deltaY[n2] += height * jitter();
            }
          }
        }
      }
    }

    for (i = 0, j = 0; i < length; i += PPN, j++) {
      NodeMatrix[i + NODE_X] += deltaX[j] * 0.1 * speed;
      NodeMatrix[i + NODE_Y] += deltaY[j] * 0.1 * speed;
    }

    return { converged: converged };
  }

  function abstractSynchronousLayout(assign, graph, params) {
    if (!isGraph(graph)) throw new Error("graphology-layout-noverlap: invalid graphology instance.");
    params = typeof params === "number" ? { maxIterations: params } : (params || {});
    var maxIterations = params.maxIterations || DEFAULT_MAX_ITERATIONS;
    if (typeof maxIterations !== "number" || maxIterations <= 0) throw new Error("graphology-layout-noverlap: invalid number of maximum iterations.");
    var settings = Object.assign({}, DEFAULT_SETTINGS, params.settings || {});
    var validationError = validateSettings(settings);
    if (validationError) throw new Error("graphology-layout-noverlap: " + validationError.message);
    var matrix = graphToByteArray(graph, params.inputReducer);
    var converged = false;
    for (var i = 0; i < maxIterations && !converged; i++) converged = iterate(settings, matrix).converged;
    if (assign) {
      assignLayoutChanges(graph, matrix, params.outputReducer);
      return;
    }
    return collectLayoutChanges(graph, matrix, params.outputReducer);
  }

  var synchronousLayout = abstractSynchronousLayout.bind(null, false);
  synchronousLayout.assign = abstractSynchronousLayout.bind(null, true);

  if (typeof window !== "undefined") {
    window.GraphologyLayoutNoverlap = synchronousLayout;
  }
}());
