var cy
var nodemenu

var remoteLayout = {
  name: "remote",
  url: "/api/graph/layout",        // server endpoint (required)
}

var remoteLayoutv2 = {
  name: "remote",
  url: "/api/graph/layout",        // server endpoint (required)
  layout: "cosev2",
}

// Configure
var d3forcelayout = {
    name: "d3-force",
    animate: true, // whether to show the layout as it's running; special 'end' value makes the layout animate like a discrete layout
    maxIterations: 0, // max iterations before the layout will bail out
    maxSimulationTime: 10000, // max length in ms to run the layout
    ungrabifyWhileSimulating: false, // so you can't drag nodes during layout
    fixedAfterDragging: false, // fixed node after dragging
    fit: true, // on every layout reposition of nodes, fit the viewport
    padding: 30, // padding around the simulation
    boundingBox: undefined, // constrain layout bounds; { x1, y1, x2, y2 } or { x1, y1, w, h }
    /**d3-force API**/
    alpha: 0.4, // sets the current alpha to the specified number in the range [0,1]
    alphaMin: 0.001, // sets the minimum alpha to the specified number in the range [0,1]
    alphaDecay: 0.2,
    // alphaDecay: 1 - Math.pow(0.001, 1 / 200), // sets the alpha decay rate to the specified number in the range [0,1]
    alphaTarget: 0, // sets the current target alpha to the specified number in the range [0,1]
    velocityDecay: 0.1, // sets the velocity decay factor to the specified number in the range [0,1]
    collideRadius: 180, // sets the radius accessor to the specified number or function
    collideStrength: 0.7, // sets the force strength to the specified number in the range [0,1]
    collideIterations: 1, // sets the number of iterations per application to the specified number
    linkId: function id(d) {
        // return d.index;
        return d.id;
    }, // sets the node id accessor to the specified function
    // linkDistance: 10, // sets the distance accessor to the specified number or function
    linkStrength: function strength(link) {
        // return 1 / Math.min(count(link.source), count(link.target));
        return 8 / link._maxprob;
    }, // sets the strength accessor to the specified number or function
    linkIterations: 25, // sets the number of iterations per application to the specified number
    manyBodyStrength: -1500, // sets the strength accessor to the specified number or function
    manyBodyTheta: 0.5, // sets the Barnes–Hut approximation criterion to the specified number
    manyBodyDistanceMin: 10, // sets the minimum distance between nodes over which this force is considered
    manyBodyDistanceMax: Infinity, // sets the maximum distance between nodes over which this force is considered
    xStrength: 0.1, // sets the strength accessor to the specified number or function
    xX: 0, // sets the x-coordinate accessor to the specified number or function
    yStrength: 0.1, // sets the strength accessor to the specified number or function
    yY: 0, // sets the y-coordinate accessor to the specified number or function
    radialStrength: 0.05, // sets the strength accessor to the specified number or function
    radialRadius: 5, // sets the circle radius to the specified number or function
    radialX: 0, // sets the x-coordinate of the circle center to the specified number
    radialY: 0, // sets the y-coordinate of the circle center to the specified number
    // layout event callbacks
    // ready: function () { }, // on layoutready
    // stop: function () { }, // on layoutstop
    tick: function (progress) { }, // on every iteration
    // positioning options
    randomize: true, // use random node positions at beginning of layout
    // infinite layout options
    infinite: false // overrides all other options for a forces-all-the-time mode
}

// Our layout options
var coselayout = {
    name: 'cose',
    animate: true,
    idealEdgeLength: 100,
    nodeOverlap: 30,
    refresh: 20,
    fit: true,
    padding: 30,
    randomize: true,
    componentSpacing: 120,
    nodeRepulsion: 4400000,
    edgeElasticity: 100,
    nestingFactor: 5,
    gravity: 10,
    numIter: 2000,
    initialTemp: 600,
    coolingFactor: 0.95,
    minTemp: 1.0
}

var dagrelayout = {
    name: 'dagre',
    animate: true,
    // dagre algo options, uses default value on undefined
    nodeSep: undefined, // the separation between adjacent nodes in the same rank
    edgeSep: undefined, // the separation between adjacent edges in the same rank
    rankSep: 50, // the separation between each rank in the layout
    rankDir: 'LR', // 'TB' for top to bottom flow, 'LR' for left to right,
    ranker: 'longest-path', // Type of algorithm to assign a rank to each node in the input graph. Possible values: 'network-simplex', 'tight-tree' or 'longest-path'
    minLen: function (edge) { return 1; }, // number of ranks to keep between the source and target of the edge
    edgeWeight: function (edge) { return 1; }, // higher weight edges are generally made shorter and straighter than lower weight edges

    // general layout options
    fit: true, // whether to fit to viewport
    padding: 15, // fit padding
    spacingFactor: 2, // Applies a multiplicative factor (>0) to expand or compress the overall area that the nodes take up
    nodeDimensionsIncludeLabels: true, // whether labels should be included in determining the space used by a node
    animateFilter: function (node, i) { return true; }, // whether to animate specific nodes when animation is on; non-animated nodes immediately go to their final positions
    animationDuration: 500, // duration of animation in ms if enabled
    animationEasing: undefined, // easing of animation if enabled
    boundingBox: undefined, // constrain layout bounds; { x1, y1, x2, y2 } or { x1, y1, w, h }
    transform: function (node, pos) { return pos; }, // a function that applies a transform to the final node position
    ready: function () { }, // on layoutready
    stop: function () { } // on layoutstop
}

var fcoselayout = {
    name: 'fcose',
    // 'draft', 'default' or 'proof' 
    // - "draft" only applies spectral layout 
    // - "default" improves the quality with incremental layout (fast cooling rate)
    // - "proof" improves the quality with incremental layout (slow cooling rate) 
    quality: "default",
    // Use random node positions at beginning of layout
    // if this is set to false, then quality option must be "proof"
    randomize: true,
    // Whether or not to animate the layout
    animate: false,
    // Duration of animation in ms, if enabled
    animationDuration: 5000,
    // Easing of animation, if enabled
    animationEasing: undefined,
    // Fit the viewport to the repositioned nodes
    fit: true,
    // Padding around layout
    padding: 30,
    // Whether to include labels in node dimensions. Valid in "proof" quality
    nodeDimensionsIncludeLabels: true,
    // Whether or not simple nodes (non-compound nodes) are of uniform dimensions
    uniformNodeDimensions: true,
    // Whether to pack disconnected components - valid only if randomize: true
    packComponents: true,

    /* spectral layout options */

    // False for random, true for greedy sampling
    samplingType: false,
    // Sample size to construct distance matrix
    sampleSize: 100,
    // Separation amount between nodes
    // nodeSeparation: 125,
    nodeSeparation: 125,
    // Power iteration tolerance
    piTol: 0.0000001,

    /* incremental layout options */

    // Node repulsion (non overlapping) multiplier
    nodeRepulsion: 4500,
    // Ideal edge (non nested) length
    idealEdgeLength: 100,
    // Divisor to compute edge forces
    edgeElasticity: 0.45,
    // Nesting factor (multiplier) to compute ideal edge length for nested edges
    nestingFactor: 0.5,
    // Maximum number of iterations to perform
    numIter: 2500,
    // For enabling tiling
    tile: true,
    // Represents the amount of the vertical space to put between the zero degree members during the tiling operation(can also be a function)
    tilingPaddingVertical: 10,
    // Represents the amount of the horizontal space to put between the zero degree members during the tiling operation(can also be a function)
    tilingPaddingHorizontal: 10,
    // Gravity force (constant)
    gravity: 0.25,
    // Gravity range (constant) for compounds
    gravityRangeCompound: 1.5,
    // Gravity force (constant) for compounds
    gravityCompound: 1.0,
    // Gravity range (constant)
    gravityRange: 3.8,
    // Initial cooling factor for incremental layout  
    initialEnergyOnIncremental: 0.3,

    /* layout event callbacks */
    ready: () => { }, // on layoutready
    stop: () => { } // on layoutstop
}

var ciselayout = {
    name: 'cise',

    // ClusterInfo can be a 2D array contaning node id's or a function that returns cluster ids. 
    // For the 2D array option, the index of the array indicates the cluster ID for all elements in 
    // the collection at that index. Unclustered nodes must NOT be present in this array of clusters.
    // 
    // For the function, it would be given a Cytoscape node and it is expected to return a cluster id  
    // corresponding to that node. Returning negative numbers, null or undefined is fine for unclustered
    // nodes.  
    // e.g
    // Array:                                     OR          function(node){
    //  [ ['n1','n2','n3'],                                       ...
    //    ['n5','n6']                                         }
    //    ['n7', 'n8', 'n9', 'n10'] ]                         
    // clusters: clusterInfo,
    animate: true,
    refresh: 10,
    animationDuration: undefined,
    animationEasing: undefined,
    fit: true,
    padding: 30,
    nodeSeparation: 12.5,
    idealInterClusterEdgeLengthCoefficient: 1.4,
    allowNodesInsideCircle: false,
    maxRatioOfNodesInsideCircle: 0.1,
    springCoeff: 0.45,
    nodeRepulsion: 4500,
    gravity: 0.25,
    gravityRange: 3.8,
    // Layout event callbacks; equivalent to `layout.one('layoutready', callback)` for example
    ready: function () { }, // on layoutready
    stop: function () { }, // on layoutstop
}

var cosebilkentlayout = {
    name: 'cose-bilkent',
    // Called on `layoutready`
    ready: function () {
    },
    // Called on `layoutstop`
    stop: function () {
    },
    // 'draft', 'default' or 'proof" 
    // - 'draft' fast cooling rate 
    // - 'default' moderate cooling rate 
    // - "proof" slow cooling rate
    quality: 'default',
    // Whether to include labels in node dimensions. Useful for avoiding label overlap
    nodeDimensionsIncludeLabels: true,
    // number of ticks per frame; higher is faster but more jerky
    refresh: 10,
    // Whether to fit the network view after when done
    fit: true,
    // Padding on fit
    padding: 10,
    // Whether to enable incremental mode
    randomize: true,
    // Node repulsion (non overlapping) multiplier
    nodeRepulsion: 4500,
    // Ideal (intra-graph) edge length
    idealEdgeLength: 50,
    // Divisor to compute edge forces
    edgeElasticity: 0.45,
    // Nesting factor (multiplier) to compute ideal edge length for inter-graph edges
    nestingFactor: 2.0,
    // Gravity force (constant)
    gravity: 0.15,
    // Maximum number of iterations to perform
    numIter: 2500,
    // Whether to tile disconnected nodes
    tile: true,
    // Type of layout animation. The option set is {'during', 'end', false}
    animate: 'end',
    // Duration for animate:end
    animationDuration: 500,
    // Amount of vertical space to put between degree zero nodes during tiling (can also be a function)
    tilingPaddingVertical: 50,
    // Amount of horizontal space to put between degree zero nodes during tiling (can also be a function)
    tilingPaddingHorizontal: 50,
    // Gravity range (constant) for compounds
    gravityRangeCompound: 1.5,
    // Gravity force (constant) for compounds
    gravityCompound: 1.0,
    // Gravity range (constant)
    gravityRange: 3.8,
    // Initial cooling factor for incremental layout
    initialEnergyOnIncremental: 0.5
};

var randomlayout = {
    name: 'random'
}

var fixedlayout = {
    name: 'preset'
}

var cytostyle = [
  {
    selector: "node, edge",
    style: {
      "min-zoomed-font-size": 12,
      "font-family": "oswald",
    },
  },
  {
    selector: "node",
    style: {
      label: function (ele) {
        return renderlabel(ele.data("label"));
      },
      color: function (ele) {
        return translateAutoTheme(getpref("theme", "auto")) == "dark" ? "white" : "black";
      },
      "background-width": "80%",
      "background-height": "80%",
    },
  },
  {
    selector: "node.target",
    style: {
      "border-color": function (ele) {
        return translateAutoTheme(getpref("theme", "auto")) == "dark" ? "white" : "black";
      },
      "border-width": 3,
    },
  },
  {
    selector: "node.source",
    style: {
      "border-color": "green",
      "border-width": 3,
    },
  },
  {
    selector: 'node[type="Group"]',
    style: {
      shape: "cut-rectangle",
      "background-image": "icons/people-fill.svg",
      "background-color": "orange",
    },
  },
  {
    selector: 'node[type="Person"]',
    style: {
      "background-image": "icons/person-fill.svg",
      "background-color": "green",
    },
  },
  {
    selector: "node[account_inactive]",
    style: {
      "background-image": "icons/no_accounts_black_48dp.svg",
    },
  },
  {
    selector: 'node[type="ms-DS-Managed-Service-Account"]',
    style: {
      "background-image": "icons/manage_accounts_black_24dp.svg",
      "background-color": "lightgreen",
    },
  },
  {
    selector: 'node[type="ms-DS-Group-Managed-ServiceAccount"]',
    style: {
      "background-image": "icons/manage_accounts_black_24dp.svg",
      "background-color": "lightgreen",
    },
  },
  {
    selector: 'node[type="Foreign-Security-Principal"]',
    style: {
      "background-image": "icons/badge_black_24dp.svg",
      "background-color": "lightgreen",
    },
  },
  {
    selector: 'node[type="Service"]',
    style: {
      shape: "diamond",
      "background-image": "icons/service.svg",
      "background-color": "lightgreen",
    },
  },
  {
    selector: 'node[type="CallableService"]',
    style: {
      "background-image": "icons/service.svg",
      "background-color": "lightgreen",
    },
  },
  {
    selector: 'node[type="Directory"]',
    style: {
      shape: "diamond",
      "background-image": "icons/source_black_24dp.svg",
      "background-color": "lightblue",
    },
  },
  {
    selector: 'node[type="File"]',
    style: {
      shape: "diamond",
      "background-image": "icons/article_black_24dp.svg",
      "background-color": "lightblue",
    },
  },
  {
    selector: 'node[type="Executable"]',
    style: {
      shape: "rectangle",
      "background-image": "icons/binary-code.svg",
      "background-color": "lightgreen",
    },
  },

  {
    selector: 'node[type="Group-Policy-Container"]',
    style: {
      shape: "rectangle",
      "background-image": "icons/gpo.svg",
      "background-color": "purple",
    },
  },
  {
    selector: 'node[type="Organizational-Unit"]',
    style: {
      shape: "rectangle",
      "background-image": "icons/source_black_24dp.svg",
      "background-color": "lightgray",
    },
  },
  {
    selector: 'node[type="Container"]',
    style: {
      shape: "rectangle",
      "background-image": "icons/folder_black_24dp.svg",
      "background-color": "lightgray",
    },
  },
  {
    selector: 'node[type="PKI-Certificate-Template"]',
    style: {
      shape: "rectangle",
      "background-image": "icons/certificate.svg",
      "background-color": "pink",
    },
  },
  {
    selector: 'node[type="DNS-Node"]',
    style: {
      shape: "rectangle",
      "background-image": "icons/dns.svg",
    },
  },
  {
    selector: 'node[type="Computer"]',
    style: {
      shape: "round-octagon",
      "background-image": "icons/tv-fill.svg",
      "background-color": "lightgreen",
    },
  },
  {
    selector: 'node[type="Machine"]',
    style: {
      shape: "round-octagon",
      "background-image": "icons/tv-fill.svg",
      "background-color": "teal",
    },
  },
  {
    selector: "node[?_canexpand]",
    style: {
      "font-style": "italic",
      color: "yellow",
      "background-color": "yellow",
    },
  },
  {
    selector: 'node[reference="start"]',
    style: {
      "border-color": "red",
      "border-width": 3,
    },
  },
  {
    selector: 'node[reference="end"]',
    style: {
      "border-color": "blue",
      "border-width": 3,
    },
  },
  {
    selector: "edge",
    style: {
      // "label": function (ele) { return edgelabel(ele); },
      "text-wrap": "wrap",
      // "text-rotation": "autorotate",
      "text-justification": "center",
      color: function (ele) {
        return translateAutoTheme(getpref("theme", "auto")) == "dark" ? "white" : "black";
      },
      "curve-style": "straight",
      "target-arrow-shape": "triangle",
    },
  },
  {
    selector: "edge[_maxprob<=90]",
    style: {
      "line-style": "dashed",
      "line-dash-pattern": [9, 1],
    },
  },
  {
    selector: "edge[_maxprob<=80]",
    style: {
      "line-style": "dashed",
      "line-dash-pattern": [8, 2],
    },
  },
  {
    selector: "edge[_maxprob<=70]",
    style: {
      "line-style": "dashed",
      "line-dash-pattern": [7, 3],
    },
  },
  {
    selector: "edge[_maxprob<=60]",
    style: {
      "line-style": "dashed",
      "line-dash-pattern": [6, 4],
    },
  },
  {
    selector: "edge[_maxprob<=50]",
    style: {
      "line-style": "dashed",
      "line-dash-pattern": [5, 5],
    },
  },
  {
    selector: "edge[_maxprob<=40]",
    style: {
      "line-style": "dashed",
      "line-dash-pattern": [4, 6],
    },
  },
  {
    selector: "edge[_maxprob<=30]",
    style: {
      "line-style": "dashed",
      "line-dash-pattern": [3, 7],
    },
  },
  {
    selector: "edge[_maxprob<=20]",
    style: {
      "line-style": "dashed",
      "line-dash-pattern": [2, 8],
    },
  },
  {
    selector: "edge[_maxprob<=10]",
    style: {
      "line-style": "dashed",
      "line-dash-pattern": [1, 9],
    },
  },
  {
    selector: "node:selected",
    style: {
      "background-color": function (ele) {
        return translateAutoTheme(getpref("theme", "auto")) == "dark" ? "white" : "grey";
      },
    },
  },
  {
    selector: "edge:selected",
    style: {
      "target-arrow-color": function (ele) {
        return translateAutoTheme(getpref("theme", "auto")) == "dark"
          ? "white"
          : "black";
      },
      "line-color": function (ele) {
        return translateAutoTheme(getpref("theme", "auto")) == "dark" ? "white" : "black";
      },
      width: 8,
    },
  },
];

function getGraphlayout(choice) {
    var layouttemplate = fcoselayout
    switch (choice) {
      case "cose":
        layouttemplate = coselayout;
        break;
      case "cosebilkent":
        layouttemplate = cosebilkentlayout;
        break;
      case "dagre":
        layouttemplate = dagrelayout;
        break;
      case "fcose":
        layouttemplate = fcoselayout;
        break;
      case "d3force":
        layouttemplate = d3forcelayout;
        break;
      case "random":
        layouttemplate = randomlayout;
        break;
      case "fixed":
        layouttemplate = fixedlayout;
        break;
      case "cise":
        layouttemplate = ciselayout;
        break;
      case "remote":
        layouttemplate = remoteLayout;
        break;
      case "remotev2":
        layouttemplate = remoteLayoutv2;
        break;
      default:
        // toast error
        console.warn("Unknown layout choice:", choice);
        break;
    }

    var layout = cy.layout(layouttemplate)

    layout.on("layoutstart", function (event) {
        busystatus("Running graph layout")
    })
    layout.on("layoutstop", function (event) {
        const statusEl = document.getElementById("status");
        if (statusEl) {
          statusEl.style.display = "none";
        }
    })
    return layout
}

function byIdValue(id, def) {
  const el = document.getElementById(id);
  if (!el) {
    return def;
  }
  return el.value;
}

function byIdChecked(id) {
  const el = document.getElementById(id);
  return !!(el && el.checked);
}

function serializeFormsToObject(selectors) {
  const result = {};
  selectors.split(",").forEach((selector) => {
    const form = document.querySelector(selector.trim());
    if (!(form instanceof HTMLFormElement)) {
      return;
    }
    new FormData(form).forEach((value, key) => {
      result[key] = value;
    });
  });
  return result;
}

async function fetchJSONOrThrow(url, options) {
  const res = await fetch(url, options);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || res.statusText);
  }
  return await res.json();
}

function renderlabel(label) {
    switch (byIdValue("nodelabels", "normal")) {
        case "normal":
            return label;
        case "off":
            return "";
        case "randomize":
            return anonymizer.anonymize(label);
        case "checksum":
            return hashFnv32a(label, true, undefined);
    }
    return "label error";
}

function edgelabel(ele) {
    switch (byIdValue("edgelabels", "normal")) {
        case "normal":
            return ele.data("methods").join('|');
        case "off":
            return "";
        case "randomize":
            return anonymizer.anonymize(data("methods").join('|'));
        case "checksum":
            return hashFnv32a(data("methods").join('|'), true, undefined);
    }
    return "edge error";
}

var anonymizer = new DataAnonymizer();

function hashFnv32a(str, asString, seed) {
    /*jshint bitwise:false */
    var i, l,
        hval = (seed === undefined) ? 0x811c9dc5 : seed;

    for (i = 0, l = str.length; i < l; i++) {
        hval ^= str.charCodeAt(i);
        hval += (hval << 1) + (hval << 4) + (hval << 7) + (hval << 8) + (hval << 24);
    }
    if (asString) {
        // Convert to 8 digit hex string
        return ("0000000" + (hval >>> 0).toString(16)).substr(-8);
    }
    return hval >>> 0;
}

function probabilityToRGB(value) {
  value = Math.max(0, Math.min(100, value)); // Clamp between 0-100
  let r = value < 50 ? 255 : Math.round(255 - (value - 50) * 5.1);
  let g = value > 50 ? 255 : Math.round(value * 5.1);
  return `rgb(${r},${g},0)`;
}


function renderedges(methodmap) {
  maxprob = -1;

    edgeoutput = Object.entries(methodmap)
      .sort()
      .map(function ([name, prob]) {
        if (prob > maxprob) {
          maxprob = prob;
        }
        return '<span class="badge text-dark" style="background-color: '+probabilityToRGB(prob)+'">' + name + " (" + prob + "%)</span>";
      })
      .join("");

    var s = '<span class="badge text-dark" style="background-color: '+probabilityToRGB(maxprob)+
    '">Edge ' + maxprob + '%</span>' + edgeoutput;

    return s
}

icons = new Map([
  [
    "Person",
    "<img src='icons/person-fill.svg' width='24' height='24'>",
  ],
  [
    "Group",
    "<img src='icons/people-fill.svg' width='24' height='24'>",
  ],
  [
    "Computer",
    "<img src='icons/computer-fill.svg' width='24' height='24'>",
  ],
  [
    "Machine",
    "<img src='icons/tv-fill.svg' width='24' height='24'>",
  ],
  [
    "ms-DS-Managed-Service-Account",
    "<img src='icons/manage_accounts_black_24dp.svg' width='24' height='24'>",
  ],
  [
    "ms-DS-Group-Managed-Service-Account",
    "<img src='icons/manage_accounts_black_24dp.svg' width='24' height='24'>",
  ],
  [
    "Foreign-Security-Principal",
    "<img src='icons/badge_black_24dp.svg' width='24' height='24'>",
  ],
  [
    "Service",
    "<img src='icons/service.svg' width='24' height='24'>",
  ],
  [
    "Directory",
    "<img src='icons/source_black_24dp.svg' width='24' height='24'>",
  ],
  [
    "File",
    "<img src='icons/article_black_24dp.svg' width='24' height='24'>",
  ],
  [
    "Executable",
    "<img src='icons/binary-code.svg' width='24' height='24'>",
  ],
  [
    "Group-Policy-Container",
    "<img src='icons/gpo.svg' width='24' height='24'>",
  ],
  [
    "Organizational-Unit",
    "<img src='icons/source_black_24dp.svg' width='24' height='24'>",
  ],
  [
    "Container",
    "<img src='icons/folder_black_24dp.svg' width='24' height='24'>",
  ],
  [
    "MS-PKI-Certificate-Template",
    "<img src='icons/certificate.svg' width='24' height='24'>",
  ],
  [
    "DNS-Node",
    "<img src='icons/dns.svg' width='24' height='24'>",
  ],
]);

function rendericon(type) {
    result = icons.get(type);
    if (!result) {
      result="<img src='icons/unknown.svg' width='24' height='24'>";
    }
    return result;
}

function rendernode(ele) {
    s = rendericon(ele.attributes['type'][0]);
    s += " " + renderlabel(ele.label);
    return s
}

// Object with values from AD and possibly other places
function rendercard(data) {
    var result = "<div>"
    if (data.attributes["type"]) {
        
    }
    for (var attr in data.attributes) {
        result += "<tr><td>" + attr + "</td><td>"
        attrvalues = data.attributes[attr]
        for (var i in attrvalues) {
            if (byIdValue("graphlabels", "normal") == "randomize") {
                result += anonymizer.anonymize(attrvalues[i]) + "</br>";
            } else {
                result += attrvalues[i] + "</br>";
            }
        }
        result += "</td></tr>"
    }
    result += "</table>"
    return result
}

// Object with values from AD and possibly other places
function renderdetails(data) {
    if (window.DetailsLayouts && typeof window.DetailsLayouts.renderDetails === "function") {
        return window.DetailsLayouts.renderDetails(data);
    }
    var result = "<table>"
    for (var attr in data.attributes) {
        result += "<tr><td>" + attr + "</td><td>"
        attrvalues = data.attributes[attr]
        for (var i in attrvalues) {
            if (byIdValue("graphlabels", "normal") == "randomize") {
                result += anonymizer.anonymize(attrvalues[i]) + "</br>";
            } else {
                result += attrvalues[i] + "</br>";
            }
        }
        result += "</td></tr>"
    }
    result += "</table>"
    return result
}

function edgeprobability(ele) {
    if (ele.data("_maxprob")) {
        return (ele.data("_maxprob"))
    }
    return -1
}

function initgraph(data) {
    cy = window.cy = cytoscape({
      container: document.getElementById("cy"),
      wheelSensitivity: 0.2,

      renderer: {
        name: "canvas", // still uses the canvas renderer
        webgl: false, // turns on WebGL mode, beta, node selection etc does not work :-(
        showFps: false,
      },
    });

    cy.style(cytostyle);

    cy.ready(function () {
        busystatus("Rendering graph");
        nodemenu = cy.contextMenus({
            // Customize event to bring up the context menu
            // Possible options https://js.cytoscape.org/#events/user-input-device-events
            evtType: 'cxttapstart',
            // List of initial menu items
            // A menu item must have either onClickFunction or submenu or both
            menuItems: [{
                id: 'target', // ID of menu item
                content: 'Set as route target', // Display content of menu item
                tooltipText: 'Node is set as target of routing operation', // Tooltip text for menu item
                // image: {src : "remove.svg", width : 12, height : 12, x : 6, y : 4}, // menu icon
                // Filters the elements to have this menu item on cxttap
                // If the selector is not truthy no elements will have this menu item on cxttap
                selector: 'node',
                onClickFunction: function (event) { // The function to be executed on click
                    // console.log("Toggling target: ", ele.id()); // `ele` holds the reference to the active element
                    cy.$("node.target").toggleClass("target")
                    event.target.toggleClass("target")
                    nodemenu.enableMenuItem("source")
                },
                disabled: false, // Whether the item will be created as disabled
                show: true, // Whether the item will be shown or not
                hasTrailingDivider: false, // Whether the item will have a trailing divider
                coreAsWell: false // Whether core instance have this item on cxttap
            },
            {
                id: 'source',
                content: 'Plot route to target',
                tooltipText: 'Find shortest route to target selected previously',
                selector: 'node',
                onClickFunction: function (event) {
                    findroute(event.target);
                },
                hasTrailingDivider: true, // Whether the item will have a trailing divider
            },
            {
                id: 'expand', // ID of menu item
                content: 'Expand node', // Display content of menu item
                tooltipText: 'Load missing edges and nodes', // Tooltip text for menu item
                // image: {src : "remove.svg", width : 12, height : 12, x : 6, y : 4}, // menu icon
                // Filters the elements to have this menu item on cxttap
                // If the selector is not truthy no elements will have this menu item on cxttap
                selector: 'node[_canexpand>0]',
                onClickFunction: function (event) { // The function to be executed on click
                    const expanddata = serializeFormsToObject("#ldapqueryform, #optionsform");
                    expanddata.expanddn = event.target.attr("distinguishedName");

                    fetchJSONOrThrow("cytograph.json", {
                      method: "POST",
                      headers: { "Content-Type": "application/json; charset=utf-8" },
                      body: JSON.stringify(expanddata),
                    })
                      .then(function (data) {
                        neweles = cy.add(data.elements)
                        replaceele = neweles.getElementById(event.target.attr("id"))
                        cy.elements().merge(neweles) // merge adds what is missing
                        cy.elements().add(replaceele) // then we forcibly update the old object

                        event.target.removeData('_canexpand')

                        // Apply layout again
                        getGraphlayout(byIdValue("graphlayout", "fcose")).run()
                      })
                      .catch(function (err) {
                        const statusEl = document.getElementById("status");
                        if (statusEl) {
                          statusEl.innerHTML = "Problem loading graph:<br>" + err.message;
                          statusEl.style.display = "";
                        }
                      });


                },
                hasTrailingDivider: true, // Whether the item will have a trailing divider
            },
            {
                id: 'whatcanipwn',
                content: 'What can this node reach?',
                tooltipText: 'Does reverse search on this node (clears graph)',
                selector: 'node',
                onClickFunction: function (evt) {
                    fetchJSONOrThrow("api/details/id/" + evt.target.id().substring(1))
                        .then(function (data) {
                            if (data.attributes["distinguishedName"]) {
                                set_query(
                                  "start:(distinguishedname=" +
                                    data.attributes["distinguishedName"] +
                                    ")-[]{1,3}->end:()"
                                );
                            } else if (data.attributes["objectSid"]) {
                                set_query(
                                  "start:(objectSid=" +
                                    data.attributes["objectSid"] +
                                    ")-[]{1,3}->end:()"
                                );
                            } else if (data.attributes["objectGuid"]) {
                                set_query(
                                  "start:(objectGuid=" +
                                    data.attributes["objectGuid"] +
                                    ")-[]{1,3}->end:()"
                                );
                            } else {
                                set_query(
                                  "start:(_id=" +
                                    evt.target.id().substring(1) +
                                    ")-[]{1,3}->end:()"
                                );
                            }

                            aqlanalyze();
                        })
                        .catch(function () {
                            toast("Node not found in backend", "There was a problem doing node lookup in the backend.");
                        });
                }
            },
            {
                id: 'whocanpwn',
                content: 'Who can reach this node?',
                tooltipText: 'Does incoming search for this node (clears graph)',
                selector: 'node',
                onClickFunction: function (evt) {
                    fetchJSONOrThrow("api/details/id/" + evt.target.id().substring(1))
                        .then(function (data) {
                            if (data.attributes["distinguishedName"]) {
                                set_query(
                                  "start:(distinguishedname=" +
                                    data.attributes["distinguishedName"] +
                                    ")<-[]{1,3}-end:()"
                                );
                            } else if (data.attributes["objectSid"]) {
                                set_query(
                                  "start:(objectSid=" +
                                    data.attributes["objectSid"] +
                                    ")<-[]{1,3}-end:()"
                                );
                            } else if (data.attributes["objectGuid"]) {
                                set_query(
                                  "start:(objectGuid=" +
                                    data.attributes["objectGuid"] +
                                    ")<-[]{1,3}-end:()"
                                );
                            } else {
                                set_query(
                                  "start:(_id=" +
                                    evt.target.id().substring(1) +
                                    ")<-[]{1,3}-end:()"
                                );
                            }

                            aqlanalyze();
                        })
                        .catch(function () {
                            toast("Node not found in backend", "There was a problem doing node lookup in the backend.");
                        });
                },
            }
            ],
            // css classes that menu items will have
            menuItemClasses: [
                // add class names to this list
                "bg-primary"
            ],
            // css classes that context menu will have
            contextMenuClasses: [
                // add class names to this list
            ],
            // Indicates that the menu item has a submenu. If not provided default one will be used
            submenuIndicator: { src: 'submenu-indicator-default.svg', width: 12, height: 12 }
        });

        cy.on('click', 'node', function (evt) {
            // console.log('clicked node ' + this.id());
            // console.log(evt);
            if (evt.originalEvent.altKey || evt.originalEvent.ctrlKey || evt.originalEvent.shiftKey) {
              return;
            }

            id = evt.target.id().substring(1);
            fetchJSONOrThrow("api/details/id/" + id)
                .then(function (data) {
                    windowname = "details_" + id;
                    if (getpref("ui.open.details.in.same.window", true)) {
                      windowname = "node_details";
                    }
                    new_window(windowname, rendernode(data), renderdetails(data));
                })
                .catch(function (err) {
                    new_window("details", "Node details", rendernode(evt.target) + "<div>Couldn't load details:" + err.message + "</div>");
                });
        });

        cy.on('click', 'edge', function (evt) {
            // console.log('clicked edge ' + this.id());
              fetchJSONOrThrow("api/edges/id/" + evt.target.source().id().substring(1) +","+ evt.target.target().id().substring(1))
                .then(function (data) {
                  windowname = "edge_" + evt.target.source().id() + "_to_" + evt.target.target().id();
                  if (getpref("ui.open.details.in.same.window", true)) {
                    windowname = "edge_details";
                  }
                  new_window(
                    windowname,
                    "Edge from "+renderlabel(data[0].from.label) + " to "+renderlabel(data[0].to.label),
                    rendernode(data[0].from) + "<br>" + 
                    renderedges(data[0].edges) + "<br>" + 
                    rendernode(data[0].to)
                  );
                })
                .catch(function (err) {
                    toast("Error loading edge details" + err.message);
                    new_window("details", "Edge details", "<div>Couldn't load details:" + err.message + "</div>");
                });
        })

        cy.on('mouseover', 'edge', function (event) {
            if (byIdChecked("showedgelabels")) {
                this.css({
                    content: this.data("methods").sort().join('\n'),
                });
            }
        });

        cy.on('mouseout', 'edge', function (event) {
            this.css({
                content: ''
            });
        });

        // cy.on('click', function (evt) {
        //     var evtTarget = evt.target;
        //     if (evtTarget === cy) {
        //         $("#details").hide();
        //         $("#route").hide();
        //     }
        // });

    });

    // Distribute all objects to predictable locations
/*    data.forEach(function (ele) {
        if (ele.group == "nodes") {
            // set x to node id modulus 1024
            x = ele.data.id.substr(1) % 1024;
            y = Math.floor(ele.data.id.substr(1) / 1024);
            ele.position = {
                x: x,
                y: y
            }
        }
    });
*/

    // Load data into Cytoscape
    cy.add(data);

    cy.expandCollapse({
      layoutBy: null, // to rearrange after expand/collapse. It's just layout options or whole layout function. Choose your side!
      // recommended usage: use cose-bilkent layout with randomize: false to preserve mental map upon expand/collapse
      fisheye: true, // whether to perform fisheye view after expand/collapse you can specify a function too
      animate: true, // whether to animate on drawing changes you can specify a function too
      animationDuration: 1000, // when animate is true, the duration in milliseconds of the animation
      ready: function () {
      }, // callback when expand/collapse initialized
      undoable: true, // and if undoRedoExtension exists,

      cueEnabled: true, // Whether cues are enabled
      expandCollapseCuePosition: "top-left", // default cue position is top left you can specify a function per node too
      expandCollapseCueSize: 12, // size of expand-collapse cue
      expandCollapseCueLineSize: 8, // size of lines used for drawing plus-minus icons
      expandCueImage: undefined, // image of expand icon if undefined draw regular expand cue
      collapseCueImage: undefined, // image of collapse icon if undefined draw regular collapse cue
      expandCollapseCueSensitivity: 1, // sensitivity of expand-collapse cues
      edgeTypeInfo: "edgeType", // the name of the field that has the edge type, retrieved from edge.data(), can be a function, if reading the field returns undefined the collapsed edge type will be "unknown"
      groupEdgesOfSameTypeOnCollapse: false, // if true, the edges to be collapsed will be grouped according to their types, and the created collapsed edges will have same type as their group. if false the collapased edge will have "unknown" type.
      allowNestedEdgeCollapse: true, // when you want to collapse a compound edge (edge which contains other edges) and normal edge, should it collapse without expanding the compound first
      zIndex: 999, // z-index value of the canvas in which cue ımages are drawn
    });

    applyEdgeStyles(cy);
    applyNodeStyles(cy);

    getGraphlayout(byIdValue("graphlayout", "fcose")).run()
}

function getEdgeColor(ele) {
        color =
          translateAutoTheme(getpref("theme", "auto")) == "dark"
            ? "white"
            : "black";
        if (ele.data("methods").includes("MemberOfGroup")) {
          color = "orange";
        } else if (ele.data("methods").includes("MemberOfGroupIndirect")) {
          color = "darkorange";
        } else if (ele.data("methods").includes("ForeignIdentity")) {
          color = "lightgreen";
        } else if (ele.data("methods").includes("ResetPassword")) {
          color = "red";
        } else if (ele.data("methods").includes("AddMember")) {
          color = "yellow";
        } else if (ele.data("methods").includes("TakeOwnership")) {
          color = "lightblue";
        } else if (ele.data("methods").includes("WriteDACL")) {
          color = "lightblue";
        } else if (ele.data("methods").includes("Owns")) {
          color = "blue";
        }
        return color;
}

function applyEdgeStyles(cy) {
    cy.edges().each(function (ele) {
      color = getEdgeColor(ele);
      ele.style('target-arrow-color', color);
      ele.style('line-color', color);
      const flow = Number(ele.data("flow"));
      const edgeWidth = Number.isFinite(flow) && flow > 0 ? 1 + Math.log(flow) : 1;
      ele.style('width', edgeWidth);
    });
};

function applyNodeStyles(cy, nodestyleOverride) {
    const nodestyle = nodestyleOverride || getpref("graph.nodesize", "incoming");

    if (nodestyle == "equal") {
        cy.nodes().each(function (ele) {
            ele.style("width", 40);
            ele.style("height", 40);
        });
    } else {
        let scale;
        switch (nodestyle) {
            case "incoming":
                scale = cy.nodes().maxIndegree(false);
                break;
            case "outgoing":
                scale = cy.nodes().maxOutdegree(false);
                break;
            default:
                scale = cy.nodes().maxIndegree(false);
                break;
        }

        // Guard for empty/sparse graphs where scale can be 0/undefined.
        if (!Number.isFinite(scale) || scale <= 0) {
          cy.nodes().each(function (ele) {
            ele.style("width", 40);
            ele.style("height", 40);
          });
          return;
        }

        // Apply node styles
        cy.nodes().each(function (ele) {
            let size;
            switch (nodestyle) {
                case "incoming":
                    size = ele.indegree();
                    break;
                case "outgoing":
                    size = ele.outdegree();
                    break;
                default:
                    size = ele.indegree();
                    break;
            }

            const numericSize = Number(size);
            const normalized = Number.isFinite(numericSize)
              ? normalize(numericSize, 0, scale, 40, 100)
              : 40;
            const safeSize = Number.isFinite(normalized) ? normalized : 40;
            ele.style("width", safeSize);
            ele.style("height", safeSize);
        });
    }
}

function findroute(source) {
    var target = cy.$("node.target")
    if (target.length == 0) {
        toast("No target node found", "error")
        return
    }


    cy.elements().unselect() // unselect everything

    var dfs = cy.elements().aStar({
        root: source,
        goal: target,
        weight: function (ele) {
            maxprobability = edgeprobability(ele)
            if (maxprobability != -1) {
                return 101 - maxprobability // higher probability equals lower priority number
            }
            return 0
        },
        directed: true
    })
    if (dfs.path) {
      dfs.path.select();
      pathprobability = 1.0;
      dfs.path.forEach(function (ele) {
        if (ele.isEdge()) {
          pathprobability = pathprobability * (edgeprobability(ele) / 100);
        }
      });
      pathprobability = pathprobability * 100; // Back to percentages

      // empty array
      nodes = [];
      edges = [];
      
      // Show path information
      routecontents = "";
      dfs.path.forEach(function (ele) {
        if (ele.isNode()) {
          if (routecontents.length > 0) {
            routecontents += ",";
          }
          routecontents += ele.id().substring(1);
        }
      });

      output = "";
      fetchJSONOrThrow("/api/edges/id/" + routecontents)
        .then(function (data) {
          output += "";
          for (var i = 0; i < data.length; i++) {
            // render node
            output += rendericon(data[i].from.attributes["type"]) + renderlabel(data[i].from.label) + "<br>";

            // render edge
            output += renderedges(data[i].edges) + "<br>";

            if (i == data.length-1) {
              output += rendericon(data[i].to.attributes["type"]) + renderlabel(data[i].to.label);
            }
          }

          new_window(
            "route_" + source.id() + "_" + target.id(),
            `Route from ` +
              renderlabel(data[0].from.label) +
              ` to ` +
              renderlabel(data[data.length-1].to.label) +
              ` - ` +
              pathprobability.toFixed(2) +
              `% probability`,
            output
          );
        })
        .catch(function (err) {
          toast("Error loading route details", err.message, "error");
        });

    } else {
        toast("No route found", "If your analysis was for multiple target nodes, there is no guarantee that all results can reach all targets. You might also have chosen the source and target in the wrong direction?", "warning");
    }
}
