var graph;

const graphState = {
  targetNodeId: "",
  selectedNodeIds: [],
  selectedEdgeId: "",
  highlightedEdgeIds: new Set(),
  contextMenu: null,
  layoutConnector: null,
  layoutConnectorReady: false,
  layoutDefinitions: {},
  activeLayoutAbort: null,
  layoutRerunTimer: null,
};

const DEFAULT_GRAPH_LAYOUT = "wasm.cluster";
const GRAPH_LAYOUT_PREF = "ui.graph.layout";
const GRAPH_LAYOUT_OPTIONS_PREF = "ui.graph.layout.options";

const iconMap = new Map([
  ["Person", "icons/person-fill.svg"],
  ["Group", "icons/people-fill.svg"],
  ["Computer", "icons/tv-fill.svg"],
  ["Machine", "icons/tv-fill.svg"],
  ["ms-DS-Managed-Service-Account", "icons/manage_accounts_black_24dp.svg"],
  ["ms-DS-Group-Managed-ServiceAccount", "icons/manage_accounts_black_24dp.svg"],
  ["ms-DS-Group-Managed-Service-Account", "icons/manage_accounts_black_24dp.svg"],
  ["Foreign-Security-Principal", "icons/badge_black_24dp.svg"],
  ["Service", "icons/service.svg"],
  ["CallableService", "icons/service.svg"],
  ["Directory", "icons/source_black_24dp.svg"],
  ["File", "icons/article_black_24dp.svg"],
  ["Executable", "icons/binary-code.svg"],
  ["Group-Policy-Container", "icons/gpo.svg"],
  ["Organizational-Unit", "icons/source_black_24dp.svg"],
  ["Container", "icons/folder_black_24dp.svg"],
  ["PKI-Certificate-Template", "icons/certificate.svg"],
  ["MS-PKI-Certificate-Template", "icons/certificate.svg"],
  ["DNS-Node", "icons/dns.svg"],
]);

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

function graphLayoutSelect() {
  return document.getElementById("graphlayout");
}

function graphLayoutOptionsRoot() {
  return document.getElementById("graphlayoutoptions");
}

function graphLayoutDefinitions() {
  return { ...(graphState.layoutDefinitions || {}) };
}

function graphLayoutDefinition(layoutKey) {
  const key = String(layoutKey || "").trim();
  return key ? (graphLayoutDefinitions()[key] || null) : null;
}

function isWasmLayout(layoutKey) {
  return String(layoutKey || "").trim().startsWith("wasm.");
}

function graphLayoutOptionValues() {
  const raw = getpref(GRAPH_LAYOUT_OPTIONS_PREF, {});
  if (raw && typeof raw === "object" && !Array.isArray(raw)) {
    return raw;
  }
  return {};
}

function persistGraphLayoutOptionValues(values) {
  setpref(GRAPH_LAYOUT_OPTIONS_PREF, values);
}

function coerceLayoutOptionValue(option, rawValue) {
  if (!option || !option.key) {
    return rawValue;
  }
  if (option.type === "boolean") {
    return rawValue === true || rawValue === "true" || rawValue === "on" || rawValue === 1;
  }
  const parsed = Number(rawValue);
  if (!Number.isFinite(parsed)) {
    const fallback = option.default;
    return typeof fallback === "number" ? fallback : Number(fallback || 0);
  }
  return parsed;
}

function ensureLayoutOptionDefaults(layoutKey) {
  const key = String(layoutKey || "").trim();
  if (!key) {
    return {};
  }
  const definition = graphLayoutDefinition(key);
  const allValues = graphLayoutOptionValues();
  const currentValues = allValues[key] && typeof allValues[key] === "object" ? { ...allValues[key] } : {};
  let changed = false;
  if (definition && Array.isArray(definition.options)) {
    definition.options.forEach((option) => {
      if (!option || !option.key) {
        return;
      }
      if (typeof currentValues[option.key] === "undefined") {
        currentValues[option.key] = option.default;
        changed = true;
      }
    });
  }
  if (changed || allValues[key] !== currentValues) {
    allValues[key] = currentValues;
    persistGraphLayoutOptionValues(allValues);
  }
  return currentValues;
}

function layoutOptionsForLayout(layoutKey) {
  const key = String(layoutKey || "").trim();
  const values = ensureLayoutOptionDefaults(key);
  return { ...values };
}

function scheduleLayoutRerun(delayMs) {
  if (!graph) {
    return;
  }
  if (graphState.layoutRerunTimer) {
    clearTimeout(graphState.layoutRerunTimer);
    graphState.layoutRerunTimer = null;
  }
  graphState.layoutRerunTimer = setTimeout(() => {
    graphState.layoutRerunTimer = null;
    runSelectedGraphLayout();
  }, Math.max(0, Number(delayMs) || 0));
}

function installTooltip(el) {
  if (!el || typeof bootstrap === "undefined" || !bootstrap || typeof bootstrap.Tooltip !== "function") {
    return;
  }
  bootstrap.Tooltip.getOrCreateInstance(el);
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
    default:
      return label;
  }
}

function edgelabel(data) {
  const methods = Array.isArray(data && data.methods) ? data.methods : [];
  return methods.sort().join("\n");
}

var anonymizer = new DataAnonymizer();

function hashFnv32a(str, asString, seed) {
  var i;
  var l;
  var hval = seed === undefined ? 0x811c9dc5 : seed;

  for (i = 0, l = str.length; i < l; i++) {
    hval ^= str.charCodeAt(i);
    hval += (hval << 1) + (hval << 4) + (hval << 7) + (hval << 8) + (hval << 24);
  }
  if (asString) {
    return ("0000000" + (hval >>> 0).toString(16)).substr(-8);
  }
  return hval >>> 0;
}

function probabilityToRGB(value) {
  value = Math.max(0, Math.min(100, value));
  let r = value < 50 ? 255 : Math.round(255 - (value - 50) * 5.1);
  let g = value > 50 ? 255 : Math.round(value * 5.1);
  return `rgb(${r},${g},0)`;
}

function normalize(value, min, max, outMin, outMax) {
  if (!Number.isFinite(value) || !Number.isFinite(min) || !Number.isFinite(max) || max <= min) {
    return outMin;
  }
  const ratio = (value - min) / (max - min);
  return outMin + ratio * (outMax - outMin);
}

function renderedges(methodmap) {
  let maxprob = -1;

  const edgeoutput = Object.entries(methodmap || {})
    .sort()
    .map(function ([name, prob]) {
      if (prob > maxprob) {
        maxprob = prob;
      }
      return '<span class="badge text-dark" style="background-color: ' + probabilityToRGB(prob) + '">' + name + " (" + prob + "%)</span>";
    })
    .join("");

  return '<span class="badge text-dark" style="background-color: ' + probabilityToRGB(maxprob) + '">Edge ' + maxprob + "%</span>" + edgeoutput;
}

function iconPathForType(type, nodeData) {
  const normalizedType = Array.isArray(type) ? String(type[0] || "") : String(type || "");
  if (nodeData && nodeData.account_inactive) {
    return "icons/no_accounts_black_48dp.svg";
  }
  return iconMap.get(normalizedType) || "icons/adalanche-logo.svg";
}

function rendericon(type, nodeData) {
  const path = iconPathForType(type, nodeData);
  return "<img src='" + path + "' width='24' height='24'>";
}

function rendernode(ele) {
  const type = Array.isArray(ele.attributes && ele.attributes.type) ? ele.attributes.type[0] : ele.type;
  return rendericon(type, ele.attributes) + " " + renderlabel(ele.label || "");
}

function renderdetails(data) {
  if (window.DetailsLayouts && typeof window.DetailsLayouts.renderDetails === "function") {
    return window.DetailsLayouts.renderDetails(data);
  }
  var result = "<table>";
  for (var attr in data.attributes) {
    result += "<tr><td>" + attr + "</td><td>";
    var attrvalues = data.attributes[attr];
    for (var i in attrvalues) {
      if (byIdValue("graphlabels", "normal") == "randomize") {
        result += anonymizer.anonymize(attrvalues[i]) + "</br>";
      } else {
        result += attrvalues[i] + "</br>";
      }
    }
    result += "</td></tr>";
  }
  result += "</table>";
  return result;
}

function getNodeType(nodeData) {
  return String(nodeData && nodeData.type ? nodeData.type : "");
}

function getNodeBaseColor(nodeData) {
  const type = getNodeType(nodeData);
  switch (type) {
    case "Group":
      return "#f59e0b";
    case "Person":
      return "#16a34a";
    case "ms-DS-Managed-Service-Account":
    case "ms-DS-Group-Managed-ServiceAccount":
    case "ms-DS-Group-Managed-Service-Account":
    case "Foreign-Security-Principal":
    case "Service":
    case "CallableService":
    case "Executable":
    case "Computer":
      return "#90ee90";
    case "Machine":
      return "#0f766e";
    case "Directory":
    case "File":
      return "#93c5fd";
    case "Group-Policy-Container":
      return "#9333ea";
    case "Organizational-Unit":
    case "Container":
      return "#d1d5db";
    case "PKI-Certificate-Template":
    case "MS-PKI-Certificate-Template":
      return "#f9a8d4";
    default:
      return translateAutoTheme(getpref("theme", "auto")) === "dark" ? "#6c757d" : "#8b949e";
  }
}

function nodeThemeTextColor() {
  return translateAutoTheme(getpref("theme", "auto")) === "dark" ? "white" : "black";
}

function graphTheme() {
  const dark = translateAutoTheme(getpref("theme", "auto")) === "dark";
  return {
    node: {
      label: byIdValue("nodelabels", "normal") !== "off",
      backgroundImage: "data(iconFull)",
      backgroundImageOpacity: 0.95,
      color: dark ? "#f8f9fa" : "#0f172a",
      fontSize: 11,
      minZoomedFontSize: 6,
      textHAlign: "center",
      textVAlign: "top",
      backgroundColor: dark ? "#6c757d" : "#94a3b8",
    },
    selectedNode: {
      borderColor: dark ? "#f8f9fa" : "#111827",
      shadowColor: "#0d6efd",
    },
    edge: {
      width: 2,
      lineColor: dark ? "#f8f9fa" : "#111827",
      targetArrowColor: dark ? "#f8f9fa" : "#111827",
      targetArrowShape: "triangle",
      curveStyle: "straight",
    },
    hoveredEdge: {
      label: byIdChecked("showedgelabels"),
      color: dark ? "#e9ecef" : "#111827",
      fontSize: 12,
      textBackgroundColor: dark ? "#0f1216" : "#ffffff",
      textBackgroundOpacity: 0.9,
      textBackgroundPadding: 2,
    },
  };
}

function computeNodeVisualPatch(nodeData) {
  const dark = translateAutoTheme(getpref("theme", "auto")) === "dark";
  const patch = {
    label: renderlabel(String(nodeData.label || "")),
    color: getNodeBaseColor(nodeData),
    iconFull: iconPathForType(getNodeType(nodeData), nodeData),
    borderColor: "rgba(0,0,0,0)",
    borderWidth: 0,
    textColor: nodeThemeTextColor(),
  };

  if (nodeData && nodeData._canexpand) {
    patch.color = "#fde047";
  }
  if (nodeData && (nodeData.reference === "start" || nodeData._querysource)) {
    patch.borderColor = "#ef4444";
    patch.borderWidth = 0.18;
  }
  if (nodeData && (nodeData.reference === "end" || nodeData._querytarget)) {
    patch.borderColor = "#2563eb";
    patch.borderWidth = 0.18;
  }
  if (graphState.targetNodeId && nodeData.id === graphState.targetNodeId) {
    patch.borderColor = dark ? "#f8f9fa" : "#111827";
    patch.borderWidth = 0.24;
  }

  return patch;
}

function getEdgeColor(data) {
  var color = translateAutoTheme(getpref("theme", "auto")) === "dark" ? "#ffffff" : "#000000";
  const methods = Array.isArray(data && data.methods) ? data.methods : [];
  if (methods.includes("MemberOfGroup")) {
    color = "#f59e0b";
  } else if (methods.includes("MemberOfGroupIndirect")) {
    color = "#f97316";
  } else if (methods.includes("ForeignIdentity")) {
    color = "#90ee90";
  } else if (methods.includes("ResetPassword")) {
    color = "#ef4444";
  } else if (methods.includes("AddMember")) {
    color = "#fde047";
  } else if (methods.includes("TakeOwnership") || methods.includes("WriteDACL")) {
    color = "#93c5fd";
  } else if (methods.includes("Owns")) {
    color = "#2563eb";
  }
  return color;
}

function clearHighlightedEdges() {
  if (!graph) {
    return;
  }
  for (const edgeId of graphState.highlightedEdgeIds.values()) {
    const edgeData = graph.edgeData.get(edgeId);
    if (!edgeData) {
      continue;
    }
    graph.updateEdgeData(edgeId, {
      color: edgeData.baseColor || getEdgeColor(edgeData),
      width: edgeData.baseWidth || 2,
    });
  }
  graphState.highlightedEdgeIds.clear();
}

function applyEdgeStyles(targetGraph) {
  if (!targetGraph) {
    return;
  }
  targetGraph.batch(function () {
    targetGraph.edgeIds().forEach(function (edgeId) {
      const data = targetGraph.edgeData.get(edgeId);
      if (!data) {
        return;
      }
      const flow = Number(data.flow);
      const edgeWidth = Number.isFinite(flow) && flow > 0 ? 1 + Math.log(flow) : 1;
      const baseColor = getEdgeColor(data);
      data.baseColor = baseColor;
      data.baseWidth = edgeWidth;
      targetGraph.updateEdgeData(edgeId, {
        label: edgelabel(data),
        color: baseColor,
        width: edgeWidth,
      });
    });
  });
}

function nodeDegreeMaps(targetGraph) {
  const incoming = new Map();
  const outgoing = new Map();
  targetGraph.edgeIds().forEach((edgeId) => {
    const endpoints = targetGraph.edgeEndpoints(edgeId);
    incoming.set(endpoints.target, (incoming.get(endpoints.target) || 0) + 1);
    outgoing.set(endpoints.source, (outgoing.get(endpoints.source) || 0) + 1);
  });
  return { incoming, outgoing };
}

function applyNodeStyles(targetGraph, nodestyleOverride) {
  if (!targetGraph) {
    return;
  }
  const nodestyle = nodestyleOverride || getpref("graph.nodesize", "incoming");
  const degreeMaps = nodeDegreeMaps(targetGraph);
  const counts = targetGraph.nodeIds().map((nodeId) => {
    if (nodestyle === "outgoing") {
      return degreeMaps.outgoing.get(nodeId) || 0;
    }
    if (nodestyle === "equal") {
      return 0;
    }
    return degreeMaps.incoming.get(nodeId) || 0;
  });
  const maxCount = counts.length > 0 ? Math.max(...counts) : 0;

  targetGraph.batch(function () {
    targetGraph.nodeIds().forEach(function (nodeId) {
      const data = targetGraph.nodeData.get(nodeId);
      if (!data) {
        return;
      }
      const patch = computeNodeVisualPatch(data);
      let size = 10;
      if (nodestyle === "equal" || maxCount <= 0) {
        size = 10;
      } else {
        const value = nodestyle === "outgoing" ? (degreeMaps.outgoing.get(nodeId) || 0) : (degreeMaps.incoming.get(nodeId) || 0);
        size = normalize(value, 0, maxCount, 10, 24);
      }
      patch.renderSize = size;
      targetGraph.updateNodeData(nodeId, patch);
    });
  });
}

function refreshGraphTheme() {
  if (!graph) {
    return;
  }
  graph.setThemeConfig(graphTheme());
  applyNodeStyles(graph, byIdValue("nodesizes", getpref("graph.nodesize", "incoming")));
  applyEdgeStyles(graph);
  if (!byIdChecked("showedgelabels")) {
    graph.clearHoveredEdges();
  }
}

function hideGraphContextMenu() {
  if (!graphState.contextMenu) {
    return;
  }
  graphState.contextMenu.style.display = "none";
  graphState.contextMenu.innerHTML = "";
}

function ensureGraphContextMenu() {
  if (graphState.contextMenu) {
    return graphState.contextMenu;
  }
  const menu = document.createElement("div");
  menu.id = "graph-context-menu";
  menu.className = "graph-context-menu card";
  menu.style.display = "none";
  document.body.appendChild(menu);
  graphState.contextMenu = menu;
  return menu;
}

function openGraphContextMenu(items, x, y) {
  const menu = ensureGraphContextMenu();
  menu.innerHTML = "";
  items.forEach((item) => {
    if (!item.show) {
      return;
    }
    const button = document.createElement("button");
    button.type = "button";
    button.className = "dropdown-item";
    button.textContent = item.label;
    button.addEventListener("click", function () {
      hideGraphContextMenu();
      item.onClick();
    });
    menu.appendChild(button);
  });
  menu.style.left = `${x}px`;
  menu.style.top = `${y}px`;
  menu.style.display = "";
}

function graphNodeData(nodeId) {
  return graph && graph.nodeData ? graph.nodeData.get(String(nodeId || "")) : null;
}

function graphEdgeData(edgeId) {
  return graph && graph.edgeData ? graph.edgeData.get(String(edgeId || "")) : null;
}

function graphNodeHtml(nodeId, fallbackLabel) {
  const nodeData = graphNodeData(nodeId) || {};
  return rendericon(getNodeType(nodeData), nodeData) + " " + renderlabel(String(nodeData.label || fallbackLabel || nodeId));
}

function showNodeDetails(nodeId) {
  fetchJSONOrThrow("api/details/id/" + String(nodeId).substring(1))
    .then(function (data) {
      let windowname = "details_" + nodeId;
      if (getpref("ui.open.details.in.same.window", true)) {
        windowname = "node_details";
      }
      new_window(windowname, rendernode(data), renderdetails(data));
    })
    .catch(function (err) {
      new_window("details", "Node details", graphNodeHtml(nodeId, nodeId) + "<div>Couldn't load details:" + err.message + "</div>");
    });
}

function showEdgeDetails(edgeId) {
  const edgeData = graphEdgeData(edgeId);
  if (!edgeData) {
    return;
  }
  fetchJSONOrThrow("api/edges/id/" + String(edgeData.source).substring(1) + "," + String(edgeData.target).substring(1))
    .then(function (data) {
      let windowname = "edge_" + edgeData.source + "_to_" + edgeData.target;
      if (getpref("ui.open.details.in.same.window", true)) {
        windowname = "edge_details";
      }
      new_window(
        windowname,
        "Edge from " + renderlabel(data[0].from.label) + " to " + renderlabel(data[0].to.label),
        rendernode(data[0].from) + "<br>" + renderedges(data[0].edges) + "<br>" + rendernode(data[0].to)
      );
    })
    .catch(function (err) {
      toast("Error loading edge details", err.message, "error");
    });
}

function setRouteTarget(nodeId) {
  graphState.targetNodeId = String(nodeId || "");
  refreshGraphTheme();
}

function probabilityWeight(edgeData) {
  const maxprobability = Number(edgeData && edgeData._maxprob);
  if (Number.isFinite(maxprobability) && maxprobability > 0) {
    return 101 - maxprobability;
  }
  return 1;
}

function shortestPath(sourceId, targetId) {
  if (!graph) {
    return null;
  }

  const distances = new Map();
  const previousNode = new Map();
  const previousEdge = new Map();
  const queue = new Set(graph.nodeIds());
  graph.nodeIds().forEach((nodeId) => distances.set(nodeId, Number.POSITIVE_INFINITY));
  distances.set(sourceId, 0);

  while (queue.size > 0) {
    let current = "";
    let bestDistance = Number.POSITIVE_INFINITY;
    queue.forEach((nodeId) => {
      const distance = distances.get(nodeId);
      if (distance < bestDistance) {
        current = nodeId;
        bestDistance = distance;
      }
    });
    if (!current) {
      break;
    }
    queue.delete(current);
    if (current === targetId) {
      break;
    }

    graph.edgeIds().forEach((edgeId) => {
      const edgeData = graphEdgeData(edgeId);
      if (!edgeData || edgeData.source !== current || !queue.has(edgeData.target)) {
        return;
      }
      const nextDistance = bestDistance + probabilityWeight(edgeData);
      if (nextDistance < (distances.get(edgeData.target) || Number.POSITIVE_INFINITY)) {
        distances.set(edgeData.target, nextDistance);
        previousNode.set(edgeData.target, current);
        previousEdge.set(edgeData.target, edgeId);
      }
    });
  }

  if (!previousNode.has(targetId)) {
    return null;
  }

  const pathNodes = [targetId];
  const pathEdges = [];
  let cursor = targetId;
  while (cursor !== sourceId) {
    pathEdges.unshift(previousEdge.get(cursor));
    cursor = previousNode.get(cursor);
    pathNodes.unshift(cursor);
  }
  return { pathNodes, pathEdges };
}

function selectGraphNodes(nodeIds) {
  clearHighlightedEdges();
  graphState.selectedNodeIds = Array.isArray(nodeIds) ? nodeIds.filter(Boolean) : [];
  if (graph) {
    graph.setSelectedNodeIDs(graphState.selectedNodeIds);
  }
}

function highlightGraphRoute(pathEdges) {
  clearHighlightedEdges();
  pathEdges.forEach((edgeId) => {
    const edgeData = graphEdgeData(edgeId);
    if (!edgeData) {
      return;
    }
    graph.updateEdgeData(edgeId, {
      color: "#0d6efd",
      width: Math.max(Number(edgeData.baseWidth || 2), 4),
    });
    graphState.highlightedEdgeIds.add(edgeId);
  });
}

function findroute(sourceId) {
  if (!graphState.targetNodeId) {
    toast("No target node found", "error");
    return;
  }

  const result = shortestPath(String(sourceId || ""), graphState.targetNodeId);
  if (!result) {
    toast("No route found", "If your analysis was for multiple target nodes, there is no guarantee that all results can reach all targets. You might also have chosen the source and target in the wrong direction?", "warning");
    return;
  }

  selectGraphNodes(result.pathNodes);
  highlightGraphRoute(result.pathEdges);

  let pathprobability = 1.0;
  result.pathEdges.forEach((edgeId) => {
    const edgeData = graphEdgeData(edgeId);
    if (edgeData && edgeData._maxprob) {
      pathprobability *= Number(edgeData._maxprob) / 100;
    }
  });
  pathprobability *= 100;

  const routecontents = result.pathNodes.map((nodeId) => String(nodeId).substring(1)).join(",");
  fetchJSONOrThrow("/api/edges/id/" + routecontents)
    .then(function (data) {
      let output = "";
      for (var i = 0; i < data.length; i++) {
        output += rendericon(data[i].from.attributes["type"], data[i].from.attributes) + renderlabel(data[i].from.label) + "<br>";
        output += renderedges(data[i].edges) + "<br>";
        if (i == data.length - 1) {
          output += rendericon(data[i].to.attributes["type"], data[i].to.attributes) + renderlabel(data[i].to.label);
        }
      }

      new_window(
        "route_" + sourceId + "_" + graphState.targetNodeId,
        "Route from " + renderlabel(data[0].from.label) + " to " + renderlabel(data[data.length - 1].to.label) + " - " + pathprobability.toFixed(2) + "% probability",
        output
      );
    })
    .catch(function (err) {
      toast("Error loading route details", err.message, "error");
    });
}

function openNodeContextMenu(nodeId, clientX, clientY) {
  const nodeData = graphNodeData(nodeId) || {};
  openGraphContextMenu(
    [
      {
        label: "Set as route target",
        show: true,
        onClick: function () {
          setRouteTarget(nodeId);
        },
      },
      {
        label: "Plot route to target",
        show: true,
        onClick: function () {
          findroute(nodeId);
        },
      },
      {
        label: "Expand node",
        show: Number(nodeData._canexpand) > 0,
        onClick: function () {
          expandNode(nodeId);
        },
      },
      {
        label: "What can this node reach?",
        show: true,
        onClick: function () {
          runReachabilityQuery(nodeId, "outbound");
        },
      },
      {
        label: "Who can reach this node?",
        show: true,
        onClick: function () {
          runReachabilityQuery(nodeId, "inbound");
        },
      },
    ],
    clientX,
    clientY
  );
}

function runReachabilityQuery(nodeId, direction) {
  fetchJSONOrThrow("api/details/id/" + String(nodeId).substring(1))
    .then(function (data) {
      if (data.attributes["distinguishedName"]) {
        set_query(direction === "outbound" ? "start:(distinguishedname=" + data.attributes["distinguishedName"] + ")-[]{1,3}->end:()" : "start:(distinguishedname=" + data.attributes["distinguishedName"] + ")<-[]{1,3}-end:()");
      } else if (data.attributes["objectSid"]) {
        set_query(direction === "outbound" ? "start:(objectSid=" + data.attributes["objectSid"] + ")-[]{1,3}->end:()" : "start:(objectSid=" + data.attributes["objectSid"] + ")<-[]{1,3}-end:()");
      } else if (data.attributes["objectGuid"]) {
        set_query(direction === "outbound" ? "start:(objectGuid=" + data.attributes["objectGuid"] + ")-[]{1,3}->end:()" : "start:(objectGuid=" + data.attributes["objectGuid"] + ")<-[]{1,3}-end:()");
      } else {
        set_query(direction === "outbound" ? "start:(_id=" + String(nodeId).substring(1) + ")-[]{1,3}->end:()" : "start:(_id=" + String(nodeId).substring(1) + ")<-[]{1,3}-end:()");
      }
      aqlanalyze();
    })
    .catch(function () {
      toast("Node not found in backend", "There was a problem doing node lookup in the backend.");
    });
}

function expandNode(nodeId) {
  const nodeData = graphNodeData(nodeId);
  if (!nodeData) {
    return;
  }
  const expanddata = serializeFormsToObject("#ldapqueryform, #optionsform");
  expanddata.expanddn = nodeData.distinguishedName;

  fetchJSONOrThrow("cytograph.json", {
    method: "POST",
    headers: { "Content-Type": "application/json; charset=utf-8" },
    body: JSON.stringify(expanddata),
  })
    .then(function (data) {
      const elements = transformGraphElements(data.elements || []);
      graph.add(elements);
      graph.updateNodeData(nodeId, { _canexpand: 0 });
      refreshGraphTheme();
      runSelectedGraphLayout();
    })
    .catch(function (err) {
      const statusEl = document.getElementById("status");
      if (statusEl) {
        statusEl.innerHTML = "Problem loading graph:<br>" + err.message;
        statusEl.style.display = "";
      }
    });
}

function bindGraphEvents() {
  graph.onNodeClick(function (evt) {
    hideGraphContextMenu();
    if (evt.originalEvent && (evt.originalEvent.altKey || evt.originalEvent.ctrlKey || evt.originalEvent.shiftKey)) {
      return;
    }
    selectGraphNodes([evt.nodeId]);
    graphState.selectedEdgeId = "";
    showNodeDetails(evt.nodeId);
  });

  graph.onEdgeClick(function (evt) {
    hideGraphContextMenu();
    graphState.selectedEdgeId = evt.edgeId;
    selectGraphNodes([]);
    clearHighlightedEdges();
    showEdgeDetails(evt.edgeId);
  });

  graph.onBackgroundClick(function () {
    hideGraphContextMenu();
    graphState.selectedEdgeId = "";
    selectGraphNodes([]);
  });

  graph.onNodeContextMenu(function (evt) {
    const client = evt.clientPosition || { x: 0, y: 0 };
    openNodeContextMenu(evt.nodeId, Number(client.x || 0), Number(client.y || 0));
  });

  graph.onEdgeContextMenu(function () {
    hideGraphContextMenu();
  });

  graph.onEdgeHoverChanged(function (evt) {
    if (!byIdChecked("showedgelabels")) {
      graph.clearHoveredEdges();
      return;
    }
    graph.setEdgeHovered(evt.edgeId, !!evt.hovered);
  });
}

function transformGraphElements(elements) {
  return (Array.isArray(elements) ? elements : []).map((item) => {
    const data = { ...(item.data || {}) };
    if (!data.id) {
      return item;
    }
    if (!data.source && !data.target) {
      data.iconFull = iconPathForType(getNodeType(data), data);
      data.color = getNodeBaseColor(data);
      data.label = String(data.label || data.id);
    }
    return {
      group: item.group,
      data,
      position: item.position,
    };
  });
}

function createAdalancheGraph(elements) {
  const container = document.getElementById("cy");
  if (!container || typeof window.createWorkspaceSigmaGraph !== "function") {
    throw new Error("Sigma graph runtime is not available");
  }
  if (graph && typeof graph.kill === "function") {
    graph.kill();
  }
  hideGraphContextMenu();
  graphState.targetNodeId = "";
  graphState.selectedNodeIds = [];
  graphState.selectedEdgeId = "";
  graphState.highlightedEdgeIds.clear();

  graph = window.graph = window.createWorkspaceSigmaGraph({
    container,
    elements: transformGraphElements(elements),
    iconMinZoom: 0,
    iconMinScreenSize: 12,
    theme: graphTheme(),
  });
  bindGraphEvents();
  refreshGraphTheme();
  return graph;
}

function selectedGraphLayout() {
  const preferred = String(getpref(GRAPH_LAYOUT_PREF, DEFAULT_GRAPH_LAYOUT) || "").trim();
  const select = graphLayoutSelect();
  if (preferred) {
    return preferred;
  }
  if (select && select.value) {
    return select.value;
  }
  return preferred || DEFAULT_GRAPH_LAYOUT;
}

function syncGraphLayoutSelection(layoutKey) {
  const key = String(layoutKey || "").trim() || DEFAULT_GRAPH_LAYOUT;
  const select = graphLayoutSelect();
  if (select && select.value !== key) {
    select.value = key;
  }
  setpref(GRAPH_LAYOUT_PREF, key);
}

function updateGraphLayoutChoices() {
  const select = graphLayoutSelect();
  if (!select) {
    return;
  }
  const currentValue = String(selectedGraphLayout() || DEFAULT_GRAPH_LAYOUT);
  const definitions = graphLayoutDefinitions();
  select.innerHTML = "";
  Object.values(definitions).forEach((definition) => {
    const option = document.createElement("option");
    option.value = definition.key;
    option.textContent = definition.label || definition.key;
    select.appendChild(option);
  });
  if (definitions[currentValue]) {
    select.value = currentValue;
    return;
  }
  const firstLayout = Object.keys(definitions)[0] || DEFAULT_GRAPH_LAYOUT;
  select.value = definitions[DEFAULT_GRAPH_LAYOUT] ? DEFAULT_GRAPH_LAYOUT : firstLayout;
}

function layoutOptionDisplayValue(option, value) {
  if (option.type === "boolean") {
    return value ? "On" : "Off";
  }
  if (!Number.isFinite(Number(value))) {
    return "";
  }
  const numericValue = Number(value);
  if (option.unit) {
    return `${numericValue}${option.unit}`;
  }
  return `${numericValue}`;
}

function renderGraphLayoutOptions() {
  const root = graphLayoutOptionsRoot();
  if (!root) {
    return;
  }
  const layoutKey = selectedGraphLayout();
  const definition = graphLayoutDefinition(layoutKey);
  root.innerHTML = "";
  if (!definition) {
    return;
  }

  if (definition.description) {
    const description = document.createElement("div");
    description.className = "form-text mb-2";
    description.textContent = definition.description;
    root.appendChild(description);
  }

  if (!Array.isArray(definition.options) || definition.options.length === 0) {
    return;
  }

  const values = ensureLayoutOptionDefaults(layoutKey);
  definition.options.forEach((option) => {
    if (!option || !option.key) {
      return;
    }
    const wrapper = document.createElement("div");
    wrapper.className = "d-flex align-items-center gap-2 mb-2";

    const label = document.createElement("label");
    label.className = "form-label mb-0 text-truncate flex-shrink-0";
    label.style.width = "7rem";
    label.htmlFor = `graphlayoutoption_${layoutKey}_${option.key}`;
    label.textContent = option.label || option.key;
    if (option.description) {
      label.setAttribute("data-bs-toggle", "tooltip");
      label.setAttribute("data-bs-placement", "top");
      label.setAttribute("data-bs-title", option.description);
      label.style.cursor = "help";
    }
    wrapper.appendChild(label);

    if (option.type === "boolean") {
      const input = document.createElement("input");
      input.type = "checkbox";
      input.className = "form-check-input";
      input.id = `graphlayoutoption_${layoutKey}_${option.key}`;
      input.checked = !!values[option.key];
      input.addEventListener("change", () => {
        const allValues = graphLayoutOptionValues();
        const layoutValues = ensureLayoutOptionDefaults(layoutKey);
        layoutValues[option.key] = input.checked;
        allValues[layoutKey] = layoutValues;
        persistGraphLayoutOptionValues(allValues);
        scheduleLayoutRerun(0);
      });
      wrapper.appendChild(input);
      const valueEl = document.createElement("span");
      valueEl.className = "small text-body-secondary ms-auto flex-shrink-0";
      valueEl.textContent = layoutOptionDisplayValue(option, input.checked);
      wrapper.appendChild(valueEl);
      input.addEventListener("change", () => {
        valueEl.textContent = layoutOptionDisplayValue(option, input.checked);
      });
      installTooltip(label);
      root.appendChild(wrapper);
      return;
    }

    const input = document.createElement("input");
    input.type = option.type === "range" ? "range" : "number";
    input.className = option.type === "range" ? "form-range flex-grow-1 mb-0" : "form-control flex-grow-1";
    input.id = `graphlayoutoption_${layoutKey}_${option.key}`;
    if (typeof option.min === "number") {
      input.min = String(option.min);
    }
    if (typeof option.max === "number") {
      input.max = String(option.max);
    }
    if (typeof option.step === "number") {
      input.step = String(option.step);
    }
    input.value = String(values[option.key]);
    wrapper.appendChild(input);

    const valueEl = document.createElement("span");
    valueEl.className = "small text-body-secondary text-end flex-shrink-0";
    valueEl.style.minWidth = "3.5rem";
    valueEl.textContent = layoutOptionDisplayValue(option, values[option.key]);
    wrapper.appendChild(valueEl);

    input.addEventListener("input", () => {
      const allValues = graphLayoutOptionValues();
      const layoutValues = ensureLayoutOptionDefaults(layoutKey);
      const nextValue = coerceLayoutOptionValue(option, input.value);
      layoutValues[option.key] = nextValue;
      allValues[layoutKey] = layoutValues;
      persistGraphLayoutOptionValues(allValues);
      valueEl.textContent = layoutOptionDisplayValue(option, nextValue);
      scheduleLayoutRerun(option.type === "range" ? 180 : 0);
    });
    installTooltip(label);
    root.appendChild(wrapper);
  });
}

function setGraphLayoutDefinitions(layouts) {
  graphState.layoutDefinitions = {};
  (Array.isArray(layouts) ? layouts : []).forEach((layout) => {
    if (!layout || !layout.key) {
      return;
    }
    graphState.layoutDefinitions[layout.key] = layout;
    ensureLayoutOptionDefaults(layout.key);
  });
  updateGraphLayoutChoices();
  renderGraphLayoutOptions();
}

function applyLayoutPositions(targetGraph, positions, fitGraph) {
  if (typeof targetGraph.clearCustomBBox === "function") {
    targetGraph.clearCustomBBox();
  }
  targetGraph.batch(function () {
    Object.entries(positions || {}).forEach(([id, pos]) => {
      targetGraph.setNodePosition(id, pos, { markDirty: false });
    });
  });
  targetGraph.refresh();
  if (fitGraph) {
    targetGraph.fit(undefined, 30);
  }
}

function stopActiveGraphLayout() {
  if (graphState.activeLayoutAbort) {
    graphState.activeLayoutAbort.abort();
    graphState.activeLayoutAbort = null;
  }
}

async function runWasmLayout(targetGraph, layoutKey) {
  if (!graphState.layoutConnector || !graphState.layoutConnectorReady) {
    throw new Error("WASM layout connector is not available");
  }
  const options = layoutOptionsForLayout(layoutKey);
  const controller = new AbortController();
  graphState.activeLayoutAbort = controller;
  try {
    const definition = graphLayoutDefinition(layoutKey);
    const supportsAnimation = !!(definition && definition.supports_animation);
    if (supportsAnimation) {
      const finalFrame = await graphState.layoutConnector.animate(
        targetGraph,
        layoutKey,
        options,
        { intervalMs: 80, stepsPerFrame: 16 },
        controller.signal,
        (frame) => applyLayoutPositions(targetGraph, frame.positions, false)
      );
      applyLayoutPositions(targetGraph, finalFrame.positions, true);
      return;
    }
    const result = await graphState.layoutConnector.run(targetGraph, layoutKey, options, controller.signal);
    applyLayoutPositions(targetGraph, result.positions, true);
  } finally {
    if (graphState.activeLayoutAbort === controller) {
      graphState.activeLayoutAbort = null;
    }
  }
}

async function runSelectedGraphLayout() {
  if (!graph) {
    return;
  }
  const layoutKey = selectedGraphLayout();
  stopActiveGraphLayout();
  busystatus("Running graph layout");
  try {
    if (!isWasmLayout(layoutKey)) {
      throw new Error(`Unsupported layout: ${layoutKey}`);
    }
    await runWasmLayout(graph, layoutKey);
  } catch (err) {
    toast("Graph layout failed", err && err.message ? err.message : String(err), "error");
  } finally {
    const statusEl = document.getElementById("status");
    if (statusEl) {
      statusEl.style.display = "none";
    }
  }
}

function initGraphLayoutUI() {
  updateGraphLayoutChoices();
  syncGraphLayoutSelection(selectedGraphLayout());
  renderGraphLayoutOptions();

  const select = graphLayoutSelect();
  if (select) {
    select.addEventListener("change", () => {
      syncGraphLayoutSelection(select.value);
      renderGraphLayoutOptions();
      if (window.graph) {
        runSelectedGraphLayout();
      }
    });
  }

  if (typeof window.createAdalancheLayoutConnector !== "function") {
    setGraphLayoutStatus("WASM layout connector script is not available.", true);
    return;
  }

  const workerCount = Math.max(1, Math.min(4, Math.floor((navigator.hardwareConcurrency || 4) / 2)));
  graphState.layoutConnector = window.createAdalancheLayoutConnector({
    workerURL: "sigma/layout-worker.js",
    workerCount,
  });

  graphState.layoutConnector.init()
    .then((payload) => {
      graphState.layoutConnectorReady = true;
      setGraphLayoutDefinitions(payload && payload.layouts ? payload.layouts : []);
      const currentLayout = selectedGraphLayout();
      if (!graphLayoutDefinition(currentLayout)) {
        syncGraphLayoutSelection(DEFAULT_GRAPH_LAYOUT);
        renderGraphLayoutOptions();
      }
    })
    .catch((err) => {
      graphState.layoutConnectorReady = false;
      toast(
        "Graph layouts unavailable",
        err && err.message ? err.message : String(err),
        "error"
      );
    });
}

function initgraph(data) {
  createAdalancheGraph(data);
  runSelectedGraphLayout();
}

function initGraphLayoutUIWhenReady() {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initGraphLayoutUI, { once: true });
    return;
  }
  initGraphLayoutUI();
}

if (typeof window.ensurePrefsLoaded === "function") {
  window.ensurePrefsLoaded()
    .catch(function () {})
    .finally(initGraphLayoutUIWhenReady);
} else {
  initGraphLayoutUIWhenReady();
}

window.addEventListener("click", function (event) {
  const menu = graphState.contextMenu;
  if (!menu || menu.style.display === "none") {
    return;
  }
  if (event.target instanceof Node && menu.contains(event.target)) {
    return;
  }
  hideGraphContextMenu();
});
