var graph;

const REMOTE_LAYOUT_V2 = {
  layout: "cosev2",
  extra: {
    k: 10.0,
    spring_coeff: 0.19,
    repulsion_coeff: 4.35,
    gravity: 0.028,
    node_distance: 12,
    ideal_edge_length: 8,
  },
};

const graphState = {
  targetNodeId: "",
  selectedNodeIds: [],
  selectedEdgeId: "",
  highlightedEdgeIds: new Set(),
  contextMenu: null,
};

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
    patch.color = "yellow";
  }
  if (nodeData && (nodeData.reference === "start" || nodeData._querysource)) {
    patch.borderColor = "red";
    patch.borderWidth = 0.18;
  }
  if (nodeData && (nodeData.reference === "end" || nodeData._querytarget)) {
    patch.borderColor = "blue";
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

function remoteLayout(targetGraph) {
  return {
    run: async function () {
      busystatus("Running graph layout");
      try {
        const nodes = targetGraph.nodeIds().map((id) => {
          const data = targetGraph.nodeData.get(id) || {};
          const position = targetGraph.nodePosition(id);
          return {
            id,
            data,
            width: Math.max(20, Number(data.renderSize || 10) * 2),
            height: Math.max(20, Number(data.renderSize || 10) * 2),
            position,
          };
        });
        const edges = targetGraph.edgeIds().map((id) => {
          const data = targetGraph.edgeData.get(id) || {};
          return {
            id,
            from: data.source,
            to: data.target,
            data,
          };
        });
        const response = await fetchJSONOrThrow("/api/graph/layout", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            graph: { nodes, edges },
            layout: REMOTE_LAYOUT_V2.layout,
            options: REMOTE_LAYOUT_V2.extra,
          }),
        });
        let positions = response && response.positions ? response.positions : response;
        if (Array.isArray(positions)) {
          positions = positions.reduce(function (acc, item) {
            if (item && item.id) {
              acc[item.id] = { x: item.x, y: item.y };
            }
            return acc;
          }, {});
        }
        targetGraph.batch(function () {
          Object.entries(positions || {}).forEach(([id, pos]) => {
            targetGraph.setNodePosition(id, pos, { markDirty: false });
          });
        });
        targetGraph.fit(undefined, 30);
      } catch (err) {
        toast("Graph layout failed", err.message, "error");
      } finally {
        const statusEl = document.getElementById("status");
        if (statusEl) {
          statusEl.style.display = "none";
        }
      }
    },
  };
}

function randomLayout(targetGraph) {
  return {
    run: function () {
      busystatus("Running graph layout");
      targetGraph.batch(function () {
        targetGraph.nodeIds().forEach((nodeId) => {
          targetGraph.setNodePosition(nodeId, {
            x: Math.round((Math.random() - 0.5) * 1000),
            y: Math.round((Math.random() - 0.5) * 1000),
          });
        });
      });
      targetGraph.fit(undefined, 30);
      const statusEl = document.getElementById("status");
      if (statusEl) {
        statusEl.style.display = "none";
      }
    },
  };
}

function fixedLayout(targetGraph) {
  return {
    run: function () {
      targetGraph.fit(undefined, 30);
      const statusEl = document.getElementById("status");
      if (statusEl) {
        statusEl.style.display = "none";
      }
    },
  };
}

function forceAtlasLayout(targetGraph) {
  return targetGraph.layout({
    name: "forceatlas2",
    iterations: 400,
    iterationsPerFrame: 8,
    refreshIntervalMs: 16,
    declump: true,
    declumpIterations: 10,
    declumpPadding: 6,
    settings: {
      gravity: 1,
      scalingRatio: 10,
      strongGravityMode: false,
      slowDown: 8,
      barnesHutOptimize: true,
    },
  });
}

function getGraphlayout(choice) {
  const selected = String(choice || "");
  switch (selected) {
    case "random":
      return randomLayout(graph);
    case "fixed":
      return fixedLayout(graph);
    case "forceatlas2":
      return forceAtlasLayout(graph);
    case "remotev2":
    default:
      return remoteLayout(graph);
  }
}

function runSelectedGraphLayout() {
  if (!graph) {
    return;
  }
  getGraphlayout(byIdValue("graphlayout", "remotev2")).run();
}

function initgraph(data) {
  createAdalancheGraph(data);
  runSelectedGraphLayout();
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
