var graph;

const graphState = {
  targetNodeId: "",
  selectedNodeIds: [],
  selectedEdgeId: "",
  highlightedEdgeIds: new Set(),
  contextMenu: null,
  edgeHoverCard: null,
  layoutConnector: null,
  layoutConnectorReady: false,
  layoutDefinitions: {},
  activeLayoutAbort: null,
  layoutRerunTimer: null,
  layoutRunToken: 0,
  layoutPending: false,
};

const DEFAULT_GRAPH_LAYOUT = "wasm.packed_separated_cluster_visibility";
const GRAPH_LAYOUT_PREF = "ui.graph.layout";
const GRAPH_LAYOUT_OPTIONS_PREF = "ui.graph.layout.options";
const LAYOUT_ASSET_VERSION = "20260411-1";

function graphDebugLog(event, details) {
  if (typeof window === "undefined") {
    return;
  }
  const debugEnabled = (() => {
    if (window.__graphDebugEnabled === true || window.__graphDebugEnabled === false) {
      return window.__graphDebugEnabled;
    }
    let enabled = false;
    try {
      const params = new URLSearchParams(window.location && window.location.search ? window.location.search : "");
      enabled = params.get("graphdebug") === "1";
      if (!enabled && window.localStorage) {
        enabled = window.localStorage.getItem("graphdebug") === "1";
      }
    } catch (_err) {}
    window.__graphDebugEnabled = enabled;
    return enabled;
  })();
  if (!debugEnabled) {
    return;
  }
  if (!window.__graphDebug) {
    window.__graphDebug = [];
  }
  const entry = {
    ts: Date.now(),
    event: String(event || ""),
    details: details || {},
  };
  window.__graphDebug.push(entry);
  if (window.__graphDebug.length > 500) {
    window.__graphDebug.splice(0, window.__graphDebug.length - 500);
  }
  try {
    console.debug("[graph-debug]", entry.event, entry.details);
  } catch (_err) {}
}

function graphPositionSummary(positions) {
  const entries = Object.entries(positions || {});
  let minX = Number.POSITIVE_INFINITY;
  let maxX = Number.NEGATIVE_INFINITY;
  let minY = Number.POSITIVE_INFINITY;
  let maxY = Number.NEGATIVE_INFINITY;
  let nonZero = 0;
  for (const [, pos] of entries) {
    const x = Number(pos && pos.x);
    const y = Number(pos && pos.y);
    if (!Number.isFinite(x) || !Number.isFinite(y)) {
      continue;
    }
    minX = Math.min(minX, x);
    maxX = Math.max(maxX, x);
    minY = Math.min(minY, y);
    maxY = Math.max(maxY, y);
    if (x !== 0 || y !== 0) {
      nonZero += 1;
    }
  }
  if (!entries.length) {
    minX = maxX = minY = maxY = 0;
  }
  return {
    count: entries.length,
    nonZero,
    minX,
    maxX,
    minY,
    maxY,
  };
}

const iconMap = new Map();
const nodeLegendRegistry = new Map();
const edgeColorRules = [];
let nodeLegendMetadataReady = null;

function clearNodeLegendEntries() {
  iconMap.clear();
  nodeLegendRegistry.clear();
}

function registerNodeLegendEntry(type, config) {
  const key = String(type || "").trim();
  if (!key) {
    return;
  }
  const entry = {
    type: key,
    label: String((config && config.label) || key),
    color: config && config.color ? String(config.color) : "",
    icon: config && config.icon ? String(config.icon) : "",
    description: config && config.description ? String(config.description) : "",
  };
  nodeLegendRegistry.set(key, entry);
  if (entry.icon) {
    iconMap.set(key, entry.icon);
  }
}

function registerEdgeColorRule(config) {
  const methods = Array.isArray(config && config.methods)
    ? config.methods.map((method) => String(method || "").trim()).filter(Boolean)
    : [];
  if (!methods.length) {
    return;
  }
  edgeColorRules.push({
    methods,
    color: String((config && config.color) || ""),
    label: String((config && config.label) || methods.join(", ")),
    description: String((config && config.description) || ""),
    priority: Number(config && config.priority) || 0,
  });
  edgeColorRules.sort((left, right) => Number(right.priority || 0) - Number(left.priority || 0));
}

function registerDefaultNodeLegendEntries() {
  registerNodeLegendEntry("Person", {
    color: "#16a34a",
    icon: "icons/person-fill.svg",
    description: "User and identity principals.",
  });
  registerNodeLegendEntry("Group", {
    color: "#f59e0b",
    icon: "icons/people-fill.svg",
    description: "Security and distribution groups.",
  });
  registerNodeLegendEntry("Computer", {
    color: "#90ee90",
    icon: "icons/tv-fill.svg",
    description: "Computer accounts and workstation objects.",
  });
  registerNodeLegendEntry("Machine", {
    color: "#0f766e",
    icon: "icons/tv-fill.svg",
    description: "Local machine entities outside directory computer accounts.",
  });
  registerNodeLegendEntry("ms-DS-Managed-Service-Account", {
    color: "#90ee90",
    icon: "icons/manage_accounts_black_24dp.svg",
    description: "Managed service accounts.",
  });
  registerNodeLegendEntry("ms-DS-Group-Managed-Service-Account", {
    color: "#90ee90",
    icon: "icons/manage_accounts_black_24dp.svg",
    description: "Group managed service accounts.",
  });
  registerNodeLegendEntry("Foreign-Security-Principal", {
    color: "#90ee90",
    icon: "icons/badge_black_24dp.svg",
    description: "External or foreign security principals.",
  });
  registerNodeLegendEntry("Service", {
    color: "#90ee90",
    icon: "icons/service.svg",
    description: "Service identities and service definitions.",
  });
  registerNodeLegendEntry("CallableService", {
    color: "#90ee90",
    icon: "icons/service.svg",
    description: "Callable service endpoints.",
  });
  registerNodeLegendEntry("Directory", {
    color: "#93c5fd",
    icon: "icons/source_black_24dp.svg",
    description: "Directory or folder-like filesystem objects.",
  });
  registerNodeLegendEntry("File", {
    color: "#93c5fd",
    icon: "icons/article_black_24dp.svg",
    description: "File objects.",
  });
  registerNodeLegendEntry("Executable", {
    color: "#90ee90",
    icon: "icons/binary-code.svg",
    description: "Executable files and binaries.",
  });
  registerNodeLegendEntry("Group-Policy-Container", {
    color: "#9333ea",
    icon: "icons/gpo.svg",
    description: "Group Policy containers.",
  });
  registerNodeLegendEntry("Organizational-Unit", {
    color: "#d1d5db",
    icon: "icons/source_black_24dp.svg",
    description: "Organizational units and directory containers.",
  });
  registerNodeLegendEntry("Container", {
    color: "#d1d5db",
    icon: "icons/folder_black_24dp.svg",
    description: "Generic directory containers.",
  });
  registerNodeLegendEntry("PKI-Certificate-Template", {
    color: "#f9a8d4",
    icon: "icons/certificate.svg",
    description: "Certificate templates.",
  });
  registerNodeLegendEntry("MS-PKI-Certificate-Template", {
    color: "#f9a8d4",
    icon: "icons/certificate.svg",
    description: "Certificate templates.",
  });
  registerNodeLegendEntry("Dns-Node", {
    label: "DNS-Node",
    color: "",
    icon: "icons/dns.svg",
    description: "DNS records and nodes.",
  });
}

function registerDefaultEdgeColorRules() {
  registerEdgeColorRule({
    methods: ["MemberOfGroup"],
    color: "#f59e0b",
    label: "Group Membership",
    description: "Direct group membership relationships.",
    priority: 100,
  });
  registerEdgeColorRule({
    methods: ["MemberOfGroupIndirect"],
    color: "#f97316",
    label: "Indirect Group Membership",
    description: "Transitive or nested group membership relationships.",
    priority: 90,
  });
  registerEdgeColorRule({
    methods: ["ForeignIdentity"],
    color: "#90ee90",
    label: "Foreign Identity",
    description: "Relationships involving foreign security identities.",
    priority: 80,
  });
  registerEdgeColorRule({
    methods: ["ResetPassword"],
    color: "#ef4444",
    label: "Reset Password",
    description: "Reset-password rights or paths.",
    priority: 70,
  });
  registerEdgeColorRule({
    methods: ["AddMember"],
    color: "#fde047",
    label: "Add Member",
    description: "Ability to add principals to groups.",
    priority: 60,
  });
  registerEdgeColorRule({
    methods: ["TakeOwnership", "WriteDACL"],
    color: "#93c5fd",
    label: "Ownership or ACL Control",
    description: "Take ownership or modify permissions on the target.",
    priority: 50,
  });
  registerEdgeColorRule({
    methods: ["Owns"],
    color: "#2563eb",
    label: "Owns",
    description: "Object ownership relationships.",
    priority: 40,
  });
}

registerDefaultEdgeColorRules();

function applyNodeTypeMetadata(typeMetadata) {
  clearNodeLegendEntries();
  Object.entries(typeMetadata || {}).forEach(([lookup, entry]) => {
    registerNodeLegendEntry(lookup, {
      label: entry && entry.name ? entry.name : lookup,
      icon: entry && entry.icon ? entry.icon : "",
      color: entry && entry["background-color"] ? entry["background-color"] : "",
      description: entry && entry.description ? entry.description : "",
    });
  });
}

function ensureNodeLegendMetadataLoaded() {
  if (nodeLegendMetadataReady) {
    return nodeLegendMetadataReady;
  }
  nodeLegendMetadataReady = fetchJSONOrThrow("backend/types")
    .then((payload) => {
      applyNodeTypeMetadata(payload);
    })
    .catch(() => {
      clearNodeLegendEntries();
      registerDefaultNodeLegendEntries();
    });
  return nodeLegendMetadataReady;
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
  const raw = pref(GRAPH_LAYOUT_OPTIONS_PREF, {});
  if (raw && typeof raw === "object" && !Array.isArray(raw)) {
    return raw;
  }
  return {};
}

function persistPreference(key, value) {
  if (window.backendPersist && typeof window.backendPersist.setItem === "function") {
    window.backendPersist.setItem(key, JSON.stringify(value));
    return;
  }
  setpref(key, value);
}

function persistGraphLayoutOptionValues(values) {
  persistPreference(GRAPH_LAYOUT_OPTIONS_PREF, values);
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

function escapehtml(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function getNodeType(nodeData) {
  return String(nodeData && nodeData.type ? nodeData.type : "");
}

function getNodeBaseColor(nodeData) {
  const type = getNodeType(nodeData);
  const entry = nodeLegendRegistry.get(type);
  if (entry && entry.color) {
    return entry.color;
  }
  return translateAutoTheme(pref("theme", "auto")) === "dark" ? "#6c757d" : "#8b949e";
}

function nodeThemeTextColor() {
  return translateAutoTheme(pref("theme", "auto")) === "dark" ? "white" : "black";
}

function edgeWidthMode() {
  return String(pref("graph.edgewidth", "flow") || "flow").toLowerCase();
}

function graphTheme() {
  const dark = translateAutoTheme(pref("theme", "auto")) === "dark";
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
      label: false,
      color: dark ? "#e9ecef" : "#111827",
      fontSize: 12,
      textBackgroundColor: dark ? "#0f1216" : "#ffffff",
      textBackgroundOpacity: 0.9,
      textBackgroundPadding: 2,
    },
  };
}

function computeNodeVisualPatch(nodeData) {
  const dark = translateAutoTheme(pref("theme", "auto")) === "dark";
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
    patch.borderWidth = 0.05;
  }
  if (nodeData && (nodeData.reference === "end" || nodeData._querytarget)) {
    patch.borderColor = "#2563eb";
    patch.borderWidth = 0.05;
  }
  if (graphState.targetNodeId && nodeData.id === graphState.targetNodeId) {
    patch.borderColor = dark ? "#f8f9fa" : "#111827";
    patch.borderWidth = 0.06;
  }

  return patch;
}

function getEdgeColor(data) {
  const methods = Array.isArray(data && data.methods) ? data.methods : [];
  for (const rule of edgeColorRules) {
    if (rule.methods.some((method) => methods.includes(method))) {
      return rule.color;
    }
  }
  return translateAutoTheme(pref("theme", "auto")) === "dark" ? "#ffffff" : "#000000";
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
  const widthMode = edgeWidthMode();
  targetGraph.batch(function () {
    targetGraph.edgeIds().forEach(function (edgeId) {
      const data = targetGraph.edgeData.get(edgeId);
      if (!data) {
        return;
      }
      const flow = Number(data.flow);
      const edgeWidth = widthMode === "thin"
        ? 1
        : (Number.isFinite(flow) && flow > 0 ? 1 + Math.log(flow) : 1);
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
  const nodestyle = nodestyleOverride || pref("graph.nodesize", "incoming");
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
  applyNodeStyles(graph, byIdValue("nodesizes", pref("graph.nodesize", "incoming")));
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

function ensureEdgeHoverCard() {
  if (graphState.edgeHoverCard) {
    return graphState.edgeHoverCard;
  }
  const card = document.createElement("div");
  card.id = "graph-edge-hover-card";
  card.className = "card shadow-sm";
  card.style.position = "fixed";
  card.style.display = "none";
  card.style.pointerEvents = "none";
  card.style.zIndex = "1080";
  card.style.maxWidth = "22rem";
  card.style.minWidth = "14rem";
  document.body.appendChild(card);
  graphState.edgeHoverCard = card;
  return card;
}

function hideEdgeHoverCard() {
  if (!graphState.edgeHoverCard) {
    return;
  }
  graphState.edgeHoverCard.style.display = "none";
  graphState.edgeHoverCard.innerHTML = "";
}

function updateEdgeHoverCardPosition(clientPosition) {
  if (!graphState.edgeHoverCard || !clientPosition) {
    return;
  }
  const offset = 14;
  const margin = 12;
  const card = graphState.edgeHoverCard;
  card.style.left = `${Number(clientPosition.x || 0) + offset}px`;
  card.style.top = `${Number(clientPosition.y || 0) + offset}px`;
  const rect = card.getBoundingClientRect();
  let left = Number(clientPosition.x || 0) + offset;
  let top = Number(clientPosition.y || 0) + offset;
  if (left + rect.width + margin > window.innerWidth) {
    left = Math.max(margin, Number(clientPosition.x || 0) - rect.width - offset);
  }
  if (top + rect.height + margin > window.innerHeight) {
    top = Math.max(margin, Number(clientPosition.y || 0) - rect.height - offset);
  }
  card.style.left = `${left}px`;
  card.style.top = `${top}px`;
}

function showEdgeHoverCard(edgeId, clientPosition) {
  const edgeData = graphEdgeData(edgeId);
  if (!edgeData) {
    hideEdgeHoverCard();
    return;
  }
  const methods = Array.isArray(edgeData.methods) ? [...edgeData.methods].sort() : [];
  if (!methods.length) {
    hideEdgeHoverCard();
    return;
  }
  const card = ensureEdgeHoverCard();
  const body = methods.map((method) => `<li class="list-group-item py-1 px-2 border-0 bg-transparent">${escapehtml(String(method))}</li>`).join("");
  card.innerHTML =
    `<div class="card-body p-2">` +
    `<div class="fw-semibold small text-uppercase text-body-secondary mb-2">Edge Methods</div>` +
    `<ul class="list-group list-group-flush small">${body}</ul>` +
    `</div>`;
  card.style.display = "";
  updateEdgeHoverCardPosition(clientPosition);
}

function legendNodeEntries() {
  return Array.from(nodeLegendRegistry.values()).sort((left, right) => left.label.localeCompare(right.label));
}

function legendEdgeEntries() {
  return edgeColorRules.map((rule) => ({
    color: rule.color,
    label: rule.label,
    methods: [...rule.methods],
    description: rule.description,
  }));
}

function legendSwatch(color) {
  const fill = color || (translateAutoTheme(pref("theme", "auto")) === "dark" ? "#6c757d" : "#8b949e");
  return `<span class="rounded-circle border flex-shrink-0" style="display:inline-block;width:2.4rem;height:2.4rem;background:${fill};"></span>`;
}

function renderLegendWindow() {
  const nodeItems = legendNodeEntries()
    .map((entry) => {
      const icon = entry.icon ? `<img src="${escapehtml(entry.icon)}" width="34" height="34" alt="">` : "";
      const description = entry.description ? `<div class="small text-body-secondary">${escapehtml(entry.description)}</div>` : "";
      return (
        `<div class="card mb-2 border-0 bg-body-tertiary">` +
        `<div class="card-body py-2 px-3 d-flex align-items-start gap-2">` +
        `<div class="position-relative flex-shrink-0" style="width:2.75rem;height:2.75rem;">` +
        `<div class="position-absolute top-50 start-50 translate-middle">` +
        `${legendSwatch(entry.color)}` +
        `</div>` +
        `<div class="position-absolute top-50 start-50 d-flex align-items-center justify-content-center" style="width:2.125rem;height:2.125rem;transform:translate(-50%,-54%);">${icon}</div>` +
        `</div>` +
        `<div class="flex-grow-1">` +
        `<div class="fw-semibold">${escapehtml(entry.label)}</div>` +
        `<div class="small font-monospace text-body-secondary">${escapehtml(entry.type)}</div>` +
        `${description}` +
        `</div>` +
        `</div>` +
        `</div>`
      );
    })
    .join("");

  const edgeItems = legendEdgeEntries()
    .map((entry) => {
      const methods = entry.methods.map((method) => `<span class="badge text-bg-light border me-1 mb-1">${escapehtml(method)}</span>`).join("");
      const description = entry.description ? `<div class="small text-body-secondary mt-1">${escapehtml(entry.description)}</div>` : "";
      return (
        `<div class="card mb-2 border-0 bg-body-tertiary">` +
        `<div class="card-body py-2 px-3 d-flex align-items-start gap-2">` +
        `${legendSwatch(entry.color)}` +
        `<div class="flex-grow-1">` +
        `<div class="fw-semibold">${escapehtml(entry.label)}</div>` +
        `<div class="mt-1">${methods}</div>` +
        `${description}` +
        `</div>` +
        `</div>` +
        `</div>`
      );
    })
    .join("");

  return (
    `<div class="container-fluid px-0">` +
    `<div class="row g-3">` +
    `<div class="col-12 col-xl-6">` +
    `<div class="card border-0 shadow-sm">` +
    `<div class="card-header fw-semibold">Node Colors and Icons</div>` +
    `<div class="card-body pb-2">${nodeItems}</div>` +
    `</div>` +
    `</div>` +
    `<div class="col-12 col-xl-6">` +
    `<div class="card border-0 shadow-sm">` +
    `<div class="card-header fw-semibold">Edge Colors</div>` +
    `<div class="card-body pb-2">${edgeItems}</div>` +
    `</div>` +
    `</div>` +
    `</div>` +
    `</div>`
  );
}

async function openLegendWindow() {
  await ensureNodeLegendMetadataLoaded();
  new_window("graph_legend", "Legend", renderLegendWindow(), "center", 640, 960);
}

function initGraphTools() {
  const legendButton = document.getElementById("legendbutton");
  if (legendButton) {
    legendButton.addEventListener("click", openLegendWindow);
  }
}

function initGraphToolsWhenReady() {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initGraphTools, { once: true });
    return;
  }
  ensureNodeLegendMetadataLoaded();
  initGraphTools();
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

function backendNodeId(nodeId) {
  const id = String(nodeId || "");
  return id.startsWith("n") ? id.substring(1) : id;
}

function showNodeDetails(nodeId) {
  fetchJSONOrThrow("api/details/nodeid/" + backendNodeId(nodeId))
    .then(function (data) {
      let windowname = "details_" + nodeId;
      if (prefBool("ui.open.details.in.same.window", true)) {
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
  fetchJSONOrThrow("api/edges/nodeid/" + backendNodeId(edgeData.source) + "," + backendNodeId(edgeData.target))
    .then(function (data) {
      let windowname = "edge_" + edgeData.source + "_to_" + edgeData.target;
      if (prefBool("ui.open.details.in.same.window", true)) {
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

  const routecontents = result.pathNodes.map((nodeId) => backendNodeId(nodeId)).join(",");
  fetchJSONOrThrow("/api/edges/nodeid/" + routecontents)
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
  fetchJSONOrThrow("api/details/nodeid/" + backendNodeId(nodeId))
    .then(function (data) {
      if (data.attributes["distinguishedName"]) {
        set_query(direction === "outbound" ? "start:(distinguishedname=" + data.attributes["distinguishedName"] + ")-[]{1,3}->end:()" : "start:(distinguishedname=" + data.attributes["distinguishedName"] + ")<-[]{1,3}-end:()");
      } else if (data.attributes["objectSid"]) {
        set_query(direction === "outbound" ? "start:(objectSid=" + data.attributes["objectSid"] + ")-[]{1,3}->end:()" : "start:(objectSid=" + data.attributes["objectSid"] + ")<-[]{1,3}-end:()");
      } else if (data.attributes["objectGuid"]) {
        set_query(direction === "outbound" ? "start:(objectGuid=" + data.attributes["objectGuid"] + ")-[]{1,3}->end:()" : "start:(objectGuid=" + data.attributes["objectGuid"] + ")<-[]{1,3}-end:()");
      } else {
        set_query(direction === "outbound" ? "start:(_id=" + backendNodeId(nodeId) + ")-[]{1,3}->end:()" : "start:(_id=" + backendNodeId(nodeId) + ")<-[]{1,3}-end:()");
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
    hideEdgeHoverCard();
    graphState.selectedEdgeId = evt.edgeId;
    selectGraphNodes([]);
    clearHighlightedEdges();
    showEdgeDetails(evt.edgeId);
  });

  graph.onBackgroundClick(function () {
    hideGraphContextMenu();
    hideEdgeHoverCard();
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
      hideEdgeHoverCard();
      return;
    }
    graph.setEdgeHovered(evt.edgeId, !!evt.hovered);
    if (evt.hovered) {
      showEdgeHoverCard(evt.edgeId, evt.clientPosition || { x: 0, y: 0 });
      return;
    }
    hideEdgeHoverCard();
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
  hideEdgeHoverCard();
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
  graphDebugLog("create-graph", {
    elementCount: Array.isArray(elements) ? elements.length : 0,
    nodeCount: typeof graph.nodeIds === "function" ? graph.nodeIds().length : 0,
    edgeCount: typeof graph.edgeIds === "function" ? graph.edgeIds().length : 0,
  });
  bindGraphEvents();
  refreshGraphTheme();
  return graph;
}

function selectedGraphLayout() {
  const preferred = String(pref(GRAPH_LAYOUT_PREF, DEFAULT_GRAPH_LAYOUT) || "").trim();
  if (preferred) {
    return preferred;
  }
  const select = graphLayoutSelect();
  if (select && select.value) {
    return select.value;
  }
  return preferred || DEFAULT_GRAPH_LAYOUT;
}

function updateGraphLayoutChoices() {
  const select = graphLayoutSelect();
  if (!select) {
    return;
  }
  const definitions = graphLayoutDefinitions();
  const layoutKeys = Object.keys(definitions);
  select.innerHTML = "";
  if (!layoutKeys.length) {
    return;
  }
  const currentValue = String(selectedGraphLayout() || DEFAULT_GRAPH_LAYOUT);
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
  const firstLayout = layoutKeys[0] || DEFAULT_GRAPH_LAYOUT;
  const fallback = definitions[DEFAULT_GRAPH_LAYOUT] ? DEFAULT_GRAPH_LAYOUT : firstLayout;
  select.value = fallback;
  persistPreference(GRAPH_LAYOUT_PREF, fallback);
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
  graphDebugLog("apply-layout-positions:start", {
    fitGraph: !!fitGraph,
    summary: graphPositionSummary(positions),
  });
  if (typeof targetGraph.clearCustomBBox === "function") {
    targetGraph.clearCustomBBox();
  }
  targetGraph.batch(function () {
    Object.entries(positions || {}).forEach(([id, pos]) => {
      targetGraph.setNodePosition(id, pos, { markDirty: false });
    });
  });
  if (typeof targetGraph.rebuildGraph === "function") {
    targetGraph.rebuildGraph();
  }
  targetGraph.refresh();
  if (fitGraph) {
    targetGraph.fit(undefined, 30);
  }
  graphDebugLog("apply-layout-positions:end", {
    bbox: typeof targetGraph.boundingBox === "function" ? targetGraph.boundingBox() : null,
    customBBox: targetGraph.customBBox || null,
  });
}

function graphNeedsSeedLayout(targetGraph) {
  if (!targetGraph || typeof targetGraph.boundingBox !== "function") {
    return false;
  }
  const bbox = targetGraph.boundingBox();
  return !!bbox && bbox.w === 0 && bbox.h === 0;
}

function seedGraphLayout(targetGraph) {
  if (!targetGraph || typeof targetGraph.nodeIds !== "function") {
    return;
  }
  const ids = targetGraph.nodeIds();
  if (!ids.length) {
    return;
  }
  const goldenAngle = Math.PI * (3 - Math.sqrt(5));
  const spacing = ids.length > 5000 ? 18 : 24;
  targetGraph.batch(function () {
    ids.forEach(function (id, index) {
      const radius = spacing * Math.sqrt(index + 1);
      const angle = index * goldenAngle;
      targetGraph.setNodePosition(id, {
        x: Math.cos(angle) * radius,
        y: Math.sin(angle) * radius,
      }, { markDirty: false });
    });
  });
  graphDebugLog("seed-layout", {
    nodeCount: ids.length,
    bboxAfterSeed: typeof targetGraph.boundingBox === "function" ? targetGraph.boundingBox() : null,
  });
  if (typeof targetGraph.rebuildGraph === "function") {
    targetGraph.rebuildGraph();
  }
  targetGraph.refresh();
  if (typeof targetGraph.fit === "function") {
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
    graphDebugLog("run-wasm-layout:connector-missing", {
      layoutKey,
      hasConnector: !!graphState.layoutConnector,
      ready: !!graphState.layoutConnectorReady,
    });
    throw new Error("WASM layout connector is not available");
  }
  if (graphNeedsSeedLayout(targetGraph)) {
    seedGraphLayout(targetGraph);
  }
  const options = layoutOptionsForLayout(layoutKey);
  const controller = new AbortController();
  graphState.activeLayoutAbort = controller;
  try {
    const definition = graphLayoutDefinition(layoutKey);
    const supportsAnimation = !!(definition && definition.supports_animation);
    graphDebugLog("run-wasm-layout:start", {
      layoutKey,
      supportsAnimation,
      nodeCount: typeof targetGraph.nodeIds === "function" ? targetGraph.nodeIds().length : 0,
      edgeCount: typeof targetGraph.edgeIds === "function" ? targetGraph.edgeIds().length : 0,
      bbox: typeof targetGraph.boundingBox === "function" ? targetGraph.boundingBox() : null,
    });
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
      graphDebugLog("run-wasm-layout:done", {
        layoutKey,
        summary: graphPositionSummary(finalFrame.positions),
      });
      return;
    }
    const result = await graphState.layoutConnector.run(targetGraph, layoutKey, options, controller.signal);
    applyLayoutPositions(targetGraph, result.positions, true);
    graphDebugLog("run-wasm-layout:done", {
      layoutKey,
      summary: graphPositionSummary(result.positions),
    });
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
  graphState.layoutRunToken += 1;
  const runToken = graphState.layoutRunToken;
  const layoutKey = selectedGraphLayout();
  stopActiveGraphLayout();
  graphState.layoutPending = false;
  graphDebugLog("run-selected-layout:start", {
    runToken,
    layoutKey,
    connectorReady: !!graphState.layoutConnectorReady,
    hasConnector: !!graphState.layoutConnector,
  });
  busystatus("Running graph layout");
  try {
    if (!isWasmLayout(layoutKey)) {
      throw new Error(`Unsupported layout: ${layoutKey}`);
    }
    await runWasmLayout(graph, layoutKey);
  } catch (err) {
    graphDebugLog("run-selected-layout:error", {
      runToken,
      layoutKey,
      error: err && err.message ? err.message : String(err),
    });
    toast("Graph layout failed", err && err.message ? err.message : String(err), "error");
  } finally {
    graphDebugLog("run-selected-layout:finish", {
      runToken,
      layoutKey,
      bbox: typeof graph?.boundingBox === "function" ? graph.boundingBox() : null,
      pending: !!graphState.layoutPending,
    });
    if (graphState.layoutRunToken === runToken) {
      const statusEl = document.getElementById("status");
      if (statusEl) {
        statusEl.style.display = "none";
      }
    }
  }
}

function initGraphLayoutUI() {
  updateGraphLayoutChoices();
  renderGraphLayoutOptions();

  const select = graphLayoutSelect();
  if (select) {
    select.addEventListener("change", () => {
      persistPreference(GRAPH_LAYOUT_PREF, select.value || DEFAULT_GRAPH_LAYOUT);
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
    workerURL: `sigma/layout-worker.js?v=${encodeURIComponent(LAYOUT_ASSET_VERSION)}`,
    workerCount,
  });

  graphState.layoutConnector.init()
    .then((payload) => {
      graphState.layoutConnectorReady = true;
      setGraphLayoutDefinitions(payload && payload.layouts ? payload.layouts : []);
      graphDebugLog("layout-connector:ready", {
        layoutCount: Object.keys(graphLayoutDefinitions()).length,
        pending: !!graphState.layoutPending,
        hasGraph: !!graph,
      });
      const currentLayout = selectedGraphLayout();
      if (!graphLayoutDefinition(currentLayout)) {
        persistPreference(GRAPH_LAYOUT_PREF, DEFAULT_GRAPH_LAYOUT);
        const select = graphLayoutSelect();
        if (select) {
          select.value = DEFAULT_GRAPH_LAYOUT;
        }
        renderGraphLayoutOptions();
      }
      if (graph && (graphState.layoutPending || graphNeedsSeedLayout(graph))) {
        runSelectedGraphLayout();
      }
    })
    .catch((err) => {
      graphState.layoutConnectorReady = false;
      graphDebugLog("layout-connector:error", {
        error: err && err.message ? err.message : String(err),
      });
      toast(
        "Graph layouts unavailable",
        err && err.message ? err.message : String(err),
        "error"
      );
    });
}

async function initgraph(data) {
  await ensureNodeLegendMetadataLoaded();
  createAdalancheGraph(data);
  graphDebugLog("initgraph", {
    connectorReady: !!graphState.layoutConnectorReady,
    hasConnector: !!graphState.layoutConnector,
  });
  if (!graphState.layoutConnectorReady) {
    graphState.layoutPending = true;
    busystatus("Running graph layout");
    seedGraphLayout(graph);
    graphDebugLog("initgraph:seed-pending", {
      bbox: typeof graph.boundingBox === "function" ? graph.boundingBox() : null,
    });
    return;
  }
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
    .finally(function () {
      initGraphLayoutUIWhenReady();
      initGraphToolsWhenReady();
    });
} else {
  initGraphLayoutUIWhenReady();
  initGraphToolsWhenReady();
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
