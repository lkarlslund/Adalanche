(function () {
  const Graphology = (typeof window !== "undefined" && window.graphology)
    ? (window.graphology.Graph || window.graphology)
    : null;
  const SigmaRenderer = (typeof window !== "undefined" && window.Sigma) ? window.Sigma : null;

  if (!Graphology || !SigmaRenderer) {
    return;
  }

  const RenderMetrics = (typeof window !== "undefined" && window.WorkspaceRenderMetrics)
    ? window.WorkspaceRenderMetrics
    : null;
  const Rendering = (typeof window !== "undefined" && window.WorkspaceSigmaRendering)
    ? window.WorkspaceSigmaRendering
    : null;
  const createWorkspaceSigmaLayout = (typeof window !== "undefined" && window.createWorkspaceSigmaLayout)
    ? window.createWorkspaceSigmaLayout
    : null;
  const createWorkspaceSigmaOverlays = (typeof window !== "undefined" && window.createWorkspaceSigmaOverlays)
    ? window.createWorkspaceSigmaOverlays
    : null;
  const createWorkspaceSigmaInteractions = (typeof window !== "undefined" && window.createWorkspaceSigmaInteractions)
    ? window.createWorkspaceSigmaInteractions
    : null;
  const createWorkspaceSigmaRenderer = (typeof window !== "undefined" && window.createWorkspaceSigmaRenderer)
    ? window.createWorkspaceSigmaRenderer
    : null;
  const createWorkspaceSigmaViewport = (typeof window !== "undefined" && window.createWorkspaceSigmaViewport)
    ? window.createWorkspaceSigmaViewport
    : null;
  const createWorkspaceSigmaNodeImageProgram = (typeof window !== "undefined" && window.createWorkspaceSigmaNodeImageProgram)
    ? window.createWorkspaceSigmaNodeImageProgram
    : null;
  if (!RenderMetrics) {
    return;
  }
  if (
    !Rendering ||
    typeof createWorkspaceSigmaLayout !== "function" ||
    typeof createWorkspaceSigmaOverlays !== "function" ||
    typeof createWorkspaceSigmaInteractions !== "function" ||
    typeof createWorkspaceSigmaRenderer !== "function" ||
    typeof createWorkspaceSigmaViewport !== "function" ||
    typeof createWorkspaceSigmaNodeImageProgram !== "function"
  ) {
    return;
  }

  function isObject(value) {
    return !!value && typeof value === "object";
  }

  function toElementArray(value) {
    if (!value) return [];
    if (Array.isArray(value)) return value;
    if (typeof value[Symbol.iterator] === "function") return Array.from(value);
    if (typeof value.length === "number") {
      const out = [];
      for (let i = 0; i < value.length; i += 1) {
        if (value[i]) out.push(value[i]);
      }
      return out;
    }
    return [];
  }

  function pointToSegmentDistance(pointX, pointY, startX, startY, endX, endY) {
    const dx = endX - startX;
    const dy = endY - startY;
    if (dx === 0 && dy === 0) {
      const px = pointX - startX;
      const py = pointY - startY;
      return Math.sqrt((px * px) + (py * py));
    }
    const t = Math.max(0, Math.min(1, (((pointX - startX) * dx) + ((pointY - startY) * dy)) / ((dx * dx) + (dy * dy))));
    const nearestX = startX + (t * dx);
    const nearestY = startY + (t * dy);
    const distX = pointX - nearestX;
    const distY = pointY - nearestY;
    return Math.sqrt((distX * distX) + (distY * distY));
  }

  class WorkspaceSigmaGraph {
    constructor(config) {
      const cfg = isObject(config) ? config : {};
      this.container = cfg.container;
      this.graph = new Graphology.Graph({ multi: false, type: "mixed" });
      this.renderer = new SigmaRenderer(this.graph, this.container, {
        allowInvalidContainer: true,
        renderLabels: true,
        renderEdgeLabels: true,
        enableEdgeHoverEvents: "debounce",
        labelRenderedSizeThreshold: 8,
        labelDensity: 1,
        defaultNodeType: "image",
        defaultEdgeType: "line",
        nodeProgramClasses: {
          image: createWorkspaceSigmaNodeImageProgram(),
        },
        zIndex: true,
      });
      this.batchDepth = 0;
      this.pendingRefresh = false;
      this.nodeData = new Map();
      this.edgeData = new Map();
      this.listeners = new Map();
      this.themeConfig = Rendering.defaultThemeConfig();
      this.selectedNodeIDsSet = new Set();
      this.hoveredNodeId = "";
      this.hoveredEdgeId = "";
      this.zoomValue = 1;
      this.minZoomValue = 0.05;
      this.maxZoomValue = 4;
      this.iconMinZoom = Number.isFinite(Number(cfg.iconMinZoom)) ? Number(cfg.iconMinZoom) : 0;
      this.iconMinScreenSize = Number.isFinite(Number(cfg.iconMinScreenSize)) ? Number(cfg.iconMinScreenSize) : 18;
      this.canDragNode = typeof cfg.canDragNode === "function" ? cfg.canDragNode : null;
      this.customBBox = null;
      this.dragState = null;
      this.suppressNextClick = false;
      this.selectionLayer = null;
      this.selectionState = null;
      this.iconRenderVisible = null;
      this.graphStructureDirty = false;
      this.overlays = createWorkspaceSigmaOverlays(this);
      this.interactions = createWorkspaceSigmaInteractions(this);
      this.rendererConfig = createWorkspaceSigmaRenderer(this);
      this.viewport = createWorkspaceSigmaViewport(this);

      this.overlays.createSelectionLayer();
      this.interactions.install();
      if (cfg.theme && typeof cfg.theme === "object") {
        this.setThemeConfig(cfg.theme);
      }
      if (Array.isArray(cfg.elements) && cfg.elements.length > 0) {
        this.add(cfg.elements);
      }
    }

    relativePoint(event) {
      return RenderMetrics.relativePoint(this.container, event);
    }

    getNodeAtPosition(x, y) {
      if (typeof this.renderer.getNodeAtPosition === "function") {
        return this.renderer.getNodeAtPosition(x, y) || "";
      }
      return "";
    }

    getEdgeAtPosition(x, y, extraTolerance) {
      const pointX = Number(x);
      const pointY = Number(y);
      if (!Number.isFinite(pointX) || !Number.isFinite(pointY) || !this.renderer || typeof this.renderer.graphToViewport !== "function") {
        return "";
      }
      const hitTolerance = Math.max(0, Number(extraTolerance || 0));
      let bestEdgeId = "";
      let bestDistance = Number.POSITIVE_INFINITY;
      for (const edgeId of this.edgeIds()) {
        if (!this.graph.hasEdge(edgeId)) continue;
        const endpoints = this.edgeEndpoints(edgeId);
        if (!endpoints.source || !endpoints.target || !this.graph.hasNode(endpoints.source) || !this.graph.hasNode(endpoints.target)) continue;
        const sourcePos = this.nodePosition(endpoints.source);
        const targetPos = this.nodePosition(endpoints.target);
        const sourceViewport = this.renderer.graphToViewport(sourcePos) || {};
        const targetViewport = this.renderer.graphToViewport(targetPos) || {};
        const sx = Number(sourceViewport.x);
        const sy = Number(sourceViewport.y);
        const tx = Number(targetViewport.x);
        const ty = Number(targetViewport.y);
        if (!Number.isFinite(sx) || !Number.isFinite(sy) || !Number.isFinite(tx) || !Number.isFinite(ty)) continue;
        const visibleWidth = Math.max(1, Number(this.themeConfig && this.themeConfig.edge && this.themeConfig.edge.width || 2));
        const allowedDistance = (visibleWidth / 2) + hitTolerance;
        const distance = pointToSegmentDistance(pointX, pointY, sx, sy, tx, ty);
        if (distance <= allowedDistance && distance < bestDistance) {
          bestDistance = distance;
          bestEdgeId = edgeId;
        }
      }
      return bestEdgeId;
    }

    nodeIDsInViewportRect(rect) {
      if (!rect || !this.renderer) return [];
      const ids = [];
      for (const id of this.nodeIds()) {
        const metrics = RenderMetrics.nodeScreenMetrics(this.renderer, this, id);
        if (RenderMetrics.rectIntersectsNode(rect, metrics)) {
          ids.push(id);
        }
      }
      return ids;
    }

    nodeIds() {
      return Array.from(this.nodeData.keys()).filter((id) => this.nodeVisible(id));
    }

    edgeIds() {
      return Array.from(this.edgeData.keys()).filter((id) => this.edgeVisible(id));
    }

    hasNode(id) {
      return this.nodeVisible(id);
    }

    hasEdge(id) {
      return this.edgeVisible(id);
    }

    nodePosition(id) {
      const attrs = this.graph.getNodeAttributes(id);
      return {
        x: Number(attrs.x || 0),
        y: Number(attrs.y || 0),
      };
    }

    setNodePosition(id, pos, opts) {
      if (!this.nodeData.has(id)) return;
      const x = Number(pos && pos.x);
      const y = Number(pos && pos.y);
      if (!Number.isFinite(x) || !Number.isFinite(y)) return;
      const data = this.nodeData.get(id);
      data.x = x;
      data.y = y;
      if (this.graph.hasNode(id)) {
        this.graph.setNodeAttribute(id, "x", x);
        this.graph.setNodeAttribute(id, "y", y);
      }
      if (!opts || opts.markDirty !== false) {
        data.positionDirty = true;
      }
      this.queueRefresh();
    }

    dirtyNodeIDs() {
      return this.nodeIds().filter((id) => {
        const data = this.nodeData.get(id);
        return !!(data && data.positionDirty);
      });
    }

    clearNodePositionDirty(id) {
      const key = String(id || "");
      if (!key || !this.nodeData.has(key)) return;
      const data = this.nodeData.get(key);
      if (!data) return;
      data.positionDirty = false;
    }

    edgeEndpoints(id) {
      const attrs = this.edgeData.get(id) || {};
      return {
        source: String(attrs.source || ""),
        target: String(attrs.target || ""),
      };
    }

    neighborhoodNodeIds(id) {
      const ids = new Set();
      this.graph.forEachNeighbor(id, (neighborId) => ids.add(neighborId));
      ids.delete(id);
      return Array.from(ids);
    }

    degree(id) {
      if (!this.nodeVisible(id)) return 0;
      return typeof this.graph.degree === "function" ? this.graph.degree(id) : this.neighborhoodNodeIds(id).length;
    }

    nodeVisible(id) {
      const item = this.nodeData.get(String(id || ""));
      return !!item && !item.hidden;
    }

    edgeVisible(id) {
      const item = this.edgeData.get(String(id || ""));
      if (!item || item.hidden) return false;
      return this.nodeVisible(item.source) && this.nodeVisible(item.target);
    }

    nodeGraphAttributes(id) {
      const data = this.nodeData.get(String(id || "")) || {};
      return {
        id: String(id || ""),
        x: Number.isFinite(Number(data.x)) ? Number(data.x) : 0,
        y: Number.isFinite(Number(data.y)) ? Number(data.y) : 0,
        label: data.label || String(id || ""),
        color: data.color || "#6c757d",
        size: 10,
      };
    }

    edgeGraphAttributes(id) {
      const data = this.edgeData.get(String(id || "")) || {};
      return {
        id: String(id || ""),
        source: String(data.source || ""),
        target: String(data.target || ""),
        label: data.label || "",
        color: data.color || "#6c757d",
        size: Number(this.themeConfig.edge.width || 2),
        type: Rendering.edgeTypeFromTheme(this.themeConfig),
      };
    }

    syncGraphVisibility() {
      if (!this.graphStructureDirty) return;
      for (const [id] of this.edgeData.entries()) {
        if (!this.edgeVisible(id) && this.graph.hasEdge(id)) {
          this.graph.dropEdge(id);
        }
      }
      for (const [id] of this.nodeData.entries()) {
        const visible = this.nodeVisible(id);
        if (!visible && this.graph.hasNode(id)) {
          this.graph.dropNode(id);
          continue;
        }
        if (visible && !this.graph.hasNode(id)) {
          this.graph.addNode(id, this.nodeGraphAttributes(id));
        }
      }
      for (const [id] of this.edgeData.entries()) {
        if (!this.edgeVisible(id) || this.graph.hasEdge(id)) continue;
        const attrs = this.edgeGraphAttributes(id);
        if (!this.graph.hasNode(attrs.source) || !this.graph.hasNode(attrs.target)) continue;
        try {
          this.graph.addEdgeWithKey(id, attrs.source, attrs.target, attrs);
        } catch (_err) {}
      }
      this.graphStructureDirty = false;
    }

    add(elements) {
      const items = Array.isArray(elements) ? elements : [elements];
      this.batch(() => {
        for (const item of items) {
          if (!item || !item.data || !item.data.id) continue;
          const data = { ...item.data, positionDirty: false };
          const id = String(data.id);
          const position = isObject(item.position) ? item.position : null;
          if (data.source && data.target) {
            if (this.edgeData.has(id)) continue;
            this.edgeData.set(id, data);
            this.graphStructureDirty = true;
            continue;
          }
          if (this.nodeData.has(id)) continue;
          data.x = position && Number.isFinite(Number(position.x)) ? Number(position.x) : 0;
          data.y = position && Number.isFinite(Number(position.y)) ? Number(position.y) : 0;
          this.nodeData.set(id, data);
          this.graphStructureDirty = true;
        }
      });
      this.queueRefresh();
    }

    clearGraph() {
      this.batch(() => {
        for (const id of this.edgeIds()) {
          this.removeElement(id);
        }
        for (const id of this.nodeIds()) {
          this.removeElement(id);
        }
      });
    }

    rebuildGraph() {
      if (this.graph && typeof this.graph.clear === "function") {
        this.graph.clear();
      }
      this.graphStructureDirty = true;
      this.queueRefresh();
    }

    removeElement(id) {
      if (this.edgeData.has(id)) {
        this.edgeData.delete(id);
        if (this.hoveredEdgeId === String(id || "")) this.hoveredEdgeId = "";
        this.graphStructureDirty = true;
      } else if (this.nodeData.has(id)) {
        this.nodeData.delete(id);
        this.selectedNodeIDsSet.delete(String(id || ""));
        this.graphStructureDirty = true;
      }
      this.queueRefresh();
    }

    batch(fn) {
      this.batchDepth += 1;
      try {
        if (typeof fn === "function") fn();
      } finally {
        this.batchDepth -= 1;
        if (this.batchDepth <= 0 && this.pendingRefresh) {
          this.pendingRefresh = false;
          this.refresh();
        }
      }
    }

    queueRefresh() {
      if (this.batchDepth > 0) {
        this.pendingRefresh = true;
        return;
      }
      this.refresh();
    }

    refresh() {
      this.syncGraphVisibility();
      this.applyStyles();
      if (this.customBBox && typeof this.renderer.setCustomBBox === "function") {
        this.renderer.setCustomBBox(this.customBBox);
      }
      if (typeof this.renderer.refresh === "function") this.renderer.refresh();
    }

    clearCustomBBox() {
      this.customBBox = null;
      if (this.renderer && typeof this.renderer.setCustomBBox === "function") {
        this.renderer.setCustomBBox(null);
      }
    }

    setThemeConfig(theme) {
      this.themeConfig = Rendering.normalizeThemeConfig(theme);
      this.applyStyles();
    }

    applyStyles() {
      this.rendererConfig.applyStyles();
    }

    iconRenderingEnabled() {
      const nodeTheme = this.themeConfig && this.themeConfig.node ? this.themeConfig.node : {};
      const hasIconTheme = !!nodeTheme.backgroundImage && nodeTheme.backgroundImage !== "none";
      if (!hasIconTheme) return false;
      if (this.iconMinZoom > 0 && Number(this.zoomValue || 0) < this.iconMinZoom) return false;
      return true;
    }

    configureRenderer() {
      this.rendererConfig.configure();
    }

    boundingBox(ids) {
      const nodeIds = (Array.isArray(ids) && ids.length > 0 ? ids : this.nodeIds()).filter((id) => this.nodeData.has(id));
      if (nodeIds.length === 0) {
        return { x1: 0, y1: 0, x2: 0, y2: 0, w: 0, h: 0 };
      }
      let x1 = Number.POSITIVE_INFINITY;
      let y1 = Number.POSITIVE_INFINITY;
      let x2 = Number.NEGATIVE_INFINITY;
      let y2 = Number.NEGATIVE_INFINITY;
      for (const id of nodeIds) {
        const pos = this.nodePosition(id);
        x1 = Math.min(x1, pos.x);
        y1 = Math.min(y1, pos.y);
        x2 = Math.max(x2, pos.x);
        y2 = Math.max(y2, pos.y);
      }
      return { x1, y1, x2, y2, w: x2 - x1, h: y2 - y1 };
    }

    fit(collection, padding) {
      const bbox = collection && typeof collection.boundingBox === "function"
        ? collection.boundingBox()
        : this.boundingBox();
      this.fitBounds(bbox, padding);
    }

    fitBounds(bbox, padding) {
      this.viewport.fitBounds(bbox, padding);
    }

    center() {
      this.viewport.center();
    }

    viewportVisibleCenter() {
      return this.viewport.viewportVisibleCenter();
    }

    viewportInsets() {
      return this.viewport.viewportInsets();
    }

    resize() {
      this.refresh();
    }

    extent() {
      return this.boundingBox();
    }

    width() {
      return Number(this.container && this.container.clientWidth) || 0;
    }

    height() {
      return Number(this.container && this.container.clientHeight) || 0;
    }

    minZoom() {
      return this.minZoomValue;
    }

    maxZoom() {
      return this.maxZoomValue;
    }

    zoom(value) {
      const camera = this.renderer.getCamera();
      if (value === undefined) return this.zoomValue;
      const next = RenderMetrics.clamp(Number(value) || 1, this.minZoomValue, this.maxZoomValue);
      this.zoomValue = next;
      if (camera && typeof camera.setState === "function") {
        const state = camera.getState();
        camera.setState({ ...state, ratio: 1 / next });
      }
      return this.zoomValue;
    }

    pan(value) {
      if (value === undefined) return { x: 0, y: 0 };
      return value;
    }

    updateNodeData(id, patch) {
      this.updateElementData("node", id, patch);
    }

    updateEdgeData(id, patch) {
      this.updateElementData("edge", id, patch);
    }

    updateElementData(kind, id, patch) {
      const key = String(id || "");
      const isNode = kind === "node";
      const store = isNode ? this.nodeData : this.edgeData;
      if (!key || !store.has(key) || !isObject(patch)) return;
      const data = store.get(key);
      Object.assign(data, patch);
      if (Object.prototype.hasOwnProperty.call(patch, "hidden")) {
        this.graphStructureDirty = true;
      }
      const attrs = {};
      if (Object.prototype.hasOwnProperty.call(patch, "label")) attrs.label = patch.label || key;
      if (Object.prototype.hasOwnProperty.call(patch, "color")) attrs.color = patch.color || "#6c757d";
      if (Object.keys(attrs).length > 0) {
        if (isNode) {
          if (this.graph.hasNode(key)) this.graph.mergeNodeAttributes(key, attrs);
        } else if (this.graph.hasEdge(key)) {
          this.graph.mergeEdgeAttributes(key, attrs);
        }
      }
      this.queueRefresh();
    }

    setSelectedNodeIDs(ids) {
      const next = new Set((Array.isArray(ids) ? ids : []).map((id) => String(id || "")).filter((id) => this.nodeData.has(id)));
      const prev = this.selectedNodeIDs();
      const same = prev.length === next.size && prev.every((id) => next.has(id));
      if (same) return;
      this.selectedNodeIDsSet = next;
      this.queueRefresh();
    }

    selectedNodeIDs() {
      return Array.from(this.selectedNodeIDsSet.values());
    }

    setNodeHidden(id, hidden) {
      const key = String(id || "");
      if (!key || !this.nodeData.has(key)) return;
      const data = this.nodeData.get(key);
      if (!!data.hidden === !!hidden) return;
      data.hidden = !!hidden;
      this.graphStructureDirty = true;
      this.queueRefresh();
    }

    setEdgeHidden(id, hidden) {
      const key = String(id || "");
      if (!key || !this.edgeData.has(key)) return;
      const data = this.edgeData.get(key);
      if (!!data.hidden === !!hidden) return;
      data.hidden = !!hidden;
      this.graphStructureDirty = true;
      this.queueRefresh();
    }

    clearHoveredEdges() {
      if (!this.hoveredEdgeId) return;
      this.hoveredEdgeId = "";
      this.queueRefresh();
    }

    exportLayoutData() {
      return {
        nodes: this.nodeIds().map((id) => {
          const pos = this.nodePosition(id);
          const data = this.nodeData.get(id) || {};
          return {
            id,
            x: Number(pos.x || 0),
            y: Number(pos.y || 0),
            render_size: Number(data.renderSize || 10),
            label: String(data.label || id),
            is_start: !!(data.reference === "start" || data._querysource),
            is_end: !!(data.reference === "end" || data._querytarget),
            selected: this.selectedNodeIDsSet.has(id),
          };
        }),
        edges: this.edgeIds().map((id) => {
          const endpoints = this.edgeEndpoints(id);
          return {
            id,
            source: endpoints.source,
            target: endpoints.target,
          };
        }),
      };
    }

    layout(options) {
      return createWorkspaceSigmaLayout(this.layoutContext(), options);
    }

    layoutContext() {
      return {
        graph: this.graph,
        notify: this.notify.bind(this),
        refresh: this.refresh.bind(this),
        batch: this.batch.bind(this),
        rebuildGraph: this.rebuildGraph.bind(this),
        nodeIds: this.nodeIds.bind(this),
        edgeIds: this.edgeIds.bind(this),
        nodePosition: this.nodePosition.bind(this),
        setNodePosition: this.setNodePosition.bind(this),
        edgeEndpoints: this.edgeEndpoints.bind(this),
        degree: this.degree.bind(this),
        breadthFirstLevels: this.breadthFirstLevels.bind(this),
      };
    }

    breadthFirstLevels(rootIds) {
      const levels = new Map();
      const queue = [];
      const visited = new Set();
      const roots = Array.isArray(rootIds) && rootIds.length > 0 ? rootIds : this.nodeIds().slice(0, 1);
      for (const id of roots) {
        if (!this.nodeData.has(id)) continue;
        visited.add(id);
        queue.push({ id, level: 0 });
      }
      while (queue.length > 0) {
        const current = queue.shift();
        if (!levels.has(current.level)) levels.set(current.level, []);
        levels.get(current.level).push(current.id);
        for (const neighbor of this.neighborhoodNodeIds(current.id)) {
          if (visited.has(neighbor)) continue;
          visited.add(neighbor);
          queue.push({ id: neighbor, level: current.level + 1 });
        }
      }
      for (const id of this.nodeIds()) {
        if (visited.has(id)) continue;
        const level = levels.size;
        if (!levels.has(level)) levels.set(level, []);
        levels.get(level).push(id);
      }
      return levels;
    }

    subscribe(eventName, handler) {
      const key = String(eventName || "").trim();
      if (!key || typeof handler !== "function") return () => {};
      if (!this.listeners.has(key)) this.listeners.set(key, []);
      const list = this.listeners.get(key);
      list.push(handler);
      return () => {
        const current = this.listeners.get(key) || [];
        const next = current.filter((fn) => fn !== handler);
        if (next.length > 0) {
          this.listeners.set(key, next);
        } else {
          this.listeners.delete(key);
        }
      };
    }

    notify(eventName, payload) {
      const key = String(eventName || "").trim();
      if (!key) return;
      const listeners = this.listeners.get(key) || [];
      for (const handler of listeners) {
        handler(payload || {});
      }
    }

    setEdgeHovered(edgeId, hovered) {
      const id = String(edgeId || "").trim();
      if (!id || !this.edgeData.has(id)) return;
      const next = hovered ? id : "";
      if (this.hoveredEdgeId === next) return;
      this.hoveredEdgeId = next;
      this.queueRefresh();
    }

    kill() {
      if (this.interactions) this.interactions.destroy();
      if (this.overlays) this.overlays.destroy();
      if (this.renderer && typeof this.renderer.kill === "function") {
        this.renderer.kill();
      }
    }
  }

  const eventSubscriptions = {
    onViewportChanged: "viewportchanged",
    onLayoutStateChanged: "layoutstatechanged",
    onNodeClick: "nodeclick",
    onEdgeClick: "edgeclick",
    onBackgroundClick: "backgroundclick",
    onNodeContextMenu: "nodecontextmenu",
    onEdgeContextMenu: "edgecontextmenu",
    onSelectionBox: "selectionbox",
    onNodeDragStart: "nodedragstart",
    onNodeDragEnd: "nodedragend",
    onEdgeHoverChanged: "edgehoverchanged",
  };

  Object.entries(eventSubscriptions).forEach(([methodName, eventName]) => {
    WorkspaceSigmaGraph.prototype[methodName] = function subscribeToWorkspaceGraphEvent(handler) {
      return this.subscribe(eventName, handler);
    };
  });

  window.createWorkspaceSigmaGraph = function createWorkspaceSigmaGraph(config) {
    return new WorkspaceSigmaGraph(config);
  };
  if (typeof window.createWorkspaceGraph !== "function") {
    window.createWorkspaceGraph = window.createWorkspaceSigmaGraph;
  }
}());
