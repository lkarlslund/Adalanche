(function () {
  const RenderMetrics = (typeof window !== "undefined" && window.WorkspaceRenderMetrics)
    ? window.WorkspaceRenderMetrics
    : null;
  const Rendering = (typeof window !== "undefined" && window.WorkspaceSigmaRendering)
    ? window.WorkspaceSigmaRendering
    : null;
  const debugEnabled = typeof window !== "undefined" && /\bdebug=1\b/.test(String((window.location && window.location.search) || ""));

  if (!RenderMetrics || !Rendering) {
    return;
  }

  function debugLog(label, payload) {
    if (!debugEnabled || typeof console === "undefined" || typeof console.debug !== "function") return;
    console.debug(`[workspace debug ${label}]`, payload || {});
  }

  // The renderer writes what sigma draws into the graph's attributes; the
  // styles declared in sigma-graph-rendering.js read them.
  function createWorkspaceSigmaRenderer(graph) {
    return {
      applyStyles() {
        const nodeTheme = graph.themeConfig.node;
        const selectedNodeTheme = graph.themeConfig.selectedNode;
        const edgeTheme = graph.themeConfig.edge;
        const hoveredEdgeTheme = graph.themeConfig.hoveredEdge;
        const head = Rendering.edgeTypeFromTheme(graph.themeConfig) === "arrow" ? "arrow" : "none";
        const showIcons = typeof graph.iconRenderingEnabled === "function"
          ? graph.iconRenderingEnabled()
          : (!!nodeTheme.backgroundImage && nodeTheme.backgroundImage !== "none");
        graph.iconRenderVisible = showIcons;
        const labelColor = String(nodeTheme.color || "#000000");
        const labelSize = Math.max(1, Number(nodeTheme.fontSize || 11));

        for (const [id, data] of graph.nodeData.entries()) {
          if (!graph.graph.hasNode(id)) {
            continue;
          }
          const selected = graph.selectedNodeIDsSet.has(id);
          const borderWidth = selected
            ? Math.max(Number(data.borderWidth || 0), 0.045)
            : Number(data.borderWidth || 0);
          graph.graph.mergeNodeAttributes(id, {
            label: nodeTheme.label ? (data.label || id) : "",
            color: data.color || nodeTheme.backgroundColor || "#6c757d",
            size: Number(data.renderSize || RenderMetrics.baseNodeSize(selected)),
            image: showIcons ? String(data.iconFull || "").trim() : "",
            borderColor: selected
              ? (selectedNodeTheme.borderColor || "#f8f9fa")
              : (data.borderColor || "rgba(0,0,0,0)"),
            // Borders were a share of the node's diameter; sigma sizes them
            // by its radius.
            borderSize: Math.min(0.9, borderWidth * 2),
            labelColor,
            labelSize,
          });
        }

        for (const [id, data] of graph.edgeData.entries()) {
          if (!graph.graph.hasEdge(id)) {
            graph.edgeData.delete(id);
            if (graph.hoveredEdgeId === id) graph.hoveredEdgeId = "";
            continue;
          }
          const hovered = graph.hoveredEdgeId === id;
          const color = data.color || edgeTheme.lineColor || "#6c757d";
          const dashes = Rendering.dashPattern(data._maxprob);
          const dashed = dashes.gapSize > 0;
          graph.graph.mergeEdgeAttributes(id, {
            label: hovered && hoveredEdgeTheme.label ? (data.label || id) : "",
            labelVisibility: hovered && hoveredEdgeTheme.label ? "visible" : "hidden",
            labelColor: String(hoveredEdgeTheme.color || "#e9ecef"),
            labelSize: Math.max(1, Number(hoveredEdgeTheme.fontSize || 12)),
            labelBackgroundColor: String(hoveredEdgeTheme.textBackgroundColor || "#0f1216"),
            labelBackgroundPadding: Math.max(0, Number(hoveredEdgeTheme.textBackgroundPadding || 2)),
            color,
            solidColor: dashed ? "rgba(0,0,0,0)" : color,
            dashSize: dashes.dashSize,
            gapSize: dashes.gapSize,
            size: Number(data.width || edgeTheme.width || 2),
            head,
          });
          if (hovered) {
            debugLog("edge.hover.style", { edgeId: id, dashed });
          }
        }
        this.configure();
      },

      configure() {
        if (typeof graph.renderer.setSetting !== "function") return;
        const nodeTheme = graph.themeConfig.node;
        const hoveredEdgeTheme = graph.themeConfig.hoveredEdge;
        const minLabel = Number(nodeTheme.minZoomedFontSize || 6);
        const settings = {
          renderLabels: !!nodeTheme.label,
          renderEdgeLabels: !!hoveredEdgeTheme.label,
          labelRenderedSizeThreshold: RenderMetrics.clamp(minLabel, 1, 32),
        };
        // Setting a setting refreshes sigma, so only changed ones are set.
        const changed = Object.entries(settings).filter(([key, value]) => graph.renderer.getSetting(key) !== value);
        if (changed.length > 0) {
          graph.renderer.setSettings(Object.fromEntries(changed));
        }
      },
    };
  }

  window.createWorkspaceSigmaRenderer = createWorkspaceSigmaRenderer;
}());
