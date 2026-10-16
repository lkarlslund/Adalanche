(function () {
  const RenderMetrics = (typeof window !== "undefined" && window.WorkspaceRenderMetrics)
    ? window.WorkspaceRenderMetrics
    : null;
  const Rendering = (typeof window !== "undefined" && window.WorkspaceSigmaRendering)
    ? window.WorkspaceSigmaRendering
    : null;

  if (!RenderMetrics || !Rendering) {
    return;
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
          const borderWidth = Number(data.borderWidth || 0);
          // Borders were a share of the node's diameter; sigma sizes them by
          // its radius. The selected* values apply while the node is selected:
          // larger, with a thick ring.
          graph.graph.mergeNodeAttributes(id, {
            label: nodeTheme.label ? (data.label || id) : "",
            color: data.color || nodeTheme.backgroundColor || "#6c757d",
            size: Number(data.renderSize || RenderMetrics.baseNodeSize(false)),
            selectedSize: data.renderSize ? Number(data.renderSize) * 1.3 : RenderMetrics.baseNodeSize(true),
            image: showIcons ? String(data.iconFull || "").trim() : "",
            borderColor: data.borderColor || "rgba(0,0,0,0)",
            borderSize: Math.min(0.9, borderWidth * 2),
            selectedBorderColor: selectedNodeTheme.borderColor || "#f8f9fa",
            // A ring a third of the radius: thinner ones vanish on small nodes.
            selectedBorderSize: Math.min(0.9, Math.max(borderWidth * 2, 0.3)),
            labelColor,
            labelSize,
          });
        }

        for (const [id, data] of graph.edgeData.entries()) {
          // Hidden edges keep their data for when they are shown again.
          if (!graph.graph.hasEdge(id)) continue;
          const color = data.color || edgeTheme.lineColor || "#6c757d";
          const dashes = Rendering.dashPattern(data._maxprob);
          const dashed = dashes.gapSize > 0;
          const size = Number(data.width || edgeTheme.width || 2);
          // Sigma shows the label while the edge is hovered, and the route*
          // values while it is on a highlighted route.
          graph.graph.mergeEdgeAttributes(id, {
            label: hoveredEdgeTheme.label ? (data.label || id) : "",
            hoverLabelVisibility: hoveredEdgeTheme.label ? "visible" : "hidden",
            labelColor: String(hoveredEdgeTheme.color || "#e9ecef"),
            labelSize: Math.max(1, Number(hoveredEdgeTheme.fontSize || 12)),
            labelBackgroundColor: String(hoveredEdgeTheme.textBackgroundColor || "#0f1216"),
            labelBackgroundPadding: Math.max(0, Number(hoveredEdgeTheme.textBackgroundPadding || 2)),
            color,
            solidColor: dashed ? "rgba(0,0,0,0)" : color,
            dashSize: dashes.dashSize,
            gapSize: dashes.gapSize,
            size,
            routeSolidColor: dashed ? "rgba(0,0,0,0)" : Rendering.ROUTE_COLOR,
            routeSize: Math.max(size, 4),
            head,
          });
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
