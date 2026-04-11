(function () {
  function cloneObject(value) {
    return value && typeof value === "object" ? { ...value } : {};
  }

  function edgeTypeFromTheme(theme) {
    const arrowShape = String(theme && theme.edge && theme.edge.targetArrowShape ? theme.edge.targetArrowShape : "").trim().toLowerCase();
    return arrowShape && arrowShape !== "none" ? "arrow" : "line";
  }

  function defaultThemeConfig() {
    return {
      node: {
        label: true,
        backgroundImage: "none",
        backgroundImageOpacity: 0,
        minZoomedFontSize: 6,
        textHAlign: "center",
        textVAlign: "top",
        color: "#000000",
        fontSize: 11,
        backgroundColor: "#6c757d",
      },
      selectedNode: {
        borderColor: "#f8f9fa",
        shadowColor: "#0d6efd",
      },
      edge: {
        width: 2,
        curveStyle: "bezier",
        lineColor: "#6c757d",
        targetArrowColor: "#6c757d",
        targetArrowShape: "triangle",
      },
      hoveredEdge: {
        label: true,
        color: "#e9ecef",
        textBackgroundColor: "#0f1216",
        textBackgroundOpacity: 0.9,
        textBackgroundPadding: 2,
        fontSize: 12,
      },
    };
  }

  function normalizeThemeConfig(input) {
    const base = defaultThemeConfig();
    const next = input && typeof input === "object" ? input : {};
    return {
      node: { ...base.node, ...cloneObject(next.node) },
      selectedNode: { ...base.selectedNode, ...cloneObject(next.selectedNode) },
      edge: { ...base.edge, ...cloneObject(next.edge) },
      hoveredEdge: { ...base.hoveredEdge, ...cloneObject(next.hoveredEdge) },
    };
  }

  window.WorkspaceSigmaRendering = {
    defaultThemeConfig,
    normalizeThemeConfig,
    edgeTypeFromTheme,
  };
}());
