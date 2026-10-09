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

  // Probability dashes: edges less likely than 100% are dashed, with longer
  // gaps the less likely they are, as a 10 pixel pattern at zoom 1 (as
  // before sigma): 90% is 9 on and 1 off, 50% is 5 and 5, 10% or less is 1
  // and 9. The pattern zooms with the line (see graphDashes).
  const DASH_PATTERN_PX = 10;

  function dashPattern(maxProbability) {
    const probability = Number(maxProbability);
    if (!Number.isFinite(probability) || probability > 90) return { dashSize: 0, gapSize: 0 };
    const tenths = Math.max(1, Math.ceil(Math.max(0, probability) / 10));
    const dash = (DASH_PATTERN_PX / 10) * tenths;
    return { dashSize: dash, gapSize: DASH_PATTERN_PX - dash };
  }

  // graphDashes is sigma's dashed edge layer with its dash and gap sizes
  // fixed along the edge rather than on screen: zooming magnifies the dashes
  // with the line, instead of keeping their size and fitting in more. Sizes
  // given in pixels are the pixels they span at zoom 1. sigma converts pixel
  // sizes with the current zoom; this replaces that with a uniform set before
  // each frame to the graph distance a pixel spans at zoom 1.
  const PIXEL_TO_WORLD = "float pixelToWorld = u_correctionRatio / u_sizeRatio;";

  function graphDashes(Sigma, options, renderParams) {
    const layer = Sigma.rendering.layerDashed(options);
    if (!layer.glsl.includes(PIXEL_TO_WORLD)) {
      // A sigma that converts differently: dashes keep their screen size.
      if (typeof console !== "undefined") console.warn("dashed edges: sigma's dashed layer changed; dashes keep their screen size");
      return layer;
    }
    // sigma sets layer uniforms from their declared values on every frame,
    // after the beforeRender hooks run, so the hook updates the value.
    const pixelToWorld = { name: "u_dashPixelToWorld", type: "float", value: 1 };
    return {
      ...layer,
      glsl: layer.glsl.replace(PIXEL_TO_WORLD, "float pixelToWorld = u_dashPixelToWorld;"),
      uniforms: [...layer.uniforms, pixelToWorld],
      lifecycle: () => ({
        beforeRender() {
          const params = renderParams();
          if (!params) return;
          // correctionRatio is the graph distance of a pixel at the current
          // zoom, which grows with the camera ratio.
          pixelToWorld.value = params.correctionRatio / Math.max(params.zoomRatio, 1e-6);
        },
      }),
    };
  }

  // sigmaOptions declares what sigma draws: nodes as a filled circle with an
  // icon and a border, edges as lines with an optional arrowhead, solid or
  // dashed. Per-element values, the theme's included, come from graph
  // attributes, so changing them never rebuilds the programs.
  function sigmaOptions(Sigma, renderParams) {
    const r = Sigma.rendering;
    const layers = Sigma.layers;
    return {
      settings: {
        allowInvalidContainer: true,
        renderLabels: true,
        renderEdgeLabels: true,
        // Sizes in screen pixels, as before sigma 4.
        itemSizesReference: "screen",
        labelRenderedSizeThreshold: 8,
        labelDensity: 1,
        // Edges are found by the workspace itself.
        enableEdgeEvents: false,
      },
      primitives: {
        nodes: {
          shapes: [r.sdfCircle()],
          variables: {
            image: { type: "string", default: "" },
            borderColor: { type: "color", default: "rgba(0,0,0,0)" },
            borderSize: { type: "number", default: 0 },
          },
          layers: [
            r.layerFill(),
            layers.layerImage({ drawingMode: "image", padding: 0.1, imageAttribute: "image" }),
            // A ring; its inside stays clear for the fill and icon under it.
            layers.layerBorder({
              borders: [
                { size: { attribute: "borderSize" }, color: { attribute: "borderColor" }, mode: "relative" },
                { size: 0, color: "rgba(0,0,0,0)", fill: true },
              ],
            }),
          ],
          label: { font: { family: "Oswald" } },
        },
        edges: {
          variables: {
            solidColor: { type: "color", default: "rgba(0,0,0,0)" },
            dashSize: { type: "number", default: 0 },
            gapSize: { type: "number", default: 0 },
          },
          paths: [r.pathLine()],
          extremities: [r.extremityArrow()],
          layers: [
            // Solid edges draw here; dashed ones leave it transparent so their
            // gaps stay open.
            r.layerPlain({ color: { attribute: "solidColor" } }),
            graphDashes(Sigma, {
              dashSize: { attribute: "dashSize", mode: "pixels" },
              gapSize: { attribute: "gapSize", mode: "pixels" },
              solidExtremities: true,
            }, renderParams || (() => null)),
          ],
        },
      },
      styles: {
        nodes: [
          Sigma.DEFAULT_STYLES.nodes,
          {
            labelColor: { attribute: "labelColor", defaultValue: "#000000" },
            labelSize: { attribute: "labelSize", defaultValue: 11 },
            labelFont: "Oswald",
            labelPosition: "above",
            // Hovered nodes: ringed, with the label on a dark box.
            backdropColor: "rgba(15, 23, 42, 0.92)",
            backdropBorderColor: "#f59e0b",
            backdropBorderWidth: 2,
            backdropCornerRadius: 6,
            backdropPadding: 3,
            backdropShadowBlur: 0,
          },
          { whenState: "isHovered", then: { labelColor: { attribute: "hoverLabelColor", defaultValue: "#f8fafc" } } },
        ],
        edges: [
          Sigma.DEFAULT_STYLES.edges,
          {
            head: { attribute: "head", defaultValue: "none" },
            labelVisibility: { attribute: "labelVisibility", defaultValue: "hidden" },
            labelColor: { attribute: "labelColor", defaultValue: "#e9ecef" },
            labelSize: { attribute: "labelSize", defaultValue: 12 },
            labelBackgroundColor: { attribute: "labelBackgroundColor", defaultValue: "rgba(15, 18, 22, 0.9)" },
            labelBackgroundPadding: { attribute: "labelBackgroundPadding", defaultValue: 2 },
            labelPosition: 0.5,
          },
        ],
      },
    };
  }

  window.WorkspaceSigmaRendering = {
    defaultThemeConfig,
    normalizeThemeConfig,
    edgeTypeFromTheme,
    dashPattern,
    sigmaOptions,
  };
}());
