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

  function createWorkspaceSigmaRenderer(graph) {
    return {
      applyStyles() {
        const nodeTheme = graph.themeConfig.node;
        const selectedNodeTheme = graph.themeConfig.selectedNode;
        const edgeTheme = graph.themeConfig.edge;
        const hoveredEdgeTheme = graph.themeConfig.hoveredEdge;
        const edgeType = Rendering.edgeTypeFromTheme(graph.themeConfig);
        const showIcons = typeof graph.iconRenderingEnabled === "function"
          ? graph.iconRenderingEnabled()
          : (!!nodeTheme.backgroundImage && nodeTheme.backgroundImage !== "none");
        graph.iconRenderVisible = showIcons;

        for (const [id, data] of graph.nodeData.entries()) {
          if (!graph.graph.hasNode(id)) {
            continue;
          }
          const selected = graph.selectedNodeIDsSet.has(id);
          const label = nodeTheme.label ? (data.label || id) : "";
          const size = Number(data.renderSize || RenderMetrics.baseNodeSize(selected));
          const baseColor = data.color || nodeTheme.backgroundColor || "#6c757d";
          const borderColor = selected
            ? (selectedNodeTheme.borderColor || "#f8f9fa")
            : (data.borderColor || "rgba(0,0,0,0)");
          const borderWidth = selected
            ? Math.max(Number(data.borderWidth || 0), 0.045)
            : Number(data.borderWidth || 0);
          graph.graph.mergeNodeAttributes(id, {
            label,
            color: baseColor,
            size,
            type: "image",
            image: showIcons ? String(data.iconFull || "").trim() : "",
            borderColor,
            borderWidth,
          });
        }

        for (const [id, data] of graph.edgeData.entries()) {
          if (!graph.graph.hasEdge(id)) {
            graph.edgeData.delete(id);
            if (graph.hoveredEdgeId === id) graph.hoveredEdgeId = "";
            continue;
          }
          const hovered = graph.hoveredEdgeId === id;
          const label = hovered && hoveredEdgeTheme.label ? (data.label || id) : "";
          graph.graph.mergeEdgeAttributes(id, {
            label,
            color: data.color || edgeTheme.lineColor || "#6c757d",
            size: Number(data.width || edgeTheme.width || 2),
            type: edgeType,
            forceLabel: hovered,
          });
          if (hovered) {
            debugLog("edge.hover.style", {
              edgeId: id,
              label,
              forceLabel: true,
            });
          }
        }
        this.configure();
      },

      configure() {
        if (typeof graph.renderer.setSetting !== "function") return;
        const nodeTheme = graph.themeConfig.node;
        const edgeTheme = graph.themeConfig.edge;
        const hoveredEdgeTheme = graph.themeConfig.hoveredEdge;
        const minLabel = Number(nodeTheme.minZoomedFontSize || 6);

        graph.renderer.setSetting("renderLabels", !!nodeTheme.label);
        graph.renderer.setSetting("renderEdgeLabels", !!hoveredEdgeTheme.label);
        graph.renderer.setSetting("defaultNodeColor", nodeTheme.backgroundColor || "#6c757d");
        graph.renderer.setSetting("defaultEdgeColor", edgeTheme.lineColor || "#6c757d");
        graph.renderer.setSetting("defaultEdgeType", Rendering.edgeTypeFromTheme(graph.themeConfig));
        graph.renderer.setSetting("labelRenderedSizeThreshold", RenderMetrics.clamp(minLabel, 1, 32));
        graph.renderer.setSetting("labelColor", { color: nodeTheme.color || "#000000" });
        graph.renderer.setSetting("labelRenderer", this.nodeLabelRenderer(nodeTheme));
        graph.renderer.setSetting("hoverRenderer", this.nodeHoverRenderer(nodeTheme));
        graph.renderer.setSetting("edgeLabelRenderer", this.edgeLabelRenderer(hoveredEdgeTheme));
        graph.renderer.setSetting("nodeReducer", null);
        graph.renderer.setSetting("edgeReducer", null);
      },

      roundedRect(context, x, y, width, height, radius) {
        if (typeof context.roundRect === "function") {
          context.beginPath();
          context.roundRect(x, y, width, height, radius);
          return;
        }
        const r = Math.max(0, Math.min(radius, width / 2, height / 2));
        context.beginPath();
        context.moveTo(x + r, y);
        context.lineTo(x + width - r, y);
        context.quadraticCurveTo(x + width, y, x + width, y + r);
        context.lineTo(x + width, y + height - r);
        context.quadraticCurveTo(x + width, y + height, x + width - r, y + height);
        context.lineTo(x + r, y + height);
        context.quadraticCurveTo(x, y + height, x, y + height - r);
        context.lineTo(x, y + r);
        context.quadraticCurveTo(x, y, x + r, y);
      },

      nodeLabelMetrics(context, data, nodeTheme) {
        const label = String(data && data.label ? data.label : "");
        if (!label) return null;
        const nodeSize = Math.max(1, Number(data.size || 0));
        const baseFontSize = Math.max(1, Number(nodeTheme.fontSize || 11));
        const fontSize = Math.max(
          1,
          Math.min(baseFontSize + 3, baseFontSize + Math.max(0, nodeSize - 10) * 0.22)
        );
        const fontFamily = "Oswald";
        const fontWeight = "normal";
        context.font = `${fontWeight} ${fontSize}px ${fontFamily}`;
        const textWidth = Number(context.measureText(label).width || 0);
        const paddingX = 6;
        const paddingY = 3;
        const boxWidth = textWidth + (paddingX * 2);
        const boxHeight = fontSize + (paddingY * 2);
        const boxX = Number(data.x || 0) - (boxWidth / 2);
        const boxY = Number(data.y || 0) - nodeSize - boxHeight - 2;
        return {
          label,
          fontSize,
          fontFamily,
          fontWeight,
          paddingX,
          paddingY,
          boxWidth,
          boxHeight,
          boxX,
          boxY,
          textX: Number(data.x || 0),
          textY: boxY + paddingY + fontSize,
        };
      },

      nodeLabelRenderer(nodeTheme) {
        return (context, data) => {
          const metrics = this.nodeLabelMetrics(context, data, nodeTheme);
          if (!metrics) return;
          context.save();
          context.font = `${metrics.fontWeight} ${metrics.fontSize}px ${metrics.fontFamily}`;
          context.textAlign = "center";
          context.textBaseline = "alphabetic";
          context.fillStyle = String(nodeTheme.color || "#e5e7eb");
          context.fillText(metrics.label, metrics.textX, metrics.textY);
          context.restore();
        };
      },

      nodeHoverRenderer(nodeTheme) {
        return (context, data) => {
          if (!data) return;
          const ringColor = "#f59e0b";
          context.save();
          context.beginPath();
          context.arc(Number(data.x || 0), Number(data.y || 0), Math.max(1, Number(data.size || 0)) + 3, 0, Math.PI * 2);
          context.strokeStyle = ringColor;
          context.lineWidth = 2;
          context.stroke();

          const metrics = this.nodeLabelMetrics(context, data, nodeTheme);
          if (metrics) {
            this.roundedRect(context, metrics.boxX, metrics.boxY, metrics.boxWidth, metrics.boxHeight, 6);
            context.fillStyle = "rgba(15, 23, 42, 0.92)";
            context.fill();
            context.font = `${metrics.fontWeight} ${metrics.fontSize}px ${metrics.fontFamily}`;
            context.textAlign = "center";
            context.textBaseline = "alphabetic";
            context.fillStyle = String(nodeTheme.color || "#f8fafc");
            context.fillText(metrics.label, metrics.textX, metrics.textY);
          }
          context.restore();
        };
      },

      edgeLabelRenderer(hoveredEdgeTheme) {
        return (context, edgeData, sourceData, targetData, settings) => {
          if (!edgeData || !edgeData.label || !sourceData || !targetData) return;
          const label = String(edgeData.label || "");
          if (!label) return;
          debugLog("edge.label.render", {
            edgeId: edgeData.key || "",
            label,
            source: {
              x: Number(sourceData.x || 0),
              y: Number(sourceData.y || 0),
            },
            target: {
              x: Number(targetData.x || 0),
              y: Number(targetData.y || 0),
            },
          });
          const fontSize = Math.max(1, Number(hoveredEdgeTheme.fontSize || (settings && settings.edgeLabelSize) || 10));
          const fontFamily = String((settings && settings.edgeLabelFont) || "Arial");
          const fontWeight = String((settings && settings.edgeLabelWeight) || "normal");
          const textColor = String(hoveredEdgeTheme.color || "#e9ecef");
          const bgColor = String(hoveredEdgeTheme.textBackgroundColor || "#0f1216");
          const bgOpacity = RenderMetrics.clamp(Number(hoveredEdgeTheme.textBackgroundOpacity || 0.9), 0, 1);
          const bgPadding = Math.max(0, Number(hoveredEdgeTheme.textBackgroundPadding || 2));
          const x = (Number(sourceData.x || 0) + Number(targetData.x || 0)) / 2;
          const y = (Number(sourceData.y || 0) + Number(targetData.y || 0)) / 2;
          context.save();
          context.font = `${fontWeight} ${fontSize}px ${fontFamily}`;
          context.textAlign = "center";
          context.textBaseline = "middle";
          const metrics = context.measureText(label);
          const textWidth = Number(metrics.width || 0);
          const boxWidth = textWidth + (bgPadding * 2);
          const boxHeight = fontSize + (bgPadding * 2);
          context.fillStyle = bgColor;
          context.globalAlpha = bgOpacity;
          const boxX = x - (boxWidth / 2);
          const boxY = y - (boxHeight / 2);
          if (typeof context.roundRect === "function") {
            context.beginPath();
            context.roundRect(boxX, boxY, boxWidth, boxHeight, 4);
            context.fill();
          } else {
            context.fillRect(boxX, boxY, boxWidth, boxHeight);
          }
          context.globalAlpha = 1;
          context.fillStyle = textColor;
          context.fillText(label, x, y);
          context.restore();
        };
      },

    };
  }

  window.createWorkspaceSigmaRenderer = createWorkspaceSigmaRenderer;
}());
