(function () {
  const RenderMetrics = (typeof window !== "undefined" && window.WorkspaceRenderMetrics)
    ? window.WorkspaceRenderMetrics
    : null;
  const debugEnabled = typeof window !== "undefined" && /\bdebug=1\b/.test(String((window.location && window.location.search) || ""));

  if (!RenderMetrics) {
    return;
  }

  function debugLog(label, payload) {
    if (!debugEnabled || typeof console === "undefined" || typeof console.debug !== "function") return;
    console.debug(`[workspace debug ${label}]`, payload || {});
  }

  function createWorkspaceSigmaInteractions(graph) {
    const listeners = [];
    const EDGE_HIT_TOLERANCE_PX = 8;

    function bind(target, eventName, handler, options) {
      if (!target || typeof target.addEventListener !== "function") return;
      target.addEventListener(eventName, handler, options);
      listeners.push(() => target.removeEventListener(eventName, handler, options));
    }

    function eventTargetsGraphSurface(event) {
      const container = graph && graph.container;
      if (!container || !event) return false;
      if (typeof event.composedPath === "function") {
        const path = event.composedPath();
        if (Array.isArray(path) && path.includes(container)) return true;
      }
      const target = event.target;
      return !!(target && typeof container.contains === "function" && container.contains(target));
    }

    function handleClick(event) {
      if (graph.suppressNextClick) {
        graph.suppressNextClick = false;
        return;
      }
      const point = graph.relativePoint(event);
      const nodeId = graph.getNodeAtPosition(point.x, point.y) || graph.hoveredNodeId || "";
      if (nodeId) {
        graph.notify("nodeclick", {
          nodeId,
          originalEvent: event,
          viewportPosition: point,
          clientPosition: RenderMetrics.eventClientPosition(event),
        });
        return;
      }
      graph.hoveredNodeId = "";
      const edgeId = graph.getEdgeAtPosition(point.x, point.y, EDGE_HIT_TOLERANCE_PX) || graph.hoveredEdgeId || "";
      if (edgeId) {
        graph.notify("edgeclick", {
          edgeId,
          originalEvent: event,
          viewportPosition: point,
          clientPosition: RenderMetrics.eventClientPosition(event),
        });
        return;
      }
      graph.notify("backgroundclick", {
        originalEvent: event,
        viewportPosition: point,
        clientPosition: RenderMetrics.eventClientPosition(event),
      });
    }

    function handleContextMenu(event) {
      if (event && typeof event.preventDefault === "function") event.preventDefault();
      const point = graph.relativePoint(event);
      const nodeId = graph.getNodeAtPosition(point.x, point.y) || graph.hoveredNodeId || "";
      if (nodeId) {
        graph.notify("nodecontextmenu", {
          nodeId,
          originalEvent: event,
          viewportPosition: point,
          clientPosition: RenderMetrics.eventClientPosition(event),
        });
        return;
      }
      const edgeId = graph.getEdgeAtPosition(point.x, point.y, EDGE_HIT_TOLERANCE_PX) || graph.hoveredEdgeId || "";
      if (edgeId) {
        graph.notify("edgecontextmenu", {
          edgeId,
          originalEvent: event,
          viewportPosition: point,
          clientPosition: RenderMetrics.eventClientPosition(event),
        });
      }
    }

    function handleMouseDown(event) {
      if (event && event.button === 0 && event.shiftKey) {
        const point = graph.relativePoint(event);
        graph.selectionState = {
          startX: point.x,
          startY: point.y,
          currentX: point.x,
          currentY: point.y,
          moved: false,
        };
        graph.overlays.updateSelectionLayer();
        event.preventDefault();
        if (typeof event.stopPropagation === "function") event.stopPropagation();
        if (typeof event.stopImmediatePropagation === "function") event.stopImmediatePropagation();
        return;
      }
      if (!event || event.button !== 0) {
        return;
      }
      const point = graph.relativePoint(event);
      const nodeId = graph.getNodeAtPosition(point.x, point.y) || graph.hoveredNodeId || "";
      if (!nodeId) return;
      if (typeof graph.canDragNode === "function" && !graph.canDragNode(nodeId, event)) {
        return;
      }
      graph.dragState = {
        nodeId,
        started: false,
        moved: false,
        startX: point.x,
        startY: point.y,
      };
      event.preventDefault();
      if (typeof event.stopPropagation === "function") event.stopPropagation();
      if (typeof event.stopImmediatePropagation === "function") event.stopImmediatePropagation();
    }

    function handleMouseMove(event) {
      const point = graph.relativePoint(event);
      const onGraphSurface = eventTargetsGraphSurface(event);
      if (onGraphSurface) {
        updateHoveredEdge(point, event);
      } else if (!graph.selectionState && !graph.dragState && graph.hoveredEdgeId) {
        updateHoveredEdge(null, event);
      }
      if (graph.selectionState) {
        const dx = Number(point.x || 0) - Number(graph.selectionState.startX || 0);
        const dy = Number(point.y || 0) - Number(graph.selectionState.startY || 0);
        graph.selectionState.currentX = point.x;
        graph.selectionState.currentY = point.y;
        graph.selectionState.moved = graph.selectionState.moved || ((dx * dx) + (dy * dy) >= 16);
        graph.overlays.updateSelectionLayer();
        event.preventDefault();
        if (typeof event.stopPropagation === "function") event.stopPropagation();
        if (typeof event.stopImmediatePropagation === "function") event.stopImmediatePropagation();
        return;
      }
      if (!graph.dragState) return;
      const dx = Number(point.x || 0) - Number(graph.dragState.startX || 0);
      const dy = Number(point.y || 0) - Number(graph.dragState.startY || 0);
      if (!graph.dragState.moved && ((dx * dx) + (dy * dy) < 16)) {
        return;
      }
      event.preventDefault();
      if (typeof event.stopPropagation === "function") event.stopPropagation();
      const graphPoint = graph.renderer.viewportToGraph(point);
      if (!graph.dragState.started) {
        graph.dragState.started = true;
        graph.notify("nodedragstart", {
          nodeId: graph.dragState.nodeId,
          originalEvent: event,
          viewportPosition: point,
          clientPosition: RenderMetrics.eventClientPosition(event),
        });
      }
      graph.dragState.moved = true;
      graph.setNodePosition(graph.dragState.nodeId, graphPoint, { markDirty: true });
      graph.refresh();
    }

    function handleMouseUp(event) {
      if (graph.selectionState) {
        const point = graph.relativePoint(event);
        graph.selectionState.currentX = point.x;
        graph.selectionState.currentY = point.y;
        const moved = !!graph.selectionState.moved;
        const rect = graph.overlays.selectionRect();
        graph.selectionState = null;
        graph.overlays.hideSelectionLayer();
        event.preventDefault();
        if (typeof event.stopPropagation === "function") event.stopPropagation();
        if (typeof event.stopImmediatePropagation === "function") event.stopImmediatePropagation();
        if (moved && rect) {
          graph.suppressNextClick = true;
          graph.notify("selectionbox", {
            originalEvent: event,
            viewportPosition: point,
            clientPosition: RenderMetrics.eventClientPosition(event),
            nodeIds: graph.nodeIDsInViewportRect(rect),
            appendSelection: true,
          });
        }
        return;
      }
      if (!graph.dragState) return;
      const point = graph.relativePoint(event);
      const nodeId = graph.dragState.nodeId;
      const moved = graph.dragState.moved;
      graph.dragState = null;
      event.preventDefault();
      if (typeof event.stopPropagation === "function") event.stopPropagation();
      if (typeof event.stopImmediatePropagation === "function") event.stopImmediatePropagation();
      if (!moved) {
        graph.suppressNextClick = true;
        graph.notify("nodeclick", {
          nodeId,
          originalEvent: event,
          viewportPosition: point,
          clientPosition: RenderMetrics.eventClientPosition(event),
          syntheticTap: true,
        });
        return;
      }
      graph.suppressNextClick = true;
      graph.notify("nodedragend", {
        nodeId,
        originalEvent: event,
        viewportPosition: point,
        clientPosition: RenderMetrics.eventClientPosition(event),
        position: graph.nodePosition(nodeId),
      });
    }

    function installSigmaEvents() {
      if (graph.renderer && typeof graph.renderer.on === "function") {
        graph.renderer.on("afterRender", () => graph.overlays.queueIconSync());
        graph.renderer.on("enterNode", (event) => {
          const id = String(event && event.node ? event.node : "");
          if (!id) return;
          graph.hoveredNodeId = id;
          graph.notify("nodehoverchanged", {
            nodeId: id,
            hovered: true,
            originalEvent: event && event.event ? event.event : {},
          });
        });
        graph.renderer.on("leaveNode", (event) => {
          const id = String(event && event.node ? event.node : "");
          if (!id) return;
          if (graph.hoveredNodeId === id) graph.hoveredNodeId = "";
          graph.notify("nodehoverchanged", {
            nodeId: id,
            hovered: false,
            originalEvent: event && event.event ? event.event : {},
          });
        });
        graph.renderer.on("rightClickNode", (event) => {
          const id = String(event && event.node ? event.node : "");
          if (!id) return;
          const originalEvent = event && event.event ? event.event : {};
          graph.notify("nodecontextmenu", {
            nodeId: id,
            originalEvent,
            viewportPosition: graph.relativePoint(originalEvent),
            clientPosition: RenderMetrics.eventClientPosition(originalEvent),
          });
        });
      }

      const target = graph.container;
      bind(target, "click", handleClick, true);
      bind(target, "contextmenu", handleContextMenu, true);
      bind(target, "mousedown", handleMouseDown, true);
      bind(window, "mousemove", handleMouseMove, true);
      bind(window, "mouseup", handleMouseUp, true);

      const camera = graph.renderer.getCamera();
      if (camera && typeof camera.on === "function") {
        camera.on("updated", () => {
          const ratio = Number(camera.getState && camera.getState().ratio);
          if (Number.isFinite(ratio) && ratio > 0) {
            graph.zoomValue = 1 / ratio;
          }
          const nextIconVisibility = typeof graph.iconRenderingEnabled === "function"
            ? graph.iconRenderingEnabled()
            : true;
          if (graph.iconRenderVisible !== nextIconVisibility) {
            graph.refresh();
          }
          graph.overlays.queueIconSync();
          graph.notify("viewportchanged", {
            zoom: graph.zoomValue,
            pan: graph.pan(),
            cause: "camera",
          });
        });
      }
    }

    function updateHoveredEdge(point, originalEvent) {
      const clientPosition = RenderMetrics.eventClientPosition(originalEvent);
      if (!point) {
        const prevEdgeId = String(graph.hoveredEdgeId || "");
        if (!prevEdgeId) return;
        debugLog("edge.leave", { edgeId: prevEdgeId, reason: "pointer-left-graph-surface" });
        graph.notify("edgehoverchanged", {
          edgeId: prevEdgeId,
          hovered: false,
          originalEvent: originalEvent || {},
          viewportPosition: null,
          clientPosition,
        });
        return;
      }
      if (graph.hoveredNodeId) {
        if (graph.hoveredEdgeId) {
          debugLog("edge.leave", { edgeId: graph.hoveredEdgeId });
          graph.notify("edgehoverchanged", {
            edgeId: graph.hoveredEdgeId,
            hovered: false,
            originalEvent: originalEvent || {},
            viewportPosition: point,
            clientPosition,
          });
        }
        return;
      }
      const nextEdgeId = graph.getEdgeAtPosition(point.x, point.y, EDGE_HIT_TOLERANCE_PX) || "";
      const prevEdgeId = String(graph.hoveredEdgeId || "");
      if (prevEdgeId && prevEdgeId === nextEdgeId) {
        graph.notify("edgehoverchanged", {
          edgeId: nextEdgeId,
          hovered: true,
          originalEvent: originalEvent || {},
          viewportPosition: point,
          clientPosition,
        });
        return;
      }
      if (prevEdgeId) {
        debugLog("edge.leave", { edgeId: prevEdgeId });
        graph.notify("edgehoverchanged", {
          edgeId: prevEdgeId,
          hovered: false,
          originalEvent: originalEvent || {},
          viewportPosition: point,
          clientPosition,
        });
      }
      if (nextEdgeId) {
        debugLog("edge.enter", { edgeId: nextEdgeId });
        graph.notify("edgehoverchanged", {
          edgeId: nextEdgeId,
          hovered: true,
          originalEvent: originalEvent || {},
          viewportPosition: point,
          clientPosition,
        });
      }
    }

    return {
      install() {
        installSigmaEvents();
      },
      destroy() {
        while (listeners.length > 0) {
          const unbind = listeners.pop();
          unbind();
        }
      },
    };
  }

  window.createWorkspaceSigmaInteractions = createWorkspaceSigmaInteractions;
}());
