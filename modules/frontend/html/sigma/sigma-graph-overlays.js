(function () {

  function createWorkspaceSigmaOverlays(graph) {
    return {
      createSelectionLayer() {
        if (!graph.container || graph.selectionLayer) return;
        const layer = document.createElement("div");
        layer.className = "workspace-sigma-selection-layer";
        layer.style.position = "absolute";
        layer.style.left = "0";
        layer.style.top = "0";
        layer.style.width = "0";
        layer.style.height = "0";
        layer.style.display = "none";
        layer.style.pointerEvents = "none";
        graph.container.appendChild(layer);
        graph.selectionLayer = layer;
      },

      queueIconSync() {
      },

      syncIconOverlay() {
      },

      selectionRect() {
        if (!graph.selectionState) return null;
        const left = Math.min(Number(graph.selectionState.startX || 0), Number(graph.selectionState.currentX || 0));
        const top = Math.min(Number(graph.selectionState.startY || 0), Number(graph.selectionState.currentY || 0));
        const right = Math.max(Number(graph.selectionState.startX || 0), Number(graph.selectionState.currentX || 0));
        const bottom = Math.max(Number(graph.selectionState.startY || 0), Number(graph.selectionState.currentY || 0));
        return {
          left,
          top,
          right,
          bottom,
          width: Math.max(0, right - left),
          height: Math.max(0, bottom - top),
        };
      },

      updateSelectionLayer() {
        if (!graph.selectionLayer || !graph.selectionState) return;
        const rect = this.selectionRect();
        if (!rect || (!graph.selectionState.moved && rect.width < 4 && rect.height < 4)) {
          graph.selectionLayer.style.display = "none";
          return;
        }
        graph.selectionLayer.style.display = "";
        graph.selectionLayer.style.left = `${rect.left}px`;
        graph.selectionLayer.style.top = `${rect.top}px`;
        graph.selectionLayer.style.width = `${rect.width}px`;
        graph.selectionLayer.style.height = `${rect.height}px`;
      },

      hideSelectionLayer() {
        if (!graph.selectionLayer) return;
        graph.selectionLayer.style.display = "none";
        graph.selectionLayer.style.width = "0";
        graph.selectionLayer.style.height = "0";
      },

      destroy() {
        this.hideSelectionLayer();
        if (graph.selectionLayer) {
          graph.selectionLayer.remove();
          graph.selectionLayer = null;
        }
      },
    };
  }

  window.createWorkspaceSigmaOverlays = createWorkspaceSigmaOverlays;
}());
