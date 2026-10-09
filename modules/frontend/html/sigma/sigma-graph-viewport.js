(function () {
  const RenderMetrics = (typeof window !== "undefined" && window.WorkspaceRenderMetrics)
    ? window.WorkspaceRenderMetrics
    : null;

  if (!RenderMetrics) {
    return;
  }

  function rectOverlap(a, b) {
    if (!a || !b) return null;
    const left = Math.max(Number(a.left) || 0, Number(b.left) || 0);
    const top = Math.max(Number(a.top) || 0, Number(b.top) || 0);
    const right = Math.min(Number(a.right) || 0, Number(b.right) || 0);
    const bottom = Math.min(Number(a.bottom) || 0, Number(b.bottom) || 0);
    if (right <= left || bottom <= top) return null;
    return {
      left,
      top,
      right,
      bottom,
      width: right - left,
      height: bottom - top,
    };
  }

  function createWorkspaceSigmaViewport(graph) {
    return {
      viewportInsets() {
        const container = graph.container;
        if (!container || typeof container.getBoundingClientRect !== "function" || typeof document === "undefined") {
          return { left: 0, right: 0, top: 0, bottom: 0 };
        }
        const sidebar = document.querySelector(".workspace-sidebar");
        if (!sidebar || typeof sidebar.getBoundingClientRect !== "function") {
          return { left: 0, right: 0, top: 0, bottom: 0 };
        }
        const containerRect = container.getBoundingClientRect();
        const sidebarRect = sidebar.getBoundingClientRect();
        const overlap = rectOverlap(containerRect, sidebarRect);
        if (!overlap) {
          return { left: 0, right: 0, top: 0, bottom: 0 };
        }
        const containerWidth = Math.max(1, Number(containerRect.width) || 1);
        const containerHeight = Math.max(1, Number(containerRect.height) || 1);
        const mostlyVerticalOverlay = overlap.height >= (containerHeight * 0.8);
        if (!mostlyVerticalOverlay) {
          return { left: 0, right: 0, top: 0, bottom: 0 };
        }
        const leftInset = RenderMetrics.clamp(overlap.right - containerRect.left, 0, containerWidth * 0.75);
        return { left: leftInset, right: 0, top: 0, bottom: 0 };
      },

      viewportVisibleCenter() {
        const insets = this.viewportInsets();
        const width = Math.max(1, Number(graph.width()) || 1);
        const height = Math.max(1, Number(graph.height()) || 1);
        const left = RenderMetrics.clamp(Number(insets.left) || 0, 0, width - 1);
        const right = RenderMetrics.clamp(Number(insets.right) || 0, 0, width - left - 1);
        const top = RenderMetrics.clamp(Number(insets.top) || 0, 0, height - 1);
        const bottom = RenderMetrics.clamp(Number(insets.bottom) || 0, 0, height - top - 1);
        const visibleWidth = Math.max(1, width - left - right);
        const visibleHeight = Math.max(1, height - top - bottom);
        return {
          x: RenderMetrics.clamp((left + (visibleWidth / 2)) / width, 0, 1),
          y: RenderMetrics.clamp((top + (visibleHeight / 2)) / height, 0, 1),
        };
      },

      fitBounds(bbox, padding) {
        if (!bbox) return;
        const pad = Number(padding || 0);
        graph.customBBox = {
          x: [Number(bbox.x1) - pad, Number(bbox.x2) + pad],
          y: [Number(bbox.y1) - pad, Number(bbox.y2) + pad],
        };
        if (typeof graph.renderer.setCustomBBox === "function") {
          graph.renderer.setCustomBBox(graph.customBBox);
        }
        const viewportCenter = this.viewportVisibleCenter();
        const camera = graph.renderer.getCamera();
        if (camera && typeof camera.animate === "function") {
          camera.animate({ x: 1 - viewportCenter.x, y: viewportCenter.y, ratio: 1 }, { duration: 150 });
        }
        graph.zoomValue = 1;
        graph.refresh();
      },

      center() {
        const viewportCenter = this.viewportVisibleCenter();
        const camera = graph.renderer.getCamera();
        if (camera && typeof camera.animate === "function") {
          camera.animate({ x: 1 - viewportCenter.x, y: viewportCenter.y }, { duration: 120 });
        }
      },
    };
  }

  window.createWorkspaceSigmaViewport = createWorkspaceSigmaViewport;
}());
