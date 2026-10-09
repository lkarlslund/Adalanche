(function () {
  function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
  }

  function eventClientPosition(eventLike) {
    if (!eventLike || typeof eventLike !== "object") return null;
    const sources = [eventLike, eventLike.original, eventLike.sourceEvent];
    for (const source of sources) {
      if (!source || typeof source !== "object") continue;
      const x = Number(source.clientX);
      const y = Number(source.clientY);
      if (Number.isFinite(x) && Number.isFinite(y)) {
        return { x, y };
      }
    }
    return null;
  }

  function relativePoint(container, eventLike) {
    if (!container || typeof container.getBoundingClientRect !== "function") {
      return { x: 0, y: 0 };
    }
    const rect = container.getBoundingClientRect();
    return {
      x: Number(eventLike && eventLike.clientX) - rect.left,
      y: Number(eventLike && eventLike.clientY) - rect.top,
    };
  }

  function zoomScale(value) {
    const zoom = Math.max(0.01, Number(value || 1));
    return clamp(Math.pow(zoom, 0.35), 0.9, 1.45);
  }

  function baseNodeSize(selected) {
    return selected ? 13 : 10;
  }

  function nodeScreenMetrics(renderer, graphLike, nodeId) {
    const graph = graphLike && graphLike.graph ? graphLike.graph : graphLike;
    if (!renderer || !graph || !nodeId || !graph.hasNode || !graph.hasNode(nodeId)) {
      return null;
    }
    const attrs = graph.getNodeAttributes(nodeId) || {};
    const display = typeof renderer.getNodeDisplayData === "function"
      ? renderer.getNodeDisplayData(nodeId)
      : null;
    const displayX = Number(display && display.x);
    const displayY = Number(display && display.y);
    const projected = typeof renderer.graphToViewport === "function"
      ? renderer.graphToViewport({
        x: Number(attrs.x || 0),
        y: Number(attrs.y || 0),
      }) || {}
      : {};
    const projectedX = Number(projected.x);
    const projectedY = Number(projected.y);
    const x = Number.isFinite(projectedX) ? projectedX : displayX;
    const y = Number.isFinite(projectedY) ? projectedY : displayY;
    const displaySize = Number(display && display.size);
    if (!(Number.isFinite(displaySize) && displaySize > 0)) {
      return null;
    }
    const radiusPx = displaySize;
    return {
      id: nodeId,
      x,
      y,
      radiusPx: Math.max(0, Number(radiusPx || 0)),
      diameterPx: Math.max(0, Number(radiusPx || 0) * 2),
      attrs,
      display,
      visible: Number.isFinite(x) && Number.isFinite(y),
    };
  }

  function labelFontPx(metrics, nodeRule, zoomValue) {
    const themedFontSize = Number(nodeRule && nodeRule["font-size"] || 11);
    const nodeRadius = Number(metrics && metrics.radiusPx || 0);
    return Math.max(1, Math.max(themedFontSize, nodeRadius * 0.95) * zoomScale(zoomValue));
  }

  function iconSizePx(metrics, multiplier) {
    const factor = Number.isFinite(Number(multiplier)) ? Number(multiplier) : 1.2;
    return Math.max(0, Number(metrics && metrics.diameterPx || 0) * factor);
  }

  function rectIntersectsNode(rect, metrics) {
    if (!rect || !metrics || !metrics.visible) return false;
    const x = Number(metrics.x);
    const y = Number(metrics.y);
    const radius = Math.max(0, Number(metrics.radiusPx || 0));
    if (!Number.isFinite(x) || !Number.isFinite(y)) return false;
    const left = x - radius;
    const right = x + radius;
    const top = y - radius;
    const bottom = y + radius;
    return !(right < rect.left || left > rect.right || bottom < rect.top || top > rect.bottom);
  }

  window.WorkspaceRenderMetrics = {
    clamp,
    eventClientPosition,
    relativePoint,
    zoomScale,
    baseNodeSize,
    nodeScreenMetrics,
    labelFontPx,
    iconSizePx,
    rectIntersectsNode,
  };
})();
