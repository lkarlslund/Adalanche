(function () {
  class WorkspaceSigmaLayout {
    constructor(context, options) {
      this._ctx = context;
      this._options = { ...(options || {}) };
      this._stopped = false;
      this._raf = 0;
    }

    emitLayoutPhase(phase) {
      this._ctx.notify("layoutstatechanged", {
        phase: String(phase || "").trim(),
        layoutKey: String(this._options.name || "").trim(),
      });
    }

    stop() {
      this._stopped = true;
      if (this._raf) {
        window.cancelAnimationFrame(this._raf);
        this._raf = 0;
      }
      return this;
    }

    declumpConfig() {
      if (!this._options || this._options.declump === false) return null;
      return {
        iterations: Math.max(1, Math.floor(Number(this._options.declumpIterations) || 10)),
        padding: Math.max(0, Number(this._options.declumpPadding) || 8),
      };
    }

    runVendorNoverlap(config) {
      var noverlap = (typeof window !== "undefined" && window.GraphologyLayoutNoverlap)
        ? window.GraphologyLayoutNoverlap
        : null;
      if (!noverlap || !this._ctx || !this._ctx.graph || typeof noverlap.assign !== "function") return false;
      var settings = config || this.declumpConfig();
      if (!settings) return false;
      noverlap.assign(this._ctx.graph, {
        maxIterations: Math.max(1, Math.floor(Number(settings.iterations) || 1)),
        settings: {
          margin: Math.max(0, Number(settings.padding) || 0),
          ratio: 1,
          expansion: 1.1,
          gridSize: Math.max(8, Math.min(64, Math.ceil(Math.sqrt(Math.max(1, this._ctx.nodeIds().length || 1))))),
          speed: 3,
        },
      });
      this._ctx.refresh();
      return true;
    }

    nodeVisualRadius(id) {
      if (!this._ctx || !this._ctx.graph || typeof this._ctx.graph.getNodeAttributes !== "function") return 10;
      const attrs = this._ctx.graph.getNodeAttributes(id) || {};
      const size = Number(attrs.size);
      return Number.isFinite(size) && size > 0 ? size : 10;
    }

    runDeclump(config) {
      const settings = config || this.declumpConfig();
      if (!settings) return false;
      if (this.runVendorNoverlap(settings)) return true;
      const nodeIds = this._ctx.nodeIds();
      if (nodeIds.length < 2) return false;
      const padding = Math.max(0, Number(settings.padding) || 0);
      const iterations = Math.max(1, Math.floor(Number(settings.iterations) || 1));
      let movedAny = false;

      for (let step = 0; step < iterations; step += 1) {
        const positions = new Map();
        const radii = new Map();
        const buckets = new Map();
        const cellSize = Math.max(8, (padding * 2) + 24);

        for (const id of nodeIds) {
          const pos = this._ctx.nodePosition(id);
          positions.set(id, {
            x: Number.isFinite(pos.x) ? pos.x : 0,
            y: Number.isFinite(pos.y) ? pos.y : 0,
          });
          radii.set(id, this.nodeVisualRadius(id));
        }

        for (const id of nodeIds) {
          const pos = positions.get(id);
          const cellX = Math.floor(pos.x / cellSize);
          const cellY = Math.floor(pos.y / cellSize);
          const key = `${cellX}:${cellY}`;
          if (!buckets.has(key)) buckets.set(key, []);
          buckets.get(key).push(id);
        }

        const deltas = new Map();
        const addDelta = (id, dx, dy) => {
          const prev = deltas.get(id) || { x: 0, y: 0 };
          prev.x += dx;
          prev.y += dy;
          deltas.set(id, prev);
        };

        for (const [key, ids] of buckets.entries()) {
          const [cellX, cellY] = key.split(":").map(Number);
          const candidates = [];
          for (let ox = -1; ox <= 1; ox += 1) {
            for (let oy = -1; oy <= 1; oy += 1) {
              const neighbor = buckets.get(`${cellX + ox}:${cellY + oy}`);
              if (neighbor && neighbor.length > 0) candidates.push(...neighbor);
            }
          }
          for (const aId of ids) {
            const aPos = positions.get(aId);
            const aRadius = radii.get(aId);
            for (const bId of candidates) {
              if (aId >= bId) continue;
              const bPos = positions.get(bId);
              const bRadius = radii.get(bId);
              const minDist = aRadius + bRadius + padding;
              let dx = aPos.x - bPos.x;
              let dy = aPos.y - bPos.y;
              let distSq = (dx * dx) + (dy * dy);
              if (distSq <= 0.0001) {
                dx = 1;
                dy = 0;
                distSq = 1;
              }
              const dist = Math.sqrt(distSq);
              if (dist >= minDist) continue;
              const overlap = (minDist - dist) / 2;
              const ux = dx / dist;
              const uy = dy / dist;
              addDelta(aId, ux * overlap, uy * overlap);
              addDelta(bId, -ux * overlap, -uy * overlap);
            }
          }
        }

        if (deltas.size === 0) break;
        movedAny = true;
        this._ctx.batch(() => {
          for (const [id, delta] of deltas.entries()) {
            const pos = positions.get(id);
            this._ctx.setNodePosition(id, {
              x: pos.x + delta.x,
              y: pos.y + delta.y,
            });
          }
        });
      }

      if (movedAny) this._ctx.refresh();
      return movedAny;
    }

    run() {
      this.emitLayoutPhase("start");
      this.emitLayoutPhase("ready");
      const name = String(this._options.name || "").trim().toLowerCase();
      if (name === "forceatlas2") {
        this.runForceAtlas2();
        return this;
      }
      this.emitLayoutPhase("stop");
      return this;
    }

    runForceAtlas2() {
      const fa2 = (typeof window !== "undefined" && window.GraphologyLayoutForceAtlas2)
        ? window.GraphologyLayoutForceAtlas2
        : null;
      if (!fa2 || !this._ctx || !this._ctx.graph) {
        this.emitLayoutPhase("stop");
        return;
      }
      const iterations = Math.max(1, Math.floor(Number(this._options.iterations) || 600));
      const iterationsPerFrame = Math.max(1, Math.floor(Number(this._options.iterationsPerFrame) || 8));
      const inferred = typeof fa2.inferSettings === "function"
        ? fa2.inferSettings(this._ctx.graph)
        : {};
      const runner = fa2.createRunner(this._ctx.graph, {
        settings: {
          ...(inferred || {}),
          ...(this._options.settings || {}),
        },
      });
      const refreshIntervalMs = Math.max(0, Math.floor(Number(this._options.refreshIntervalMs) || 0));
      let completed = 0;
      let lastRefreshAt = 0;
      const maybeRefresh = (force) => {
        const now = Date.now();
        if (force || refreshIntervalMs <= 16 || lastRefreshAt === 0 || (now - lastRefreshAt) >= refreshIntervalMs) {
          this._ctx.refresh();
          lastRefreshAt = now;
          return true;
        }
        return false;
      };
      const tick = () => {
        if (this._stopped) return;
        const remaining = iterations - completed;
        if (remaining <= 0) {
          this.runDeclump();
          maybeRefresh(true);
          this.emitLayoutPhase("stop");
          return;
        }
        const stepCount = Math.min(iterationsPerFrame, remaining);
        runner.step(stepCount);
        completed += stepCount;
        maybeRefresh(completed >= iterations);
        this._raf = window.requestAnimationFrame(tick);
      };
      this._raf = window.requestAnimationFrame(tick);
    }
  }

  window.createWorkspaceSigmaLayout = function createWorkspaceSigmaLayout(context, options) {
    return new WorkspaceSigmaLayout(context, options);
  };
}());
