function createAdalancheLayoutConnector(config) {
  const workerURL = String((config && config.workerURL) || "sigma/layout-worker.js");
  const workerCount = Math.max(1, Math.min(Number((config && config.workerCount) || 1), 8));
  const workers = [];
  const requests = new Map();
  let seq = 0;

  function nextID() {
    seq += 1;
    return `adalanche-layout-${Date.now()}-${seq}`;
  }

  function setupWorker(worker) {
    worker.onmessage = (event) => {
      const msg = event && event.data ? event.data : {};
      const id = String(msg.id || "");
      if (!id || !requests.has(id)) return;
      const pending = requests.get(id);
      requests.delete(id);
      if (msg.ok) {
        pending.resolve(msg.payload || null);
        return;
      }
      pending.reject(new Error(String(msg.error || "layout worker error")));
    };
    worker.onerror = (event) => {
      const err = event && event.message ? event.message : "layout worker crashed";
      for (const [id, pending] of requests) {
        if (pending.worker !== worker) continue;
        requests.delete(id);
        pending.reject(new Error(err));
      }
    };
  }

  function request(worker, type, payload) {
    return new Promise((resolve, reject) => {
      const id = nextID();
      requests.set(id, { resolve, reject, worker });
      worker.postMessage({ id, type, payload });
    });
  }

  function toGraphPayload(graphView) {
    if (!graphView || typeof graphView.exportLayoutData !== "function") {
      return { nodes: [], edges: [] };
    }
    const payload = graphView.exportLayoutData();
    return {
      nodes: Array.isArray(payload && payload.nodes) ? payload.nodes : [],
      edges: Array.isArray(payload && payload.edges) ? payload.edges : [],
    };
  }

  function connectedComponents(graph) {
    const ids = graph.nodes.map((node) => node.id);
    const index = new Map(ids.map((id, idx) => [id, idx]));
    const parent = ids.map((_, idx) => idx);

    function find(nodeIndex) {
      let cursor = nodeIndex;
      while (parent[cursor] !== cursor) {
        parent[cursor] = parent[parent[cursor]];
        cursor = parent[cursor];
      }
      return cursor;
    }

    function union(a, b) {
      const rootA = find(a);
      const rootB = find(b);
      if (rootA !== rootB) {
        parent[rootB] = rootA;
      }
    }

    for (const edge of graph.edges) {
      const source = index.get(edge.source);
      const target = index.get(edge.target);
      if (typeof source === "number" && typeof target === "number") {
        union(source, target);
      }
    }

    const groups = new Map();
    for (let idx = 0; idx < ids.length; idx += 1) {
      const root = find(idx);
      if (!groups.has(root)) {
        groups.set(root, []);
      }
      groups.get(root).push(idx);
    }

    const components = [];
    for (const indices of groups.values()) {
      const nodeIDs = new Set(indices.map((idx) => graph.nodes[idx].id));
      components.push({
        nodes: indices.map((idx) => graph.nodes[idx]),
        edges: graph.edges.filter((edge) => nodeIDs.has(edge.source) && nodeIDs.has(edge.target)),
      });
    }
    return components;
  }

  return {
    async init() {
      if (workers.length > 0) {
        return request(workers[0], "init", null);
      }
      for (let idx = 0; idx < workerCount; idx += 1) {
        const worker = new Worker(workerURL);
        setupWorker(worker);
        workers.push(worker);
      }
      return request(workers[0], "init", null);
    },
    shutdown() {
      for (const worker of workers) {
        try {
          worker.terminate();
        } catch (_err) {}
      }
      workers.length = 0;
      for (const [id, pending] of requests) {
        requests.delete(id);
        pending.reject(new Error("layout connector shutdown"));
      }
    },
    async run(graphView, layoutKey, options, signal) {
      if (!graphView) {
        return { positions: {} };
      }
      if (signal && signal.aborted) {
        throw new Error("layout aborted");
      }
      if (workers.length === 0) {
        await this.init();
      }

      const graph = toGraphPayload(graphView);
      const components = connectedComponents(graph);
      if (components.length === 0) {
        return { positions: {} };
      }

      const results = await Promise.all(components.map((component, idx) => request(
        workers[idx % workers.length],
        "run",
        { layout: layoutKey, graph: component, options: options || {} }
      )));

      if (signal && signal.aborted) {
        throw new Error("layout aborted");
      }

      const merged = { positions: {} };
      for (const result of results) {
        const positions = result && result.positions ? result.positions : {};
        for (const [id, pos] of Object.entries(positions)) {
          merged.positions[id] = pos;
        }
      }
      return merged;
    },
    async animate(graphView, layoutKey, options, animationConfig, signal, onFrame) {
      if (!graphView) {
        return { positions: {} };
      }
      if (signal && signal.aborted) {
        throw new Error("layout aborted");
      }
      if (workers.length === 0) {
        await this.init();
      }

      const worker = workers[0];
      const graph = toGraphPayload(graphView);
      const start = await request(worker, "animate_start", {
        layout: layoutKey,
        graph,
        options: options || {},
      });
      const sessionID = String(start && start.session_id ? start.session_id : "");
      if (!sessionID) {
        throw new Error("layout animation session not created");
      }

      const intervalMs = Math.max(16, Number(animationConfig && animationConfig.intervalMs) || 100);
      const stepsPerFrame = Math.max(1, Math.floor(Number(animationConfig && animationConfig.stepsPerFrame) || 20));
      const now = () => (
        typeof performance !== "undefined" &&
        performance &&
        typeof performance.now === "function"
      ) ? performance.now() : Date.now();

      try {
        let done = false;
        let latest = { positions: {} };
        let lastFrameAt = now();
        while (!done) {
          if (signal && signal.aborted) {
            throw new Error("layout aborted");
          }
          const step = await request(worker, "animate_step", {
            session_id: sessionID,
            steps: stepsPerFrame,
          });
          latest = { positions: step && step.positions ? step.positions : {} };
          done = !!(step && step.done);
          const currentAt = now();
          if (typeof onFrame === "function" && (done || (currentAt - lastFrameAt) >= intervalMs)) {
            onFrame(latest);
            lastFrameAt = currentAt;
          }
          if (!done) {
            await new Promise((resolve) => setTimeout(resolve, 0));
          }
        }
        return latest;
      } finally {
        try {
          await request(worker, "animate_stop", { session_id: sessionID });
        } catch (_err) {}
      }
    },
  };
}

window.createAdalancheLayoutConnector = createAdalancheLayoutConnector;
