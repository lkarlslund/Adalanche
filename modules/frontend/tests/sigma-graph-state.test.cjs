const {test} = require("node:test");
const assert = require("node:assert/strict");
const {readFileSync} = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

// A graph store with what the workspace graph uses; dropping an element
// drops its sigma state, as sigma does.
function makeGraphStore(states) {
    return class {
        constructor() { this.nodes = new Map(); this.edges = new Map(); }
        hasNode(id) { return this.nodes.has(id); }
        hasEdge(id) { return this.edges.has(id); }
        addNode(id, attrs) { this.nodes.set(id, {...attrs}); }
        addEdgeWithKey(id, source, target, attrs) { this.edges.set(id, {...attrs}); }
        dropNode(id) { this.nodes.delete(id); states.nodes.delete(id); }
        dropEdge(id) { this.edges.delete(id); states.edges.delete(id); }
        mergeNodeAttributes(id, attrs) { Object.assign(this.nodes.get(id), attrs); }
        mergeEdgeAttributes(id, attrs) { Object.assign(this.edges.get(id), attrs); }
        getNodeAttributes(id) { return this.nodes.get(id); }
        clear() { this.nodes.clear(); this.edges.clear(); states.nodes.clear(); states.edges.clear(); }
    };
}

// The workspace graph over a stub sigma that records element state and
// counts full refreshes.
function load() {
    const states = {nodes: new Map(), edges: new Map(), calls: 0, refreshes: 0};
    const merge = (store, keys, state) => {
        states.calls += 1;
        for (const key of keys) store.set(key, {...(store.get(key) || {}), ...state});
    };
    class Sigma {
        setNodesState(keys, state) { merge(states.nodes, keys, state); }
        setEdgesState(keys, state) { merge(states.edges, keys, state); }
        refresh() { states.refreshes += 1; }
        getSetting() { return undefined; }
        setSettings() {}
        setSetting() {}
    }
    // The bundle's Graph class carries itself as Graph.
    const Store = makeGraphStore(states);
    Store.Graph = Store;
    Sigma.rendering = {};
    Sigma.layers = {};
    const factory = () => ({install() {}, createSelectionLayer() {}, destroy() {}});
    const window = {
        location: {search: ""},
        graphology: {Graph: Store},
        Sigma,
        createWorkspaceSigmaLayout: factory,
        createWorkspaceSigmaOverlays: factory,
        createWorkspaceSigmaInteractions: factory,
        createWorkspaceSigmaViewport: factory,
    };
    const context = vm.createContext({window});
    for (const file of ["render-metrics.js", "sigma-graph-rendering.js", "sigma-graph-renderer.js", "sigma-graph.js"]) {
        vm.runInContext(readFileSync(path.join(__dirname, "../html/sigma", file), "utf8"), context);
    }
    // sigmaOptions needs sigma's real rendering factories; it isn't under test.
    window.WorkspaceSigmaRendering.sigmaOptions = () => ({});
    const graph = window.createWorkspaceSigmaGraph({
        container: {},
        elements: [
            {data: {id: "a"}}, {data: {id: "b"}}, {data: {id: "c"}},
            {data: {id: "ab", source: "a", target: "b"}}, {data: {id: "bc", source: "b", target: "c"}},
        ],
    });
    return {graph, states};
}

const flag = (store, key, name) => !!(store.get(key) || {})[name];

test("selecting and highlighting set sigma state on the changed elements, without a full refresh", () => {
    const {graph, states} = load();
    const before = states.refreshes;

    graph.setSelectedNodeIDs(["a", "b"]);
    assert.ok(flag(states.nodes, "a", "isSelected") && flag(states.nodes, "b", "isSelected"));
    graph.setSelectedNodeIDs(["b", "c"]);
    assert.deepEqual(["a", "b", "c"].map((id) => flag(states.nodes, id, "isSelected")), [false, true, true]);

    graph.setHighlightedEdgeIDs(["ab", "bc"]);
    graph.setHighlightedEdgeIDs(["bc"]);
    assert.deepEqual(["ab", "bc"].map((id) => flag(states.edges, id, "isHighlighted")), [false, true]);
    assert.deepEqual(["a", "b", "c"].map((id) => flag(states.nodes, id, "isHighlighted")), [false, true, true], "the route's nodes are on it too");
    assert.deepEqual(["a", "b", "c"].map((id) => flag(states.nodes, id, "isFaded")), [true, false, false], "the rest fades");
    assert.deepEqual(["ab", "bc"].map((id) => flag(states.edges, id, "isFaded")), [true, false]);
    graph.setHighlightedEdgeIDs([]);
    assert.ok(!flag(states.nodes, "a", "isFaded") && !flag(states.edges, "ab", "isFaded"), "clearing the route brings it back");
    graph.setHighlightedEdgeIDs(["bc"]);

    graph.setEdgeHovered("ab", true);
    assert.equal(graph.hoveredEdgeId, "ab");
    assert.equal(states.refreshes, before, "selection, routes and hover leave the other elements alone");

    const calls = states.calls;
    graph.setSelectedNodeIDs(["c", "b"]);
    assert.equal(states.calls, calls, "the same selection sets nothing");
});

test("elements hidden and shown again get their state back", () => {
    const {graph, states} = load();
    graph.setSelectedNodeIDs(["c"]);
    graph.setHighlightedEdgeIDs(["bc"]);

    graph.setNodeHidden("c", true);
    assert.ok(!states.nodes.has("c") && !states.edges.has("bc"), "sigma forgets dropped elements");
    graph.setNodeHidden("c", false);
    assert.ok(flag(states.nodes, "c", "isSelected"));
    assert.ok(flag(states.edges, "bc", "isHighlighted"), "the edge comes back with its node");
});
