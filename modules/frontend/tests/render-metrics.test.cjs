const {test} = require("node:test");
const assert = require("node:assert/strict");
const {readFileSync} = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function loadMetrics() {
    const window = {};
    vm.runInContext(readFileSync(path.join(__dirname, "../html/sigma/render-metrics.js"), "utf8"), vm.createContext({window}));
    return window.WorkspaceRenderMetrics;
}

// A renderer placing nodes at their graph coordinates, with display sizes
// already in screen pixels.
function stubGraph(nodes) {
    const graph = {
        hasNode: (id) => id in nodes,
        getNodeAttributes: (id) => nodes[id],
    };
    const renderer = {
        getNodeDisplayData: (id) => ({x: nodes[id].x, y: nodes[id].y, size: nodes[id].size, hidden: !!nodes[id].hidden}),
        graphToViewport: (p) => ({x: p.x, y: p.y}),
        scaleSize: (size) => size,
    };
    return {graph, renderer};
}

test("a node is found under a point within its radius, without being hovered first", () => {
    const {nodeAtPoint} = loadMetrics();
    const nodes = {a: {x: 100, y: 100, size: 10}, b: {x: 112, y: 100, size: 10}, c: {x: 300, y: 300, size: 10, hidden: true}};
    const {graph, renderer} = stubGraph(nodes);
    const ids = Object.keys(nodes);
    assert.equal(nodeAtPoint(renderer, graph, ids, 100, 100), "a");
    assert.equal(nodeAtPoint(renderer, graph, ids, 105, 100), "a", "overlapping nodes: the nearest");
    assert.equal(nodeAtPoint(renderer, graph, ids, 107, 100), "b");
    assert.equal(nodeAtPoint(renderer, graph, ids, 110, 100), "b");
    assert.equal(nodeAtPoint(renderer, graph, ids, 100, 111), "a", "within the radius plus a little");
    assert.equal(nodeAtPoint(renderer, graph, ids, 100, 113), "");
    assert.equal(nodeAtPoint(renderer, graph, ids, 300, 300), "", "hidden nodes are not hit");
    assert.equal(nodeAtPoint(null, graph, ids, 100, 100), "");
});
