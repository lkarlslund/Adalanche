const {test} = require("node:test");
const assert = require("node:assert/strict");
const {readFileSync} = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function target() {
    const listeners = [];
    return {
        listeners,
        addEventListener(name, handler, options) { listeners.push({name, handler, capture: options === true || !!(options && options.capture)}); },
        removeEventListener() {},
        fire(name, event) { for (const l of listeners) if (l.name === name) l.handler(event); },
    };
}

function load() {
    const window = target();
    window.location = {search: ""};
    const context = vm.createContext({window});
    for (const file of ["render-metrics.js", "sigma-graph-interactions.js"]) {
        vm.runInContext(readFileSync(path.join(__dirname, "../html/sigma", file), "utf8"), context);
    }
    return window;
}

function pointer(type, x, y, extra) {
    const event = {type, clientX: x, clientY: y, button: 0, pointerType: "mouse", stopped: false, prevented: false,
        preventDefault() { this.prevented = true; },
        stopPropagation() { this.stopped = true; },
        stopImmediatePropagation() { this.stopped = true; }};
    return Object.assign(event, extra);
}

// A graph with one node at (50, 50) and a container at the origin.
function stubGraph() {
    const container = target();
    container.getBoundingClientRect = () => ({left: 0, top: 0});
    container.contains = () => true;
    const graph = {
        container,
        notified: [],
        moved: [],
        hoveredNodeId: "",
        hoveredEdgeId: "",
        renderer: {on() {}, getCamera: () => ({on() {}}), viewportToGraph: (p) => p},
        relativePoint(event) { return {x: event.clientX, y: event.clientY}; },
        getNodeAtPosition: (x, y) => (Math.hypot(x - 50, y - 50) <= 10 ? "n" : ""),
        getEdgeAtPosition: () => "",
        setNodePosition(id, p) { graph.moved.push([id, p.x, p.y]); },
        nodePosition: () => ({x: 0, y: 0}),
        refresh() {},
        notify(name, payload) { graph.notified.push(name); },
        overlays: {updateSelectionLayer() {}, hideSelectionLayer() {}, queueIconSync() {}},
    };
    return graph;
}

test("a press on a node drags it, and sigma never sees the press, so the camera does not pan", () => {
    const window = load();
    const graph = stubGraph();
    window.createWorkspaceSigmaInteractions(graph).install();

    // Sigma 4 pans from pointerdown on the container; ours must run first.
    const down = graph.container.listeners.find((l) => l.name === "pointerdown");
    assert.ok(down && down.capture, "pointerdown is handled in the capture phase");
    assert.ok(!graph.container.listeners.some((l) => l.name === "mousedown"), "mousedown comes after sigma has started panning");

    const press = pointer("pointerdown", 50, 50);
    graph.container.fire("pointerdown", press);
    assert.ok(press.stopped && press.prevented, "the press on a node stops before sigma");
    window.fire("pointermove", pointer("pointermove", 80, 90));
    window.fire("pointerup", pointer("pointerup", 80, 90));
    assert.deepEqual(JSON.parse(JSON.stringify(graph.moved)), [["n", 80, 90]]);
    assert.deepEqual(graph.notified.filter((n) => n.startsWith("nodedrag")), ["nodedragstart", "nodedragend"]);

    // A press on the background goes on to sigma, which pans.
    const background = pointer("pointerdown", 200, 200);
    graph.container.fire("pointerdown", background);
    assert.ok(!background.stopped);

    // Touch stays with sigma.
    const touch = pointer("pointerdown", 50, 50, {pointerType: "touch"});
    graph.container.fire("pointerdown", touch);
    assert.ok(!touch.stopped);
});
