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

// A graph of nodes a, b and c, with a and b selected, over a renderer that
// records its settings and event handlers.
function stubGraph() {
    const container = target();
    container.getBoundingClientRect = () => ({left: 0, top: 0});
    container.contains = () => true;
    const handlers = {};
    const positions = {};
    const graph = {
        container,
        notified: [],
        hoveredNodeId: "",
        hoveredEdgeId: "",
        selectedNodeIDsSet: new Set(["a", "b"]),
        graph: {hasNode: (id) => ["a", "b", "c"].includes(id)},
        renderer: {
            settings: {},
            handlers,
            on(name, handler) { handlers[name] = handler; },
            setSettings(settings) { Object.assign(this.settings, settings); },
            getCamera: () => ({on() {}}),
        },
        relativePoint(event) { return {x: event.clientX, y: event.clientY}; },
        getNodeAtPosition: () => "",
        setNodePosition(id, p) { positions[id] = [p.x, p.y]; },
        positions,
        nodePosition: (id) => ({x: positions[id][0], y: positions[id][1]}),
        notify(name, payload) { graph.notified.push([name, payload]); },
        overlays: {updateSelectionLayer() {}, hideSelectionLayer() {}, queueIconSync() {}, selectionRect: () => null},
    };
    return graph;
}

test("sigma drags nodes, taking the selection along, and our positions follow", () => {
    const window = load();
    const graph = stubGraph();
    window.createWorkspaceSigmaInteractions(graph).install();
    const {settings, handlers} = graph.renderer;

    assert.equal(settings.enableNodeDrag, true);
    assert.deepEqual(Array.from(settings.getDraggedNodes("a")).sort(), ["a", "b"], "a selected node drags the selection");
    assert.deepEqual(Array.from(settings.getDraggedNodes("c")), ["c"]);
    assert.deepEqual(JSON.parse(JSON.stringify(settings.dragPositionToAttributes({x: 3, y: 4}, "a"))), {x: 3, y: 4});
    assert.deepEqual(graph.positions.a, [3, 4], "the workspace's own positions follow the drag");

    const coords = {x: 3, y: 4, original: {clientX: 3, clientY: 4}};
    handlers.nodeDragStart({node: "a", allDraggedNodes: ["a", "b"], event: coords});
    handlers.nodeDragEnd({node: "a", allDraggedNodes: ["a", "b"], event: coords});
    const notified = graph.notified.map(([name]) => name);
    assert.deepEqual(notified, ["nodedragstart", "nodedragend"]);
    const end = graph.notified[1][1];
    assert.equal(end.nodeId, "a");
    assert.deepEqual(Array.from(end.nodeIds), ["a", "b"]);
    assert.ok(graph.suppressNextClick, "the click that ends a drag is not a node click");
});

test("only a shift-press for the selection box is kept from sigma", () => {
    const window = load();
    const graph = stubGraph();
    window.createWorkspaceSigmaInteractions(graph).install();
    const down = graph.container.listeners.find((l) => l.name === "pointerdown");
    assert.ok(down && down.capture, "pointerdown is handled in the capture phase, before sigma");

    const press = pointer("pointerdown", 50, 50);
    graph.container.fire("pointerdown", press);
    assert.ok(!press.stopped, "a plain press goes to sigma, which drags or pans");

    const shift = pointer("pointerdown", 50, 50, {shiftKey: true});
    graph.container.fire("pointerdown", shift);
    assert.ok(shift.stopped && graph.selectionState, "a shift-press starts the selection box");

    const touch = pointer("pointerdown", 50, 50, {pointerType: "touch", shiftKey: true});
    graph.selectionState = null;
    graph.container.fire("pointerdown", touch);
    assert.ok(!touch.stopped, "touch stays with sigma");
});

test("edges come from sigma's picking: hover follows the pointer, clicks go to the edge", () => {
    const window = load();
    const graph = stubGraph();
    window.createWorkspaceSigmaInteractions(graph).install();
    const {handlers} = graph.renderer;
    const names = () => graph.notified.map(([name, p]) => name + (p.edgeId ? ":" + p.edgeId + ":" + p.hovered : ""));

    handlers.enterEdge({edge: "e1", event: {x: 10, y: 10, original: pointer("pointermove", 10, 10)}});
    window.fire("pointermove", pointer("pointermove", 12, 11, {target: graph.container}));
    const follow = graph.notified[1][1];
    assert.deepEqual([follow.clientPosition.x, follow.clientPosition.y], [12, 11], "the hover card follows the pointer");

    graph.container.fire("click", pointer("click", 12, 11));
    assert.equal(graph.notified[2][0], "edgeclick");
    assert.equal(graph.notified[2][1].edgeId, "e1");

    handlers.leaveEdge({edge: "e1", event: {x: 40, y: 40, original: pointer("pointermove", 40, 40)}});
    window.fire("pointermove", pointer("pointermove", 41, 41, {target: graph.container}));
    graph.container.fire("click", pointer("click", 41, 41));
    assert.deepEqual(names(), ["edgehoverchanged:e1:true", "edgehoverchanged:e1:true", "edgeclick:e1:undefined",
        "edgehoverchanged:e1:false", "backgroundclick"]);
});
