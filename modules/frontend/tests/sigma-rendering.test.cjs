const {test} = require("node:test");
const assert = require("node:assert/strict");
const {readFileSync, existsSync} = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

// Values made inside the vm context have its prototypes; compare plain copies.
const plain = (value) => JSON.parse(JSON.stringify(value));

function loadRendering() {
    const window = {};
    vm.runInContext(readFileSync(path.join(__dirname, "../html/sigma/sigma-graph-rendering.js"), "utf8"), vm.createContext({window}));
    return window.WorkspaceSigmaRendering;
}

test("edges less likely than certain are dashed, with longer gaps the less likely they are", () => {
    const {dashPattern} = loadRendering();
    for (const [probability, dash, gap] of [
        [100, 0, 0], [95, 0, 0], [undefined, 0, 0],
        [90, 9, 1], [81, 9, 1], [80, 8, 2], [50, 5, 5], [30, 3, 7], [10, 1, 9], [0, 1, 9], [-1, 1, 9],
    ]) {
        assert.deepEqual(plain(dashPattern(probability)), {dashSize: dash, gapSize: gap}, `probability ${probability}`);
    }
});

test("solid edges draw in the plain layer, and dashed ones leave it clear", () => {
    const {sigmaOptions} = loadRendering();
    const made = [];
    const factory = (name) => (options) => { made.push({name, options}); return {name}; };
    const dashedGLSL = "vec4 layer_dashed(EdgeContext ctx) {\n  float pixelToWorld = u_correctionRatio / u_sizeRatio;\n}";
    const Sigma = {
        DEFAULT_STYLES: {nodes: {}, edges: {}},
        rendering: {sdfCircle: factory("circle"), layerFill: factory("fill"), pathLine: factory("line"), extremityArrow: factory("arrow"), layerPlain: factory("plain"),
            layerDashed: (options) => { made.push({name: "dashed", options}); return {name: "dashed", glsl: dashedGLSL, uniforms: [], attributes: []}; }},
        layers: {layerImage: factory("image"), layerBorder: factory("border")},
    };
    const options = sigmaOptions(Sigma, () => ({correctionRatio: 0.02, zoomRatio: 0.5}));
    assert.deepEqual(plain(options.primitives.edges.layers.map((l) => l.name)), ["plain", "dashed"]);
    assert.deepEqual(plain(made.find((m) => m.name === "plain").options.color), {attribute: "solidColor"});
    const dashed = made.find((m) => m.name === "dashed").options;
    assert.equal(dashed.dashSize.attribute, "dashSize");
    assert.equal(dashed.gapSize.mode, "pixels");
    assert.equal(options.settings.itemSizesReference, "screen");
    const border = made.find((m) => m.name === "border").options.borders;
    assert.equal(border.at(-1).fill, true, "the border ring keeps its inside clear");

    // Dashes are sized along the edge: the pixel conversion is a uniform set
    // each frame to a pixel's graph distance at zoom 1.
    const dashedLayer = options.primitives.edges.layers[1];
    assert.match(dashedLayer.glsl, /float pixelToWorld = u_dashPixelToWorld;/);
    assert.ok(dashedLayer.uniforms.some((u) => u.name === "u_dashPixelToWorld"));
    dashedLayer.lifecycle({}).beforeRender();
    assert.equal(dashedLayer.uniforms.find((u) => u.name === "u_dashPixelToWorld").value, 0.04);
});

// Sigma restyles an element whose state changed into its cached display
// data, keeping values no rule sets this time. Every value a state rule
// changes must come back when the state ends.
const sigmaTypes = path.join(__dirname, "../vendor-src/node_modules/sigma/types/dist/sigma-types.cjs.dev.js");

test("selection and route styles come and go with their state", {skip: !existsSync(sigmaTypes) && "sigma is not installed in vendor-src"}, () => {
    globalThis.WebGL2RenderingContext = globalThis.WebGL2RenderingContext || new Proxy({}, {get: () => 0});
    const T = require(sigmaTypes);
    const factory = () => () => ({});
    const Sigma = {
        DEFAULT_STYLES: T.DEFAULT_STYLES,
        rendering: new Proxy({layerDashed: () => ({glsl: "", uniforms: []})}, {get: (t, k) => t[k] || factory()}),
        layers: new Proxy({}, {get: () => factory()}),
    };
    const {styles, customNodeState, customEdgeState} = loadRendering().sigmaOptions(Sigma, () => null);
    const style = (kind, attrs, state, data) => {
        const evaluate = kind === "node" ? T.evaluateNodeStyle : T.evaluateEdgeStyle;
        const base = kind === "node" ? {...T.DEFAULT_NODE_STATE, ...customNodeState} : {...T.DEFAULT_EDGE_STATE, ...customEdgeState};
        evaluate(styles[kind === "node" ? "nodes" : "edges"], attrs, {...base, ...state}, T.DEFAULT_GRAPH_STATE, null, data);
        return {...data};
    };

    const edge = {color: "#888", solidColor: "#888", size: 2, routeSolidColor: "#0d6efd", routeSize: 4};
    const edgeData = {};
    const routed = style("edge", edge, {isHighlighted: true}, edgeData);
    assert.deepEqual([routed.color, routed.solidColor, routed.size, routed.depth], ["#0d6efd", "#0d6efd", 4, "topEdges"]);
    const after = style("edge", edge, {isHighlighted: false}, edgeData);
    assert.deepEqual([after.color, after.solidColor, after.size, after.depth], ["#888", "#888", 2, "edges"]);
    assert.equal(style("edge", edge, {isFaded: true}, edgeData).opacity, 0.15);
    assert.equal(style("edge", edge, {isFaded: false}, edgeData).opacity, 1);

    const node = {x: 0, y: 0, size: 10, selectedSize: 13, borderColor: "rgba(0,0,0,0)", borderSize: 0, selectedBorderColor: "#fff", selectedBorderSize: 0.09};
    const nodeData = {};
    const selected = style("node", node, {isSelected: true, isHighlighted: true}, nodeData);
    assert.deepEqual([selected.size, selected.borderColor, selected.borderSize, selected.depth], [13, "#fff", 0.09, "topNodes"]);
    const plainNode = style("node", node, {isSelected: false, isHighlighted: false}, nodeData);
    assert.deepEqual([plainNode.size, plainNode.borderColor, plainNode.borderSize, plainNode.depth], [10, "rgba(0,0,0,0)", 0, "nodes"]);
    const faded = style("node", node, {isFaded: true}, nodeData);
    assert.deepEqual([faded.opacity, faded.labelVisibility], [0.15, "hidden"]);
    const back = style("node", node, {isFaded: false}, nodeData);
    assert.deepEqual([back.opacity, back.labelVisibility], [1, "auto"]);
});
