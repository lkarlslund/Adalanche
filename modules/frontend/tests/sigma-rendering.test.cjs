const {test} = require("node:test");
const assert = require("node:assert/strict");
const {readFileSync} = require("node:fs");
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
