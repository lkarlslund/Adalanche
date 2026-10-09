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
        [90, 18, 2], [81, 18, 2], [80, 16, 4], [50, 10, 10], [30, 6, 14], [10, 2, 18], [0, 2, 18], [-1, 2, 18],
    ]) {
        assert.deepEqual(plain(dashPattern(probability)), {dashSize: dash, gapSize: gap}, `probability ${probability}`);
    }
});

test("solid edges draw in the plain layer, and dashed ones leave it clear", () => {
    const {sigmaOptions} = loadRendering();
    const made = [];
    const factory = (name) => (options) => { made.push({name, options}); return {name}; };
    const Sigma = {
        DEFAULT_STYLES: {nodes: {}, edges: {}},
        rendering: {sdfCircle: factory("circle"), layerFill: factory("fill"), pathLine: factory("line"), extremityArrow: factory("arrow"), layerPlain: factory("plain"), layerDashed: factory("dashed")},
        layers: {layerImage: factory("image"), layerBorder: factory("border")},
    };
    const options = sigmaOptions(Sigma);
    assert.deepEqual(plain(options.primitives.edges.layers.map((l) => l.name)), ["plain", "dashed"]);
    assert.deepEqual(plain(made.find((m) => m.name === "plain").options.color), {attribute: "solidColor"});
    const dashed = made.find((m) => m.name === "dashed").options;
    assert.equal(dashed.dashSize.attribute, "dashSize");
    assert.equal(dashed.gapSize.mode, "pixels");
    assert.equal(options.settings.itemSizesReference, "screen");
    const border = made.find((m) => m.name === "border").options.borders;
    assert.equal(border.at(-1).fill, true, "the border ring keeps its inside clear");
});
