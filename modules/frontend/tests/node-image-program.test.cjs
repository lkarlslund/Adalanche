const {test} = require("node:test");
const assert = require("node:assert/strict");
const {readFileSync} = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

test("icon atlas uses complete texture parameters before and after upload", () => {
    const parameters = new Map();
    let mipmaps = 0;
    const gl = new Proxy({
        TEXTURE_2D: 1, TEXTURE_WRAP_S: 2, TEXTURE_WRAP_T: 3, CLAMP_TO_EDGE: 4,
        TEXTURE_MIN_FILTER: 5, TEXTURE_MAG_FILTER: 6, LINEAR: 7,
        texParameteri(target, parameter, value) { parameters.set(parameter, value); },
        generateMipmap() { mipmaps++; },
    }, {get(object, key) { return key in object ? object[key] : () => ({}); }});
    const window = {Sigma: {}};
    const context = vm.createContext({window, ImageData: class {constructor(width, height) {this.width=width;this.height=height;}}});
    vm.runInContext(readFileSync(path.join(__dirname, "../html/sigma/sigma-node-image-program.js"), "utf8"), context);
    const Program = window.createWorkspaceSigmaNodeImageProgram();
    const program = new Program(gl, {});
    for (const parameter of [gl.TEXTURE_WRAP_S, gl.TEXTURE_WRAP_T]) assert.equal(parameters.get(parameter), gl.CLAMP_TO_EDGE);
    for (const parameter of [gl.TEXTURE_MIN_FILTER, gl.TEXTURE_MAG_FILTER]) assert.equal(parameters.get(parameter), gl.LINEAR);
    program.rebindTexture();
    assert.equal(mipmaps, 0, "arbitrary atlas dimensions must not generate mipmaps");
});
