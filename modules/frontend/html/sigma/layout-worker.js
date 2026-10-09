let wasmInitPromise = null;
let wasmReady = false;
let layoutDescribe = null;
let layoutRun = null;
let layoutAnimationStart = null;
let layoutAnimationStep = null;
let layoutAnimationStop = null;

async function ensureWasmReady() {
  if (wasmReady) return;
  if (!wasmInitPromise) {
    wasmInitPromise = (async () => {
      const assetVersion = new URL(self.location.href).searchParams.get("v");
      const cacheSuffix = assetVersion ? `?v=${encodeURIComponent(assetVersion)}` : "";
      const bindingURL = new URL(`../wasm/layout-engine-rust.js${cacheSuffix}`, self.location.href).href;
      importScripts(bindingURL);
      const bindgen = (typeof wasm_bindgen === "function")
        ? wasm_bindgen
        : ((typeof self.wasm_bindgen === "function") ? self.wasm_bindgen : null);
      if (typeof bindgen !== "function") {
        throw new Error("rust wasm bindgen loader missing");
      }
      const wasmURL = new URL(`../wasm/layout-engine-rust_bg.wasm${cacheSuffix}`, self.location.href).href;
      await bindgen({ module_or_path: wasmURL });
      layoutDescribe = bindgen.adalancheLayoutDescribe || bindgen.investig8rLayoutDescribe || self.adalancheLayoutDescribe || self.investig8rLayoutDescribe;
      layoutRun = bindgen.adalancheLayoutRun || bindgen.investig8rLayoutRun || self.adalancheLayoutRun || self.investig8rLayoutRun;
      layoutAnimationStart = bindgen.adalancheLayoutAnimationStart || bindgen.investig8rLayoutAnimationStart || self.adalancheLayoutAnimationStart || self.investig8rLayoutAnimationStart;
      layoutAnimationStep = bindgen.adalancheLayoutAnimationStep || bindgen.investig8rLayoutAnimationStep || self.adalancheLayoutAnimationStep || self.investig8rLayoutAnimationStep;
      layoutAnimationStop = bindgen.adalancheLayoutAnimationStop || bindgen.investig8rLayoutAnimationStop || self.adalancheLayoutAnimationStop || self.investig8rLayoutAnimationStop;
      if (
        typeof layoutDescribe !== "function" ||
        typeof layoutRun !== "function" ||
        typeof layoutAnimationStart !== "function" ||
        typeof layoutAnimationStep !== "function" ||
        typeof layoutAnimationStop !== "function"
      ) {
        throw new Error("layout wasm bridge functions missing");
      }
      wasmReady = true;
    })();
  }
  await wasmInitPromise;
}

function post(id, ok, payload, error) {
  self.postMessage({
    id,
    ok,
    payload: payload || null,
    error: error ? String(error) : "",
  });
}

function parsePayload(raw) {
  if (raw && typeof raw === "object") return raw;
  if (typeof raw === "string") {
    const text = raw.trim();
    if (!text) return {};
    return JSON.parse(text);
  }
  return {};
}

function normalizeInitPayload(parsed) {
  if (Array.isArray(parsed)) {
    return { layouts: parsed };
  }
  if (!parsed || typeof parsed !== "object") {
    return { layouts: [] };
  }
  const layouts = Array.isArray(parsed.layouts)
    ? parsed.layouts
    : (Array.isArray(parsed.Layouts) ? parsed.Layouts : []);
  return { layouts };
}

function normalizeRunPayload(parsed) {
  if (!parsed || typeof parsed !== "object") {
    throw new Error("layout run returned invalid payload");
  }
  const hasOK = typeof parsed.ok === "boolean"
    ? parsed.ok
    : (typeof parsed.OK === "boolean" ? parsed.OK : null);
  const error = String(parsed.error || parsed.Error || "").trim();
  const positions = (parsed.positions && typeof parsed.positions === "object")
    ? parsed.positions
    : ((parsed.Positions && typeof parsed.Positions === "object") ? parsed.Positions : null);

  if (hasOK === false) {
    throw new Error(error || "layout run failed");
  }
  if (hasOK === true) {
    return { ok: true, positions: positions || {} };
  }
  if (positions) {
    return { ok: true, positions };
  }
  if (error) {
    throw new Error(error);
  }
  throw new Error("layout run returned no positions");
}

function normalizeAnimationStartPayload(parsed) {
  if (!parsed || typeof parsed !== "object") {
    throw new Error("layout animation start returned invalid payload");
  }
  const hasOK = typeof parsed.ok === "boolean"
    ? parsed.ok
    : (typeof parsed.OK === "boolean" ? parsed.OK : null);
  const error = String(parsed.error || parsed.Error || "").trim();
  const sessionID = String(parsed.session_id || parsed.SessionID || "").trim();
  if (hasOK === false) {
    throw new Error(error || "layout animation start failed");
  }
  if (!sessionID) {
    throw new Error(error || "layout animation start returned no session id");
  }
  return { ok: true, session_id: sessionID };
}

function normalizeAnimationStepPayload(parsed) {
  if (!parsed || typeof parsed !== "object") {
    throw new Error("layout animation step returned invalid payload");
  }
  const hasOK = typeof parsed.ok === "boolean"
    ? parsed.ok
    : (typeof parsed.OK === "boolean" ? parsed.OK : null);
  const error = String(parsed.error || parsed.Error || "").trim();
  const positions = (parsed.positions && typeof parsed.positions === "object")
    ? parsed.positions
    : ((parsed.Positions && typeof parsed.Positions === "object") ? parsed.Positions : {});
  const done = !!(parsed.done || parsed.Done);
  if (hasOK === false) {
    throw new Error(error || "layout animation step failed");
  }
  return { ok: true, positions, done };
}

self.onmessage = async (event) => {
  const msg = event && event.data ? event.data : {};
  const id = msg.id || "";
  const type = msg.type || "";
  try {
    await ensureWasmReady();
    if (type === "init") {
      const raw = layoutDescribe();
      const parsed = parsePayload(raw);
      post(id, true, normalizeInitPayload(parsed), "");
      return;
    }
    if (type === "run") {
      const raw = layoutRun(JSON.stringify(msg.payload || {}));
      const parsed = parsePayload(raw);
      const normalized = normalizeRunPayload(parsed);
      post(id, true, normalized, "");
      return;
    }
    if (type === "animate_start") {
      const raw = layoutAnimationStart(JSON.stringify(msg.payload || {}));
      const parsed = parsePayload(raw);
      const normalized = normalizeAnimationStartPayload(parsed);
      post(id, true, normalized, "");
      return;
    }
    if (type === "animate_step") {
      const raw = layoutAnimationStep(JSON.stringify(msg.payload || {}));
      const parsed = parsePayload(raw);
      const normalized = normalizeAnimationStepPayload(parsed);
      post(id, true, normalized, "");
      return;
    }
    if (type === "animate_stop") {
      const raw = layoutAnimationStop(JSON.stringify(msg.payload || {}));
      const parsed = parsePayload(raw);
      const normalized = normalizeRunPayload(parsed);
      post(id, true, normalized, "");
      return;
    }
    post(id, false, null, `unsupported worker message type: ${type}`);
  } catch (err) {
    post(id, false, null, err && err.message ? err.message : String(err));
  }
};
