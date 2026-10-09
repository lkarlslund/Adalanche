let prefs = {};
let alpinePrefsStore = null;
let prefsLoadPromise = null;
let backendPersistCache = {};
let prefsLoadedEventDispatched = false;

window.backendPersist = {
  getItem(key) {
    return Object.prototype.hasOwnProperty.call(backendPersistCache, key)
      ? backendPersistCache[key]
      : null;
  },
  setItem(key, value) {
    backendPersistCache[key] = String(value);
    try {
      const parsed = JSON.parse(value);
      setpref(key, parsed);
    } catch {
      setpref(key, value);
    }
  },
  removeItem(key) {
    delete backendPersistCache[key];
  },
};

function parsePreferenceValue(value) {
  if (typeof value === "boolean" || typeof value === "number" || value == null) {
    return value;
  }
  if (typeof value !== "string") {
    return value;
  }
  if (value === "true") {
    return true;
  }
  if (value === "false") {
    return false;
  }
  if (value !== "" && !isNaN(value)) {
    return Number(value);
  }
  return value;
}

function syncBackendPersistCache() {
  const cache = {};
  for (const key in prefs) {
    cache[key] = JSON.stringify(prefs[key]);
  }
  backendPersistCache = cache;
}

function ingestPrefs(data, dispatchLoadedEvent = false) {
  for (const key in data) {
    data[key] = parsePreferenceValue(data[key]);
  }

  prefs = data;
  syncBackendPersistCache();
  syncAlpinePrefsStore();

  if (dispatchLoadedEvent && !prefsLoadedEventDispatched) {
    prefsLoadedEventDispatched = true;
    document.dispatchEvent(new Event("preferences.loaded"));
  }
}

function loadprefs() {
  return fetch("/api/preferences")
    .then((res) => {
      if (!res.ok) {
        throw new Error(res.statusText);
      }
      return res.json();
    })
    .then((data) => {
      ingestPrefs(data, true);
    });
}

function ensurePrefsLoaded() {
  if (!prefsLoadPromise) {
    prefsLoadPromise = loadprefs();
  }
  return prefsLoadPromise;
}
window.ensurePrefsLoaded = ensurePrefsLoaded;

function getpref(key, defvalue) {
  const value = prefs[key];
  if (value != null) {
    return value;
  }
  return defvalue;
}
window.getpref = getpref;

function setpref(key, value) {
  const oldValue = prefs[key];
  const unchanged =
    oldValue === value ||
    JSON.stringify(oldValue) === JSON.stringify(value);

  if (unchanged) {
    return;
  }

  prefs[key] = value;
  backendPersistCache[key] = JSON.stringify(value);
  syncAlpinePrefsStore();
  document.dispatchEvent(
    new CustomEvent("preferences.updated", {
      detail: { key, value },
    })
  );
  fetch(`/api/preferences/${encodeURIComponent(key)}`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(value),
  }).catch(() => {});
}
window.setpref = setpref;

function preferenceStore() {
  if (window.Alpine && typeof window.Alpine.store === "function") {
    const store = window.Alpine.store("prefs");
    if (store) {
      return store;
    }
  }
  return alpinePrefsStore;
}

function pref(key, defvalue) {
  const store = preferenceStore();
  if (store && typeof store.get === "function") {
    return store.get(key, defvalue);
  }
  return getpref(key, defvalue);
}
window.pref = pref;

function prefBool(key, defvalue = false) {
  const store = preferenceStore();
  if (store && typeof store.bool === "function") {
    return store.bool(key, defvalue);
  }
  return toBoolean(getpref(key, defvalue), defvalue);
}
window.prefBool = prefBool;

function syncAlpinePrefsStore() {
  if (!alpinePrefsStore) {
    return;
  }
  alpinePrefsStore.data = { ...prefs };
  alpinePrefsStore.ready = true;
}

function toBoolean(raw, defvalue) {
  if (raw === true || raw === false) {
    return raw;
  }
  if (raw === "true") {
    return true;
  }
  if (raw === "false") {
    return false;
  }
  if (raw == null) {
    return Boolean(defvalue);
  }
  return Boolean(raw);
}

function initAlpinePrefsBridge() {
  if (!window.Alpine || typeof window.Alpine.store !== "function") {
    return;
  }
  if (!alpinePrefsStore) {
    alpinePrefsStore = {
      ready: false,
      data: {},
      get(key, defvalue) {
        return getpref(key, defvalue);
      },
      set(key, value) {
        setpref(key, value);
        return value;
      },
      bool(key, defvalue = false) {
        return toBoolean(this.get(key, defvalue), defvalue);
      },
      number(key, defvalue = 0) {
        const n = Number(this.get(key, defvalue));
        return Number.isFinite(n) ? n : defvalue;
      },
      has(key) {
        return prefs[key] != null;
      },
    };
    window.Alpine.store("prefs", alpinePrefsStore);
    if (typeof window.Alpine.magic === "function") {
      window.Alpine.magic("pref", () => (key, defvalue) => getpref(key, defvalue));
      window.Alpine.magic("setpref", () => (key, value) => setpref(key, value));
    }
  }
  syncAlpinePrefsStore();
}

document.addEventListener("alpine:init", initAlpinePrefsBridge);
