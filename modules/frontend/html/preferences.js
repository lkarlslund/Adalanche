let prefs = {};
let alpinePrefsStore = null;
let prefsLoadPromise = null;
let backendPersistCache = {};

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

function loadprefs() {
  return fetch("/api/preferences")
    .then((res) => {
      if (!res.ok) {
        throw new Error(res.statusText);
      }
      return res.json();
    })
    .then((data) => {
      for (const key in data) {
        data[key] = parsePreferenceValue(data[key]);
      }

      prefs = data;
      syncBackendPersistCache();
      syncAlpinePrefsStore();
      document.querySelectorAll("[preference]").forEach((el) => updatecontrol(el));
      document.dispatchEvent(new Event("preferences.loaded"));
    });
}

function ensurePrefsLoaded() {
  if (!prefsLoadPromise) {
    prefsLoadPromise = loadprefs();
  }
  return prefsLoadPromise;
}

function dispatchPrefUpdate(ele) {
  ele.dispatchEvent(new Event("prefupdate", { bubbles: true }));
}

function updatecontrol(ele) {
  const name = ele.getAttribute("name");
  const defaultEle = name
    ? document.querySelector(`input[name="${CSS.escape(name)}"][defaultpref]`)
    : null;
  const defaultval = defaultEle ? defaultEle.getAttribute("defaultpref") : undefined;
  let val = getpref(ele.getAttribute("preference"), defaultval);
  if (val == null) {
    return;
  }

  if (ele.type === "checkbox") {
    if (val === "false") {
      val = false;
    }
    ele.checked = Boolean(val);
    dispatchPrefUpdate(ele);
  } else if (ele.type === "radio") {
    if (!name) {
      return;
    }
    document.querySelectorAll(`input[type="radio"][name="${CSS.escape(name)}"]`).forEach((radio) => {
      radio.checked = radio.value == val;
      if (radio.checked) {
        dispatchPrefUpdate(radio);
      }
    });
  } else {
    ele.value = val;
    dispatchPrefUpdate(ele);
  }

  console.log(
    "Triggering change event for element with preference " +
      ele.getAttribute("preference") +
      " with value " +
      val
  );
}

function onUIPreferenceChange(ele) {
  const prefKey = ele.getAttribute("preference");
  if (!prefKey) {
    return;
  }

  if (ele.type === "checkbox") {
    setpref(prefKey, ele.checked);
    dispatchPrefUpdate(ele);
    return;
  }

  if (ele.type === "radio") {
    const name = ele.getAttribute("name");
    if (!name) {
      return;
    }
    const checked = document.querySelector(`input[name="${CSS.escape(name)}"]:checked`);
    if (checked) {
      setpref(prefKey, checked.value);
      dispatchPrefUpdate(checked);
    }
    return;
  }

  setpref(prefKey, ele.value);
  dispatchPrefUpdate(ele);
}

function getpref(key, defvalue) {
  const value = prefs[key];
  if (value != null) {
    return value;
  }

  const uiDefault = document.querySelector(`[preference="${CSS.escape(key)}"][defaultpref]`);
  if (uiDefault && uiDefault.dataset.defaultpref !== undefined) {
    return uiDefault.dataset.defaultpref;
  }
  return defvalue;
}

function setpref(key, value) {
  prefs[key] = value;
  backendPersistCache[key] = JSON.stringify(value);
  syncAlpinePrefsStore();
  document.dispatchEvent(
    new CustomEvent("preferences.updated", {
      detail: { key, value },
    })
  );
  fetch(`/api/preferences/${key}/${value}`).catch(() => {});
}

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

function prefsinit() {
  initAlpinePrefsBridge();
  ensurePrefsLoaded().catch((err) => {
    console.error("Failed to load preferences", err);
  });

  const prefobserver = new MutationObserver(function (mutations) {
    mutations.forEach(function (mutation) {
      const ele = mutation.target;
      if (ele && ele.getAttribute && ele.getAttribute("preference") != null) {
        updatecontrol(ele);
      }
    });
  });

  document.querySelectorAll("[preference]").forEach((el) => {
    prefobserver.observe(el, { childList: true });
  });

  document.querySelectorAll("[preference]").forEach((el) => {
    el.addEventListener("change", function () {
      onUIPreferenceChange(el);
    });
  });
}

// Kick off preference loading immediately so Alpine Persist adapters
// can read cached backend values as early as possible.
ensurePrefsLoaded().catch((err) => {
  console.error("Failed to preload preferences", err);
});
