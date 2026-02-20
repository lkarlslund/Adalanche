window.onpopstate = function (event) {
  document.body.innerHTML = event.state;
};

function translateAutoTheme(theme) {
  if (theme === "auto") {
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  return theme;
}

function setTheme(theme) {
  document.documentElement.setAttribute("data-bs-theme", theme);
  if (window.cy) {
    cy.style(cytostyle);
    applyEdgeStyles(cy);
    applyNodeStyles(cy);
  }
}

function applyPreferredTheme() {
  const themeMode = getpref("theme", "auto");
  setTheme(translateAutoTheme(themeMode));
}

document.addEventListener("preferences.loaded", applyPreferredTheme);
document.addEventListener("preferences.updated", (event) => {
  if (event?.detail?.key === "theme") {
    applyPreferredTheme();
  }
});

window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
  if (getpref("theme", "auto") === "auto") {
    applyPreferredTheme();
  }
});

function set_query(query) {
  const queryEl = document.getElementById("aqlquerytext");
  if (queryEl) {
    queryEl.value = query;
  }
}

function getWindowManager() {
  const windowsRoot = document.getElementById("windows");
  if (!windowsRoot || !window.Alpine || typeof window.Alpine.$data !== "function") {
    return null;
  }
  return window.Alpine.$data(windowsRoot);
}

function get_window(id) {
  const wm = getWindowManager();
  if (!wm) {
    return document.querySelector("#windows > #window_" + id);
  }
  const win = wm.findWindow(id);
  if (!win) {
    return null;
  }
  return {
    remove: () => wm.closeWindow(id),
  };
}

function new_window(id, title, content, alignment = "topleft", height = 0, width = 0) {
  const wm = getWindowManager();
  if (!wm) {
    return true;
  }
  return wm.openWindow({
    id,
    title,
    content,
    alignment,
    height,
    width,
  });
}

function busystatus(busytext) {
  const status = document.getElementById("status");
  if (!status) {
    return;
  }
  status.innerHTML =
    `<div class="text-center pb-3">` +
    busytext +
    `</div>
            <div class="p-2">
        <div class="sk-center sk-chase">
  <div class="sk-chase-dot"></div>
  <div class="sk-chase-dot"></div>
  <div class="sk-chase-dot"></div>
  <div class="sk-chase-dot"></div>
  <div class="sk-chase-dot"></div>
  <div class="sk-chase-dot"></div>
</div>
            </div>`;
  status.style.display = "";
}

function encodeaqlquery() {
  const forms = ["aqlqueryform", "analysisoptionsform"];
  const payload = {};
  forms.forEach((formId) => {
    const form = document.getElementById(formId);
    if (!form) {
      return;
    }
    Array.from(form.elements).forEach((el) => {
      if (!el.name || el.disabled) {
        return;
      }
      if ((el.type === "checkbox" || el.type === "radio") && !el.checked) {
        return;
      }
      if (el.type === "number") {
        payload[el.name] = Number(el.value);
      } else if (el.type === "checkbox") {
        payload[el.name] = true;
      } else {
        payload[el.name] = el.value;
      }
    });
  });
  return JSON.stringify(payload);
}

function buildURL(url, params) {
  if (!params) {
    return url;
  }
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null) {
      query.append(key, value);
    }
  });
  const qs = query.toString();
  return qs ? `${url}?${qs}` : url;
}

function getErrorText(err) {
  if (err && typeof err === "object") {
    if (err.text) {
      return err.text;
    }
    if (err.message) {
      return err.message;
    }
  }
  return String(err);
}

async function fetchJSON(url, options = {}) {
  const response = await fetch(url, options);
  const text = await response.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch (e) {
      data = null;
    }
  }
  if (!response.ok) {
    throw {
      status: response.status,
      text: text || response.statusText,
      data,
    };
  }
  return data;
}

async function fetchJSONWithTimeout(url, timeoutMs) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetchJSON(url, { signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}

function setVisible(id, visible) {
  const el = document.getElementById(id);
  if (!el) {
    return;
  }
  el.style.display = visible ? "" : "none";
}

function setHTML(id, html) {
  const el = document.getElementById(id);
  if (!el) {
    return;
  }
  el.innerHTML = html;
}

function clearElement(id) {
  const el = document.getElementById(id);
  if (!el) {
    return;
  }
  el.innerHTML = "";
}

async function aqlanalyze(e) {
  busystatus("Analyzing");

  try {
    const data = await fetchJSON("/api/aql/analyze", {
      method: "POST",
      headers: {
        "Content-Type": "application/json; charset=utf-8",
      },
      body: encodeaqlquery(),
    });

    if (data.total == 0) {
      setHTML("status", "No results");
      setVisible("status", true);
      return;
    }

    // Remove all windows
    document.querySelectorAll("#windows .window").forEach((el) => el.remove());

    var info = "";
    if (data.nodecounts["start"] > 0 && data.nodecounts["end"] > 0) {
      info +=
        "Located " +
        data.nodecounts["start"] +
        " start nodes and " +
        data.nodecounts["end"] +
        " end nodes<hr/>";
    }

    info += "<table>";
    for (var objecttype in data.resulttypes) {
      info +=
        '<tr><td class="text-end pe-3">' +
        data.resulttypes[objecttype] +
        "</td><td>" +
        objecttype +
        "</td></tr>";
    }
    info +=
      '<tr><td class="text-end pe-3">' +
      data.total +
      "</td><td>total nodes in analysis</td></tr>";
    if (data.removed > 0) {
      info +=
        '<tr><td class="text-end pe-3"><b>' +
        data.removed +
        "</b></td><td><b>nodes were removed by node limiter</b></td></tr>";
    }
    info += "</table>";

    new_window("results", "Query results", info);

    // Single Alpine state write collapses immediately; $persist+backend adapter
    // handles saving state.
    if (getpref("ui.hide.options.on.analysis", false)) {
      if (window.Alpine && typeof window.Alpine.$data === "function") {
        const optionsRoot = document.getElementById("options");
        if (optionsRoot) {
          const data = window.Alpine.$data(optionsRoot);
          if (data && typeof data.open === "boolean") {
            data.open = false;
          }
        }
      }
    }
    if (getpref("ui.hide.query.on.analysis", false)) {
      window.dispatchEvent(
        new CustomEvent("ui:set-query-open", {
          detail: false,
        })
      );
    }

    new Promise((resolve) => {
      initgraph(data.elements);
    });

    history.pushState(document.body.innerHTML, "adalanche");
  } catch (err) {
    toast("Problem loading graph", getErrorText(err), "error");
    clearElement("status");
    setVisible("status", false);
  }
}


let lastwasidle;
let progressSocket;

function setOfflineStatusUI(isOffline) {
  const upperStatus = document.getElementById("upperstatus");
  const reconnecting = document.getElementById("reconnecting");
  if (upperStatus) {
    upperStatus.classList.toggle("upperstatus-offline", !!isOffline);
  }
  if (reconnecting) {
    reconnecting.classList.toggle("d-none", !isOffline);
  }
}

function showBackendOffline() {
  setHTML("backendstatus", "Adalanche backend is offline");
  setVisible("upperstatus", true);
  clearElement("progressbars");
  setVisible("progressbars", false);
  setVisible("offlineblur", true);
  setOfflineStatusUI(true);
}

function connectProgress() {
  if (location.origin.startsWith("https://")) {
    // Polled
    fetchJSONWithTimeout("/api/backend/progress", 2000)
      .then((data) => {
        handleProgressData(data);
        setTimeout(connectProgress, 2000);
      })
      .catch(() => {
        showBackendOffline();

        setTimeout(connectProgress, 10000);
      });
  } else {
    // Websocket
    progressSocket = new WebSocket(
      location.origin.replace(/^http/, "ws") + "/api/backend/ws-progress"
    );

    progressSocket.onopen = function () {
      lastwasidle = false;
    }

    progressSocket.onerror = function () {
      showBackendOffline();
    };

    progressSocket.onclose = function () {
      showBackendOffline();
      setTimeout(connectProgress, 3000);
    };

    progressSocket.onmessage = function (message) {
      progress = JSON.parse(message.data);
      handleProgressData(progress);
    };
  }
}

function handleProgressData(progress) {
  setVisible("offlineblur", false);
  setOfflineStatusUI(false);

  if (progress.status == "Ready") {
    if (!data_loaded) {
      data_loaded = true;
      autorun_query();
    }
  }

  const progressbars = progress.progressbars;
  if (progressbars.length > 0) {
    lastwasidle = false;
    const keepProgressbars = new Set();
    const progressRoot = document.getElementById("progressbars");
    for (let i in progressbars) {
      const progressbar = progressbars[i];
      if (progressbar.Done) {
        continue;
      }
      keepProgressbars.add(String(progressbar.ID));

      // find progressbar
      let pb = document.getElementById("progressbar_" + progressbar.ID);
      if (!pb && !progressbar.Done && progressRoot) {
        progressRoot.insertAdjacentHTML(
          "beforeend",
          `<div id="progressbar_` +
            progressbar.ID +
            `" class="mb-1" data-progress-id="` +
            progressbar.ID +
            `">
            <div class="small">` +
            progressbar.Title +
            `
              <div id="pct" class="small float-end">` +
            progressbar.Percent.toFixed(2) +
            `%</div>
            </div>
            <div class="progress">
              <div class="progress-bar rounded-0" role="progressbar" aria-valuemin="0" aria-valuemax="100"></div>
            </div>
          </div>`
        );
        pb = document.getElementById("progressbar_" + progressbar.ID);
      }

      // Update progressbar
      if (pb) {
        const progbar = pb.querySelector(".progress-bar");
        if (progbar) {
          progbar.setAttribute("aria-valuenow", progressbar.Percent.toFixed(0));
          progbar.style.width = progressbar.Percent.toFixed(0) + "%";
        }
        const pct = pb.querySelector("#pct");
        if (pct) {
          pct.innerHTML = progressbar.Percent.toFixed(2) + "%";
        }
      }
    }
    // remove old progressbars
    document.querySelectorAll("#progressbars [data-progress-id]").forEach((el) => {
      const id = el.id;
      if (!keepProgressbars.has(id.substring(12))) {
        el.remove();
      }
    });

    setVisible("upperstatus", true);
    setVisible("progressbars", true);
    setHTML("backendstatus", "Adalanche is processing");
  } else {
    if (!lastwasidle) {
      clearElement("progressbars");
      setVisible("progressbars", false);
      setHTML("backendstatus", "Adalanche backend is idle");
      setVisible("upperstatus", false);
    }
    lastwasidle = true;
  }
}

// start update cycle
connectProgress();

function toast(title, contents, toastclass) {
  if (!toastclass) {
    toastclass = "info";
  }
  toastbody = contents;
  if (title) {
    toastbody = "<span class='fw-bold'>" + title + "</span><br>" + contents;
  }
  Toastify({
    text: toastbody,
    duration: 1000000,
    // avatar: icon,
    // destination: "https://github.com/apvarun/toastify-js",
    newWindow: true,
    close: true,
    className: toastclass,
    escapeMarkup: false,
    gravity: "bottom", // `top` or `bottom`
    position: "left", // `left`, `center` or `right`
    stopOnFocus: true, // Prevents dismissing of toast on hover
    style: {
      // background: "orange",
      // background: "linear-gradient(to right, #00b09b, #96c93d)",
    },
    onClick: function () {}, // Callback after click
  }).showToast();
}

var initial_query_set = false;
var queries = [];

function renderQueriesDropdown() {
  const dropdowncontent = document.getElementById("aqlqueries");
  if (!dropdowncontent) {
    return;
  }
  dropdowncontent.innerHTML = "";

  queries.forEach((query, i) => {
    const li = document.createElement("li");
    li.className = "dropdown-item";
    li.setAttribute("querynum", String(i));
    li.setAttribute("queryname", query.name);
    if (query.default) {
      li.id = "defaultquery";
    }
    li.append(document.createTextNode(query.name));

    if (query.user_defined) {
      const eraseIcon = document.createElement("i");
      eraseIcon.className = "float-end bi-eraser";
      li.appendChild(eraseIcon);
    }

    li.addEventListener("click", function (event) {
      if (event.target !== li) return; // not children, only the li
      const queryIndex = Number(li.getAttribute("querynum"));
      set_query(queries[queryIndex].query);
    });

    const icon = li.querySelector("i");
    if (icon) {
      icon.addEventListener("click", async function (event) {
        event.stopPropagation();
        const queryname = li.getAttribute("queryname");
        try {
          await fetchJSON("api/backend/queries/" + queryname, {
            method: "DELETE",
          });
          toast("Query deleted successfully", "", "success");
          updateQueries();
        } catch (err) {
          toast("Error deleting query", getErrorText(err), "error");
        }
      });
    }

    dropdowncontent.appendChild(li);
  });
}

async function updateQueries() {
  try {
    queries = await fetchJSON("/api/backend/queries");
    renderQueriesDropdown();

    if (!initial_query_set) {
      const defaultQuery = document.getElementById("defaultquery");
      if (defaultQuery) {
        const querynum = Number(defaultQuery.getAttribute("querynum"));
        set_query(queries[querynum].query);
      }
      initial_query_set = true;
      autorun_query();
    }
  } catch (err) {
    toast("Error loading queries", getErrorText(err), "error");
  }
}

// When we´re ready ...
document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll("[data-bs-toggle='tooltip']").forEach((el) => {
    new bootstrap.Tooltip(el);
  });

  const exploreButton = document.getElementById("explore");
  if (exploreButton) {
    exploreButton.addEventListener("click", function () {
      new_window(
        "explore",
        "Explore objects",
        `<div id="exploretree" x-data="exploreTree()" x-init="init()" class="p-1">
          <template x-for="node in nodes" :key="node.id">
            <div x-data="exploreTreeNode(node, loadChildren, onNodeClick)">
              <div class="d-flex align-items-center gap-1 py-1">
                <button
                  type="button"
                  class="btn btn-sm btn-outline-secondary py-0 px-1"
                  x-show="node.children"
                  @click="toggle()"
                  x-text="open ? '-' : '+'"
                ></button>
                <span
                  class="cursor-pointer"
                  :class="selected ? 'fw-bold text-warning' : ''"
                  @click="selectNode()"
                  x-text="node.text"
                ></span>
              </div>
              <div x-show="open" class="ps-3">
                <div x-show="loading" class="small text-muted">Loading...</div>
                <template x-for="child in children" :key="child.id">
                  <div x-data="exploreTreeNode(child, loadChildren, onNodeClick)">
                    <div class="d-flex align-items-center gap-1 py-1">
                      <button
                        type="button"
                        class="btn btn-sm btn-outline-secondary py-0 px-1"
                        x-show="node.children"
                        @click="toggle()"
                        x-text="open ? '-' : '+'"
                      ></button>
                      <span
                        class="cursor-pointer"
                        :class="selected ? 'fw-bold text-warning' : ''"
                        @click="selectNode()"
                        x-text="node.text"
                      ></span>
                    </div>
                    <div x-show="open" class="ps-3">
                      <div x-show="loading" class="small text-muted">Loading...</div>
                      <template x-for="child in children" :key="child.id">
                        <div x-data="exploreTreeNode(child, loadChildren, onNodeClick)">
                          <div class="d-flex align-items-center gap-1 py-1">
                            <button
                              type="button"
                              class="btn btn-sm btn-outline-secondary py-0 px-1"
                              x-show="node.children"
                              @click="toggle()"
                              x-text="open ? '-' : '+'"
                            ></button>
                            <span
                              class="cursor-pointer"
                              :class="selected ? 'fw-bold text-warning' : ''"
                              @click="selectNode()"
                              x-text="node.text"
                            ></span>
                          </div>
                          <div x-show="open" class="ps-3">
                            <div x-show="loading" class="small text-muted">Loading...</div>
                            <template x-for="child in children" :key="child.id">
                              <div x-data="exploreTreeNode(child, loadChildren, onNodeClick)">
                                <div class="d-flex align-items-center gap-1 py-1">
                                  <button
                                    type="button"
                                    class="btn btn-sm btn-outline-secondary py-0 px-1"
                                    x-show="node.children"
                                    @click="toggle()"
                                    x-text="open ? '-' : '+'"
                                  ></button>
                                  <span
                                    class="cursor-pointer"
                                    :class="selected ? 'fw-bold text-warning' : ''"
                                    @click="selectNode()"
                                    x-text="node.text"
                                  ></span>
                                </div>
                              </div>
                            </template>
                          </div>
                        </div>
                      </template>
                    </div>
                  </div>
                </template>
              </div>
            </div>
          </template>
        </div>`
      );
      const treeRoot = document.getElementById("exploretree");
      if (treeRoot && window.Alpine && typeof window.Alpine.initTree === "function") {
        window.Alpine.initTree(treeRoot);
      }
    });
  }

  const nodeInfoButton = document.getElementById("node-info");
  if (nodeInfoButton) {
    nodeInfoButton.addEventListener("click", function () {
      /* get json data and show window on success */
      fetchJSON("backend/nodes")
        .then(function (data) {
          var details = renderdetails(data);
          new_window("node_info", "Known Nodes", details);
        })
        .catch(function (err) {
          toast("API Error", "Couldn't load details:" + getErrorText(err), "error");
        });
    });
  }

  const edgeInfoButton = document.getElementById("edge-info");
  if (edgeInfoButton) {
    edgeInfoButton.addEventListener("click", function () {
      /* get json data and show window on success */
      fetchJSON("backend/edges")
        .then(function (data) {
          var details = renderdetails(data);
          new_window("edge_info", "Known Edges", details);
        })
        .catch(function (err) {
          toast("API Error", "Couldn't load details:" + getErrorText(err), "error");
        });
    });
  }

  const highlightButton = document.getElementById("highlightbutton");
  if (highlightButton) {
    highlightButton.addEventListener("click", function () {
      if (
        new_window(
          "highlight",
          "Highlight nodes",
          '<textarea id="highlighttext" class="w-100 mb-2" placeholder="(name=*admin*)"></textarea><div id="highlightqueryerror"></div><button id="searchandhighlight" class="btn btn-primary float-end">Highlight</button>'
        )
      ) {
        var highlightchangetimer;
        const highlighttext = document.getElementById("highlighttext");
        if (highlighttext) {
          highlighttext.addEventListener("input", function () {
            clearTimeout(highlightchangetimer);
            highlightchangetimer = setTimeout(function () {
              // check query for errors when user has been idle for 200ms
              fetchJSON(
                buildURL("/api/backend/validatequery", {
                  query: highlighttext.value,
                })
              )
                .then(function () {
                  const highlightError = document.getElementById("highlightqueryerror");
                  if (highlightError) {
                    highlightError.style.display = "none";
                  }
                })
                .catch(function (err) {
                  const highlightError = document.getElementById("highlightqueryerror");
                  if (highlightError) {
                    highlightError.innerHTML =
                      getErrorText(err) + ", will use (*=" + highlighttext.value + ") as query";
                    highlightError.style.display = "";
                  }
                });
            }, 200);
          });
        }

        const searchAndHighlight = document.getElementById("searchandhighlight");
        if (searchAndHighlight) {
          searchAndHighlight.addEventListener("click", function () {
            if (cy && highlighttext) {
              fetchJSON(
                buildURL("/api/search/get-ids", {
                  query: highlighttext.value,
                })
              ).then(function (data) {
                cy.$("*").unselect();
                for (var id of data) {
                  cy.$("#" + id).select();
                }
              });
            }
          });
        }
      }
    });
  }

  let aqlchangetimer;
  const aqlquerytext = document.getElementById("aqlquerytext");
  if (aqlquerytext) {
    aqlquerytext.addEventListener("input", function (e) {
      clearTimeout(aqlchangetimer);
      aqlchangetimer = setTimeout(function () {
        // check query for errors when user has been idle for 200ms
        fetchJSON(
          buildURL("/api/aql/validatequery", {
            query: e.target.value,
          })
        )
          .then(function () {
            const analyzeButton = document.getElementById("aqlanalyzebutton");
            const queryError = document.getElementById("aqlqueryerror");
            if (analyzeButton) {
              analyzeButton.disabled = false;
            }
            if (queryError) {
              queryError.style.display = "none";
            }
          })
          .catch(function (err) {
            const analyzeButton = document.getElementById("aqlanalyzebutton");
            const queryError = document.getElementById("aqlqueryerror");
            if (analyzeButton) {
              analyzeButton.disabled = true;
            }
            if (queryError) {
              queryError.innerHTML = getErrorText(err);
              queryError.style.display = "";
            }
          });
      }, 200);
    });
  }

  // Display stats on screen
  fetchJSON("api/backend/statistics")
    .then(function (data) {
      const statustext =
        "<div class='text-center pt-2'><img class='only-dark' height=128 src='icons/adalanche-logo.svg'><img class='only-light' height=128 src='icons/adalanche-logo-black.svg'></div><div class='text-center'><h2>" +
        data.adalanche.program +
        "</h2><b>" +
        data.adalanche.shortversion +
        "</b></div>";
      setHTML("status", statustext);
      setVisible("status", true);
      setTimeout(() => setVisible("status", false), 15000);
      setHTML("programinfo", data.adalanche.program + " " + data.adalanche.shortversion);
    })
    .catch(function (err) {
      setHTML("status", "guru meditation:<br>" + getErrorText(err));
      setVisible("status", true);
    });

  updateQueries();

  ensurePrefsLoaded()
    .then(() => {
      settings_loaded = true;
      autorun_query();
    })
    .catch((err) => {
      console.error("Failed to load preferences", err);
    });


  // End of on document loaded function
});

settings_loaded = false;
data_loaded = false;
initial_query_has_run = false;
function autorun_query() {
  if (initial_query_set && settings_loaded && data_loaded && getpref("ui.run.query.on.startup", true) && !initial_query_has_run) {
    initial_query_has_run = true;
    aqlanalyze();
  }
}

function exploreTree() {
  return {
    nodes: [],
    async init() {
      try {
        this.nodes = await this.loadChildren("#");
      } catch (err) {
        toast("Error loading tree", getErrorText(err), "error");
      }
    },
    async loadChildren(id) {
      return await fetchJSON(buildURL("/api/tree", { id: String(id) }));
    },
    async onNodeClick(node) {
      try {
        const data = await fetchJSON("api/details/id/" + node.id);
        const details = renderdetails(data);
        let windowname = "details_" + node.id;
        if (getpref("ui.open.details.in.same.window", true)) {
          windowname = "node_details";
        }
        new_window(windowname, "Item details", details);
      } catch (err) {
        toast("API Error", "Couldn't load details:" + getErrorText(err), "error");
      }
    },
  };
}

function exploreTreeNode(node, loadChildren, onNodeClick) {
  return {
    node,
    open: false,
    loading: false,
    loaded: false,
    selected: false,
    children: [],
    async toggle() {
      if (!this.node.children) {
        return;
      }
      this.open = !this.open;
      if (this.open && !this.loaded) {
        this.loading = true;
        try {
          this.children = await loadChildren(this.node.id);
          this.loaded = true;
        } catch (err) {
          toast("Error loading tree node", getErrorText(err), "error");
        } finally {
          this.loading = false;
        }
      }
    },
    async selectNode() {
      this.selected = true;
      await onNodeClick(this.node);
    },
  };
}

function windowManager() {
  const MIN_WINDOW_WIDTH = 140;
  const MIN_WINDOW_HEIGHT = 100;
  const AUTO_MAX_WIDTH_RATIO = 0.5;
  const AUTO_MAX_HEIGHT_RATIO = 0.7;

  return {
    windows: [],
    nextZ: 200,
    dragState: null,
    resizeState: null,

    init() {
      const moveHandler = (event) => {
        if (this.dragState) {
          const win = this.findWindow(this.dragState.id);
          if (!win) {
            return;
          }
          win.x = Math.max(0, event.clientX - this.dragState.offsetX);
          win.y = Math.max(0, event.clientY - this.dragState.offsetY);
          return;
        }
        if (this.resizeState) {
          const win = this.findWindow(this.resizeState.id);
          if (!win) {
            return;
          }
          const dx = event.clientX - this.resizeState.startX;
          const dy = event.clientY - this.resizeState.startY;
          const maxWidth = window.innerWidth * 0.6;
          const maxHeight = window.innerHeight * 0.8;
          if (this.resizeState.mode === "corner") {
            win.w = Math.min(maxWidth, Math.max(MIN_WINDOW_WIDTH, this.resizeState.startW + dx));
            win.h = Math.min(maxHeight, Math.max(MIN_WINDOW_HEIGHT, this.resizeState.startH + dy));
            return;
          }
          if (this.resizeState.mode === "bottom") {
            win.h = Math.min(maxHeight, Math.max(MIN_WINDOW_HEIGHT, this.resizeState.startH + dy));
            return;
          }
          if (this.resizeState.mode === "right") {
            win.w = Math.min(maxWidth, Math.max(MIN_WINDOW_WIDTH, this.resizeState.startW + dx));
          }
        }
      };
      const upHandler = () => {
        this.dragState = null;
        this.resizeState = null;
      };
      window.addEventListener("mousemove", moveHandler);
      window.addEventListener("mouseup", upHandler);
    },

    findWindow(id) {
      return this.windows.find((w) => String(w.id) === String(id));
    },

    bringToFront(win) {
      this.nextZ += 1;
      win.z = this.nextZ;
    },

    startDrag(event, win) {
      this.bringToFront(win);
      this.dragState = {
        id: win.id,
        offsetX: event.clientX - win.x,
        offsetY: event.clientY - win.y,
      };
    },

    startResize(event, win, mode = "corner") {
      this.bringToFront(win);
      this.resizeState = {
        id: win.id,
        mode,
        startX: event.clientX,
        startY: event.clientY,
        startW: win.w,
        startH: win.h,
      };
    },

    closeWindow(id) {
      this.windows = this.windows.filter((w) => String(w.id) !== String(id));
    },

    autoSizeWindow(win, autoWidth, autoHeight) {
      if (!autoWidth && !autoHeight) {
        return true;
      }

      const el = document.getElementById(`window_${win.id}`);
      if (!el) {
        return false;
      }

      const wrapper = el.querySelector(".window-wrapper");
      const content = el.querySelector(".window-content");
      if (!wrapper || !content) {
        return false;
      }

      const maxHeight = window.innerHeight * AUTO_MAX_HEIGHT_RATIO;
      const maxWidth = window.innerWidth * AUTO_MAX_WIDTH_RATIO;
      const widthChrome = Math.max(0, el.offsetWidth - wrapper.clientWidth);
      const heightChrome = Math.max(0, el.offsetHeight - wrapper.clientHeight);

      if (autoWidth) {
        const targetWidth = content.scrollWidth + widthChrome + 2;
        win.w = Math.min(maxWidth, Math.max(MIN_WINDOW_WIDTH, targetWidth));
      }

      if (autoHeight) {
        // Re-evaluate after width settles so wrapped content gets correct height.
        requestAnimationFrame(() => {
          const targetHeight = content.scrollHeight + heightChrome + 2;
          win.h = Math.min(maxHeight, Math.max(MIN_WINDOW_HEIGHT, targetHeight));
        });
      }
      return true;
    },

    queueAutoSize(winId, autoWidth, autoHeight) {
      if (!autoWidth && !autoHeight) {
        return;
      }
      let tries = 0;
      const run = () => {
        const liveWin = this.findWindow(winId);
        if (!liveWin) {
          return;
        }
        this.autoSizeWindow(liveWin, autoWidth, autoHeight);
        if (tries >= 10) {
          return;
        }
        tries += 1;
        requestAnimationFrame(run);
      };
      requestAnimationFrame(run);
    },

    openWindow({ id, title, content, alignment = "topleft", height = 0, width = 0 }) {
      const existing = this.findWindow(id);
      const maxheight = window.innerHeight * 0.8;
      const maxwidth = window.innerWidth * 0.6;
      const autoWidth = !(width > 0);
      const autoHeight = !(height > 0);

      if (existing) {
        existing.title = title;
        existing.content = content;
        existing.w = Math.min(
          maxwidth,
          Math.max(MIN_WINDOW_WIDTH, width > 0 ? width : autoWidth ? MIN_WINDOW_WIDTH : existing.w)
        );
        existing.h = Math.min(
          maxheight,
          Math.max(MIN_WINDOW_HEIGHT, height > 0 ? height : autoHeight ? MIN_WINDOW_HEIGHT : existing.h)
        );
        this.bringToFront(existing);
        this.queueAutoSize(existing.id, autoWidth, autoHeight);
        return false;
      }

      const offset = this.windows.length + 1;
      let xpos = offset * 24;
      let ypos = offset * 16;
      if (alignment === "center") {
        xpos = window.innerWidth / 2;
        ypos = window.innerHeight / 2;
      }

      const win = {
        id: String(id),
        title,
        content,
        x: xpos,
        y: ypos,
        w: Math.min(maxwidth, Math.max(MIN_WINDOW_WIDTH, width > 0 ? width : MIN_WINDOW_WIDTH)),
        h: Math.min(maxheight, Math.max(MIN_WINDOW_HEIGHT, height > 0 ? height : MIN_WINDOW_HEIGHT)),
        z: ++this.nextZ,
      };
      this.windows.push(win);
      this.queueAutoSize(win.id, autoWidth, autoHeight);
      return true;
    },
  };
}
