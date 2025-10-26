(function () {
  "use strict";

  // registers the extension on a cytoscape lib ref
  var register = function (cytoscape) {
    if (!cytoscape) return;

    var defaults = {
      url: null,
      method: "POST",
      layout: "cose",
      nodeMapper: (n) => ({
        id: n.id(),
        data: n.data(),
        width: n.width(),
        height: n.height(),
        position: n.position(),
      }),
      edgeMapper: (e) => ({
        id: e.id(),
        from: e.source().id(),
        to: e.target().id(),
        data: e.data(),
      }),
      extra: {},
      timeout: 120000,
      onError: (err) => {
        console.error(err);
      },
      responsePositionsKey: "positions",
      ready: () => {},
      stop: () => {},
      animate: false,
      animationDuration: 500,
      animationEasing: undefined,
      fit: true,
      padding: 30,
    };

    function RemoteLayout(options) {
      var opts = (this.options = {});
      for (var i in defaults) {
        opts[i] = defaults[i];
      }
      for (var i in options) {
        opts[i] = options[i];
      }
      // Set non-configurable instance properties
      this.aborted = false;
      this.stopRequested = false;
      this.controller = null;
    }

    RemoteLayout.prototype.run = function () {
      const layout = this;
      const cy = this.options.cy;
      const eles = this.options.eles || cy.elements();

      // Start the layout process
      layout.trigger("layoutstart");

      // Prepare payload
      const nodes = eles.nodes().map((n) => this.options.nodeMapper(n));
      const edges = eles.edges().map((e) => this.options.edgeMapper(e));
      const payload = {
        graph: {
          nodes: nodes,
          edges: edges,
        },
        layout: this.options.layout,
        options: this.options.extra,
      };

      if (!this.options.url) {
        const err = new Error("remote layout: url is required");
        this.onError(err);
        layout.trigger("layoutstop");
        return;
      }

      // Use fetch with AbortController for timeout & abort
      this.controller =
        typeof AbortController !== "undefined" ? new AbortController() : null;
      const signal = this.controller ? this.controller.signal : null;

      const timer = setTimeout(() => {
        if (this.controller) {
          this.controller.abort();
        }
      }, this.options.timeout);

      fetch(this.options.url, {
        method: this.options.method,
        headers: {
          "Content-Type": "application/json",
          ...(this.options.headers || {}),
        },
        body: JSON.stringify(payload),
        signal: signal,
      })
        .then(async (res) => {
          clearTimeout(timer);
          if (!res.ok) {
            const text = await res.text().catch(() => "<no body>");
            throw new Error(
              "Server returned " +
                res.status +
                " " +
                res.statusText +
                " - " +
                text
            );
          }
          return res.json();
        })
        .then((json) => {
          if (layout.aborted || layout.stopRequested) {
            layout.trigger("layoutstop");
            return;
          }

          // Parse positions
          let positions = null;
          if (
            json &&
            typeof json === "object" &&
            this.responsePositionsKey in json
          ) {
            positions = json[this.responsePositionsKey];
          } else if (Array.isArray(json)) {
            positions = {};
            json.forEach((item) => {
              if (
                item &&
                item.id &&
                (typeof item.x === "number" || typeof item.y === "number")
              ) {
                positions[item.id] = { x: item.x, y: item.y };
              }
            });
          } else if (json && typeof json === "object") {
            positions = json;
          } else {
            throw new Error(
              "Unrecognized response format from remote layout server"
            );
          }

          if (!positions || typeof positions !== "object") {
            throw new Error("Remote layout: positions not found in response");
          }

          // Apply positions
          layout.positionNodes(positions);

          // Clean up
          layout.trigger("layoutready");

          if (this.options.fit) {
            cy.fit(this.options.padding);
          }

          layout.trigger("layoutstop");
        })
        .catch((err) => {
          clearTimeout(timer);
          if (
            this.controller &&
            this.controller.signal &&
            this.controller.signal.aborted &&
            !this.aborted
          ) {
            const e = new Error(
              "remote layout aborted (timeout or user) - " +
                (err && err.message ? err.message : "")
            );
            this.onError(e);
          } else {
            this.onError(err);
          }
          layout.trigger("layoutstop");
        });

      return this;
    };

    // OnError
    RemoteLayout.prototype.onError = function (err) {
      if (this.options.onError && typeof this.options.onError === "function") {
        this.options.onError(err);
      } else {
        console.error(err);
      }
    } 

    // Add helper methods
    RemoteLayout.prototype.trigger = function (eventName) {
      const event = { type: eventName, layout: this };
      this.options.cy.emit(eventName, event);
      return this;
    };

    RemoteLayout.prototype.positionNodes = function (positions) {
      const cy = this.options.cy;
      const pos = {};

      cy.nodes().forEach((node) => {
        if (positions[node.id()]) {
          pos[node.id()] = positions[node.id()];
        }
      });

      if (this.animate) {
        cy.nodes()
          .filter((node) => pos[node.id()])
          .animation({
            position: pos[node.id()],
            duration: this.animationDuration,
            easing: this.animationEasing,
          })
          .play();
      } else {
        cy.nodes()
          .filter((node) => pos[node.id()])
          .positions((node) => pos[node.id()]);
      }
    };

    RemoteLayout.prototype.stop = function () {
      this.stopRequested = true;
      this.aborted = true;
      if (this.controller && typeof this.controller.abort === "function") {
        try {
          this.controller.abort();
        } catch (e) {}
      }
    };

    RemoteLayout.prototype.destroy = function () {
      this.stop();
    };

    cytoscape("layout", "remote", RemoteLayout);
  };

  if (typeof cytoscape !== "undefined") {
    register(cytoscape);
  }
})();
