! function(e, n) { "object" == typeof exports && "object" == typeof module ? module.exports = n(require("dagre")) : "function" == typeof define && define.amd ? define(["dagre"], n) : "object" == typeof exports ? exports.cytoscapeDagre = n(require("dagre")) : e.cytoscapeDagre = n(e.dagre) }(window, (function(e) { return function(e) { var n = {};

        function t(r) { if (n[r]) return n[r].exports; var o = n[r] = { i: r, l: !1, exports: {} }; return e[r].call(o.exports, o, o.exports, t), o.l = !0, o.exports } return t.m = e, t.c = n, t.d = function(e, n, r) { t.o(e, n) || Object.defineProperty(e, n, { enumerable: !0, get: r }) }, t.r = function(e) { "undefined" != typeof Symbol && Symbol.toStringTag && Object.defineProperty(e, Symbol.toStringTag, { value: "Module" }), Object.defineProperty(e, "__esModule", { value: !0 }) }, t.t = function(e, n) { if (1 & n && (e = t(e)), 8 & n) return e; if (4 & n && "object" == typeof e && e && e.__esModule) return e; var r = Object.create(null); if (t.r(r), Object.defineProperty(r, "default", { enumerable: !0, value: e }), 2 & n && "string" != typeof e)
                for (var o in e) t.d(r, o, function(n) { return e[n] }.bind(null, o)); return r }, t.n = function(e) { var n = e && e.__esModule ? function() { return e.default } : function() { return e }; return t.d(n, "a", n), n }, t.o = function(e, n) { return Object.prototype.hasOwnProperty.call(e, n) }, t.p = "", t(t.s = 0) }([function(e, n, t) { var r = t(1),
            o = function(e) { e && e("layout", "dagre", r) }; "undefined" != typeof cytoscape && o(cytoscape), e.exports = o }, function(e, n, t) {
        function r(e) { return (r = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function(e) { return typeof e } : function(e) { return e && "function" == typeof Symbol && e.constructor === Symbol && e !== Symbol.prototype ? "symbol" : typeof e })(e) } var o = t(2),
            i = t(3),
            a = t(4);

        function u(e) { this.options = i({}, o, e) }
        u.prototype.run = function() { var e = this.options,
                n = e.cy,
                t = e.eles,
                o = function(e, n) { return "function" == typeof n ? n.apply(e, [e]) : n },
                i = e.boundingBox || { x1: 0, y1: 0, w: n.width(), h: n.height() };
            void 0 === i.x2 && (i.x2 = i.x1 + i.w), void 0 === i.w && (i.w = i.x2 - i.x1), void 0 === i.y2 && (i.y2 = i.y1 + i.h), void 0 === i.h && (i.h = i.y2 - i.y1); var u = new a.graphlib.Graph({ multigraph: !0, compound: !0 }),
                c = {},
                f = function(e, n) { null != n && (c[e] = n) };
            f("nodesep", e.nodeSep), f("edgesep", e.edgeSep), f("ranksep", e.rankSep), f("rankdir", e.rankDir), f("ranker", e.ranker), u.setGraph(c), u.setDefaultEdgeLabel((function() { return {} })), u.setDefaultNodeLabel((function() { return {} })); for (var d = t.nodes(), s = 0; s < d.length; s++) { var y = d[s],
                    p = y.layoutDimensions(e);
                u.setNode(y.id(), { width: p.w, height: p.h, name: y.id() }) } for (var l = 0; l < d.length; l++) { var g = d[l];
                g.isChild() && u.setParent(g.id(), g.parent().id()) } for (var h = t.edges().stdFilter((function(e) { return !e.source().isParent() && !e.target().isParent() })), x = 0; x < h.length; x++) { var b = h[x];
                u.setEdge(b.source().id(), b.target().id(), { minlen: o(b, e.minLen), weight: o(b, e.edgeWeight), name: b.id() }, b.id()) }
            a.layout(u); for (var v, m = u.nodes(), w = 0; w < m.length; w++) { var S = m[w],
                    j = u.node(S);
                n.getElementById(S).scratch().dagre = j }
            e.boundingBox ? (v = { x1: 1 / 0, x2: -1 / 0, y1: 1 / 0, y2: -1 / 0 }, d.forEach((function(e) { var n = e.scratch().dagre;
                v.x1 = Math.min(v.x1, n.x), v.x2 = Math.max(v.x2, n.x), v.y1 = Math.min(v.y1, n.y), v.y2 = Math.max(v.y2, n.y) })), v.w = v.x2 - v.x1, v.h = v.y2 - v.y1) : v = i; return d.layoutPositions(this, e, (function(n) { var t = (n = "object" === r(n) ? n : this).scratch().dagre; return function(n) { if (e.boundingBox) { var t = 0 === v.w ? 0 : (n.x - v.x1) / v.w,
                            r = 0 === v.h ? 0 : (n.y - v.y1) / v.h; return { x: i.x1 + t * i.w, y: i.y1 + r * i.h } } return n }({ x: t.x, y: t.y }) })), this }, e.exports = u }, function(e, n) { var t = { nodeSep: void 0, edgeSep: void 0, rankSep: void 0, rankDir: void 0, ranker: void 0, minLen: function(e) { return 1 }, edgeWeight: function(e) { return 1 }, fit: !0, padding: 30, spacingFactor: void 0, nodeDimensionsIncludeLabels: !1, animate: !1, animateFilter: function(e, n) { return !0 }, animationDuration: 500, animationEasing: void 0, boundingBox: void 0, transform: function(e, n) { return n }, ready: function() {}, stop: function() {} };
        e.exports = t }, function(e, n) { e.exports = null != Object.assign ? Object.assign.bind(Object) : function(e) { for (var n = arguments.length, t = new Array(n > 1 ? n - 1 : 0), r = 1; r < n; r++) t[r - 1] = arguments[r]; return t.forEach((function(n) { Object.keys(n).forEach((function(t) { return e[t] = n[t] })) })), e } }, function(n, t) { n.exports = e }]) }));