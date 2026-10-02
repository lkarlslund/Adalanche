// Package enginetest builds graphs for tests. Every change goes through a
// transaction committed right away, as any other writer's would.
package enginetest

import (
	"fmt"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

// Update runs fn in a transaction and commits it.
func Update(g *engine.IndexedGraph, fn func(tx *engine.Tx)) {
	tx := g.Begin("test")
	fn(tx)
	if err := tx.Commit(); err != nil {
		panic(err)
	}
}

// Add adds nodes built with engine.NewNode.
func Add(g *engine.IndexedGraph, nodes ...*engine.Node) {
	Update(g, func(tx *engine.Tx) {
		for _, n := range nodes {
			tx.Add(n)
		}
	})
}

// AddNew adds a node with the attributes in flexinit and returns it.
func AddNew(g *engine.IndexedGraph, flexinit ...any) *engine.Node {
	var h engine.TxNode
	Update(g, func(tx *engine.Tx) { h = tx.AddNew(flexinit...) })
	return h.Node()
}

// NewGraph returns a graph holding nodes.
func NewGraph(nodes ...*engine.Node) *engine.IndexedGraph {
	g := engine.NewIndexedGraph()
	Add(g, nodes...)
	return g
}

// Edge adds an edge, even where EdgeTo would leave it out.
func Edge(g *engine.IndexedGraph, from, to *engine.Node, edge engine.Edge) {
	Update(g, func(tx *engine.Tx) { tx.EdgeToEx(from, to, edge, true) })
}

// EdgeTo adds an edge as tx.EdgeTo does, leaving out edges between a node
// and itself or between nodes with the same SID.
func EdgeTo(g *engine.IndexedGraph, from, to *engine.Node, edge engine.Edge) {
	Update(g, func(tx *engine.Tx) { tx.EdgeTo(from, to, edge) })
}

// Set sets an attribute of a node in g.
func Set(g *engine.IndexedGraph, n *engine.Node, attr engine.Attribute, values ...engine.AttributeValue) {
	Update(g, func(tx *engine.Tx) { tx.Node(n).Set(attr, values...) })
}

// AddValues adds values to an attribute of a node in g.
func AddValues(g *engine.IndexedGraph, n *engine.Node, attr engine.Attribute, values ...engine.AttributeValue) {
	Update(g, func(tx *engine.Tx) { tx.Node(n).Add(attr, values...) })
}

// Tag tags a node in g.
func Tag(g *engine.IndexedGraph, n *engine.Node, tag string) {
	Update(g, func(tx *engine.Tx) { tx.Node(n).Tag(tag) })
}

// ChildOf places child under parent.
func ChildOf(g *engine.IndexedGraph, child, parent *engine.Node) {
	Update(g, func(tx *engine.Tx) { tx.Node(child).ChildOf(parent) })
}

// FindOrAddAdjacentSID returns the node for a SID as seen from relativeTo,
// adding it when there is none.
func FindOrAddAdjacentSID(g *engine.IndexedGraph, s windowssecurity.SID, relativeTo *engine.Node) *engine.Node {
	var h engine.TxNode
	Update(g, func(tx *engine.Tx) { h = tx.FindOrAddAdjacentSID(s, relativeTo) })
	return h.Node()
}

// Load puts graphs built by hand into one analysis graph the way Run does,
// each as a separate loader committing through a load transaction, then
// finishes loading: parent claims, merge preparers and reference resolution.
// Nodes keep their identity; nodes with the same distinguished name become
// one.
func Load(graphs ...*engine.IndexedGraph) *engine.IndexedGraph {
	g := engine.NewAnalysisGraph()
	for i, src := range graphs {
		target := engine.NewLoadTarget(g, fmt.Sprintf("test loader %d", i))
		tx := target.Begin("test")
		handles := map[*engine.Node]engine.TxNode{}
		src.IterateStable(func(n *engine.Node) bool {
			handles[n] = tx.AddIdentified(n, engine.DistinguishedName)
			return true
		})
		src.IterateStable(func(n *engine.Node) bool {
			src.IterateEdges(n, engine.Out, func(to *engine.Node, eb engine.EdgeBitmap) bool {
				tx.SetEdge(handles[n], handles[to], eb, true)
				return true
			})
			return true
		})
		if err := tx.Commit(); err != nil {
			panic(err)
		}
	}
	if err := g.FinishLoading(); err != nil {
		panic(err)
	}
	return g
}
