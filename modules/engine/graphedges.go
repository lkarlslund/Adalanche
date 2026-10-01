package engine

import (
	"math"
	"sync"

	gsync "github.com/SaveTheRbtz/generic-sync-map-go"
	"github.com/lkarlslund/adalanche/modules/ui"
)

func (g *IndexedGraph) loadEdge(from, to NodeIndex, direction EdgeDirection) (EdgeBitmap, bool) {
	// Load the edge
	toMap := g.edges[direction][from]
	if toMap == nil {
		return EdgeBitmap{}, false
	}
	combo, found := toMap[to]
	if !found {
		return EdgeBitmap{}, false
	}
	return g.EdgeComboToEdgeBitmap(combo), true
}

func (g *IndexedGraph) saveEdge(from, to NodeIndex, edge EdgeBitmap, direction EdgeDirection) {
	g.edgeVersion++ // callers hold edgeMutex
	// Save the edge
	toMap := g.edges[direction][from]
	if toMap == nil {
		if edge.IsBlank() {
			// Writing a blank edge "unsets" it, but we have none
			return
		}
		toMap = make(map[NodeIndex]EdgeCombo)
		g.edges[direction][from] = toMap
	}
	if edge.IsBlank() {
		delete(toMap, to)
	} else {
		toMap[to] = g.edgeBitmapToEdgeCombo(edge)
	}
}

func (g *IndexedGraph) edgeBitmapToEdgeCombo(edge EdgeBitmap) EdgeCombo {
	return g.edgeCombos.intern(edge)
}

// edgeComboTable interns edge bitmaps as small combination IDs. Reads in
// both directions take no lock; only adding a new combination locks.
type edgeComboTable struct {
	mu      sync.Mutex
	lookup  gsync.MapOf[EdgeBitmap, EdgeCombo]
	bitmaps *chunkedTable[EdgeBitmap]
}

func newEdgeComboTable() *edgeComboTable {
	t := &edgeComboTable{bitmaps: newChunkedTable[EdgeBitmap]()}
	t.intern(EdgeBitmap{}) // Combination 0 is always the blank bitmap.
	return t
}

func (t *edgeComboTable) intern(edge EdgeBitmap) EdgeCombo {
	if combo, found := t.lookup.Load(edge); found {
		return combo
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if combo, found := t.lookup.Load(edge); found {
		return combo
	}
	index := t.bitmaps.add(edge)
	if index >= math.MaxUint16 {
		ui.Fatal().Msgf("Too many unique edges")
	}
	t.lookup.Store(edge, EdgeCombo(index))
	return EdgeCombo(index)
}

func (t *edgeComboTable) get(combo EdgeCombo) EdgeBitmap {
	return t.bitmaps.get(uint32(combo))
}

func (g *IndexedGraph) EdgeBitmapToEdgeCombo(edge EdgeBitmap) EdgeCombo {
	return g.edgeCombos.intern(edge)
}

func (g *IndexedGraph) EdgeComboToEdgeBitmap(ue EdgeCombo) EdgeBitmap {
	return g.edgeCombos.get(ue)
}

type CompressedEdgeSubSlice []byte

// Register that this object can pwn another object using the given method
func (g *IndexedGraph) EdgeTo(from, to *Node, edge Edge) {
	g.EdgeToEx(from, to, edge, false)
}

// Clear the edge from one object to another
func (g *IndexedGraph) EdgeClear(from, to *Node, edge Edge) {
	g.edgeToEx(from, to, edge, false, true, true)
}

// Enhanched Pwns function that allows us to force the pwn (normally self-pwns are filtered out)
func (g *IndexedGraph) EdgeToEx(from, to *Node, edge Edge, force bool) {
	g.edgeToEx(from, to, edge, force, false, true)
}

func (g *IndexedGraph) edgeToEx(from, to *Node, edge Edge, force, clear, merge bool) {
	op, ok := g.resolveSingleEdgeMutation(nodeEdgeMutation{
		From:  from,
		To:    to,
		Edge:  edge,
		Merge: merge,
		Clear: clear,
		Force: force,
	})
	if !ok {
		return
	}
	g.edgeMutex.Lock()

	var ebm EdgeBitmap
	if op.Merge {
		ebm, _ = g.loadEdge(op.From, op.To, Out)
	}

	if op.Clear {
		ebm = ebm.Clear(op.Edge)
	} else {
		ebm = ebm.Set(op.Edge)
	}
	g.saveEdge(op.From, op.To, ebm, Out)
	g.saveEdge(op.To, op.From, ebm, In)
	g.edgeMutex.Unlock()
}

// Needs optimization
func (g *IndexedGraph) GetEdge(from, to *Node) (EdgeBitmap, bool) {
	fromIndex, ok := g.nodeLookup.Load(from)
	toIndex, ok2 := g.nodeLookup.Load(to)
	if !ok || !ok2 {
		return EdgeBitmap{}, false
	}
	g.edgeMutex.RLock()
	eb, found := g.loadEdge(fromIndex, toIndex, Out)
	g.edgeMutex.RUnlock()
	return eb, found
}

func (g *IndexedGraph) SetEdge(from, to *Node, eb EdgeBitmap, merge bool) {
	op := g.resolveBitmapMutation(nodeEdgeMutation{
		From:       from,
		To:         to,
		Edge:       NonExistingEdge,
		EdgeBitmap: eb,
		Merge:      merge,
	})
	g.edgeMutex.Lock()
	if op.Merge {
		oldeb, _ := g.loadEdge(op.From, op.To, Out)
		eb = oldeb.Merge(eb)
	}
	g.saveEdge(op.From, op.To, eb, Out)
	g.saveEdge(op.To, op.From, eb, In)
	g.edgeMutex.Unlock()
}

func (g *IndexedGraph) Edges(node *Node, direction EdgeDirection) EdgeFilter {
	i, ok := g.nodeLookup.Load(node)
	if !ok {
		return EdgeFilter{
			graph:     g,
			direction: Invalid,
			fromNode:  0, // Invalid index
		}
	}
	return EdgeFilter{
		graph:     g,
		direction: direction,
		fromNode:  i,
	}
}

// NodeIndexOf returns the node's position in this graph, for use with NodeAt
// and EdgesAt when a search wants to avoid holding node pointers.
func (g *IndexedGraph) NodeIndexOf(node *Node) (NodeIndex, bool) {
	return g.nodeLookup.Load(node)
}

// NodeAt returns the node at a position from NodeIndexOf or IterateIndexed.
// Like Iterate, it must not race with nodes being added.
func (g *IndexedGraph) NodeAt(index NodeIndex) *Node {
	return g.nodes[index]
}

// EdgesAt is Edges for a node given by its position in this graph.
func (g *IndexedGraph) EdgesAt(index NodeIndex, direction EdgeDirection) EdgeFilter {
	return EdgeFilter{
		graph:     g,
		direction: direction,
		fromNode:  index,
	}
}

func (g *IndexedGraph) IterateEdges(node *Node, direction EdgeDirection, iter func(target *Node, ebm EdgeBitmap) bool) {
	g.Edges(node, direction).Iterate(iter)
}

type EdgeFilter struct {
	graph     *IndexedGraph
	direction EdgeDirection
	fromNode  NodeIndex
}

func (ef EdgeFilter) Len() int {
	if ef.direction > In {
		return 0
	}
	ef.graph.edgeMutex.RLock()
	defer ef.graph.edgeMutex.RUnlock()
	return len(ef.graph.edges[ef.direction][ef.fromNode])
}

// IterateIndexed is Iterate, passing each target's position in the graph.
func (ef EdgeFilter) IterateIndexed(iter func(targetIndex NodeIndex, target *Node, ebm EdgeBitmap) bool) {
	if ef.direction > In {
		return
	}
	ef.graph.edgeMutex.RLock()
	defer ef.graph.edgeMutex.RUnlock()
	for nodeIndex, edgeCombo := range ef.graph.edges[ef.direction][ef.fromNode] {
		if !iter(nodeIndex, ef.graph.nodes[nodeIndex], ef.graph.edgeCombos.get(edgeCombo)) {
			return
		}
	}
}

func (ef EdgeFilter) Iterate(iter func(target *Node, ebm EdgeBitmap) bool) {
	if ef.direction > In {
		return
	}
	ef.graph.edgeMutex.RLock()
	defer ef.graph.edgeMutex.RUnlock()
	for nodeIndex, edgeCombo := range ef.graph.edges[ef.direction][ef.fromNode] {
		eb := ef.graph.edgeCombos.get(edgeCombo)
		target := ef.graph.nodes[nodeIndex]
		if !iter(target, eb) {
			return
		}
	}
}

func (g *IndexedGraph) EdgeIteratorRecursive(node *Node, direction EdgeDirection, edgeMatch EdgeBitmap, excludemyself bool, goDeeperFunc func(source, target *Node, edge EdgeBitmap, depth int) bool) {
	seenobjects := make(map[*Node]struct{})
	if excludemyself {
		seenobjects[node] = struct{}{}
	}
	g.edgeIteratorRecursive(node, direction, edgeMatch, goDeeperFunc, seenobjects, 1)
}

func (g *IndexedGraph) edgeIteratorRecursive(node *Node, direction EdgeDirection, edgeMatch EdgeBitmap, goDeeperFunc func(source, target *Node, edge EdgeBitmap, depth int) bool, appliedTo map[*Node]struct{}, depth int) {
	g.Edges(node, direction).Iterate(func(target *Node, edge EdgeBitmap) bool {
		if _, found := appliedTo[target]; !found {
			edgeMatches := edge.Intersect(edgeMatch)
			if !edgeMatches.IsBlank() {
				appliedTo[target] = struct{}{}
				if goDeeperFunc(node, target, edgeMatches, depth) {
					g.edgeIteratorRecursive(target, direction, edgeMatch, goDeeperFunc, appliedTo, depth+1)
				}
			}
		}
		return true
	})
}
