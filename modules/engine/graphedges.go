package engine

import (
	"math"
	"sort"

	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func (g *IndexedGraph) processIncomingEdges(queuesize int) {
	bulkProcessBuffer := make([]BulkEdgeRequest, 0, queuesize)

	// continue running while incomingEdges is not closed
	// add new edges to buffer while there is space
	// if buffer is full or a signal comes in on flushEdges process buffer

	for {
		select {
		case ep, ok := <-g.incomingEdges:
			if !ok {
				g.bulkloading = false
				if len(bulkProcessBuffer) > 0 {
					g.processBulkEdges(bulkProcessBuffer)
				}
				g.bulkWorkers.Done()
				return
			}
			bulkProcessBuffer = append(bulkProcessBuffer, ep)

			if len(bulkProcessBuffer) >= cap(bulkProcessBuffer) {
				g.processBulkEdges(bulkProcessBuffer)
				bulkProcessBuffer = bulkProcessBuffer[:0]
			}
		case <-g.flushEdges:
			if len(bulkProcessBuffer) > 0 {
				g.processBulkEdges(bulkProcessBuffer)
				bulkProcessBuffer = bulkProcessBuffer[:0]
			}
		}
	}
}

func (g *IndexedGraph) processBulkEdges(eps []BulkEdgeRequest) {
	// sort eps by from, to to improve cache locality
	sort.Slice(eps, func(i, j int) bool {
		if eps[i].From == eps[j].From {
			return eps[i].To < eps[j].To
		}
		return eps[i].From < eps[j].From
	})

	var lastFrom, lastTo NodeIndex
	var lastEdge EdgeBitmap

	g.edgeMutex.Lock()
	first := true
	for _, ep := range eps {
		if ep.From != lastFrom || ep.To != lastTo {
			if first {
				first = false
			} else {
				// save it
				g.saveEdge(lastFrom, lastTo, lastEdge, Out)
				g.saveEdge(lastTo, lastFrom, lastEdge, In)
			}

			lastFrom = ep.From
			lastTo = ep.To
			lastEdge, _ = g.loadEdge(lastFrom, lastTo, Out)
		}
		// Modify edge
		if ep.Edge == NonExistingEdge {
			// It's a complete bitmap
			if ep.Clear {
				lastEdge = lastEdge.Intersect(ep.EdgeBitmap.Invert())
			} else if ep.Merge {
				lastEdge = lastEdge.Merge(ep.EdgeBitmap)
			} else {
				lastEdge = ep.EdgeBitmap
			}
		} else {
			// Single edge
			if !ep.Merge {
				// Makes no sense, but we'll do it anyway
				lastEdge = EdgeBitmap{}
			}
			if ep.Clear {
				lastEdge = lastEdge.Clear(ep.Edge)
			} else {
				lastEdge = lastEdge.Set(ep.Edge)
			}
		}
	}
	if !first {
		g.saveEdge(lastFrom, lastTo, lastEdge, Out)
		g.saveEdge(lastTo, lastFrom, lastEdge, In)
	}
	g.edgeMutex.Unlock()
}

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
	ue, found := g.edgeComboLookup[edge]
	if !found {
		ue = EdgeCombo(len(g.edgeCombos))
		if ue == math.MaxUint16 {
			ui.Fatal().Msgf("Too many unique edges")
		}
		g.edgeComboLookup[edge] = ue
		g.edgeCombos = append(g.edgeCombos, edge)
	}
	return ue
}

func (g *IndexedGraph) EdgeBitmapToEdgeCombo(edge EdgeBitmap) EdgeCombo {
	g.edgeComboMutex.RLock()
	ue, found := g.edgeComboLookup[edge]
	g.edgeComboMutex.RUnlock()
	if !found {
		g.edgeComboMutex.Lock()
		ue = EdgeCombo(len(g.edgeCombos))
		if ue == math.MaxUint16 {
			ui.Fatal().Msgf("Too many unique edges")
		}
		g.edgeComboLookup[edge] = ue
		g.edgeCombos = append(g.edgeCombos, edge)
		g.edgeComboMutex.Unlock()
	}
	return ue
}

func (g *IndexedGraph) EdgeComboToEdgeBitmap(ue EdgeCombo) EdgeBitmap {
	g.edgeComboMutex.RLock()
	defer g.edgeComboMutex.RUnlock()
	return g.edgeCombos[ue]
}

func (g *IndexedGraph) edgeComboToEdgeBitmap(ue EdgeCombo) EdgeBitmap {
	return g.edgeCombos[ue]
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
	if from == to {
		return // Self-loop not supported
	}

	if !force {
		fromSid := from.SID()

		// Ignore these, SELF = self own, Creator/Owner always has full rights
		if fromSid == windowssecurity.SelfSID {
			return
		}

		toSid := to.SID()
		if !fromSid.IsBlank() && fromSid == toSid {
			return
		}
	}

	fromIndex, found := g.nodeLookup.Load(from)
	if !found {
		ui.Fatal().Msgf("Node not found in graph")
	}
	toIndex, found := g.nodeLookup.Load(to)
	if !found {
		ui.Fatal().Msgf("Node not found in graph")
	}

	if g.bulkloading {
		// Handle this eventually
		g.incomingEdges <- BulkEdgeRequest{
			From:  fromIndex,
			To:    toIndex,
			Edge:  edge,
			Clear: clear,
			Merge: merge,
		}
		return
	}
	g.edgeMutex.Lock()

	// normal
	var ebm EdgeBitmap
	if merge {
		ebm, _ = g.loadEdge(fromIndex, toIndex, Out)
	}

	if clear {
		ebm = ebm.Clear(edge)
	} else {
		ebm = ebm.Set(edge)
	}
	g.saveEdge(fromIndex, toIndex, ebm, Out)
	g.saveEdge(toIndex, fromIndex, ebm, In)
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
	fromIndex, ok := g.nodeLookup.Load(from)
	toIndex, ok2 := g.nodeLookup.Load(to)
	if !ok || !ok2 {
		return
	}
	if g.bulkloading {
		g.incomingEdges <- BulkEdgeRequest{
			From:       fromIndex,
			To:         toIndex,
			Edge:       NonExistingEdge, // Indicate we should process the bitmap
			EdgeBitmap: eb,
			Merge:      merge,
		}
		return
	}
	g.edgeMutex.Lock()
	if merge {
		oldeb, _ := g.loadEdge(fromIndex, toIndex, Out)
		eb = oldeb.Merge(eb)
	}
	g.saveEdge(fromIndex, toIndex, eb, Out)
	g.saveEdge(toIndex, fromIndex, eb, In)
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

func (ef EdgeFilter) Iterate(iter func(target *Node, ebm EdgeBitmap) bool) {
	if ef.direction > In {
		return
	}
	ef.graph.edgeMutex.RLock()
	defer ef.graph.edgeMutex.RUnlock()
	for nodeIndex, edgeCombo := range ef.graph.edges[ef.direction][ef.fromNode] {
		eb := ef.graph.edgeCombos[edgeCombo]
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
