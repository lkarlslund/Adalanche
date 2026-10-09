package engine

import (
	"cmp"
	"slices"
	"strings"
)

// CanonicalRanks returns a rank for every node position in the graph, from
// attributes that identify a node regardless of the order the data was
// loaded in: type, distinguished name, SID, object GUID, data source and
// label. Code that must give the same answer on every run, like path
// searches, visits nodes in rank order instead of position or map order.
// Nodes that agree on all of these keep their position order.
//
// The ranks are computed on first use and again only after nodes are added.
func (g *IndexedGraph) CanonicalRanks() []uint32 {
	g.canonicalMutex.Lock()
	defer g.canonicalMutex.Unlock()
	return g.canonicalRanksLocked()
}

func (g *IndexedGraph) canonicalRanksLocked() []uint32 {
	g.nodeMutex.RLock()
	nodes := g.nodes
	g.nodeMutex.RUnlock()

	if len(g.canonicalRanks) == len(nodes) {
		return g.canonicalRanks
	}

	keys := make([]string, len(nodes))
	var b strings.Builder
	for i, n := range nodes {
		b.Reset()
		b.WriteString(n.Type().String())
		for _, part := range []string{
			n.DN(),
			n.SID().String(),
			n.OneAttrString(ObjectGUID),
			n.OneAttrString(DataSource),
			n.Label(),
		} {
			b.WriteByte(0)
			b.WriteString(part)
		}
		keys[i] = b.String()
	}
	order := make([]int, len(nodes))
	for i := range order {
		order[i] = i
	}
	slices.SortFunc(order, func(a, b int) int {
		return cmp.Or(strings.Compare(keys[a], keys[b]), cmp.Compare(a, b))
	})
	ranks := make([]uint32, len(nodes))
	for rank, position := range order {
		ranks[position] = uint32(rank)
	}
	g.canonicalRanks = ranks
	return ranks
}

// RankedEdge is one neighbour in a RankedAdjacency.
type RankedEdge struct {
	Target NodeIndex
	Combo  EdgeCombo
}

// RankedAdjacency lists every node's neighbours in canonical rank order, per
// direction, indexed by node position.
type RankedAdjacency struct {
	Ranks     []uint32
	Neighbors [2][][]RankedEdge
	nodes     int
	version   uint64
}

// RankedAdjacency returns the neighbours of every node sorted by canonical
// rank, so searches can visit them in a repeatable order without sorting on
// every visit. It is built on first use and again after nodes or edges
// change; the result must not be modified.
func (g *IndexedGraph) RankedAdjacency() *RankedAdjacency {
	g.canonicalMutex.Lock()
	defer g.canonicalMutex.Unlock()
	ranks := g.canonicalRanksLocked()

	g.edgeMutex.RLock()
	defer g.edgeMutex.RUnlock()
	if r := g.rankedEdges; r != nil && r.nodes == len(ranks) && r.version == g.edgeVersion {
		return r
	}
	r := &RankedAdjacency{Ranks: ranks, nodes: len(ranks), version: g.edgeVersion}
	for direction := range r.Neighbors {
		total := 0
		for _, targets := range g.edges[direction] {
			total += len(targets)
		}
		backing := make([]RankedEdge, 0, total)
		lists := make([][]RankedEdge, len(ranks))
		for from, targets := range g.edges[direction] {
			if len(targets) == 0 || int(from) >= len(lists) {
				continue
			}
			start := len(backing)
			for target, combo := range targets {
				backing = append(backing, RankedEdge{target, combo})
			}
			list := backing[start:len(backing):len(backing)]
			slices.SortFunc(list, func(a, b RankedEdge) int {
				return cmp.Compare(ranks[a.Target], ranks[b.Target])
			})
			lists[from] = list
		}
		r.Neighbors[direction] = lists
	}
	g.rankedEdges = r
	return r
}
