package engine

import (
	"runtime"
	"slices"
	"sync"
)

// compact removes folded nodes from the graph in place. Each folded node's
// edges move to the node it was folded into (edges between the two vanish);
// a node folded into nil is removed with its edges.
// node indexes are renumbered in order, and attribute indexes are dropped to
// be rebuilt on use.
func (g *IndexedGraph) compact(folded map[*Node]*Node) {
	if len(folded) == 0 {
		return
	}
	final := func(n *Node) *Node {
		for n != nil {
			next, found := folded[n]
			if !found {
				return n
			}
			n = next
		}
		return nil
	}

	g.nodeMutex.Lock()
	g.edgeMutex.Lock()
	g.indexlock.Lock()
	defer g.nodeMutex.Unlock()
	defer g.edgeMutex.Unlock()
	defer g.indexlock.Unlock()

	// New positions: kept nodes in their old order.
	const gone = ^NodeIndex(0)
	position := make([]NodeIndex, len(g.nodes)) // by old index
	kept := make([]*Node, 0, len(g.nodes)-len(folded))
	for i, n := range g.nodes {
		if _, isFolded := folded[n]; isFolded {
			position[i] = gone
			continue
		}
		position[i] = NodeIndex(len(kept))
		kept = append(kept, n)
	}
	remap := make([]NodeIndex, len(g.nodes))
	for i, n := range g.nodes {
		remap[i] = position[i]
		if remap[i] != gone {
			continue
		}
		if target := final(n); target != nil {
			if old, found := g.nodeLookup.Load(target); found {
				remap[i] = position[old]
			}
		}
	}

	var wg sync.WaitGroup
	for direction := range g.edges {
		wg.Go(func() {
			old := g.edges[direction]
			edges := make(map[NodeIndex]map[NodeIndex]EdgeCombo, len(old))
			for from, targets := range old {
				nf := remap[from]
				if nf == gone {
					continue
				}
				for to, combo := range targets {
					nt := remap[to]
					if nt == gone || nf == nt {
						continue
					}
					m := edges[nf]
					if m == nil {
						m = make(map[NodeIndex]EdgeCombo, len(targets))
						edges[nf] = m
					}
					if existing, found := m[nt]; found {
						combo = g.edgeCombos.intern(g.edgeCombos.get(existing).Merge(g.edgeCombos.get(combo)))
					}
					m[nt] = combo
				}
			}
			g.edges[direction] = edges
		})
	}
	wg.Wait()
	g.edgeVersion++

	for n := range folded {
		g.nodeLookup.Delete(n)
		if n.id != InvalidNodeID {
			if current, found := g.idLookup.Load(n.id); found && current == n {
				g.idLookup.Delete(n.id)
			}
		}
	}
	// Only nodes after the first removed one move.
	first := slices.Index(position, gone)
	if first >= 0 {
		workers := runtime.GOMAXPROCS(0)
		for w := range workers {
			wg.Go(func() {
				for i := first + w; i < len(position); i += workers {
					if position[i] != gone {
						g.nodeLookup.Store(g.nodes[i], position[i])
					}
				}
			})
		}
		wg.Wait()
	}
	g.nodes = kept

	g.typecount = typestatistics{}
	for _, n := range kept {
		g.typecount[n.Type()]++
	}
	for i := range g.indexes {
		g.indexes[i] = nil
	}
	clear(g.multiindexes)
}
