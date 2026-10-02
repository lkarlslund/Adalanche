package engine

import (
	"runtime"
	"slices"
	"sync"
)

// compact removes folded nodes from the graph in place. Each folded node's
// edges move to the node it was folded into (edges between the two vanish);
// a node folded into nil is removed with its edges.
// node indexes are renumbered in order, and the removed nodes leave the
// attribute indexes.
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

	// Kept nodes keep their own targets at their new position, so ranges of
	// them are rebuilt in parallel; folded nodes' edges then join the node
	// they were folded into.
	var wg sync.WaitGroup
	workers := runtime.GOMAXPROCS(0)
	for direction := range g.edges {
		old := g.edges[direction]
		edges := make(adjacency, len(kept))
		rebuild := func(into map[NodeIndex]EdgeCombo, from NodeIndex, targets map[NodeIndex]EdgeCombo) map[NodeIndex]EdgeCombo {
			nf := remap[from]
			for to, combo := range targets {
				nt := remap[to]
				if nt == gone || nf == nt {
					continue
				}
				if into == nil {
					into = make(map[NodeIndex]EdgeCombo, len(targets))
				}
				if existing, found := into[nt]; found {
					combo = g.edgeCombos.intern(g.edgeCombos.get(existing).Merge(g.edgeCombos.get(combo)))
				}
				into[nt] = combo
			}
			return into
		}
		chunk := (len(old) + workers - 1) / workers
		for w := range workers {
			wg.Go(func() {
				for from := w * chunk; from < min(len(old), (w+1)*chunk); from++ {
					if targets := old[from]; len(targets) > 0 && position[from] != gone {
						edges[position[from]] = rebuild(edges[position[from]], NodeIndex(from), targets)
					}
				}
			})
		}
		wg.Wait()
		for from, targets := range old {
			if len(targets) > 0 && position[from] == gone && remap[from] != gone {
				edges[remap[from]] = rebuild(edges[remap[from]], NodeIndex(from), targets)
			}
		}
		g.edges[direction] = edges
	}
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
	// Indexes hold nodes, not positions, so they survive renumbering; only
	// the removed nodes leave them. Nodes that others were folded into were
	// reindexed as they were folded.
	for _, index := range g.indexes {
		if index != nil {
			wg.Go(func() {
				for _, entries := range index.lookup {
					for e := entries; e != nil; e = e.next {
						e.removeAll(folded)
					}
				}
			})
		}
	}
	for _, index := range g.multiindexes {
		wg.Go(func() {
			for _, entries := range index.lookup {
				for e := entries; e != nil; e = e.next {
					e.removeAll(folded)
				}
			}
		})
	}
	wg.Wait()
}
