package engine

import (
	"cmp"
	"runtime"
	"slices"
	"sync"

	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

type indexedEdgeMutation struct {
	From       NodeIndex
	To         NodeIndex
	EdgeBitmap EdgeBitmap
	Edge       Edge
	Merge      bool
	Clear      bool
}

type nodeEdgeMutation struct {
	From       *Node
	To         *Node
	EdgeBitmap EdgeBitmap
	Edge       Edge
	Merge      bool
	Clear      bool
	Force      bool
}

type EdgeImporter struct {
	mu  sync.Mutex
	ops []nodeEdgeMutation
}

func NewEdgeImporter(capacity int) *EdgeImporter {
	return &EdgeImporter{
		ops: make([]nodeEdgeMutation, 0, capacity),
	}
}

func (ei *EdgeImporter) Add(from, to *Node, edge Edge, force bool) {
	ei.mu.Lock()
	ei.ops = append(ei.ops, nodeEdgeMutation{
		From:  from,
		To:    to,
		Edge:  edge,
		Merge: true,
		Force: force,
	})
	ei.mu.Unlock()
}

func (ei *EdgeImporter) Clear(from, to *Node, edge Edge, force bool) {
	ei.mu.Lock()
	ei.ops = append(ei.ops, nodeEdgeMutation{
		From:  from,
		To:    to,
		Edge:  edge,
		Merge: true,
		Clear: true,
		Force: force,
	})
	ei.mu.Unlock()
}

func (ei *EdgeImporter) Set(from, to *Node, eb EdgeBitmap, merge bool) {
	ei.mu.Lock()
	ei.ops = append(ei.ops, nodeEdgeMutation{
		From:       from,
		To:         to,
		Edge:       NonExistingEdge,
		EdgeBitmap: eb,
		Merge:      merge,
	})
	ei.mu.Unlock()
}

func (ei *EdgeImporter) HasOperations() bool {
	ei.mu.Lock()
	defer ei.mu.Unlock()
	return len(ei.ops) > 0
}

func (ei *EdgeImporter) Commit(graph *IndexedGraph) {
	ei.mu.Lock()
	ops := append([]nodeEdgeMutation(nil), ei.ops...)
	ei.ops = ei.ops[:0]
	ei.mu.Unlock()

	if len(ops) == 0 {
		return
	}
	graph.applyIndexedEdgeMutations(graph.resolveEdgeMutations(ops))
}

func (g *IndexedGraph) resolveEdgeMutations(ops []nodeEdgeMutation) []indexedEdgeMutation {
	resolved := make([]indexedEdgeMutation, 0, len(ops))
	for _, op := range ops {
		if op.Edge == NonExistingEdge {
			resolved = append(resolved, g.resolveBitmapMutation(op))
			continue
		}
		resolvedOp, ok := g.resolveSingleEdgeMutation(op)
		if ok {
			resolved = append(resolved, resolvedOp)
		}
	}
	return resolved
}

func (g *IndexedGraph) resolveBitmapMutation(op nodeEdgeMutation) indexedEdgeMutation {
	fromIndex, found := g.nodeLookup.Load(op.From)
	if !found {
		ui.Fatal().Msgf("Node not found in graph")
	}
	toIndex, found := g.nodeLookup.Load(op.To)
	if !found {
		ui.Fatal().Msgf("Node not found in graph")
	}
	return indexedEdgeMutation{
		From:       fromIndex,
		To:         toIndex,
		Edge:       NonExistingEdge,
		EdgeBitmap: op.EdgeBitmap,
		Merge:      op.Merge,
		Clear:      op.Clear,
	}
}

func (g *IndexedGraph) resolveSingleEdgeMutation(op nodeEdgeMutation) (indexedEdgeMutation, bool) {
	if op.From == op.To {
		return indexedEdgeMutation{}, false
	}
	if !op.Force {
		fromSID := op.From.SID()
		if fromSID == windowssecurity.SelfSID {
			return indexedEdgeMutation{}, false
		}

		toSID := op.To.SID()
		if !fromSID.IsBlank() && fromSID == toSID {
			return indexedEdgeMutation{}, false
		}
	}

	fromIndex, found := g.nodeLookup.Load(op.From)
	if !found {
		ui.Fatal().Msgf("Node not found in graph")
	}
	toIndex, found := g.nodeLookup.Load(op.To)
	if !found {
		ui.Fatal().Msgf("Node not found in graph")
	}

	return indexedEdgeMutation{
		From:  fromIndex,
		To:    toIndex,
		Edge:  op.Edge,
		Merge: op.Merge,
		Clear: op.Clear,
	}, true
}

func (g *IndexedGraph) applyIndexedEdgeMutations(ops []indexedEdgeMutation) {
	if len(ops) == 0 {
		return
	}

	sortEdgeMutations(ops)
	g.applySortedEdgeMutations(ops)
}

// sortEdgeMutations orders mutations by endpoints, keeping the order of
// mutations of one edge.
func sortEdgeMutations(ops []indexedEdgeMutation) {
	// Sorting by position as the last key is a stable sort, without the
	// slow merging of one.
	type positioned struct {
		indexedEdgeMutation
		position int
	}
	sorted := make([]positioned, len(ops))
	for i, op := range ops {
		sorted[i] = positioned{op, i}
	}
	slices.SortFunc(sorted, func(a, b positioned) int {
		return cmp.Or(cmp.Compare(a.From, b.From), cmp.Compare(a.To, b.To), cmp.Compare(a.position, b.position))
	})
	for i, op := range sorted {
		ops[i] = op.indexedEdgeMutation
	}
}

// applySortedEdgeMutations applies mutations sorted by sortEdgeMutations.
func (g *IndexedGraph) applySortedEdgeMutations(ops []indexedEdgeMutation) {
	if len(ops) == 0 {
		return
	}
	g.edgeMutex.Lock()
	defer g.edgeMutex.Unlock()
	if len(ops) >= parallelEdgeMutations {
		g.applySortedEdgeMutationsParallel(ops)
		return
	}
	foldEdgeMutations(ops,
		func(from, to NodeIndex) EdgeBitmap {
			edge, _ := g.loadEdge(from, to, Out)
			return edge
		},
		func(from, to NodeIndex, edge EdgeBitmap) {
			g.saveEdge(from, to, edge, Out)
			g.saveEdge(to, from, edge, In)
		})
}

// foldEdgeMutations applies sorted mutations edge by edge: each edge starts
// as current gives it and its result goes to save.
func foldEdgeMutations(ops []indexedEdgeMutation, current func(from, to NodeIndex) EdgeBitmap, save func(from, to NodeIndex, edge EdgeBitmap)) {
	var lastFrom, lastTo NodeIndex
	var lastEdge EdgeBitmap
	first := true
	for _, op := range ops {
		if op.From != lastFrom || op.To != lastTo || first {
			if !first {
				save(lastFrom, lastTo, lastEdge)
			}
			first = false
			lastFrom = op.From
			lastTo = op.To
			lastEdge = current(lastFrom, lastTo)
		}

		if op.Edge == NonExistingEdge {
			if op.Clear {
				lastEdge = lastEdge.Intersect(op.EdgeBitmap.Invert())
			} else if op.Merge {
				lastEdge = lastEdge.Merge(op.EdgeBitmap)
			} else {
				lastEdge = op.EdgeBitmap
			}
			continue
		}

		if !op.Merge {
			lastEdge = EdgeBitmap{}
		}
		if op.Clear {
			lastEdge = lastEdge.Clear(op.Edge)
		} else {
			lastEdge = lastEdge.Set(op.Edge)
		}
	}
	if !first {
		save(lastFrom, lastTo, lastEdge)
	}
}

const parallelEdgeMutations = 1 << 16

// applySortedEdgeMutationsParallel applies many mutations on several
// workers: outgoing edges in ranges of source nodes (the mutations are
// sorted by source), then incoming edges by target node. Callers hold
// edgeMutex.
func (g *IndexedGraph) applySortedEdgeMutationsParallel(ops []indexedEdgeMutation) {
	var highest NodeIndex
	for _, op := range ops {
		highest = max(highest, op.From, op.To)
	}
	// Workers then never resize the adjacency while others write to it.
	for direction := range g.edges {
		g.edges[direction].grow(int(highest) + 1)
	}
	workers := runtime.GOMAXPROCS(0)
	// Split at source boundaries so each source belongs to one worker.
	var bounds []int
	for start := 0; start < len(ops); {
		end := min(len(ops), start+(len(ops)+workers-1)/workers)
		for end < len(ops) && ops[end].From == ops[end-1].From {
			end++
		}
		bounds = append(bounds, start)
		start = end
	}
	bounds = append(bounds, len(ops))
	type incoming struct {
		to, from NodeIndex
		edge     EdgeBitmap
	}
	incomings := make([][]incoming, len(bounds)-1)
	var wg sync.WaitGroup
	for chunk := range len(bounds) - 1 {
		wg.Go(func() {
			foldEdgeMutations(ops[bounds[chunk]:bounds[chunk+1]],
				func(from, to NodeIndex) EdgeBitmap {
					edge, _ := g.loadEdge(from, to, Out)
					return edge
				},
				func(from, to NodeIndex, edge EdgeBitmap) {
					g.storeEdge(from, to, edge, Out)
					incomings[chunk] = append(incomings[chunk], incoming{to, from, edge})
				})
		})
	}
	wg.Wait()
	for w := range workers {
		wg.Go(func() {
			for _, list := range incomings {
				for _, in := range list {
					if int(in.to)%workers == w {
						g.storeEdge(in.to, in.from, in.edge, In)
					}
				}
			}
		})
	}
	wg.Wait()
	g.edgeVersion++
}
