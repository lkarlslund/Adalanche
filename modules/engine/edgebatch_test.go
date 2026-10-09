package engine

import (
	"math/rand/v2"
	"testing"
)

// Large batches are applied on several workers; the result is the same as
// applying them one by one.
func TestParallelEdgeMutationsMatchSerial(t *testing.T) {
	random := rand.New(rand.NewPCG(1, 2))
	const nodes = 5000
	ops := make([]indexedEdgeMutation, parallelEdgeMutations*2)
	for i := range ops {
		op := indexedEdgeMutation{
			From:  NodeIndex(random.IntN(nodes)),
			To:    NodeIndex(random.IntN(nodes)),
			Edge:  Edge(random.IntN(4)),
			Merge: random.IntN(4) != 0,
			Clear: random.IntN(5) == 0,
		}
		ops[i] = op
	}
	sortEdgeMutations(ops)
	apply := func(parallel bool) *IndexedGraph {
		g := NewIndexedGraph()
		g.edgeMutex.Lock()
		if parallel {
			g.applySortedEdgeMutationsParallel(ops)
		} else {
			foldEdgeMutations(ops,
				func(from, to NodeIndex) EdgeBitmap { edge, _ := g.loadEdge(from, to, Out); return edge },
				func(from, to NodeIndex, edge EdgeBitmap) {
					g.saveEdge(from, to, edge, Out)
					g.saveEdge(to, from, edge, In)
				})
		}
		g.edgeMutex.Unlock()
		return g
	}
	serial, parallel := apply(false), apply(true)
	for direction := range serial.edges {
		for from := range NodeIndex(nodes) {
			s, p := serial.edges[direction].get(from), parallel.edges[direction].get(from)
			if len(s) != len(p) {
				t.Fatalf("direction %v node %v: %v edges serially, %v in parallel", direction, from, len(s), len(p))
			}
			for to, combo := range s {
				if serial.edgeCombos.get(combo) != parallel.edgeCombos.get(p[to]) {
					t.Fatalf("direction %v edge %v-%v differs", direction, from, to)
				}
			}
		}
	}
}
