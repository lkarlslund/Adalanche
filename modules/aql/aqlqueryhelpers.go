package aql

import (
	"cmp"
	"slices"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/graph"
)

type Priority int

const (
	ShortestFirst Priority = iota
	ProbableShortest
	LongestFirst
	UnlikelyLongest
)

type PriorityQueue struct {
	items []searchState
	p     Priority
}

func (pq *PriorityQueue) Len() int { return len(pq.items) }

func (pq *PriorityQueue) Less(i, j int) bool {
	switch pq.p {
	case ProbableShortest:
		if pq.items[i].overAllProbabilityFraction > pq.items[j].overAllProbabilityFraction {
			return true
		}
		if pq.items[i].overAllProbabilityFraction < pq.items[j].overAllProbabilityFraction {
			return false
		}
		fallthrough
	case ShortestFirst:
		if pq.items[i].currentTotalDepth < pq.items[j].currentTotalDepth {
			return true
		}
		if pq.items[i].currentTotalDepth > pq.items[j].currentTotalDepth {
			return false
		}
	case UnlikelyLongest:
		if pq.items[i].overAllProbabilityFraction < pq.items[j].overAllProbabilityFraction {
			return true
		}
		if pq.items[i].overAllProbabilityFraction > pq.items[j].overAllProbabilityFraction {
			return false
		}
		fallthrough
	case LongestFirst:
		if pq.items[i].currentTotalDepth > pq.items[j].currentTotalDepth {
			return true
		}
		if pq.items[i].currentTotalDepth < pq.items[j].currentTotalDepth {
			return false
		}
	}
	// A strict total order, so the pop order never depends on heap layout.
	a, b := &pq.items[i], &pq.items[j]
	if a.rank != b.rank {
		return a.rank < b.rank
	}
	if a.path != b.path {
		return a.path < b.path
	}
	return a.currentSearchIndex < b.currentSearchIndex
}

// The queue is a 4-ary heap: half the depth of a binary heap, and siblings
// share cache lines, which matters with millions of queued states.
const queueArity = 4

func (pq *PriorityQueue) Swap(i, j int) {
	pq.items[i], pq.items[j] = pq.items[j], pq.items[i]
}

func (pq *PriorityQueue) Push(x searchState) {
	if len(pq.items) == cap(pq.items) {
		newCap := cap(pq.items) * 2
		if newCap == 0 {
			newCap = 1
		}
		newItems := make([]searchState, len(pq.items), newCap)
		copy(newItems, pq.items)
		pq.items = newItems
	}
	pq.items = append(pq.items, x)
	pq.siftUp(len(pq.items) - 1)
}

func (pq *PriorityQueue) Pop() searchState {
	if len(pq.items) == 0 {
		panic("pop from empty priority queue")
	}
	item := pq.items[0]
	pq.items[0] = pq.items[len(pq.items)-1]
	pq.items = pq.items[:len(pq.items)-1]
	pq.siftDown(0)

	if len(pq.items) <= cap(pq.items)/4 {
		newCap := max(cap(pq.items)/2, 1)
		newItems := make([]searchState, len(pq.items), newCap)
		copy(newItems, pq.items)
		pq.items = newItems
	}
	return item
}

func (pq *PriorityQueue) siftUp(i int) {
	for i > 0 {
		parent := (i - 1) / queueArity
		if !pq.Less(i, parent) {
			break
		}
		pq.Swap(i, parent)
		i = parent
	}
}

func (pq *PriorityQueue) siftDown(i int) {
	for {
		first := queueArity*i + 1
		if first >= len(pq.items) {
			break
		}
		best := i
		for child := first; child < min(first+queueArity, len(pq.items)); child++ {
			if pq.Less(child, best) {
				best = child
			}
		}
		if best == i {
			break
		}
		pq.Swap(i, best)
		i = best
	}
}

func (pq *PriorityQueue) DropBack(n int) {
	if n < 0 || n > len(pq.items) {
		panic("n must be between 0 and the current length of the queue")
	}
	pq.items = pq.items[:len(pq.items)-n]
}

// searchState is one partial path in the search. The path itself lives in the
// resolver's pathArena; a state only holds the index of its last step. States
// hold no pointers, so the collector never has to scan the queue.
type searchState struct {
	filter                     pathFilter       // node IDs on the path
	nodeIndex                  engine.NodeIndex // position in the data source graph
	path                       int32            // last step in the pathArena
	rank                       uint32           // canonical rank of the node, for a repeatable order
	overAllProbabilityFraction float32
	currentSearchIndex         byte // index into Next and sourceCache patterns
	currentDepth               byte // depth in current edge searcher
	currentTotalDepth          byte // total depth in all edge searchers (for total depth limiting)
}

type pathItem struct {
	target    engine.NodeIndex // position in the data source graph
	combo     engine.EdgeCombo
	direction engine.EdgeDirection
	reference byte
}

type pathStep struct {
	item       pathItem
	parent     int32  // previous step, or -1 at the start of the path
	commits    uint32 // committed paths that include this step
	lastCommit uint32 // sequence number of the latest of those commits
}

// pathArena stores all paths explored from one start node as a tree of
// steps. Paths that share a prefix share its steps, so extending a path
// costs one step instead of copying the whole path.
type pathArena struct {
	steps   []pathStep
	commits uint32
	scratch []int32
	// committedEdges holds the edges of committed paths as source->target
	// pairs while the search runs, for TRAIL. Nil when not tracked.
	committedEdges map[[2]engine.NodeIndex]struct{}
}

// hasCommittedEdge reports whether a committed path uses the edge from->to.
func (a *pathArena) hasCommittedEdge(from, to engine.NodeIndex) bool {
	_, found := a.committedEdges[[2]engine.NodeIndex{from, to}]
	return found
}

func (a *pathArena) add(parent int32, item pathItem) int32 {
	a.steps = append(a.steps, pathStep{item: item, parent: parent})
	return int32(len(a.steps) - 1)
}

func (a *pathArena) hasNode(tail int32, filter pathFilter, node engine.NodeIndex) bool {
	if !filter.mayHave(node) {
		return false
	}
	for i := tail; i >= 0; i = a.steps[i].parent {
		if a.steps[i].item.target == node {
			return true
		}
	}
	return false
}

// hasEdge reports whether the path already traversed from -> to, in the
// direction each step was taken.
func (a *pathArena) hasEdge(tail int32, filter pathFilter, from, to engine.NodeIndex) bool {
	if !filter.mayHave(from) || !filter.mayHave(to) {
		return false
	}
	for i := tail; i >= 0 && a.steps[i].parent >= 0; i = a.steps[i].parent {
		step, previous := a.steps[i].item, a.steps[a.steps[i].parent].item
		if step.direction == engine.Out {
			if previous.target == from && step.target == to {
				return true
			}
		} else if previous.target == to && step.target == from {
			return true
		}
	}
	return false
}

// commit records a completed path. Its nodes are added to g immediately,
// because the search checks them; edges and node data are written once per
// step by flush.
func (a *pathArena) commit(tail int32, ds *engine.IndexedGraph, g graph.Graph[*engine.Node, engine.EdgeBitmap]) {
	a.commits++
	for i := tail; i >= 0; i = a.steps[i].parent {
		step := &a.steps[i]
		if step.commits == 0 {
			g.AddNode(ds.NodeAt(step.item.target))
			if a.committedEdges != nil && step.parent >= 0 {
				from, to := a.steps[step.parent].item.target, step.item.target
				if step.item.direction == engine.In {
					from, to = to, from
				}
				a.committedEdges[[2]engine.NodeIndex{from, to}] = struct{}{}
			}
		}
		step.commits++
		step.lastCommit = a.commits
	}
}

// flush writes the edges and reference data of all committed steps. Steps
// are applied in the order of their latest commit, and path order within a
// commit, so the last value written for any node or edge is the same as if
// every commit had written its whole path; each edge's flow is the number of
// committed paths through it.
func (a *pathArena) flush(ds *engine.IndexedGraph, g graph.Graph[*engine.Node, engine.EdgeBitmap], references []NodeQuery) {
	a.scratch = a.scratch[:0]
	for i := range a.steps {
		if a.steps[i].commits > 0 {
			a.scratch = append(a.scratch, int32(i))
		}
	}
	slices.SortFunc(a.scratch, func(x, y int32) int {
		if c := cmp.Compare(a.steps[x].lastCommit, a.steps[y].lastCommit); c != 0 {
			return c
		}
		return cmp.Compare(x, y) // a parent always precedes its children
	})
	for _, i := range a.scratch {
		step := a.steps[i]
		node := ds.NodeAt(step.item.target)
		if step.item.reference != 255 {
			g.SetNodeData(node, "reference", references[step.item.reference].Reference)
		}
		if step.parent < 0 {
			continue
		}
		previous := ds.NodeAt(a.steps[step.parent].item.target)
		eb := ds.EdgeComboToEdgeBitmap(step.item.combo)
		if step.item.direction == engine.Out {
			g.AddEdgeFlow(previous, node, eb, int(step.commits))
		} else {
			g.AddEdgeFlow(node, previous, eb, int(step.commits))
		}
	}
}
