package aql

import (
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/graph"
	"github.com/lkarlslund/adalanche/modules/ui"
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
	// ensure stability
	return pq.items[i].node.ID() < pq.items[j].node.ID()
}

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
	for {
		parent := (i - 1) / 2
		if parent == i || !pq.Less(i, parent) {
			break
		}
		pq.Swap(i, parent)
		i = parent
	}
}

func (pq *PriorityQueue) siftDown(i int) {
	for {
		left := 2*i + 1
		right := 2*i + 2
		largest := i
		if left < len(pq.items) && pq.Less(left, largest) {
			largest = left
		}
		if right < len(pq.items) && pq.Less(right, largest) {
			largest = right
		}
		if largest == i {
			break
		}
		pq.Swap(i, largest)
		i = largest
	}
}

func (pq *PriorityQueue) DropBack(n int) {
	if n < 0 || n > len(pq.items) {
		panic("n must be between 0 and the current length of the queue")
	}
	pq.items = pq.items[:len(pq.items)-n]
}

type searchState struct {
	node                       *engine.Node
	workingGraph               probableWorkingPath
	overAllProbabilityFraction float32
	currentSearchIndex         byte // index into Next and sourceCache patterns
	currentDepth               byte // depth in current edge searcher
	currentTotalDepth          byte // total depth in all edge searchers (for total depth limiting)
}

type pathItem struct {
	target    engine.NodeID
	combo     engine.EdgeCombo
	direction engine.EdgeDirection
	reference byte
}

type probableWorkingPath struct {
	path   []pathItem
	filter bloom
}

func (pWP probableWorkingPath) Clone() probableWorkingPath {
	clone := pWPPool.Get().(probableWorkingPath)
	clone.filter = pWP.filter
	clone.path = append(clone.path[:0], pWP.path...)
	return clone
}

func (pWP probableWorkingPath) HasNode(node engine.NodeID) bool {
	if pWP.filter.Has(node) {
		for _, item := range pWP.path {
			if node == item.target {
				return true
			}
		}
	}
	return false
}

func (pWP probableWorkingPath) HasEdge(from, to engine.NodeID) bool {
	if pWP.filter.Has(from) && pWP.filter.Has(to) {
		for i := 0; i < len(pWP.path)-1; i++ {
			if pWP.path[i+1].direction == engine.Out {
				if pWP.path[i].target == from && pWP.path[i+1].target == to {
					return true
				}
			} else {
				if pWP.path[i].target == to && pWP.path[i+1].target == from {
					return true
				}
			}
		}
	}
	return false
}

func (pWP *probableWorkingPath) Add(node engine.NodeID, direction engine.EdgeDirection, ec engine.EdgeCombo, reference byte) {
	pWP.filter.Add(node)
	pWP.path = append(pWP.path, pathItem{
		target:    node,
		direction: direction,
		reference: reference,
		combo:     ec,
	})
}

func (pWP *probableWorkingPath) CommitToGraph(ao *engine.IndexedGraph, g graph.Graph[*engine.Node, engine.EdgeBitmap], references []NodeQuery) {
	var lastNode *engine.Node

	for _, pathItem := range pWP.path {
		currentNode, found := ao.LookupNodeByID(pathItem.target)
		if !found {
			ui.Fatal().Msgf("Graph has no node with ID %v!?", pathItem.target)
			continue
		}
		if pathItem.reference != 255 {
			g.SetNodeData(currentNode, "reference", references[pathItem.reference].Reference)
		}
		if lastNode == nil {
			lastNode = currentNode
			continue
		}

		eb := ao.EdgeComboToEdgeBitmap(pathItem.combo)
		if pathItem.direction == engine.Out {
			g.AddEdge(lastNode, currentNode, eb)
		} else {
			g.AddEdge(currentNode, lastNode, eb)
		}
		lastNode = currentNode
	}
}
