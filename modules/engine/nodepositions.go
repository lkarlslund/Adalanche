package engine

import "sync/atomic"

// nodePositions maps nodes to their position in one graph. A node keeps its
// position in the first graph it joins that owns nodes (the analysis graph,
// not a collection's private one) itself, as that graph's ID and the position
// in one word; positions in any other graph are in a map.
type nodePositions struct {
	graph uint32 // this graph's ID, 0 when it keeps all positions in the map
	other shardedMap[*Node, NodeIndex]
}

var graphIDs atomic.Uint32

func (p *nodePositions) own() {
	p.graph = graphIDs.Add(1)
}

func (p *nodePositions) home(h uint64) (NodeIndex, bool) {
	if p.graph != 0 && uint32(h>>32) == p.graph {
		return NodeIndex(uint32(h)), true
	}
	return 0, false
}

func (p *nodePositions) Load(n *Node) (NodeIndex, bool) {
	if i, ok := p.home(n.home.Load()); ok {
		return i, true
	}
	return p.other.Load(n)
}

// LoadOrStore returns the node's position if it has one, and otherwise
// stores i; found reports which.
func (p *nodePositions) LoadOrStore(n *Node, i NodeIndex) (NodeIndex, bool) {
	if p.graph != 0 {
		if n.home.CompareAndSwap(0, uint64(p.graph)<<32|uint64(i)) {
			return i, false
		}
		if existing, ok := p.home(n.home.Load()); ok {
			return existing, true
		}
	}
	return p.other.LoadOrStore(n, i)
}

func (p *nodePositions) Store(n *Node, i NodeIndex) {
	if _, ok := p.home(n.home.Load()); ok {
		n.home.Store(uint64(p.graph)<<32 | uint64(i))
		return
	}
	p.other.Store(n, i)
}

func (p *nodePositions) Delete(n *Node) {
	if h := n.home.Load(); p.graph != 0 && uint32(h>>32) == p.graph {
		n.home.CompareAndSwap(h, 0)
		return
	}
	p.other.Delete(n)
}
