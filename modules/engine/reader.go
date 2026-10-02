package engine

import "github.com/lkarlslund/adalanche/modules/windowssecurity"

// GraphReader reads a graph: the graph itself, or a transaction on it,
// which also sees its own staged nodes.
type GraphReader interface {
	Graph() *IndexedGraph
	Root() *Node
	Order() int
	Iterate(each func(o *Node) bool)
	Find(attribute Attribute, value AttributeValue) (*Node, bool)
	FindMulti(attribute Attribute, value AttributeValue) (NodeSlice, bool)
	FindTwo(attribute Attribute, value AttributeValue, attribute2 Attribute, value2 AttributeValue) (*Node, bool)
	FindTwoMulti(attribute Attribute, value AttributeValue, attribute2 Attribute, value2 AttributeValue) (NodeSlice, bool)
	FindAdjacentSID(s windowssecurity.SID, relativeTo *Node) (*Node, bool)
	DistinguishedParent(o *Node) (*Node, bool)
	GetEdge(from, to *Node) (EdgeBitmap, bool)
	IterateEdges(o *Node, direction EdgeDirection, iter func(target *Node, ebm EdgeBitmap) bool)
	EdgeIteratorRecursive(node *Node, direction EdgeDirection, edgeMatch EdgeBitmap, excludemyself bool, goDeeperFunc func(source, target *Node, edge EdgeBitmap, depth int) bool)
}

// Graph returns the graph itself, so a graph is a GraphReader.
func (os *IndexedGraph) Graph() *IndexedGraph { return os }

var (
	_ GraphReader = (*IndexedGraph)(nil)
	_ GraphReader = (*Tx)(nil)
)
