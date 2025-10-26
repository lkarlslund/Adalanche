package graph

type CoarseGraph[NodeType GraphNodeInterface[NodeType], EdgeType GraphEdgeInterface[EdgeType]] struct {
	coarseGraph *Graph[NodeType, EdgeType]
	fineGraph   *Graph[NodeType, EdgeType]
}

type coarseNode[NodeType GraphNodeInterface[NodeType], EdgeType GraphEdgeInterface[EdgeType]] struct {
	originalNodes []NodeType
}

type coarseEdge[NodeType GraphNodeInterface[NodeType]] struct {
	from NodeType
	to   NodeType
}

// Coarsen creates a coarsened version of the graph by merging nodes and edges
func (g *Graph[NodeType, EdgeType]) CoarsenOuterNodes() Graph[NodeType, EdgeType] {
	newGraph := g.Clone()

	// Simple coarsening: merge nodes with degree 1 into their neighbors
	degreeMap := make(map[NodeType]int)
	fwd := g.AdjacencyMap()
	rwd := g.PredecessorMap()
	for node := range g.nodes {
		degreeMap[node] = len(fwd[node]) + len(rwd[node])
	}

	for node := range g.nodes {
		if degreeMap[node] == 1 {
			// Nuke it
			newGraph.DeleteNode(node)
		}
	}
	newGraph.autoCleanupEdges()

	return newGraph
}
