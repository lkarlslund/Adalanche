package graph

import "slices"

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

func (g *Graph[NodeType, EdgeType]) CoarsenBySCCs() Graph[NodeType, EdgeType] {
	sccs := g.SCCGabow()
	newGraph := NewGraph[NodeType, EdgeType]()

	sccNodeMap := make(map[int]NodeType)

	// Create new nodes for each SCC
	for i, scc := range sccs {
		if len(scc) == 0 {
			continue
		}
		// Create a new coarse node representing this SCC
		coarseNode := scc[0] // Just pick the first node as representative
		newGraph.AddNode(coarseNode)
		sccNodeMap[i] = coarseNode
	}

	outgoingMap := g.AdjacencyMap()

	// Create edges between coarse nodes
	for i, scc := range sccs {
		fromNode := sccNodeMap[i]
		for _, node := range scc {
			for _, toNode := range outgoingMap[node] {
				toSCCIndex := -1
				for j, targetSCC := range sccs {
					if slices.Contains(targetSCC, toNode) {
						toSCCIndex = j
					}
					if toSCCIndex != -1 {
						break
					}
				}
				if toSCCIndex != -1 && toSCCIndex != i {
					edge, found := g.GetEdge(node, toNode)
					if !found {
						continue
					}

					toCoarseNode := sccNodeMap[toSCCIndex]
					newGraph.AddEdge(fromNode, toCoarseNode, edge)
				}
			}
		}
	}

	return newGraph
}
