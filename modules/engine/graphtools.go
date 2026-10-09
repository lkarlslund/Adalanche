package engine

import (
	"github.com/lkarlslund/adalanche/modules/graph"
	"github.com/lkarlslund/adalanche/modules/ui"
)

type GraphValueReader interface {
	Order() int
	Iterate(func(o *Node) bool)
	IterateEdges(node *Node, direction EdgeDirection, iter func(target *Node, ebm EdgeBitmap) bool)
}

func CalculateGraphValues(ao GraphValueReader, matchEdges EdgeBitmap, requiredProbability Probability, name string, valueFunc func(o *Node) int) map[*Node]int {
	return calculateGraphValues(ao, matchEdges, requiredProbability, name, valueFunc)
}

func CalculateGraphValuesSlice(ao GraphValueReader, matchEdges EdgeBitmap, requiredProbability Probability, name string, valueFunc func(o *Node) int) map[*Node]int {
	return calculateGraphValues(ao, matchEdges, requiredProbability, name, valueFunc)
}

func calculateGraphValues(ao GraphValueReader, matchEdges EdgeBitmap, requiredProbability Probability, name string, valueFunc func(o *Node) int) map[*Node]int {
	nodeCount := ao.Order()
	pb := ui.ProgressBar(name+" power calculation", int64(nodeCount*3))

	ui.Debug().Msgf("Building maps and graphs for %v power calculation", name)

	// Build the graph with selected edges in it
	g := graph.NewGraphWithCapacity[*Node, EdgeBitmap](nodeCount, nodeCount)

	ao.Iterate(func(source *Node) bool {
		ao.IterateEdges(source, Out, func(target *Node, edge EdgeBitmap) bool {
			intersectingEdge := edge.Intersect(matchEdges)
			if intersectingEdge.Count() > 0 && intersectingEdge.MaxProbability(source, target) >= requiredProbability {
				g.AddEdge(source, target, intersectingEdge)
			}
			return true
		})

		return true
	})

	// Find cycles
	ui.Debug().Msgf("Finding strongly connected nodes for %v power calculation", name)
	scc := g.SCCKosaraju()

	ui.Debug().Msgf("Creating SCC collapsed graph for %v power calculation", name)
	dag := graph.CollapseSCCs(scc, g)

	// First calculate the internal score of the SCC with ALL nodes
	sccBaseScore := make([]int, len(dag.Nodes))
	sccScore := make([]int, len(dag.Nodes))
	sccSize := make([]int, len(dag.Nodes))
	for i, scc := range dag.Nodes {
		sccSize[i] = len(scc)
		for _, v := range scc {
			sccBaseScore[i] += valueFunc(v)
		}
		sccScore[i] = sccBaseScore[i]
	}

	topo := graph.TopoSortDAG(dag)

	// Step 3: propagate scores in topological order
	for _, sccIdx := range topo {
		// Add contributions from successor SCCs
		for succ := range dag.Edges[sccIdx] {
			sccScore[sccIdx] += sccScore[succ]
			sccScore[sccIdx] += sccSize[sccIdx] * sccBaseScore[succ]
		}
	}

	deepValues := make(map[*Node]int, nodeCount)
	for i, scc := range dag.Nodes {
		for _, v := range scc {
			deepValues[v] = sccScore[i]
		}
	}

	pb.Finish()

	// Result
	return deepValues
}
