package engine

import (
	"github.com/lkarlslund/adalanche/modules/graph"
	"github.com/lkarlslund/adalanche/modules/ui"
)

func CalculateGraphValues(ao *IndexedGraph, matchEdges EdgeBitmap, requiredProbability Probability, name string, valueFunc func(o *Node) int) map[*Node]int {
	pb := ui.ProgressBar(name+" power calculation", int64(ao.Order()*3))

	ui.Debug().Msgf("Building maps and graphs for %v power calculation", name)

	// Build the graph with selected edges in it
	g := graph.NewGraph[*Node, EdgeBitmap]()

	ao.Iterate(func(source *Node) bool {
		ao.Edges(source, Out).Iterate(func(target *Node, edge EdgeBitmap) bool {
			intersectingEdge := edge.Intersect(matchEdges)
			if intersectingEdge.Count() > 0 && intersectingEdge.MaxProbability(source, target) >= requiredProbability {
				g.AddEdge(source, target, intersectingEdge)
			}
			return true
		})

		return true
	})

	// Find cycles
	ui.Info().Msg("Finding strongly connected nodes")
	scc := g.SCCKosaraju()

	ui.Info().Msg("Creating SCC collapsed graph")
	dag := graph.CollapseSCCs(scc, g)

	// First calculate the internal score of the SCC with ALL nodes
	sccScore := make([]int, len(dag.Nodes))
	for i, scc := range dag.Nodes {
		for _, v := range scc {
			sccScore[i] += valueFunc(v)
		}
	}

	topo := graph.TopoSortDAG(dag)

	// Step 3: propagate scores in topological order
	for _, sccIdx := range topo {
		// Add contributions from successor SCCs
		for succ := range dag.Edges[sccIdx] {
			sccScore[sccIdx] += sccScore[succ]

			// also add edge-based values between SCCs
			for range dag.Nodes[sccIdx] {
				for _, v := range dag.Nodes[succ] {
					sccScore[sccIdx] += valueFunc(v)
				}
			}
		}
	}

	deepValues := make(map[*Node]int)
	for i, scc := range dag.Nodes {
		for _, v := range scc {
			deepValues[v] = sccScore[i]
		}
	}

	pb.Finish()

	// Result
	return deepValues
}

func CalculateGraphValuesSlice(ao *IndexedGraph, matchEdges EdgeBitmap, requiredProbability Probability, name string, valueFunc func(o *Node) int) map[*Node]int {
	pb := ui.ProgressBar(name+" power calculation", int64(ao.Order()*3))

	ui.Debug().Msgf("Building maps and graphs for %v power calculation", name)

	// Build the graph with selected edges in it
	g := graph.NewGraph[*Node, EdgeBitmap]()

	ao.Iterate(func(source *Node) bool {
		ao.Edges(source, Out).Iterate(func(target *Node, edge EdgeBitmap) bool {
			intersectingEdge := edge.Intersect(matchEdges)
			if intersectingEdge.Count() > 0 && intersectingEdge.MaxProbability(source, target) >= requiredProbability {
				g.AddEdge(source, target, intersectingEdge)
			}
			return true
		})

		return true
	})

	// Find cycles
	ui.Info().Msg("Finding strongly connected nodes")
	scc := g.SCCKosaraju()

	ui.Info().Msg("Creating SCC collapsed graph")
	dag := graph.CollapseSCCs(scc, g)

	// First calculate the internal score of the SCC with ALL nodes
	sccScore := make([]int, len(dag.Nodes))
	for i, scc := range dag.Nodes {
		for _, v := range scc {
			sccScore[i] += valueFunc(v)
		}
	}

	topo := graph.TopoSortDAG(dag)

	// Step 3: propagate scores in topological order
	for _, sccIdx := range topo {
		// Add contributions from successor SCCs
		for succ := range dag.Edges[sccIdx] {
			sccScore[sccIdx] += sccScore[succ]

			// also add edge-based values between SCCs
			for range dag.Nodes[sccIdx] {
				for _, v := range dag.Nodes[succ] {
					sccScore[sccIdx] += valueFunc(v)
				}
			}
		}
	}

	deepValues := make(map[*Node]int)
	for i, scc := range dag.Nodes {
		for _, v := range scc {
			deepValues[v] = sccScore[i]
		}
	}

	pb.Finish()

	// Result
	return deepValues
}
