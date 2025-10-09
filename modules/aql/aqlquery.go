package aql

import (
	"errors"
	"runtime"
	"sync"

	deque "github.com/edwingeng/deque/v2"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/graph"
	"github.com/lkarlslund/adalanche/modules/query"
	"github.com/lkarlslund/adalanche/modules/ui"
)

type AQLquery struct {
	datasource         *engine.IndexedGraph
	Sources            []NodeQuery // count is n
	sourceCache        []*engine.IndexedGraph
	Next               []EdgeSearcher // count is n-1
	Mode               QueryMode
	Shortest           bool
	OverAllProbability engine.Probability
}

func (aqlq AQLquery) Resolve(opts ResolverOptions) (*graph.Graph[*engine.Node, engine.EdgeBitmap], error) {
	if aqlq.Mode == Walk {
		// Check we don't have endless filtering potential
		for _, nf := range aqlq.Next {
			if nf.MaxIterations == 0 {
				return nil, errors.New("can't resolve Walk query without edge iteration limit")
			}
		}
	}
	pb := ui.ProgressBar("Preparing AQL query sources", int64(len(aqlq.Sources)*2))
	defer pb.Finish()

	// Prepare all the potentialnodes by filtering them and saving them in potentialnodes[n]
	aqlq.sourceCache = make([]*engine.IndexedGraph, len(aqlq.Sources))
	for i, q := range aqlq.Sources {
		aqlq.sourceCache[i] = q.Populate(aqlq.datasource)
		ui.Debug().Msgf("Node cache %v has %v nodes", i, aqlq.sourceCache[i].Order())
		pb.Add(1)
	}
	for i, q := range aqlq.Next {
		if q.PathNodeRequirement != nil {
			aqlq.Next[i].pathNodeRequirementCache = q.PathNodeRequirement.Populate(aqlq.datasource)
		}
		pb.Add(1)
	}
	pb.Add(1)
	pb.Finish()
	// nodes := make([]*engine.Objects, len(aqlq.Sources))
	result := graph.NewGraph[*engine.Node, engine.EdgeBitmap]()

	if len(aqlq.Sources) == 1 {
		aqlq.sourceCache[0].Iterate(func(o *engine.Node) bool {
			result.AddNode(o)
			if aqlq.Sources[0].Reference != "" {
				result.SetNodeData(o, "reference", aqlq.Sources[0].Reference)
			}
			return true
		})
		return &result, nil
	}

	var resultlock sync.Mutex
	nodeindex := 0
	// Iterate over all starting nodes
	aqlq.sourceCache[nodeindex].IterateParallel(func(o *engine.Node) bool {
		searchResult := aqlq.resolveEdgesFrom(opts, o)
		resultlock.Lock()
		defer resultlock.Unlock()
		if opts.NodeLimit == 0 || result.Order() <= opts.NodeLimit {
			result.Merge(searchResult)
			return true
		}
		return false
	}, runtime.NumCPU())
	return &result, nil
}

var (
	directionsIn  = []engine.EdgeDirection{engine.In}
	directionsOut = []engine.EdgeDirection{engine.Out}
	directionsAny = []engine.EdgeDirection{engine.In, engine.Out}
)

var pWPPool sync.Pool

func init() {
	pWPPool.New = func() any {
		return &probableWorkingPath{}
	}
}

type pathItem struct {
	target    *engine.Node
	reference byte
	direction engine.EdgeDirection
}

type probableWorkingPath struct {
	filter bloom
	path   []pathItem
}

func (pWP probableWorkingPath) Clone() probableWorkingPath {
	clone := pWPPool.Get().(*probableWorkingPath)
	clone.filter = pWP.filter
	clone.path = append(clone.path[:0], pWP.path...)
	return *clone
}

func (pWP probableWorkingPath) HasNode(node *engine.Node) bool {
	if pWP.filter.Has(node.ID()) {
		for _, item := range pWP.path {
			if node == item.target {
				return true
			}
		}
	}
	return false
}

func (pWP probableWorkingPath) HasEdge(from, to *engine.Node) bool {
	if pWP.filter.Has(from.ID()) && pWP.filter.Has(to.ID()) {
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

func (pWP *probableWorkingPath) Add(node *engine.Node, direction engine.EdgeDirection, reference byte) {
	pWP.filter.Add(node.ID())
	pWP.path = append(pWP.path, pathItem{
		target:    node,
		direction: direction,
		reference: reference,
	})
}

func (pWP *probableWorkingPath) CommitToGraph(ao *engine.IndexedGraph, g graph.Graph[*engine.Node, engine.EdgeBitmap], references []NodeQuery) {
	var lastNode *engine.Node
	for _, pathItem := range pWP.path {
		if pathItem.reference != 255 {
			g.SetNodeData(pathItem.target, "reference", references[pathItem.reference].Reference)
		}
		if lastNode == nil {
			lastNode = pathItem.target
			continue
		}
		if pathItem.direction == engine.Out {
			// lookup edge from start object to current object
			bitmap, found := ao.GetEdge(lastNode, pathItem.target)
			if !found {
				ui.Error().Msgf("Graph has no outgoing edge from %v to %v!?", lastNode, pathItem.target)
			}
			g.AddEdge(lastNode, pathItem.target, bitmap)
		} else {
			bitmap, found := ao.GetEdge(pathItem.target, lastNode)
			if !found {
				ui.Error().Msgf("Graph has no incoming edge from %v to %v!?", pathItem.target, lastNode)
			}
			g.AddEdge(pathItem.target, lastNode, bitmap)
		}
		lastNode = pathItem.target
	}
}

func (aqlq AQLquery) resolveEdgesFrom(
	opts ResolverOptions,
	startObject *engine.Node,
) graph.Graph[*engine.Node, engine.EdgeBitmap] {

	committedGraph := graph.NewGraph[*engine.Node, engine.EdgeBitmap]()

	type searchState struct {
		currentObject             *engine.Node
		workingGraph              probableWorkingPath
		currentSearchIndex        int // index into Next and sourceCache patterns
		currentDepth              int // depth in current edge searcher
		currentTotalDepth         int // total depth in all edge searchers (for total depth limiting)
		currentOverAllProbability float64
	}

	// Initialize the search queue with the starting object and search index
	var initialWorkingGraph probableWorkingPath
	initialWorkingGraph.Add(startObject, engine.Any, 0)
	// FIXME initialWorkingGraph.SetNodeData(startObject, "reference", aqlq.Sources[0].Reference)

	queue := deque.NewDeque[searchState]()
	queue.PushBack(searchState{
		currentObject:             startObject,
		currentSearchIndex:        0,
		workingGraph:              initialWorkingGraph,
		currentDepth:              0,
		currentTotalDepth:         0,
		currentOverAllProbability: 1,
	})

	first := true
	var currentState searchState
	for !queue.IsEmpty() {
		// Check if we've reached the node limit
		if opts.NodeLimit > 0 && committedGraph.Order() >= opts.NodeLimit {
			break
		}

		if !first {
			pWPPool.Put(currentState)
		}

		if aqlq.Shortest {
			// Pop from front for BFS (standard, shortest results)
			currentState = queue.PopFront()
		} else {
			// Pop from end for DFS
			currentState = queue.PopBack()
		}
		nextDepth := currentState.currentDepth + 1
		nextTotalDepth := currentState.currentTotalDepth + 1

		thisEdgeSearcher := aqlq.Next[currentState.currentSearchIndex]
		nextTargets := aqlq.sourceCache[currentState.currentSearchIndex+1]

		// If edge has node requirements, use that, otherwise default to the next final node requirement
		nextEdgeTargets := thisEdgeSearcher.pathNodeRequirementCache
		if nextEdgeTargets == nil {
			nextEdgeTargets = nextTargets
		}

		var directions []engine.EdgeDirection
		switch thisEdgeSearcher.Direction {
		case engine.In:
			directions = directionsIn
		case engine.Out:
			directions = directionsOut
		case engine.Any:
			directions = directionsAny
		}

		// Optionally skip this edge searcher if MinIterations == 0
		if thisEdgeSearcher.MinIterations == 0 && currentState.currentDepth == 0 {
			// We can skip this one!
			if currentState.currentSearchIndex < len(aqlq.Next)-1 {
				queue.PushBack(searchState{
					currentObject:             currentState.currentObject,
					currentSearchIndex:        currentState.currentSearchIndex + 1,
					workingGraph:              currentState.workingGraph,
					currentDepth:              0,
					currentTotalDepth:         currentState.currentTotalDepth,
					currentOverAllProbability: currentState.currentOverAllProbability,
				})
			} else {
				// The last edge searcher is not required, so add this as a match
				currentState.workingGraph.CommitToGraph(aqlq.datasource, committedGraph, aqlq.Sources)
			}
		}

		for _, direction := range directions {
			aqlq.datasource.Edges(currentState.currentObject, direction).Iterate(func(nextObject *engine.Node, eb engine.EdgeBitmap) bool {
				if opts.NodeLimit > 0 && committedGraph.Order() >= opts.NodeLimit {
					return false
				}

				// Check homomorphism requirements
				switch aqlq.Mode {
				case Trail:
					if direction == engine.Out {
						if committedGraph.HasEdge(currentState.currentObject, nextObject) ||
							currentState.workingGraph.HasEdge(currentState.currentObject, nextObject) {
							return true
						}
					} else {
						if committedGraph.HasEdge(nextObject, currentState.currentObject) ||
							currentState.workingGraph.HasEdge(nextObject, currentState.currentObject) {
							return true
						}
					}
				case Acyclic:
					if currentState.workingGraph.HasNode(nextObject) || committedGraph.HasNode(nextObject) {
						return true
					}
				case Simple:
					if currentState.workingGraph.HasNode(nextObject) {
						return true
					}
				}

				// Check if the edge is a match
				matchedEdges := thisEdgeSearcher.FilterEdges.Bitmap.Intersect(eb)
				if thisEdgeSearcher.FilterEdges.Comparator != query.CompareInvalid {
					if !query.Comparator[int64](thisEdgeSearcher.FilterEdges.Comparator).Compare(int64(matchedEdges.Count()), thisEdgeSearcher.FilterEdges.Count) {
						return true
					}
				} else {
					if matchedEdges.IsBlank() {
						return true
					}
				}

				var edgeProbability engine.Probability
				if direction == engine.Out {
					edgeProbability = matchedEdges.MaxProbability(currentState.currentObject, nextObject)
				} else {
					edgeProbability = matchedEdges.MaxProbability(nextObject, currentState.currentObject)
				}

				// Edge probability filtering
				if thisEdgeSearcher.ProbabilityComparator != query.CompareInvalid && !query.Comparator[engine.Probability](thisEdgeSearcher.ProbabilityComparator).Compare(edgeProbability, thisEdgeSearcher.ProbabilityValue) {
					return true
				}

				// Options based edge probability filtering
				if opts.MinEdgeProbability > 0 && edgeProbability < opts.MinEdgeProbability {
					return true
				}

				nextOverAllProbability := currentState.currentOverAllProbability * float64(edgeProbability)
				if nextOverAllProbability < float64(aqlq.OverAllProbability) {
					return true
				}
				nextOverAllProbability = nextOverAllProbability / 100 // make it 0-1 float

				// addedge := matchedEdges
				// if thisEdgeSearcher.FilterEdges.NoTrimEdges {
				// 	addedge = eb
				// }

				// Next node is a match
				if currentState.currentDepth >= thisEdgeSearcher.MinIterations &&
					(nextTargets == nil || nextTargets.Contains(nextObject)) {
					newWorkingGraph := currentState.workingGraph.Clone()
					newWorkingGraph.Add(nextObject, direction, byte(currentState.currentSearchIndex+1))

					atLastIndex := currentState.currentSearchIndex == len(aqlq.Next)-1
					if atLastIndex {
						// We've reached the end of the current search index, so let's merge the working graph into the committed graph - it's a complete match
						newWorkingGraph.CommitToGraph(aqlq.datasource, committedGraph, aqlq.Sources)
					}
					// Reached max depth for this edge searcher, cannot continue
					if currentState.currentSearchIndex < len(aqlq.Next)-1 && nextTotalDepth <= opts.MaxDepth {
						// queue next search index
						queue.PushBack(searchState{
							currentObject:             nextObject,
							currentSearchIndex:        currentState.currentSearchIndex + 1,
							workingGraph:              newWorkingGraph,
							currentDepth:              0,
							currentTotalDepth:         nextTotalDepth,
							currentOverAllProbability: nextOverAllProbability,
						})
					}
				}
				if nextDepth < thisEdgeSearcher.MaxIterations && nextTotalDepth <= opts.MaxDepth &&
					(nextEdgeTargets == nil || nextEdgeTargets.Contains(nextObject)) {
					// More edges and nodes along the same searcher (deeper search)
					newWorkingGraph := currentState.workingGraph.Clone()
					newWorkingGraph.Add(nextObject, direction, 255)

					queue.PushBack(searchState{
						currentObject:             nextObject,
						currentSearchIndex:        currentState.currentSearchIndex,
						workingGraph:              newWorkingGraph,
						currentDepth:              nextDepth,
						currentTotalDepth:         nextTotalDepth,
						currentOverAllProbability: nextOverAllProbability,
					})
				}
				return true
			})
		}
	}

	return committedGraph
}
