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
	datasource         *engine.Objects
	Sources            []NodeQuery // count is n
	sourceCache        []*engine.Objects
	Next               []EdgeSearcher // count is n-1
	Mode               QueryMode
	Shortest           bool
	OverAllProbability engine.Probability
}

func (aqlq AQLquery) Resolve(opts ResolverOptions) (*graph.Graph[*engine.Object, engine.EdgeBitmap], error) {
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
	aqlq.sourceCache = make([]*engine.Objects, len(aqlq.Sources))
	for i, q := range aqlq.Sources {
		aqlq.sourceCache[i] = q.Populate(aqlq.datasource)
		ui.Debug().Msgf("Node cache %v has %v nodes", i, aqlq.sourceCache[i].Len())
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
	result := graph.NewGraph[*engine.Object, engine.EdgeBitmap]()

	if len(aqlq.Sources) == 1 {
		aqlq.sourceCache[0].Iterate(func(o *engine.Object) bool {
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
	aqlq.sourceCache[nodeindex].IterateParallel(func(o *engine.Object) bool {
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

func (aqlq AQLquery) resolveEdgesFrom(
	opts ResolverOptions,
	startObject *engine.Object,
) graph.Graph[*engine.Object, engine.EdgeBitmap] {

	committedGraph := graph.NewGraph[*engine.Object, engine.EdgeBitmap]()

	type searchState struct {
		currentObject             *engine.Object
		workingGraph              graph.Graph[*engine.Object, engine.EdgeBitmap]
		currentSearchIndex        int // index into Next and sourceCache patterns
		currentDepth              int // depth in current edge searcher
		currentTotalDepth         int // total depth in all edge searchers (for total depth limiting)
		currentOverAllProbability float64
	}

	// Initialize the search queue with the starting object and search index
	initialWorkingGraph := graph.NewGraph[*engine.Object, engine.EdgeBitmap]()
	initialWorkingGraph.AddNode(startObject)
	initialWorkingGraph.SetNodeData(startObject, "reference", aqlq.Sources[0].Reference)

	queue := deque.NewDeque[searchState]()
	queue.PushBack(searchState{
		currentObject:             startObject,
		currentSearchIndex:        0,
		workingGraph:              initialWorkingGraph,
		currentDepth:              0,
		currentTotalDepth:         0,
		currentOverAllProbability: 1,
	})

	for !queue.IsEmpty() {
		// Check if we've reached the node limit
		if opts.NodeLimit > 0 && committedGraph.Order() >= opts.NodeLimit {
			break
		}

		var currentState searchState
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
			if len(aqlq.Next) > currentState.currentSearchIndex+1 {
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
				committedGraph.Merge(currentState.workingGraph)
				committedGraph.SetNodeData(currentState.currentObject, "reference", aqlq.Sources[currentState.currentSearchIndex].Reference)
			}
		}

		// Reached max depth for this edge searcher, cannot continue
		if nextDepth > thisEdgeSearcher.MaxIterations {
			continue
		}

		for _, direction := range directions {
			currentState.currentObject.Edges(direction).Range(func(nextObject *engine.Object, eb engine.EdgeBitmap) bool {
				if opts.NodeLimit > 0 && committedGraph.Order() >= opts.NodeLimit {
					return false
				}

				// Check homomorphism requirements
				switch aqlq.Mode {
				case Trail:
					if direction == engine.Out {
						if committedGraph.HasEdge(currentState.currentObject, nextObject) || currentState.workingGraph.HasEdge(currentState.currentObject, nextObject) {
							return true
						}
					} else {
						if committedGraph.HasEdge(nextObject, currentState.currentObject) || currentState.workingGraph.HasEdge(nextObject, currentState.currentObject) {
							return true
						}
					}
				case Acyclic:
					if committedGraph.HasNode(nextObject) || currentState.workingGraph.HasNode(nextObject) {
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

				if thisEdgeSearcher.pathNodeRequirementCache != nil && !thisEdgeSearcher.pathNodeRequirementCache.Contains(nextObject) {
					return true
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

				addedge := matchedEdges
				if thisEdgeSearcher.FilterEdges.NoTrimEdges {
					addedge = eb
				}

				// Valid next object
				newWorkingGraph := currentState.workingGraph.Clone()
				if direction == engine.Out {
					newWorkingGraph.AddEdge(currentState.currentObject, nextObject, addedge)
				} else {
					newWorkingGraph.AddEdge(nextObject, currentState.currentObject, addedge)
				}

				if nextDepth >= thisEdgeSearcher.MinIterations {
					// Next node is a match
					if (nextTargets == nil || nextTargets.Contains(nextObject)) &&
						currentState.currentSearchIndex < len(aqlq.Next)-1 {
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

					if currentState.currentSearchIndex == len(aqlq.Next)-1 &&
						(nextTargets == nil || nextTargets.Contains(nextObject)) {
						// We've reached the end of the current search index, so let's merge the working graph into the committed graph - it's a complete match
						committedGraph.Merge(newWorkingGraph)
						committedGraph.SetNodeData(nextObject, "reference", aqlq.Sources[currentState.currentSearchIndex+1].Reference)
					}

					// check overall node limit
					if opts.NodeLimit > 0 && committedGraph.Order() >= opts.NodeLimit {
						return false
					}
				}

				// More edges and nodes along the same searcher (deeper search)
				if nextDepth < thisEdgeSearcher.MaxIterations &&
					(nextEdgeTargets == nil ||
						nextEdgeTargets.Contains(nextObject)) {
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
