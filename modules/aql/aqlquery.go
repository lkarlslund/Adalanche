package aql

import (
	"errors"
	"sync"

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
	Traversal          Priority
	OverAllProbability engine.Probability
}

func (aqlq AQLquery) Resolve(opts ResolverOptions) (*graph.Graph[*engine.Node, engine.EdgeBitmap], error) {
	if aqlq.Mode == Walk {
		for _, nf := range aqlq.Next {
			if nf.MaxIterations == 0 {
				return nil, errors.New("can't resolve Walk query without edge iteration limit")
			}
		}
	}
	pb := ui.ProgressBar("Preparing AQL query sources", int64(len(aqlq.Sources)*2))

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
	pb = ui.ProgressBar("Searching from start nodes", int64(len(aqlq.sourceCache)))
	aqlq.sourceCache[nodeindex].IterateParallel(func(o *engine.Node) bool {
		pb.Add(1)
		searchResult := aqlq.resolveEdgesFrom(opts, o)
		resultlock.Lock()
		if opts.NodeLimit == 0 || result.Order() <= opts.NodeLimit {
			result.Merge(searchResult)
		}
		resultlock.Unlock()
		return false
	}, 0)
	pb.Finish()
	return &result, nil
}

func (aqlq AQLquery) resolveEdgesFrom(
	opts ResolverOptions,
	startObject *engine.Node,
) graph.Graph[*engine.Node, engine.EdgeBitmap] {
	committedGraph := graph.NewGraph[*engine.Node, engine.EdgeBitmap]()
	maxSearchIndex := byte(len(aqlq.Next))

	var initialWorkingGraph probableWorkingPath
	initialWorkingGraph.Add(startObject.ID(), engine.Any, 0, 0)

	queue := PriorityQueue{
		p: aqlq.Traversal,
	}
	queue.Push(searchState{
		node:                       startObject,
		currentSearchIndex:         0,
		workingGraph:               initialWorkingGraph,
		currentDepth:               0,
		currentTotalDepth:          0,
		overAllProbabilityFraction: 1,
	})

	var processed int
	var currentState searchState
	for queue.Len() > 0 {
		if opts.NodeLimit > 0 && committedGraph.Order() >= opts.NodeLimit {
			break
		}

		if processed != 0 {
			pWPPool.Put(currentState.workingGraph)
		}
		processed++

		currentState = queue.Pop()

		// completed path in queue
		if currentState.currentSearchIndex == maxSearchIndex {
			// do deduplication checks here if needed
			currentState.workingGraph.CommitToGraph(aqlq.datasource, committedGraph, aqlq.Sources)
			continue
		}

		nextDepth := currentState.currentDepth + 1
		nextTotalDepth := currentState.currentTotalDepth + 1
		nextSearchIndex := currentState.currentSearchIndex + 1

		thisEdgeSearcher := aqlq.Next[currentState.currentSearchIndex]
		nextTargets := aqlq.sourceCache[currentState.currentSearchIndex+1]

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

		if thisEdgeSearcher.MinIterations == 0 && currentState.currentDepth == 0 {
			queue.Push(searchState{
				node:                       currentState.node,
				currentSearchIndex:         currentState.currentSearchIndex + 1,
				workingGraph:               currentState.workingGraph,
				currentDepth:               0,
				currentTotalDepth:          currentState.currentTotalDepth,
				overAllProbabilityFraction: currentState.overAllProbabilityFraction,
			})
		}

		for _, direction := range directions {
			aqlq.datasource.Edges(currentState.node, direction).Iterate(func(nextNode *engine.Node, eb engine.EdgeBitmap) bool {
				if opts.NodeLimit > 0 && committedGraph.Order() >= opts.NodeLimit {
					return false
				}

				switch aqlq.Mode {
				case Walk:
					// no-op
				case Trail:
					if direction == engine.Out {
						if /*committedGraph.HasEdge(currentState.node, nextNode) ||*/
						currentState.workingGraph.HasEdge(currentState.node.ID(), nextNode.ID()) {
							return true
						}
					} else {
						if /*committedGraph.HasEdge(nextNode, currentState.node) ||*/
						currentState.workingGraph.HasEdge(nextNode.ID(), currentState.node.ID()) {
							return true
						}
					}
				case Acyclic:
					if currentState.workingGraph.HasNode(nextNode.ID()) || committedGraph.HasNode(nextNode) {
						return true
					}
					// case Path:
					// 	if currentState.workingGraph.HasNode(nextNode.ID()) {
					// 		return true
					// 	}
				}

				if thisEdgeSearcher.FilterEdges.NegativeComparator != query.CompareInvalid {
					matchedEdges := thisEdgeSearcher.FilterEdges.NegativeBitmap.Intersect(eb)
					if query.Comparator[int64](thisEdgeSearcher.FilterEdges.NegativeComparator).Compare(int64(matchedEdges.Count()), thisEdgeSearcher.FilterEdges.NegativeCount) {
						return true
					}
				}

				var edgeProbabilityPct engine.Probability // default to 100%
				matchedEdges := eb                        // start with all edges as a match
				filteredMatches := eb
				if thisEdgeSearcher.FilterEdges.Comparator != query.CompareInvalid {
					matchedEdges = thisEdgeSearcher.FilterEdges.Bitmap.Intersect(eb)
					if !thisEdgeSearcher.FilterEdges.NoTrimEdges {
						filteredMatches = matchedEdges
					}

					if !query.Comparator[int64](thisEdgeSearcher.FilterEdges.Comparator).Compare(int64(matchedEdges.Count()), thisEdgeSearcher.FilterEdges.Count) {
						return true
					}
				}

				if direction == engine.Out {
					edgeProbabilityPct = matchedEdges.MaxProbability(currentState.node, nextNode)
				} else {
					edgeProbabilityPct = matchedEdges.MaxProbability(nextNode, currentState.node)
				}

				if thisEdgeSearcher.ProbabilityComparator != query.CompareInvalid && !query.Comparator[engine.Probability](thisEdgeSearcher.ProbabilityComparator).Compare(edgeProbabilityPct, thisEdgeSearcher.ProbabilityValue) {
					return true
				}

				if opts.MinEdgeProbability > 0 && edgeProbabilityPct < opts.MinEdgeProbability {
					return true
				}

				nextOverAllProbabilityPct := currentState.overAllProbabilityFraction * float32(edgeProbabilityPct)
				if nextOverAllProbabilityPct < float32(aqlq.OverAllProbability) {
					return true
				}
				nextOverAllProbabilityFraction := nextOverAllProbabilityPct / 100

				if nextDepth >= byte(thisEdgeSearcher.MinIterations) &&
					(nextTargets == nil || nextTargets.Contains(nextNode)) {
					newWorkingGraph := currentState.workingGraph.Clone()

					ec := aqlq.datasource.EdgeBitmapToEdgeCombo(filteredMatches)
					newWorkingGraph.Add(nextNode.ID(), direction, ec, byte(currentState.currentSearchIndex+1))

					if nextSearchIndex <= maxSearchIndex && nextTotalDepth <= byte(opts.MaxDepth) {
						queue.Push(searchState{
							node:                       nextNode,
							currentSearchIndex:         nextSearchIndex,
							workingGraph:               newWorkingGraph,
							currentDepth:               0,
							currentTotalDepth:          nextTotalDepth,
							overAllProbabilityFraction: nextOverAllProbabilityFraction,
						})
					}
				}
				if nextDepth < byte(thisEdgeSearcher.MaxIterations) && nextTotalDepth <= byte(opts.MaxDepth) &&
					(nextEdgeTargets == nil || nextEdgeTargets.Contains(nextNode)) {
					newWorkingGraph := currentState.workingGraph.Clone()

					ec := aqlq.datasource.EdgeBitmapToEdgeCombo(filteredMatches)
					newWorkingGraph.Add(nextNode.ID(), direction, ec, 255)

					queue.Push(searchState{
						node:                       nextNode,
						currentSearchIndex:         currentState.currentSearchIndex,
						workingGraph:               newWorkingGraph,
						currentDepth:               nextDepth,
						currentTotalDepth:          nextTotalDepth,
						overAllProbabilityFraction: nextOverAllProbabilityFraction,
					})
				}
				return true
			})
		}
	}

	ui.Debug().Msgf("Processed %v path permutations, returning graph with %v nodes", processed, committedGraph.Order())

	return committedGraph
}

var (
	directionsIn  = []engine.EdgeDirection{engine.In}
	directionsOut = []engine.EdgeDirection{engine.Out}
	directionsAny = []engine.EdgeDirection{engine.In, engine.Out}
)

var pWPPool sync.Pool

func init() {
	pWPPool.New = func() any {
		return probableWorkingPath{}
	}
}
