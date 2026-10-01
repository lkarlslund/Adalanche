package aql

import (
	"cmp"
	"errors"
	"runtime"
	"slices"
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

	// Start nodes are searched in parallel but merged in canonical order, so
	// the result, including where a node limit cuts it off, is the same on
	// every run.
	adjacency := aqlq.datasource.RankedAdjacency()
	ranks := adjacency.Ranks
	var starts []*engine.Node
	aqlq.sourceCache[0].Iterate(func(o *engine.Node) bool {
		starts = append(starts, o)
		return true
	})
	rankOf := func(o *engine.Node) uint32 {
		if i, found := aqlq.datasource.NodeIndexOf(o); found {
			return ranks[i]
		}
		return ^uint32(0)
	}
	slices.SortStableFunc(starts, func(a, b *engine.Node) int {
		return cmp.Compare(rankOf(a), rankOf(b))
	})

	type startResult struct {
		position int
		result   graph.Graph[*engine.Node, engine.EdgeBitmap]
	}
	jobs := make(chan int)
	results := make(chan startResult)
	workers := runtime.NumCPU()
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for position := range jobs {
				results <- startResult{position, aqlq.resolveEdgesFrom(opts, starts[position], adjacency)}
			}
		}()
	}
	go func() {
		for position := range starts {
			jobs <- position
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	pb = ui.ProgressBar("Searching from start nodes", int64(len(starts)))
	pending := make(map[int]graph.Graph[*engine.Node, engine.EdgeBitmap])
	next := 0
	for r := range results {
		pb.Add(1)
		pending[r.position] = r.result
		for {
			searchResult, ready := pending[next]
			if !ready {
				break
			}
			delete(pending, next)
			next++
			if opts.NodeLimit == 0 || result.Order() <= opts.NodeLimit {
				result.Merge(searchResult)
			}
		}
	}
	pb.Finish()
	return &result, nil
}

func (aqlq AQLquery) resolveEdgesFrom(
	opts ResolverOptions,
	startObject *engine.Node,
	adjacency *engine.RankedAdjacency,
) graph.Graph[*engine.Node, engine.EdgeBitmap] {
	ranks := adjacency.Ranks
	committedGraph := graph.NewGraph[*engine.Node, engine.EdgeBitmap]()
	maxSearchIndex := byte(len(aqlq.Next))

	var paths pathArena
	if aqlq.Mode == Trail {
		paths.committedEdges = make(map[[2]engine.NodeIndex]struct{})
	}
	startIndex, found := aqlq.datasource.NodeIndexOf(startObject)
	if !found {
		return committedGraph
	}

	queue := PriorityQueue{
		p: aqlq.Traversal,
	}
	queue.Push(searchState{
		nodeIndex:                  startIndex,
		rank:                       ranks[startIndex],
		path:                       paths.add(-1, pathItem{target: startIndex, direction: engine.Any}),
		filter:                     pathFilter(0).with(startIndex),
		currentSearchIndex:         0,
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

		processed++

		currentState = queue.Pop()
		currentNode := aqlq.datasource.NodeAt(currentState.nodeIndex)

		// completed path in queue
		if currentState.currentSearchIndex == maxSearchIndex {
			// do deduplication checks here if needed
			paths.commit(currentState.path, aqlq.datasource, committedGraph)
			continue
		}

		nextDepth := currentState.currentDepth + 1
		nextTotalDepth := currentState.currentTotalDepth + 1
		nextSearchIndex := currentState.currentSearchIndex + 1

		thisEdgeSearcher := aqlq.Next[currentState.currentSearchIndex]
		nextTargets := aqlq.sourceCache[currentState.currentSearchIndex+1]

		nextEdgeTargets := thisEdgeSearcher.pathNodeRequirementCache

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
				nodeIndex:                  currentState.nodeIndex,
				rank:                       currentState.rank,
				path:                       currentState.path,
				filter:                     currentState.filter,
				currentSearchIndex:         currentState.currentSearchIndex + 1,
				currentDepth:               0,
				currentTotalDepth:          currentState.currentTotalDepth,
				overAllProbabilityFraction: currentState.overAllProbabilityFraction,
			})
		}

		visit := func(direction engine.EdgeDirection, nextIndex engine.NodeIndex, nextNode *engine.Node, eb engine.EdgeBitmap) bool {

			if opts.NodeLimit > 0 && committedGraph.Order() >= opts.NodeLimit {
				return false
			}

			switch aqlq.Mode {
			case Walk:
				// no-op
			case Trail:
				// No edge twice in a path, nor an edge already in the result.
				from, to := currentState.nodeIndex, nextIndex
				if direction != engine.Out {
					from, to = to, from
				}
				if paths.hasEdge(currentState.path, currentState.filter, from, to) || paths.hasCommittedEdge(from, to) {
					return true
				}
			case Acyclic:
				// No node twice in a path, nor a node already in the result.
				if paths.hasNode(currentState.path, currentState.filter, nextIndex) || committedGraph.HasNode(nextNode) {
					return true
				}
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
				edgeProbabilityPct = matchedEdges.MaxProbability(currentNode, nextNode)
			} else {
				edgeProbabilityPct = matchedEdges.MaxProbability(nextNode, currentNode)
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
				if nextSearchIndex <= maxSearchIndex && nextTotalDepth <= byte(opts.MaxDepth) {
					ec := aqlq.datasource.EdgeBitmapToEdgeCombo(filteredMatches)
					queue.Push(searchState{
						nodeIndex:                  nextIndex,
						rank:                       ranks[nextIndex],
						path:                       paths.add(currentState.path, pathItem{target: nextIndex, combo: ec, direction: direction, reference: byte(currentState.currentSearchIndex + 1)}),
						filter:                     currentState.filter.with(nextIndex),
						currentSearchIndex:         nextSearchIndex,
						currentDepth:               0,
						currentTotalDepth:          nextTotalDepth,
						overAllProbabilityFraction: nextOverAllProbabilityFraction,
					})
				}
			}
			if nextDepth < byte(thisEdgeSearcher.MaxIterations) && nextTotalDepth <= byte(opts.MaxDepth) &&
				(nextEdgeTargets == nil || nextEdgeTargets.Contains(nextNode)) {
				ec := aqlq.datasource.EdgeBitmapToEdgeCombo(filteredMatches)
				queue.Push(searchState{
					nodeIndex:                  nextIndex,
					rank:                       ranks[nextIndex],
					path:                       paths.add(currentState.path, pathItem{target: nextIndex, combo: ec, direction: direction, reference: 255}),
					filter:                     currentState.filter.with(nextIndex),
					currentSearchIndex:         currentState.currentSearchIndex,
					currentDepth:               nextDepth,
					currentTotalDepth:          nextTotalDepth,
					overAllProbabilityFraction: nextOverAllProbabilityFraction,
				})
			}
			return true
		}

		for _, direction := range directions {
			// Edges are stored in maps; visit neighbours in canonical order so
			// which paths are found first does not change between runs.
			for _, e := range adjacency.Neighbors[direction][currentState.nodeIndex] {
				if !visit(direction, e.Target, aqlq.datasource.NodeAt(e.Target), aqlq.datasource.EdgeComboToEdgeBitmap(e.Combo)) {
					break
				}
			}
		}
	}

	paths.flush(aqlq.datasource, committedGraph, aqlq.Sources)
	ui.Debug().Msgf("Processed %v path permutations, returning graph with %v nodes", processed, committedGraph.Order())

	return committedGraph
}

var (
	directionsIn  = []engine.EdgeDirection{engine.In}
	directionsOut = []engine.EdgeDirection{engine.Out}
	directionsAny = []engine.EdgeDirection{engine.In, engine.Out}
)
