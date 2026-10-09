package aql

import (
	"cmp"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"

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
	Routes             ReachRoutes // which routes REACH keeps
	Traversal          Priority
	OverAllProbability engine.Probability
}

func (aqlq AQLquery) Resolve(opts ResolverOptions) (*graph.Graph[*engine.Node, engine.EdgeBitmap], error) {
	result, err := aqlq.resolve(opts)
	if err != nil || result == nil {
		return result, err
	}
	if err := opts.cancelled(); err != nil {
		return nil, err
	}
	// resolve filled in the start nodes.
	setHops(result, aqlq.sourceCache[0].Contains, aqlq.startSide())
	return arrangeNodes(result, opts.MergeNodes, aqlq.startSide()), nil
}

// arrangeNodes folds and merges nodes as the merge mode says.
func arrangeNodes(result *graph.Graph[*engine.Node, engine.EdgeBitmap], mode MergeMode, startSide engine.EdgeDirection) *graph.Graph[*engine.Node, engine.EdgeBitmap] {
	if mode == MergeRoutes {
		result = FoldMachineLocal(result)
	}
	if mode.enabled() {
		result = MergeNodes(result, mergeSide(mode, startSide))
	}
	return result
}

func (aqlq *AQLquery) resolve(opts ResolverOptions) (*graph.Graph[*engine.Node, engine.EdgeBitmap], error) {
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
		if err := opts.cancelled(); err != nil {
			pb.Finish()
			return nil, err
		}
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

	if aqlq.Mode == Reach {
		return aqlq.resolveReach(opts)
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
		limited  bool // the search stopped at the node limit
	}
	jobs := make(chan int)
	results := make(chan startResult)
	workers := runtime.NumCPU()
	// Once the merged result is full, start nodes still waiting are not
	// searched.
	var full atomic.Bool
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			routes := engine.NewRouteChecker(aqlq.datasource)
			for position := range jobs {
				if full.Load() || opts.cancelled() != nil {
					results <- startResult{position: position}
					continue
				}
				g, limited := aqlq.resolveEdgesFrom(opts, starts[position], adjacency, routes)
				results <- startResult{position, g, limited}
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
	pending := make(map[int]startResult)
	next, searched := 0, 0
	limited := false
	for r := range results {
		pb.Add(1)
		pending[r.position] = r
		for {
			searchResult, ready := pending[next]
			if !ready {
				break
			}
			delete(pending, next)
			next++
			if opts.NodeLimit > 0 && result.Order() >= opts.NodeLimit {
				limited = true
				continue
			}
			result.Merge(searchResult.result)
			searched++
			limited = limited || searchResult.limited
			if opts.NodeLimit > 0 && result.Order() >= opts.NodeLimit {
				full.Store(true)
			}
		}
	}
	pb.Finish()
	if err := opts.cancelled(); err != nil {
		return nil, err
	}
	if limited {
		result.Limited(fmt.Sprintf("Node limit of %v reached after searching %v of %v start nodes", opts.NodeLimit, searched, len(starts)))
	}
	return &result, nil
}

func (aqlq AQLquery) resolveEdgesFrom(
	opts ResolverOptions,
	startObject *engine.Node,
	adjacency *engine.RankedAdjacency,
	routes *engine.RouteChecker,
) (graph.Graph[*engine.Node, engine.EdgeBitmap], bool) {
	ranks := adjacency.Ranks
	committedGraph := graph.NewGraph[*engine.Node, engine.EdgeBitmap]()
	maxSearchIndex := byte(len(aqlq.Next))

	var paths pathArena
	if aqlq.Mode == Trail {
		paths.committedEdges = make(map[[2]engine.NodeIndex]struct{})
	}
	startIndex, found := aqlq.datasource.NodeIndexOf(startObject)
	if !found {
		return committedGraph, false
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
	limited := false
	for queue.Len() > 0 {
		if opts.NodeLimit > 0 && committedGraph.Order() >= opts.NodeLimit {
			limited = true
			break
		}

		processed++
		if processed%1024 == 0 && opts.cancelled() != nil {
			break
		}

		currentState = queue.Pop()
		currentNode := aqlq.datasource.NodeAt(currentState.nodeIndex)

		// completed path in queue
		if currentState.currentSearchIndex == maxSearchIndex {
			if paths.refused(currentState.path, aqlq.datasource, routes) {
				continue
			}
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
				limited = true
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

			filteredMatches, edgeProbabilityPct, ok := thisEdgeSearcher.allows(opts, currentNode, nextNode, direction, eb)
			if !ok {
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

	return committedGraph, limited
}

var (
	directionsIn  = []engine.EdgeDirection{engine.In}
	directionsOut = []engine.EdgeDirection{engine.Out}
	directionsAny = []engine.EdgeDirection{engine.In, engine.Out}
)

// allows applies an edge searcher's per-edge rules to one step from current
// to next: the edge type filters, the edge probability filter and the
// minimum edge probability option. It returns the edges to keep in the
// result and the step's probability.
func (es EdgeSearcher) allows(opts ResolverOptions, current, next *engine.Node, direction engine.EdgeDirection, eb engine.EdgeBitmap) (engine.EdgeBitmap, engine.Probability, bool) {
	if es.FilterEdges.NegativeComparator != query.CompareInvalid {
		matchedEdges := es.FilterEdges.NegativeBitmap.Intersect(eb)
		if query.Comparator[int64](es.FilterEdges.NegativeComparator).Compare(int64(matchedEdges.Count()), es.FilterEdges.NegativeCount) {
			return eb, 0, false
		}
	}

	matchedEdges := eb // start with all edges as a match
	filteredMatches := eb
	if es.FilterEdges.Comparator != query.CompareInvalid {
		matchedEdges = es.FilterEdges.Bitmap.Intersect(eb)
		if !es.FilterEdges.NoTrimEdges {
			filteredMatches = matchedEdges
		}
		if !query.Comparator[int64](es.FilterEdges.Comparator).Compare(int64(matchedEdges.Count()), es.FilterEdges.Count) {
			return eb, 0, false
		}
	}

	var probability engine.Probability
	if direction == engine.Out {
		probability = matchedEdges.MaxProbability(current, next)
	} else {
		probability = matchedEdges.MaxProbability(next, current)
	}
	if es.ProbabilityComparator != query.CompareInvalid && !query.Comparator[engine.Probability](es.ProbabilityComparator).Compare(probability, es.ProbabilityValue) {
		return eb, 0, false
	}
	if opts.MinEdgeProbability > 0 && probability < opts.MinEdgeProbability {
		return eb, 0, false
	}
	return filteredMatches, probability, true
}
