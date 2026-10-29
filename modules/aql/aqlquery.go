package aql

import (
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
}

// Resolve runs the query as a search: alone, and stopped if memory runs
// short (see Guarded).
func (aqlq AQLquery) Resolve(opts ResolverOptions) (*graph.Graph[*engine.Node, engine.EdgeBitmap], error) {
	return guardedResolve(opts, aqlq.resolveAlone)
}

// resolveAlone is Resolve, for a caller that already holds the search slot.
func (aqlq AQLquery) resolveAlone(opts ResolverOptions) (*graph.Graph[*engine.Node, engine.EdgeBitmap], error) {
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
		counters, cstates, err := buildTransitCounters(q.Transit, aqlq.datasource)
		if err != nil {
			pb.Finish()
			return nil, err
		}
		aqlq.Next[i].counters, aqlq.Next[i].cstates = counters, cstates
		aqlq.Next[i].edgeTags = resolveEdgeTags(q, aqlq.datasource)
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

	return aqlq.resolveReach(opts)
}

var (
	directionsIn  = []engine.EdgeDirection{engine.In}
	directionsOut = []engine.EdgeDirection{engine.Out}
	directionsAny = []engine.EdgeDirection{engine.In, engine.Out}
)

// allows applies an edge searcher's per-edge rules to one step from current
// to next: the edge type filters, the edge tag filters, the edge probability
// filter and the minimum edge probability option. It returns the edges to
// keep in the result and the step's probability.
func (es EdgeSearcher) allows(opts ResolverOptions, current, next *engine.Node, currentIndex, nextIndex engine.NodeIndex, direction engine.EdgeDirection, eb engine.EdgeBitmap) (engine.EdgeBitmap, engine.Probability, bool) {
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
	if es.edgeTags != nil {
		// Tags are kept on the edge as stored, from its source to its target.
		from, to := currentIndex, nextIndex
		if direction != engine.Out {
			from, to = to, from
		}
		matchedEdges = es.edgeTags.keep(from, to, matchedEdges)
		filteredMatches = es.edgeTags.keep(from, to, filteredMatches)
		if matchedEdges.IsBlank() {
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
