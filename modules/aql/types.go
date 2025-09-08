package aql

import (
	"errors"
	"strconv"
	"sync"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/graph"
	"github.com/lkarlslund/adalanche/modules/query"
	"github.com/lkarlslund/adalanche/modules/ui"
)

type AQLresolver interface {
	Resolve(ResolverOptions) (*graph.Graph[*engine.Object, engine.EdgeBitmap], error)
}

type IndexLookup struct {
	v engine.AttributeValue
	a engine.Attribute
}

type NodeQuery struct {
	IndexLookup IndexLookup      // Possible start of search, quickly narrows it down
	Selector    query.NodeFilter // Where style boolean approval filter for objects
	OrderBy     NodeSorter       // Sorting
	Reference   string           // For cross result reference
	Skip        int              // Skipping
	Limit       int              // Limiting
}

func (nq NodeQuery) Populate(ao *engine.Objects) *engine.Objects {
	result := ao
	if nq.Selector != nil {
		result = query.NodeFilterExecute(nq.Selector, ao)
	}
	if nq.Limit != 0 || nq.Skip != 0 {
		// Get nodes as slice, then sort and filter by limit/skip
		n := result.AsSlice()
		if nq.OrderBy != nil {
			n = nq.OrderBy.Sort(n)
		}
		n.Skip(nq.Skip)
		n.Limit(nq.Limit)
		no := engine.NewObjects()
		n.Iterate(func(o *engine.Object) bool {
			no.Add(o)
			return true
		})
		result = no
	}
	return result
}

type EdgeMatcher struct {
	Bitmap      engine.EdgeBitmap
	Count       int64 // minimum number of edges to match
	Comparator  query.ComparatorType
	NoTrimEdges bool // don't trim edges to just the filter
}
type EdgeSearcher struct {
	PathNodeRequirement          *NodeQuery // Nodes passed along the way must fulfill this filter
	pathNodeRequirementCache     *engine.Objects
	FilterEdges                  EdgeMatcher // match any of these
	Direction                    engine.EdgeDirection
	MinIterations, MaxIterations int // there should be between min and max iterations in the chain
	ProbabilityValue             engine.Probability
	ProbabilityComparator        query.ComparatorType
}
type NodeMatcher interface {
	Match(o *engine.Object) bool
}
type NodeSorter interface {
	Sort(engine.ObjectSlice) engine.ObjectSlice
}
type NodeSorterImpl struct {
	Attr       engine.Attribute
	Descending bool
}

func (nsi NodeSorterImpl) Sort(o engine.ObjectSlice) engine.ObjectSlice {
	o.Sort(nsi.Attr, nsi.Descending)
	return o
}

type NodeLimiter interface {
	Limit(engine.ObjectSlice) engine.ObjectSlice
}

// Union of multiple queries
type AQLqueryUnion struct {
	queries []AQLresolver
}

func (aqlqu AQLqueryUnion) Resolve(opts ResolverOptions) (*graph.Graph[*engine.Object, engine.EdgeBitmap], error) {
	var result *graph.Graph[*engine.Object, engine.EdgeBitmap]
	for _, q := range aqlqu.queries {
		g, err := q.Resolve(opts)
		if err != nil {
			return nil, err
		}
		if g != nil {
			if result == nil {
				result = g
			} else {
				result.Merge(*g)
			}
		}
	}
	// Post process options
	return result, nil
}

type QueryMode int

const (
	Walk    QueryMode = iota // No Homomorphism
	Trail                    // Edge homomorphism (unique edges)
	Acyclic                  // Node homomorphism (unique nodes)
	Simple                   // Partial node-isomorphism
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
		searchResult := graph.NewGraph[*engine.Object, engine.EdgeBitmap]()
		aqlq.resolveEdgesFrom(opts, &searchResult, nil, o, 0, 0, 0, 1)
		resultlock.Lock()
		defer resultlock.Unlock()
		if opts.NodeLimit == 0 || result.Order() <= opts.NodeLimit {
			result.Merge(searchResult)
			return true
		}
		return false
	}, 0)
	return &result, nil
}

var (
	directionsIn  = []engine.EdgeDirection{engine.In}
	directionsOut = []engine.EdgeDirection{engine.Out}
	directionsAny = []engine.EdgeDirection{engine.In, engine.Out}
)

func (aqlq AQLquery) resolveEdgesFrom(
	opts ResolverOptions,
	committedGraph *graph.Graph[*engine.Object, engine.EdgeBitmap],
	workingGraph *graph.Graph[*engine.Object, engine.EdgeBitmap],
	startObject *engine.Object,
	startSearchIndex int,
	_ int, // currentDepth, unused in BFS
	_ int, // currentTotalDepth, unused in BFS
	_ float64, // currentOverAllProbability, unused in BFS
) {
	type searchState struct {
		currentObject             *engine.Object
		workingGraph              *graph.Graph[*engine.Object, engine.EdgeBitmap]
		path                      []*engine.Object
		currentSearchIndex        int
		currentDepth              int
		currentTotalDepth         int
		currentOverAllProbability float64
	}

	queue := []searchState{{
		currentObject:             startObject,
		currentSearchIndex:        startSearchIndex,
		path:                      []*engine.Object{startObject},
		workingGraph:              workingGraph,
		currentDepth:              0,
		currentTotalDepth:         0,
		currentOverAllProbability: 1,
	}}

	foundTargets := make(map[*engine.Object]bool)

	for len(queue) > 0 {
		var state searchState
		if aqlq.Shortest {
			// Pop from front for BFS (standard, shortest results)
			state = queue[0]
			queue = queue[1:]
		} else {
			// Pop from end for DFS
			state = queue[len(queue)-1]
			queue = queue[:len(queue)-1]
		}

		es := aqlq.Next[state.currentSearchIndex]
		targets := aqlq.sourceCache[state.currentSearchIndex+1]

		var directions []engine.EdgeDirection
		switch es.Direction {
		case engine.In:
			directions = directionsIn
		case engine.Out:
			directions = directionsOut
		case engine.Any:
			directions = directionsAny
		}

		// Optionally skip this edge searcher if MinIterations == 0
		if es.MinIterations == 0 && state.currentDepth == 0 {
			if len(aqlq.Next) > state.currentSearchIndex+1 {
				queue = append(queue, searchState{
					currentObject:             state.currentObject,
					currentSearchIndex:        state.currentSearchIndex + 1,
					path:                      state.path,
					workingGraph:              state.workingGraph,
					currentDepth:              0,
					currentTotalDepth:         state.currentTotalDepth + 1,
					currentOverAllProbability: state.currentOverAllProbability,
				})
				continue
			} else {
				committedGraph.Merge(*state.workingGraph)
				continue
			}
		}

		for _, direction := range directions {
			nextDepth := state.currentDepth + 1
			nextTotalDepth := state.currentTotalDepth + 1

			state.currentObject.Edges(direction).Range(func(nextObject *engine.Object, eb engine.EdgeBitmap) bool {
				if opts.NodeLimit > 0 && committedGraph.Order() >= opts.NodeLimit {
					return false
				}
				switch aqlq.Mode {
				case Trail:
					if committedGraph.HasEdge(state.currentObject, nextObject) || (state.workingGraph != nil && state.workingGraph.HasEdge(state.currentObject, nextObject)) {
						return true
					}
				case Acyclic:
					if committedGraph.HasNode(nextObject) || (state.workingGraph != nil && state.workingGraph.HasNode(nextObject)) {
						return true
					}
				case Simple:
					if state.workingGraph != nil && state.workingGraph.HasNode(nextObject) {
						return true
					}
				}

				matchedEdges := es.FilterEdges.Bitmap.Intersect(eb)
				if es.FilterEdges.Comparator != query.CompareInvalid {
					if !query.Comparator[int64](es.FilterEdges.Comparator).Compare(int64(matchedEdges.Count()), es.FilterEdges.Count) {
						return true
					}
				} else {
					if matchedEdges.IsBlank() {
						return true
					}
				}

				if es.pathNodeRequirementCache != nil && !es.pathNodeRequirementCache.Contains(nextObject) {
					return true
				}

				edgeProbability := matchedEdges.MaxProbability(state.currentObject, nextObject)
				if es.ProbabilityComparator != query.CompareInvalid {
					if !query.Comparator[engine.Probability](es.ProbabilityComparator).Compare(edgeProbability, es.ProbabilityValue) {
						return true
					}
				}
				if edgeProbability < opts.MinEdgeProbability {
					return true
				}

				nextOverAllProbability := state.currentOverAllProbability * float64(edgeProbability) / 100
				if nextOverAllProbability*100 < float64(aqlq.OverAllProbability) {
					return true
				}

				addedge := matchedEdges
				if es.FilterEdges.NoTrimEdges {
					addedge = eb
				}

				// Prepare a new working graph for this path, handles nil inteligently
				newWorkingGraph := state.workingGraph.Clone()

				hadCurrentNode := newWorkingGraph.HasNode(state.currentObject)
				hadNextNode := newWorkingGraph.HasNode(nextObject)
				if direction == engine.Out {
					newWorkingGraph.AddEdge(state.currentObject, nextObject, addedge)
				} else {
					newWorkingGraph.AddEdge(nextObject, state.currentObject, addedge)
				}
				if !hadCurrentNode && aqlq.Sources[state.currentSearchIndex].Reference != "" {
					newWorkingGraph.SetNodeData(state.currentObject, "reference", aqlq.Sources[state.currentSearchIndex].Reference)
				}

				if nextDepth >= es.MinIterations && nextDepth <= es.MaxIterations {
					if targets.Contains(nextObject) {
						if state.currentSearchIndex == len(aqlq.Next)-1 {
							if !foundTargets[nextObject] {
								if !hadNextNode && aqlq.Sources[state.currentSearchIndex+1].Reference != "" {
									newWorkingGraph.SetNodeData(nextObject, "reference", aqlq.Sources[state.currentSearchIndex+1].Reference)
								}
								committedGraph.Merge(*newWorkingGraph)
								foundTargets[nextObject] = true
							}
							// if !hadNextNode && aqlq.Sources[state.currentSearchIndex+1].Reference != "" {
							// 	newWorkingGraph.SetNodeData(nextObject, "reference", aqlq.Sources[state.currentSearchIndex+1].Reference)
							// }
							// committedGraph.Merge(*newWorkingGraph)
						} else {
							// Not done yet, so let's enqueue the next search state
							if opts.MaxDepth >= 0 && nextTotalDepth < opts.MaxDepth {
								queue = append(queue, searchState{
									currentObject:             nextObject,
									currentSearchIndex:        state.currentSearchIndex + 1,
									path:                      append(state.path, nextObject),
									workingGraph:              newWorkingGraph,
									currentDepth:              0,
									currentTotalDepth:         nextTotalDepth,
									currentOverAllProbability: nextOverAllProbability,
								})
							}
						}
					}
				}
				if nextDepth < es.MaxIterations {
					queue = append(queue, searchState{
						currentObject:             nextObject,
						currentSearchIndex:        state.currentSearchIndex,
						path:                      append(state.path, nextObject),
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
}

type SkipLimiter int

func (sl SkipLimiter) Limit(o engine.ObjectSlice) engine.ObjectSlice {
	new := o
	new.Skip(int(sl))
	return new
}

type FirstLimiter int

func (fl FirstLimiter) Limit(o engine.ObjectSlice) engine.ObjectSlice {
	new := o
	new.Limit(int(fl))
	return new
}

type id struct {
	c     query.ComparatorType
	idval int64
}

func (i *id) Evaluate(o *engine.Object) bool {
	return query.Comparator[int64](i.c).Compare(int64(o.ID()), i.idval)
}
func (i *id) ToLDAPFilter() string {
	return "id" + i.c.String() + strconv.FormatInt(i.idval, 10)
}
func (i *id) ToWhereClause() string {
	return "id" + i.c.String() + strconv.FormatInt(i.idval, 10)
}
