package aql

import (
	"errors"
	"runtime"
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
	queue := []searchState{{
		currentObject:             startObject,
		currentSearchIndex:        0,
		workingGraph:              initialWorkingGraph,
		currentDepth:              0,
		currentTotalDepth:         0,
		currentOverAllProbability: 1,
	}}

	for len(queue) > 0 {
		// Check if we've reached the node limit
		if opts.NodeLimit > 0 && committedGraph.Order() >= opts.NodeLimit {
			break
		}

		var currentState searchState
		if aqlq.Shortest {
			// Pop from front for BFS (standard, shortest results)
			currentState = queue[0]
			queue = queue[1:]
		} else {
			// Pop from end for DFS
			currentState = queue[len(queue)-1]
			queue = queue[:len(queue)-1]
		}
		nextDepth := currentState.currentDepth + 1
		nextTotalDepth := currentState.currentTotalDepth + 1

		thisEdgeSearcher := aqlq.Next[currentState.currentSearchIndex]
		nextTargets := aqlq.sourceCache[currentState.currentSearchIndex+1]

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
				queue = append(queue, searchState{
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

				// Next node is not a match
				if nextTargets != nil && !nextTargets.Contains(nextObject) {
					return true
				}

				// Check homomorphism requirements
				switch aqlq.Mode {
				case Trail:
					if committedGraph.HasEdge(currentState.currentObject, nextObject) || currentState.workingGraph.HasEdge(currentState.currentObject, nextObject) {
						return true
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

				edgeProbability := matchedEdges.MaxProbability(currentState.currentObject, nextObject)
				if !query.Comparator[engine.Probability](thisEdgeSearcher.ProbabilityComparator).Compare(edgeProbability, thisEdgeSearcher.ProbabilityValue) {
					return true
				}

				if edgeProbability < opts.MinEdgeProbability {
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
					// queue next search index
					if currentState.currentSearchIndex < len(aqlq.Next)-1 {
						queue = append(queue, searchState{
							currentObject:             nextObject,
							currentSearchIndex:        currentState.currentSearchIndex + 1,
							workingGraph:              newWorkingGraph,
							currentDepth:              0,
							currentTotalDepth:         nextTotalDepth,
							currentOverAllProbability: nextOverAllProbability,
						})
					}

					if currentState.currentSearchIndex == len(aqlq.Next)-1 {
						// We've reached the end of the current search index, so let's merge the working graph into the committed graph - it's a complete match
						committedGraph.Merge(newWorkingGraph)
						committedGraph.SetNodeData(nextObject, "reference", aqlq.Sources[currentState.currentSearchIndex+1].Reference)
					}

					// check overall node limit
					if opts.NodeLimit > 0 && committedGraph.Order() >= opts.NodeLimit {
						return false
					}
				}

				if nextDepth < thisEdgeSearcher.MaxIterations {
					queue = append(queue, searchState{
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
