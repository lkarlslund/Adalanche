package aql

import (
	"strconv"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/graph"
	"github.com/lkarlslund/adalanche/modules/query"
)

type AQLresolver interface {
	Resolve(ResolverOptions) (*graph.Graph[*engine.Node, engine.EdgeBitmap], error)
}

type NodeQuery struct {
	Selector  query.NodeFilter // Where style boolean approval filter for objects
	OrderBy   NodeSorter       // Sorting
	Reference string           // For cross result reference
	Skip      int              // Skipping
	Limit     int              // Limiting
}

func (nq NodeQuery) Populate(ao *engine.IndexedGraph) *engine.IndexedGraph {
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
		result = engine.NewResultGraph(n)
	}
	return result
}

type EdgeMatcher struct {
	Bitmap     engine.EdgeBitmap
	Count      int64 // minimum number of edges to match
	Comparator query.ComparatorType

	NegativeBitmap     engine.EdgeBitmap
	NegativeCount      int64 // minimum number of edges to match
	NegativeComparator query.ComparatorType

	NoTrimEdges bool // don't trim returned edges to just the filter
}
type EdgeSearcher struct {
	// Transit constrains the nodes a route passes through within this step
	// (via, through, avoid; see TransitConstraint).
	Transit []TransitConstraint
	// counters and cstates are Transit resolved against the data source.
	counters []transitCounter
	cstates  int
	// EdgeTagsRequired and EdgeTagsExcluded follow only edge types that
	// carry, or do not carry, these edge tags (edgetag=, !edgetag=).
	EdgeTagsRequired, EdgeTagsExcluded []string
	edgeTags                           *edgeTagFilter
	FilterEdges                        EdgeMatcher // match any of these
	Direction                          engine.EdgeDirection
	MinIterations, MaxIterations       int // there should be between min and max iterations in the chain
	ProbabilityValue                   engine.Probability
	ProbabilityComparator              query.ComparatorType
}
type NodeMatcher interface {
	Match(o *engine.Node) bool
}
type NodeSorter interface {
	Sort(engine.NodeSlice) engine.NodeSlice
}
type NodeSorterImpl struct {
	Attr       engine.Attribute
	Descending bool
}

func (nsi NodeSorterImpl) Sort(o engine.NodeSlice) engine.NodeSlice {
	o.Sort(nsi.Attr, nsi.Descending)
	return o
}

type NodeLimiter interface {
	Limit(engine.NodeSlice) engine.NodeSlice
}

// Union of multiple queries
type AQLqueryUnion struct {
	queries []AQLresolver
}

// aloneResolver resolves without taking the search slot, for a resolver
// that holds it already, such as a union resolving its queries.
type aloneResolver interface {
	resolveAlone(ResolverOptions) (*graph.Graph[*engine.Node, engine.EdgeBitmap], error)
}

// Resolve runs the queries as one search (see Guarded).
func (aqlqu AQLqueryUnion) Resolve(opts ResolverOptions) (*graph.Graph[*engine.Node, engine.EdgeBitmap], error) {
	return guardedResolve(opts, aqlqu.resolveAlone)
}

func (aqlqu AQLqueryUnion) resolveAlone(opts ResolverOptions) (*graph.Graph[*engine.Node, engine.EdgeBitmap], error) {
	var result *graph.Graph[*engine.Node, engine.EdgeBitmap]
	// Nodes are merged once the queries' results are combined, comparing
	// them by the side all the queries agree on.
	merge := opts.MergeNodes
	opts.MergeNodes = MergeOff
	side := engine.Any
	for i, q := range aqlqu.queries {
		var s engine.EdgeDirection = engine.Any
		if aqlq, ok := q.(AQLquery); ok {
			s = aqlq.startSide()
		}
		if i > 0 && s != side {
			s = engine.Any
		}
		side = s
	}
	for _, q := range aqlqu.queries {
		var g *graph.Graph[*engine.Node, engine.EdgeBitmap]
		var err error
		if alone, ok := q.(aloneResolver); ok {
			g, err = alone.resolveAlone(opts)
		} else {
			g, err = q.Resolve(opts)
		}
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
	if err := opts.cancelled(); err != nil {
		return nil, err
	}
	if result != nil {
		result = arrangeNodes(result, merge, side)
	}
	return result, nil
}

type QueryMode int

const (
	Reach QueryMode = iota // Every edge on any route within the query's rules (the only mode)
)

type id struct {
	c     query.ComparatorType
	idval int64
}

func (i *id) Evaluate(o *engine.Node) bool {
	return query.Comparator[int64](i.c).Compare(int64(o.ID()), i.idval)
}
func (i *id) ToLDAPFilter() string {
	return "id" + i.c.String() + strconv.FormatInt(i.idval, 10)
}
func (i *id) ToWhereClause() string {
	return "id" + i.c.String() + strconv.FormatInt(i.idval, 10)
}
