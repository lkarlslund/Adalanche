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
		no := engine.NewIndexedGraph()
		n.Iterate(func(o *engine.Node) bool {
			no.Add(o)
			return true
		})
		result = no
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
	PathNodeRequirement          *NodeQuery // Nodes passed along the way must fulfill this filter
	pathNodeRequirementCache     *engine.IndexedGraph
	FilterEdges                  EdgeMatcher // match any of these
	Direction                    engine.EdgeDirection
	MinIterations, MaxIterations int // there should be between min and max iterations in the chain
	ProbabilityValue             engine.Probability
	ProbabilityComparator        query.ComparatorType
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

func (aqlqu AQLqueryUnion) Resolve(opts ResolverOptions) (*graph.Graph[*engine.Node, engine.EdgeBitmap], error) {
	var result *graph.Graph[*engine.Node, engine.EdgeBitmap]
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
