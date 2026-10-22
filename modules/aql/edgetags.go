package aql

import (
	"sync/atomic"

	"github.com/lkarlslund/adalanche/modules/engine"
)

// Following edges by their tags (edgetag=, !edgetag=) is part of the edge
// tags an extension provides; queries using it are refused until it calls
// EnableEdgeTags.
var edgeTagsEnabled atomic.Bool

// EnableEdgeTags lets queries filter edges by their tags.
func EnableEdgeTags() { edgeTagsEnabled.Store(true) }

// edgeTagFilter is an edge step's edgetag= and !edgetag= resolved against
// the graph: only edge types carrying every required tag, and none of the
// excluded ones, are followed. A tag on the pair is on all its edge types.
type edgeTagFilter struct {
	graph    *engine.IndexedGraph
	required []engine.EdgeTagID
	excluded []engine.EdgeTagID
	never    bool // a required tag is on no edge in the graph
}

// resolveEdgeTags returns the filter for a step, or nil when it has none.
func resolveEdgeTags(es EdgeSearcher, g *engine.IndexedGraph) *edgeTagFilter {
	if len(es.EdgeTagsRequired) == 0 && len(es.EdgeTagsExcluded) == 0 {
		return nil
	}
	f := &edgeTagFilter{graph: g}
	for _, name := range es.EdgeTagsRequired {
		if id, found := g.LookupEdgeTag(name); found {
			f.required = append(f.required, id)
		} else {
			f.never = true
		}
	}
	for _, name := range es.EdgeTagsExcluded {
		if id, found := g.LookupEdgeTag(name); found {
			f.excluded = append(f.excluded, id)
		}
	}
	return f
}

// keep narrows eb, edge types from one node to another, to those the filter
// lets a route follow.
func (f *edgeTagFilter) keep(from, to engine.NodeIndex, eb engine.EdgeBitmap) engine.EdgeBitmap {
	if f == nil || eb.IsBlank() {
		return eb
	}
	if f.never {
		return engine.EdgeBitmap{}
	}
	for _, id := range f.required {
		eb = f.graph.EdgeTypesTagged(from, to, id, eb)
	}
	for _, id := range f.excluded {
		eb = eb.Intersect(f.graph.EdgeTypesTagged(from, to, id, eb).Invert())
	}
	return eb
}
