package query

import (
	"sort"

	"github.com/lkarlslund/adalanche/modules/engine"
)

type IndexSelectorInfo struct {
	match      string
	results    engine.NodeSlice
	a          engine.Attribute
	queryIndex int
}

// Semi optimized way of executing a node filter
func NodeFilterExecute(q NodeFilter, ao *engine.IndexedGraph) *engine.IndexedGraph {
	var potentialindexes []IndexSelectorInfo
	switch t := q.(type) {
	case AndQuery:
		// Iterate over all subitems
		for _, st := range t.Subitems {
			if qo, ok := st.(FilterOneAttribute); ok {
				if sm, ok := qo.FilterAttribute.(HasStringMatch); ok {
					// This might be in an index
					potentialindexes = append(potentialindexes, IndexSelectorInfo{
						a:     qo.Attribute,
						match: sm.Value.String(),
					})
				}
			}
		}
	case FilterOneAttribute:
		qo := t
		if sm, ok := qo.FilterAttribute.(HasStringMatch); ok {
			// This might be in an index
			potentialindexes = append(potentialindexes, IndexSelectorInfo{
				a:          qo.Attribute,
				match:      sm.Value.String(),
				queryIndex: -1,
			})
		}
	}

	// No optimization possible
	if len(potentialindexes) == 0 {
		return ao.Filter(q.Evaluate)
	}

	for i, potentialIndex := range potentialindexes {
		index := ao.GetIndex(potentialIndex.a)
		foundObjects, found := index.Lookup(engine.NV(potentialIndex.match))
		if found {
			potentialindexes[i].results = foundObjects
		}
	}

	sort.Slice(potentialindexes, func(i, j int) bool {
		return potentialindexes[i].results.Len() < potentialindexes[j].results.Len()
	})

	for _, foundindex := range potentialindexes {
		if foundindex.results.Len() != 0 {
			filteredobjects := engine.NewIndexedGraph()

			// best working index is first
			if foundindex.queryIndex == -1 {
				// not an AND query with subitems

				foundindex.results.Iterate(func(o *engine.Node) bool {
					filteredobjects.Add(o)
					return true
				})
			} else {
				// can be optimized by patching out the index matched query filter (remove queryIndex item from filter)
				foundindex.results.Iterate(func(o *engine.Node) bool {
					if q.Evaluate(o) {
						filteredobjects.Add(o)
					}
					return true
				})
			}

			return filteredobjects
		}
	}

	// Return unoptimized filter
	return ao.Filter(q.Evaluate)
}
