package query

import (
	"sort"

	"github.com/lkarlslund/adalanche/modules/engine"
)

type IndexSelectorInfo struct {
	a          engine.Attribute
	match      string
	results    []*engine.Object
	queryIndex int
}

func Execute(q Query, ao *engine.Objects) *engine.Objects {
	var potentialindexes []IndexSelectorInfo
	switch t := q.(type) {
	case andquery:
		// Iterate over all subitems
		for _, st := range t.subitems {
			if qo, ok := st.(QueryOneAttribute); ok {
				if sm, ok := qo.q.(hasStringMatch); ok {
					// This might be in an index
					potentialindexes = append(potentialindexes, IndexSelectorInfo{
						a:     qo.a,
						match: sm.m,
					})
				}
			}
		}
	case QueryOneAttribute:
		qo := t
		if sm, ok := qo.q.(hasStringMatch); ok {
			// This might be in an index
			potentialindexes = append(potentialindexes, IndexSelectorInfo{
				a:          qo.a,
				match:      sm.m,
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
		foundObjects, found := index.Lookup(engine.AttributeValueToIndex(engine.AttributeValueString(potentialIndex.match)))
		if found {
			potentialindexes[i].results = foundObjects
		}
	}

	sort.Slice(potentialindexes, func(i, j int) bool {
		return len(potentialindexes[i].results) < len(potentialindexes[j].results)
	})

	for _, foundindex := range potentialindexes {
		if len(foundindex.results) != 0 {
			filteredobjects := engine.NewObjects()

			// best working index is first
			if foundindex.queryIndex == -1 {
				// not an AND query with subitems
				for _, o := range foundindex.results {
					filteredobjects.Add(o)
				}
			} else {
				// can be optimized by patching out the index matched query filter (remove queryIndex item from filter)
				for _, o := range foundindex.results {
					if q.Evaluate(o) {
						filteredobjects.Add(o)
					}
				}
			}

			return filteredobjects
		}
	}

	// Return unoptimized filter
	return ao.Filter(q.Evaluate)
}
