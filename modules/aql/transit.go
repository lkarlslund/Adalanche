package aql

import (
	"fmt"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/query"
)

// A transit constraint bounds how many of a route's transit nodes (every node
// a route passes through within one edge step, so not that step's start or
// landing node) match a filter. The three spellings all compile to one:
//
//	avoid (F)          via 0 (F)         no transit node matches F
//	via N (F)                            exactly N match F
//	via >=N (F) etc.                     a comparator on the count
//	through (F)        via all (F)       every transit node matches F
//	via all but N (F)                    all but at most N match F
//
// "all" and "all but N" are counts on the complement: through (F) is "zero
// transit nodes match (!F)", so it sets Negate and counts the nodes that do
// NOT match the filter. A count of zero (avoid, through) never grows the
// state space, so it stays a plain per-node gate; a count of one or more adds
// a small bounded counter to the search.
type TransitConstraint struct {
	Filter     NodeQuery            // nodes this counts (or, with Negate, does not count)
	Negate     bool                 // count the nodes that do NOT match Filter (all / all but)
	Comparator query.ComparatorType // how the count is constrained
	Value      int                  // the count it is compared against
}

// transitCounter is a TransitConstraint with its filter resolved to a node
// set and its tracking bounds worked out once, up front.
type transitCounter struct {
	set    *engine.IndexedGraph // nodes matching the constraint's filter
	negate bool                 // count nodes NOT in set

	cmp   query.ComparatorType
	value int

	// A route's count is tracked up to maxTrack. Above it, prune drops the
	// route (<, <=, ==, which can never recover once over) or, when prune is
	// false (>=, >), the count saturates at maxTrack because nothing above it
	// changes the verdict.
	maxTrack int
	prune    bool

	radixMul int // place value of this counter in the packed state integer
}

// countsNode reports whether node contributes one to this counter.
func (c *transitCounter) countsNode(node *engine.Node) bool {
	in := c.set.Contains(node)
	if c.negate {
		return !in
	}
	return in
}

// validEnd reports whether a route whose packed state holds this counter's
// value satisfies the comparator.
func (c *transitCounter) validEnd(count int) bool {
	return query.Comparator[int](c.cmp).Compare(count, c.value)
}

// maxTransitStates caps the packed transit-count state space of one edge step,
// so a query cannot ask the search to track an unreasonable number of counts.
const maxTransitStates = 4096

// buildTransitCounters resolves each constraint's filter against ds and works
// out the packed state space. cstates is 1 when every constraint is a gate
// (count zero), so gate-only steps add no state at all.
func buildTransitCounters(constraints []TransitConstraint, ds *engine.IndexedGraph) (counters []transitCounter, cstates int, err error) {
	cstates = 1
	for _, tc := range constraints {
		c := transitCounter{
			set:    tc.Filter.Populate(ds),
			negate: tc.Negate,
			cmp:    tc.Comparator,
			value:  tc.Value,
		}
		switch tc.Comparator {
		case query.CompareEqual:
			c.maxTrack, c.prune = tc.Value, true
		case query.CompareLessThanEqual:
			c.maxTrack, c.prune = tc.Value, true
		case query.CompareLessThan:
			c.maxTrack, c.prune = tc.Value-1, true
		case query.CompareGreaterThanEqual:
			c.maxTrack, c.prune = tc.Value, false
		case query.CompareGreaterThan:
			c.maxTrack, c.prune = tc.Value+1, false
		default:
			return nil, 0, fmt.Errorf("unsupported comparator in transit count")
		}
		if c.maxTrack < 0 {
			// e.g. "< 0": nothing can satisfy it; track nothing and let
			// validEnd refuse every route.
			c.maxTrack = 0
		}
		c.radixMul = cstates
		cstates *= c.maxTrack + 1
		if cstates > maxTransitStates {
			return nil, 0, fmt.Errorf("transit count constraints need more than %d states; tighten the counts", maxTransitStates)
		}
		counters = append(counters, c)
	}
	return counters, cstates, nil
}

// countMask marks, bit i per counter, whether node contributes to counter i.
// It depends only on the node, so a search can work it out once per node.
func countMask(counters []transitCounter, node *engine.Node) uint64 {
	var mask uint64
	for i := range counters {
		if counters[i].countsNode(node) {
			mask |= 1 << uint(i)
		}
	}
	return mask
}

// combineTransit folds node (via its countMask) into the packed state, giving
// the new state, or -1 when a count passes a bound that can never recover
// (the route is pruned). With no counters it returns 0 and never prunes.
func combineTransit(counters []transitCounter, state int, mask uint64) int {
	if mask == 0 {
		return state
	}
	next := state
	for i := range counters {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		c := &counters[i]
		v := (state / c.radixMul) % (c.maxTrack + 1)
		if v == c.maxTrack {
			if c.prune {
				return -1
			}
			continue // saturated, nothing changes
		}
		next += c.radixMul // one more, within range
	}
	return next
}

// transitValidEnd reports whether a route ending with this packed state meets
// every counter's comparator. With no counters it is always true.
func transitValidEnd(counters []transitCounter, state int) bool {
	for i := range counters {
		c := &counters[i]
		v := (state / c.radixMul) % (c.maxTrack + 1)
		if !c.validEnd(v) {
			return false
		}
	}
	return true
}

// gatePassable reports whether a route may pass through node as far as the
// gates (count-zero constraints) go, independent of any running count. The pair
// search (REACH CHEAPEST/SHORTEST) and flow counting only ever run with gates,
// so this is all they need.
func gatePassable(counters []transitCounter, node *engine.Node) bool {
	for i := range counters {
		c := &counters[i]
		if c.maxTrack == 0 && c.prune && c.countsNode(node) {
			return false
		}
	}
	return true
}

// isGate reports whether a constraint only says which nodes a route may pass
// through (a count of zero), rather than counting along the route.
func (tc TransitConstraint) isGate() bool {
	switch tc.Comparator {
	case query.CompareEqual, query.CompareLessThanEqual:
		return tc.Value == 0
	case query.CompareLessThan:
		return tc.Value == 1
	}
	return false
}

// transitHasCount reports whether any constraint is a real count (not a
// gate), which is what makes REACH CHEAPEST/SHORTEST recombination invalid.
func transitHasCount(constraints []TransitConstraint) bool {
	for _, tc := range constraints {
		if !tc.isGate() {
			return true
		}
	}
	return false
}
