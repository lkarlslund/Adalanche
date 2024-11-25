package engine

import (
	"fmt"
	"slices"
	"sync"
)

type StartLength struct {
	start  int
	length int
}

type AttributesAndValues struct {
	mu         sync.Mutex
	attributes map[Attribute]StartLength
	values     AttributeValues
}

func (avm *AttributesAndValues) init() {
	avm.attributes = make(map[Attribute]StartLength)
}

func (avm *AttributesAndValues) Merge(avm2 *AttributesAndValues) *AttributesAndValues {
	avm.mu.Lock()
	defer avm.mu.Unlock()

	avm2.mu.Lock()
	defer avm2.mu.Unlock()

	// Create a new AttributesAndValues to store the merged result.
	var merged AttributesAndValues
	merged.init()
	// Assume no collisions, so help by not reallocating the slice over and over
	merged.values = make(AttributeValues, 0, len(avm.values)+len(avm2.values))

	attributes := make([]Attribute, 0, len(avm.attributes)+len(avm2.attributes))
	avm.Iterate(func(attr Attribute, values AttributeValues) bool {
		attributes = append(attributes, attr)
		return true
	})
	avm2.Iterate(func(attr Attribute, values AttributeValues) bool {
		attributes = append(attributes, attr)
		return true
	})
	slices.Sort(attributes)
	attributes = slices.Compact(attributes)

	for _, attr := range attributes {
		avm1values, _ := avm.get(attr)
		avm2values, _ := avm2.get(attr)
		merged.set(attr, MergeValues(avm1values, avm2values))
	}

	return &merged
}

func (avm *AttributesAndValues) Get(a Attribute) (av AttributeValues, found bool) {
	avm.mu.Lock()
	defer avm.mu.Unlock()
	return avm.get(a)
}

func (avm *AttributesAndValues) get(a Attribute) (av AttributeValues, found bool) {
	sl, found := avm.attributes[a]
	if !found {
		return nil, false
	}
	return avm.values[sl.start : sl.start+sl.length], true
}

func sliceOverlap[T any](s1, s2 []T) bool {
	cap1 := cap(s1)
	cap2 := cap(s2)

	// nil slices will never have the same array.
	if cap1 == 0 || cap2 == 0 {
		return false
	}

	// compare the address of the last element in each backing array.
	return &s1[0:cap1][cap1-1] == &s2[0:cap2][cap2-1]
}

func (avm *AttributesAndValues) Set(a Attribute, av AttributeValues) {
	avm.mu.Lock()
	avm.set(a, av)
	avm.mu.Unlock()
}

func (avm *AttributesAndValues) set(a Attribute, av AttributeValues) {
	if sliceOverlap(av, avm.values) {
		panic(fmt.Sprintf("AttributeValues slice %v overlaps with existing values %v", av, avm.values))
	}

	wasnil := len(av) > 0 && av[0] == nil
	sl, found := avm.attributes[a]
	if found {
		// If we are last and there is room just add the missing elements
		weAreLast := sl.start+sl.length == len(avm.values)
		if weAreLast && cap(avm.values)-len(avm.values) >= len(av)-sl.length {
			// extend the slice
			avm.values = avm.values[:len(avm.values)+len(av)-sl.length]
			copy(avm.values[sl.start:], av)
			avm.attributes[a] = StartLength{sl.start, len(av)} // Update the length
			return
		}

		if sl.length == len(av) {
			// Easy
			copy(avm.values[sl.start:sl.start+sl.length], av)
			return
		} else {
			// Remove it, and we add it again below
			avm.values = slices.Delete(avm.values, sl.start, sl.start+sl.length)
			if !weAreLast {
				// Adjust start positions of all attributes that come after the deleted one
				for k, v := range avm.attributes {
					if v.start >= sl.start {
						avm.attributes[k] = StartLength{v.start - sl.length, v.length}
					}
				}
			}
		}
	}

	if len(av) == 0 {
		return
	}
	// Find where to insert it. We want to keep the values sorted by attribute name.

	start := len(avm.values)
	length := len(av)
	avm.attributes[a] = StartLength{start, length}
	if len(avm.values)+length > cap(avm.values) {
		newCap := len(avm.values) + len(av)
		if newCap < 8 {
			newCap = 8
		} else if newCap < 2*cap(avm.values) {
			newCap = 2 * cap(avm.values)
		}
		newValues := make(AttributeValues, len(avm.values), newCap)
		copy(newValues, avm.values)
		avm.values = newValues
	}
	if av[0] == nil {
		panic(fmt.Sprintf("nil attribute value (was %v)", wasnil))
	}
	avm.values = append(avm.values, av...)
}

func (avm *AttributesAndValues) Len() int {
	avm.mu.Lock()
	defer avm.mu.Unlock()
	return len(avm.attributes)
}

func (avm *AttributesAndValues) Clear(a Attribute) {
	avm.mu.Lock()
	defer avm.mu.Unlock()
	sl, found := avm.attributes[a]
	if found {
		// Remove it, and we add it again below
		weAreLast := sl.start+sl.length == len(avm.values)
		avm.values = slices.Delete(avm.values, sl.start, sl.start+sl.length)
		if !weAreLast {
			for k, v := range avm.attributes {
				if v.start > sl.start {
					avm.attributes[k] = StartLength{v.start - sl.length, v.length}
				}
			}
		}
		delete(avm.attributes, a)
	}
}

func (avm *AttributesAndValues) Iterate(f func(attr Attribute, values AttributeValues) bool) {
	for attr, sl := range avm.attributes {
		if !f(attr, avm.values[sl.start:sl.start+sl.length]) {
			return
		}
	}
}
