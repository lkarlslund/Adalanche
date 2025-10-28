package engine

import (
	"fmt"
	"slices"
	"sync"
	"unsafe"
)

type StartLength struct {
	start  uint16
	length uint16
}

type AttributesAndValues struct {
	attributes map[Attribute]StartLength
	values     AttributeValues
	mu         sync.Mutex
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

	// pre-allocate backing array for values to avoid repeated reallocations
	longestlen := max(len(avm2.values), len(avm.values))
	merged.values = make(AttributeValues, 0, longestlen)

	// Collect keys directly from both maps (avoids extra Iterate/map lookups).
	attributes := make([]Attribute, 0, len(avm.attributes)+len(avm2.attributes))
	for attr := range avm.attributes {
		attributes = append(attributes, attr)
	}
	for attr := range avm2.attributes {
		attributes = append(attributes, attr)
	}

	// For each attribute, grab the slices directly and append merged values once.
	slices.Sort(attributes)
	var lastAttribute Attribute
	for _, attr := range attributes {
		if attr == lastAttribute {
			// already processed this attribute (duplicate in combined list)
			continue
		}
		lastAttribute = attr

		var av1 AttributeValues
		if sl, found := avm.attributes[attr]; found {
			av1 = avm.values[sl.start : sl.start+sl.length]
		}
		var av2 AttributeValues
		if !attr.HasFlag(DropWhenMerging) {
			if sl, found := avm2.attributes[attr]; found {
				av2 = avm2.values[sl.start : sl.start+sl.length]
			}
		}
		mergedVals := mergeValues(av1, av2)
		if len(mergedVals) == 0 {
			// nothing to store for this attribute
			continue
		}
		start := len(merged.values)
		merged.values = append(merged.values, mergedVals...)
		if start > 0xFFFF || len(mergedVals) > 0xFFFF {
			panic("too many attribute values to store in merged AttributesAndValues")
		}
		merged.attributes[attr] = StartLength{uint16(start), uint16(len(mergedVals))}
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

func sliceOverlap(s1, s2 AttributeValues) bool {
	cap1 := cap(s1)
	cap2 := cap(s2)

	// nil slices will never have the same array.
	if cap1 == 0 || cap2 == 0 {
		return false
	}

	// Get pointer to the first element of each backing array safely by
	// slicing to the full capacity so indexing is valid.
	base1 := unsafe.Pointer(&s1[:cap1][0])
	base2 := unsafe.Pointer(&s2[:cap2][0])

	// size of each element (may be 0 for zero-sized types)
	elemSize := unsafe.Sizeof(s1[:cap1][0])
	if elemSize == 0 {
		// For zero-sized elements, overlapping is meaningful only if they point to same backing address.
		return base1 == base2
	}

	start1 := uintptr(base1)
	end1 := start1 + uintptr(cap1)*elemSize - 1
	start2 := uintptr(base2)
	end2 := start2 + uintptr(cap2)*elemSize - 1

	// ranges overlap if they are not disjoint
	return !(end1 < start2 || end2 < start1)
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
		weAreLast := sl.start+sl.length == uint16(len(avm.values))
		if weAreLast && cap(avm.values)-len(avm.values) >= len(av)-int(sl.length) {
			// extend the slice
			avm.values = avm.values[:len(avm.values)+len(av)-int(sl.length)]
			copy(avm.values[sl.start:], av)
			avm.attributes[a] = StartLength{sl.start, uint16(len(av))} // Update the length
			return
		}

		if int(sl.length) == len(av) {
			// Easy
			copy(avm.values[sl.start:sl.start+sl.length], av)
			return
		} else {
			// Remove it, and we add it again below
			avm.values = slices.Delete(avm.values, int(sl.start), int(sl.start+sl.length))
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
	avm.attributes[a] = StartLength{uint16(start), uint16(length)}
	if len(avm.values)+length > cap(avm.values) {
		newCap := len(avm.values) + len(av)
		if newCap < 8 {
			newCap = 8
		} else if newCap < cap(avm.values)*100/80 { // grow by 25%
			newCap = cap(avm.values) * 100 / 80
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
		weAreLast := int(sl.start+sl.length) == len(avm.values)
		avm.values = slices.Delete(avm.values, int(sl.start), int(sl.start+sl.length))
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
