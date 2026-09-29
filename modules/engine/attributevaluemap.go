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

// attributeSlot locates one attribute's values in AttributesAndValues.values.
type attributeSlot struct {
	attribute Attribute
	StartLength
}

// AttributesAndValues stores a node's attributes as a slice sorted by
// attribute, pointing into one shared values slice. Nodes have tens of
// attributes, where a binary search over a compact slice beats a map and
// saves a map allocation per node.
type AttributesAndValues struct {
	attributes []attributeSlot
	values     AttributeValues
	mu         sync.Mutex
}

func (avm *AttributesAndValues) init() {}

// find returns the position of a in attributes, or where it would be inserted.
func (avm *AttributesAndValues) find(a Attribute) (int, bool) {
	return slices.BinarySearchFunc(avm.attributes, a, func(slot attributeSlot, a Attribute) int {
		return int(slot.attribute) - int(a)
	})
}

func (avm *AttributesAndValues) Merge(avm2 *AttributesAndValues) *AttributesAndValues {
	avm.mu.Lock()
	defer avm.mu.Unlock()

	avm2.mu.Lock()
	defer avm2.mu.Unlock()

	// Create a new AttributesAndValues to store the merged result.
	var merged AttributesAndValues
	merged.init()

	// pre-allocate backing arrays to avoid repeated reallocations
	longestlen := max(len(avm2.values), len(avm.values))
	merged.values = make(AttributeValues, 0, longestlen)
	merged.attributes = make([]attributeSlot, 0, max(len(avm.attributes), len(avm2.attributes)))

	// Both attribute lists are sorted, so walk them together.
	i, j := 0, 0
	for i < len(avm.attributes) || j < len(avm2.attributes) {
		var attr Attribute
		switch {
		case j == len(avm2.attributes) || (i < len(avm.attributes) && avm.attributes[i].attribute < avm2.attributes[j].attribute):
			attr = avm.attributes[i].attribute
		default:
			attr = avm2.attributes[j].attribute
		}

		var av1 AttributeValues
		if i < len(avm.attributes) && avm.attributes[i].attribute == attr {
			sl := avm.attributes[i].StartLength
			av1 = avm.values[sl.start : sl.start+sl.length]
			i++
		}
		var av2 AttributeValues
		if j < len(avm2.attributes) && avm2.attributes[j].attribute == attr {
			if !attr.HasFlag(DropWhenMerging) {
				sl := avm2.attributes[j].StartLength
				av2 = avm2.values[sl.start : sl.start+sl.length]
			}
			j++
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
		merged.attributes = append(merged.attributes, attributeSlot{attr, StartLength{uint16(start), uint16(len(mergedVals))}})
	}

	return &merged
}

func (avm *AttributesAndValues) Replace(other *AttributesAndValues) {
	avm.mu.Lock()
	avm.attributes = other.attributes
	avm.values = other.values
	avm.mu.Unlock()
}

func (avm *AttributesAndValues) Get(a Attribute) (av AttributeValues, found bool) {
	avm.mu.Lock()
	defer avm.mu.Unlock()
	return avm.get(a)
}

func (avm *AttributesAndValues) get(a Attribute) (av AttributeValues, found bool) {
	i, found := avm.find(a)
	if !found {
		return nil, false
	}
	sl := avm.attributes[i].StartLength
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

// shiftAfter moves the value ranges that start after start down by length,
// after those values were removed from the values slice.
func (avm *AttributesAndValues) shiftAfter(start, length uint16) {
	for k := range avm.attributes {
		if avm.attributes[k].start > start {
			avm.attributes[k].start -= length
		}
	}
}

func (avm *AttributesAndValues) set(a Attribute, av AttributeValues) {
	if sliceOverlap(av, avm.values) {
		panic(fmt.Sprintf("AttributeValues slice %v overlaps with existing values %v", av, avm.values))
	}

	wasnil := len(av) > 0 && av[0].IsNil()
	i, found := avm.find(a)
	if found {
		sl := avm.attributes[i].StartLength
		// If we are last and there is room just add the missing elements
		weAreLast := sl.start+sl.length == uint16(len(avm.values))
		if weAreLast && len(av) > 0 && cap(avm.values)-len(avm.values) >= len(av)-int(sl.length) {
			// extend or shrink the slice in place
			avm.values = avm.values[:len(avm.values)+len(av)-int(sl.length)]
			copy(avm.values[sl.start:], av)
			avm.attributes[i].length = uint16(len(av)) // Update the length
			return
		}

		if int(sl.length) == len(av) {
			// Easy
			copy(avm.values[sl.start:sl.start+sl.length], av)
			return
		}

		// Remove it, and we add it again below
		avm.values = slices.Delete(avm.values, int(sl.start), int(sl.start+sl.length))
		avm.attributes = slices.Delete(avm.attributes, i, i+1)
		if !weAreLast {
			avm.shiftAfter(sl.start, sl.length)
		}
	}

	if len(av) == 0 {
		return
	}

	start := len(avm.values)
	length := len(av)
	if start+length > 0xFFFF || length > 0xFFFF {
		panic("too many attribute values to store in AttributesAndValues")
	}
	avm.attributes = slices.Insert(avm.attributes, i, attributeSlot{a, StartLength{uint16(start), uint16(length)}})
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
	if av[0].IsNil() {
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
	avm.clear(a)
	avm.mu.Unlock()
}

func (avm *AttributesAndValues) clear(a Attribute) {
	i, found := avm.find(a)
	if !found {
		return
	}
	sl := avm.attributes[i].StartLength

	weAreLast := int(sl.start+sl.length) == len(avm.values)
	avm.values = slices.Delete(avm.values, int(sl.start), int(sl.start+sl.length))
	avm.attributes = slices.Delete(avm.attributes, i, i+1)
	if !weAreLast {
		avm.shiftAfter(sl.start, sl.length)
	}
}

// Iterate visits attributes in attribute order.
func (avm *AttributesAndValues) Iterate(f func(attr Attribute, values AttributeValues) bool) {
	for _, slot := range avm.attributes {
		if !f(slot.attribute, avm.values[slot.start:slot.start+slot.length]) {
			return
		}
	}
}
