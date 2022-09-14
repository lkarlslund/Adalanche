package engine

type AttributeValueMap struct {
	m map[Attribute]AttributeValues
	// firstattribute Attribute
	// data           []AttributeValues
}

func (avm AttributeValueMap) Get(a Attribute) (av AttributeValues, found bool) {
	if avm.m == nil {
		return nil, false
	}
	av, found = avm.m[a]
	return
	// if a < avm.firstattribute || int(a-avm.firstattribute) >= len(avm.data) {
	// 	return nil, false
	// }
	// result := avm.data[a-avm.firstattribute]
	// return result, result != nil
}

func (avm *AttributeValueMap) Set(a Attribute, av AttributeValues) {
	if avm.m == nil {
		avm.m = make(map[Attribute]AttributeValues)
	}
	avm.m[a] = av
	// if len(avm.data) == 0 {
	// 	avm.firstattribute = a
	// 	avm.data = make([]AttributeValues, 1)
	// 	avm.data[0] = av
	// } else if a < avm.firstattribute {
	// 	shift := int(avm.firstattribute - a)
	// 	newdata := make([]AttributeValues, len(avm.data)+shift, len(avm.data)+shift)
	// 	copy(newdata[shift:], avm.data)
	// 	avm.data = newdata
	// 	avm.firstattribute = a
	// } else if int(a-avm.firstattribute) >= len(avm.data) {
	// 	add := int(a-avm.firstattribute) - len(avm.data) + 1
	// 	newdata := make([]AttributeValues, len(avm.data)+add, len(avm.data)+add)
	// 	copy(newdata, avm.data)
	// 	avm.data = newdata
	// }
	// avm.data[a-avm.firstattribute] = av
}

func (avm AttributeValueMap) Len() int {
	return len(avm.m)
	// var count int
	// for _, v := range avm.data {
	// 	if v != nil {
	// 		count++
	// 	}
	// }
	// return count
}

func (avm *AttributeValueMap) Clear(a Attribute) {
	if avm.m != nil {
		delete(avm.m, a)
	}
	// avm.data[a-avm.firstattribute] = nil
}

func (avm AttributeValueMap) Iterate(f func(attr Attribute, values AttributeValues) bool) {
	for attr, values := range avm.m {
		if !f(attr, values) {
			break
		}
	}
	// for i, values := range avm.data {
	// 	if values != nil {
	// 		if !f(avm.firstattribute+Attribute(i), values) {
	// 			break
	// 		}
	// 	}
	// }
}
