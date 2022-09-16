package engine

type AttributeValueMap struct {
	m map[Attribute]AttributeValues
}

func (avm AttributeValueMap) Get(a Attribute) (av AttributeValues, found bool) {
	if avm.m == nil {
		return nil, false
	}
	av, found = avm.m[a]
	return
}

func (avm *AttributeValueMap) Set(a Attribute, av AttributeValues) {
	if avm.m == nil {
		avm.m = make(map[Attribute]AttributeValues)
	}
	avm.m[a] = av
}

func (avm AttributeValueMap) Len() int {
	return len(avm.m)
}

func (avm *AttributeValueMap) Clear(a Attribute) {
	if avm.m != nil {
		delete(avm.m, a)
	}
}

func (avm AttributeValueMap) Iterate(f func(attr Attribute, values AttributeValues) bool) {
	for attr, values := range avm.m {
		if !f(attr, values) {
			break
		}
	}
}
