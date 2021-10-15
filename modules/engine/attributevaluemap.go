package engine

type AttributeValueMap map[Attribute]AttributeValues

func (avm AttributeValueMap) Find(a Attribute) (av AttributeValues, found bool) {
	av, found = avm[a]
	return
}

func (avm AttributeValueMap) Set(a Attribute, av AttributeValues) {
	if av.Len() == 1 {
		// Ensure this is optimal
		avm[a] = AttributeValueOne{av.Slice()[0]}
	} else {
		avm[a] = av
	}
}
