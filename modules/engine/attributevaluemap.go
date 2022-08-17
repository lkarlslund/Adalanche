package engine

type AttributeValueMap map[Attribute]AttributeValues

func NewAttributeValueMap() AttributeValueMap {
	return make(AttributeValueMap)
}

func (avm AttributeValueMap) Get(a Attribute) (av AttributeValues, found bool) {
	av, found = avm[a]
	return
}

func (avm AttributeValueMap) Set(a Attribute, av AttributeValues) {
	avm[a] = av
}

func (avm AttributeValueMap) Clear(a Attribute) {
	delete(avm, a)
}
