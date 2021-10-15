package engine

// AttributeNode can contain children
type AttributeNode interface {
	Children() AttributeValueMap
	ChildrenLen() int
	ChildrenSlice() []AttributeAndValues
}

type AttributeValueWithChildren struct {
	AttributeValue
	data AttributeValueMap
}

func (avwc AttributeValueWithChildren) Children() AttributeValueMap {
	return nil
}

func (avwc AttributeValueWithChildren) ChildrenLen() int {
	return 0
}

func (avwc AttributeValueWithChildren) ChildrenSlice() []AttributeAndValues {
	return nil
}
